"""Compile structured IPv4 egress policies to the native OpenVMM rule grammar."""

from __future__ import annotations

import ipaddress
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .common import ScriptError, strict_json_object

MAX_RULES_PER_ACTION = 256
MAX_POLICY_FILE_SIZE = 1024 * 1024
_ROOT_FIELDS = frozenset(("allow", "deny"))
_RULE_FIELDS = frozenset(("cidr", "except", "protocol", "port", "endPort"))


@dataclass(frozen=True)
class CompiledEgressPolicy:
    allow: tuple[str, ...]
    deny: tuple[str, ...]


@dataclass(frozen=True)
class _Rule:
    networks: tuple[ipaddress.IPv4Network, ...]
    protocol: str | None
    start_port: int | None
    end_port: int | None


def _object(value: object, description: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ScriptError(f"{description} must be an object")
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        raise ScriptError(f"{description} fields must be strings")
    return cast(dict[str, object], value)


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise ScriptError(f"{description} must be an array")
    return cast(list[object], value)


def _network(value: object, description: str) -> ipaddress.IPv4Network:
    if not isinstance(value, str):
        raise ScriptError(f"{description} must be an IPv4 CIDR string")
    try:
        parsed = ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise ScriptError(f"{description} is not a valid IPv4 CIDR: {value}") from error
    if not isinstance(parsed, ipaddress.IPv4Network):
        raise ScriptError(f"{description} must be an IPv4 CIDR")
    return parsed


def _port(value: object, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScriptError(f"{description} must be an integer")
    if not 1 <= value <= 65535:
        raise ScriptError(f"{description} must be between 1 and 65535")
    return value


def _subtract_exclusions(
    parent: ipaddress.IPv4Network,
    exclusions: list[object],
    description: str,
) -> tuple[ipaddress.IPv4Network, ...]:
    parsed: list[ipaddress.IPv4Network] = []
    for index, value in enumerate(exclusions):
        exclusion = _network(value, f"{description}.except[{index}]")
        if not exclusion.subnet_of(parent):
            raise ScriptError(
                f"{description}.except[{index}] must be contained in {parent}"
            )
        parsed.append(exclusion)

    fragments = [parent]
    for exclusion in ipaddress.collapse_addresses(parsed):
        next_fragments: list[ipaddress.IPv4Network] = []
        for fragment in fragments:
            if exclusion == fragment:
                continue
            if exclusion.subnet_of(fragment):
                next_fragments.extend(fragment.address_exclude(exclusion))
            else:
                next_fragments.append(fragment)
        fragments = next_fragments
    return tuple(ipaddress.collapse_addresses(fragments))


def _parse_rule(value: object, description: str) -> _Rule:
    rule = _object(value, description)
    unknown = sorted(set(rule) - _RULE_FIELDS)
    if unknown:
        raise ScriptError(f"{description} has unknown field '{unknown[0]}'")
    if "cidr" not in rule:
        raise ScriptError(f"{description}.cidr is required")
    parent = _network(rule["cidr"], f"{description}.cidr")
    exclusions = _array(rule.get("except", []), f"{description}.except")
    networks = _subtract_exclusions(parent, exclusions, description)

    protocol_value = rule.get("protocol")
    if "protocol" not in rule:
        if "port" in rule or "endPort" in rule:
            raise ScriptError(f"{description}.port requires protocol")
        return _Rule(networks, None, None, None)
    if not isinstance(protocol_value, str) or protocol_value not in ("tcp", "udp"):
        raise ScriptError(f"{description}.protocol must be tcp or udp")
    if "port" not in rule:
        raise ScriptError(f"{description}.port is required with protocol")
    start = _port(rule["port"], f"{description}.port")
    end = _port(rule.get("endPort", start), f"{description}.endPort")
    if end < start:
        raise ScriptError(f"{description}.endPort cannot be below port")
    return _Rule(networks, protocol_value, start, end)


def _lower_protocol_rules(
    rules: list[_Rule],
    protocol: str,
    category: str,
    address_only: tuple[ipaddress.IPv4Network, ...],
    remaining_budget: int,
) -> list[tuple[ipaddress.IPv4Network, str, int]]:
    events: dict[int, list[tuple[int, tuple[ipaddress.IPv4Network, ...]]]] = {}
    for rule in rules:
        if rule.protocol != protocol or not rule.networks:
            continue
        assert rule.start_port is not None
        assert rule.end_port is not None
        events.setdefault(rule.start_port, []).append((1, rule.networks))
        events.setdefault(rule.end_port + 1, []).append((-1, rule.networks))

    active: Counter[ipaddress.IPv4Network] = Counter()
    lowered: list[tuple[ipaddress.IPv4Network, str, int]] = []
    previous_port: int | None = None
    for port in sorted(events):
        if previous_port is not None and previous_port < port and active:
            networks = list(ipaddress.collapse_addresses(active))
            for covering in address_only:
                uncovered: list[ipaddress.IPv4Network] = []
                for network in networks:
                    if network.subnet_of(covering):
                        continue
                    if covering.subnet_of(network):
                        uncovered.extend(network.address_exclude(covering))
                    else:
                        uncovered.append(network)
                networks = uncovered
            emitted = len(networks) * (port - previous_port)
            if len(lowered) + emitted > remaining_budget:
                raise ScriptError(
                    f"{category} emits at most {MAX_RULES_PER_ACTION} native rules"
                )
            lowered.extend(
                (network, protocol, current_port)
                for current_port in range(previous_port, port)
                for network in networks
            )
        for direction, networks in events[port]:
            for network in networks:
                active[network] += direction
                if active[network] == 0:
                    del active[network]
        previous_port = port
    return lowered


def _compile_category(value: object, category: str) -> tuple[str, ...]:
    values = _array(value, category)
    rules = [
        _parse_rule(rule, f"{category}[{index}]") for index, rule in enumerate(values)
    ]
    address_only = tuple(
        ipaddress.collapse_addresses(
            network
            for rule in rules
            if rule.protocol is None
            for network in rule.networks
        )
    )
    if len(address_only) > MAX_RULES_PER_ACTION:
        raise ScriptError(
            f"{category} emits at most {MAX_RULES_PER_ACTION} native rules"
        )
    lowered: list[tuple[ipaddress.IPv4Network, str | None, int | None]] = [
        (network, None, None) for network in address_only
    ]
    for protocol in ("tcp", "udp"):
        lowered.extend(
            _lower_protocol_rules(
                rules,
                protocol,
                category,
                address_only,
                MAX_RULES_PER_ACTION - len(lowered),
            )
        )
    lowered.sort(
        key=lambda item: (
            int(item[0].network_address),
            item[0].prefixlen,
            "" if item[1] is None else item[1],
            0 if item[2] is None else item[2],
        )
    )
    return tuple(
        str(network) if protocol is None else f"{network}:{protocol}:{port}"
        for network, protocol, port in lowered
    )


def compile_policy(value: object) -> CompiledEgressPolicy:
    root = _object(value, "egress policy")
    unknown = sorted(set(root) - _ROOT_FIELDS)
    if unknown:
        raise ScriptError(f"egress policy has unknown field '{unknown[0]}'")
    return CompiledEgressPolicy(
        allow=_compile_category(root.get("allow", []), "allow"),
        deny=_compile_category(root.get("deny", []), "deny"),
    )


def compile_policy_file(path: Path) -> CompiledEgressPolicy:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_POLICY_FILE_SIZE + 1)
    except OSError as error:
        raise ScriptError(f"failed to read egress policy file: {path}") from error
    if len(data) > MAX_POLICY_FILE_SIZE:
        raise ScriptError(
            f"egress policy file exceeds {MAX_POLICY_FILE_SIZE}-byte limit: {path}"
        )
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=strict_json_object)
    except (UnicodeDecodeError, ValueError) as error:
        raise ScriptError(f"failed to read egress policy file: {path}") from error
    return compile_policy(value)
