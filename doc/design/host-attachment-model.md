# Host attachment model

[Design index](../design.md)

Snapshot state contains guest-visible progress, not process-local resources.
Each external resource has a stable ID and a declarative reconstruction policy.

| Resource | Saved | Reconstructed or supplied on restore |
| --- | --- | --- |
| portb | Pending RX/TX bytes | Host serial endpoint, fresh process generation ID, and optional restore packet |
| console | Queue progress, staged RX, partial TX, endpoint identity, and reconnect policy | Listener recreated at its captured endpoint, required client connection, or supplied inherited terminal |
| Control console | Distinct attachment identity and broker policy, plus bounded broker state without queued records, host output, or receive credit; never the capability or peer identity | The captured same-user Unix socket or Windows named pipe and a fresh launcher-provided capability; the broker restarts with a fresh instance and epoch, keeping only its guest-side parser, any partially written guest record, and counters |
| network | Static identity, queue/packet progress, profile, and policy digest | Fresh in-process Consomme endpoint and matching egress policy; live host-loopback port forwards are rejected |
| filesystem | FUSE namespace, handles, cookies, root/object identity, access mode, and denied paths, or explicit dormant state | Fresh host-directory attachment with the same canonical path, target, mode, and denied paths; a dormant slot may stay unattached or bind a new attachment |
| sandbox block | Queue/device state, fixed roles, access, geometry, read-only layer identities, and scratch policy | Matching read-only layers plus a verified private paired scratch copy, or a new same-geometry scratch file |
| Readiness endpoint | Nothing | Optional single-use Unix socket or named pipe supplied for one restore |

Attachment resolution happens before vCPU start. A supplied attachment must
reproduce the saved identity; restore does not relocate saved endpoints.
Missing privileges, endpoint binding failures, changed egress policy, replaced
filesystem objects, or a wrong attachment kind fail restore explicitly.
