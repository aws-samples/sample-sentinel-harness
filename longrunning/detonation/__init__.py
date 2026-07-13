"""longrunning.detonation — sample-detonation long-running Runtime skeleton.

A SIMULATED, import-safe skeleton for the M3 "sample detonation" tier: a
one-shot microVM per ``runtimeSessionId`` that is destroyed after use, into
which a "sample" enters only via a controlled S3-dropbox ABSTRACTION (a uri /
dropbox id — never a live fetch), where every offensive/detonation step stays
human-gated via the existing Play Mode.

Nothing in this package detonates real malware, spins a real VM, or touches the
network. See ``README.md`` for the precise real-vs-simulated boundary.
"""
