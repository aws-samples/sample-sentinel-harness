"""M4 acceptance smoke suite.

A thin, re-runnable freeze of the M4 acceptance proofs (the ROADMAP M7
``tests/smoke`` habit). Importing this package does nothing and touches no
AWS/network; the checks live in ``test_m4_acceptance.py`` and are OFFLINE by
default (opt into the live re-verification with ``SENTINEL_SMOKE_LIVE=1``).
"""
