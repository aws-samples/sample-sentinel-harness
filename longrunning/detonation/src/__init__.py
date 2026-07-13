"""longrunning.detonation.src — internal machinery for the detonation skeleton.

Holds the :mod:`vm` one-shot microVM ABSTRACTION. Kept in a ``src`` subpackage
(mirroring ``longrunning/bas-runner/src``) so the entrypoint stays thin and the
lifecycle logic is unit-testable offline with no AWS / no heavy deps.
"""
