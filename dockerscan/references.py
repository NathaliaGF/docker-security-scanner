"""
Mapping of rule IDs to the CIS Docker Benchmark recommendations they implement.

Only mappings that match a recommendation one-to-one are listed; rules without
an entry are good-practice checks that the benchmark does not cover directly.
"""

CIS_DOCKER = {
    "DC001": ("4.1", "Ensure that a user for the container has been created"),
    "DC002": ("5.7", "Ensure that privileged ports are not mapped within containers"),
    "DC004": ("5.5", "Ensure sensitive host system directories are not mounted on containers"),
    "DC006": ("4.6", "Ensure that HEALTHCHECK instructions have been added to container images"),
    "DC007": ("5.4", "Ensure that privileged containers are not used"),
    "DC008": ("5.9", "Ensure that the host's network namespace is not shared"),
    "DC009": ("5.10", "Ensure that the memory usage for containers is limited"),
    "DC010": ("5.3", "Ensure that Linux kernel capabilities are restricted within containers"),
    "DF001": ("4.1", "Ensure that a user for the container has been created"),
    "DF003": ("4.10", "Ensure secrets are not stored in Dockerfiles"),
}


def cis_reference(rule_id: str) -> str | None:
    """Return e.g. 'CIS Docker Benchmark 4.1: Ensure ...' or None."""
    ref = CIS_DOCKER.get(rule_id)
    if ref is None:
        return None
    return f"CIS Docker Benchmark {ref[0]}: {ref[1]}"
