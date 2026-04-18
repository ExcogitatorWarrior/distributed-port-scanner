def is_compliant(found_ports, allowed_ports):
    return set(found_ports).issubset(set(allowed_ports))