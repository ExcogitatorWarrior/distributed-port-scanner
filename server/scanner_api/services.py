def is_compliant(found_ports, allowed_ports):
    """
    Helper function to determine if the found_ports match the allowed_ports.
    Returns True if all found_ports are within the allowed_ports.
    """
    if not allowed_ports:
        allowed_ports = [0]  # Default to 0 if no allowed ports are specified

    # Check if all found ports are within the allowed ports
    return all(port in allowed_ports or port == 0 for port in found_ports)