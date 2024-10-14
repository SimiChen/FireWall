#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
import psutil
import socket

def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'c4_pro.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    argv = sys.argv
    if len(argv) == 1:
        argv.append('runserver')
        current_interface = get_current_interface()
        if current_interface:
            argv.append(current_interface + ':8000')
            print(argv)
    execute_from_command_line(argv)

def get_current_interface():
    # Get a list of network interfaces
    interfaces = psutil.net_if_addrs()
    # Iterate through the interfaces and find the one that is up and has an IPv4 address
    for interface, addresses in interfaces.items():
        for address in addresses:
            if address.family == socket.AF_INET and address.address != '127.0.0.1' and address.address.startswith('192.168'):
                print(address.address, interface)
                return address.address

    return None


if __name__ == '__main__':
    main()


