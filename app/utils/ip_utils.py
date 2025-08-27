import socket
import requests


def is_valid_ip(ip):
    """Check if the provided string is a valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_valid_domain(domain):
    """Check if the provided string is a valid domain name"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def get_ip_location(ip):
    """Get location information for an IP address using ipinfo.io"""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None