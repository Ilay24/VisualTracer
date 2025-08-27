import os
import json
import subprocess
import dns.resolver
import whois
import socket
import time
import requests
from flask import Blueprint, render_template, jsonify, request, current_app, flash, url_for, redirect
from flask_login import current_user, login_required
from app import db
from app.models import TracerouteHistory
from datetime import datetime
from app.utils.ip_utils import get_ip_location


tools_bp = Blueprint('tools', __name__, url_prefix='/tools')


@tools_bp.route('/traceroute')
@login_required
def traceroute_page():
    return render_template('tools/traceroute.html', title='Visual Traceroute')


@tools_bp.route('/traceroute/run', methods=['POST'])
@login_required
def run_traceroute():
    target = request.json.get('target')
    if not target:
        return jsonify({'error': 'No target specified'}), 400

    # Run traceroute and get the output
    try:
        result = perform_traceroute(target)

        # Save to history
        history = TracerouteHistory(user_id=current_user.id, target=target)
        history.set_result(result)
        db.session.add(history)
        db.session.commit()

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def perform_traceroute(target):
    """
    Perform a traceroute and return structured data with better IP detection
    """
    import re  # Add this import at the top of your file if not already there

    try:
        # Execute traceroute and capture output
        if os.name == 'nt':  # Windows
            process = subprocess.Popen(['tracert', target],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       text=True)
        else:  # Unix-like
            process = subprocess.Popen(['traceroute', target],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       text=True)

        stdout, stderr = process.communicate()

        if process.returncode != 0:
            raise Exception(f"Traceroute failed: {stderr}")

        # Regular expression to find IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        # Parse the output into a structured format
        hops = []
        hop_num = 0

        lines = stdout.strip().split('\n')

        # Skip the first line (header)
        for line in lines[1:]:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Extract hop number
            if os.name == 'nt':  # Windows
                match = re.match(r'^\s*(\d+)', line)
                if match:
                    hop_num = int(match.group(1))
            else:  # Unix
                match = re.match(r'^\s*(\d+)', line)
                if match:
                    hop_num = int(match.group(1))

            # Find all IP addresses in the line
            ip_addresses = re.findall(ip_pattern, line)

            if ip_addresses:
                for ip in ip_addresses:
                    # Skip local and private IPs
                    if ip.startswith(('10.', '192.168.', '127.')):
                        continue

                    # Try to get location data
                    location = get_ip_location_advanced(ip)

                    # Only add the hop if we got a real location
                    if location['country'] != 'Unknown' or location['city'] != 'Unknown':
                        hops.append({
                            'hop': hop_num,
                            'ip': ip,
                            'location': location
                        })
                        # We only need one IP per hop
                        break

        return {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'hops': hops
        }
    except Exception as e:
        print(f"Traceroute error: {e}")
        # Return a minimal result with the error
        return {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e),
            'hops': []
        }


def get_ip_location_advanced(ip):
    """
    Get location information for an IP address, trying multiple services
    """
    # Skip private IPs
    if ip.startswith(('10.', '192.168.', '127.')):
        return {
            'country': 'Local Network',
            'region': 'Local Network',
            'city': 'Local Network',
            'loc': '0,0'
        }

    # Try ipapi.co first
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if 'error' not in data:
                return {
                    'country': data.get('country_name', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'loc': f"{data.get('latitude', 0)},{data.get('longitude', 0)}"
                }
    except Exception:
        pass

    # Try ipinfo.io as a backup
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'loc': data.get('loc', '0,0')
            }
    except Exception:
        pass

    # Default response if all services fail
    return {
        'country': 'Unknown',
        'region': 'Unknown',
        'city': 'Unknown',
        'loc': '0,0'
    }


@tools_bp.route('map-maker/ip/get')
@login_required
def get_ip_location_route():
    target = request.args.get('target')
    if not target:
        return jsonify({'error': 'Missing target'}), 400

    from app.utils.ip_utils import get_ip_location, is_valid_domain
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return jsonify({'error': 'Invalid domain or IP'}), 400

    location = get_ip_location(ip)
    if not location:
        return jsonify({'error': 'Location not found'}), 404

    return jsonify({
        'ip': ip,
        'location': location
    })


@tools_bp.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    history_query = TracerouteHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(TracerouteHistory.created_at.desc())

    history_pages = history_query.paginate(page=page, per_page=per_page)

    return render_template('tools/history.html',
                           title='Traceroute History',
                           history=history_pages)


@tools_bp.route('/history/<int:id>')
@login_required
def view_history(id):
    history_item = TracerouteHistory.query.get_or_404(id)

    # Check if the history belongs to the current user
    if history_item.user_id != current_user.id:
        flash('You do not have permission to view this history item.', 'danger')
        return redirect(url_for('tools.history'))

    return render_template('tools/traceroute.html',
                           title='View Traceroute',
                           history_item=history_item)


@tools_bp.route('/history/delete/<int:id>', methods=['POST'])
@login_required
def delete_history(id):
    history_item = TracerouteHistory.query.get_or_404(id)

    if history_item.user_id != current_user.id:
        flash('You do not have permission to delete this item.', 'danger')
        return redirect(url_for('tools.history'))

    db.session.delete(history_item)
    db.session.commit()
    flash('Traceroute history deleted.', 'success')
    return redirect(url_for('tools.history'))


@tools_bp.route('/ip')
@login_required
def ip_location():
    return render_template('tools/ip_location.html', title='IP Location')


@tools_bp.route("/guess-where")
@login_required
def guess_where():
    return render_template("tools/guess_where.html", title="Guess Where")


@tools_bp.route('/ip/get', methods=['GET'])
@login_required
def get_my_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        ip = response.json()['ip']

        # Get location data
        location = get_ip_location_advanced(ip)

        return jsonify({
            'ip': ip,
            'location': location
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@tools_bp.route('/dns')
@login_required
def dns_lookup():
    return render_template('tools/dns_lookup.html', title='DNS Lookup')


@tools_bp.route('/map-maker')
@login_required
def map_maker():
    return render_template('tools/map_maker.html', title='Map Maker')


@tools_bp.route('/dns/lookup', methods=['POST'])
@login_required
def perform_dns_lookup():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'No domain specified'}), 400

    try:
        # Get different record types
        results = {}

        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                results[record_type] = []
            except dns.resolver.NXDOMAIN:
                results['error'] = f"Domain {domain} does not exist"
                break
            except Exception as e:
                results[record_type] = [f"Error: {str(e)}"]

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@tools_bp.route('/whois')
@login_required
def whois_lookup():
    return render_template('tools/whois.html', title='WHOIS Lookup')


@tools_bp.route('/whois/lookup', methods=['POST'])
@login_required
def perform_whois_lookup():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'No domain specified'}), 400

    try:
        # Set a lower socket timeout to prevent long waits
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(15)  # 15 seconds timeout

        try:
            # Try using python-whois library
            result = whois.whois(domain)

            # Convert certain fields to make them JSON serializable
            whois_data = {}
            for key, value in result.items():
                if isinstance(value, (list, dict, str, int, float, bool, type(None))):
                    whois_data[key] = value
                else:
                    whois_data[key] = str(value)

            return jsonify(whois_data)
        except Exception as e:
            # If python-whois fails, try using a public API
            try:
                # Use RDAP API (a modern replacement for WHOIS)
                response = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
                if response.status_code == 200:
                    rdap_data = response.json()

                    # Convert RDAP format to WHOIS-like format
                    whois_data = {
                        'domain_name': domain,
                        'registrar': next((entity['handle'] for entity in rdap_data.get('entities', [])
                                           if 'registrar' in str(entity.get('roles', [])).lower()), None),
                        'creation_date': rdap_data.get('events', {}).get('registration', None),
                        'updated_date': rdap_data.get('events', {}).get('lastChanged', None),
                        'expiration_date': rdap_data.get('events', {}).get('expiration', None),
                        'name_servers': [ns.get('ldhName') for ns in rdap_data.get('nameservers', [])],
                        'status': rdap_data.get('status', []),
                        'emails': None,  # RDAP typically doesn't include emails
                        'dnssec': rdap_data.get('secureDNS', {}).get('delegationSigned', None),
                        'raw_rdap': rdap_data  # Include the raw data for completeness
                    }
                    return jsonify(whois_data)
            except Exception as rdap_error:
                # If RDAP fails, try a third-party WHOIS API
                try:
                    response = requests.get(f"https://api.domainsdb.info/v1/domains/search?domain={domain}", timeout=10)
                    if response.status_code == 200:
                        domains_data = response.json().get('domains', [])
                        if domains_data:
                            domain_info = domains_data[0]
                            whois_data = {
                                'domain_name': domain_info.get('domain', domain),
                                'creation_date': domain_info.get('create_date', None),
                                'updated_date': domain_info.get('update_date', None),
                                'expiration_date': None,
                                'name_servers': None,
                                'status': None,
                                'country': domain_info.get('country', None),
                                'isDead': domain_info.get('isDead', None),
                                'raw_data': domain_info
                            }
                            return jsonify(whois_data)
                except Exception as third_party_error:
                    pass

            # If all API methods fail, fallback to a minimal response based on DNS
            try:
                import dns.resolver
                dns_info = {
                    'domain_name': domain,
                    'name_servers': [],
                    'a_records': [],
                    'mx_records': [],
                    'txt_records': []
                }

                # Get NS records
                try:
                    answers = dns.resolver.resolve(domain, 'NS')
                    dns_info['name_servers'] = [str(rdata) for rdata in answers]
                except Exception:
                    pass

                # Get A records
                try:
                    answers = dns.resolver.resolve(domain, 'A')
                    dns_info['a_records'] = [str(rdata) for rdata in answers]
                except Exception:
                    pass

                # Get MX records
                try:
                    answers = dns.resolver.resolve(domain, 'MX')
                    dns_info['mx_records'] = [str(rdata) for rdata in answers]
                except Exception:
                    pass

                # Get TXT records
                try:
                    answers = dns.resolver.resolve(domain, 'TXT')
                    dns_info['txt_records'] = [str(rdata) for rdata in answers]
                except Exception:
                    pass

                return jsonify({
                    'domain_name': domain,
                    'note': 'Full WHOIS data unavailable. Showing DNS information instead.',
                    'dns_info': dns_info
                })
            except Exception as dns_error:
                return jsonify({
                    'domain_name': domain,
                    'error': 'Limited information available',
                    'message': 'Could not retrieve detailed domain information.'
                })

        finally:
            # Restore original timeout
            socket.setdefaulttimeout(original_timeout)

    except Exception as e:
        return jsonify({'error': str(e)}), 500