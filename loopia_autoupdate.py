import ipaddress
import json
import pathlib
import socket
import subprocess
import typing

import appdirs
import loopialib.client
import pydantic


class Config(pydantic.BaseModel):
    loopia_user: str
    loopia_pass: str
    domain: str
    subdomains: typing.List[str]


def main():
    config_path = pathlib.Path(appdirs.user_config_dir("loopia-autoupdate")) / "config.json"
    with open(config_path, "r") as f:
        config = Config(**json.load(f))
    print("WAN")
    wan_ipv4 = find_wan_ip(ipv6=False)
    print("  IPv4:", wan_ipv4)
    wan_ipv6 = find_wan_ip(ipv6=True)
    print("  IPv6:", wan_ipv6)
    print("DNS")
    dns_ipv4 = find_dns_ip(config.domain, ipv6=False)
    print("  IPv4:", dns_ipv4)
    dns_ipv6 = find_dns_ip(config.domain, ipv6=True)
    print("  IPv6:", dns_ipv6)
    print()
    if wan_ipv4 == dns_ipv4 and wan_ipv6 == dns_ipv6:
        print("DNS records are up to date.")
    else:
        print("DNS records NOT up to date. Verifying Loopia records...")
        subdomain_records = get_zone_records(config.loopia_user, config.loopia_pass,
                                             config.domain, config.subdomains)
        if verify_zone_records(subdomain_records, wan_ipv4, wan_ipv6):
            print()
            print("Loopia records up to date. Not doing anything more.")
        else:
            print()
            print("Loopia records NOT up to date. Updating Loopia records...")
            update_zone_records(config.loopia_user, config.loopia_pass,
                                config.domain, subdomain_records,
                                wan_ipv4, wan_ipv6)
            print()
            print("Loopia records were updated.")


def find_wan_ip(ipv6):
    veropt = "--ipv6" if ipv6 else "--ipv4"
    res = subprocess.run(["curl", veropt, "--max-time", "10", "https://api64.ipify.org"],
                         check=True, capture_output=True, encoding="ascii")
    s = res.stdout
    addr = ipaddress.ip_address(s)
    if ipv6:
        assert isinstance(addr, ipaddress.IPv6Address)
    else:
        assert isinstance(addr, ipaddress.IPv4Address)
    return str(addr)


def find_dns_ip(hostname, ipv6):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    addrinfo = socket.getaddrinfo(hostname, None, family, socket.SOCK_RAW)
    return ", ".join(entry[4][0] for entry in addrinfo)


def get_zone_records(loopia_user, loopia_pass, domain, subdomains):
    result = {}
    client = loopialib.client.Loopia(loopia_user, loopia_pass)
    for subdomain in subdomains:
        print(f"  {subdomain}.{domain}")
        records = client.get_zone_records(domain, subdomain)
        ipv4s = [record for record in records if record.type == "A"]
        ipv6s = [record for record in records if record.type == "AAAA"]
        print("    IPv4:", ", ".join(r.data for r in ipv4s))
        print("    IPv6:", ", ".join(r.data for r in ipv6s))
        result[subdomain] = ipv4s + ipv6s
    return result


def verify_zone_records(subdomain_records, real_ipv4, real_ipv6):
    all_ok = True
    for subdomain, records in subdomain_records.items():
        ipv4s = [record.data for record in records if record.type == "A"]
        ipv6s = [record.data for record in records if record.type == "AAAA"]
        if ipv4s != [real_ipv4] or ipv6s != [real_ipv6]:
            all_ok = False
    return all_ok


def update_zone_records(loopia_user, loopia_pass, domain, subdomain_records, real_ipv4, real_ipv6):
    type_to_data = {
        "A": real_ipv4,
        "AAAA": real_ipv6,
    }
    type_to_name = {
        "A": "IPv4",
        "AAAA": "IPv6",
    }
    client = loopialib.client.Loopia(loopia_user, loopia_pass)
    for subdomain, records in subdomain_records.items():
        print(f"  {subdomain}.{domain}")
        for record in sorted(records, key=lambda r: r.type):
            new_record = record._replace(data=type_to_data[record.type])
            client.update_zone_record(new_record, domain, subdomain)
            print(f"    {type_to_name[new_record.type]}: {record.data} -> {new_record.data}")


if __name__ == "__main__":
    main()
