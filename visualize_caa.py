import dns.resolver
from dns.resolver import NoAnswer
from urllib.parse import urlsplit


def check_caa(domain, end_cert):
    caa_records = []
    strip_domain = domain.replace("www.", "")
    try:
        caa_records_data = dns.resolver.query(strip_domain, 'CAA')

        for record in caa_records_data.rrset.items:
            record_info = {}
            record_info["flags"] = record.flags
            record_info["tag"] = record.tag.decode("utf-8")
            record_info["ca_issuer"] = record.value.decode("utf-8")
            caa_records.append(record_info)

        return (True, caa_records)

    except NoAnswer:
        return (False, None)
