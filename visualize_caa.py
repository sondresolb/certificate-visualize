import dns.resolver
from dns.resolver import NoAnswer
import tld


def check_caa(domain, end_cert):
    """Certificate Authority Authorization

    If a top level domain has a registered dns caa record,
    then all subdomain will inherit this unless specified.
    """
    original_domain = domain.replace("www.", "")

    od_res = caa_lookup(original_domain)
    if od_res[0]:
        return od_res

    else:
        # Testing top level domain if original domain fails
        try:
            top_level_domain = tld.get_fld(domain, fix_protocol=True)
            return caa_lookup(top_level_domain)
        except tld.exceptions.TldDomainNotFound:
            return (False, None)


def caa_lookup(domain):
    caa_records = []
    try:
        caa_records_data = dns.resolver.query(domain, 'CAA')

        for record in caa_records_data.rrset.items:
            record_info = {}
            record_info["flags"] = record.flags
            record_info["tag"] = record.tag.decode("utf-8")
            record_info["ca_issuer"] = record.value.decode("utf-8")
            caa_records.append(record_info)

        return (True, caa_records)

    except NoAnswer:
        return (False, None)
