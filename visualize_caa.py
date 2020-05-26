import dns.resolver
import tld
from tld.exceptions import TldBadUrl, TldDomainNotFound


def check_caa(domain):
    """Certificate Authority Authorization

    If a top level domain has a registered dns caa record,
    then all subdomain will inherit this unless specified
    for the subdomain.
    """
    strip_domain = domain.replace("www.", "")

    try:
        tld_obj = tld.get_tld(
            strip_domain, as_object=True, fix_protocol=True)
        fld_str = tld_obj.fld
        subdomain_str = tld_obj.subdomain

    except (TldBadUrl, TldDomainNotFound) as tld_err:
        print(f"\nCAA failure: {str(tld_err)}")
        return (False, None)

    # Testing subdomain hierarchy
    if subdomain_str:
        subdomain_lst = subdomain_str.split(".")
        for _ in range(len(subdomain_lst)):
            subdomain = f"{'.'.join(subdomain_lst)}.{fld_str}"
            subdomain_lst.pop(0)
            sub_res = caa_lookup(subdomain)
            if sub_res[0]:
                return sub_res

    # Testing top level domain
    return caa_lookup(fld_str)


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

    except Exception:
        return (False, None)
