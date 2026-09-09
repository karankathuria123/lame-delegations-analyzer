import logging

from .dns_utils import query_soa_authoritative, resolve_hostname

logger = logging.getLogger(__name__)

def check_ns_records(zone_name: str, record_sets: list[dict]) -> list[dict]:
    zone_apex = zone_name.rstrip(".")
    findings: list[dict] = []

    ns_records = [rrs for rrs in record_sets if rrs["Type"] == "NS"]
    logger.info("Zone %s: Checking %d NS record set(s)", zone_apex, len(ns_records))

    for rrs in ns_records:
        record_name = rrs["Name"].rstrip(".")
        is_apex = record_name == zone_apex

        # Alias records dont carry ResourceRecords, - Skip them
        ns_values = [rr["Value"] for rr in rrs.get("ResourceRecords", [])]

        for ns_value in ns_values:
            ns_host = ns_value.rstrip(".")

            # Check 1: NS hostname must resolve
            resolved, resolve_detail = resolve_hostname(ns_host)
            if not resolved:
                logger.warning("Lame [%s] NS %s -> %s does not resolve: %s",
                               zone_apex, record_name, ns_host, resolve_detail,
                )
                findings.append({
                    "type": "LAME_DELEGATION",
                    "zone": zone_apex,
                    "record_name": record_name,
                    "ns_value": ns_host,
                    "reason": f"NS hostname does not resolve {resolve_detail}"
                })
                continue

            # Check 2: (sub zone delegation only) SOA authority probe

            if is_apex:
                logger.debug(
                    "Zone: %s: skipping SOA Probe for apex NS %s (resolves Okay)",
                    zone_apex, ns_host
                )
                continue

            is_auth, auth_detail = query_soa_authoritative(ns_host, record_name)
            if not is_auth:
                logger.warning(
                    "Lame [%s] NS %s -> %s is not authoritative: %s",
                    zone_apex, record_name, ns_host, auth_detail
                )
                findings.append({
                    "type": "LAME_DELEGATION",
                    "zone": zone_apex,
                    "record_name": record_name,
                    "ns_value": ns_host,
                    "reason": f"NS hostname is not authoritative for {record_name}: {auth_detail}"
                })
            else:
                logger.debug(
                    "Zone: %s: NS %s -> %s is authoritative (resolves Okay)",
                    zone_apex, record_name, ns_host, auth_detail
                )

    return findings