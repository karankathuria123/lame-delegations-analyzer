import logging

from .dns_utils import resolve_hostname

logger = logging.getLogger(__name__)

def check_cname_records(zone_name: str, record_sets: list[dict]) -> list[dict]:
    zone_apex = zone_name.rstrip(".")
    findings: list[dict] = []

    cname_records = [rrs for rrs in record_sets if rrs["Type"] == "CNAME"]
    logger.info("Zone %s: Checking %d CNAME record set(s)", zone_apex, len(cname_records))

    for rrs in cname_records:
        record_name = rrs["Name"].rstrip(".")

        for rr in rrs.get("ResourceRecords", []):
            target = rr["Value"].rstrip(".")

            # Check 1: CNAME hostname must resolve
            resolved, detail = resolve_hostname(target)
            if not resolved:
                logger.warning(
                    "Lame [%s] CNAME %s -> %s does not resolve: %s",
                    zone_apex, record_name, target, detail,
                )
                findings.append({
                    "type": "Dangling_CNAME",
                    "zone": zone_apex,
                    "record_name": record_name,
                    "cname_value": target,
                    "reason": f"CNAME hostname does not resolve {detail}",
                })
            else:
                logger.debug(
                    "Zone: %s: CNAME %s -> %s resolves okay",
                    zone_apex, record_name, target
                )

    return findings