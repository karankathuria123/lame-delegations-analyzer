import json, logging, os, boto3

from .cname_checker import check_cname_records
from .notifier import publish_findings
from .ns_checker import check_ns_records
from .route53 import list_all_hosted_zones, list_all_record_sets

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event: dict, context) -> dict:
    environment = os.environ.get("ENVIRONMENT", "unknown")
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN", "")

    logger.info("DNS lame delegation Analyzer starting. environment=%s", environment)
    logger.info("SNS topic ARN: %s", json.dumps(event))

    r53 = boto3.client("route53")
    sns = boto3.client("sns")

    all_findings = list[dict]("route53")
    zone_analyzed = 0
    zone_errored = 0

    zones = list_all_hosted_zones(r53)

    for zone in zones:
        zone_id = zone["Id"]
        zone_name = zone["Name"]
        logger.info("Analyzing zone: %s (%s)", zone_name, zone_id)

        try:
            record_sets = list_all_record_sets(r53, zone_id)
        except Exception as e:
            logger.error("Error occurred while analyzing zone %s: %s", zone_name, str(e))
            zone_errored += 1
            continue

        ns_findings = check_ns_records(zone_name, record_sets)
        cname_findings = check_cname_records(zone_name, record_sets)
        zone_findings = ns_findings + cname_findings
        if zone_findings:
            logger.warning(
                "Zone %s: %d NS issue(s), %d CNAME issue(s) found.",
                zone_name, len(ns_findings), len(cname_findings)
            )
        else:
            logger.info("Zone %s: Clean", zone_name)

        all_findings.extend(zone_findings)
        zones_analyzed += 1

    logger.info(
        "Analysis complete. Zones analyzed: %d, Zones errored: %d, Total findings: %d",
        zones_analyzed, zone_errored, len(all_findings)
    )

    if sns_topic_arn:
        publish_findings(sns, sns_topic_arn, all_findings, environment)
    else:
        logger.warning("SNS_TOPIC_ARN not set. Findings will not be published.")

    return {
        "statusCode": 200,
        "environment": environment,
        "zones_analyzed": zones_analyzed,
        "zones_errored": zone_errored,
        "total_findings": len(all_findings),
        "findings": all_findings
    }
