import logging

logger = logging.getLogger(__name__)

def list_all_hosted_zones(r53_client) -> list[dict]:
    zones: list[dict] = []
    paginator = r53_client.get_paginator("list_hosted_zones")
    for page in paginator.paginate():
        zones.extend(page.get("HostedZones"))
    logger.info("Retrieved %d hosted zones", len(zones))
    return zones


def list_all_record_sets(r53_client, zone_id: str) -> list[dict]:
    record_sets: list[dict] = []
    kwargs = {"HostedZoneId": zone_id}

    while True:
        response = r53_client.list_resource_record_sets(**kwargs)
        record_sets.extend(response.get("ResourceRecordSets"))

        if not response["IsTruncated"]:
            break

        kwargs["startRecordName"] = response["NextRecordName"]
        kwargs["StartRecordType"] = response["NextRecordType"]

        if "NextRecordIdentifier" in response:
            kwargs["StartRecordIdentifier"] = response["NextRecordIdentifier"]

    logger.debug("Zone %s: fetched %d record set(s)", zone_id, len(record_sets))
    return record_sets
