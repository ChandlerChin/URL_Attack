"""Algorithm 1/2 control flow. Target operations are non-executing boundaries.

Only the published core logic is provided. These functions cannot deliver mail,
log into a service, operate a client, or capture a real target. All environment
values would belong to the private configuration, not this module.
"""
from construct_pairs import build_catalog
from execution import assess
from compare_regions import compare_screenshot_set


class TargetExecutionUnavailable(RuntimeError):
    pass


class TargetOperations:
    """The target-dependent operations are intentionally not implemented."""
    @staticmethod
    def deliver_pair(pair, target, config):
        raise TargetExecutionUnavailable('Target delivery is not part of the public release')

    @staticmethod
    def inspect_delivered_links(pair, target, config):
        raise TargetExecutionUnavailable('Target inspection is not part of the public release')

    @staticmethod
    def observe_warnings(pair, target, config):
        raise TargetExecutionUnavailable('Target interaction is not part of the public release')

    @staticmethod
    def capture_domain_regions(pair, target, config):
        raise TargetExecutionUnavailable('Target capture is not part of the public release')


def algorithm1(targets, config):
    """ConstructPairs -> target -> pair -> deliver -> inspect -> MR1 -> record."""
    pairs = [p for p in build_catalog() if p['technique'] in ('A1', 'A2')]
    results = []
    for target in targets:
        for pair in pairs:
            TargetOperations.deliver_pair(pair, target, config)
            observations = TargetOperations.inspect_delivered_links(pair, target, config)
            verdict = assess(pair, observations)
            results.append((pair, target, observations, verdict))
    return results


def algorithm2(targets, config):
    """ConstructPairs -> target -> pair -> MR2 or image/MR3 branch -> record."""
    pairs = [p for p in build_catalog() if p['technique'] in ('A3', 'A4', 'A5', 'A6', 'A7')]
    results = []
    for target in targets:
        for pair in pairs:
            TargetOperations.deliver_pair(pair, target, config)
            if pair['technique'] in ('A3', 'A4', 'A5'):
                observations = TargetOperations.observe_warnings(pair, target, config)
                verdict = assess(pair, observations)
            else:
                images, hosts = TargetOperations.capture_domain_regions(pair, target, config)
                region = target['profile']['regions']
                comparison = compare_screenshot_set(
                    images['body_ref'], images['body_att'],
                    images.get('warning_ref'), images.get('warning_att'),
                    body_box=region['message_body_box'], warn_box=region.get('warning_box'),
                    has_warning_dialog=hosts['has_warning_dialog'])
                observations = dict(hosts, **comparison)
                verdict = assess(pair, observations)
            results.append((pair, target, observations, verdict))
    return results
