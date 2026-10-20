"""Pure assessment dispatch over supplied observations; no target execution."""
import mr_assessment as MR


def assess(entry, observations):
    if not isinstance(observations, dict):
        raise MR.ObservationError('adapter observations must be a dictionary')
    expected = observations.get('expected_destination')
    MR.destination_host(expected)
    navigation = observations if entry['mr'] == 'MR3' else observations['attack']
    if navigation.get('reaches_expected_destination') is True and not navigation.get('actual_navigation_url'):
        raise MR.ObservationError('successful navigation requires the observed actual URL')
    if entry['mr'] == 'MR1':
        return MR.assess_mr1(observations['reference'], observations['attack'], expected)
    if entry['mr'] == 'MR2':
        return MR.assess_mr2(observations['reference'], observations['attack'], expected)
    # Identities are actual parsed destination identities, not display strings.
    h_ref = MR.destination_host(observations['resolved_href_ref'])
    h_att = MR.destination_host(observations['resolved_href_att'])
    reached = MR._navigation(observations, expected)
    if h_att != MR.destination_host(expected):
        raise MR.ObservationError('resolved attack href and expected host disagree')
    return MR.assess_mr3(
        observations['body_md5_ref'], observations['body_md5_att'],
        observations.get('warning_md5_ref'), observations.get('warning_md5_att'),
        observations['has_warning_dialog'],
        reaches_expected_destination=reached, distinct_destinations=h_ref != h_att)

