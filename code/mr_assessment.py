"""MR assessments. Completed trials have paper verdicts only.

Missing or malformed observations raise ObservationError (an execution error),
never a measured failure or success. Unit-test fixtures are not measurements.
"""
from urllib.parse import urlsplit


class ObservationError(ValueError):
    pass


def boolean(record, key):
    if key not in record or type(record[key]) is not bool:
        raise ObservationError('%s must be an observed boolean' % key)
    return record[key]


def _verdict(mr, success, reason):
    return {'mr': mr, 'verdict': 'success' if success else 'unsuccessful',
            'reason': reason}


def destination_host(url):
    if not isinstance(url, str) or not url.strip():
        raise ObservationError('a nonempty absolute destination URL is required')
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if parsed.scheme.lower() not in ('http', 'https') or not host:
            raise ValueError('not an HTTP(S) destination')
        try:
            host = host.encode('idna').decode('ascii')
        except UnicodeError:
            # Keep an unsupported spelling visible; do not strip bidi characters.
            pass
        return host.lower().rstrip('.')
    except (ValueError, UnicodeError) as exc:
        raise ObservationError('invalid observed destination: %s' % exc) from exc


def _navigation(o_att, expected_destination):
    if not isinstance(expected_destination, str) or not expected_destination:
        raise ObservationError('expected_destination is required')
    reached = boolean(o_att, 'reaches_expected_destination')
    actual = o_att.get('actual_navigation_url')
    # When the adapter supplies actual navigation, also check host identity.
    # A5 must supply the final destination, not the redirect entry URL.
    if actual is not None:
        matches = destination_host(actual) == destination_host(expected_destination)
        if reached and not matches:
            raise ObservationError('navigation claim conflicts with actual host')
    return reached


def assess_mr1(o_ref, o_att, expected_destination):
    reference = boolean(o_ref, 'seg_rewritten')
    attack_rewritten = boolean(o_att, 'seg_rewritten')
    generated = boolean(o_att, 'client_link_generated')
    preserved = boolean(o_att, 'transport_preserved')
    reached = _navigation(o_att, expected_destination)
    success = reference and not attack_rewritten and generated and preserved and reached
    return _verdict('MR1', success,
                    'reference rewritten; preserved attack link unrewritten and reached'
                    if success else 'MR1 bypass conditions not all observed')


def assess_mr2(o_ref, o_att, expected_destination):
    # Explicitly observed lack of a reference warning (False) cannot be a
    # warning-preservation violation. Missing capture (None) is an error.
    reference_warning = boolean(o_ref, 'warning_shown')
    attack_warning = boolean(o_att, 'warning_shown')
    ref_openable = boolean(o_ref, 'link_openable')
    att_openable = boolean(o_att, 'link_openable')
    reached = _navigation(o_att, expected_destination)
    success = (reference_warning and not attack_warning and ref_openable
               and att_openable and reached)
    return _verdict('MR2', success,
                    'reference warned; attack reached without warning' if success
                    else 'MR2 bypass conditions not all observed')


def _hash(value, name):
    if not isinstance(value, str) or len(value) != 32:
        raise ObservationError('%s must be a 32-character MD5 hex digest' % name)
    try:
        int(value, 16)
    except ValueError as exc:
        raise ObservationError('%s is not hexadecimal' % name) from exc
    return value.lower()


def assess_mr3(body_md5_ref, body_md5_att, warning_md5_ref, warning_md5_att,
               has_warning_dialog, *, reaches_expected_destination,
               distinct_destinations):
    if type(has_warning_dialog) is not bool:
        raise ObservationError('has_warning_dialog must be observed')
    if type(reaches_expected_destination) is not bool or type(distinct_destinations) is not bool:
        raise ObservationError('navigation and distinct destination identity must be observed')
    body_equal = (_hash(body_md5_ref, 'body_md5_ref') ==
                  _hash(body_md5_att, 'body_md5_att'))
    if has_warning_dialog:
        warning_equal = (_hash(warning_md5_ref, 'warning_md5_ref') ==
                         _hash(warning_md5_att, 'warning_md5_att'))
    else:
        if warning_md5_ref is not None or warning_md5_att is not None:
            raise ObservationError('no-dialog observation conflicts with warning hashes')
        warning_equal = False
    if not reaches_expected_destination or not distinct_destinations or not body_equal:
        return {'mr': 'MR3', 'verdict': 'unsuccessful',
                'reason': 'visual attack conditions not all observed'}
    if has_warning_dialog and warning_equal:
        return {'mr': 'MR3', 'verdict': 'success',
                'reason': 'distinct reached domain; identical body and warning images'}
    return {'mr': 'MR3', 'verdict': 'limited',
            'reason': 'identical body images; warning absent or distinguishable'}

