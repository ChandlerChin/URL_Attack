"""Load per-target runtime profiles from external JSON files.

All executable locations, browser window positions, UI selectors and screenshot
regions are external data. This loader launches nothing and contacts no target.
"""
from copy import deepcopy
import json
from pathlib import Path


def merge(base, update):
    out = deepcopy(base)
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = deepcopy(value)
    return out


def load_configuration(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    external = {}
    for role, filename in config.get('profile_files', {}).items():
        source = Path(filename)
        if not source.is_absolute():
            source = path.parent / source
        external[role] = json.loads(source.read_text(encoding='utf-8-sig'))
    config['external_profiles'] = external
    runtime = external.get('runtime', {})
    regions = external.get('regions', {}).get('clients', {})
    for group in ('seg_targets', 'web_targets'):
        for target in config.get(group, []):
            tid = target['target_id']
            profile = merge(runtime.get('defaults', {}), runtime.get('clients', {}).get(tid, {}))
            profile['regions'] = deepcopy(regions.get(tid))
            target['profile'] = profile
    return config


def require_live_profile(target):
    """Reject unconfigured installation/calibration data before adapter calls.

    An attached browser/debugger or existing Windows process is allowed as an
    alternative to an executable path; neither is hard-coded in the runner.
    """
    profile = target.get('profile', {})
    platform = target.get('platform')
    if platform == 'Windows':
        app = profile.get('windows_client', {})
        if not any(app.get(k) for k in ('executable_path', 'process_id', 'window_selector')):
            raise ValueError('Windows installation/process/window must be configured externally: ' + target['target_id'])
    elif platform == 'Web':
        browser = profile.get('browser', {})
        if not any(browser.get(k) for k in ('executable_path', 'debugger_address')):
            raise ValueError('Browser executable or debugger address must be configured externally: ' + target['target_id'])
    else:
        raise ValueError('Target platform must be explicitly Windows or Web')
