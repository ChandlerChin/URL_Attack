"""Fixed-region MD5 over width, height and RGB bytes; no visual inference."""
import hashlib
from PIL import Image


def validate_box(img, box):
    if img is None:
        raise ValueError('screenshot missing')
    if box is None or len(box) != 4 or any(type(x) is not int for x in box):
        raise ValueError('crop must be four integer coordinates')
    left, upper, right, lower = box
    if not (0 <= left < right <= img.width and 0 <= upper < lower <= img.height):
        raise ValueError('empty or out-of-bounds crop')
    return tuple(box)


def region_md5(img, box):
    box = validate_box(img, box)
    region = img.crop(box).convert('RGB')
    width, height = region.size
    digest = hashlib.md5()
    digest.update(width.to_bytes(4, 'little'))
    digest.update(height.to_bytes(4, 'little'))
    digest.update(region.tobytes())
    return digest.hexdigest()


def compare_pair(ref_img, att_img, box, att_box=None):
    # Whole screenshots may differ outside the fixed crop. Only crops are
    # compared. Separate boxes permit verifying unequal crop dimensions.
    a = region_md5(ref_img, box)
    b = region_md5(att_img, box if att_box is None else att_box)
    return a, b, a == b


def compare_screenshot_set(ref_body, att_body, ref_warn=None, att_warn=None,
                           body_box=None, warn_box=None, *, has_warning_dialog):
    if type(has_warning_dialog) is not bool:
        raise ValueError('dialog presence must be observed explicitly')
    a, b, equal = compare_pair(ref_body, att_body, body_box)
    out = {'body_md5_ref': a, 'body_md5_att': b, 'body_identical': equal,
           'has_warning_dialog': has_warning_dialog}
    if has_warning_dialog:
        a, b, equal = compare_pair(ref_warn, att_warn, warn_box)
        out.update(warning_md5_ref=a, warning_md5_att=b, warning_identical=equal)
    else:
        if ref_warn is not None or att_warn is not None:
            raise ValueError('warning captures conflict with absent-dialog observation')
        out.update(warning_md5_ref=None, warning_md5_att=None, warning_identical=None)
    return out


def compare_from_profile(ref_body, att_body, ref_warn, att_warn, profile, *, has_warning_dialog):
    """Use crop positions loaded from target['profile']['regions']."""
    if not isinstance(profile, dict):
        raise ValueError('external screenshot region profile is required')
    return compare_screenshot_set(ref_body, att_body, ref_warn, att_warn,
                                  body_box=profile.get('message_body_box'),
                                  warn_box=profile.get('warning_box'),
                                  has_warning_dialog=has_warning_dialog)

