"""Language-independent structural features for target/reference HTML pairs."""
from __future__ import annotations

import math


SCHEMA_VERSION = 1
COUNT_FIELDS = (
    'element_count', 'visible_text_length', 'max_depth', 'mean_depth',
    'link_count', 'external_link_count', 'image_count', 'external_image_count',
    'input_count', 'hidden_input_count', 'button_count', 'stylesheet_count',
    'external_stylesheet_count', 'resource_host_count', 'script_count',
    'external_script_count', 'iframe_count', 'password_fields',
    'meta_refresh_count',
)


def _number(value):
    try:
        value = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    return value if math.isfinite(value) and value >= 0 else 0.0


def ratio_similarity(left, right):
    left, right = _number(left), _number(right)
    if left == right == 0:
        return 1.0
    return min(left, right) / max(left, right)


def histogram_similarity(left, right):
    left, right = left or {}, right or {}
    keys = set(left) | set(right)
    denominator = sum(max(_number(left.get(key)), _number(right.get(key))) for key in keys)
    if not denominator:
        return 1.0
    return sum(min(_number(left.get(key)), _number(right.get(key))) for key in keys) / denominator


def pair_features(target, reference):
    """Return stable numeric observations. Higher similarity never means safe."""
    values = {
        'tag_histogram_similarity': histogram_similarity(target.get('tag_counts'), reference.get('tag_counts')),
    }
    similarities = []
    for field in COUNT_FIELDS:
        similarity = ratio_similarity(target.get(field), reference.get(field))
        values[field + '_similarity'] = similarity
        similarities.append(similarity)
        values[field + '_delta'] = _number(target.get(field)) - _number(reference.get(field))
    target_forms = target.get('forms') or []
    reference_forms = reference.get('forms') or []
    values.update({
        'form_count_similarity': ratio_similarity(len(target_forms), len(reference_forms)),
        'form_count_delta': float(len(target_forms) - len(reference_forms)),
        'target_external_forms': float(sum(bool(form.get('external_host')) for form in target_forms)),
        'reference_external_forms': float(sum(bool(form.get('external_host')) for form in reference_forms)),
        'target_insecure_forms': float(sum(bool(form.get('insecure_http')) for form in target_forms)),
        'reference_insecure_forms': float(sum(bool(form.get('insecure_http')) for form in reference_forms)),
    })
    # Descriptive aggregate for the GUI. It is not a safety probability.
    values['structure_similarity'] = (
        values['tag_histogram_similarity'] * 0.35
        + sum(similarities) / len(similarities) * 0.55
        + values['form_count_similarity'] * 0.10
    )
    return values


FEATURE_NAMES = tuple(pair_features({}, {}).keys())
