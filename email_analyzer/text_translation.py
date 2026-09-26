"""Optional local translation used only for contextual ML input."""
from __future__ import annotations

import re
from pathlib import Path

from langdetect import DetectorFactory, LangDetectException, detect

DetectorFactory.seed = 0

_TRANSLATORS = {}
_PROTECTED = re.compile(r"https?://\S+|www\.\S+|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", re.I)
_LANGUAGE_ALIASES = {
    'zh-cn': 'zh', 'zh-tw': 'zh', 'no': 'no', 'nb': 'no', 'iw': 'he',
}


def detect_text_language(text: str) -> str:
    sample = re.sub(_PROTECTED, ' ', text or '').strip()
    if len(sample) < 20:
        return 'unknown'
    try:
        value = detect(sample)
    except LangDetectException:
        return 'unknown'
    return _LANGUAGE_ALIASES.get(value, value)


def _mask_machine_tokens(text: str) -> str:
    """Keep URLs and addresses out of translation; structural engines use originals."""
    return _PROTECTED.sub(' [LINK] ', text)


def _chunks(text: str, limit: int = 900):
    paragraphs = [part.strip() for part in re.split(r'(?<=[.!?。！？])\s+|\n+', text) if part.strip()]
    result = []
    current = ''
    for paragraph in paragraphs:
        if len(current) + len(paragraph) + 1 <= limit:
            current = f'{current} {paragraph}'.strip()
            continue
        if current:
            result.append(current)
        while len(paragraph) > limit:
            result.append(paragraph[:limit])
            paragraph = paragraph[limit:]
        current = paragraph
    if current:
        result.append(current)
    return result


def preload_translation_model(model_path):
    path = str(Path(model_path).resolve())
    if path in _TRANSLATORS:
        return _TRANSLATORS[path]
    if not Path(path).is_dir():
        raise OSError(f'Translation model directory is missing: {path}')
    from transformers import M2M100ForConditionalGeneration, M2M100Tokenizer
    tokenizer = M2M100Tokenizer.from_pretrained(path, local_files_only=True)
    model = M2M100ForConditionalGeneration.from_pretrained(path, local_files_only=True)
    model.eval()
    _TRANSLATORS[path] = (tokenizer, model)
    return _TRANSLATORS[path]


def translate_context_to_korean(text: str, model_path, *, max_chars: int = 6000):
    """Translate visible context to Korean while returning explicit runtime status."""
    original = (text or '').strip()
    language = detect_text_language(original)
    if not original or language in ('ko', 'unknown'):
        return {'text': original, 'status': 'not_required' if language == 'ko' else 'language_unknown',
                'source_language': language, 'translated': False}
    if not model_path:
        return {'text': original, 'status': 'model_unavailable', 'source_language': language,
                'translated': False}
    try:
        tokenizer, model = preload_translation_model(model_path)
        if language not in tokenizer.lang_code_to_id:
            return {'text': original, 'status': 'unsupported_language', 'source_language': language,
                    'translated': False}
        import torch
        tokenizer.src_lang = language
        translated = []
        for chunk in _chunks(_mask_machine_tokens(original[:max_chars])):
            inputs = tokenizer(chunk, return_tensors='pt', truncation=True, max_length=512)
            input_tokens = int(inputs['input_ids'].shape[-1])
            output_limit = min(384, max(48, input_tokens * 2 + 16))
            with torch.inference_mode():
                generated = model.generate(
                    **inputs,
                    forced_bos_token_id=tokenizer.get_lang_id('ko'),
                    max_length=output_limit,
                    num_beams=1,
                )
            translated.extend(tokenizer.batch_decode(generated, skip_special_tokens=True))
        output = ' '.join(part.strip() for part in translated if part.strip())
        if not output:
            raise ValueError('empty translation')
        return {'text': output, 'status': 'translated', 'source_language': language, 'translated': True}
    except (OSError, ValueError, TypeError, KeyError, ImportError, RuntimeError) as exc:
        return {'text': original, 'status': 'translation_error', 'source_language': language,
                'translated': False, 'error': f'{type(exc).__name__}: {exc}'}
