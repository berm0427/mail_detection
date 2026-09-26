"""Download or verify the local multilingual context models."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


MODELS = {
    'multilingual_embedding': (
        'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2',
        'multilingual-minilm-l12-v2',
        ('modules.json', 'config.json'),
    ),
    'translation': (
        'facebook/m2m100_418M',
        'm2m100_418M',
        ('config.json', 'sentencepiece.bpe.model', 'vocab.json'),
    ),
}


def model_ready(path: Path, required):
    return path.is_dir() and all((path / name).is_file() for name in required)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path,
                        default=Path.home() / '.dise' / 'language_models')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = {}
    for name, (repository, directory, required) in MODELS.items():
        destination = args.root.resolve() / directory
        ready = model_ready(destination, required)
        if not ready and not args.check:
            from huggingface_hub import snapshot_download
            snapshot_download(repo_id=repository, local_dir=destination)
            ready = model_ready(destination, required)
        result[name] = {'ready': ready, 'path': str(destination), 'repository': repository}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if all(item['ready'] for item in result.values()) else 2)


if __name__ == '__main__':
    main()
