"""Independent Phase 1 engine orchestration; scores do not alter legacy verdicts."""
from dataclasses import asdict
import json
from pathlib import Path
from email_analyzer.engines.evidence_ml import EvidenceMLEngine
from email_analyzer.engines.semantic_ml import SemanticMLEngine
from email_analyzer.engines.html_pair_ml import HtmlPairMLEngine
from email_analyzer.engines.razor import RazorEngine


def analyze_engines(message, config_override=None):
    root = Path(__file__).resolve().parents[1]
    config_path = root / 'engine_config.json'
    config = json.loads(config_path.read_text(encoding='utf-8')) if config_path.exists() else {}
    if config_override:
        config.update(config_override)
    # The former feature-only and CEAS baseline engines were experimental and
    # never contributed to the final decision.  Do not spend time running them
    # or expose their scores in the user-facing evidence table.
    engines = [RazorEngine(config.get('razor_command'), config.get('razor_timeout',25))]
    return {engine.name: asdict(engine.analyze(message)) for engine in engines}


def analyze_evidence_engine(message, result, config_override=None):
    root = Path(__file__).resolve().parents[1]
    config_path = root / 'engine_config.json'
    config = json.loads(config_path.read_text(encoding='utf-8')) if config_path.exists() else {}
    if config_override:
        config.update(config_override)
    model = config.get('evidence_ml_model')
    if model:
        model = Path(model)
        if not model.is_absolute(): model = root / model
    engine = EvidenceMLEngine(model)
    return asdict(engine.analyze(message, result))

def analyze_semantic_engine(message, config_override=None):
    root=Path(__file__).resolve().parents[1];config_path=root/'engine_config.json'
    config=json.loads(config_path.read_text(encoding='utf-8')) if config_path.exists() else {}
    if config_override:config.update(config_override)
    model=config.get('semantic_ml_model')
    if model:
        model=Path(model)
        if not model.is_absolute():model=root/model
    return asdict(SemanticMLEngine(model).analyze(message))


def analyze_html_pair_engine(homepage_comparison, config_override=None):
    root=Path(__file__).resolve().parents[1];config_path=root/'engine_config.json'
    config=json.loads(config_path.read_text(encoding='utf-8')) if config_path.exists() else {}
    if config_override:config.update(config_override)
    model=config.get('html_pair_ml_model')
    if model:
        model=Path(model)
        if not model.is_absolute():model=root/model
    return asdict(HtmlPairMLEngine(model).analyze(homepage_comparison))
