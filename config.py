import os
from pathlib import Path

# 설정 파일 경로
CONFIG_DIR = Path(__file__).parent / "config"
os.makedirs(CONFIG_DIR, exist_ok=True)

# API 키 설정
ANTHROPIC_API_KEY = "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"  # 개인키 입력

# AI 분석 설정
AI_ENABLED = False  # AI 분석 활성화 여부
AI_MODEL = "claude-3-7-sonnet-20250219"  # 사용할 AI 모델