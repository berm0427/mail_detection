"""이메일 분석 엔진이 공유하는 인터페이스와 결과 형식."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Dict, Literal, Optional


@dataclass
class EngineResult:
    """엔진 실행 결과.

    score는 0~1 범위의 위험도이며 미지원·미실행·실패 시 None이다.
    서로 다른 엔진의 점수는 보정 없이 동일한 의미로 비교할 수 없다.
    점수 범위는 인터페이스 계약이며 이 자료형이 자동 검증하지는 않는다.
    """

    engine_name: str
    status: Literal["ok", "skipped", "error"]
    score: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class BaseEngine(ABC):
    """입력 이메일을 변경하지 않고 분석하는 엔진의 추상 인터페이스."""

    @property
    @abstractmethod
    def name(self) -> str:
        """엔진을 식별하는 이름을 반환한다."""
        raise NotImplementedError

    @abstractmethod
    def analyze(self, email: EmailMessage) -> EngineResult:
        """입력 이메일을 변경하지 않고 분석 결과를 반환한다."""
        raise NotImplementedError
