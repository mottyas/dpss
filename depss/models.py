"""
Модуль с моделями данных
"""

import enum
from time import timezone
from dataclasses import dataclass
from datetime import datetime

import paramiko
from pydantic import (
    Field,
    StringConstraints,
    BaseModel,
    AnyUrl,
    field_validator,
)

from depss.const import TIMESTAMP_FORMAT


@dataclass
class ScanConfig:
    """Класс конфигурации сканирования"""

    host: str
    user: str
    secret: str
    date: str = datetime.now().strftime(TIMESTAMP_FORMAT)
    name: str = 'default'
    project_dir: str = './'
    project_name: str = 'default'
    project_type: str = 'python'
    port: int = 22


@dataclass
class SSHResponse:
    """Класс ответа выполнения команды"""

    stdin: paramiko.channel.ChannelStdinFile
    stdout: paramiko.channel.ChannelFile
    stderr: paramiko.channel.ChannelStderrFile


@dataclass
class SoftComponent:
    """Класс описания программного компонента"""

    name: str
    purl: str
    type: str
    version: str


class VersionBorder(enum.StrEnum):
    LTE: str = 'lte'
    GTE: str = 'gte'
    LT: str = 'lt'
    GT: str = 'gt'


@dataclass
class VulnerableInterval:
    """Класс описания границ уязвимого интервала"""

    left_border: VersionBorder
    right_version: str
    left_version: str
    right_border: VersionBorder


@dataclass
class DetectedSoft:
    """Найденный уязвимый софт"""

    vulnerable_interval: VulnerableInterval
    pkg_name: str
    pkg_version: str

@dataclass
class DetectedVulnerability:
    """Датакласс с кратким описанием найденной уязвимости"""

    vulner_id: str
    source_name: str
    affected_soft: list[DetectedSoft]

class AffectedSoft(BaseModel):
    """Класс валидации уязвимого софта"""

    name: str
    pkg_version: str
    pkg_type: str | None = None
    vendor: str | None = None
    vulnerable_interval: VulnerableInterval


class Rating(BaseModel):
    """Класс валидации уязвимого софта"""

    method: str | None = None
    score: float | None = None
    severity: str | None = None
    source_name: str | None = None
    source_url: AnyUrl | None = None
    vector: str | None = None
    version: float | None = None

class VulnerDataModel(BaseModel):

    identifier: str
    published: str
    source_name: str
    source_url: AnyUrl
    description: str
    affected_packages: list[AffectedSoft]
    cwes: list[str] | None = None
    ratings: list[Rating] | None = None
    references: list[dict] | None = None

class ReportModel(BaseModel):
    """Модель валидации отчета"""

    vulnerabilities: list[VulnerDataModel] | None = []
    creation_date: str
    author: str | None = None
