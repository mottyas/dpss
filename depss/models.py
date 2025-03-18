"""
Модуль с моделями данных
"""

import enum
from datetime import datetime

import paramiko
from pydantic import (
    BaseModel,
    AnyUrl,
    Field,
    ConfigDict,
)

from depss.const import TIMESTAMP_FORMAT


class ProjectConfigSchema(BaseModel):
    """Схема конфигурации проекта"""

    name: str
    type: str = 'python'
    dir: str
    description: str = ''

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class ScanConfigSchema(BaseModel):
    """Класс конфигурации сканирования"""

    host: str
    user: str
    secret: str
    date: str = datetime.now().strftime(TIMESTAMP_FORMAT)
    name: str
    description: str = ''
    projects: list[ProjectConfigSchema]
    port: int = 22

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class SSHResponseSchema(BaseModel):
    """Схема ответа выполнения команды"""

    stdin: paramiko.channel.ChannelStdinFile
    stdout: paramiko.channel.ChannelFile
    stderr: paramiko.channel.ChannelStderrFile

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class SoftComponentSchema(BaseModel):
    """Схема описания программного компонента"""

    name: str
    purl: str
    type: str
    version: str

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class VersionBorder(enum.StrEnum):
    LTE: str = 'lte'
    GTE: str = 'gte'
    LT: str = 'lt'
    GT: str = 'gt'


class VulnerableIntervalSchema(BaseModel):
    """Схема описания границ уязвимого интервала"""

    left_border: VersionBorder
    right_version: str
    left_version: str
    right_border: VersionBorder

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class DetectedSoftSchema(BaseModel):
    """Найденный уязвимый софт"""

    vulnerable_interval: VulnerableIntervalSchema
    pkg_name: str
    pkg_version: str

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class DetectedVulnerabilitySchema(BaseModel):
    """Схема с кратким описанием найденной уязвимости"""

    vulner_id: str
    source_name: str
    affected_soft: list[DetectedSoftSchema]

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class AffectedSoftSchema(BaseModel):
    """Схема валидации уязвимого софта"""

    name: str
    pkg_version: str
    pkg_type: str | None = None
    vendor: str | None = None
    vulnerable_interval: VulnerableIntervalSchema

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class RatingSchema(BaseModel):
    """Схема валидации рейтинга уязвимости"""

    method: str | None = None
    score: float | None = None
    severity: str | None = None
    source_name: str | None = None
    source_url: AnyUrl | None = None
    vector: str | None = None
    version: float | None = None

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class VulnerDataSchema(BaseModel):
    """Схема валидации информации об уязвимости"""

    identifier: str
    published: str
    source_name: str
    source_url: AnyUrl
    description: str
    affected_packages: list[AffectedSoftSchema]
    cwes: list[str] | None = None
    ratings: list[RatingSchema] | None = None
    references: list[dict] | None = None

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)


class ReportModelSchema(BaseModel):
    """Схема валидации всего отчета"""

    vulnerabilities: list[VulnerDataSchema] | None = []
    creation_date: str
    author: str | None = None

    model_config = ConfigDict(extra='forbid', arbitrary_types_allowed=True)
