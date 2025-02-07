"""
Модуль с моделями данных
"""

from time import timezone
from dataclasses import dataclass
from datetime import datetime

import paramiko

TIMESTAMP_FORMAT: str = '%d_%m_%Y_%H_%M_%S'

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

