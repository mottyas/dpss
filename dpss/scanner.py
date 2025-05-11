"""
Модуль сканера удаленных хостов
"""

from pathlib import Path

import paramiko

from dpss.models import ScanConfigSchema, SSHResponseSchema
from dpss.utils import write_file
from dpss.const import REQUIREMENTS_FILE


class Scanner:
    """Класс сканера проекта"""

    def __init__(
        self,
        data_dir: str | Path,
        scan_config: ScanConfigSchema,
    ) -> None:
        """
        Метод инициализации объекта

        :param scan_config: Конфигурация сканирования
        """

        if isinstance(data_dir, str):
            data_dir = Path(data_dir)

        self.config = scan_config
        self.data_dir = data_dir
        self.client = self._get_connection()

    def _get_connection(self) -> paramiko.SSHClient:
        """
        Метод установки соединения со сканируемым хостом

        :return: Объект клиента сканера
        """

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.config.host,
            username=self.config.user,
            password=self.config.secret,
            port=self.config.port,
        )

        return client

    def close_connection(self) -> None:
        """Метод закрытия соединения со сканируемым хостом"""

        self.client.close()

    def send_command(self, command: str) -> SSHResponseSchema:
        """
        Метод отправки команд на удаленный хост

        :param command: Команда для выполнения
        :return: Кортеж с ответом сканируемого хоста
        """

        stdin, stdout, stderr = self.client.exec_command(command)

        return SSHResponseSchema(
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        )

    def save_project_requirements(self) -> None:
        """Метод сохранения requirements"""

        for project in self.config.projects:
            command = f'cat {project.dir}/{REQUIREMENTS_FILE}'
            response = self.send_command(command)
            output_dir = self.data_dir / project.type / project.name
            data = response.stdout.read().decode()

            if not response.stderr.read().decode():
                write_file(
                    output_dir=output_dir,
                    filename=REQUIREMENTS_FILE,
                    data=data,
                )
