"""
Модуль сканера удаленных хостов
"""

import paramiko

from depss.models import ScanConfigSchema, SSHResponseSchema
from depss.utils import write_file

from depss.config import DATA_DIR
from depss.const import REQUIREMENTS_FILE


class Scanner:
    """Класс сканера проекта"""

    def __init__(self, scan_config: ScanConfigSchema) -> None:
        """
        Метод инициализации объекта

        :param scan_config: Конфигурация сканирования
        """

        self.config = scan_config
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

        command = f'cat {self.config.project_dir}/{REQUIREMENTS_FILE}'
        response = self.send_command(command)
        output_dir = DATA_DIR / self.config.project_type / self.config.project_name
        data = response.stdout.read().decode()

        if not response.stderr.read().decode():
            write_file(
                output_dir=output_dir,
                filename=REQUIREMENTS_FILE,
                data=data,
            )
