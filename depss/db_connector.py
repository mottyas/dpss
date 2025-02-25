import sqlite3
from pathlib import Path

from depss.models import VulnerableInterval, VersionBorder

class VulnerabilityDB:
    """Класс работы с БД уязвимостей"""

    def __init__(self, db_path: Path | str) -> None:
        """
        Инициализация

        :param db_path: Путь до файла с БД
        """

        self.db_path = db_path
        self.connection = sqlite3.connect(self.db_path)

    def __enter__(self):
        """Инициализация контекста"""

        self.connection = sqlite3.connect(self.db_path)

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Финализация контекста"""

        self.connection.close()

    def get_package_vulnerabilities(self, pkg_name: str) -> list:
        """
        Метод получения информации об уязвимостях пакета

        :param pkg_name: Имя пакета
        :return: Список найденных уязвимостей
        """

        cursor = self.connection.cursor()
        cursor.execute(
            f'''
            SELECT vulnerability, source, name, opener, version_left, version_right, closer
            FROM packages
            WHERE name == "{pkg_name}";
            '''
        )

        found_pkgs = cursor.fetchall()

        result_data = []
        for pkg in found_pkgs:
            vulnerability, source, name, opener, version_left, version_right, closer = pkg
            if version_right == 'inf':
                version_right = '9999999999999999'
            vulnerable_interval = VulnerableInterval(
                left_border=opener,
                right_version=version_right,
                left_version=version_left,
                right_border=closer,
            )
            result_data.append(
                (
                    vulnerability,
                    source,
                    name,
                    vulnerable_interval,
                )
            )

        return result_data
