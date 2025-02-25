import sqlite3
from pathlib import Path

from depss.models import VulnerableInterval, VersionBorder
from depss.const import INF, INFINITE_VERSION

class VulnerabilityDB:
    """Класс работы с БД уязвимостей"""

    SELECT_PKG_INFO_QUERY = '''
    SELECT vulnerability, source, name, opener, version_left, version_right, closer
    FROM packages
    WHERE name == "{pkg_name}";
    '''

    def __init__(self, db_path: Path | str) -> None:
        """
        Инициализация класса

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
        cursor.execute(self.SELECT_PKG_INFO_QUERY.format(pkg_name=pkg_name))
        vulnerable_packages = cursor.fetchall()

        result_data = []
        for pkg in vulnerable_packages:
            vulnerability, source, name, opener, version_left, version_right, closer = pkg
            if version_right == INF:
                version_right = INFINITE_VERSION
            result_data.append((
                vulnerability,
                source,
                name,
                VulnerableInterval(
                    left_border=opener,
                    right_version=version_right,
                    left_version=version_left,
                    right_border=closer,
                ),
            ))

        return result_data
