import sqlite3
from pathlib import Path

from depss.models import VulnerableIntervalSchema
from depss.const import INF, INFINITE_VERSION
from depss.utils import orjson_load_file


class VulnerabilityDB:
    """Класс работы с БД уязвимостей"""

    SELECT_PKG_INFO_QUERY = '''
    SELECT vulnerability, source, name, opener, version_left, version_right, closer
    FROM packages
    WHERE name == "{pkg_name}";
    '''

    CREATE_TABLE_PACKAGES = '''
    CREATE TABLE IF NOT EXISTS packages (
        id INTEGER PRIMARY KEY,
        vulnerability TEXT NOT NULL,
        source TEXT NOT NULL,
        name TEXT NOT NULL,
        opener TEXT NOT NULL,
        version_left TEXT NOT NULL,
        version_right TEXT NOT NULL,
        closer TEXT NOT NULL
    );
    '''

    # Создаем индекс для столбца "name"
    CREATE_INDEX_PACKAGES = 'CREATE INDEX idx_name ON packages (name);'

    INSERT_PACKAGE_INFO = '''
    INSERT INTO packages (vulnerability, source, name, opener, version_left, version_right, closer)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    '''


    def __init__(self, db_path: Path | str, package_folder: str | Path = None) -> None:
        """
        Инициализация класса

        :param db_path: Путь до файла с БД
        :param package_folder: Путь до директории с БД
        """
        if isinstance(db_path, str):
            db_path = Path(db_path)

        if isinstance(package_folder, str):
            package_folder = Path(package_folder)

        self.db_path = db_path
        self.package_folder = package_folder or db_path.parent

    def __enter__(self):
        """Инициализация контекста"""

        is_db_exist = self.db_path.exists()
        self.connection = sqlite3.connect(self.db_path)
        if not is_db_exist:
            self.update_db()
        return self

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
                VulnerableIntervalSchema(
                    left_border=opener,
                    right_version=version_right,
                    left_version=version_left,
                    right_border=closer,
                ),
            ))

        return result_data

    def prepare_pkg_data(self) -> list[tuple]:
        """Метод подготовки данных из пакета для отгрузки в БД"""

        result_data = []
        for file_path in self.package_folder.iterdir():
            data = orjson_load_file(file_path)
            vulner_id = data['identifier']
            source_name = data['source'][0]['source_name']
            for package in data['affects']:
                result_data.append((
                    vulner_id,
                    source_name,
                    package['name'],
                    package['version']['start_condition'],
                    package['version']['start_value'],
                    package['version']['end_value'],
                    package['version']['end_condition'],
                ))

        return result_data

    def update_db(self) -> None:
        """Метод обновления базы данных"""

        cursor = self.connection.cursor()
        cursor.execute(self.CREATE_TABLE_PACKAGES)
        cursor.execute(self.CREATE_INDEX_PACKAGES)

        prepared_data = self.prepare_pkg_data()
        cursor.executemany(self.INSERT_PACKAGE_INFO, prepared_data)
        self.connection.commit()
