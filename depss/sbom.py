"""
Модуль генератора Software Bill Of Materials
"""

import json
import subprocess
from pathlib import Path

from depss.utils import orjson_dump_file, orjson_load_file
from depss.models import SoftComponentSchema, DetectedSoftSchema, DetectedVulnerabilitySchema, ReportModelSchema
from depss.const import REQUIREMENTS_FILE
from depss.vulnerdb import VulnerabilityDB
from depss.utils import check_is_vulnerable
from depss.reporter import Reporter

class GeneratorSBOM:
    """Класс генератора SBOM"""

    def __init__(
            self,
            source_type: str = 'requirements',
            source_path: str | Path = './',
            output_path: str | Path = './',
            sbom_generator_app: str = 'cyclonedx-py',
    ) -> None:
        """
        Инициализация генератора SBOM

        :param source_type: Тип источника информации для SBOM
        :param source_path: Путь до источника информации для SBOM
        :param output_path: Путь для сохранения информации SBOM
        :param sbom_generator_app: Способ генерации SBOM
        """

        self.source_type = source_type
        self.sbom_generator_app = sbom_generator_app
        self.source_path = Path(source_path) if isinstance(source_path, str) else source_path
        self.output_path = Path(output_path) if isinstance(output_path, str) else output_path

    def generate_sbom(self, is_need_dump_file: bool = False) -> None:
        """
        Метод генерации SBOM

        :param is_need_dump_file: Флаг необходимости записи SBOM в файл
        :return: Словарь полученный при генерации SBOM
        """

        requirements_file_path = self.source_path / REQUIREMENTS_FILE
        command = [self.sbom_generator_app, self.source_type, requirements_file_path]
        command_result = subprocess.run(command, capture_output=True, text=True)
        sbom_data = json.loads(command_result.stdout)

        if is_need_dump_file:
            orjson_dump_file(
                output_dir=self.output_path,
                filename='sbom.json',
                data=sbom_data,
            )

        return sbom_data


class ParserSBOM:
    """Класс парсера SBOM файлов и объектов"""

    def __init__(self, source: str | Path) -> None:
        """
        Метод инициализации объекта

        :param source: Путь до SBOM файла
        """

        self.sbom = orjson_load_file(source)

    def get_components(self) -> list[SoftComponentSchema]:
        """Метод получения компонентов из SBOM"""

        components = []
        for component in self.sbom.get('components', []):
            components.append(
                SoftComponentSchema(
                    name=component['name'],
                    purl=component['purl'],
                    type=component['type'],
                    version=component['version'],
                )
            )

        return components

class ComponentsAnalyzer:
    """Класс анализатора компонентов"""

    def __init__(
            self,
            sbom_source: str | Path,
            db_path: Path | str,
            package_folder: str | Path = None,
    ) -> None:
        """
        Инициализация класса

        :param sbom_source: Путь до SBOM файла
        :param db_path: Путь до файла с БД
        :param package_folder: Путь до директории с БД
        """

        self.sbom = orjson_load_file(sbom_source)
        self.db_path = db_path
        self.package_folder = package_folder

    def get_components(self) -> list[SoftComponentSchema]:
        """Метод получения компонентов из SBOM"""

        components = []
        for component in self.sbom.get('components', []):
            components.append(
                SoftComponentSchema(
                    name=component['name'],
                    purl=component['purl'],
                    type=component['type'],
                    version=component['version'],
                )
            )

        return components

    def find_vulnerabilities_in_components(self) ->  list[DetectedVulnerabilitySchema]:
        """
        Метод поиска уязвимостей в компонентах

        :return: Список найденных уязвимостей
        """

        found_vulnerabilities = {}
        with VulnerabilityDB(db_path=self.db_path, package_folder=self.package_folder) as vulner_db:
            for component in self.get_components():
                pkg_version = component.version
                pkg_name = component.name
                vulnerabilities = vulner_db.get_package_vulnerabilities(pkg_name)
                for vulner in vulnerabilities:
                    vulnerability, source, pkg_name, vulnerable_interval = vulner
                    is_vulnerable = check_is_vulnerable(pkg_version, vulnerable_interval)
                    if not is_vulnerable:
                        continue

                    if not found_vulnerabilities.get(vulnerability):
                        found_vulnerabilities[vulnerability] = {
                            'id': vulnerability,
                            'source': source,
                            'soft': []
                        }
                    found_vulnerabilities[vulnerability]['soft'].append(
                        DetectedSoftSchema(
                            vulnerable_interval=vulnerable_interval,
                            pkg_name=pkg_name,
                            pkg_version=pkg_version,
                        )
                    )

        detected_vulnerabilities = []
        for vulner, data in found_vulnerabilities.items():
            detected_vulnerabilities.append(
                DetectedVulnerabilitySchema(
                    vulner_id=vulner,
                    source_name=data['source'],
                    affected_soft=data['soft'],
                )
            )

        return detected_vulnerabilities

    def fast_check(self) -> ReportModelSchema:
        """Метод для быстрой проверки"""

        detected_vulnerabilities = self.find_vulnerabilities_in_components()

        reporter = Reporter(
            detected_vulnerabilities=detected_vulnerabilities
        )

        return reporter.generate_report()
