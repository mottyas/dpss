"""
Модуль генератора Software Bill Of Materials
"""

import json
import subprocess
from pathlib import Path

from depss.utils import orjson_dump_file, orjson_load_file
from depss.models import SoftComponent
from depss.const import REQUIREMENTS_FILE


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

    def get_components(self) -> list[SoftComponent]:
        """Метод получения компонентов из SBOM"""

        components = []
        for component in self.sbom.get('components', []):
            components.append(
                SoftComponent(
                    name=component['name'],
                    purl=component['purl'],
                    type=component['type'],
                    version=component['version'],
                )
            )

        return components
