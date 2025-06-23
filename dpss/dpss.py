from pathlib import Path

from dpss.scanner import Scanner
from dpss.sbom import GeneratorSBOM, ParserSBOM
from dpss.models import ScanConfigSchema, SoftComponentSchema, DetectedVulnerabilitySchema, DetectedSoftSchema
from dpss.vulnerdb import VulnerabilityDB
from dpss.reporter import Reporter
from dpss.utils import check_is_vulnerable


class OldDependencySecurityScanner:
    """Класс работы с анализатором компонентов"""

    def __init__(
            self,
            scan_config: ScanConfigSchema,
            db_path: str | Path,
            data_dir: Path,
            vulners_package_dir: Path,
    ) -> None:
        """Инициализация объекта класса"""

        self.scanner = Scanner(scan_config=scan_config, data_dir=data_dir)
        self.data_dir = data_dir
        self.db_path = db_path
        self.vulners_package_dir = vulners_package_dir
        self.found_vulnerabilities = {}
        self.report_type = scan_config.report_type
        self.report = None

    def run(self) -> None:
        """Метод запуска сканирования"""

        components = []

        self.scanner.save_project_requirements()

        local_project_dirs = []
        for project in self.scanner.config.projects:
            local_project_dirs.append(self.data_dir / project.type / project.name)

        for local_project_dir in local_project_dirs:
            self.generate_sbom(local_project_dir)
            components.extend(
                self.get_components_from_sbom(local_project_dir)
            )

        self.find_vulnerabilities_by_components(components)
        self.make_report()

    @staticmethod
    def generate_sbom(local_project_dir: Path) -> None:
        """Метода генерации SBOM данных"""

        sbom_generator = GeneratorSBOM(
            source_path=local_project_dir,
            output_path=local_project_dir,
        )

        sbom_generator.generate_sbom(is_need_dump_file=True)

    @staticmethod
    def get_components_from_sbom(local_project_dir: Path) -> list[SoftComponentSchema]:
        """Метода парсинга SBOM данных"""

        return ParserSBOM(local_project_dir / 'sbom.json').get_components()

    def find_vulnerabilities_by_components(self, components: list[SoftComponentSchema]) -> list[DetectedVulnerabilitySchema]:
        """
        Метод поиска уязвимостей по обнаруженным компонентам

        :param components: Список компонентов
        :return: Список уязвимостей, включающий уязвимый компоненты
        """

        for component in components:
            pkg_version = component.version
            pkg_name = component.name

            with VulnerabilityDB(db_path=self.db_path, package_folder=self.vulners_package_dir) as vulner_db:
                vulnerabilities = vulner_db.get_package_vulnerabilities(pkg_name)

            for vulner in vulnerabilities:
                vulnerability, source, pkg_name, vulnerable_interval = vulner
                is_vulnerable = check_is_vulnerable(pkg_version, vulnerable_interval)
                if not is_vulnerable:
                    continue

                if not self.found_vulnerabilities.get(vulnerability):
                    self.found_vulnerabilities[vulnerability] = dict(
                        id=vulnerability,
                        source=source,
                        soft=[],
                    )

                self.found_vulnerabilities[vulnerability]['soft'].append(
                    DetectedSoftSchema(
                        vulnerable_interval=vulnerable_interval,
                        name=pkg_name,
                        version=pkg_version,
                    )
                )

    def make_report(self) -> None:
        """Метод составления отчета о результатах сканирования"""

        detected_vulnerabilities = []
        for vulner, data in self.found_vulnerabilities.items():
            detected_vulnerabilities.append(
                DetectedVulnerabilitySchema(
                    vulner_id=vulner,
                    source_name=data['source'],
                    affected_soft=data['soft'],
                )
            )

        reporter = Reporter(
            detected_vulnerabilities=detected_vulnerabilities,
            vulnerabilities_package_path=self.vulners_package_dir,
            report_type=self.report_type,
        )

        self.report = reporter.generate_report()


class DependencySecurityScanner:
    """Класс работы с анализатором компонентов"""

    def __init__(
            self,
            scan_config: ScanConfigSchema,
            db_path: str | Path,
            data_dir: Path,
            vulners_package_dir: Path,
    ) -> None:
        """Инициализация объекта класса"""

        self.scanner = Scanner(scan_config=scan_config, data_dir=data_dir)
        self.data_dir = data_dir
        self.db_path = db_path
        self.vulners_package_dir = vulners_package_dir
        self.found_vulnerabilities = {}
        self.report_type = scan_config.report_type
        self.report = None

    def run(self) -> None:
        """Метод запуска сканирования"""

        components = []

        self.scanner.save_project_requirements()

        local_project_dirs = []
        for project in self.scanner.config.projects:
            local_project_dirs.append(self.data_dir / project.type / project.name)

        for local_project_dir in local_project_dirs:
            self.generate_sbom(local_project_dir)
            components.extend(
                self.get_components_from_sbom(local_project_dir)
            )

        self.find_vulnerabilities_by_components(components)
        self.make_report()

    @staticmethod
    def generate_sbom(local_project_dir: Path) -> None:
        """Метода генерации SBOM данных"""

        sbom_generator = GeneratorSBOM(
            source_path=local_project_dir,
            output_path=local_project_dir,
        )

        sbom_generator.generate_sbom(is_need_dump_file=True)

    @staticmethod
    def get_components_from_sbom(local_project_dir: Path) -> list[SoftComponentSchema]:
        """Метода парсинга SBOM данных"""

        return ParserSBOM(local_project_dir / 'sbom.json').get_components()

    def find_vulnerabilities_by_components(self, components: list[SoftComponentSchema]) -> list[DetectedVulnerabilitySchema]:
        """
        Метод поиска уязвимостей по обнаруженным компонентам

        :param components: Список компонентов
        :return: Список уязвимостей, включающий уязвимый компоненты
        """

        for component in components:
            pkg_version = component.version
            pkg_name = component.name

            with VulnerabilityDB(db_path=self.db_path, package_folder=self.vulners_package_dir) as vulner_db:
                vulnerabilities = vulner_db.get_package_vulnerabilities(pkg_name)

            for vulner in vulnerabilities:
                vulnerability, source, pkg_name, vulnerable_interval = vulner
                is_vulnerable = check_is_vulnerable(pkg_version, vulnerable_interval)
                if not is_vulnerable:
                    continue

                if not self.found_vulnerabilities.get(vulnerability):
                    self.found_vulnerabilities[vulnerability] = dict(
                        id=vulnerability,
                        source=source,
                        soft=[],
                    )

                self.found_vulnerabilities[vulnerability]['soft'].append(
                    DetectedSoftSchema(
                        vulnerable_interval=vulnerable_interval,
                        name=pkg_name,
                        version=pkg_version,
                    )
                )

    def make_report(self) -> None:
        """Метод составления отчета о результатах сканирования"""

        detected_vulnerabilities = []
        for vulner, data in self.found_vulnerabilities.items():
            detected_vulnerabilities.append(
                DetectedVulnerabilitySchema(
                    vulner_id=vulner,
                    source_name=data['source'],
                    affected_soft=data['soft'],
                )
            )

        reporter = Reporter(
            detected_vulnerabilities=detected_vulnerabilities,
            vulnerabilities_package_path=self.vulners_package_dir,
            report_type=self.report_type,
        )

        self.report = reporter.generate_report()
