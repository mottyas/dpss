import enum
from datetime import datetime

from depss.config import PYTHON_PACKAGE_VULNERS_DIR
from depss.const import TIMESTAMP_FORMAT
from depss.utils import orjson_load_file
from depss.models import (
    DetectedVulnerability,
    ReportModel,
    AffectedSoft,
    Rating,
    VulnerDataModel,
)

class ReportTypes(enum.StrEnum):
    """Типы отчетов"""

    JSON: str = 'json'
    HTML: str = 'html'
    MARKDOWN: str = 'markdown'


class Reporter:
    """Класс работы с отчетами"""

    def __init__(
            self,
            detected_vulnerabilities: list[DetectedVulnerability],
            report_type: str = ReportTypes.JSON,
    ) -> None:
        """
        Инициализация класса

        :param detected_vulnerabilities: Список найденных уязвимостей
        :param report_type: Тип отчета
        """

        self.type = report_type
        self.vulnerabilities = detected_vulnerabilities

    def generate_report(self) -> ReportModel | str | None:
        """Метод генерации отчета"""

        match self.type:
            case ReportTypes.JSON:
                return self.__generate_report_json()
            case ReportTypes.HTML:
                return self.__generate_report_html()
            case ReportTypes.MARKDOWN:
                return self.__generate_report_markdown()

    def __generate_report_html(self) -> str:
        """Метод генерации отчета"""

        pass

    def __generate_report_markdown(self) -> str:
        """Метод генерации отчета"""

        pass

    def __generate_report_json(self) -> ReportModel:
        """Метод генерации отчета"""


        report = ReportModel(
            creation_date=datetime.now().strftime(TIMESTAMP_FORMAT),
        )
        for vulner in self.vulnerabilities:
            file_name = f'{vulner.source_name}.{vulner.vulner_id}.{vulner.vulner_id}.json'
            pkg_vulner_data = orjson_load_file(PYTHON_PACKAGE_VULNERS_DIR / file_name)
            ratings = []
            for rating in pkg_vulner_data['ratings']:
                ratings.append(
                    Rating(
                        method='CVSS',
                        score=rating['score'],
                        severity=rating['severity'],
                        source_name=rating['source_name'],
                        source_url=rating['source_url'],
                        vector=rating['vector'],
                        version=rating['version'],
                    )
                )

            affected_soft = []
            for soft in vulner.affected_soft:
                affected_soft.append(
                    AffectedSoft(
                        name=soft.pkg_name,
                        pkg_version=soft.pkg_version,
                        vulnerable_interval=soft.vulnerable_interval,
                    )
                )

            report.vulnerabilities.append(
                VulnerDataModel(
                    identifier=pkg_vulner_data['identifier'],
                    published=pkg_vulner_data['published'],
                    source_name=pkg_vulner_data['source'][0]['source_name'],
                    source_url=pkg_vulner_data['source'][0]['source_url'],
                    description=pkg_vulner_data['description'],
                    affected_packages=affected_soft,
                    cwes=pkg_vulner_data['cwes'],
                    ratings=ratings,
                    references=pkg_vulner_data['references'],
                )
            )

        return report
