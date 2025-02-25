import os
import subprocess

import paramiko

from pathlib import Path

from depss.sbom import GeneratorSBOM
from depss.scanner import Scanner
from depss.models import ScanConfig, DetectedVulnerability, DetectedSoft
from depss.config import DATA_DIR
from depss.sbom import ParserSBOM
from depss.db_connector import VulnerabilityDB
from depss.utils import check_is_vulnerable, orjson_load_file
from depss.reporter import Reporter

# CMD = ['cyclonedx-py', 'requirements']
REQUIREMENTS_FILE_PATH = Path('/home/matvey/projects/coffee-socialnetwork/requirements.txt')
HOST = '172.16.160.129'
USER = 'matvey'
PASSWORD = 'P@ssw0rd'
port = 22

COMMAND = 'ls -l /home/matvey/projects/fastapi'
# PROJECT_DIR = '/home/matvey/projects/fastapi'
PROJECT_DIR = '/home/matvey/projects/etlsrc'

# from depss.utils import check_is_vulnerable
from depss.models import VulnerableInterval, VersionBorder

def main() -> None:
    """Главная функция программы"""

    scan_config = ScanConfig(
        host=HOST,
        user=USER,
        secret=PASSWORD,
        project_dir=PROJECT_DIR,
    )

    scanner = Scanner(scan_config=scan_config)

    scanner.save_project_requirements()
    project_dir = DATA_DIR / scanner.config.project_type / scanner.config.project_name

    sbom_generator = GeneratorSBOM(
        source_path=project_dir,
        output_path=project_dir,

    )

    sbom_generator.generate_sbom(is_need_dump_file=True)

    parser = ParserSBOM(project_dir / 'sbom.json')

    components = parser.get_components()

    db_path = Path('/home/motya/malife/projects/depss/vulnerabilities/vulner.db')
    # found_vulnerabilities = []
    vulner_db = VulnerabilityDB(db_path)
    # with VulnerabilityDB(db_path=db_path) as vulner_db:

    found_vulnerabilities = {}
    for component in components:
        pkg_version = component.version
        pkg_name = component.name

        vulnerabilities = vulner_db.get_package_vulnerabilities(pkg_name)
        for vulner in vulnerabilities:
            vulnerability, source, pkg_name, vulnerable_interval = vulner
            is_vulnerable = check_is_vulnerable(pkg_version, vulnerable_interval)
            if is_vulnerable:
                if not found_vulnerabilities.get(vulnerability):
                    found_vulnerabilities[vulnerability] = {
                        'id': vulnerability,
                        'source': source,
                        'soft': []
                    }
                found_vulnerabilities[vulnerability]['soft'].append(
                    DetectedSoft(
                        vulnerable_interval=vulnerable_interval,
                        pkg_name=pkg_name,
                        pkg_version=pkg_version,
                    )
                )

    detected_vulnerabilities = []
    for vulner, data in found_vulnerabilities.items():
        detected_vulnerabilities.append(
            DetectedVulnerability(
                vulner_id=vulner,
                source_name=data['source'],
                affected_soft=data['soft'],
            )
        )

    vulner_db.connection.close()

    reporter = Reporter(
        detected_vulnerabilities=detected_vulnerabilities
    )

    report = reporter.generate_report()

    from pprint import pprint

    pprint(report)


if __name__ == '__main__':
    main()
