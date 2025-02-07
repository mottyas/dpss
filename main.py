import os
import subprocess

import paramiko

from pathlib import Path
from depss.sbom import GeneratorSBOM

from depss.scanner import Scanner
from depss.models import ScanConfig
from depss.config import DATA_DIR
from depss.sbom import ParserSBOM

# CMD = ['cyclonedx-py', 'requirements']
REQUIREMENTS_FILE_PATH = Path('/home/matvey/projects/coffee-socialnetwork/requirements.txt')
HOST = '172.16.160.129'
USER = 'matvey'
PASSWORD = 'P@ssw0rd'
port = 22

COMMAND = 'ls -l /home/matvey/projects/fastapi'
# PROJECT_DIR = '/home/matvey/projects/fastapi'
PROJECT_DIR = '/home/matvey/projects/coffee-socialnetwork'


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

    for component in components:
        print(component.purl)


if __name__ == '__main__':
    main()
