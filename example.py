import os
from pathlib import Path
from pprint import pprint

from dpss.models import ScanConfigSchema, ProjectConfigSchema, ProjectTypes
from dpss.dpss import DependencySecurityScanner


DATA_DIR = os.getenv('DATA_DIR')

HOST = os.getenv('HOST')
USER = os.getenv('USER')
PASSWORD = os.getenv('PASSWORD')
PORT = os.getenv('PORT')

PROJECT_DIR = os.getenv('PROJECT_DIR')
PACKAGE_FOLDER = os.getenv('PACKAGE_FOLDER')
DB_PATH = os.getenv('DB_PATH')


def main() -> None:
    """Главная функция программы"""

    project_config = ProjectConfigSchema(
        name='first_proj',
        type=ProjectTypes.PYTHON,
        dir=PROJECT_DIR,
        description='first_proj',
    )

    scan_config = ScanConfigSchema(
        host=HOST,
        user=USER,
        secret=PASSWORD,
        name='first_scan',
        projects=[project_config],
    )

    dpss = DependencySecurityScanner(
        scan_config=scan_config,
        db_path=DB_PATH,
        vulners_package_dir=Path(PACKAGE_FOLDER),
        data_dir=Path(DATA_DIR),
    )

    dpss.run()

    pprint(dpss.report)


if __name__ == '__main__':
    main()
