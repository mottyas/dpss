"""
Модуль с настройками конфигурации
"""

import os
from pathlib import Path

DATA_DIR = Path(os.getenv('DATA_DIR', './'))
PYTHON_PACKAGE_VULNERS_DIR = Path('/home/motya/malife/projects/depss/vulnerabilities/packages/pyup-1.20250224.001/content/')
