"""
Модуль с настройками конфигурации
"""

import os
from pathlib import Path

DATA_DIR = Path(os.getenv('DATA_DIR', './'))
