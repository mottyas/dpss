"""
Модуль со вспомогательным инструментарием
"""

import json
import shutil
from pathlib import Path

import orjson


def make_path_from_str(path_string: str | Path) -> Path:
    """
    Функция конвертации пути из строки в Path

    :param path_string: Путь
    :return: Конвертированный путь в объект Path
    """

    if isinstance(path_string, str):
        path_string = Path(path_string)

    return path_string


def prepare_output_dir(
    dir_name: Path | str,
    parents: bool = True,
    exist_ok: bool = True,
) -> None:
    """
    Функция создания выходных директорий.

    :param dir_name: Путь с конечной директорией, которую требуется создать.
    :param parents: Флаг необходимости создания родительских директорий (по умолчанию True).
    :param exist_ok: Флаг необходимости создания директории, если она уже существует (по умолчанию True).
    """

    dir_name = make_path_from_str(dir_name)

    if not dir_name.exists():
        dir_name.mkdir(parents=parents, exist_ok=exist_ok)


def delete_dir(dir_path: str | Path) -> None:
    """
    Удаление директории всех вложенных директорий с файлами.

    :param dir_path: Путь директории, которую необходимо удалить.
    """

    dir_path = make_path_from_str(dir_path)

    if not dir_path.exists():
        return

    shutil.rmtree(dir_path)


def orjson_dump_file(
    output_dir: Path | str,
    filename: str,
    data: dict | list[dict | str],
    options: int | None = orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
) -> None:
    """
    Выгрузка данных в JSON с помощью модуля orjson.

    :param output_dir: Директория, в которую будет сохранен файл
    :param filename: Имя файла.
    :param data: Данные для сохранения, в формате словаря или объекта DocumentModel.
    :param options: Опции сериализации (по умолчанию orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS).
    """

    output_dir = make_path_from_str(output_dir)
    prepare_output_dir(output_dir)

    if not filename.lower().endswith('.json'):
        filename = f'{filename}.json'

    serialized_data = orjson.dumps(data, option=options)

    path_to_file = output_dir / filename
    path_to_file.write_bytes(serialized_data)


def write_file(
    output_dir: Path | str,
    filename: str,
    data: str,
    mode: str = 'w',
    encoding: str | None = 'UTF-8',
    errors: str | None = 'ignore',
) -> None:
    """
    Запись в текстовый файл.

    :param output_dir: Директория, в которую будет сохранен файл.
    :param filename: Имя файла.
    :param data: Данные для сохранения.
    :param mode: Режим записи (по умолчанию 'w').
    :param encoding: Кодировка (по умолчанию 'UTF-8').
    :param errors: Обработка ошибок (по умолчанию 'ignore').
    :return: None
    """

    output_dir = make_path_from_str(output_dir)
    prepare_output_dir(output_dir)
    output_dir = output_dir / filename

    with output_dir.open(mode=mode, encoding=encoding, errors=errors) as _file:
        _file.write(data)


def orjson_load_file(path_to_file: Path | str) -> dict | list[dict | str]:
    """
    Чтение JSON файла с помощью модуля orjson.

    :param path_to_file: Путь к файлу.
    :return: Данные файла в виде словаря.
    """

    path_to_file = make_path_from_str(path_to_file)
    data: dict = orjson.loads(path_to_file.read_bytes())
    return data
