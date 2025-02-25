import sqlite3
from pathlib import Path
from depss.utils import orjson_dump_file, orjson_load_file

CREATE_TABLE_PACKAGES = '''
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY,
    vulnerability TEXT NOT NULL,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    opener TEXT NOT NULL,
    version_left TEXT NOT NULL,
    version_right TEXT NOT NULL,
    closer TEXT NOT NULL
);
'''

# Создаем индекс для столбца "email"
CREATE_INDEX_PACKAGES = 'CREATE INDEX idx_name ON packages (name);'

INSERT_PACKAGE_INFO = '''
INSERT INTO packages (vulnerability, source, name, opener, version_left, version_right, closer)
VALUES (?, ?, ?, ?, ?, ?, ?);
'''

PACKAGES_FOLDER = Path('../vulnerabilities/packages/pyup-1.20250224.001/content')


def prepare_data() -> list[tuple]:

    result_data = []
    for file_path in PACKAGES_FOLDER.iterdir():
        # if file_path.name == 'status.json':
        #     continue
        data = orjson_load_file(file_path)
        # print(data)

        vulner_id = data['identifier']
        source_name = 'PyUp'
        for package in data['affects']:
            name = package['name']
            end_condition = package['version']['end_condition']
            end_value = package['version']['end_value']
            start_condition = package['version']['start_condition']
            start_value = package['version']['start_value']
            result_data.append(
                (
                    vulner_id,
                    source_name,
                    name,
                    start_condition,
                    start_value,
                    end_value,
                    end_condition,
                )
            )
    return result_data


def main() -> None:

    prepared_data = prepare_data()
    with sqlite3.connect('../vulnerabilities/vulner.db') as connection:
        cursor = connection.cursor()
        cursor.execute(CREATE_TABLE_PACKAGES)
        cursor.execute(CREATE_INDEX_PACKAGES)
        connection.commit()

        cursor.executemany(INSERT_PACKAGE_INFO, prepared_data)
        connection.commit()


if __name__ == '__main__':
    main()
