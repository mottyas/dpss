"""Скрипт Setup.py для проекта по упаковке."""

from setuptools import setup, find_packages

REQUIREMENTS = 'requirements.txt'


def get_package_version():
    return '0.0.0'


def get_requirements(requirements_file: str = REQUIREMENTS) -> list[str]:
    """
    Функция получения пакетов из requirements.txt

    :param requirements_file: Путь до файла с requirements
    :return: Список собранных requirements
    """

    requirements = []
    with open(requirements_file) as _file:
        requirements_file_data = _file.read()
        for requirement in requirements_file_data.split('\n'):
            if requirement := requirement.split('==')[0]:
                requirements.append(requirement)

    return requirements


if __name__ == '__main__':
    setup(
        name='depss',
        python_requires='>=3.12.0',
        version=get_package_version(),
        description='Software Composition Analysis package to protect your project from vulnerable dependencies.',
        license='',
        url='https://github.com/mottyas/depss',
        download_url='https://github.com/mottyas/depss/archive/refs/heads/main.zip',
        entry_points={},
        classifiers=[
            'Intended Audience :: Developers',
            'Programming Language :: Python :: 3.12'
        ],
        keywords=[
            'vulnerabilities',
            'package',
            'dependencies',
            'software bill of materials',
            'component',
            'software composition analysis',
        ],
        packages=find_packages(exclude=('*test*',)),
        package_data={'': ['template.html']},
        include_package_data=True,
        tests_require=['pytest', ],
        install_requires=get_requirements(),
    )
