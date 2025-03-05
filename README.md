# Dependency security screening system (depss)

## Краткое описание

Данный проект является частью моей магистерской работы. 
Depss - это библиотека, в которой заложена базовая логика 
работы связанная с поиском уязвимостей в проектах написанных 
на python (пока что), а именно анализ зависимостей в проект (SCA).

## Примеры использования

### Создание конфигурации сканирования и запуск

Пример:

```python
from depss.models import ScanConfigSchema
from depss.scanner import Scanner

# Создаем конфигурацию сканирования
scan_config = ScanConfigSchema(
    host='localhost',
    user='user',
    secret='password',
    project_dir='/home/user/projects/some-project',
)

# Создаем объект сканера, передав ему конфиг
scanner = Scanner(scan_config=scan_config)
scanner.save_project_requirements()

```

### Генерация SBOM и сохранение в файл

```python
from depss.sbom import GeneratorSBOM

# Создаем объект генератора
sbom_generator = GeneratorSBOM(
    source_path='/home/user/projects/some-project',
    output_path='/home/user/projects/some-project',
)

# Генерируем SBOM из файла requirements.txt сохраненного выше
sbom_generator.generate_sbom(is_need_dump_file=True)
```

### Использование парсера SBOM

Для удобства получения данных из SBOM можно воспользоваться парсером:
```python
from depss.sbom import ParserSBOM

parser = ParserSBOM('project_dir/sbom.json')

# Получаем компоненты из SBOM с помощью парсера
components = parser.get_components()
```

### Работа с базой данных и анализатором

Для того чтобы проанализировать сгенерированный SBOM файл:
```python
from depss.sbom import ComponentsAnalyzer

sbom_analyzer = ComponentsAnalyzer(
    sbom_source='project_dir/sbom.json',
    db_path='some/path/to/vulner.db',
    package_folder='some/path/to/package/',
)

report = sbom_analyzer.fast_check()

print(report)
```