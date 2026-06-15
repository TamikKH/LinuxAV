# LinuxAV

## 1. Описание проекта

LinuxAV — антивирусное решение для операционных систем Linux с графическим интерфейсом на PySide6. Приложение предназначено для обнаружения и нейтрализации вредоносного ПО в Linux-окружении.

Приложение включает:

- сканирование файловой системы (быстрое, полное, выборочное);
- обнаружение угроз по сигнатурам, хешам и поведенческому анализу;
- карантин с возможностью восстановления файлов;
- обновление баз сигнатур из интернета;
- кэширование результатов для ускорения повторных сканирований;
- анализ ELF-файлов (бинарный анализ, энтропия, подозрительные секции);
- сканирование оперативной памяти на наличие активных угроз;
- песочницу для безопасного выполнения подозрительных файлов;
- гибкие настройки (исключения, глубина сканирования, размер файлов).

## 2. Технологический стек

**Frontend / GUI**

- PySide6 (Qt6)

**Backend / Анализ**

- SQLite — базы данных сигнатур, белого списка, кэша
- pyelftools — анализ ELF-файлов
- psutil — системные вызовы, процессы, память
- python-magic — определение MIME-типов

**Дополнительно**

- subprocess + tempfile — песочница для выполнения файлов
- requests — обновление сигнатур по HTTP
- hashlib — вычисление хешей файлов

## 3. Функциональность

### 3.1 Сканирование

Пользователь может:

- выполнить быстрое сканирование системных директорий;
- выполнить полное сканирование всей корневой файловой системы;
- выполнить сканирование выбранной пользователем директории;
- отслеживать прогресс сканирования (текущий файл, общее количество);
- просматривать результаты сканирования с цветовой маркировкой по серьезности.

Типы сканирования:

| Тип | Область сканирования | Глубина | Ограничение по файлам |
|-----|---------------------|---------|----------------------|
| Быстрое | /bin, /usr, /home, /etc, /tmp | 5 уровней | 1000 файлов |
| Полное | Корневая директория (/) | Неограниченно | 10000 файлов |
| Выборочное | Выбранная пользователем директория | Неограниченно | 2000 файлов |

### 3.2 Обнаружение угроз

**По сигнатурам**

Пользователь может обнаруживать:

- EICAR тестовый файл;
- Meterpreter стейджер Metasploit;
- Shellcode XOR декодер;
- записки ransomware;
- Mimikatz инструмент дампа паролей.

**Поведенческий анализ (Linux специфичный)**

Обнаруживаются:

- команды удаления данных (rm -rf /, mkfs);
- криптомайнеры (xmrig, cpuminer, stratum+tcp);
- reverse shell (bash -i >& /dev/tcp/, nc -e /bin/sh);
- автоматическая загрузка и запуск кода (wget + chmod + x).

**Анализ ELF-файлов**

Анализируются:

- RWX секции (память с правами чтение/запись/исполнение);
- высокая энтропия (более 7) — упакованные или зашифрованные секции;
- entry point вне .text — подозрительная точка входа;
- анти-отладка (строки ptrace, strace, gdb);
- подозрительные символы (ptrace, mprotect, socket, execve).

### 3.3 Карантин

Пользователь может:

- помещать зараженные файлы в изолированное хранилище;
- восстанавливать файлы из карантина в исходное местоположение;
- безвозвратно удалять файлы из карантина;
- просматривать метаданные: оригинальный путь, причина, дата, хеш.

### 3.4 Базы данных

Используются две базы данных SQLite:

**signatures.db**

Таблицы:
- signatures — хранение сигнатур (id, name, type, pattern, hash, description, severity, created);
- whitelist — белый список доверенных файлов (id, path, hash, reason, added).

**cache.db**

Таблицы:
- scan_cache — кэш результатов сканирования (path, hash, last_scan, threat_level).

### 3.5 Песочница

Пользователь может безопасно выполнять подозрительные файлы с ограничениями:

- временная директория для изолированного выполнения;
- ограничение времени выполнения (15 секунд по умолчанию);
- захват stdout, stderr и кода возврата;
- автоматическая очистка временных файлов после выполнения.

### 3.6 Сканирование памяти

Пользователь может:

- обнаруживать криптомайнеры по имени процесса;
- находить майнеры в командной строке по ключевым словам (stratum, pool);
- мониторить процессы в реальном времени через psutil.

## 4. Структура проекта
```python
linuxav/
├── main.py
├── gui.py
├── scanner.py
├── signatures.py 
├── binary_analyzer.py 
├── quarantine.py 
├── sandbox.py 
├── updater.py
├── utils.py 
├── config.py 
└── data/ 
    ├── signatures.db 
    ├── cache.db 
    ├── quarantine/ 
    └── logs/ 
```

**Директории данных**

| Путь | Назначение |
|------|------------|
| ~/.local/share/linuxav/ | Пользовательские данные (БД, карантин) |
| /opt/linuxav/ | Программные файлы (установка) |
| /tmp/linuxav/ | Временные файлы |

---

## 5. Установка и запуск

### 5.1 Установка зависимостей

```bash
pip install PySide6 python-magic pyelftools psutil requests
```

### 5.2 Переменные окружения
Переменные окружения не требуются. Все настройки хранятся в config.py и файле конфигурации пользователя.

### 5.3 Запуск в режиме разработки
```bash
python3 main.py
```

### 5.4 Запуск с правами root (рекомендуется)
```bash
sudo python3 main.py
```
### 5.5 Сборка проекта
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name LinuxAV main.py
```
### 5.6 Предпросмотр собранной версии
```bash
./dist/LinuxAV
```
## 6. Архитектура приложения
### 6.1 Точка входа
Файл main.py проверяет:

- платформу (только Linux);
- версию Python (3.8 и выше);
- права root (выводит предупреждение при отсутствии);
- импортирует и запускает GUI приложение.

### 6.2 Маршрутизация
Приложение использует QTabWidget с вкладками:

Сканирование — основная вкладка сканирования файлов;
Карантин — управление карантинными файлами;
Сигнатуры — управление базой сигнатур;
Настройки — конфигурация приложения.

### 6.3 Защита данных
RLS-политики не используются (локальное приложение);
доступ к файлам ограничен правами ОС Linux;
для сканирования системных файлов требуются права root.

### 6.4 Контекст приложения
Главный класс LinuxAVApp хранит:

signature_manager — менеджер сигнатур;
scanner — сканер файлов;
updater — менеджер обновлений;
quarantine — менеджер карантина;
window — главное окно.

### 6.5 Система оценки угроз (ELF)
Компонент	Вес
Каждый индикатор подозрительности	3
RWX секция	10
Высокая энтропия (>7)	5
Наличие URL/IP	10
Anti-analysis (ptrace + mprotect)	15
Сетевая активность	10
Выполнение команд	20
Reverse shell	30
Downloader	20
Уровни угроз

Critical >= 40
High >= 25
Medium >= 15
Low >= 5
Clean < 5

## 7. Модули и компоненты
### 7.1 SignatureManager (signatures.py)
Назначение: Управление базами сигнатур, белым списком, кэшем.

Методы:

- check_hash(file_hash) — поиск по хешу
- check_content(file_data) — поиск по содержимому
- add_signature() — добавление новой сигнатуры
- remove_signature() — удаление сигнатуры
- get_all_signatures() — получение всех сигнатур
- add_to_whitelist(path, reason) — добавление в белый список
- is_whitelisted(file_path) — проверка в белом списке
- update_cache() — обновление кэша
- get_cached_result() — получение из кэша
- update_from_server(url) — обновление с сервера
- get_statistics() — получение статистики

Пример использования:

python
signature_manager = SignatureManager("/path/to/data")
threat = signature_manager.check_hash(file_hash)
if threat:
    print(f"Найдена угроза: {threat['name']}")
7.2 LinuxAVScanner (scanner.py)
Назначение: Ядро сканирования, координация проверок.

Атрибуты:

max_file_size — максимальный размер файла (по умолчанию 50 МБ)

scan_depth — глубина анализа (0=быстрое, 1=обычное, 2=глубокое)

cache_enabled — флаг кэширования (True/False)

trusted_system_dirs — множество доверенных системных директорий

trusted_patterns — список доверенных системных файлов

Методы:

scan_path(path, scan_type, progress_callback) — сканирование директории

scan_memory() — сканирование оперативной памяти

_scan_file(file_path) — сканирование одного файла

_deep_analyze_linux_file(path, data) — углубленный анализ

_is_trusted_system_file(file_path) — проверка системного файла

_is_safe_script_content(content) — проверка безопасности скрипта

_collect_files(paths, limit) — сбор файлов для сканирования

_calculate_hash(file_path) — вычисление SHA256

Пример использования:

python
scanner = LinuxAVScanner(signature_manager)
results = scanner.scan_path("/home/user", scan_type="quick")
print(f"Найдено угроз: {results['threats_found']}")
7.3 BinaryAnalyzer (binary_analyzer.py)
Назначение: Анализ ELF-файлов с помощью pyelftools.

Атрибуты:

suspicious_symbols — множество подозрительных символов

anti_analysis_indicators — индикаторы анти-отладки

Методы:

analyze(file_path, file_data) — полный анализ ELF-файла

_extract_features(elf) — извлечение характеристик

_extract_strings(file_path, file_data, min_len) — извлечение строк

_detect_iocs(strings) — обнаружение IOC

_detect_indicators(features, strings) — обнаружение индикаторов

_correlate_behaviors(features, strings) — корреляция поведений

_calculate_score_v2(features, indicators, behaviors, iocs) — расчет score

_determine_threat_level(score) — определение уровня угрозы

Пример использования:

python
analyzer = BinaryAnalyzer()
result = analyzer.analyze("/path/to/executable")
print(f"Score: {result['score']}, Level: {result['threat_level']}")
7.4 QuarantineManager (quarantine.py)
Назначение: Изолированное хранение угроз.

Атрибуты:

quarantine_dir — директория карантина

metadata_file — файл с метаданными

Методы:

quarantine_file(file_path, reason) — помещение в карантин

restore_file(file_hash) — восстановление из карантина

delete_file(file_hash) — полное удаление

list_quarantine() — список всех файлов в карантине

_load_metadata() — загрузка метаданных

_save_metadata(metadata) — сохранение метаданных

_calculate_hash(file_path) — вычисление SHA256

Пример использования:

python
quarantine = QuarantineManager("/path/to/quarantine")
success, path = quarantine.quarantine_file("/malware/file", "Обнаружен троян")
7.5 Sandbox (sandbox.py)
Назначение: Безопасное выполнение подозрительных файлов.

Атрибуты:

timeout — таймаут выполнения (по умолчанию 15 секунд)

Методы:

execute_file(file_path) — выполнение файла в песочнице

Возвращаемый результат:

python
{
    "success": True/False,
    "return_code": 0,
    "stdout": "output text",
    "stderr": "error text",
    "execution_time": 1.23,
    "error": "error message"
}
Пример использования:

python
sandbox = Sandbox(timeout=10)
result = sandbox.execute_file("/path/to/suspicious")
if result["success"]:
    print(f"Вывод: {result['stdout']}")
7.6 UpdateManager (updater.py)
Назначение: Обновление баз сигнатур из интернета.

Атрибуты:

update_url — URL для загрузки обновлений

local_db_path — путь к локальной базе сигнатур

Методы:

update_signatures() — обновление сигнатур

signatures_exist() — проверка существования базы

get_signature_size() — получение размера базы

Пример использования:

python
updater = UpdateManager("https://example.com/signatures.db", "signatures.db")
result = updater.update_signatures()
if result["success"]:
    print("Сигнатуры обновлены")
7.7 ConfigManager (config.py)
Назначение: Управление конфигурацией приложения.

Настройки по умолчанию:

python
{
    "app_name": "LinuxAV",
    "version": "1.0.0",
    "data_dir": "~/.local/share/linuxav",
    "program_dir": "/opt/linuxav",
    "scan": {
        "quick_scan_paths": ["/bin", "/usr", "/home", "/etc", "/tmp"],
        "excluded_paths": ["/proc", "/sys", "/dev", "/run"]
    }
}
Методы:

load() — загрузка конфигурации из файла

save() — сохранение конфигурации в файл

7.8 Утилиты (utils.py)
Назначение: Вспомогательные функции.

Функции:

is_executable(file_path) — проверка, является ли файл исполняемым

get_file_type(file_path) — определение MIME-типа файла

normalize_path_for_db(path) — нормализация пути для БД
