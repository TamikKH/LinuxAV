import os
from pathlib import Path

def is_executable(file_path):
    """Проверка, является ли файл исполняемым"""
    return os.access(file_path, os.X_OK)

def get_file_type(file_path):
    """Определение типа файла"""
    import magic
    try:
        mime = magic.from_file(file_path, mime=True)
        return mime
    except:
        # fallback по расширению
        ext = Path(file_path).suffix.lower()
        mime_map = {
            '.sh': 'text/x-shellscript',
            '.py': 'text/x-python',
            '.pl': 'text/x-perl',
            '.so': 'application/x-sharedlib',
            '.bin': 'application/x-executable',
            '': 'application/x-executable'
        }
        return mime_map.get(ext, 'application/octet-stream')

def normalize_path_for_db(path):
    """Нормализация пути для БД"""
    return str(Path(path).resolve())