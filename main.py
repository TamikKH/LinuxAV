import sys
import os


def is_root():
    """Проверка прав root"""
    return os.geteuid() == 0


def check_platform():
    """Проверка платформы"""
    if not sys.platform.startswith("linux"):
        print("Этот антивирус предназначен для Linux!")
        sys.exit(1)


def check_python_version():
    if sys.version_info < (3, 8):
        print("Требуется Python 3.8+")
        sys.exit(1)


def main():
    print("=" * 50)
    print("LinuxAV - Антивирус для Linux")
    print("Версия 1.0.0")
    print("=" * 50)

    check_platform()
    check_python_version()

    if not is_root():
        print("⚠️ Рекомендуется запуск от root (sudo)")

    try:
        from gui import LinuxAVApp
        app = LinuxAVApp(sys.argv)
        app.run()
    except ImportError as e:
        print(f"Ошибка импорта: {e}")
        print("pip install PySide6 psutil requests")
        sys.exit(1)


if __name__ == "__main__":
    main()
