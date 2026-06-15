from PySide6.QtWidgets import *
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction

from scanner import LinuxAVScanner
from signatures import SignatureManager
from updater import UpdateManager
from quarantine import QuarantineManager
from config import get_user_data_dir


class ScanThread(QThread):
    progress = Signal(int, int, str)
    result = Signal(dict)
    finished = Signal()
    error = Signal(str)

    def __init__(self, scanner, path, scan_type="quick"):
        super().__init__()
        self.scanner = scanner
        self.path = path
        self.scan_type = scan_type

    def run(self):
        try:
            results = self.scanner.scan_path(
                self.path,
                scan_type=self.scan_type,
                progress_callback=self._progress_callback
            )
            self.result.emit(results)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()

    def _progress_callback(self, current, total, current_file):
        self.progress.emit(current, total, current_file)


class LinuxAVApp:
    def __init__(self, argv):
        self.app = QApplication(argv)

        self.data_dir = get_user_data_dir()
        self.signature_manager = SignatureManager(self.data_dir)
        self.scanner = LinuxAVScanner(self.signature_manager)
        self.updater = UpdateManager("https://example.com/updates", self.data_dir / "signatures.db")
        self.quarantine = QuarantineManager(self.data_dir / "quarantine")

        self.window = MainWindow(self)
        self.window.setWindowTitle("LinuxAV - Антивирус для Linux")
        self.window.resize(1200, 800)

    def run(self):
        self.window.show()
        return self.app.exec()


class MainWindow(QMainWindow):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setup_ui()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        self.create_menu()
        self.tab_widget = QTabWidget()

        self.scan_tab = QWidget()
        self.setup_scan_tab()
        self.tab_widget.addTab(self.scan_tab, "🔍 Сканирование")

        self.quarantine_tab = QWidget()
        self.setup_quarantine_tab()
        self.tab_widget.addTab(self.quarantine_tab, "🛡️ Карантин")

        self.signatures_tab = QWidget()
        self.setup_signatures_tab()
        self.tab_widget.addTab(self.signatures_tab, "📋 Сигнатуры")

        self.settings_tab = QWidget()
        self.setup_settings_tab()
        self.tab_widget.addTab(self.settings_tab, "⚙️ Настройки")

        main_layout.addWidget(self.tab_widget)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Готов к сканированию")

    def create_menu(self):
        menubar = self.menuBar()

        # Файл меню
        file_menu = menubar.addMenu("📁 Файл")

        exit_action = QAction("Выход", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Сервис меню
        service_menu = menubar.addMenu("🛠️ Сервис")

        update_action = QAction("Обновить сигнатуры", self)
        update_action.triggered.connect(self.update_signatures)
        service_menu.addAction(update_action)

        # Справка меню
        help_menu = menubar.addMenu("❓ Справка")

        about_action = QAction("О программе", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def setup_scan_tab(self):
        layout = QVBoxLayout(self.scan_tab)

        # Панель выбора пути
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Путь для сканирования:"))

        self.path_input = QLineEdit("/home")
        path_layout.addWidget(self.path_input)

        self.browse_btn = QPushButton("Обзор")
        self.browse_btn.clicked.connect(self.browse_path)
        path_layout.addWidget(self.browse_btn)

        layout.addLayout(path_layout)

        # Кнопки сканирования
        buttons_layout = QHBoxLayout()

        self.quick_scan_btn = QPushButton("🚀 Быстрое сканирование")
        self.quick_scan_btn.clicked.connect(lambda: self.start_scan("quick"))
        buttons_layout.addWidget(self.quick_scan_btn)

        self.full_scan_btn = QPushButton("🔍 Полное сканирование")
        self.full_scan_btn.clicked.connect(lambda: self.start_scan("full"))
        buttons_layout.addWidget(self.full_scan_btn)

        self.custom_scan_btn = QPushButton("📁 Сканировать выбранный путь")
        self.custom_scan_btn.clicked.connect(lambda: self.start_scan("custom"))
        buttons_layout.addWidget(self.custom_scan_btn)

        layout.addLayout(buttons_layout)

        # Прогресс бар
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Текущий файл
        self.current_file_label = QLabel("Готов к сканированию")
        layout.addWidget(self.current_file_label)

        # Результаты сканирования
        layout.addWidget(QLabel("Результаты сканирования:"))

        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Путь к файлу", "Угроза", "Серьезность", "Дата"])
        self.results_tree.setAlternatingRowColors(True)
        layout.addWidget(self.results_tree)

        # Кнопки действий с результатами
        results_buttons = QHBoxLayout()

        self.quarantine_selected_btn = QPushButton("Поместить в карантин")
        self.quarantine_selected_btn.clicked.connect(self.quarantine_selected)
        results_buttons.addWidget(self.quarantine_selected_btn)

        self.ignore_selected_btn = QPushButton("Игнорировать")
        self.ignore_selected_btn.clicked.connect(self.ignore_selected)
        results_buttons.addWidget(self.ignore_selected_btn)

        self.clear_results_btn = QPushButton("Очистить результаты")
        self.clear_results_btn.clicked.connect(self.clear_results)
        results_buttons.addWidget(self.clear_results_btn)

        layout.addLayout(results_buttons)

    def setup_quarantine_tab(self):
        layout = QVBoxLayout(self.quarantine_tab)

        # Кнопки управления карантином
        buttons_layout = QHBoxLayout()

        self.refresh_quarantine_btn = QPushButton("🔄 Обновить список")
        self.refresh_quarantine_btn.clicked.connect(self.refresh_quarantine)
        buttons_layout.addWidget(self.refresh_quarantine_btn)

        self.restore_btn = QPushButton("↩️ Восстановить")
        self.restore_btn.clicked.connect(self.restore_from_quarantine)
        buttons_layout.addWidget(self.restore_btn)

        self.delete_quarantine_btn = QPushButton("🗑️ Удалить навсегда")
        self.delete_quarantine_btn.clicked.connect(self.delete_from_quarantine)
        buttons_layout.addWidget(self.delete_quarantine_btn)

        layout.addLayout(buttons_layout)

        # Список карантина
        self.quarantine_list = QTreeWidget()
        self.quarantine_list.setHeaderLabels(["Хеш", "Оригинальный путь", "Причина", "Дата"])
        self.quarantine_list.setAlternatingRowColors(True)
        layout.addWidget(self.quarantine_list)

        # Информационная панель
        self.quarantine_info = QTextEdit()
        self.quarantine_info.setMaximumHeight(100)
        self.quarantine_info.setReadOnly(True)
        layout.addWidget(self.quarantine_info)

        # Загружаем данные
        self.refresh_quarantine()

    def setup_signatures_tab(self):
        layout = QVBoxLayout(self.signatures_tab)

        # Верхняя панель
        top_panel = QHBoxLayout()

        self.add_signature_btn = QPushButton("➕ Добавить сигнатуру")
        self.add_signature_btn.clicked.connect(self.add_signature_dialog)
        top_panel.addWidget(self.add_signature_btn)

        self.remove_signature_btn = QPushButton("➖ Удалить сигнатуру")
        self.remove_signature_btn.clicked.connect(self.remove_signature)
        top_panel.addWidget(self.remove_signature_btn)

        self.update_signatures_btn = QPushButton("🔄 Обновить из сети")
        self.update_signatures_btn.clicked.connect(self.update_signatures)
        top_panel.addWidget(self.update_signatures_btn)

        layout.addLayout(top_panel)

        # Статистика
        stats_group = QGroupBox("Статистика")
        stats_layout = QHBoxLayout()

        self.stats_label = QLabel("Загрузка статистики...")
        stats_layout.addWidget(self.stats_label)

        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        # Список сигнатур
        layout.addWidget(QLabel("База сигнатур:"))

        self.signatures_list = QTreeWidget()
        self.signatures_list.setHeaderLabels(["ID", "Название", "Тип", "Серьезность", "Описание"])
        self.signatures_list.setAlternatingRowColors(True)
        layout.addWidget(self.signatures_list)

        # Загружаем сигнатуры
        self.refresh_signatures()

    def setup_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)

        # Настройки сканирования
        scan_group = QGroupBox("Настройки сканирования")
        scan_layout = QGridLayout()

        scan_layout.addWidget(QLabel("Максимальный размер файла (МБ):"), 0, 0)
        self.max_file_size = QSpinBox()
        self.max_file_size.setRange(1, 500)
        self.max_file_size.setValue(50)
        scan_layout.addWidget(self.max_file_size, 0, 1)

        scan_layout.addWidget(QLabel("Глубина сканирования:"), 1, 0)
        self.scan_depth = QComboBox()
        self.scan_depth.addItems(["Быстрое", "Обычное", "Глубокое"])
        scan_layout.addWidget(self.scan_depth, 1, 1)

        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)

        # Системные пути (исключения)
        exceptions_group = QGroupBox("Исключения (доверенные пути)")
        exceptions_layout = QVBoxLayout()

        self.exceptions_list = QListWidget()
        self.load_exceptions()
        exceptions_layout.addWidget(self.exceptions_list)

        exceptions_buttons = QHBoxLayout()

        self.add_exception_btn = QPushButton("➕ Добавить путь")
        self.add_exception_btn.clicked.connect(self.add_exception_path)
        exceptions_buttons.addWidget(self.add_exception_btn)

        self.remove_exception_btn = QPushButton("➖ Удалить путь")
        self.remove_exception_btn.clicked.connect(self.remove_exception_path)
        exceptions_buttons.addWidget(self.remove_exception_btn)

        exceptions_layout.addLayout(exceptions_buttons)
        exceptions_group.setLayout(exceptions_layout)
        layout.addWidget(exceptions_group)

        # Настройки кэширования
        cache_group = QGroupBox("Настройки кэширования")
        cache_layout = QVBoxLayout()

        self.enable_cache_checkbox = QCheckBox("✅ Включить кэширование результатов сканирования")
        self.enable_cache_checkbox.setChecked(True)
        cache_layout.addWidget(self.enable_cache_checkbox)

        # Информация о кэше
        self.cache_info_label = QLabel("📊 Загрузка информации о кэше...")
        self.cache_info_label.setWordWrap(True)
        self.cache_info_label.setStyleSheet("color: blue; font-size: 9pt; padding: 5px;")
        cache_layout.addWidget(self.cache_info_label)

        cache_info = QLabel(
            "ℹ️ Кэширование ускоряет повторные сканирования, сохраняя результаты проверки файлов.\n"
            "Рекомендуется оставить включенным для быстрого сканирования."
        )
        cache_info.setWordWrap(True)
        cache_info.setStyleSheet("color: gray; font-size: 10pt;")
        cache_layout.addWidget(cache_info)

        clear_cache_btn = QPushButton("🗑️ Очистить кэш")
        clear_cache_btn.clicked.connect(self.clear_scan_cache)
        clear_cache_btn.setStyleSheet("QPushButton { color: orange; }")
        cache_layout.addWidget(clear_cache_btn)

        cache_group.setLayout(cache_layout)
        layout.addWidget(cache_group)

        # Кнопка сохранения настроек
        self.save_settings_btn = QPushButton("💾 Сохранить настройки")
        self.save_settings_btn.clicked.connect(self.save_settings)
        self.save_settings_btn.setStyleSheet(
            "QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }")
        layout.addWidget(self.save_settings_btn)

        layout.addStretch()

        # Обновляем информацию о кэше при загрузке
        self.refresh_cache_info()

    def browse_path(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите директорию для сканирования")
        if path:
            self.path_input.setText(path)

    def start_scan(self, scan_type):
        if scan_type == "quick":
            path = "/"
        elif scan_type == "custom":
            path = self.path_input.text()
        else:  # full
            path = "/"

        self.results_tree.clear()
        self.progress_bar.setValue(0)

        self.scan_thread = ScanThread(self.app.scanner, path, scan_type)
        self.scan_thread.progress.connect(self.update_scan_progress)
        self.scan_thread.result.connect(self.show_scan_results)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.error.connect(self.scan_error)

        self.scan_thread.start()

        # Блокируем кнопки
        self.quick_scan_btn.setEnabled(False)
        self.full_scan_btn.setEnabled(False)
        self.custom_scan_btn.setEnabled(False)

        self.status_bar.showMessage(f"Сканирование запущено... ({scan_type})")

    def update_scan_progress(self, current, total, current_file):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.current_file_label.setText(f"Сканируется: {current_file}")
        self.status_bar.showMessage(f"Сканирование: {current}/{total} файлов")

    def show_scan_results(self, results):
        threats = results.get("threats", [])

        for threat in threats:
            item = QTreeWidgetItem([
                threat.get("path", ""),
                threat.get("name", ""),
                threat.get("severity", ""),
                threat.get("date", "")
            ])

            # Цветовая маркировка по серьезности
            severity = threat.get("severity", "").lower()
            if severity == "critical":
                item.setForeground(2, Qt.red)
            elif severity == "high":
                item.setForeground(2, Qt.darkRed)
            elif severity == "medium":
                item.setForeground(2, Qt.darkYellow)

            self.results_tree.addTopLevelItem(item)

        # Информация о сканировании
        info_text = f"""
        Сканирование завершено!
        Всего сканировано: {results.get('total_scanned', 0)} файлов
        Угроз найдено: {results.get('threats_found', 0)}
        Время сканирования: {results.get('scan_time', 0):.2f} сек.
        """

        QMessageBox.information(self, "Результаты сканирования", info_text)

    def scan_finished(self):
        self.quick_scan_btn.setEnabled(True)
        self.full_scan_btn.setEnabled(True)
        self.custom_scan_btn.setEnabled(True)
        self.status_bar.showMessage("Сканирование завершено")

    def scan_error(self, error):
        QMessageBox.critical(self, "Ошибка сканирования", f"Произошла ошибка:\n{error}")
        self.scan_finished()

    def quarantine_selected(self):
        selected = self.results_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите файлы для помещения в карантин")
            return

        for item in selected:
            file_path = item.text(0)
            threat_name = item.text(1)

            success, result = self.app.quarantine.quarantine_file(file_path, threat_name)

            if success:
                item.setHidden(True)
                QMessageBox.information(self, "Успех", f"Файл помещен в карантин: {file_path}")
            else:
                QMessageBox.warning(self, "Ошибка", f"Не удалось поместить в карантин: {result}")

    def ignore_selected(self):
        selected = self.results_tree.selectedItems()
        if not selected:
            return

        for item in selected:
            file_path = item.text(0)
            self.app.signature_manager.add_to_whitelist(file_path, "Игнорирован пользователем")
            item.setHidden(True)

        QMessageBox.information(self, "Успех", "Выбранные файлы добавлены в белый список")

    def clear_results(self):
        self.results_tree.clear()
        self.progress_bar.setValue(0)
        self.current_file_label.setText("Готов к сканированию")

    def refresh_quarantine(self):
        self.quarantine_list.clear()
        metadata = self.app.quarantine.list_quarantine()

        for file_hash, info in metadata.items():
            item = QTreeWidgetItem([
                file_hash[:16] + "...",
                info.get("original_path", ""),
                info.get("reason", ""),
                info.get("date", "")
            ])
            self.quarantine_list.addTopLevelItem(item)

        self.quarantine_info.setText(f"Всего в карантине: {len(metadata)} файлов")

    def refresh_cache_info(self):
        """Обновление информации о кэше"""
        try:
            import sqlite3
            from config import get_user_data_dir
            from pathlib import Path

            cache_db = get_user_data_dir() / "cache.db"
            if cache_db.exists():
                conn = sqlite3.connect(str(cache_db))
                cursor = conn.cursor()

                # Получаем статистику кэша
                cursor.execute("SELECT COUNT(*) FROM scan_cache")
                total = cursor.fetchone()[0]

                cursor.execute(
                    "SELECT COUNT(*) FROM scan_cache WHERE threat_level != 'Clean' AND threat_level IS NOT NULL")
                threats = cursor.fetchone()[0]

                cursor.execute(
                    "SELECT datetime(last_scan, 'localtime') FROM scan_cache ORDER BY last_scan DESC LIMIT 1")
                last = cursor.fetchone()
                last_scan = last[0] if last and last[0] else "Нет данных"

                conn.close()

                self.cache_info_label.setText(
                    f"📊 Статистика кэша:\n"
                    f"   • Всего записей: {total}\n"
                    f"   • Угроз в кэше: {threats}\n"
                    f"   • Последнее сканирование: {last_scan}"
                )
            else:
                self.cache_info_label.setText("📊 Кэш пуст (еще не создан)")
        except Exception as e:
            self.cache_info_label.setText(f"❌ Ошибка загрузки статистики: {str(e)[:50]}")

    def clear_scan_cache(self):
        """Очистка кэша сканирования"""
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "🧹 Очистить кэш результатов сканирования?\n\n"
            "Это может замедлить следующее сканирование,\n"
            "но не влияет на безопасность и не удаляет файлы.",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                import sqlite3
                from config import get_user_data_dir
                from pathlib import Path

                cache_db = get_user_data_dir() / "cache.db"
                if cache_db.exists():
                    conn = sqlite3.connect(str(cache_db))
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM scan_cache")
                    deleted_count = cursor.rowcount
                    conn.commit()
                    conn.close()

                    QMessageBox.information(
                        self,
                        "Успех",
                        f"✅ Кэш успешно очищен!\n\nУдалено записей: {deleted_count}"
                    )
                    self.refresh_cache_info()  # Обновляем статистику
                else:
                    QMessageBox.information(self, "Информация", "📭 Кэш пуст, очистка не требуется")
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Ошибка",
                    f"❌ Не удалось очистить кэш:\n\n{str(e)}"
                )

    def save_settings(self):
        """Сохранение настроек"""
        # Сохраняем настройки сканирования
        self.app.scanner.max_file_size = self.max_file_size.value() * 1024 * 1024
        self.app.scanner.scan_depth = self.scan_depth.currentIndex()
        self.app.scanner.cache_enabled = self.enable_cache_checkbox.isChecked()

        # Сохраняем исключения (доверенные пути)
        exceptions = [self.exceptions_list.item(i).text() for i in range(self.exceptions_list.count())]

        QMessageBox.information(
            self,
            "Успех",
            "✅ Настройки успешно сохранены!\n\n"
            f"• Максимальный размер файла: {self.max_file_size.value()} МБ\n"
            f"• Глубина сканирования: {self.scan_depth.currentText()}\n"
            f"• Кэширование: {'включено' if self.enable_cache_checkbox.isChecked() else 'выключено'}\n"
            f"• Исключений в списке: {len(exceptions)}"
        )

    def restore_from_quarantine(self):
        selected = self.quarantine_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите файл для восстановления")
            return

        # Получаем полный хеш из metadata
        metadata = self.app.quarantine.list_quarantine()
        items = list(metadata.items())

        for idx, item in enumerate(selected):
            file_hash = list(metadata.keys())[idx]
            success, result = self.app.quarantine.restore_file(file_hash)

            if success:
                QMessageBox.information(self, "Успех", f"Файл восстановлен: {result}")
            else:
                QMessageBox.warning(self, "Ошибка", f"Не удалось восстановить: {result}")

        self.refresh_quarantine()

    def delete_from_quarantine(self):
        selected = self.quarantine_list.selectedItems()
        if not selected:
            return

        reply = QMessageBox.question(self, "Подтверждение",
                                     "Вы уверены, что хотите удалить выбранные файлы навсегда?",
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            metadata = self.app.quarantine.list_quarantine()
            items = list(metadata.items())

            for idx, item in enumerate(selected):
                file_hash = list(metadata.keys())[idx]
                success, result = self.app.quarantine.delete_file(file_hash)

                if not success:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось удалить: {result}")

            self.refresh_quarantine()

    def refresh_signatures(self):
        self.signatures_list.clear()
        signatures = self.app.signature_manager.get_all_signatures()

        for sig in signatures:
            item = QTreeWidgetItem([
                str(sig.get("id", "")),
                sig.get("name", ""),
                sig.get("type", ""),
                sig.get("severity", ""),
                sig.get("description", "")
            ])
            self.signatures_list.addTopLevelItem(item)

        stats = self.app.signature_manager.get_statistics()
        self.stats_label.setText(f"Сигнатур в базе: {stats['signatures']} | "
                                 f"В белом списке: {stats['whitelist']} | "
                                 f"Последнее обновление: {stats['last_update']}")

    def add_signature_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Добавить сигнатуру")
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        # Название
        layout.addWidget(QLabel("Название:"))
        name_input = QLineEdit()
        layout.addWidget(name_input)

        # Тип
        layout.addWidget(QLabel("Тип:"))
        type_combo = QComboBox()
        type_combo.addItems(["content", "bytes", "hash"])
        layout.addWidget(type_combo)

        # Паттерн/Хеш
        layout.addWidget(QLabel("Паттерн/Хеш:"))
        pattern_input = QLineEdit()
        layout.addWidget(pattern_input)

        # Описание
        layout.addWidget(QLabel("Описание:"))
        desc_input = QTextEdit()
        desc_input.setMaximumHeight(100)
        layout.addWidget(desc_input)

        # Серьезность
        layout.addWidget(QLabel("Серьезность:"))
        severity_combo = QComboBox()
        severity_combo.addItems(["Low", "Medium", "High", "Critical"])
        layout.addWidget(severity_combo)

        # Кнопки
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() == QDialog.Accepted:
            success, msg = self.app.signature_manager.add_signature(
                name_input.text(),
                type_combo.currentText(),
                pattern=pattern_input.text(),
                description=desc_input.toPlainText(),
                severity=severity_combo.currentText()
            )

            if success:
                QMessageBox.information(self, "Успех", msg)
                self.refresh_signatures()
            else:
                QMessageBox.critical(self, "Ошибка", msg)

    def remove_signature(self):
        selected = self.signatures_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите сигнатуру для удаления")
            return

        sig_id = int(selected[0].text(0))

        reply = QMessageBox.question(self, "Подтверждение",
                                     "Вы уверены, что хотите удалить эту сигнатуру?",
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            success, msg = self.app.signature_manager.remove_signature(sig_id)

            if success:
                QMessageBox.information(self, "Успех", msg)
                self.refresh_signatures()
            else:
                QMessageBox.critical(self, "Ошибка", msg)

    def update_signatures(self):
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Обновить базу сигнатур из интернета?",
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.status_bar.showMessage("Обновление сигнатур...")
            # Здесь должен быть реальный URL
            success, msg = self.app.signature_manager.update_from_server("https://example.com")

            if success:
                QMessageBox.information(self, "Успех", msg)
                self.refresh_signatures()
            else:
                QMessageBox.critical(self, "Ошибка", msg)

            self.status_bar.showMessage("Готов")

    def load_exceptions(self):
        # Загружаем исключения из базы
        # Для примера добавляем стандартные системные пути
        default_exceptions = [
            "/usr/lib",
            "/usr/share",
            "/lib",
            "/lib64",
            "/boot",
            "/sys",
            "/proc",
            "/dev"
        ]

        for path in default_exceptions:
            self.exceptions_list.addItem(path)

    def add_exception_path(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите директорию для исключения")
        if path and path not in [self.exceptions_list.item(i).text() for i in range(self.exceptions_list.count())]:
            self.exceptions_list.addItem(path)
            self.app.signature_manager.add_to_whitelist(path, "Пользовательское исключение")

    def remove_exception_path(self):
        selected = self.exceptions_list.selectedItems()
        for item in selected:
            self.exceptions_list.takeItem(self.exceptions_list.row(item))

    def save_settings(self):
        # Сохраняем настройки
        self.app.scanner.max_file_size = self.max_file_size.value() * 1024 * 1024
        self.app.scanner.scan_depth = self.scan_depth.currentIndex()
        self.app.scanner.cache_enabled = self.enable_cache_checkbox.isChecked()

        # Сохраняем исключения
        exceptions = [self.exceptions_list.item(i).text() for i in range(self.exceptions_list.count())]
        # Здесь нужно сохранить в конфиг

        QMessageBox.information(self, "Успех", "Настройки сохранены")

    def show_about(self):
        about_text = """
        <h2>LinuxAV Антивирус</h2>
        <p>Версия 1.0.0</p>
        <p>Антивирусное решение для Linux систем</p>
        <p>Особенности:</p>
        <ul>
            <li>Сканирование файловой системы</li>
            <li>Обнаружение вредоносных программ</li>
            <li>Карантин и восстановление файлов</li>
            <li>Обновление баз сигнатур</li>
        </ul>
        <p>© 2024 LinuxAV Team</p>
        """

        QMessageBox.about(self, "О программе", about_text)