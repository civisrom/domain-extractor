import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, Menu
import re
from pathlib import Path
import threading
import json
import os
import chardet
from collections import deque, Counter
import time
from datetime import datetime
import csv

class DomainExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Domain Extractor Pro v3.0")
        self.root.geometry("1250x850")
        self.root.minsize(1000, 700)

        # === Переменные ===
        self.input_files = []
        self.output_file = tk.StringVar()
        self.prefix = tk.StringVar(value="")
        self.suffix = tk.StringVar(value="")
        self.separator = tk.StringVar(value="\n")
        self.domain_format = tk.StringVar(value="full")
        self.remove_www = tk.BooleanVar(value=True)
        self.remove_duplicates = tk.BooleanVar(value=True)
        self.sort_results = tk.BooleanVar(value=False)
        self.selected_tlds = set()
        self.export_format = tk.StringVar(value="txt")
        self.dark_mode = tk.BooleanVar(value=False)
        
        # Новые переменные
        self.use_advanced_mask = tk.BooleanVar(value=False)
        self.advanced_mask = tk.StringVar(value="https://{domain}")
        self.strip_chars = tk.StringVar(value="[](){}\"'<>")
        self.min_length = tk.IntVar(value=3)
        self.max_length = tk.IntVar(value=255)
        self.validate_dns = tk.BooleanVar(value=True)
        self.case_mode = tk.StringVar(value="lower")
        self.blacklist_patterns = []
        self.whitelist_patterns = []
        self.extraction_mode = tk.StringVar(value="standard")
        
        # История операций
        self.history = []
        self.max_history = 10

        # Очередь задач
        self.task_queue = deque()
        self.is_processing = False
        
        # Статистика
        self.stats = {}

        # Настройки
        self.config_file = "domain_extractor_config_v3.json"
        self.load_config()

        self.create_widgets()
        self.apply_theme()

        # Горячие клавиши
        self.root.bind("<Control-o>", lambda e: self.browse_input())
        self.root.bind("<Control-s>", lambda e: self.browse_output())
        self.root.bind("<F5>", lambda e: self.process_file())
        self.root.bind("<Control-f>", lambda e: self.focus_search())
        self.root.bind("<Control-z>", lambda e: self.undo_last())

    def create_widgets(self):
        # === Меню ===
        menubar = Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Добавить файлы (Ctrl+O)", command=self.browse_input)
        file_menu.add_command(label="Сохранить как (Ctrl+S)", command=self.browse_output)
        file_menu.add_separator()
        file_menu.add_command(label="Экспорт статистики", command=self.export_stats)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.quit)

        edit_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        edit_menu.add_command(label="Отменить (Ctrl+Z)", command=self.undo_last)
        edit_menu.add_separator()
        edit_menu.add_command(label="Чёрный список", command=self.manage_blacklist)
        edit_menu.add_command(label="Белый список", command=self.manage_whitelist)

        view_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Вид", menu=view_menu)
        view_menu.add_checkbutton(label="Тёмная тема", variable=self.dark_mode, command=self.toggle_theme)

        tools_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Инструменты", menu=tools_menu)
        tools_menu.add_command(label="Тест регулярного выражения", command=self.test_regex)
        tools_menu.add_command(label="Валидатор доменов", command=self.validate_domains_tool)

        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Помощь", menu=help_menu)
        help_menu.add_command(label="Справка по маскам", command=self.show_mask_help)
        help_menu.add_command(label="О программе", command=self.show_about)

        # === Notebook для вкладок ===
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # === Вкладка 1: Основные настройки ===
        main_tab = ttk.Frame(notebook, padding="10")
        notebook.add(main_tab, text="Основные")
        self.create_main_tab(main_tab)

        # === Вкладка 2: Продвинутые настройки ===
        advanced_tab = ttk.Frame(notebook, padding="10")
        notebook.add(advanced_tab, text="Продвинутые")
        self.create_advanced_tab(advanced_tab)

        # === Вкладка 3: Лог и результаты ===
        log_tab = ttk.Frame(notebook, padding="10")
        notebook.add(log_tab, text="Лог и результаты")
        self.create_log_tab(log_tab)

        # === Статус ===
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=5, pady=2)
        self.status_label = ttk.Label(status_frame, text="Готово", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress = ttk.Progressbar(status_frame, mode='determinate', maximum=100, length=200)
        self.progress.pack(side=tk.RIGHT, padx=5)

    def create_main_tab(self, parent):
        parent.columnconfigure(0, weight=1)
        row = 0

        # === Входные файлы ===
        input_frame = ttk.LabelFrame(parent, text="Входные файлы", padding="10")
        input_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5)
        input_frame.columnconfigure(0, weight=1)

        self.input_listbox = tk.Listbox(input_frame, height=4)
        self.input_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        input_scroll = ttk.Scrollbar(input_frame, orient="vertical", command=self.input_listbox.yview)
        input_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.input_listbox.config(yscrollcommand=input_scroll.set)

        input_btn_frame = ttk.Frame(input_frame)
        input_btn_frame.grid(row=1, column=0, columnspan=2, pady=5)
        ttk.Button(input_btn_frame, text="Добавить", command=self.browse_input).pack(side=tk.LEFT, padx=2)
        ttk.Button(input_btn_frame, text="Удалить", command=self.remove_input).pack(side=tk.LEFT, padx=2)
        ttk.Button(input_btn_frame, text="Очистить", command=self.clear_inputs).pack(side=tk.LEFT, padx=2)

        row += 1

        # === Выходной файл ===
        output_frame = ttk.LabelFrame(parent, text="Выходной файл", padding="10")
        output_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5)
        output_frame.columnconfigure(0, weight=1)

        out_entry_frame = ttk.Frame(output_frame)
        out_entry_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        out_entry_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(out_entry_frame, textvariable=self.output_file).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(out_entry_frame, text="Обзор...", command=self.browse_output).grid(row=0, column=1, padx=2)

        format_frame = ttk.Frame(output_frame)
        format_frame.grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(format_frame, text="Формат:").pack(side=tk.LEFT, padx=5)
        ttk.Combobox(format_frame, textvariable=self.export_format, 
                     values=["txt", "csv", "json", "xml"], state="readonly", width=10).pack(side=tk.LEFT)

        row += 1

        # === Режим извлечения ===
        extract_frame = ttk.LabelFrame(parent, text="Режим извлечения", padding="10")
        extract_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5)
        
        modes = [
            ("Стандартный", "standard", "Обычные домены (example.com)"),
            ("Агрессивный", "aggressive", "Включая поддомены и сложные случаи"),
            ("Email", "email", "Извлечение из email-адресов"),
            ("URL", "url", "Из полных URL (http://...)"),
        ]
        
        for i, (text, val, desc) in enumerate(modes):
            rb = ttk.Radiobutton(extract_frame, text=text, variable=self.extraction_mode, value=val)
            rb.grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
            ttk.Label(extract_frame, text=desc, foreground="gray").grid(row=i, column=1, sticky=tk.W, padx=10)

        row += 1

        # === Формат вывода ===
        format_frame = ttk.LabelFrame(parent, text="Формат вывода", padding="10")
        format_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(format_frame, text="Тип:").grid(row=0, column=0, sticky=tk.W, padx=5)
        fmt_frame = ttk.Frame(format_frame)
        fmt_frame.grid(row=0, column=1, sticky=tk.W)
        for text, val in [("Полный", "full"), ("Без TLD", "no_tld"), ("Только TLD", "only_tld"), ("SLD", "sld")]:
            ttk.Radiobutton(fmt_frame, text=text, variable=self.domain_format, value=val).pack(side=tk.LEFT, padx=5)

        ttk.Label(format_frame, text="Префикс:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(format_frame, textvariable=self.prefix, width=30).grid(row=1, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(format_frame, text="Суффикс:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(format_frame, textvariable=self.suffix, width=30).grid(row=2, column=1, sticky=tk.W, padx=5)

        ttk.Label(format_frame, text="Разделитель:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        sep_frame = ttk.Frame(format_frame)
        sep_frame.grid(row=3, column=1, sticky=tk.W)
        for text, val in [("Строка", "\n"), ("Пробел", " "), ("Запятая", ", "), ("Таб", "\t"), ("Точка-запятая", ";")]:
            ttk.Radiobutton(sep_frame, text=text, variable=self.separator, value=val).pack(side=tk.LEFT, padx=3)

        row += 1

        # === Опции ===
        opts_frame = ttk.LabelFrame(parent, text="Опции обработки", padding="10")
        opts_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5)
        
        opts_col1 = ttk.Frame(opts_frame)
        opts_col1.grid(row=0, column=0, sticky=tk.W, padx=10)
        ttk.Checkbutton(opts_col1, text="Удалить www.", variable=self.remove_www).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(opts_col1, text="Удалить дубликаты", variable=self.remove_duplicates).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(opts_col1, text="Сортировать результаты", variable=self.sort_results).pack(anchor=tk.W, pady=2)
        
        opts_col2 = ttk.Frame(opts_frame)
        opts_col2.grid(row=0, column=1, sticky=tk.W, padx=20)
        ttk.Checkbutton(opts_col2, text="Валидация DNS структуры", variable=self.validate_dns).pack(anchor=tk.W, pady=2)
        
        case_frame = ttk.Frame(opts_col2)
        case_frame.pack(anchor=tk.W, pady=2)
        ttk.Label(case_frame, text="Регистр:").pack(side=tk.LEFT)
        ttk.Combobox(case_frame, textvariable=self.case_mode, values=["lower", "upper", "original"], 
                     state="readonly", width=10).pack(side=tk.LEFT, padx=5)

        row += 1

        # === Кнопки действий ===
        btn_frame = ttk.Frame(parent)
        btn_frame.grid(row=row, column=0, pady=15)
        
        ttk.Button(btn_frame, text="🚀 Обработать (F5)", command=self.process_file, 
                   style="Accent.TButton", width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="👁 Предпросмотр", command=self.preview_results, 
                   width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🧹 Очистить лог", command=self.clear_log, 
                   width=15).pack(side=tk.LEFT, padx=5)

    def create_advanced_tab(self, parent):
        parent.columnconfigure(0, weight=1)
        row = 0

        # === Продвинутые маски ===
        mask_frame = ttk.LabelFrame(parent, text="Продвинутые маски", padding="10")
        mask_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5)
        mask_frame.columnconfigure(1, weight=1)

        ttk.Checkbutton(mask_frame, text="Использовать шаблон маски", 
                       variable=self.use_advanced_mask).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(mask_frame, text="Шаблон:").grid(row=1, column=0, sticky=tk.W, padx=5)
        ttk.Entry(mask_frame, textvariable=self.advanced_mask).grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        
        help_text = "Переменные: {domain} {name} {tld} {sld} {subdomain}\nПример: https://{domain}/path или {name}@mail.com"
        ttk.Label(mask_frame, text=help_text, foreground="gray", font=("Arial", 9)).grid(
            row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

        row += 1

        # === Фильтрация символов ===
        filter_frame = ttk.LabelFrame(parent, text="Очистка и фильтрация", padding="10")
        filter_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5)
        filter_frame.columnconfigure(1, weight=1)

        ttk.Label(filter_frame, text="Удалить символы:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(filter_frame, textvariable=self.strip_chars).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)

        ttk.Label(filter_frame,
                  text=r'Например: [](){}"\'<>' if os.name == 'nt' else 'Например: [](){}"\\\'<>',
                  foreground="gray").grid(
            row=1, column=1, sticky=tk.W, padx=5)

        ttk.Label(filter_frame, text="Мин. длина домена:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(filter_frame, from_=1, to=100, textvariable=self.min_length, width=10).grid(
            row=2, column=1, sticky=tk.W, padx=5)
        ttk.Label(filter_frame, text="Макс. длина домена:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(filter_frame, from_=10, to=255, textvariable=self.max_length, width=10).grid(
            row=3, column=1, sticky=tk.W, padx=5)

        row += 1

        # === Фильтр TLD ===
        tld_frame = ttk.LabelFrame(parent, text="Фильтр доменных зон (TLD)", padding="10")
        tld_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5)
        tld_frame.columnconfigure(0, weight=1)

        tld_entry_frame = ttk.Frame(tld_frame)
        tld_entry_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        tld_entry_frame.columnconfigure(0, weight=1)
        
        self.tld_entry = ttk.Entry(tld_entry_frame)
        self.tld_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5)
        self.tld_entry.insert(0, ".com, .ru, .org, .net")
        ttk.Button(tld_entry_frame, text="Применить", command=self.update_tld_filter).grid(row=0, column=1, padx=2)

        ttk.Label(tld_frame, text="Поддержка двухуровневых TLD: .co.uk, .com.au и т.д.", 
                 foreground="gray").grid(row=1, column=0, sticky=tk.W, padx=5)

        row += 1

        # === Чёрный/Белый списки ===
        lists_frame = ttk.LabelFrame(parent, text="Списки фильтрации", padding="10")
        lists_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5)

        lists_info = ttk.Frame(lists_frame)
        lists_info.pack(fill=tk.X, pady=5)
        
        ttk.Label(lists_info, text=f"Чёрный список: {len(self.blacklist_patterns)} паттернов").pack(side=tk.LEFT, padx=10)
        ttk.Button(lists_info, text="Настроить", command=self.manage_blacklist).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(lists_info, text=f"Белый список: {len(self.whitelist_patterns)} паттернов").pack(side=tk.LEFT, padx=10)
        ttk.Button(lists_info, text="Настроить", command=self.manage_whitelist).pack(side=tk.LEFT, padx=5)

        ttk.Label(lists_frame, text="Используйте * как wildcard: google.*, *.example.com", 
                 foreground="gray").pack(anchor=tk.W, padx=5, pady=2)

    def create_log_tab(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        # === Поиск ===
        search_frame = ttk.Frame(parent)
        search_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        search_frame.columnconfigure(1, weight=1)
        
        ttk.Label(search_frame, text="Поиск:").grid(row=0, column=0, padx=5)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(search_frame, text="Найти", command=self.search_log).grid(row=0, column=2, padx=2)
        ttk.Button(search_frame, text="Найти далее", command=self.search_next).grid(row=0, column=3, padx=2)

        # === Лог ===
        log_frame = ttk.Frame(parent)
        log_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Цветовые теги для лога
        self.log_text.tag_config("info", foreground="blue")
        self.log_text.tag_config("success", foreground="green")
        self.log_text.tag_config("warning", foreground="orange")
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("header", font=("Consolas", 10, "bold"))

        # === Статистика ===
        stats_frame = ttk.LabelFrame(parent, text="Статистика последней операции", padding="10")
        stats_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.stats_text = tk.Text(stats_frame, height=6, font=("Consolas", 9), state=tk.DISABLED)
        self.stats_text.pack(fill=tk.BOTH, expand=True)

    def browse_input(self):
        files = filedialog.askopenfilenames(
            title="Выберите входные файлы",
            filetypes=[("Текстовые файлы", "*.txt *.log *.csv *.html"), ("Все файлы", "*.*")]
        )
        for f in files:
            if f not in self.input_files:
                self.input_files.append(f)
                self.input_listbox.insert(tk.END, Path(f).name)

    def remove_input(self):
        selection = self.input_listbox.curselection()
        for i in reversed(selection):
            self.input_files.pop(i)
            self.input_listbox.delete(i)

    def clear_inputs(self):
        self.input_files.clear()
        self.input_listbox.delete(0, tk.END)

    def browse_output(self):
        fmt = self.export_format.get()
        ext_map = {"txt": ".txt", "csv": ".csv", "json": ".json", "xml": ".xml"}
        ext = ext_map.get(fmt, ".txt")
        filename = filedialog.asksaveasfilename(
            title="Сохранить результат",
            defaultextension=ext,
            filetypes=[(f"{fmt.upper()} files", f"*{ext}"), ("All files", "*.*")]
        )
        if filename:
            self.output_file.set(filename)

    def update_tld_filter(self):
        text = self.tld_entry.get().strip()
        self.selected_tlds = {tld.strip().lower().lstrip('.') for tld in text.split(',') if tld.strip()}
        self.log(f"✓ Фильтр TLD обновлён: {', '.join('.' + t for t in self.selected_tlds) or 'отключён'}", "info")

    def extract_domains(self, text):
        """Улучшенное извлечение доменов с учётом режима"""
        mode = self.extraction_mode.get()
        
        # Удаление символов из strip_chars
        for char in self.strip_chars.get():
            text = text.replace(char, ' ')
        
        domains = []
        
        if mode == "standard":
            # Стандартный режим - основные домены
            pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            domains = re.findall(pattern, text, re.IGNORECASE)
            
        elif mode == "aggressive":
            # Агрессивный - включая поддомены и IDN
            pattern = r'(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?'
            domains = re.findall(pattern, text, re.IGNORECASE)
            
        elif mode == "email":
            # Извлечение из email
            pattern = r'[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})'
            domains = re.findall(pattern, text, re.IGNORECASE)
            
        elif mode == "url":
            # Из URL
            pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})'
            domains = re.findall(pattern, text, re.IGNORECASE)
        
        # Очистка и валидация
        valid_domains = []
        for d in domains:
            d = d.lower().strip('.-')
            
            # Проверка длины
            if len(d) < self.min_length.get() or len(d) > self.max_length.get():
                continue
            
            # Проверка наличия точки
            if '.' not in d:
                continue
            
            # Валидация DNS
            if self.validate_dns.get() and not self.is_valid_domain(d):
                continue
            
            # Проверка TLD
            if self.selected_tlds:
                tld = d.split('.')[-1]
                # Поддержка двухуровневых TLD
                if len(d.split('.')) > 2:
                    tld2 = '.'.join(d.split('.')[-2:])
                    if tld not in self.selected_tlds and tld2 not in self.selected_tlds:
                        continue
                elif tld not in self.selected_tlds:
                    continue
            
            # Чёрный список
            if self.is_blacklisted(d):
                continue
            
            # Белый список (если задан, пропускаем только совпадения)
            if self.whitelist_patterns and not self.is_whitelisted(d):
                continue
            
            valid_domains.append(d)
        
        return valid_domains

    def is_valid_domain(self, domain):
        """Валидация структуры домена"""
        if not domain or len(domain) > 253:
            return False
        
        # Проверка на недопустимые символы
        if re.search(r'[^a-z0-9\.\-]', domain):
            return False
        
        # Проверка частей домена
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
        
        return True

    def is_blacklisted(self, domain):
        """Проверка на чёрный список"""
        for pattern in self.blacklist_patterns:
            if self.match_pattern(domain, pattern):
                return True
        return False

    def is_whitelisted(self, domain):
        """Проверка на белый список"""
        for pattern in self.whitelist_patterns:
            if self.match_pattern(domain, pattern):
                return True
        return False

    def match_pattern(self, domain, pattern):
        """Сопоставление домена с паттерном (поддержка wildcard)"""
        pattern = pattern.replace('.', r'\.')
        pattern = pattern.replace('*', '.*')
        pattern = f'^{pattern}$'  # Исправлено: добавлены $ и закрывающая кавычка
        return bool(re.match(pattern, domain, re.IGNORECASE))

    def format_domain(self, domain):
        """Форматирование домена с учётом всех настроек"""
        original = domain
        
        # Удаление www
        if self.remove_www.get() and domain.startswith('www.'):
            domain = domain[4:]
        
        # Регистр
        case_mode = self.case_mode.get()
        if case_mode == "lower":
            domain = domain.lower()
        elif case_mode == "upper":
            domain = domain.upper()
        
        # Формат домена
        parts = domain.split('.')
        fmt = self.domain_format.get()
        
        if fmt == "no_tld" and len(parts) > 1:
            domain = '.'.join(parts[:-1])
        elif fmt == "only_tld" and len(parts) > 1:
            domain = '.' + parts[-1]
        elif fmt == "sld" and len(parts) >= 2:
            # Second-level domain (example из example.com)
            domain = parts[-2]
        
        # Продвинутая маска
        if self.use_advanced_mask.get():
            mask = self.advanced_mask.get()
            
            # Подготовка переменных для шаблона
            full_domain = original
            name = '.'.join(parts[:-1]) if len(parts) > 1 else parts[0]
            tld = parts[-1] if len(parts) > 1 else ''
            sld = parts[-2] if len(parts) >= 2 else ''
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
            
            # Замена переменных
            result = mask.replace('{domain}', domain)
            result = result.replace('{name}', name)
            result = result.replace('{tld}', tld)
            result = result.replace('{sld}', sld)
            result = result.replace('{subdomain}', subdomain)
            result = result.replace('{full}', full_domain)
            
            return result
        
        # Простой префикс/суффикс
        return self.prefix.get() + domain + self.suffix.get()

    def detect_encoding(self, filepath):
        """Определение кодировки файла"""
        try:
            with open(filepath, 'rb') as f:
                raw = f.read(100000)
                result = chardet.detect(raw)
                return result['encoding'] or 'utf-8'
        except:
            return 'utf-8'

    def process_domains(self, input_paths, output_path=None, preview_mode=False, preview_limit=100):
        """Основная обработка доменов"""
        try:
            start_time = time.time()
            total_domains = 0
            all_formatted = []
            stats = {
                'files_processed': 0,
                'raw_domains': 0,
                'valid_domains': 0,
                'filtered_out': 0,
                'duplicates_removed': 0,
                'final_count': 0,
                'tld_distribution': Counter(),
                'processing_time': 0
            }

            self.log("=" * 70, "header")
            self.log(f"🚀 НАЧАЛО ОБРАБОТКИ - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "header")
            self.log("=" * 70, "header")

            for idx, path in enumerate(input_paths):
                self.log(f"\n[{idx+1}/{len(input_paths)}] 📄 Обработка: {Path(path).name}")
                
                # Определение кодировки
                encoding = self.detect_encoding(path)
                self.log(f"   ℹ Кодировка: {encoding}", "info")
                
                # Чтение файла
                with open(path, 'r', encoding=encoding, errors='ignore') as f:
                    content = f.read()

                # Извлечение доменов
                domains = self.extract_domains(content)
                raw_count = len(domains)
                stats['raw_domains'] += raw_count
                
                self.log(f"   ✓ Извлечено доменов: {raw_count}", "success")

                # Форматирование
                formatted = [self.format_domain(d) for d in domains]
                all_formatted.extend(formatted)
                total_domains += len(domains)
                
                # Статистика TLD
                for d in domains:
                    tld = d.split('.')[-1]
                    stats['tld_distribution'][tld] += 1

                stats['files_processed'] += 1

                # Прогресс
                progress = (idx + 1) / len(input_paths) * 100
                self.root.after(0, self.progress.configure, {'value': progress})

            if not all_formatted:
                self.log("\n⚠ Домены не найдены!", "warning")
                messagebox.showwarning("Предупреждение", "Домены не найдены ни в одном файле.")
                return

            stats['valid_domains'] = len(all_formatted)

            # Удаление дубликатов
            if self.remove_duplicates.get():
                orig = len(all_formatted)
                all_formatted = list(dict.fromkeys(all_formatted))
                removed = orig - len(all_formatted)
                stats['duplicates_removed'] = removed
                self.log(f"\n🗑 Удалено дубликатов: {removed}", "info")

            # Сортировка
            if self.sort_results.get():
                all_formatted.sort()
                self.log("📊 Результаты отсортированы", "info")

            stats['final_count'] = len(all_formatted)
            stats['processing_time'] = time.time() - start_time

            # Предпросмотр
            if preview_mode:
                self.show_preview(all_formatted, preview_limit, stats)
                return

            # Экспорт
            self.export_results(all_formatted, output_path, stats)
            
            # Сохранение в историю
            self.history.append({
                'timestamp': datetime.now().isoformat(),
                'domains': all_formatted.copy(),
                'stats': stats.copy()
            })
            if len(self.history) > self.max_history:
                self.history.pop(0)
            
            # Отображение статистики
            self.display_stats(stats)
            
            self.log("\n" + "=" * 70, "header")
            self.log(f"✅ ОБРАБОТКА ЗАВЕРШЕНА за {stats['processing_time']:.2f} сек", "success")
            self.log("=" * 70, "header")
            
            messagebox.showinfo("Готово", 
                f"Обработано файлов: {stats['files_processed']}\n"
                f"Уникальных доменов: {stats['final_count']}\n"
                f"Время: {stats['processing_time']:.2f} сек")

        except Exception as e:
            self.log(f"\n❌ ОШИБКА: {e}", "error")
            messagebox.showerror("Ошибка", str(e))
        finally:
            self.root.after(0, self.progress.configure, {'value': 0})
            self.root.after(0, self.update_status, "Готово")
            self.is_processing = False
            self.process_queue()

    def show_preview(self, domains, limit, stats):
        """Отображение предпросмотра"""
        preview = domains[:limit]
        self.log("\n" + "=" * 70, "header")
        self.log(f"👁 ПРЕДПРОСМОТР ({len(preview)} из {len(domains)})", "header")
        self.log("=" * 70, "header")
        
        for i, d in enumerate(preview, 1):
            self.log(f"{i:4}. {d}")
        
        if len(domains) > limit:
            self.log(f"\n... ещё {len(domains) - limit} доменов", "info")
        
        self.log("\n" + "=" * 70, "header")
        self.display_stats(stats)

    def export_results(self, domains, output_path, stats):
        """Экспорт результатов в различных форматах"""
        fmt = self.export_format.get()
        
        if fmt == "txt":
            sep = self.separator.get().replace('\\n', '\n').replace('\\t', '\t')
            result = sep.join(domains)
            
        elif fmt == "csv":
            result = "domain\n" + "\n".join(domains)
            
        elif fmt == "json":
            output_data = {
                'domains': domains,
                'count': len(domains),
                'timestamp': datetime.now().isoformat(),
                'statistics': {
                    'files_processed': stats['files_processed'],
                    'total_extracted': stats['raw_domains'],
                    'duplicates_removed': stats['duplicates_removed'],
                    'processing_time': f"{stats['processing_time']:.2f}s"
                }
            }
            result = json.dumps(output_data, ensure_ascii=False, indent=2)
            
        elif fmt == "xml":
            result = '<?xml version="1.0" encoding="UTF-8"?>\n<domains>\n'
            for d in domains:
                result += f'  <domain>{d}</domain>\n'
            result += '</domains>'

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)

        self.log(f"\n💾 Сохранено: {output_path}", "success")

    def display_stats(self, stats):
        """Отображение статистики"""
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        
        stats_str = f"""
Файлов обработано:     {stats['files_processed']}
Извлечено доменов:     {stats['raw_domains']}
Валидных доменов:      {stats['valid_domains']}
Удалено дубликатов:    {stats['duplicates_removed']}
Итоговый результат:    {stats['final_count']}
Время обработки:       {stats['processing_time']:.2f} сек

Топ-5 доменных зон:
"""
        for tld, count in stats['tld_distribution'].most_common(5):
            stats_str += f"  .{tld}: {count}\n"
        
        self.stats_text.insert(1.0, stats_str)
        self.stats_text.config(state=tk.DISABLED)

    def process_file(self):
        """Запуск обработки"""
        if not self.input_files:
            messagebox.showwarning("Ошибка", "Выберите хотя бы один входной файл!")
            return
        if not self.output_file.get():
            messagebox.showwarning("Ошибка", "Выберите выходной файл!")
            return

        self.update_tld_filter()  # Применить фильтр TLD
        self.task_queue.append((self.input_files.copy(), self.output_file.get(), False))
        if not self.is_processing:
            self.process_queue()

    def preview_results(self):
        """Предпросмотр результатов"""
        if not self.input_files:
            messagebox.showwarning("Ошибка", "Выберите входной файл!")
            return
        self.update_tld_filter()
        self.task_queue.append((self.input_files.copy(), None, True))
        if not self.is_processing:
            self.process_queue()

    def process_queue(self):
        """Обработка очереди задач"""
        if not self.task_queue or self.is_processing:
            return
        self.is_processing = True
        inputs, output, preview = self.task_queue.popleft()
        self.update_status("Обработка...")
        thread = threading.Thread(target=self.process_domains, args=(inputs, output, preview))
        thread.daemon = True
        thread.start()

    def manage_blacklist(self):
        """Управление чёрным списком"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Чёрный список доменов")
        dialog.geometry("500x400")
        
        ttk.Label(dialog, text="Паттерны для исключения (один на строку):").pack(pady=5)
        ttk.Label(dialog, text="Примеры: google.*, *.example.com, spam-domain.ru", 
                 foreground="gray").pack()
        
        text = scrolledtext.ScrolledText(dialog, height=15)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(1.0, '\n'.join(self.blacklist_patterns))
        
        def save():
            content = text.get(1.0, tk.END).strip()
            self.blacklist_patterns = [line.strip() for line in content.split('\n') if line.strip()]
            self.log(f"✓ Чёрный список обновлён: {len(self.blacklist_patterns)} паттернов", "info")
            dialog.destroy()
        
        ttk.Button(dialog, text="Сохранить", command=save).pack(pady=5)

    def manage_whitelist(self):
        """Управление белым списком"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Белый список доменов")
        dialog.geometry("500x400")
        
        ttk.Label(dialog, text="Паттерны для включения (один на строку):").pack(pady=5)
        ttk.Label(dialog, text="Только эти домены будут обработаны (если список не пуст)", 
                 foreground="gray").pack()
        
        text = scrolledtext.ScrolledText(dialog, height=15)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(1.0, '\n'.join(self.whitelist_patterns))
        
        def save():
            content = text.get(1.0, tk.END).strip()
            self.whitelist_patterns = [line.strip() for line in content.split('\n') if line.strip()]
            self.log(f"✓ Белый список обновлён: {len(self.whitelist_patterns)} паттернов", "info")
            dialog.destroy()
        
        ttk.Button(dialog, text="Сохранить", command=save).pack(pady=5)

    def test_regex(self):
        """Тестирование регулярных выражений"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Тест извлечения доменов")
        dialog.geometry("700x500")
        
        ttk.Label(dialog, text="Введите текст для тестирования:").pack(pady=5)
        
        input_text = scrolledtext.ScrolledText(dialog, height=8)
        input_text.pack(fill=tk.BOTH, padx=10, pady=5)
        input_text.insert(1.0, "Пример: Посетите example.com или test@mail.ru, https://subdomain.example.co.uk")
        
        def test():
            text = input_text.get(1.0, tk.END)
            domains = self.extract_domains(text)
            result_text.config(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            result_text.insert(1.0, f"Найдено доменов: {len(domains)}\n\n")
            for i, d in enumerate(domains, 1):
                formatted = self.format_domain(d)
                result_text.insert(tk.END, f"{i}. {d} → {formatted}\n")
            result_text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Извлечь домены", command=test).pack(pady=5)
        
        ttk.Label(dialog, text="Результат:").pack(pady=5)
        result_text = scrolledtext.ScrolledText(dialog, height=10, state=tk.DISABLED)
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def validate_domains_tool(self):
        """Инструмент валидации доменов"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Валидатор доменов")
        dialog.geometry("600x450")
        
        ttk.Label(dialog, text="Введите домены (один на строку):").pack(pady=5)
        
        input_text = scrolledtext.ScrolledText(dialog, height=10)
        input_text.pack(fill=tk.BOTH, padx=10, pady=5)
        
        def validate():
            text = input_text.get(1.0, tk.END)
            domains = [line.strip() for line in text.split('\n') if line.strip()]
            
            result_text.config(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            
            valid_count = 0
            for d in domains:
                is_valid = self.is_valid_domain(d)
                status = "✓ Валидный" if is_valid else "✗ Невалидный"
                color = "green" if is_valid else "red"
                
                result_text.insert(tk.END, f"{status}: {d}\n")
                result_text.tag_add(color, f"{result_text.index(tk.END)}-1l", f"{result_text.index(tk.END)}-1l lineend")
                
                if is_valid:
                    valid_count += 1
            
            result_text.insert(1.0, f"Проверено: {len(domains)}, Валидных: {valid_count}\n\n")
            result_text.tag_config("green", foreground="green")
            result_text.tag_config("red", foreground="red")
            result_text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Проверить", command=validate).pack(pady=5)
        
        result_text = scrolledtext.ScrolledText(dialog, height=12, state=tk.DISABLED)
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def export_stats(self):
        """Экспорт статистики в CSV"""
        if not self.stats:
            messagebox.showinfo("Информация", "Нет данных для экспорта. Выполните обработку сначала.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Экспорт статистики",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        
        if filename:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Метрика', 'Значение'])
                writer.writerow(['Файлов обработано', self.stats.get('files_processed', 0)])
                writer.writerow(['Извлечено доменов', self.stats.get('raw_domains', 0)])
                writer.writerow(['Валидных доменов', self.stats.get('valid_domains', 0)])
                writer.writerow(['Удалено дубликатов', self.stats.get('duplicates_removed', 0)])
                writer.writerow(['Итоговый результат', self.stats.get('final_count', 0)])
                writer.writerow(['Время обработки (сек)', f"{self.stats.get('processing_time', 0):.2f}"])
                writer.writerow([])
                writer.writerow(['Доменная зона', 'Количество'])
                for tld, count in self.stats.get('tld_distribution', Counter()).most_common():
                    writer.writerow([f'.{tld}', count])
            
            self.log(f"✓ Статистика экспортирована: {filename}", "success")

    def undo_last(self):
        """Отмена последней операции"""
        if not self.history:
            messagebox.showinfo("Информация", "Нет операций для отмены")
            return
        
        last = self.history[-1]
        response = messagebox.askyesno("Отмена", 
            f"Восстановить результат от {last['timestamp']}?\n"
            f"Доменов: {len(last['domains'])}")
        
        if response and self.output_file.get():
            try:
                domains = last['domains']
                self.export_results(domains, self.output_file.get(), last['stats'])
                self.log(f"✓ Восстановлено из истории: {len(domains)} доменов", "success")
                messagebox.showinfo("Успех", "Результат восстановлен")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось восстановить: {e}")

    def log(self, msg, tag=None):
        """Логирование с поддержкой тегов"""
        self.log_text.insert(tk.END, msg + "\n", tag)
        self.log_text.see(tk.END)

    def clear_log(self):
        """Очистка лога"""
        self.log_text.delete(1.0, tk.END)

    def update_status(self, msg):
        """Обновление статуса"""
        self.status_label.config(text=msg)

    def search_log(self):
        """Поиск в логе"""
        query = self.search_var.get().lower()
        if not query:
            return
        
        self.log_text.tag_remove("search", 1.0, tk.END)
        
        start = "1.0"
        while True:
            pos = self.log_text.search(query, start, tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self.log_text.tag_add("search", pos, end)
            start = end
        
        self.log_text.tag_config("search", background="yellow", foreground="black")
        
        # Переход к первому совпадению
        first = self.log_text.search(query, 1.0, tk.END, nocase=True)
        if first:
            self.log_text.see(first)
        else:
            messagebox.showinfo("Поиск", "Совпадений не найдено")

    def search_next(self):
        """Поиск следующего совпадения"""
        query = self.search_var.get().lower()
        if not query:
            return
        
        current = self.log_text.index(tk.INSERT)
        pos = self.log_text.search(query, current, tk.END, nocase=True)
        
        if pos:
            self.log_text.mark_set(tk.INSERT, pos)
            self.log_text.see(pos)
        else:
            # Начать сначала
            pos = self.log_text.search(query, "1.0", tk.END, nocase=True)
            if pos:
                self.log_text.mark_set(tk.INSERT, pos)
                self.log_text.see(pos)

    def focus_search(self):
        """Фокус на поиск"""
        self.search_entry.focus()

    def toggle_theme(self):
        """Переключение темы"""
        self.apply_theme()
        self.save_config()

    def apply_theme(self):
        """Применение темы"""
        if self.dark_mode.get():
            self.root.configure(bg="#2e2e2e")
            self.log_text.configure(bg="#1e1e1e", fg="#ffffff", insertbackground="white")
            self.stats_text.configure(bg="#1e1e1e", fg="#ffffff")
        else:
            self.root.configure(bg="SystemButtonFace")
            self.log_text.configure(bg="white", fg="black", insertbackground="black")
            self.stats_text.configure(bg="white", fg="black")

    def save_config(self):
        """Сохранение конфигурации"""
        config = {
            "prefix": self.prefix.get(),
            "suffix": self.suffix.get(),
            "separator": self.separator.get(),
            "domain_format": self.domain_format.get(),
            "remove_www": self.remove_www.get(),
            "remove_duplicates": self.remove_duplicates.get(),
            "sort_results": self.sort_results.get(),
            "export_format": self.export_format.get(),
            "dark_mode": self.dark_mode.get(),
            "tld_filter": self.tld_entry.get(),
            "use_advanced_mask": self.use_advanced_mask.get(),
            "advanced_mask": self.advanced_mask.get(),
            "strip_chars": self.strip_chars.get(),
            "min_length": self.min_length.get(),
            "max_length": self.max_length.get(),
            "validate_dns": self.validate_dns.get(),
            "case_mode": self.case_mode.get(),
            "extraction_mode": self.extraction_mode.get(),
            "blacklist": self.blacklist_patterns,
            "whitelist": self.whitelist_patterns
        }
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except:
            pass

    def load_config(self):
        """Загрузка конфигурации"""
        if not os.path.exists(self.config_file):
            return
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Загрузка простых переменных
            for k, v in config.items():
                if k in ['blacklist', 'whitelist']:
                    continue
                var = getattr(self, k, None)
                if var and isinstance(var, tk.Variable):
                    var.set(v)
            
            # Загрузка списков
            self.blacklist_patterns = config.get('blacklist', [])
            self.whitelist_patterns = config.get('whitelist', [])
        except:
            pass

    def show_mask_help(self):
        """Справка по маскам"""
        help_text = """
СПРАВКА ПО ПРОДВИНУТЫМ МАСКАМ

Переменные шаблона:
  {domain}     - Полный домен (example.com)
  {name}       - Имя без TLD (example)
  {tld}        - Доменная зона (com)
  {sld}        - Second-level domain (example из example.com)
  {subdomain}  - Поддомен (www из www.example.com)
  {full}       - Оригинальный домен без изменений

Примеры использования:

1. URL формат:
   https://{domain}
   → https://example.com

2. Email формат:
   info@{domain}
   → info@example.com

3. Поддомен:
   www.{domain}
   → www.example.com

4. Пользовательский формат:
   [{sld}].{tld}
   → [example].com

5. Комплексный:
   https://{subdomain}.{name}.{tld}/api
   → https://api.example.com/api

РЕЖИМЫ ИЗВЛЕЧЕНИЯ:

Стандартный:
  - Обычные домены в тексте
  - example.com, test.org

Агрессивный:
  - Включая сложные случаи
  - subdomain.example.com
  - multi.level.domain.co.uk

Email:
  - Извлечение доменов из email
  - user@example.com → example.com

URL:
  - Из полных адресов
  - https://example.com/path → example.com

ФИЛЬТРАЦИЯ:

Чёрный список (исключить):
  google.*        - все домены Google
  *.spam.com      - все поддомены spam.com
  bad-domain.ru   - конкретный домен

Белый список (оставить только):
  *.example.com   - только домены example.com
  trusted.*       - только домены trusted

УДАЛЕНИЕ СИМВОЛОВ:

В поле "Удалить символы" укажите символы,
которые будут удалены из текста перед извлечением:
  [](){}\"'<>     - скобки и кавычки
  ,;:             - знаки препинания
"""
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Справка по маскам")
        dialog.geometry("700x600")
        
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, font=("Consolas", 9))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(1.0, help_text)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Закрыть", command=dialog.destroy).pack(pady=5)

    def show_about(self):
        """О программе"""
        about_text = """
Domain Extractor Pro v3.0

Профессиональный инструмент для извлечения 
и обработки доменных имён из текстовых файлов.

НОВЫЕ ВОЗМОЖНОСТИ v3.0:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Продвинутые маски с переменными
✓ 4 режима извлечения доменов
✓ Чёрный и белый списки
✓ Валидация DNS структуры
✓ Поддержка двухуровневых TLD
✓ Фильтрация по длине домена
✓ Настройка регистра
✓ Удаление символов
✓ История операций (Ctrl+Z)
✓ Экспорт статистики
✓ Тестер регулярных выражений
✓ Валидатор доменов
✓ Улучшенный поиск в логе
✓ Экспорт в TXT, CSV, JSON, XML

ГОРЯЧИЕ КЛАВИШИ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Ctrl+O  - Добавить файлы
Ctrl+S  - Сохранить как
F5      - Обработать
Ctrl+F  - Поиск в логе
Ctrl+Z  - Отменить последнюю операцию

© 2025 Domain Extractor Pro
Версия 3.0.0
"""
        
        dialog = tk.Toplevel(self.root)
        dialog.title("О программе")
        dialog.geometry("550x650")
        dialog.resizable(False, False)
        
        # Заголовок
        header = ttk.Label(dialog, text="Domain Extractor Pro", 
                          font=("Arial", 16, "bold"))
        header.pack(pady=10)
        
        version = ttk.Label(dialog, text="Версия 3.0.0", 
                           font=("Arial", 10), foreground="gray")
        version.pack()
        
        # Текст
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, 
                                        font=("Consolas", 9), 
                                        height=28)
        text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        text.insert(1.0, about_text)
        text.config(state=tk.DISABLED)
        
        # Кнопка
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Закрыть", command=dialog.destroy, 
                  width=15).pack()


def main():
    root = tk.Tk()
    app = DomainExtractorApp(root)
    
    # Приветственное сообщение
    app.log("=" * 70, "header")
    app.log("  Domain Extractor Pro v3.0 - Готов к работе!", "header")
    app.log("=" * 70, "header")
    app.log("\n💡 Подсказки:")
    app.log("   • Перетащите файлы в список или используйте Ctrl+O")
    app.log("   • Настройте фильтры во вкладке 'Продвинутые'")
    app.log("   • Используйте предпросмотр перед обработкой")
    app.log("   • F5 - быстрая обработка, Ctrl+Z - отмена")
    app.log("\n📚 Справка → Помощь → Справка по маскам\n")
    
    root.mainloop()


if __name__ == "__main__":
    main()
