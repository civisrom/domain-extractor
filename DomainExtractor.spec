import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, Menu
import re
from pathlib import Path
import threading
import json
import os
import chardet
from collections import deque
import time

class DomainExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Domain Extractor Pro v2.0")
        self.root.geometry("1150x780")
        self.root.minsize(900, 600)

        # === Переменные ===
        self.input_files = []  # Список входных файлов
        self.output_file = tk.StringVar()
        self.prefix = tk.StringVar(value="")
        self.suffix = tk.StringVar(value="")
        self.separator = tk.StringVar(value="\n")
        self.domain_format = tk.StringVar(value="full")
        self.remove_www = tk.BooleanVar(value=True)
        self.remove_duplicates = tk.BooleanVar(value=True)
        self.sort_results = tk.BooleanVar(value=False)
        self.selected_tlds = set()  # Выбранные TLD
        self.export_format = tk.StringVar(value="txt")
        self.dark_mode = tk.BooleanVar(value=False)

        # Очередь задач
        self.task_queue = deque()
        self.is_processing = False

        # Настройки
        self.config_file = "domain_extractor_config.json"
        self.load_config()

        self.create_widgets()
        self.setup_drag_drop()
        self.apply_theme()

        # Горячие клавиши
        self.root.bind("<Control-o>", lambda e: self.browse_input())
        self.root.bind("<Control-s>", lambda e: self.browse_output())
        self.root.bind("<F5>", lambda e: self.process_file())
        self.root.bind("<Control-f>", lambda e: self.focus_search())

    def create_widgets(self):
        # === Меню ===
        menubar = Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Добавить файлы (Ctrl+O)", command=self.browse_input)
        file_menu.add_command(label="Сохранить как (Ctrl+S)", command=self.browse_output)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.quit)

        view_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Вид", menu=view_menu)
        view_menu.add_checkbutton(label="Тёмная тема", variable=self.dark_mode, command=self.toggle_theme)

        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Помощь", menu=help_menu)
        help_menu.add_command(label="О программе", command=self.show_about)

        # === Основной фрейм ===
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        row = 0

        # === Входные файлы (список) ===
        input_frame = ttk.LabelFrame(main_frame, text="Входные файлы (перетащите сюда)", padding="10")
        input_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)

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
        output_frame = ttk.LabelFrame(main_frame, text="Выходной файл", padding="10")
        output_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        output_frame.columnconfigure(1, weight=1)

        ttk.Entry(output_frame, textvariable=self.output_file, width=60).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(output_frame, text="Обзор...", command=self.browse_output).grid(row=0, column=1, padx=2)

        # Формат экспорта
        ttk.Label(output_frame, text="Формат:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        format_combo = ttk.Combobox(output_frame, textvariable=self.export_format, values=["txt", "csv", "json"], state="readonly", width=10)
        format_combo.grid(row=1, column=1, sticky=tk.W, padx=5)

        row += 1

        # === Настройки формата ===
        format_frame = ttk.LabelFrame(main_frame, text="Формат вывода", padding="10")
        format_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        # Формат домена
        ttk.Label(format_frame, text="Формат:").grid(row=0, column=0, sticky=tk.W)
        format_opts = ttk.Frame(format_frame)
        format_opts.grid(row=0, column=1, sticky=tk.W, columnspan=2)
        for text, val in [("Полный", "full"), ("Без TLD", "no_tld"), ("Только TLD", "only_tld")]:
            ttk.Radiobutton(format_opts, text=text, variable=self.domain_format, value=val).pack(side=tk.LEFT, padx=5)

        # Префикс / Суффикс
        ttk.Label(format_frame, text="Префикс:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(format_frame, textvariable=self.prefix, width=20).grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Label(format_frame, text="Суффикс:").grid(row=1, column=2, sticky=tk.W, padx=10)
        ttk.Entry(format_frame, textvariable=self.suffix, width=20).grid(row=1, column=3, sticky=tk.W, padx=5)

        # Разделитель
        ttk.Label(format_frame, text="Разделитель:").grid(row=2, column=0, sticky=tk.W, pady=2)
        sep_frame = ttk.Frame(format_frame)
        sep_frame.grid(row=2, column=1, sticky=tk.W, columnspan=3)
        for text, val in [("Строка", "\n"), ("Пробел", " "), ("Запятая", ", "), ("Таб", "\t")]:
            ttk.Radiobutton(sep_frame, text=text, variable=self.separator, value=val).pack(side=tk.LEFT, padx=5)

        row += 1

        # === Фильтр TLD ===
        tld_frame = ttk.LabelFrame(main_frame, text="Фильтр по TLD (оставить пустым = все)", padding="10")
        tld_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        tld_frame.columnconfigure(0, weight=1)

        self.tld_entry = ttk.Entry(tld_frame)
        self.tld_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5)
        self.tld_entry.insert(0, ".com, .ru, .org")
        ttk.Button(tld_frame, text="Применить", command=self.update_tld_filter).grid(row=0, column=1, padx=2)

        row += 1

        # === Опции ===
        opts_frame = ttk.LabelFrame(main_frame, text="Опции", padding="10")
        opts_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        ttk.Checkbutton(opts_frame, text="Удалить www.", variable=self.remove_www).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(opts_frame, text="Удалить дубликаты", variable=self.remove_duplicates).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(opts_frame, text="Сортировать", variable=self.sort_results).pack(side=tk.LEFT, padx=10)

        row += 1

        # === Кнопки ===
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=row, column=0, columnspan=3, pady=10)
        ttk.Button(btn_frame, text="Обработать всё (F5)", command=self.process_file, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Предпросмотр", command=self.preview_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Очистить лог", command=self.clear_log).pack(side=tk.LEFT, padx=5)

        row += 1

        # === Прогресс ===
        self.progress = ttk.Progressbar(main_frame, mode='determinate', maximum=100)
        self.progress.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        row += 1

        # === Лог + поиск ===
        log_frame = ttk.LabelFrame(main_frame, text="Лог и поиск", padding="5")
        log_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)

        search_frame = ttk.Frame(log_frame)
        search_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=2)
        ttk.Label(search_frame, text="Поиск:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(search_frame, text="Найти", command=self.search_log).pack(side=tk.LEFT)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.log_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        main_frame.rowconfigure(row, weight=1)

        # === Статус ===
        self.status_label = ttk.Label(main_frame, text="Готово", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.grid(row=row+1, column=0, columnspan=3, sticky=(tk.W, tk.E))

    def setup_drag_drop(self):
        self.root.drop_target_register(tk.dnd.DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.on_drop)

    def on_drop(self, event):
        files = self.root.tk.splitlist(event.data)
        for file in files:
            if file not in self.input_files:
                self.input_files.append(file)
                self.input_listbox.insert(tk.END, Path(file).name)

    def browse_input(self):
        files = filedialog.askopenfilenames(
            title="Выберите входные файлы",
            filetypes=[("Текстовые файлы", "*.txt *.log *.csv"), ("Все файлы", "*.*")]
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
        ext = {"txt": ".txt", "csv": ".csv", "json": ".json"}.get(fmt, ".txt")
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
        self.log(f"Фильтр TLD: {', '.join('.' + t for t in self.selected_tlds) or 'отключён'}")

    def extract_domains(self, text):
        pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        domains = re.findall(pattern, text)
        valid = []
        for d in domains:
            d = d.lower().strip('.')
            if len(d) > 3 and '.' in d:
                tld = d.rsplit('.', 1)[-1]
                if not self.selected_tlds or tld in self.selected_tlds:
                    valid.append(d)
        return valid

    def format_domain(self, domain):
        if self.remove_www.get() and domain.startswith('www.'):
            domain = domain[4:]
        if self.domain_format.get() == "no_tld":
            domain = domain.rsplit('.', 1)[0]
        elif self.domain_format.get() == "only_tld":
            domain = '.' + domain.rsplit('.', 1)[-1]
        return self.prefix.get() + domain + self.suffix.get()

    def detect_encoding(self, filepath):
        with open(filepath, 'rb') as f:
            raw = f.read(100000)
            return chardet.detect(raw)['encoding'] or 'utf-8'

    def process_domains(self, input_paths, output_path=None, preview_mode=False, preview_limit=100):
        try:
            total_domains = 0
            all_formatted = []

            for idx, path in enumerate(input_paths):
                self.log(f"[{idx+1}/{len(input_paths)}] Чтение: {Path(path).name}")
                encoding = self.detect_encoding(path)
                with open(path, 'r', encoding=encoding, errors='ignore') as f:
                    content = f.read()

                domains = self.extract_domains(content)
                self.log(f"   → Найдено: {len(domains)} доменов")

                formatted = [self.format_domain(d) for d in domains]
                all_formatted.extend(formatted)
                total_domains += len(domains)

                progress = (idx + 1) / len(input_paths) * 100
                self.root.after(0, self.progress.configure, {'value': progress})

            if not all_formatted:
                self.log("Домены не найдены!")
                messagebox.showwarning("Предупреждение", "Домены не найдены ни в одном файле.")
                return

            # Удаление дубликатов
            if self.remove_duplicates.get():
                orig = len(all_formatted)
                all_formatted = list(dict.fromkeys(all_formatted))
                self.log(f"Удалено дубликатов: {orig - len(all_formatted)}")

            if self.sort_results.get():
                all_formatted.sort()

            if preview_mode:
                preview = all_formatted[:preview_limit]
                self.log("\n" + "═" * 60)
                self.log(f"ПРЕДПРОСМОТР ({len(preview)} из {len(all_formatted)}):")
                for i, d in enumerate(preview, 1):
                    self.log(f"{i:3}. {d}")
                self.log("═" * 60 + "\n")
                return

            # Экспорт
            sep = self.separator.get().replace('\\n', '\n').replace('\\t', '\t')
            fmt = self.export_format.get()

            if fmt == "txt":
                result = sep.join(all_formatted)
            elif fmt == "csv":
                result = "domain\n" + "\n".join(all_formatted)
            elif fmt == "json":
                result = json.dumps(all_formatted, ensure_ascii=False, indent=2)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(result)

            self.log(f"Успешно сохранено: {output_path}")
            self.log(f"Всего уникальных доменов: {len(all_formatted)}")
            messagebox.showinfo("Готово", f"Обработано {len(input_paths)} файл(ов)\nУникальных доменов: {len(all_formatted)}")

        except Exception as e:
            self.log(f"ОШИБКА: {e}")
            messagebox.showerror("Ошибка", str(e))
        finally:
            self.root.after(0, self.progress.stop)
            self.root.after(0, self.update_status, "Готово")
            self.is_processing = False
            self.process_queue()

    def process_file(self):
        if not self.input_files:
            messagebox.showwarning("Ошибка", "Выберите хотя бы один входной файл!")
            return
        if not self.output_file.get():
            messagebox.showwarning("Ошибка", "Выберите выходной файл!")
            return

        self.task_queue.append((self.input_files.copy(), self.output_file.get(), False))
        if not self.is_processing:
            self.process_queue()

    def preview_results(self):
        if not self.input_files:
            messagebox.showwarning("Ошибка", "Выберите входной файл!")
            return
        self.task_queue.append((self.input_files.copy(), None, True))
        if not self.is_processing:
            self.process_queue()

    def process_queue(self):
        if not self.task_queue or self.is_processing:
            return
        self.is_processing = True
        inputs, output, preview = self.task_queue.popleft()
        self.progress.start() if preview else self.progress.configure(value=0)
        thread = threading.Thread(target=self.process_domains, args=(inputs, output, preview))
        thread.daemon = True
        thread.start()

    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def update_status(self, msg):
        self.status_label.config(text=msg)

    def search_log(self):
        query = self.search_var.get().lower()
        if not query:
            return
        text = self.log_text.get(1.0, tk.END).lower()
        pos = text.find(query)
        if pos >= 0:
            self.log_text.tag_remove("search", 1.0, tk.END)
            self.log_text.tag_add("search", f"1.0+{pos}c", f"1.0+{pos+len(query)}c")
            self.log_text.tag_config("search", background="yellow")
            self.log_text.see(f"1.0+{pos}c")
        else:
            messagebox.showinfo("Поиск", "Не найдено")

    def focus_search(self):
        self.search_entry.focus()

    def toggle_theme(self):
        self.apply_theme()
        self.save_config()

    def apply_theme(self):
        theme = "clam" if not self.dark_mode.get() else "equilux"
        style = ttk.Style()
        style.theme_use(theme)
        if self.dark_mode.get():
            self.root.configure(bg="#2e2e2e")
            self.log_text.configure(bg="#1e1e1e", fg="#ffffff", insertbackground="white")
        else:
            self.root.configure(bg="SystemButtonFace")
            self.log_text.configure(bg="white", fg="black", insertbackground="black")

    def save_config(self):
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
            "tld_filter": self.tld_entry.get()
        }
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except:
            pass

    def load_config(self):
        if not os.path.exists(self.config_file):
            return
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            for k, v in config.items():
                var = getattr(self, k, None)
                if var and isinstance(var, tk.Variable):
                    var.set(v)
            if "tld_filter" in config:
                self.tld_entry.insert(0, config["tld_filter"])
        except:
            pass

    def show_about(self):
        messagebox.showinfo("О программе", "Domain Extractor Pro v2.0\n\nМощный инструмент для извлечения и обработки доменов.\n\n© 2025")

def main():
    root = tk.Tk()
    app = DomainExtractorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
