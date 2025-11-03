import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import re
from pathlib import Path
import threading

class DomainExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Domain Extractor - Обработчик доменных имен")
        self.root.geometry("1000x700")
        
        # Переменные
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.prefix = tk.StringVar(value="")
        self.suffix = tk.StringVar(value="")
        self.separator = tk.StringVar(value="\n")
        self.domain_format = tk.StringVar(value="full")
        self.remove_www = tk.BooleanVar(value=True)
        self.remove_duplicates = tk.BooleanVar(value=True)
        self.sort_results = tk.BooleanVar(value=False)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Главный контейнер
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Настройка весов для растягивания
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        row = 0
        
        # === РАЗДЕЛ ВЫБОРА ФАЙЛОВ ===
        file_frame = ttk.LabelFrame(main_frame, text="Файлы", padding="10")
        file_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        file_frame.columnconfigure(1, weight=1)
        
        # Входной файл
        ttk.Label(file_frame, text="Входной файл:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(file_frame, textvariable=self.input_file, width=50).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(file_frame, text="Обзор...", command=self.browse_input).grid(row=0, column=2, padx=2)
        
        # Выходной файл
        ttk.Label(file_frame, text="Выходной файл:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(file_frame, textvariable=self.output_file, width=50).grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(file_frame, text="Обзор...", command=self.browse_output).grid(row=1, column=2, padx=2)
        
        row += 1
        
        # === РАЗДЕЛ НАСТРОЕК ФОРМАТА ===
        format_frame = ttk.LabelFrame(main_frame, text="Формат вывода", padding="10")
        format_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        format_frame.columnconfigure(1, weight=1)
        
        # Формат домена
        ttk.Label(format_frame, text="Формат домена:").grid(row=0, column=0, sticky=tk.W, pady=2)
        format_options = ttk.Frame(format_frame)
        format_options.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Radiobutton(format_options, text="Полный (domain.com)", 
                       variable=self.domain_format, value="full").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_options, text="Без TLD (domain)", 
                       variable=self.domain_format, value="no_tld").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_options, text="Только TLD (.com)", 
                       variable=self.domain_format, value="only_tld").pack(side=tk.LEFT, padx=5)
        
        # Префикс
        ttk.Label(format_frame, text="Префикс:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(format_frame, textvariable=self.prefix, width=30).grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # Суффикс
        ttk.Label(format_frame, text="Суффикс:").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Entry(format_frame, textvariable=self.suffix, width=30).grid(row=2, column=1, sticky=tk.W, padx=5)
        
        # Разделитель
        ttk.Label(format_frame, text="Разделитель:").grid(row=3, column=0, sticky=tk.W, pady=2)
        sep_frame = ttk.Frame(format_frame)
        sep_frame.grid(row=3, column=1, sticky=tk.W, pady=2)
        
        ttk.Radiobutton(sep_frame, text="Новая строка", 
                       variable=self.separator, value="\n").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(sep_frame, text="Пробел", 
                       variable=self.separator, value=" ").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(sep_frame, text="Запятая", 
                       variable=self.separator, value=", ").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(sep_frame, text="Табуляция", 
                       variable=self.separator, value="\t").pack(side=tk.LEFT, padx=5)
        
        row += 1
        
        # === РАЗДЕЛ ДОПОЛНИТЕЛЬНЫХ ОПЦИЙ ===
        options_frame = ttk.LabelFrame(main_frame, text="Дополнительные опции", padding="10")
        options_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Checkbutton(options_frame, text="Удалить www.", 
                       variable=self.remove_www).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(options_frame, text="Удалить дубликаты", 
                       variable=self.remove_duplicates).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(options_frame, text="Сортировать результаты", 
                       variable=self.sort_results).pack(side=tk.LEFT, padx=10)
        
        row += 1
        
        # === РАЗДЕЛ КНОПОК ДЕЙСТВИЙ ===
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=row, column=0, columnspan=3, pady=10)
        
        ttk.Button(button_frame, text="Обработать файл", 
                  command=self.process_file, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Предпросмотр (100 записей)", 
                  command=self.preview_results, width=25).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Очистить", 
                  command=self.clear_log, width=15).pack(side=tk.LEFT, padx=5)
        
        row += 1
        
        # === ПРОГРЕСС БАР ===
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        
        # === РАЗДЕЛ ЛОГА ===
        log_frame = ttk.LabelFrame(main_frame, text="Лог обработки", padding="5")
        log_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=80, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        main_frame.rowconfigure(row, weight=1)
        
        # Статус бар
        self.status_label = ttk.Label(main_frame, text="Готов к работе", relief=tk.SUNKEN)
        self.status_label.grid(row=row+1, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
    def browse_input(self):
        filename = filedialog.askopenfilename(
            title="Выберите входной файл",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
        )
        if filename:
            self.input_file.set(filename)
            
    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            title="Выберите выходной файл",
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
        )
        if filename:
            self.output_file.set(filename)
            
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
        
    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
    def extract_domains(self, text):
        """Извлечение доменов из текста"""
        # Регулярное выражение для поиска доменов
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        
        domains = re.findall(domain_pattern, text)
        
        # Фильтрация валидных доменов
        valid_domains = []
        for domain in domains:
            domain = domain.lower().strip('.')
            # Проверка на минимальную длину и наличие точки
            if len(domain) > 3 and '.' in domain:
                valid_domains.append(domain)
        
        return valid_domains
    
    def format_domain(self, domain):
        """Форматирование домена согласно настройкам"""
        # Удаление www
        if self.remove_www.get() and domain.startswith('www.'):
            domain = domain[4:]
        
        # Применение формата
        if self.domain_format.get() == "no_tld":
            # Удаление TLD
            parts = domain.rsplit('.', 1)
            if len(parts) > 1:
                domain = parts[0]
        elif self.domain_format.get() == "only_tld":
            # Только TLD
            parts = domain.rsplit('.', 1)
            if len(parts) > 1:
                domain = '.' + parts[1]
        
        # Добавление префикса и суффикса
        domain = self.prefix.get() + domain + self.suffix.get()
        
        return domain
    
    def process_domains(self, input_path, output_path=None, preview_mode=False, preview_limit=100):
        """Обработка файла с доменами"""
        try:
            self.log(f"Начало обработки файла: {input_path}")
            self.update_status("Обработка...")
            
            # Чтение файла
            with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            self.log(f"Файл прочитан. Размер: {len(content)} символов")
            
            # Извлечение доменов
            domains = self.extract_domains(content)
            self.log(f"Найдено доменов: {len(domains)}")
            
            if not domains:
                self.log("⚠️ Домены не найдены в файле!")
                messagebox.showwarning("Предупреждение", "Домены не найдены в файле!")
                return []
            
            # Форматирование доменов
            formatted_domains = [self.format_domain(d) for d in domains]
            
            # Удаление дубликатов
            if self.remove_duplicates.get():
                original_count = len(formatted_domains)
                formatted_domains = list(dict.fromkeys(formatted_domains))  # Сохраняет порядок
                self.log(f"Удалено дубликатов: {original_count - len(formatted_domains)}")
            
            # Сортировка
            if self.sort_results.get():
                formatted_domains.sort()
                self.log("Результаты отсортированы")
            
            # Режим предпросмотра
            if preview_mode:
                preview_domains = formatted_domains[:preview_limit]
                self.log("\n" + "="*50)
                self.log(f"ПРЕДПРОСМОТР (первые {len(preview_domains)} из {len(formatted_domains)}):")
                self.log("="*50)
                for i, domain in enumerate(preview_domains, 1):
                    self.log(f"{i}. {domain}")
                self.log("="*50 + "\n")
                return preview_domains
            
            # Сохранение результата
            if output_path:
                separator = self.separator.get()
                # Замена \n и \t на реальные символы
                separator = separator.replace('\\n', '\n').replace('\\t', '\t')
                
                result_text = separator.join(formatted_domains)
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(result_text)
                
                self.log(f"✓ Результат сохранен в: {output_path}")
                self.log(f"✓ Всего обработано доменов: {len(formatted_domains)}")
                messagebox.showinfo("Успех", 
                    f"Обработка завершена!\n\nНайдено доменов: {len(formatted_domains)}\nСохранено в: {output_path}")
            
            self.update_status("Готово")
            return formatted_domains
            
        except Exception as e:
            self.log(f"❌ ОШИБКА: {str(e)}")
            messagebox.showerror("Ошибка", f"Произошла ошибка:\n{str(e)}")
            self.update_status("Ошибка")
            return []
        finally:
            self.progress.stop()
    
    def process_file(self):
        """Обработка файла в отдельном потоке"""
        if not self.input_file.get():
            messagebox.showwarning("Предупреждение", "Выберите входной файл!")
            return
        
        if not self.output_file.get():
            messagebox.showwarning("Предупреждение", "Выберите выходной файл!")
            return
        
        self.progress.start()
        thread = threading.Thread(target=self.process_domains, 
                                 args=(self.input_file.get(), self.output_file.get()))
        thread.daemon = True
        thread.start()
    
    def preview_results(self):
        """Предпросмотр результатов"""
        if not self.input_file.get():
            messagebox.showwarning("Предупреждение", "Выберите входной файл!")
            return
        
        self.progress.start()
        thread = threading.Thread(target=self.process_domains, 
                                 args=(self.input_file.get(),), 
                                 kwargs={'preview_mode': True})
        thread.daemon = True
        thread.start()

def main():
    root = tk.Tk()
    app = DomainExtractorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
