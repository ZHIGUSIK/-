import socket
import requests
import json
import argparse
from datetime import datetime
from urllib.parse import urlparse


class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            'target': target,
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'vulnerabilities': []
        }

    def scan_ports(self, ports=[21, 22, 80, 443, 8080, 3306]):
        """Сканирование открытых портов на целевой системе"""
        print(f"\n[+] Сканирование портов для {self.target}...")

        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            print(f"[-] Не удалось разрешить имя хоста: {self.target}")
            return

        open_ports = []

        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"[+] Порт {port} открыт")
            sock.close()

        self.results['open_ports'] = open_ports
        return open_ports

    def check_web_vulnerabilities(self):
        """Проверка распространенных веб-уязвимостей"""
        print(f"\n[+] Проверка веб-уязвимостей для {self.target}...")

        if not hasattr(self, 'open_ports'):
            self.scan_ports()

        web_ports = [80, 443, 8080]
        has_web = any(port in self.results.get('open_ports', []) for port in web_ports)

        if not has_web:
            print("[-] Веб-сервисы не обнаружены")
            return

        schemes = ['http', 'https'] if 443 in self.results['open_ports'] else ['http']

        for scheme in schemes:
            url = f"{scheme}://{self.target}"
            try:
                # Проверка уязвимости к директориям
                test_url = f"{url}/.git/"
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200:
                    self._add_vulnerability(
                        "Раскрытие исходного кода",
                        "Обнаружен доступ к директории .git",
                        "Высокий",
                        test_url
                    )

                # Проверка устаревшего ПО
                headers = response.headers
                if 'server' in headers:
                    server = headers['server']
                    if 'Apache/2.4.1' in server:
                        self._add_vulnerability(
                            "Устаревшая версия сервера",
                            f"Используется устаревший сервер: {server}",
                            "Средний",
                            url
                        )

                # Проверка CORS misconfiguration
                if 'access-control-allow-origin' in headers and headers['access-control-allow-origin'] == '*':
                    self._add_vulnerability(
                        "Неправильная настройка CORS",
                        "Обнаружена политика CORS 'Access-Control-Allow-Origin: *'",
                        "Средний",
                        url
                    )

            except requests.RequestException as e:
                print(f"[-] Ошибка при проверке {url}: {str(e)}")

    def check_sql_injection(self, test_paths=['/product?id=1']):
        """Тестирование на возможность SQL-инъекции"""
        print(f"\n[+] Проверка на SQL-инъекции для {self.target}...")

        schemes = ['http', 'https'] if 443 in self.results.get('open_ports', []) else ['http']

        for scheme in schemes:
            base_url = f"{scheme}://{self.target}"

            for path in test_paths:
                test_url = base_url + path
                test_payloads = [
                    ("'", "SQL syntax error"),
                    ("1' OR '1'='1", "always true condition"),
                    ("1 AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))", "blind injection")
                ]

                for payload, description in test_payloads:
                    try:
                        full_url = test_url + payload
                        response = requests.get(full_url, timeout=5)

                        # Простая проверка на ошибки в ответе
                        if "error" in response.text.lower() or "syntax" in response.text.lower():
                            self._add_vulnerability(
                                "Возможная SQL-инъекция",
                                f"Обнаружена уязвимость к SQL-инъекциям ({description}) в {test_url}",
                                "Критический",
                                full_url
                            )
                            break

                    except requests.RequestException:
                        continue

    def _add_vulnerability(self, name, description, severity, location):
        """Добавление уязвимости в результаты"""
        vuln = {
            'name': name,
            'description': description,
            'severity': severity,
            'location': location,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.results['vulnerabilities'].append(vuln)
        print(f"[!] Обнаружена уязвимость: {name} ({severity})")

    def generate_report(self, filename=None):
        """Генерация отчета о сканировании"""
        if not filename:
            filename = f"vulnerability_scan_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)

        print(f"\n[+] Отчет сохранен в файл: {filename}")
        return filename

    def full_scan(self):
        """Выполнение полного сканирования"""
        self.scan_ports()
        self.check_web_vulnerabilities()
        self.check_sql_injection()
        return self.results


def main():
    parser = argparse.ArgumentParser(description='Система проверки на уязвимости')
    parser.add_argument('target', help='Целевой хост или URL')
    parser.add_argument('-p', '--ports', nargs='+', type=int, help='Порты для сканирования')
    parser.add_argument('-o', '--output', help='Файл для сохранения отчета')
    args = parser.parse_args()

    scanner = VulnerabilityScanner(args.target)

    if args.ports:
        scanner.scan_ports(args.ports)
    else:
        scanner.full_scan()

    if args.output:
        scanner.generate_report(args.output)
    else:
        scanner.generate_report()


if __name__ == '__main__':
    main()








import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from vulnerability_scanner import VulnerabilityScanner  # Импорт нашего сканера


class VulnerabilityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerability Scanner")
        self.root.geometry("800x600")
        self.create_widgets()

    def create_widgets(self):
        # Frame для параметров сканирования
        input_frame = ttk.LabelFrame(self.root, text="Параметры сканирования")
        input_frame.pack(padx=10, pady=5, fill="x")

        # Поле для ввода цели
        ttk.Label(input_frame, text="Цель (домен или IP):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.target_entry = ttk.Entry(input_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="we")

        # Поле для портов
        ttk.Label(input_frame, text="Порты (через пробел):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.ports_entry = ttk.Entry(input_frame, width=40)
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5, sticky="we")
        self.ports_entry.insert(0, "21 22 80 443 8080 3306")

        # Checkbuttons для типов сканирования
        self.scan_web_var = tk.BooleanVar(value=True)
        self.scan_sql_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(input_frame, text="Проверять веб-уязвимости", variable=self.scan_web_var).grid(row=2, column=0,
                                                                                                       padx=5, pady=2,
                                                                                                       sticky="w")
        ttk.Checkbutton(input_frame, text="Проверять SQL-инъекции", variable=self.scan_sql_var).grid(row=2, column=1,
                                                                                                     padx=5, pady=2,
                                                                                                     sticky="w")

        # Кнопки управления
        button_frame = ttk.Frame(self.root)
        button_frame.pack(padx=10, pady=5, fill="x")

        self.scan_button = ttk.Button(button_frame, text="Начать сканирование", command=self.start_scan)
        self.scan_button.pack(side="left", padx=5)

        self.save_button = ttk.Button(button_frame, text="Сохранить отчет", command=self.save_report, state="disabled")
        self.save_button.pack(side="left", padx=5)

        # Область вывода результатов
        output_frame = ttk.LabelFrame(self.root, text="Результаты сканирования")
        output_frame.pack(padx=10, pady=5, fill="both", expand=True)

        self.output_area = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_area.pack(padx=5, pady=5, fill="both", expand=True)

        # Статус бар
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken")
        status_bar.pack(side="bottom", fill="x")

        # Переменная для хранения результатов
        self.scan_results = None

    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Ошибка", "Пожалуйста, укажите цель сканирования")
            return

        try:
            ports = list(map(int, self.ports_entry.get().split()))
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректный формат портов. Укажите числа через пробел")
            return

        # Очищаем предыдущие результаты
        self.output_area.delete(1.0, tk.END)
        self.status_var.set("Сканирование начато...")
        self.scan_button.config(state="disabled")
        self.save_button.config(state="disabled")
        self.root.update()

        try:
            # Создаем сканер и выполняем проверки
            scanner = VulnerabilityScanner(target)

            # Выводим информацию о начале сканирования
            self.output_area.insert(tk.END, f"Начато сканирование: {target}\n")
            self.output_area.insert(tk.END, f"Порты для проверки: {ports}\n\n")

            # Сканирование портов
            self.output_area.insert(tk.END, "=== Сканирование портов ===\n")
            open_ports = scanner.scan_ports(ports)
            self.output_area.insert(tk.END, f"Открытые порты: {open_ports}\n\n")

            # Проверка веб-уязвимостей
            if self.scan_web_var.get():
                self.output_area.insert(tk.END, "=== Проверка веб-уязвимостей ===\n")
                scanner.check_web_vulnerabilities()

            # Проверка SQL-инъекций
            if self.scan_sql_var.get():
                self.output_area.insert(tk.END, "\n=== Проверка SQL-инъекций ===\n")
                scanner.check_sql_injection()

            # Получаем результаты
            self.scan_results = scanner.results
            self.display_results()

            self.status_var.set("Сканирование завершено")
            self.save_button.config(state="normal")

        except Exception as e:
            self.output_area.insert(tk.END, f"\nОшибка: {str(e)}\n")
            self.status_var.set("Ошибка при сканировании")
        finally:
            self.scan_button.config(state="normal")

    def display_results(self):
        if not self.scan_results:
            return

        self.output_area.insert(tk.END, "\n=== Результаты сканирования ===\n")

        # Выводим основную информацию
        self.output_area.insert(tk.END, f"Цель: {self.scan_results['target']}\n")
        self.output_area.insert(tk.END, f"Дата: {self.scan_results['date']}\n")
        self.output_area.insert(tk.END, f"Открытые порты: {self.scan_results.get('open_ports', [])}\n\n")

        # Выводим найденные уязвимости
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        if vulnerabilities:
            self.output_area.insert(tk.END, "Найденные уязвимости:\n")
            for i, vuln in enumerate(vulnerabilities, 1):
                self.output_area.insert(tk.END, f"{i}. [{vuln['severity']}] {vuln['name']}\n")
                self.output_area.insert(tk.END, f"   Описание: {vuln['description']}\n")
                self.output_area.insert(tk.END, f"   Локация: {vuln['location']}\n")
                self.output_area.insert(tk.END, f"   Время обнаружения: {vuln['timestamp']}\n\n")
        else:
            self.output_area.insert(tk.END, "Уязвимости не обнаружены\n")

    def save_report(self):
        if not self.scan_results:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Сохранить отчет"
        )

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    import json
                    json.dump(self.scan_results, f, indent=4)
                messagebox.showinfo("Успех", f"Отчет успешно сохранен в {file_path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить отчет: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerGUI(root)
    root.mainloop()
