#!/usr/bin/env python3
"""
HTTP-сервер для управления задачами с интеграцией внешних API
"""

import json
import os
import base64
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import requests

# Файл для хранения задач
TASKS_FILE = "tasks.txt"


class Task:
    """Класс для представления задачи"""

    def __init__(self, task_id, title, priority, is_done=False):
        """
        Инициализация задачи

        Args:
            task_id (int): Уникальный идентификатор задачи
            title (str): Название задачи
            priority (str): Приоритет (low, normal, high)
            is_done (bool): Статус выполнения задачи
        """
        self.id = task_id
        self.title = title
        self.priority = priority
        self.is_done = is_done

    def to_dict(self):
        """Преобразование задачи в словарь для JSON сериализации"""
        return {
            "id": self.id,
            "title": self.title,
            "priority": self.priority,
            "isDone": self.is_done
        }

    @classmethod
    def from_dict(cls, data):
        """Создание объекта Task из словаря"""
        return cls(
            task_id=data["id"],
            title=data["title"],
            priority=data["priority"],
            is_done=data["isDone"]
        )


class TaskManager:
    """Менеджер задач - отвечает за хранение и управление задачами"""

    def __init__(self, tasks_file=None):
        """Инициализация менеджера задач"""
        self.tasks = {}  # Хранение задач по ID
        self.next_id = 1  # Следующий доступный ID
        self.lock = threading.Lock()  # Блокировка для потокобезопасности
        self.tasks_file = tasks_file or TASKS_FILE  # Файл для хранения задач

    def load_from_file(self):
        """Загрузка задач из файла при запуске сервера"""
        if os.path.exists(self.tasks_file):
            try:
                with open(self.tasks_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.tasks = {}
                    max_id = 0
                    for task_data in data:
                        task = Task.from_dict(task_data)
                        self.tasks[task.id] = task
                        max_id = max(max_id, task.id)
                    self.next_id = max_id + 1
                    print(f"Загружено {len(self.tasks)} задач из файла")
            except Exception as e:
                print(f"Ошибка при загрузке задач: {e}")
                self.tasks = {}
                self.next_id = 1

    def save_to_file(self):
        """Сохранение всех задач в файл"""
        try:
            # Не используем блокировку здесь, так как метод вызывается из заблокированного контекста
            tasks_list = [task.to_dict() for task in self.tasks.values()]
            with open(self.tasks_file, 'w', encoding='utf-8') as f:
                json.dump(tasks_list, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Ошибка при сохранении задач: {e}")

    def create_task(self, title, priority):
        """
        Создание новой задачи

        Args:
            title (str): Название задачи
            priority (str): Приоритет (low, normal, high)

        Returns:
            Task: Созданная задача

        Raises:
            ValueError: Если приоритет некорректный
        """
        with self.lock:
            if priority not in ["low", "normal", "high"]:
                raise ValueError("Приоритет должен быть: low, normal или high")

            task = Task(self.next_id, title, priority, False)
            self.tasks[task.id] = task
            self.next_id += 1
            self.save_to_file()
            return task

    def get_all_tasks(self):
        """Получение списка всех задач"""
        with self.lock:
            return list(self.tasks.values())

    def complete_task(self, task_id):
        """
        Отметка задачи как выполненной

        Args:
            task_id (int): ID задачи для выполнения

        Returns:
            bool: True если задача найдена и выполнена, False если не найдена
        """
        with self.lock:
            if task_id not in self.tasks:
                return False

            self.tasks[task_id].is_done = True
            self.save_to_file()
            return True


class VirusTotalScanner:
    """Класс для работы с VirusTotal API"""

    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY', '')
        self.base_url = 'https://www.virustotal.com/api/v3'

    def _get_api_key(self):
        """Получение API ключа (с проверкой переменных окружения)"""
        return os.getenv('VIRUSTOTAL_API_KEY', self.api_key)

    def get_file_hash(self, file_data):
        """Вычисление SHA-256 хеша файла"""
        return hashlib.sha256(file_data).hexdigest()

    def scan_file(self, file_data, filename):
        """
        Отправка файла на сканирование в VirusTotal

        Args:
            file_data (bytes): Данные файла
            filename (str): Имя файла

        Returns:
            dict: Результат сканирования или информация об ошибке
        """
        if not self._get_api_key():
            return {"error": "VirusTotal API key not configured"}

        try:
            headers = {
                'x-apikey': self._get_api_key(),
                'accept': 'application/json'
            }

            # Сначала проверяем, не сканировался ли уже этот файл
            file_hash = self.get_file_hash(file_data)
            existing_result = self.get_scan_result(file_hash)
            if existing_result and 'error' not in existing_result:
                return existing_result

            # Если не сканировался, отправляем на анализ
            files = {
                'file': (filename, file_data)
            }

            response = requests.post(
                f'{self.base_url}/files',
                headers=headers,
                files=files,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                analysis_id = result['data']['id']
                return self.get_analysis_result(analysis_id)
            else:
                return {"error": f"Upload failed: {response.status_code}", "details": response.text}

        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}

    def get_scan_result(self, file_hash):
        """Получение результата сканирования по хешу"""
        if not self.api_key:
            return None

        try:
            headers = {
                'x-apikey': self._get_api_key(),
                'accept': 'application/json'
            }

            response = requests.get(
                f'{self.base_url}/files/{file_hash}',
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                return response.json()
            else:
                return None

        except Exception:
            return None

    def get_analysis_result(self, analysis_id):
        """Получение результата анализа"""
        if not self._get_api_key():
            return {"error": "VirusTotal API key not configured"}

        try:
            headers = {
                'x-apikey': self._get_api_key(),
                'accept': 'application/json'
            }

            response = requests.get(
                f'{self.base_url}/analyses/{analysis_id}',
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Analysis retrieval failed: {response.status_code}"}

        except Exception as e:
            return {"error": f"Analysis retrieval failed: {str(e)}"}


class VulnersScanner:
    """Класс для работы с Vulners API"""

    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv('VULNERS_API_KEY', '')
        self.base_url = 'https://vulners.com/api/v3'

    def _get_api_key(self):
        """Получение API ключа (с проверкой переменных окружения)"""
        return os.getenv('VULNERS_API_KEY', self.api_key)

    def search_vulnerabilities(self, software_name, version=None):
        """
        Поиск уязвимостей для программного обеспечения

        Args:
            software_name (str): Название ПО
            version (str, optional): Версия ПО

        Returns:
            dict: Результаты поиска уязвимостей
        """
        if not self._get_api_key():
            return {"error": "Vulners API key not configured"}

        try:
            headers = {
                'Content-Type': 'application/json'
            }

            query = software_name
            if version:
                query += f" {version}"

            data = {
                "query": query,
                "apiKey": self._get_api_key(),
                "size": 10
            }

            response = requests.post(
                f'{self.base_url}/search/lucene/',
                headers=headers,
                json=data,
                timeout=15
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Search failed: {response.status_code}", "details": response.text}

        except Exception as e:
            return {"error": f"Search failed: {str(e)}"}

    def get_cve_details(self, cve_id):
        """
        Получение деталей уязвимости по CVE ID

        Args:
            cve_id (str): CVE идентификатор

        Returns:
            dict: Детали уязвимости
        """
        if not self._get_api_key():
            return {"error": "Vulners API key not configured"}

        try:
            headers = {
                'Content-Type': 'application/json'
            }

            data = {
                "id": cve_id,
                "apiKey": self.api_key
            }

            response = requests.post(
                f'{self.base_url}/search/id/',
                headers=headers,
                json=data,
                timeout=10
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"CVE lookup failed: {response.status_code}"}

        except Exception as e:
            return {"error": f"CVE lookup failed: {str(e)}"}


# Глобальные сканеры
vt_scanner = VirusTotalScanner()
vulners_scanner = VulnersScanner()

# Глобальный менеджер задач
task_manager = TaskManager()


class TaskHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP запросов для API задач"""

    def _read_json_body(self):
        """
        Чтение и парсинг JSON тела запроса

        Returns:
            dict or None: Распарсенный JSON или None при ошибке
        """
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return None

        raw_data = self.rfile.read(content_length)
        try:
            return json.loads(raw_data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _parse_multipart_form_data(self):
        """
        Парсинг multipart/form-data для загрузки файлов

        Returns:
            tuple: (fields, files) - словарь полей и словарь файлов
        """
        content_type = self.headers.get('Content-Type', '')
        if not content_type.startswith('multipart/form-data'):
            return {}, {}

        # Простая реализация парсинга multipart (для учебных целей)
        # В продакшене лучше использовать библиотеку типа multipart
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}, {}

        body = self.rfile.read(content_length)
        boundary = content_type.split('boundary=')[1].encode()

        fields = {}
        files = {}

        parts = body.split(b'--' + boundary)
        for part in parts:
            if b'Content-Disposition' in part:
                lines = part.split(b'\r\n')
                if len(lines) >= 3:
                    disposition_line = lines[1].decode()
                    if 'name=' in disposition_line:
                        name_start = disposition_line.find('name="') + 6
                        name_end = disposition_line.find('"', name_start)
                        field_name = disposition_line[name_start:name_end]

                        # Проверяем, является ли это файлом
                        if 'filename=' in disposition_line:
                            filename_start = disposition_line.find('filename="') + 10
                            filename_end = disposition_line.find('"', filename_start)
                            filename = disposition_line[filename_start:filename_end]

                            # Находим начало данных файла (после пустой строки)
                            data_start = part.find(b'\r\n\r\n') + 4
                            file_data = part[data_start:].rstrip(b'\r\n')

                            files[field_name] = {
                                'filename': filename,
                                'data': file_data
                            }
                        else:
                            # Обычное поле формы
                            data_start = part.find(b'\r\n\r\n') + 4
                            field_data = part[data_start:].rstrip(b'\r\n').decode()
                            fields[field_name] = field_data

        return fields, files

    def _send_json_response(self, data, status=200):
        """
        Отправка JSON ответа клиенту

        Args:
            data: Данные для сериализации в JSON
            status (int): HTTP статус код
        """
        response = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def _send_empty_response(self, status=200):
        """
        Отправка пустого ответа (без тела)

        Args:
            status (int): HTTP статус код
        """
        self.send_response(status)
        self.end_headers()

    def do_POST(self):
        """Маршрутизация POST запросов"""
        parsed_path = urlparse(self.path)
        path_parts = [p for p in parsed_path.path.split('/') if p]

        if parsed_path.path == '/tasks':
            # POST /tasks - создание новой задачи
            self._handle_create_task()
        elif len(path_parts) >= 2 and path_parts[0] == 'tasks' and path_parts[1].isdigit():
            task_id = int(path_parts[1])
            if len(path_parts) == 3 and path_parts[2] == 'complete':
                # POST /tasks/{id}/complete - выполнение задачи
                self._handle_complete_task(task_id)
            else:
                self._send_empty_response(404)
        elif parsed_path.path == '/scan/file':
            # POST /scan/file - сканирование файла через VirusTotal
            self._handle_file_scan()
        elif parsed_path.path == '/scan/vulnerabilities':
            # POST /scan/vulnerabilities - поиск уязвимостей через Vulners
            self._handle_vulnerability_scan()
        else:
            self._send_empty_response(404)

    def do_GET(self):
        """Маршрутизация GET запросов"""
        if self.path == '/tasks':
            # GET /tasks - получение списка задач
            self._handle_get_tasks()
        else:
            self._send_empty_response(404)

    def _handle_create_task(self):
        """Обработка запроса на создание новой задачи"""
        try:
            data = self._read_json_body()
            if not data or 'title' not in data or 'priority' not in data:
                self._send_json_response({"error": "Необходимо указать title и priority"}, 400)
                return

            title = data['title'].strip()
            priority = data['priority'].strip()

            if not title:
                self._send_json_response({"error": "Название задачи не может быть пустым"}, 400)
                return

            task = task_manager.create_task(title, priority)
            self._send_json_response(task.to_dict(), 201)

        except ValueError as e:
            self._send_json_response({"error": str(e)}, 400)
        except Exception as e:
            print(f"Ошибка при создании задачи: {e}")
            self._send_json_response({"error": "Внутренняя ошибка сервера"}, 500)

    def _handle_get_tasks(self):
        """Обработка запроса на получение списка всех задач"""
        try:
            tasks = task_manager.get_all_tasks()
            tasks_data = [task.to_dict() for task in tasks]
            self._send_json_response(tasks_data)
        except Exception as e:
            print(f"Ошибка при получении задач: {e}")
            self._send_json_response({"error": "Внутренняя ошибка сервера"}, 500)

    def _handle_complete_task(self, task_id):
        """
        Обработка запроса на отметку задачи как выполненной

        Args:
            task_id (int): ID задачи для выполнения
        """
        try:
            if task_manager.complete_task(task_id):
                self._send_empty_response(200)
            else:
                self._send_empty_response(404)
        except Exception as e:
            print(f"Ошибка при выполнении задачи {task_id}: {e}")
            self._send_empty_response(500)

    def _handle_file_scan(self):
        """Обработка запроса на сканирование файла через VirusTotal"""
        try:
            fields, files = self._parse_multipart_form_data()

            if 'file' not in files:
                self._send_json_response({"error": "Файл не найден в запросе"}, 400)
                return

            file_info = files['file']
            file_data = file_info['data']
            filename = file_info['filename']

            if not file_data:
                self._send_json_response({"error": "Пустой файл"}, 400)
                return

            print(f"Сканирование файла: {filename} ({len(file_data)} bytes)")
            result = vt_scanner.scan_file(file_data, filename)
            self._send_json_response(result)

        except Exception as e:
            print(f"Ошибка при сканировании файла: {e}")
            self._send_json_response({"error": "Внутренняя ошибка сервера"}, 500)

    def _handle_vulnerability_scan(self):
        """Обработка запроса на поиск уязвимостей через Vulners"""
        try:
            data = self._read_json_body()
            if not data or 'software' not in data:
                self._send_json_response({"error": "Необходимо указать поле 'software'"}, 400)
                return

            software = data['software']
            version = data.get('version')

            print(f"Поиск уязвимостей для: {software} {version or ''}")
            result = vulners_scanner.search_vulnerabilities(software, version)
            self._send_json_response(result)

        except Exception as e:
            print(f"Ошибка при поиске уязвимостей: {e}")
            self._send_json_response({"error": "Внутренняя ошибка сервера"}, 500)

    def log_message(self, format, *args):
        """Отключение стандартных логов сервера для чистоты вывода"""
        pass


def load_env_file():
    """Загрузка переменных окружения из файла env"""
    env_file = os.path.join(os.path.dirname(__file__), 'env')
    if os.path.exists(env_file):
        try:
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
                        print(f"Загружена переменная окружения: {key.strip()}")
        except Exception as e:
            print(f"Ошибка при загрузке файла env: {e}")


def main():
    """Запуск HTTP сервера для управления задачами"""
    # Загрузка переменных окружения из файла env
    load_env_file()

    # Загрузка существующих задач из файла при старте
    task_manager.load_from_file()

    host = '127.0.0.1'
    port = 8080

    print(f"Сервер задач запущен на http://{host}:{port}")
    print("Доступные API endpoints:")
    print("  POST /tasks - создание новой задачи")
    print("  GET /tasks - получение списка всех задач")
    print("  POST /tasks/{id}/complete - отметка задачи как выполненной")
    print()
    print("Дополнительные функции (требуют API ключей):")
    print("  POST /scan/file - сканирование файла через VirusTotal")
    print("  POST /scan/vulnerabilities - поиск уязвимостей через Vulners")

    server = HTTPServer((host, port), TaskHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен")
        server.server_close()


if __name__ == '__main__':
    main()
