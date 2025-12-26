"""
HTTP-сервер для управления задачами с интеграцией внешних API
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import threading

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

    def log_message(self, format, *args):
        """Отключение стандартных логов сервера для чистоты вывода"""
        pass


def main():
    """Запуск HTTP сервера для управления задачами"""
    # Загрузка существующих задач из файла при старте
    task_manager.load_from_file()

    host = '127.0.0.1'
    port = 8080

    print(f"Сервер задач запущен на http://{host}:{port}")
    print("Доступные API endpoints:")
    print("  POST /tasks - создание новой задачи")
    print("  GET /tasks - получение списка всех задач")
    print("  POST /tasks/{id}/complete - отметка задачи как выполненной")

    server = HTTPServer((host, port), TaskHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен")
        server.server_close()


if __name__ == '__main__':
    main()
