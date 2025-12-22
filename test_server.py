#!/usr/bin/env python3

import os
import pytest
import tempfile

from server import Task, TaskManager


class TestTask:
    """Unit тесты для класса Task"""

    def test_task_creation(self):
        """Тест создания задачи"""
        task = Task(1, "Тестовая задача", "normal", False)
        assert task.id == 1
        assert task.title == "Тестовая задача"
        assert task.priority == "normal"
        assert task.is_done == False

    def test_task_to_dict(self):
        """Тест преобразования задачи в словарь"""
        task = Task(1, "Тест", "high", True)
        expected = {
            "id": 1,
            "title": "Тест",
            "priority": "high",
            "isDone": True
        }
        assert task.to_dict() == expected

    def test_task_from_dict(self):
        """Тест создания задачи из словаря"""
        data = {
            "id": 2,
            "title": "Восстановленная задача",
            "priority": "low",
            "isDone": False
        }
        task = Task.from_dict(data)
        assert task.id == 2
        assert task.title == "Восстановленная задача"
        assert task.priority == "low"
        assert task.is_done == False


class TestTaskManager:
    """Unit тесты для класса TaskManager"""

    def setup_method(self):
        """Подготовка перед каждым тестом"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()

        # Создаем временный менеджер задач
        self.manager = TaskManager()
        # Подменяем файл для тестирования (используем атрибут tasks_file)
        self.manager.tasks_file = self.temp_file.name

    def teardown_method(self):
        """Очистка после каждого теста"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_create_task_success(self):
        """Тест успешного создания задачи"""
        # Отключаем сохранение в файл для этого теста
        original_save = self.manager.save_to_file
        self.manager.save_to_file = lambda: None

        try:
            task = self.manager.create_task("Новая задача", "normal")

            assert task.id == 1
            assert task.title == "Новая задача"
            assert task.priority == "normal"
            assert task.is_done == False
            assert len(self.manager.tasks) == 1
            assert self.manager.next_id == 2
        finally:
            # Восстанавливаем оригинальный метод
            self.manager.save_to_file = original_save

    def test_create_task_invalid_priority(self):
        """Тест создания задачи с некорректным приоритетом"""
        # Отключаем сохранение в файл для этого теста
        original_save = self.manager.save_to_file
        self.manager.save_to_file = lambda: None

        try:
            with pytest.raises(ValueError, match="Приоритет должен быть: low, normal или high"):
                self.manager.create_task("Задача", "invalid")
        finally:
            self.manager.save_to_file = original_save

    def test_create_task_empty_title(self):
        """Тест создания задачи с пустым названием"""
        # Отключаем сохранение в файл для этого теста
        original_save = self.manager.save_to_file
        self.manager.save_to_file = lambda: None

        try:
            task = self.manager.create_task("", "normal")
            assert task.title == ""  # Пустое название разрешено
        finally:
            self.manager.save_to_file = original_save

    def test_get_all_tasks_empty(self):
        """Тест получения пустого списка задач"""
        tasks = self.manager.get_all_tasks()
        assert tasks == []

    def test_get_all_tasks_with_data(self):
        """Тест получения списка задач с данными"""
        # Отключаем сохранение в файл для этого теста
        original_save = self.manager.save_to_file
        self.manager.save_to_file = lambda: None

        try:
            self.manager.create_task("Задача 1", "high")
            self.manager.create_task("Задача 2", "low")

            tasks = self.manager.get_all_tasks()
            assert len(tasks) == 2
            assert tasks[0].id == 1
            assert tasks[1].id == 2
        finally:
            self.manager.save_to_file = original_save

    def test_complete_task_success(self):
        """Тест успешного выполнения задачи"""
        # Отключаем сохранение в файл для этого теста
        original_save = self.manager.save_to_file
        self.manager.save_to_file = lambda: None

        try:
            task = self.manager.create_task("Тестовая задача", "normal")
            assert task.is_done == False

            result = self.manager.complete_task(task.id)
            assert result == True
            assert self.manager.tasks[task.id].is_done == True
        finally:
            self.manager.save_to_file = original_save

    def test_complete_task_not_found(self):
        """Тест выполнения несуществующей задачи"""
        # Отключаем сохранение в файл для этого теста
        original_save = self.manager.save_to_file
        self.manager.save_to_file = lambda: None

        try:
            result = self.manager.complete_task(999)
            assert result == False
        finally:
            self.manager.save_to_file = original_save



class TestTaskManagerConcurrency:
    """Тесты для проверки потокобезопасности"""

    def setup_method(self):
        """Подготовка перед каждым тестом"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
        self.manager = TaskManager()
        self.manager.tasks_file = self.temp_file.name

    def teardown_method(self):
        """Очистка после каждого теста"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_concurrent_task_creation(self):
        """Тест создания задач в многопоточной среде"""
        import threading

        results = []
        errors = []

        # Отключаем сохранение в файл для этого теста
        original_save = self.manager.save_to_file
        self.manager.save_to_file = lambda: None

        try:
            def create_tasks(thread_id):
                try:
                    for i in range(10):
                        task = self.manager.create_task(f"Задача {thread_id}-{i}", "normal")
                        results.append((thread_id, task.id))
                except Exception as e:
                    errors.append(e)

            # Запускаем несколько потоков
            threads = []
            for thread_id in range(3):
                thread = threading.Thread(target=create_tasks, args=(thread_id,))
                threads.append(thread)

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join()

            # Проверяем результаты
            assert len(errors) == 0, f"Были ошибки: {errors}"
            assert len(results) == 30, f"Ожидалось 30 задач, получено {len(results)}"

            # Проверяем уникальность ID
            task_ids = [task_id for _, task_id in results]
            assert len(set(task_ids)) == len(task_ids), "ID задач не уникальны"
        finally:
            self.manager.save_to_file = original_save


if __name__ == "__main__":
    pytest.main([__file__])
