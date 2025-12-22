#!/usr/bin/env python3

import requests

BASE_URL = "http://127.0.0.1:8080"

def test_vulnerability_scan():
    print("=== Тест поиска уязвимостей ===")
    url = f"{BASE_URL}/scan/vulnerabilities"
    data = {"software": "nginx"}

    try:
        response = requests.post(url, json=data, timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")
    print()

def test_file_scan():
    print("=== Тест сканирования файла ===")
    url = f"{BASE_URL}/scan/file"

    test_content = b"Hello, this is a test file for VirusTotal scanning."
    files = {'file': ('test.txt', test_content)}

    try:
        response = requests.post(url, files=files, timeout=30)
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Response: {result}")
    except Exception as e:
        print(f"Error: {e}")
    print()

def test_create_task():
    print("=== Тест создания задачи ===")
    url = "http://127.0.0.1:8080/tasks"
    data = {"title": "API тест задача", "priority": "high"}

    try:
        response = requests.post(url, json=data, timeout=5)
        print(f"Status: {response.status_code}")
        if response.status_code == 201:
            print("Задача успешно создана!")
            task_data = response.json()
            print(f"ID задачи: {task_data.get('id')}")
            return task_data.get('id')
        else:
            print(f"Ошибка: {response.text}")
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None
    print()

if __name__ == "__main__":
    print("Тестирование всех функций API...")
    print("Убедитесь, что сервер запущен!")
    print()

    task_id = test_create_task()
    test_vulnerability_scan()
    test_file_scan()
