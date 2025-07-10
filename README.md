# Amnezia Admin Panel

## Описание

Веб-панель для мониторинга и управления VPN-клиентами (WireGuard, AmneziaWG, XRay и др.), с автообновлением статистики, отображением пользователей, мониторингом ресурсов и топ-процессов.

---

## Быстрый старт

### 1. Клонирование и подготовка
```bash
git clone <URL-ВАШЕГО-РЕПОЗИТОРИЯ>
cd <имя_каталога>
python3.12 -m venv venv
source venv/bin/activate
pip install --break-system-packages -r requirements.txt
```

### 2. Настройка переменных окружения
Создайте файл `.env` в корне проекта:
```
DJANGO_SECRET_KEY=your-very-secret-key
DJANGO_DEBUG=False
```

### 3. Миграции и суперпользователь
```bash
python3.12 manage.py migrate
python3.12 manage.py createsuperuser
```

### 4. Сборка статики (production)
```bash
python3.12 manage.py collectstatic
```

### 5. Запуск через Gunicorn (production)
```bash
source venv/bin/activate
venv/bin/gunicorn --bind 0.0.0.0:8000 amnezia_admin_core.wsgi:application
```

---

## Автоматический запуск через systemd

Пример файла `/etc/systemd/system/amnezia_admin_panel.service`:
```
[Unit]
Description=Amnezia Admin Panel (Gunicorn)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt
EnvironmentFile=/opt/.env
ExecStart=/opt/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:8000 amnezia_admin_core.wsgi:application

[Install]
WantedBy=multi-user.target
```

---

## Nginx (production)

Пример конфига `/etc/nginx/sites-available/amnezia_admin_panel`:
```
server {
    listen 80;
    server_name <ваш_IP>;

    location = /favicon.ico { access_log off; log_not_found off; }
    location /static/ {
        alias /opt/staticfiles/;
    }

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://127.0.0.1:8000;
    }

    client_max_body_size 20M;
    access_log /var/log/nginx/amnezia_admin_panel_access.log;
    error_log /var/log/nginx/amnezia_admin_panel_error.log;
}
```

---

## Безопасность и open source
- **В репозитории нет приватных данных**: .env, db.sqlite3, venv, staticfiles/ и другие временные/секретные файлы исключены через .gitignore.
- **SECRET_KEY и DEBUG** задаются только через переменные окружения.
- **Права доступа**: для работы с Docker пользователь www-data добавлен в группу docker.
- **Проверено**: нет лишних файлов, старых проектов, node.js, TypeScript, приватных ключей и т.д.
- **Готов к публикации на GitHub/Open Source**.

---

## FAQ
- **Миграции:**
    - `python3.12 manage.py makemigrations` — создать миграции
    - `python3.12 manage.py migrate` — применить миграции
- **Суперпользователь:**
    - `python3.12 manage.py createsuperuser`
- **Статика:**
    - `python3.12 manage.py collectstatic`
- **Логи:**
    - Смотрите systemd: `journalctl -u amnezia_admin_panel -f`

---

## Структура проекта
- `amnezia_admin_core/settings.py` — настройки Django
- `adminpanel/` — основное приложение
- `templates/`, `static/` — шаблоны и статика
- `manage.py` — точка входа
- `.gitignore` — исключает все лишние и приватные файлы

---

## Контакты и поддержка
- Issues: создавайте на GitHub
- Email: <ваш email>