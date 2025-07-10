# Amnezia Admin Panel

## Описание

Веб-панель для мониторинга и управления VPN-клиентами (WireGuard, AmneziaWG, XRay и др.), с автообновлением статистики, отображением пользователей, мониторингом ресурсов и топ-процессов.

---

## Быстрый старт

### 1. Клонирование и подготовка
```bash
git clone <URL-ВАШЕГО-РЕПОЗИТОРИЯ>
cd amnezia_admin_panel
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Настройка переменных окружения
Создайте файл `.env` или экспортируйте переменные:
```
DJANGO_SECRET_KEY=your-very-secret-key
DJANGO_DEBUG=False
```

Можно использовать [python-dotenv](https://pypi.org/project/python-dotenv/) для автозагрузки .env.

### 3. Миграции и суперпользователь
```bash
python manage.py migrate
python manage.py createsuperuser
```

### 4. Сборка статики (если нужно)
```bash
python manage.py collectstatic
```

### 5. Запуск через Gunicorn (production)
```bash
source venv/bin/activate
gunicorn --bind 0.0.0.0:8000 amnezia_admin_core.wsgi:application
```

---

## Автоматический запуск через systemd

Создайте файл `/etc/systemd/system/amnezia_admin_panel.service`:
```
[Unit]
Description=Amnezia Admin Panel (Gunicorn)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/amnezia_admin_panel
Environment="DJANGO_SECRET_KEY=your-very-secret-key"
Environment="DJANGO_DEBUG=False"
ExecStart=/opt/amnezia_admin_panel/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:8000 amnezia_admin_core.wsgi:application

[Install]
WantedBy=multi-user.target
```

Перезапустите и включите сервис:
```bash
sudo systemctl daemon-reload
sudo systemctl enable amnezia_admin_panel
sudo systemctl start amnezia_admin_panel
```

---

## Безопасность
- **SECRET_KEY** и **DEBUG** не должны храниться в git! Используйте переменные окружения.
- **db.sqlite3**, **venv/**, приватные ключи и пароли не должны попадать в репозиторий (см. .gitignore).
- Для production используйте HTTPS и настройте ALLOWED_HOSTS.

---

## FAQ
- **Миграции:**
    - `python manage.py makemigrations` — создать миграции
    - `python manage.py migrate` — применить миграции
- **Суперпользователь:**
    - `python manage.py createsuperuser`
- **Статика:**
    - `python manage.py collectstatic`
- **Логи:**
    - Смотрите systemd: `journalctl -u amnezia_admin_panel -f`

---

## Структура проекта
- `amnezia_admin_core/settings.py` — настройки Django
- `adminpanel/` — основное приложение
- `templates/`, `static/` — шаблоны и статика
- `manage.py` — точка входа

---

## Контакты и поддержка
- Issues: только через гитхаб