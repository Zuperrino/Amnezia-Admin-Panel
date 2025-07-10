from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.shortcuts import redirect
import subprocess
import psutil
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from collections import deque
import threading
import time
from django.utils import translation
from django.conf import settings
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages
import tempfile
import uuid
from django.views.decorators.http import require_POST

# Create your views here.

def set_language_from_request(request):
    lang = request.GET.get('lang')
    if lang in dict(settings.LANGUAGES):
        request.session[translation.LANGUAGE_SESSION_KEY] = lang
        translation.activate(lang)

# В начало каждого view (пример для login_view)
def login_view(request):
    set_language_from_request(request)
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            log_event('login', 'Вход в систему', user)
            return redirect('home')
        else:
            log_event('login_fail', f'Неудачный вход: {username}')
            return render(request, 'login.html', {'error': 'Неверные данные для входа'})
    return render(request, 'login.html')

@login_required
def home(request):
    return render(request, 'home.html')

@login_required
def users(request):
    import re, json
    users = []
    errors = []
    # Получаем clientsTable для имён пользователей WireGuard/AmneziaWG
    clients_table = {}
    try:
        result = subprocess.run([
            'docker', 'ps', '--format', '{{.Names}}|{{.Image}}'
        ], capture_output=True, text=True, check=True)
        wg_container = None
        for line in result.stdout.strip().split('\n'):
            if 'wireguard' in line.lower():
                wg_container = line.split('|')[0]
                break
        if wg_container:
            clients_json = subprocess.run([
                'docker', 'exec', wg_container, 'cat', '/opt/amnezia/wireguard/clientsTable'
            ], capture_output=True, text=True, check=True).stdout
            import json as _json
            for entry in _json.loads(clients_json):
                clients_table[entry['clientId']] = entry['userData'].get('clientName', '')
        else:
            errors.append('Контейнер WireGuard не найден')
    except Exception as e:
        errors.append(f'WireGuard clientsTable: {e}')
    # Получаем clientsTable для имён пользователей AmneziaWG
    awg_clients_table = {}
    try:
        awg_container = None
        for line in result.stdout.strip().split('\n'):
            if 'awg' in line.lower():
                awg_container = line.split('|')[0]
                break
        if awg_container:
            clients_json = subprocess.run([
                'docker', 'exec', awg_container, 'cat', '/opt/amnezia/awg/clientsTable'
            ], capture_output=True, text=True, check=True).stdout
            for entry in _json.loads(clients_json):
                awg_clients_table[entry['clientId']] = entry['userData'].get('clientName', '')
    except Exception as e:
        errors.append(f'AmneziaWG clientsTable: {e}')
    # Получаем clientsTable для имён пользователей XRay
    xray_clients_table = {}
    try:
        xray_container = None
        for line in result.stdout.strip().split('\n'):
            if 'xray' in line.lower():
                xray_container = line.split('|')[0]
                break
        if xray_container:
            clients_json = subprocess.run([
                'docker', 'exec', xray_container, 'cat', '/opt/amnezia/xray/clientsTable'
            ], capture_output=True, text=True, check=True).stdout
            for entry in _json.loads(clients_json):
                xray_clients_table[entry['clientId']] = entry['userData'].get('clientName', '')
    except Exception as e:
        errors.append(f'XRay clientsTable: {e}')
    # WireGuard
    try:
        if wg_container:
            conf = subprocess.run([
                'docker', 'exec', wg_container, 'cat', '/opt/amnezia/wireguard/wg0.conf'
            ], capture_output=True, text=True, check=True).stdout
            for peer in conf.split('[Peer]'):
                if 'PublicKey' in peer:
                    pub = re.search(r'PublicKey\s*=\s*(.+)', peer)
                    allowed = re.search(r'AllowedIPs\s*=\s*(.+)', peer)
                    public_key = pub.group(1).strip() if pub else ''
                    users.append({
                        'type': 'WireGuard',
                        'public_key': public_key,
                        'allowed_ips': allowed.group(1).strip() if allowed else '',
                        'name': clients_table.get(public_key, '')
                    })
        else:
            errors.append('Контейнер WireGuard не найден')
    except Exception as e:
        errors.append(f'WireGuard: {e}')
    # AmneziaWG
    try:
        if awg_container:
            conf = subprocess.run([
                'docker', 'exec', awg_container, 'cat', '/opt/amnezia/awg/wg0.conf'
            ], capture_output=True, text=True, check=True).stdout
            for peer in conf.split('[Peer]'):
                if 'PublicKey' in peer:
                    pub = re.search(r'PublicKey\s*=\s*(.+)', peer)
                    allowed = re.search(r'AllowedIPs\s*=\s*(.+)', peer)
                    public_key = pub.group(1).strip() if pub else ''
                    users.append({
                        'type': 'AmneziaWG',
                        'public_key': public_key,
                        'allowed_ips': allowed.group(1).strip() if allowed else '',
                        'name': awg_clients_table.get(public_key, '')
                    })
        else:
            errors.append('Контейнер AmneziaWG не найден')
    except Exception as e:
        errors.append(f'AmneziaWG: {e}')
    # XRay
    try:
        if xray_container:
            json_str = subprocess.run([
                'docker', 'exec', xray_container, 'cat', '/opt/amnezia/xray/server.json'
            ], capture_output=True, text=True, check=True).stdout
            data = json.loads(json_str)
            for inbound in data.get('inbounds', []):
                for client in inbound.get('settings', {}).get('clients', []):
                    client_id = client.get('id', '')
                    users.append({
                        'type': 'XRay',
                        'public_key': client_id,
                        'allowed_ips': client.get('flow', ''),
                        'name': xray_clients_table.get(client_id, '')
                    })
        else:
            errors.append('Контейнер XRay не найден')
    except Exception as e:
        errors.append(f'XRay: {e}')
    # --- Получаем трафик по пользователям ---
    traffic_stats = []
    try:
        # WireGuard
        wg_clients_json = subprocess.run([
            'docker', 'exec', 'amnezia-wireguard', 'cat', '/opt/amnezia/wireguard/clientsTable'
        ], capture_output=True, text=True, check=True).stdout
        import json as _json
        for entry in _json.loads(wg_clients_json):
            name = entry['userData'].get('clientName', '')
            rx = entry['userData'].get('dataReceived', 0)
            tx = entry['userData'].get('dataSent', 0)
            traffic_stats.append({'type': 'WireGuard', 'name': name, 'rx': rx, 'tx': tx})
    except Exception:
        pass
    try:
        # AmneziaWG
        awg_clients_json = subprocess.run([
            'docker', 'exec', 'amnezia-awg', 'cat', '/opt/amnezia/awg/clientsTable'
        ], capture_output=True, text=True, check=True).stdout
        for entry in _json.loads(awg_clients_json):
            name = entry['userData'].get('clientName', '')
            rx = entry['userData'].get('dataReceived', 0)
            tx = entry['userData'].get('dataSent', 0)
            traffic_stats.append({'type': 'AmneziaWG', 'name': name, 'rx': rx, 'tx': tx})
    except Exception:
        pass
    try:
        # XRay
        xray_clients_json = subprocess.run([
            'docker', 'exec', 'amnezia-xray', 'cat', '/opt/amnezia/xray/clientsTable'
        ], capture_output=True, text=True, check=True).stdout
        for entry in _json.loads(xray_clients_json):
            name = entry['userData'].get('clientName', '')
            rx = entry['userData'].get('dataReceived', 0)
            tx = entry['userData'].get('dataSent', 0)
            traffic_stats.append({'type': 'XRay', 'name': name, 'rx': rx, 'tx': tx})
    except Exception:
        pass
    # --- Формируем список пользователей с трафиком ---
    def format_bytes(val):
        if val is None or str(val).strip() == '' or str(val) == '—':
            return '0 B'
        # Ensure val is a number
        try:
            val = float(val)
        except (ValueError, TypeError):
            return '0 B'
        k = 1024
        sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
        i = 0
        while val >= k and i < len(sizes)-1:
            val /= k
            i += 1
        return f"{val:.2f} {sizes[i]}"
    users_with_traffic = []
    for u in users:
        # ищем трафик по имени и типу
        t = next((t for t in traffic_stats if t['name'] == u['name'] and t['type'] == u['type']), None)
        print(f"User: {u['name']} Type: {u['type']} Traffic: {t}")  # DEBUG
        def safe_traffic(val):
            if isinstance(val, str) and any(x in val for x in ['B', 'KiB', 'MiB', 'GiB', 'TiB']):
                return val
            try:
                return format_bytes(val)
            except Exception:
                return '—'
        rx = safe_traffic(t['rx']) if t and t.get('rx') is not None else '—'
        tx = safe_traffic(t['tx']) if t and t.get('tx') is not None else '—'
        u2 = u.copy()
        u2['rx'] = rx
        u2['tx'] = tx
        users_with_traffic.append(u2)
    return render(request, 'users.html', {'users': users_with_traffic, 'error': '\n'.join(errors) if errors else None})

@login_required
def monitoring(request):
    # Получаем список контейнеров через docker ps
    try:
        result = subprocess.run([
            'docker', 'ps', '--format', '{{.Names}}|{{.Image}}|{{.Status}}'
        ], capture_output=True, text=True, check=True)
        containers = []
        for line in result.stdout.strip().split('\n'):
            if line:
                name, image, status = line.split('|')
                containers.append({'name': name, 'image': image, 'status': status})
    except Exception as e:
        containers = []
        error = str(e)
    else:
        error = None
    # Общая статистика по серверу
    try:
        cpu = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(percpu=True, interval=None)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        server_stats = {
            'cpu': cpu,
            'cpu_per_core': cpu_per_core,
            'ram_total': ram.total,
            'ram_used': ram.used,
            'ram_percent': ram.percent,
            'disk_total': disk.total,
            'disk_used': disk.used,
            'disk_percent': disk.percent,
        }
    except Exception as e:
        server_stats = {'error': str(e)}
    # Трафик по клиентам WireGuard/AmneziaWG
    traffic_stats = []
    try:
        # WireGuard
        wg_clients_json = subprocess.run([
            'docker', 'exec', 'amnezia-wireguard', 'cat', '/opt/amnezia/wireguard/clientsTable'
        ], capture_output=True, text=True, check=True).stdout
        import json as _json
        for entry in _json.loads(wg_clients_json):
            name = entry['userData'].get('clientName', '')
            rx = entry['userData'].get('dataReceived', 0)
            tx = entry['userData'].get('dataSent', 0)
            traffic_stats.append({'type': 'WireGuard', 'name': name, 'rx': rx, 'tx': tx})
    except Exception:
        pass
    try:
        # AmneziaWG
        awg_clients_json = subprocess.run([
            'docker', 'exec', 'amnezia-awg', 'cat', '/opt/amnezia/awg/clientsTable'
        ], capture_output=True, text=True, check=True).stdout
        for entry in _json.loads(awg_clients_json):
            name = entry['userData'].get('clientName', '')
            rx = entry['userData'].get('dataReceived', 0)
            tx = entry['userData'].get('dataSent', 0)
            traffic_stats.append({'type': 'AmneziaWG', 'name': name, 'rx': rx, 'tx': tx})
    except Exception:
        pass
    try:
        # XRay
        xray_clients_json = subprocess.run([
            'docker', 'exec', 'amnezia-xray', 'cat', '/opt/amnezia/xray/clientsTable'
        ], capture_output=True, text=True, check=True).stdout
        for entry in _json.loads(xray_clients_json):
            name = entry['userData'].get('clientName', '')
            rx = entry['userData'].get('dataReceived', 0)
            tx = entry['userData'].get('dataSent', 0)
            traffic_stats.append({'type': 'XRay', 'name': name, 'rx': rx, 'tx': tx})
    except Exception:
        pass
    # Удаляем топ-10 процессов по CPU
    # (весь блок с top_processes и его возврат в render/JsonResponse)
    return render(request, 'monitoring.html', {
        'containers': containers,
        'error': error,
        'server_stats': server_stats,
        'traffic_stats': traffic_stats
    })

@csrf_exempt
@login_required
def monitoring_api(request):
    # Логика аналогична monitoring, но возвращает JSON
    response = None
    try:
        result = subprocess.run([
            'docker', 'ps', '--format', '{{.Names}}|{{.Image}}|{{.Status}}'
        ], capture_output=True, text=True, check=True)
        containers = []
        for line in result.stdout.strip().split('\n'):
            if line:
                name, image, status = line.split('|')
                containers.append({'name': name, 'image': image, 'status': status})
    except Exception as e:
        containers = []
        error = str(e)
    else:
        error = None
    try:
        cpu = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(percpu=True, interval=None)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        server_stats = {
            'cpu': cpu,
            'cpu_per_core': cpu_per_core,
            'ram_total': ram.total,
            'ram_used': ram.used,
            'ram_percent': ram.percent,
            'disk_total': disk.total,
            'disk_used': disk.used,
            'disk_percent': disk.percent,
        }
    except Exception as e:
        server_stats = {'error': str(e)}
    traffic_stats = []
    try:
        wg_clients_json = subprocess.run([
            'docker', 'exec', 'amnezia-wireguard', 'cat', '/opt/amnezia/wireguard/clientsTable'
        ], capture_output=True, text=True, check=True).stdout
        import json as _json
        for entry in _json.loads(wg_clients_json):
            name = entry['userData'].get('clientName', '')
            rx = entry['userData'].get('dataReceived', 0)
            tx = entry['userData'].get('dataSent', 0)
            traffic_stats.append({'type': 'WireGuard', 'name': name, 'rx': rx, 'tx': tx})
    except Exception:
        pass
    try:
        awg_clients_json = subprocess.run([
            'docker', 'exec', 'amnezia-awg', 'cat', '/opt/amnezia/awg/clientsTable'
        ], capture_output=True, text=True, check=True).stdout
        for entry in _json.loads(awg_clients_json):
            name = entry['userData'].get('clientName', '')
            rx = entry['userData'].get('dataReceived', 0)
            tx = entry['userData'].get('dataSent', 0)
            traffic_stats.append({'type': 'AmneziaWG', 'name': name, 'rx': rx, 'tx': tx})
    except Exception:
        pass
    try:
        xray_clients_json = subprocess.run([
            'docker', 'exec', 'amnezia-xray', 'cat', '/opt/amnezia/xray/clientsTable'
        ], capture_output=True, text=True, check=True).stdout
        for entry in _json.loads(xray_clients_json):
            name = entry['userData'].get('clientName', '')
            rx = entry['userData'].get('dataReceived', 0)
            tx = entry['userData'].get('dataSent', 0)
            traffic_stats.append({'type': 'XRay', 'name': name, 'rx': rx, 'tx': tx})
    except Exception:
        pass
    # Удаляем топ-10 процессов по CPU
    # (весь блок с top_processes и его возврат в render/JsonResponse)
    response = JsonResponse({
        'containers': containers,
        'error': error,
        'server_stats': server_stats,
        'traffic_stats': traffic_stats
    })
    response["Access-Control-Allow-Origin"] = "*"
    return response

@login_required
def server_control(request):
    import subprocess
    services = []
    try:
        result = subprocess.run([
            'systemctl', '--type=service', '--state=running,exited,failed', '--no-pager', '--no-legend'
        ], capture_output=True, text=True, check=True)
        for line in result.stdout.strip().split('\n'):
            if line:
                parts = line.split()
                name = parts[0]
                status = 'Работает' if 'running' in parts else 'Остановлен'
                services.append({'name': name, 'status': status})
    except Exception as e:
        pass
    return render(request, 'server_control.html', {'services': services})

@login_required
def notifications(request):
    return render(request, 'notifications.html')

@csrf_protect
@login_required
def add_user(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        proto = request.POST.get('proto', '').strip()
        if not name or proto not in ['WireGuard', 'AmneziaWG', 'XRay']:
            messages.error(request, 'Заполните все поля и выберите протокол.')
            return render(request, 'add_user.html')
        try:
            if proto == 'WireGuard':
                result = generate_wg_user(name)
            elif proto == 'AmneziaWG':
                result = generate_awg_user(name)
            elif proto == 'XRay':
                result = generate_xray_user(name)
            messages.success(request, f'Пользователь {name} ({proto}) успешно создан!')
            return redirect('users')
        except Exception as e:
            messages.error(request, f'Ошибка: {e}')
            return render(request, 'add_user.html')
    return render(request, 'add_user.html')

def generate_wg_user(name):
    import subprocess, json, os
    # 1. Получить имя контейнера
    result = subprocess.run([
        'docker', 'ps', '--format', '{{.Names}}|{{.Image}}'
    ], capture_output=True, text=True, check=True)
    wg_container = None
    for line in result.stdout.strip().split('\n'):
        if 'wireguard' in line.lower():
            wg_container = line.split('|')[0]
            break
    if not wg_container:
        raise Exception('WireGuard контейнер не найден')
    # 2. Генерация ключей внутри контейнера
    private_key = subprocess.check_output([
        'docker', 'exec', wg_container, 'wg', 'genkey'
    ]).decode().strip()
    public_key = subprocess.check_output([
        'docker', 'exec', '-i', wg_container, 'sh', '-c', f'echo "{private_key}" | wg pubkey'
    ]).decode().strip()
    # 3. AllowedIPs по умолчанию
    import uuid
    allowed_ips = f"10.8.0.{100 + int(uuid.uuid4().int % 100)}/32"
    # 4. Прочитать wg0.conf
    conf = subprocess.check_output([
        'docker', 'exec', wg_container, 'cat', '/opt/amnezia/wireguard/wg0.conf'
    ]).decode()
    # 5. Добавить секцию [Peer]
    peer_conf = f"\n[Peer]\n# {name}\nPublicKey = {public_key}\nAllowedIPs = {allowed_ips}\n"
    new_conf = conf.strip() + peer_conf
    # 6. Записать новый wg0.conf (через временный файл и docker cp)
    import tempfile
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
        tmp.write(new_conf)
        tmp_path = tmp.name
    subprocess.check_call(['docker', 'cp', tmp_path, f'{wg_container}:/opt/amnezia/wireguard/wg0.conf'])
    os.unlink(tmp_path)
    # 7. Прочитать clientsTable
    clients_json = subprocess.check_output([
        'docker', 'exec', wg_container, 'cat', '/opt/amnezia/wireguard/clientsTable'
    ]).decode()
    try:
        clients = json.loads(clients_json)
    except Exception:
        clients = []
    # 8. Добавить пользователя в clientsTable
    client_id = public_key
    clients.append({
        'clientId': client_id,
        'userData': {
            'clientName': name,
            'dataReceived': 0,
            'dataSent': 0
        }
    })
    # 9. Записать clientsTable
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
        json.dump(clients, tmp, ensure_ascii=False)
        tmp_path = tmp.name
    subprocess.check_call(['docker', 'cp', tmp_path, f'{wg_container}:/opt/amnezia/wireguard/clientsTable'])
    os.unlink(tmp_path)
    # 10. (Опционально) Перезапустить контейнер или отправить сигнал
    # subprocess.run(['docker', 'restart', wg_container])
    return True

def generate_awg_user(name):
    import subprocess, json, os, uuid, tempfile
    # 1. Получить имя контейнера
    result = subprocess.run([
        'docker', 'ps', '--format', '{{.Names}}|{{.Image}}'
    ], capture_output=True, text=True, check=True)
    awg_container = None
    for line in result.stdout.strip().split('\n'):
        if 'awg' in line.lower():
            awg_container = line.split('|')[0]
            break
    if not awg_container:
        raise Exception('AmneziaWG контейнер не найден')
    # 2. Генерация ключей внутри контейнера
    private_key = subprocess.check_output([
        'docker', 'exec', awg_container, 'wg', 'genkey'
    ]).decode().strip()
    public_key = subprocess.check_output([
        'docker', 'exec', '-i', awg_container, 'sh', '-c', f'echo "{private_key}" | wg pubkey'
    ]).decode().strip()
    allowed_ips = f"10.9.0.{100 + int(uuid.uuid4().int % 100)}/32"
    # 3. Прочитать wg0.conf
    conf = subprocess.check_output([
        'docker', 'exec', awg_container, 'cat', '/opt/amnezia/awg/wg0.conf'
    ]).decode()
    peer_conf = f"\n[Peer]\n# {name}\nPublicKey = {public_key}\nAllowedIPs = {allowed_ips}\n"
    new_conf = conf.strip() + peer_conf
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
        tmp.write(new_conf)
        tmp_path = tmp.name
    subprocess.check_call(['docker', 'cp', tmp_path, f'{awg_container}:/opt/amnezia/awg/wg0.conf'])
    os.unlink(tmp_path)
    # 4. Прочитать clientsTable
    clients_json = subprocess.check_output([
        'docker', 'exec', awg_container, 'cat', '/opt/amnezia/awg/clientsTable'
    ]).decode()
    try:
        clients = json.loads(clients_json)
    except Exception:
        clients = []
    client_id = public_key
    clients.append({
        'clientId': client_id,
        'userData': {
            'clientName': name,
            'dataReceived': 0,
            'dataSent': 0
        }
    })
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
        json.dump(clients, tmp, ensure_ascii=False)
        tmp_path = tmp.name
    subprocess.check_call(['docker', 'cp', tmp_path, f'{awg_container}:/opt/amnezia/awg/clientsTable'])
    os.unlink(tmp_path)
    return True

def generate_xray_user(name):
    import subprocess, json, os, uuid, tempfile
    # 1. Получить имя контейнера
    result = subprocess.run([
        'docker', 'ps', '--format', '{{.Names}}|{{.Image}}'
    ], capture_output=True, text=True, check=True)
    xray_container = None
    for line in result.stdout.strip().split('\n'):
        if 'xray' in line.lower():
            xray_container = line.split('|')[0]
            break
    if not xray_container:
        raise Exception('XRay контейнер не найден')
    # 2. Генерация UUID
    client_id = str(uuid.uuid4())
    # 3. Прочитать server.json
    server_json = subprocess.check_output([
        'docker', 'exec', xray_container, 'cat', '/opt/amnezia/xray/server.json'
    ]).decode()
    data = json.loads(server_json)
    # 4. Добавить клиента в первый inbound
    if data.get('inbounds'):
        clients = data['inbounds'][0]['settings']['clients']
        clients.append({
            'id': client_id,
            'email': name,
            'flow': '',
        })
    else:
        raise Exception('Некорректный server.json (нет inbounds)')
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
        json.dump(data, tmp, ensure_ascii=False)
        tmp_path = tmp.name
    subprocess.check_call(['docker', 'cp', tmp_path, f'{xray_container}:/opt/amnezia/xray/server.json'])
    os.unlink(tmp_path)
    # 5. Прочитать clientsTable
    clients_json = subprocess.check_output([
        'docker', 'exec', xray_container, 'cat', '/opt/amnezia/xray/clientsTable'
    ]).decode()
    try:
        clients_table = json.loads(clients_json)
    except Exception:
        clients_table = []
    clients_table.append({
        'clientId': client_id,
        'userData': {
            'clientName': name,
            'dataReceived': 0,
            'dataSent': 0
        }
    })
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
        json.dump(clients_table, tmp, ensure_ascii=False)
        tmp_path = tmp.name
    subprocess.check_call(['docker', 'cp', tmp_path, f'{xray_container}:/opt/amnezia/xray/clientsTable'])
    os.unlink(tmp_path)
    return True

# Удаление пользователя (по имени и протоколу)
def delete_user(name, proto):
    import subprocess, json, os, tempfile
    # Получить имя контейнера
    result = subprocess.run([
        'docker', 'ps', '--format', '{{.Names}}|{{.Image}}'
    ], capture_output=True, text=True, check=True)
    container = None
    proto_dir = None
    if proto == 'WireGuard':
        for line in result.stdout.strip().split('\n'):
            if 'wireguard' in line.lower():
                container = line.split('|')[0]
                proto_dir = '/opt/amnezia/wireguard'
                break
    elif proto == 'AmneziaWG':
        for line in result.stdout.strip().split('\n'):
            if 'awg' in line.lower():
                container = line.split('|')[0]
                proto_dir = '/opt/amnezia/awg'
                break
    elif proto == 'XRay':
        for line in result.stdout.strip().split('\n'):
            if 'xray' in line.lower():
                container = line.split('|')[0]
                proto_dir = '/opt/amnezia/xray'
                break
    if not container:
        raise Exception(f'Контейнер {proto} не найден')
    # Удаление из конфигов
    if proto in ['WireGuard', 'AmneziaWG']:
        conf = subprocess.check_output([
            'docker', 'exec', container, 'cat', f'{proto_dir}/wg0.conf'
        ]).decode()
        # Удалить секцию [Peer] с нужным именем
        peers = conf.split('[Peer]')
        new_conf = peers[0]
        for peer in peers[1:]:
            if f'# {name}' not in peer:
                new_conf += '[Peer]' + peer
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            tmp.write(new_conf.strip())
            tmp_path = tmp.name
        subprocess.check_call(['docker', 'cp', tmp_path, f'{container}:{proto_dir}/wg0.conf'])
        os.unlink(tmp_path)
    elif proto == 'XRay':
        server_json = subprocess.check_output([
            'docker', 'exec', container, 'cat', f'{proto_dir}/server.json'
        ]).decode()
        data = json.loads(server_json)
        if data.get('inbounds'):
            clients = data['inbounds'][0]['settings']['clients']
            data['inbounds'][0]['settings']['clients'] = [c for c in clients if c.get('email') != name]
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            json.dump(data, tmp, ensure_ascii=False)
            tmp_path = tmp.name
        subprocess.check_call(['docker', 'cp', tmp_path, f'{container}:{proto_dir}/server.json'])
        os.unlink(tmp_path)
    # Удаление из clientsTable
    clients_json = subprocess.check_output([
        'docker', 'exec', container, 'cat', f'{proto_dir}/clientsTable'
    ]).decode()
    try:
        clients = json.loads(clients_json)
    except Exception:
        clients = []
    clients = [c for c in clients if c['userData'].get('clientName') != name]
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
        json.dump(clients, tmp, ensure_ascii=False)
        tmp_path = tmp.name
    subprocess.check_call(['docker', 'cp', tmp_path, f'{container}:{proto_dir}/clientsTable'])
    os.unlink(tmp_path)
    return True

# Деактивация пользователя (по имени и протоколу)
def deactivate_user(name, proto):
    import subprocess, json, os, tempfile
    # Получить имя контейнера
    result = subprocess.run([
        'docker', 'ps', '--format', '{{.Names}}|{{.Image}}'
    ], capture_output=True, text=True, check=True)
    container = None
    proto_dir = None
    if proto == 'WireGuard':
        for line in result.stdout.strip().split('\n'):
            if 'wireguard' in line.lower():
                container = line.split('|')[0]
                proto_dir = '/opt/amnezia/wireguard'
                break
    elif proto == 'AmneziaWG':
        for line in result.stdout.strip().split('\n'):
            if 'awg' in line.lower():
                container = line.split('|')[0]
                proto_dir = '/opt/amnezia/awg'
                break
    elif proto == 'XRay':
        for line in result.stdout.strip().split('\n'):
            if 'xray' in line.lower():
                container = line.split('|')[0]
                proto_dir = '/opt/amnezia/xray'
                break
    if not container:
        raise Exception(f'Контейнер {proto} не найден')
    # Деактивация в конфиге
    if proto in ['WireGuard', 'AmneziaWG']:
        conf = subprocess.check_output([
            'docker', 'exec', container, 'cat', f'{proto_dir}/wg0.conf'
        ]).decode()
        peers = conf.split('[Peer]')
        new_conf = peers[0]
        for peer in peers[1:]:
            if f'# {name}' in peer:
                # Комментируем строки секции
                peer_lines = ['#DEACTIVATED ' + l if l.strip() and not l.strip().startswith('#') else l for l in peer.splitlines(True)]
                new_conf += '[Peer]' + ''.join(peer_lines)
            else:
                new_conf += '[Peer]' + peer
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            tmp.write(new_conf.strip())
            tmp_path = tmp.name
        subprocess.check_call(['docker', 'cp', tmp_path, f'{container}:{proto_dir}/wg0.conf'])
        os.unlink(tmp_path)
    elif proto == 'XRay':
        server_json = subprocess.check_output([
            'docker', 'exec', container, 'cat', f'{proto_dir}/server.json'
        ]).decode()
        data = json.loads(server_json)
        if data.get('inbounds'):
            for c in data['inbounds'][0]['settings']['clients']:
                if c.get('email') == name:
                    c['disabled'] = True
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            json.dump(data, tmp, ensure_ascii=False)
            tmp_path = tmp.name
        subprocess.check_call(['docker', 'cp', tmp_path, f'{container}:{proto_dir}/server.json'])
        os.unlink(tmp_path)
    # Деактивация в clientsTable (добавляем поле disabled)
    clients_json = subprocess.check_output([
        'docker', 'exec', container, 'cat', f'{proto_dir}/clientsTable'
    ]).decode()
    try:
        clients = json.loads(clients_json)
    except Exception:
        clients = []
    for c in clients:
        if c['userData'].get('clientName') == name:
            c['userData']['disabled'] = True
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
        json.dump(clients, tmp, ensure_ascii=False)
        tmp_path = tmp.name
    subprocess.check_call(['docker', 'cp', tmp_path, f'{container}:{proto_dir}/clientsTable'])
    os.unlink(tmp_path)
    return True

# История метрик (храним последние 60 точек, ~3-5 минут)
METRICS_HISTORY = deque(maxlen=60)
METRICS_LOCK = threading.Lock()

# История событий (храним последние 200 событий)
EVENTS_HISTORY = deque(maxlen=200)
EVENTS_LOCK = threading.Lock()

# Утилита для логирования событий
def log_event(event_type, message, user=None):
    from datetime import datetime
    with EVENTS_LOCK:
        EVENTS_HISTORY.appendleft({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'user': getattr(user, 'username', None) if user else None,
            'message': message,
        })

# Фоновый сборщик метрик
def collect_metrics():
    while True:
        data = {
            'timestamp': int(time.time()),
            'cpu': psutil.cpu_percent(),
            'ram': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('/').percent,
            'net': psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv,
        }
        with METRICS_LOCK:
            METRICS_HISTORY.append(data)
        # Алерты
        if data['cpu'] > 90:
            log_event('alert', f'Высокая загрузка CPU: {data["cpu"]}%')
        if data['ram'] > 90:
            log_event('alert', f'Высокая загрузка RAM: {data["ram"]}%')
        if data['disk'] > 95:
            log_event('alert', f'Мало места на диске: {data["disk"]}%')
        time.sleep(3)

# Запускать сборщик только один раз
if not hasattr(psutil, '_amnezia_metrics_started'):
    threading.Thread(target=collect_metrics, daemon=True).start()
    psutil._amnezia_metrics_started = True

@csrf_exempt
@login_required
def metrics_history_api(request):
    with METRICS_LOCK:
        history = list(METRICS_HISTORY)
    return JsonResponse({'history': history})

@csrf_exempt
@login_required
def events_history_api(request):
    with EVENTS_LOCK:
        events = list(EVENTS_HISTORY)
    return JsonResponse({'events': events})

@require_POST
@login_required
def delete_user_view(request):
    name = request.POST.get('name')
    proto = request.POST.get('proto')
    try:
        delete_user(name, proto)
        messages.success(request, f'Пользователь {name} ({proto}) удалён.')
    except Exception as e:
        messages.error(request, f'Ошибка удаления: {e}')
    return redirect('users')

@require_POST
@login_required
def deactivate_user_view(request):
    name = request.POST.get('name')
    proto = request.POST.get('proto')
    try:
        deactivate_user(name, proto)
        messages.success(request, f'Пользователь {name} ({proto}) временно деактивирован.')
    except Exception as e:
        messages.error(request, f'Ошибка деактивации: {e}')
    return redirect('users')
