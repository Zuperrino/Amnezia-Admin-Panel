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
