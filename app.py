from flask import Flask, request, redirect, render_template_string, jsonify, Response, flash
import sqlite3, csv, io, socket, sys
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "kii-monitor-secret"
DB = "kii.db"

# =====================================================================
# МОНИТОРИНГ И УПРАВЛЕНИЕ ИНЦИДЕНТАМИ КИИ
# =====================================================================

CORRELATION_RULES = [
    {"name": "Массовая сетевая атака",  "event_type": "Сетевая атака",              "threshold": 3, "severity": "critical"},
    {"name": "Повторный НСД",           "event_type": "Несанкционированный доступ",  "threshold": 2, "severity": "high"},
    {"name": "Серия утечек",            "event_type": "Утечка данных",              "threshold": 2, "severity": "critical"},
    {"name": "Всплеск вредоносного ПО", "event_type": "Вредоносное ПО",             "threshold": 3, "severity": "high"},
    {"name": "Отказ в обслуживании",    "event_type": "Отказ в обслуживании",       "threshold": 2, "severity": "critical"},
]

SLA_HOURS       = {"low": 72, "medium": 24, "high": 8, "critical": 2}
SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 15}
CATEGORY_WEIGHT = {"1": 3, "2": 2, "3": 1}


# ------------------------- ЕДИНОЕ ПОДКЛЮЧЕНИЕ -----------------------
def db_connect():
    """Единая точка подключения: таймаут + WAL (чтение при записи)."""
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


# ------------------------- Инициализация БД -------------------------
def init_db():
    with db_connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS objects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, category TEXT, location TEXT, responsible TEXT,
            status TEXT DEFAULT 'норма', created_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id INTEGER, event_type TEXT, severity TEXT,
            description TEXT, source_ip TEXT,
            detected_at TEXT, resolved INTEGER DEFAULT 0, resolved_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id INTEGER, rule_name TEXT, severity TEXT,
            description TEXT, created_at TEXT, resolved INTEGER DEFAULT 0,
            resolved_at TEXT, sla_deadline TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT, severity TEXT, ts TEXT, read INTEGER DEFAULT 0)""")
    migrate_db()


def migrate_db():
    """Добавляет недостающие столбцы в старую БД."""
    expected = {
        "objects":   {"location": "TEXT", "responsible": "TEXT",
                      "created_at": "TEXT", "status": "TEXT DEFAULT 'норма'"},
        "events":    {"source_ip": "TEXT", "resolved": "INTEGER DEFAULT 0",
                      "resolved_at": "TEXT"},
        "incidents": {"resolved": "INTEGER DEFAULT 0", "resolved_at": "TEXT",
                      "sla_deadline": "TEXT"},
    }
    with db_connect() as c:
        for table, cols in expected.items():
            existing = {row[1] for row in c.execute(f"PRAGMA table_info({table})")}
            for col, typ in cols.items():
                if col not in existing:
                    try:
                        c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
                        print(f"➕ Добавлен столбец {table}.{col}")
                    except sqlite3.OperationalError as e:
                        print(f"⚠️  {table}.{col}: {e}")


def seed_orenburg():
    """Заполняет БД объектами КИИ Оренбурга и области (при первом запуске)."""
    demo = [
        ("АСУ ТП Оренбургского ГПЗ",                      "1", "п. Газзавод",     "Ковалёв А.Н."),
        ("SCADA газопромыслового управления",             "1", "г. Оренбург",     "Мухин С.П."),
        ("Система телеметрии магистрального газопровода", "1", "г. Оренбург",     "Абрамов В.И."),
        ("АСУ ТП нефтеперекачивающей станции",            "1", "п. Переволоцкий", "Сафин Р.Т."),
        ("Система учёта газа промышленных потребителей",  "2", "г. Оренбург",     "Юсупов Д.М."),
        ("АСУ ТП Ириклинской ГРЭС",                       "1", "п. Ириклинский",  "Волков П.С."),
        ("SCADA Сакмарской ТЭЦ",                          "1", "г. Оренбург",     "Никитин А.Ю."),
        ("Диспетчерский пункт «Оренбургэнерго»",          "1", "г. Оренбург",     "Смирнов Г.В."),
        ("Система учёта электроэнергии области",          "2", "г. Оренбург",     "Фёдорова Л.И."),
        ("АСУ ТП подстанции 500 кВ «Преображенская»",     "1", "п. Преображенка", "Зайцев И.К."),
        ("АСУ диспетчеризации аэропорта Оренбург",        "1", "г. Оренбург",     "Белов М.А."),
        ("Система управления ж/д узлом",                  "1", "г. Оренбург",     "Романов С.Н."),
        ("АСУ дорожного движения города",                 "2", "г. Оренбург",     "Гусев А.П."),
        ("Портал продажи билетов",                        "3", "г. Оренбург",     "Иванова О.С."),
        ("Система управления трамвайной сетью",           "2", "г. Оренбург",     "Петрова Т.Д."),
        ("МИС Оренбургской областной больницы",           "1", "г. Оренбург",     "Соколова Н.А."),
        ("АСУ скорой медицинской помощи",                 "1", "г. Оренбург",     "Григорьев П.Л."),
        ("Система телемедицины области",                  "2", "г. Оренбург",     "Морозова Е.В."),
        ("Регистратура поликлиники №5",                   "3", "г. Орск",         "Захаров К.Ю."),
        ("Портал госуслуг Оренбургской области",          "1", "г. Оренбург",     "Сидорова А.В."),
        ("АПК «Безопасный город»",                        "1", "г. Оренбург",     "Чернов Д.С."),
        ("ГИС ЖКХ Оренбурга",                             "2", "г. Оренбург",     "Максимова Е.П."),
        ("Система управления светофорами",                "3", "г. Оренбург",     "Игнатьев Б.О."),
        ("Портал записи к врачу",                         "3", "г. Оренбург",     "Лебедева И.Н."),
        ("АСУ ТП Орского машиностроительного завода",     "1", "г. Орск",         "Тихонов В.В."),
        ("MES-система «Оренбургнефть»",                   "1", "г. Бузулук",      "Белов Р.С."),
        ("АСУ ТП Сорочинского МЭЗ",                       "2", "г. Сорочинск",    "Алексеева Л.Г."),
        ("Система управления элеватором",                 "3", "г. Бугуруслан",   "Юсупов Т.Р."),
        ("Ядро сети оператора связи",                     "1", "г. Оренбург",     "Волков Г.И."),
        ("Система биллинга абонентов",                    "2", "г. Оренбург",     "Кириллова Н.С."),
        ("Портал самообслуживания абонентов",             "3", "г. Оренбург",     "Матвеев А.Ю."),
    ]
    with db_connect() as c:
        if c.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0:
            for name, cat, loc, resp in demo:
                c.execute("""INSERT INTO objects (name,category,location,responsible,created_at)
                             VALUES (?,?,?,?,?)""",
                          (name, cat, loc, resp,
                           datetime.now().strftime("%Y-%m-%d %H:%M")))
            print(f"✅ Загружено {len(demo)} объектов КИИ Оренбуржья")


# ---------------------- Уведомления (в том же соединении) -----------
def notify(conn, message, severity="medium"):
    """Пишет уведомление, используя ПЕРЕДАННОЕ соединение (без вложенных)."""
    conn.execute("INSERT INTO notifications (message,severity,ts) VALUES (?,?,?)",
                 (message, severity, datetime.now().strftime("%Y-%m-%d %H:%M")))


# ---------------------- Корреляция ----------------------------------
def correlate(obj_id):
    """Правило: N событий одного типа → 1 инцидент. Всё в ОДНОЙ транзакции."""
    with db_connect() as c:
        for rule in CORRELATION_RULES:
            cnt = c.execute("""SELECT COUNT(*) FROM events
                               WHERE object_id=? AND event_type=? AND resolved=0""",
                            (obj_id, rule["event_type"])).fetchone()[0]
            if cnt < rule["threshold"]:
                continue
            exists = c.execute("""SELECT 1 FROM incidents
                                  WHERE object_id=? AND rule_name=? AND resolved=0""",
                               (obj_id, rule["name"])).fetchone()
            if exists:
                continue

            deadline = (datetime.now() +
                        timedelta(hours=SLA_HOURS[rule["severity"]])).strftime("%Y-%m-%d %H:%M")
            c.execute("""INSERT INTO incidents
                (object_id,rule_name,severity,description,created_at,sla_deadline)
                VALUES (?,?,?,?,?,?)""",
                (obj_id, rule["name"], rule["severity"],
                 f"Правило «{rule['name']}»: {cnt}×«{rule['event_type']}»",
                 datetime.now().strftime("%Y-%m-%d %H:%M"), deadline))
            c.execute("UPDATE objects SET status='критично' WHERE id=?", (obj_id,))
            notify(c, f"🚨 Инцидент «{rule['name']}» на объекте ID={obj_id}",
                   rule["severity"])
            print(f"🚨 Создан инцидент «{rule['name']}» для объекта ID={obj_id}")


# ---------------------- Риск-скоринг --------------------------------
def risk_score(obj_id):
    with db_connect() as c:
        cat = c.execute("SELECT category FROM objects WHERE id=?", (obj_id,)).fetchone()
        if not cat:
            return 0
        score = 0
        for sev, cnt in c.execute("""SELECT severity, COUNT(*) FROM events
                                     WHERE object_id=? AND resolved=0
                                     GROUP BY severity""", (obj_id,)):
            score += SEVERITY_WEIGHT.get(sev, 0) * cnt
        return score * CATEGORY_WEIGHT.get(cat[0], 1)


def sla_status(deadline):
    if not deadline: return ("—", "secondary")
    try:
        d = datetime.strptime(deadline, "%Y-%m-%d %H:%M")
    except Exception:
        return ("—", "secondary")
    if datetime.now() > d:                       return ("просрочен", "danger")
    if datetime.now() > d - timedelta(hours=1):  return ("истекает",  "warning")
    return ("в норме", "success")


# ========================== HTML =====================================
BASE_STYLE = """
<style>
 body{font-family:Arial;background:#f4f6f9;margin:0;padding:20px;color:#222}
 h1,h2,h3{color:#1a2b4c;margin:0 0 10px}
 a{color:#1a2b4c}
 .nav{background:#1a2b4c;color:#fff;padding:10px 16px;border-radius:8px;margin-bottom:16px;
      display:flex;gap:16px;align-items:center;flex-wrap:wrap}
 .nav a{color:#fff;text-decoration:none;font-size:14px}
 .nav a:hover{text-decoration:underline}
 .card{background:#fff;padding:16px;border-radius:8px;margin-bottom:16px;
       box-shadow:0 2px 6px rgba(0,0,0,.08)}
 table{width:100%;border-collapse:collapse;margin-top:8px}
 th,td{padding:7px;border-bottom:1px solid #eee;font-size:13px;text-align:left}
 th{background:#1a2b4c;color:#fff}
 .badge{padding:3px 8px;border-radius:12px;color:#fff;font-size:12px;display:inline-block}
 .норма{background:#28a745}.внимание{background:#ffc107;color:#000}.критично{background:#dc3545}
 .low{background:#28a745}.medium{background:#ffc107;color:#000}
 .high{background:#fd7e14}.critical{background:#dc3545}
 .success{background:#28a745}.warning{background:#ffc107;color:#000}
 .danger{background:#dc3545}.secondary{background:#6c757d}
 form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
 input,select,textarea{padding:7px;border:1px solid #ccc;border-radius:6px;font-size:13px}
 button{padding:7px 12px;border:none;border-radius:6px;background:#1a2b4c;color:#fff;cursor:pointer}
 button:hover{background:#2c4a80}
 .btn-sm{padding:3px 9px;font-size:12px;background:#28a745}
 .btn-red{background:#dc3545}
 .info{background:#e7f1ff;border-left:4px solid #1a2b4c;padding:10px;margin-bottom:16px;font-size:13px}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
 .stat{background:#fff;padding:14px;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,.08);text-align:center}
 .stat b{font-size:22px;display:block;color:#1a2b4c}
 .risk-bar{height:8px;background:#eee;border-radius:4px;overflow:hidden;margin-top:4px}
 .risk-bar>div{height:100%;background:#dc3545}
 .notif{padding:8px 12px;border-radius:6px;margin-bottom:6px;font-size:13px}
 .notif.critical{background:#f8d7da}.notif.high{background:#ffe5cc}
 .notif.medium{background:#fff3cd}.notif.low{background:#d4edda}
 .flash{background:#d4edda;border-left:4px solid #28a745;padding:10px;margin-bottom:12px;border-radius:6px}
</style>
"""

NAV = """
<div class="nav">
  <a href="/">🏠 Объекты</a>
  <a href="/analytics">📊 Аналитика</a>
  <a href="/incidents">🚨 Инциденты</a>
  <a href="/export/events.csv">⬇️ Экспорт CSV</a>
  <a href="/api/objects">🔌 API objects</a>
</div>
"""


# ========================== Главная ==================================
PAGE = BASE_STYLE + NAV + """
{% with msgs = get_flashed_messages() %}
  {% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}
{% endwith %}

<div class="info">
<b>Система мониторинга и управления инцидентами КИИ.</b>
</div>

<div class="grid">
  <div class="stat">Объектов<b>{{ total_obj }}</b></div>
  <div class="stat">Открытых событий<b>{{ open_ev }}</b></div>
  <div class="stat">Инцидентов<b style="color:#dc3545">{{ open_inc }}</b></div>
  <div class="stat">SLA просрочено<b style="color:#dc3545">{{ sla_bad }}</b></div>
</div>

{% if notifications %}
<div class="card">
  <h3>🔔 Уведомления</h3>
  {% for n in notifications %}
    <div class="notif {{ n.severity }}">[{{ n.ts }}] {{ n.message }}</div>
  {% endfor %}
</div>
{% endif %}

<div class="card">
  <h3>Добавить объект КИИ</h3>
  <form method="post" action="/add_object">
    <input name="name" placeholder="Название" required>
    <select name="category">
      <option value="1">Категория 1</option><option value="2">Категория 2</option>
      <option value="3">Категория 3</option></select>
    <input name="location" placeholder="Расположение">
    <input name="responsible" placeholder="Ответственный">
    <button>Добавить</button>
  </form>
</div>

{% for o in objects %}
<div class="card">
  <h3>{{ o.name }}
    <span class="badge {{ o.status }}">{{ o.status }}</span>
    <small style="color:#888">(кат. {{ o.category }}{% if o.location %}, {{ o.location }}{% endif %})</small>
  </h3>
  <div style="font-size:13px;color:#555">
    Риск-скор: <b>{{ o.risk }}</b>
    <div class="risk-bar"><div style="width:{{ o.risk_pct }}%"></div></div>
  </div>

  <form method="post" action="/add_event/{{ o.id }}" style="margin-top:10px">
    <select name="event_type">
      <option>Несанкционированный доступ</option>
      <option>Вредоносное ПО</option>
      <option>Сетевая атака</option>
      <option>Утечка данных</option>
      <option>Отказ в обслуживании</option>
    </select>
    <select name="severity">
      <option value="low">Низкая</option><option value="medium">Средняя</option>
      <option value="high">Высокая</option><option value="critical">Критическая</option>
    </select>
    <input name="source_ip" placeholder="IP-источник" style="width:130px">
    <input name="description" placeholder="Описание" style="flex:1">
    <button>Зафиксировать</button>
  </form>

  {% if o.incidents %}
  <h4 style="margin-top:14px;color:#dc3545">🚨 Инциденты</h4>
  <table>
    <tr><th>Время</th><th>Правило</th><th>Ур.</th><th>SLA до</th><th>Состояние</th><th>Описание</th><th></th></tr>
    {% for i in o.incidents %}
    <tr>
      <td>{{ i.created_at }}</td><td>{{ i.rule_name }}</td>
      <td><span class="badge {{ i.severity }}">{{ i.severity }}</span></td>
      <td>{{ i.sla_deadline }}</td>
      <td><span class="badge {{ i.sla_class }}">{{ i.sla_text }}</span></td>
      <td>{{ i.description }}</td>
      <td>{% if not i.resolved %}
        <form method="post" action="/resolve_incident/{{ i.id }}">
          <button class="btn-sm">Закрыть</button></form>
      {% else %}✅{% endif %}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if o.events %}
  <h4 style="margin-top:14px">📋 События</h4>
  <table>
    <tr><th>Время</th><th>Тип</th><th>Ур.</th><th>IP</th><th>Описание</th><th></th></tr>
    {% for e in o.events %}
    <tr>
      <td>{{ e.detected_at }}</td><td>{{ e.event_type }}</td>
      <td><span class="badge {{ e.severity }}">{{ e.severity }}</span></td>
      <td>{{ e.source_ip or '—' }}</td>
      <td>{{ e.description or '—' }}</td>
      <td>{% if not e.resolved %}
        <form method="post" action="/resolve/{{ e.id }}">
          <button class="btn-sm">Закрыть</button></form>
      {% else %}✅{% endif %}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
</div>
{% endfor %}
"""


@app.route("/")
def index():
    with db_connect() as c:
        c.row_factory = sqlite3.Row
        objects = [dict(r) for r in c.execute("SELECT * FROM objects ORDER BY category, id")]
        for o in objects:
            o["events"] = [dict(r) for r in c.execute(
                "SELECT * FROM events WHERE object_id=? ORDER BY detected_at DESC LIMIT 10", (o["id"],))]
            incs = [dict(r) for r in c.execute(
                "SELECT * FROM incidents WHERE object_id=? ORDER BY created_at DESC", (o["id"],))]
            for i in incs:
                i["sla_text"], i["sla_class"] = sla_status(i["sla_deadline"])
            o["incidents"] = incs
            o["risk"] = risk_score(o["id"])
            o["risk_pct"] = min(100, o["risk"] * 2)

        total_obj = len(objects)
        open_ev   = c.execute("SELECT COUNT(*) FROM events WHERE resolved=0").fetchone()[0]
        open_inc  = c.execute("SELECT COUNT(*) FROM incidents WHERE resolved=0").fetchone()[0]
        notifications = [dict(r) for r in c.execute(
            "SELECT * FROM notifications WHERE read=0 ORDER BY ts DESC LIMIT 5")]

    sla_bad = sum(1 for o in objects for i in o["incidents"]
                  if not i["resolved"] and i["sla_class"] == "danger")

    return render_template_string(PAGE, objects=objects, total_obj=total_obj,
        open_ev=open_ev, open_inc=open_inc, notifications=notifications, sla_bad=sla_bad)


# ---------------------- Действия ------------------------------------
@app.route("/add_object", methods=["POST"])
def add_object():
    try:
        with db_connect() as c:
            c.execute("""INSERT INTO objects (name,category,location,responsible,created_at)
                         VALUES (?,?,?,?,?)""",
                      (request.form["name"], request.form["category"],
                       request.form.get("location"), request.form.get("responsible"),
                       datetime.now().strftime("%Y-%m-%d %H:%M")))
        flash(f"✅ Объект «{request.form['name']}» добавлен")
    except sqlite3.OperationalError as e:
        flash(f"⚠️ Ошибка БД: {e}")
    return redirect("/")


@app.route("/add_event/<int:oid>", methods=["POST"])
def add_event(oid):
    # 1) Записываем событие
    with db_connect() as c:
        c.execute("""INSERT INTO events
            (object_id,event_type,severity,description,source_ip,detected_at)
            VALUES (?,?,?,?,?,?)""",
            (oid, request.form["event_type"], request.form["severity"],
             request.form.get("description"), request.form.get("source_ip"),
             datetime.now().strftime("%Y-%m-%d %H:%M")))
        sev = request.form["severity"]
        if sev == "critical":
            c.execute("UPDATE objects SET status='критично' WHERE id=?", (oid,))
        elif sev == "high":
            c.execute("UPDATE objects SET status='внимание' WHERE id=? AND status!='критично'", (oid,))

    # 2) Корреляция (создаст инцидент, если порог набран)
    correlate(oid)

    flash("📌 Событие зафиксировано")
    return redirect("/")


@app.route("/resolve/<int:eid>", methods=["POST"])
def resolve(eid):
    with db_connect() as c:
        c.execute("UPDATE events SET resolved=1, resolved_at=? WHERE id=?",
                  (datetime.now().strftime("%Y-%m-%d %H:%M"), eid))
    flash("✅ Событие закрыто")
    return redirect("/")


@app.route("/resolve_incident/<int:iid>", methods=["POST"])
def resolve_incident(iid):
    with db_connect() as c:
        c.execute("UPDATE incidents SET resolved=1, resolved_at=? WHERE id=?",
                  (datetime.now().strftime("%Y-%m-%d %H:%M"), iid))
        oid = c.execute("SELECT object_id FROM incidents WHERE id=?", (iid,)).fetchone()[0]
        left = c.execute("""SELECT COUNT(*) FROM incidents
                            WHERE object_id=? AND resolved=0 AND severity='critical'""", (oid,)).fetchone()[0]
        if left == 0:
            c.execute("UPDATE objects SET status='норма' WHERE id=?", (oid,))
    flash("✅ Инцидент закрыт")
    return redirect("/")


# ---------------------- Аналитика -----------------------------------
ANALYTICS_PAGE = BASE_STYLE + NAV + """
<h2>📊 Аналитика мониторинга</h2>
<div class="grid">
  <div class="stat">Всего событий<b>{{ total_ev }}</b></div>
  <div class="stat">Всего инцидентов<b>{{ total_inc }}</b></div>
  <div class="stat">Закрыто инцидентов<b>{{ resolved_inc }}</b></div>
  <div class="stat">Ср. время реакции (мин)<b>{{ avg_mttr }}</b></div>
</div>

<div class="card">
  <h3>События по критичности</h3>
  <table><tr><th>Уровень</th><th>Кол-во</th></tr>
  {% for row in by_sev %}<tr><td><span class="badge {{ row[0] }}">{{ row[0] }}</span></td><td>{{ row[1] }}</td></tr>{% endfor %}
  </table>
</div>

<div class="card">
  <h3>Топ-5 объектов по риску</h3>
  <table><tr><th>Объект</th><th>Категория</th><th>Риск</th><th>Статус</th></tr>
  {% for o in top_risk %}<tr><td>{{ o.name }}</td><td>{{ o.category }}</td>
     <td><b>{{ o.risk }}</b></td>
     <td><span class="badge {{ o.status }}">{{ o.status }}</span></td></tr>{% endfor %}
  </table>
</div>

<div class="card">
  <h3>События по типам</h3>
  <table><tr><th>Тип</th><th>Кол-во</th></tr>
  {% for row in by_type %}<tr><td>{{ row[0] }}</td><td>{{ row[1] }}</td></tr>{% endfor %}
  </table>
</div>

<div class="card">
  <h3>Динамика за 7 дней</h3>
  <table><tr><th>День</th><th>Событий</th></tr>
  {% for d, n in trend %}<tr><td>{{ d }}</td><td>{{ '█' * n }} {{ n }}</td></tr>{% endfor %}
  </table>
</div>
"""


@app.route("/analytics")
def analytics():
    with db_connect() as c:
        c.row_factory = sqlite3.Row
        total_ev     = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_inc    = c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        resolved_inc = c.execute("SELECT COUNT(*) FROM incidents WHERE resolved=1").fetchone()[0]
        by_sev  = list(c.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity"))
        by_type = list(c.execute("SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY 2 DESC"))

        top = [dict(r) for r in c.execute("SELECT * FROM objects")]
        for o in top:
            o["risk"] = risk_score(o["id"])
        top_risk = sorted(top, key=lambda x: x["risk"], reverse=True)[:5]

        trend = []
        for i in range(6, -1, -1):
            day = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            n = c.execute("SELECT COUNT(*) FROM events WHERE detected_at LIKE ?", (day+"%",)).fetchone()[0]
            trend.append((day, n))

        rows = c.execute("""SELECT created_at, resolved_at FROM incidents
                            WHERE resolved=1 AND resolved_at IS NOT NULL""").fetchall()
        deltas = []
        for a, b in rows:
            try:
                deltas.append((datetime.strptime(b,"%Y-%m-%d %H:%M") -
                               datetime.strptime(a,"%Y-%m-%d %H:%M")).total_seconds()/60)
            except Exception:
                pass
        avg_mttr = round(sum(deltas)/len(deltas), 1) if deltas else 0

    return render_template_string(ANALYTICS_PAGE, total_ev=total_ev, total_inc=total_inc,
        resolved_inc=resolved_inc, avg_mttr=avg_mttr, by_sev=by_sev, by_type=by_type,
        top_risk=top_risk, trend=trend)


# ---------------------- Список инцидентов ---------------------------
INC_PAGE = BASE_STYLE + NAV + """
<h2>🚨 Все инциденты</h2>
<div class="card"><table>
<tr><th>ID</th><th>Объект</th><th>Правило</th><th>Ур.</th><th>Создан</th>
    <th>SLA до</th><th>Состояние</th><th>Закрыт</th></tr>
{% for i in items %}
<tr>
  <td>{{ i.id }}</td><td>{{ i.obj_name }}</td><td>{{ i.rule_name }}</td>
  <td><span class="badge {{ i.severity }}">{{ i.severity }}</span></td>
  <td>{{ i.created_at }}</td><td>{{ i.sla_deadline }}</td>
  <td><span class="badge {{ i.sla_class }}">{{ i.sla_text }}</span></td>
  <td>{{ '✅ '+i.resolved_at if i.resolved else '—' }}</td>
</tr>
{% endfor %}
</table></div>
"""


@app.route("/incidents")
def incidents():
    with db_connect() as c:
        c.row_factory = sqlite3.Row
        items = [dict(r) for r in c.execute("""
            SELECT i.*, o.name AS obj_name FROM incidents i
            JOIN objects o ON o.id=i.object_id ORDER BY i.created_at DESC""")]
        for i in items:
            i["sla_text"], i["sla_class"] = sla_status(i["sla_deadline"])
    return render_template_string(INC_PAGE, items=items)


# ---------------------- Экспорт CSV ---------------------------------
@app.route("/export/events.csv")
def export_events():
    with db_connect() as c:
        rows = c.execute("""SELECT e.id, o.name, e.event_type, e.severity,
                                   e.source_ip, e.description, e.detected_at, e.resolved
                            FROM events e JOIN objects o ON o.id=e.object_id
                            ORDER BY e.detected_at DESC""").fetchall()
    out = io.StringIO()
    w = csv.writer(out, delimiter=';')
    w.writerow(["ID","Объект","Тип","Критичность","IP","Описание","Время","Закрыто"])
    w.writerows(rows)
    return Response(out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition":"attachment;filename=events.csv"})


# ---------------------- REST API ------------------------------------
@app.route("/api/events", methods=["POST"])
def api_add_event():
    data = request.get_json(force=True)
    required = ["object_id","event_type","severity"]
    if not all(k in data for k in required):
        return jsonify({"error":"missing fields","required":required}), 400
    with db_connect() as c:
        c.execute("""INSERT INTO events
            (object_id,event_type,severity,description,source_ip,detected_at)
            VALUES (?,?,?,?,?,?)""",
            (data["object_id"], data["event_type"], data["severity"],
             data.get("description",""), data.get("source_ip"),
             datetime.now().strftime("%Y-%m-%d %H:%M")))
    correlate(data["object_id"])
    return jsonify({"status":"ok"}), 201


@app.route("/api/objects")
def api_objects():
    with db_connect() as c:
        c.row_factory = sqlite3.Row
        objs = [dict(r) for r in c.execute("SELECT * FROM objects")]
        for o in objs:
            o["risk"] = risk_score(o["id"])
    return jsonify(objs)


@app.route("/api/incidents/critical")
def api_critical():
    with db_connect() as c:
        c.row_factory = sqlite3.Row
        rows = [dict(r) for r in c.execute("""SELECT i.*, o.name AS obj
            FROM incidents i JOIN objects o ON o.id=i.object_id
            WHERE i.resolved=0 AND i.severity IN ('high','critical')
            ORDER BY i.created_at DESC""")]
    return jsonify(rows)


@app.route("/api/health")
def health():
    return jsonify({"status":"ok","time":datetime.now().isoformat()})


# ---------------------- Запуск --------------------------------------
if __name__ == "__main__":
    init_db()
    seed_orenburg()

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5050

    def is_free(p):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(("127.0.0.1", p)) != 0

    while not is_free(port) and port < 5100:
        print(f"Порт {port} занят, пробую {port+1}...")
        port += 1

    print(f"🚀 Сервер запущен: http://localhost:{port}")
    # use_reloader=False — важно! Один процесс = нет блокировки БД
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=port)
