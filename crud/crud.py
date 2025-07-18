from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
import os, logging, ssl, socket
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet
import certifi
import asyncio
from aiomqtt import Client, MqttError
from dotenv import load_dotenv
import pymysql
import threading
from datetime import datetime, timedelta

# Cargar variables de entorno desde .env
load_dotenv()

app = Flask(__name__)
app.config['APPLICATION_ROOT'] = '/voltlogger'
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

ssl_context = ssl.create_default_context(cafile=certifi.where())
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED


@app.before_request
def before_request():
    if request.script_root != app.config['APPLICATION_ROOT']:
        request.environ['SCRIPT_NAME'] = app.config['APPLICATION_ROOT']


app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config["MYSQL_USER"]     = os.environ["MYSQL_USER"]
app.config["MYSQL_PASSWORD"] = os.environ["MYSQL_PASSWORD"]
app.config["MYSQL_DB"]       = os.environ["MYSQL_DB"]
app.config["MYSQL_HOST"]     = os.environ["MYSQL_HOST"]
app.config["PERMANENT_SESSION_LIFETIME"] = 600

logging.basicConfig(format='%(asctime)s - CRUD - %(levelname)s - %(message)s', level=logging.INFO)

mysql = MySQL(app)

# Verificar conexión a la base de datos
try:
    with app.app_context():
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1")
        cur.close()
        logging.info(f"Conexión a la base de datos establecida correctamente en {app.config['MYSQL_HOST']}")
except Exception as e:
    logging.error(f"Error al conectar con la base de datos: {str(e)}")
    raise


FERNET_KEY = os.getenv("FERNET_KEY")
fernet = Fernet(FERNET_KEY.encode())

def get_broker_cfg_for_device(device_id):
    """
    Retorna un dict con:
      dominio, puerto, usuario, password (desencriptado)
    o None si no está configurado.
    """
    conn = pymysql.connect(
        host=app.config["MYSQL_HOST"],
        user=app.config["MYSQL_USER"],
        password=app.config["MYSQL_PASSWORD"],
        db=app.config["MYSQL_DB"],
        cursorclass=pymysql.cursors.DictCursor
    )
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT b.dominio, b.puerto_tls AS puerto,
                       b.usuario_broker AS usuario, b.pass_encrypted
                  FROM nodos n
                  JOIN brokers b ON n.broker_id = b.id
                 WHERE n.id_dispositivo = %s
            """, (device_id,))
            row = cur.fetchone()
            if not row:
                return None
            try:
                pwd = fernet.decrypt(row["pass_encrypted"].encode()).decode()
            except:
                return None
            return {
                "dominio": row["dominio"],
                "puerto":   row["puerto"],
                "usuario":  row["usuario"],
                "password": pwd
            }


def encrypt_password(raw_password: str) -> str:
    token = fernet.encrypt(raw_password.encode())
    return token.decode()

def decrypt_password(encrypted_password: str) -> str:
    plain = fernet.decrypt(encrypted_password.encode())
    return plain.decode()

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/registrar", methods=["GET", "POST"])
def registrar():
    if request.method == "POST":
        try:
            usuario = request.form.get("usuario")
            password = request.form.get("password")


            cur = mysql.connection.cursor()
            cur.execute("SELECT 1 FROM usuarios WHERE usuario = %s", (usuario,))
            if cur.fetchone():
                flash("El usuario ya existe", "danger")
                cur.close()
                return redirect(url_for('registrar'))

            passhash = generate_password_hash(password, method='scrypt', salt_length=16)
            cur.execute("INSERT INTO usuarios (usuario, hash) VALUES (%s, %s)", (usuario, passhash[17:]))
            mysql.connection.commit()
            cur.close()

            flash("¡Usuario creado con éxito! Por favor inicie sesión", "success")
            logging.info("Se agregó un usuario")
            return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Error en el registro: {str(e)}")
            flash('Error al registrar el usuario. Por favor, intente nuevamente.', "danger")
            return redirect(url_for('registrar'))

    return render_template('registrar.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            usuario = request.form.get("usuario")
            password = request.form.get("password")

            logging.info(f"Intento de login para usuario: {usuario}")

            cur = mysql.connection.cursor()
            cur.execute("SELECT id, hash, tema FROM usuarios WHERE usuario = %s", (usuario,))
            fila = cur.fetchone()
            if fila and check_password_hash('scrypt:32768:8:1$' + fila[1], password):
                session.permanent = True
                session["user_id"]  = fila[0]
                session["username"] = usuario
                session["tema"]     = fila[2]
                logging.info(f"Usuario autenticado exitosamente: {usuario}")
                cur.close()

                # Seleccionar automáticamente el primer dispositivo y lanzar worker
                cur2 = mysql.connection.cursor()
                cur2.execute("""
                    SELECT n.id_dispositivo FROM nodos AS n WHERE n.usuario_id = %s ORDER BY n.id ASC LIMIT 1
                """, (session["user_id"],))
                primer_nodo = cur2.fetchone()
                if primer_nodo:
                    session["id_dispositivo"] = primer_nodo[0]
                    broker_cfg = get_broker_cfg_for_device(primer_nodo[0])
                    if broker_cfg:
                        start_device_worker(primer_nodo[0], broker_cfg)
                cur2.close()

                return redirect(url_for('index'))
            else:
                flash('Usuario o contraseña incorrecto', "danger")
                logging.warning(f"Intento de login fallido para usuario: {usuario}")
                cur.close()
                return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Error en el login: {str(e)}")
            flash('Error al iniciar sesión. Por favor, intente nuevamente.', "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/')
@require_login
def index():
    try:
        user_id = session["user_id"]
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT n.id, n.nombre, n.id_dispositivo, b.dominio
            FROM nodos AS n
            JOIN brokers AS b ON n.broker_id = b.id
            WHERE n.usuario_id = %s
        """, (user_id,))
        nodos = cur.fetchall()

        cur.execute("SELECT tema FROM usuarios WHERE id = %s", (user_id,))
        tema_result = cur.fetchone()
        tema_preferido = tema_result[0] if tema_result else 0

        dispositivo_seleccionado = session.get("id_dispositivo")
        # Seleccionar automáticamente el primer dispositivo si no hay ninguno seleccionado
        if not dispositivo_seleccionado and nodos:
            session["id_dispositivo"] = nodos[0][2]  # id_dispositivo del primer nodo
            dispositivo_seleccionado = nodos[0][2]

        cur.close()
        return render_template(
            'bienvenida.html',
            username=session.get("username"),
            nodos=nodos,
            tema_preferido=tema_preferido,
            dispositivo_seleccionado=dispositivo_seleccionado
        )
    except Exception as e:
        logging.error(f"Error al obtener nodos: {str(e)}")
        flash("Error al cargar la lista de nodos", "danger")
        return redirect(url_for('index'))


# =====================
# WORKERS PARA MQTT → INFLUXDB
# =====================

# Diccionario global para workers activos por dispositivo
active_workers = {}

def test_influxdb_connection():
    """
    Prueba la conexión a InfluxDB y muestra la configuración actual
    """
    try:
        import influxdb_client
        
        # Configuración de InfluxDB
        INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
        INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "token")
        INFLUX_ORG = os.getenv("INFLUX_ORG", "org")
        INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "voltlogger")
        
        logging.info(f"Configuración InfluxDB:")
        logging.info(f"  URL: {INFLUX_URL}")
        logging.info(f"  Token: {'***' if INFLUX_TOKEN != 'token' else 'DEFAULT'}")
        logging.info(f"  Org: {INFLUX_ORG}")
        logging.info(f"  Bucket: {INFLUX_BUCKET}")
        
        # Probar conexión
        client = influxdb_client.InfluxDBClient(
            url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG
        )
        
        # Verificar que el bucket existe
        buckets_api = client.buckets_api()
        buckets = buckets_api.find_buckets()
        bucket_names = [bucket.name for bucket in buckets.buckets]
        
        if INFLUX_BUCKET in bucket_names:
            logging.info(f"✅ Bucket '{INFLUX_BUCKET}' encontrado en InfluxDB")
        else:
            logging.warning(f"⚠️  Bucket '{INFLUX_BUCKET}' NO encontrado. Buckets disponibles: {bucket_names}")
        
        client.close()
        return True
        
    except Exception as e:
        logging.error(f"❌ Error conectando a InfluxDB: {e}")
        return False

def start_device_worker(device_id, broker_cfg):
    """
    Inicia un worker (hilo) para un dispositivo si no existe ya.
    El worker se suscribe a los tópicos voltlogger/<device_id>/tension y voltlogger/<device_id>/frecuencia
    y guarda los datos recibidos en InfluxDB.
    """
    if device_id in active_workers:
        logging.info(f"Ya existe un worker activo para {device_id}")
        return

    def worker():
        import time
        import influxdb_client
        from influxdb_client.client.write_api import SYNCHRONOUS
        from aiomqtt import Client
        import asyncio

        # Configuración de InfluxDB (ajusta según tu entorno)
        INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
        INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "token")
        INFLUX_ORG = os.getenv("INFLUX_ORG", "org")
        INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "voltlogger")

        write_api = None
        client_influx = None
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            client_influx = influxdb_client.InfluxDBClient(
                url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG
            )
            write_api = client_influx.write_api(write_options=SYNCHRONOUS)
            logging.info(f"✅ Conectado a InfluxDB: {INFLUX_URL}")
        except Exception as e:
            logging.error(f"❌ Error conectando a InfluxDB: {e}")
            return

        async def mqtt_worker():
            try:
                async with Client(
                    broker_cfg["dominio"],
                    port=broker_cfg["puerto"],
                    username=broker_cfg["usuario"],
                    password=broker_cfg["password"],
                    tls_context=ssl_context,
                ) as mqtt:
                    topics = [f"voltlogger/{device_id}/tension", f"voltlogger/{device_id}/frecuencia"]
                    for t in topics:
                        await mqtt.subscribe(t)
                    logging.info(f"Suscrito a tópicos MQTT para {device_id}: {topics}")
                    async for message in mqtt.messages:
                        topic = str(message.topic)
                        payload = message.payload.decode()
                        if topic.endswith("/tension"):
                            try:
                                valor = float(payload)
                            except ValueError:
                                logging.warning(f"Payload inválido para tensión: '{payload}' en {topic}")
                                continue
                            punto = influxdb_client.Point("tension").tag("device", device_id).field("valor", valor)
                        elif topic.endswith("/frecuencia"):
                            try:
                                valor = float(payload)
                            except ValueError:
                                logging.warning(f"Payload inválido para frecuencia: '{payload}' en {topic}")
                                continue
                            punto = influxdb_client.Point("frecuencia").tag("device", device_id).field("valor", valor)
                        else:
                            continue
                        try:
                            write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=punto)
                            logging.info(f"✅ Dato guardado en InfluxDB: {topic}={payload}")
                        except Exception as e:
                            logging.error(f"❌ Error escribiendo en InfluxDB: {e}")
                            logging.error(f"  Bucket: {INFLUX_BUCKET}, Org: {INFLUX_ORG}")
            except Exception as e:
                logging.error(f"Error en worker MQTT para {device_id}: {e}")
            finally:
                if client_influx:
                    client_influx.close()

        try:
            loop.run_until_complete(mqtt_worker())
        except Exception as e:
            logging.error(f"Worker MQTT finalizó con error: {e}")
        finally:
            if client_influx:
                client_influx.close()
            active_workers.pop(device_id, None)
            logging.info(f"Worker para {device_id} finalizado y removido de activos")

    hilo = threading.Thread(target=worker, daemon=True)
    active_workers[device_id] = hilo
    hilo.start()
    logging.info(f"Worker iniciado para {device_id}")


@app.route('/seleccionar_dispositivo', methods=['POST'])
@require_login
def seleccionar_dispositivo():
    try:
        id_dispositivo = request.form.get('id_dispositivo')
        if id_dispositivo:
            session['id_dispositivo'] = id_dispositivo
            # Iniciar worker para el dispositivo seleccionado
            broker_cfg = get_broker_cfg_for_device(id_dispositivo)
            if broker_cfg:
                start_device_worker(id_dispositivo, broker_cfg)
            else:
                logging.warning(f"No se pudo obtener configuración de broker para {id_dispositivo}")
            flash("Dispositivo seleccionado correctamente", "success")
        else:
            session.pop('id_dispositivo', None)
            flash("Por favor, seleccione un dispositivo para ver sus opciones de control.", "danger")
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Error al seleccionar dispositivo: {str(e)}")
        flash("Error al seleccionar el dispositivo", "danger")
        return redirect(url_for('index'))


@app.route('/agregar_nodo', methods=['GET', 'POST'])
@require_login
def agregar_nodo():
    user_id = session["user_id"]
    if request.method == 'POST':
        try:
            nombre         = request.form.get('nombre')
            id_dispositivo = request.form.get('id_dispositivo')
            broker_id      = request.form.get('broker_id')

            if not nombre or not id_dispositivo or not broker_id:
                flash("Todos los campos son obligatorios", "danger")
                return redirect(url_for('agregar_nodo'))

            cur = mysql.connection.cursor()
            cur.execute(
                "SELECT 1 FROM brokers WHERE id = %s AND usuario_id = %s",
                (broker_id, user_id)
            )
            if not cur.fetchone():
                flash("Broker no válido", "danger")
                cur.close()
                return redirect(url_for('agregar_nodo'))

            cur.execute(
                "INSERT INTO nodos (nombre, id_dispositivo, broker_id, usuario_id) VALUES (%s, %s, %s, %s)",
                (nombre, id_dispositivo, broker_id, user_id)
            )
            mysql.connection.commit()
            cur.close()

            flash("¡Nodo agregado correctamente!", "success")
            return redirect(url_for('index'))

        except Exception as e:
            logging.error(f"Error al agregar nodo: {str(e)}")
            flash('Error al agregar el nodo. Por favor, intente nuevamente.', "danger")
            return redirect(url_for('agregar_nodo'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, dominio FROM brokers WHERE usuario_id = %s", (user_id,))
    brokers = cur.fetchall()
    cur.execute("SELECT tema FROM usuarios WHERE id = %s", (user_id,))
    tema_result = cur.fetchone()
    tema_preferido = tema_result[0] if tema_result else 0
    cur.close()

    return render_template('agregar_nodo.html', 
                           brokers=brokers,
                           tema_preferido=tema_preferido)


@app.route('/actualizar_tema', methods=['POST'])
@require_login
def actualizar_tema():
    try:
        tema = request.form.get('tema')
        if tema is not None:
            tema_valor = 1 if tema == 'dark' else 0
            cur = mysql.connection.cursor()
            cur.execute(
                "UPDATE usuarios SET tema = %s WHERE id = %s",
                (tema_valor, session["user_id"])
            )
            mysql.connection.commit()
            cur.close()
            return jsonify({"success": True}), 200
        return jsonify({"error": "No se proporcionó tema"}), 400
    except Exception as e:
        logging.error(f"Error al actualizar tema: {str(e)}")
        return jsonify({"error": "Error al actualizar tema"}), 500


@app.route('/brokers')
@require_login
def listar_brokers():
    try:
        user_id = session["user_id"]
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT id, dominio, usuario_broker, pass_encrypted, puerto_tls "
            "FROM brokers WHERE usuario_id = %s",
            (user_id,)
        )
        filas = cur.fetchall()
        cur.close()

        brokers = []
        for fila in filas:
            id_b, dominio, usuario_b, pass_enc, puerto = fila
            try:
                pass_plain = decrypt_password(pass_enc)
            except Exception:
                pass_plain = ""
            brokers.append({
                "id":         id_b,
                "dominio":    dominio,
                "usuario":    usuario_b,
                "password":   pass_plain,
                "puerto_tls": puerto
            })

        return render_template('brokers.html',
                               username=session.get("username"),
                               brokers=brokers)
    except Exception as e:
        logging.error(f"Error al listar brokers: {str(e)}")
        flash("Error al cargar los brokers", "danger")
        return redirect(url_for('index'))


@app.route('/agregar_broker', methods=['GET', 'POST'])
@require_login
def agregar_broker():
    if request.method == "POST":
        dominio    = request.form.get("dominio")
        usuario_b  = request.form.get("usuario_broker")
        password_b = request.form.get("password_broker")
        puerto     = request.form.get("puerto_tls")

        try:
            puerto = int(puerto)
        except ValueError:
            flash("El puerto TLS debe ser un número", "danger")
            return redirect(url_for('agregar_broker'))

        pass_cifrada = encrypt_password(password_b)
        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO brokers (dominio, usuario_broker, pass_encrypted, puerto_tls, usuario_id) "
                "VALUES (%s, %s, %s, %s, %s)",
                (dominio, usuario_b, pass_cifrada, puerto, session["user_id"])
            )
            mysql.connection.commit()
            cur.close()
            flash("Broker agregado correctamente", "success")
            return redirect(url_for('listar_brokers'))
        except Exception as e:
            logging.error(f"Error al agregar broker: {str(e)}")
            flash("Error al agregar el broker. Intente nuevamente.", "danger")
            return redirect(url_for('agregar_broker'))

    return render_template('agregar_broker.html',
                           tema_preferido=session.get("tema"),
                           username=session.get("username"))


@app.route('/editar_broker/<int:id_broker>', methods=['GET', 'POST'])
@require_login
def editar_broker(id_broker):
    user_id = session["user_id"]
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT dominio, usuario_broker, pass_encrypted, puerto_tls "
        "FROM brokers WHERE id = %s AND usuario_id = %s",
        (id_broker, user_id)
    )
    fila = cur.fetchone()
    if not fila:
        cur.close()
        flash("Broker no encontrado o no autorizado", "danger")
        return redirect(url_for('listar_brokers'))

    if request.method == "POST":
        dominio_n   = request.form.get("dominio")
        usuario_n   = request.form.get("usuario_broker")
        password_n  = request.form.get("password_broker")
        puerto_n    = request.form.get("puerto_tls")

        try:
            puerto_n = int(puerto_n)
        except ValueError:
            flash("El puerto TLS debe ser un número", "danger")
            cur.close()
            return redirect(url_for('editar_broker', id_broker=id_broker))

        pass_cifrada = encrypt_password(password_n)
        try:
            cur.execute(
                "UPDATE brokers SET dominio = %s, usuario_broker = %s, pass_encrypted = %s, puerto_tls = %s "
                "WHERE id = %s AND usuario_id = %s",
                (dominio_n, usuario_n, pass_cifrada, puerto_n, id_broker, user_id)
            )
            mysql.connection.commit()
            cur.close()
            flash("Broker actualizado correctamente", "success")
            return redirect(url_for('listar_brokers'))
        except Exception as e:
            logging.error(f"Error al editar broker: {str(e)}")
            flash("Error al actualizar el broker. Intente nuevamente.", "danger")
            cur.close()
            return redirect(url_for('editar_broker', id_broker=id_broker))

    dominio, usuario_b, pass_enc, puerto = fila
    try:
        pass_plain = decrypt_password(pass_enc)
    except Exception:
        pass_plain = ""
    cur.close()
    return render_template('editar_broker.html',
                           id_broker=id_broker,
                           dominio=dominio,
                           usuario_broker=usuario_b,
                           password_broker=pass_plain,
                           puerto_tls=puerto,
                           tema_preferido=session.get("tema"),
                           username=session.get("username"))

@app.route('/eliminar_broker/<int:id_broker>', methods=['POST'])
@require_login
def eliminar_broker(id_broker):
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "DELETE FROM brokers WHERE id = %s AND usuario_id = %s",
            (id_broker, session["user_id"])
        )
        mysql.connection.commit()
        cur.close()
        flash("Broker eliminado correctamente", "success")
    except Exception as e:
        logging.error(f"Error al eliminar broker: {str(e)}")
        flash("Error al eliminar el broker", "danger")
    return redirect(url_for('listar_brokers'))


# ============================================================================
# RUTAS PARA DASHBOARDS
# ============================================================================

@app.route('/dashboards')
@require_login
def dashboards():
    """Página principal de dashboards"""
    try:
        # Dos dashboards fijos: tensión y frecuencia
        dashboards_fijos = [
            {
                "id": 1,
                "nombre": "Monitoreo de Tensión",
                "descripcion": "Gráfico de tensión a través del tiempo",
                "tipo": "tension",
                "icono": "fas fa-bolt",
                "color": "warning"
            },
            {
                "id": 2,
                "nombre": "Monitoreo de Frecuencia",
                "descripcion": "Gráfico de frecuencia a través del tiempo",
                "tipo": "frecuencia",
                "icono": "fas fa-wave-square",
                "color": "info"
            }
        ]
        dispositivo_seleccionado = session.get("id_dispositivo")
        return render_template('dashboards/index.html',
                               username=session.get("username"),
                               dashboards=dashboards_fijos,
                               tema_preferido=session.get("tema"),
                               dispositivo_seleccionado=dispositivo_seleccionado)
    except Exception as e:
        logging.error(f"Error al cargar dashboards: {str(e)}")
        flash("Error al cargar los dashboards", "danger")
        return redirect(url_for('index'))


@app.route('/dashboards/tension')
@require_login
def dashboard_tension():
    """Dashboard de tensión"""
    try:
        return render_template('dashboards/tension.html',
                               username=session.get("username"),
                               tema_preferido=session.get("tema"))
    except Exception as e:
        logging.error(f"Error al cargar dashboard de tensión: {str(e)}")
        flash("Error al cargar el dashboard de tensión", "danger")
        return redirect(url_for('dashboards'))


@app.route('/dashboards/frecuencia')
@require_login
def dashboard_frecuencia():
    try:
        return render_template('dashboards/frecuencia.html',
                               username=session.get("username"),
                               tema_preferido=session.get("tema"))
    except Exception as e:
        logging.error(f"Error al cargar dashboard de frecuencia: {str(e)}")
        flash("Error al cargar el dashboard de frecuencia", "danger")
        return redirect(url_for('dashboards'))


@app.route('/api/tension')
@require_login
def api_tension():
    try:
        device_id = session.get('id_dispositivo')
        if not device_id:
            return jsonify({"error": "No hay dispositivo seleccionado"}), 400

        # Leer parámetro de rango (en minutos)
        try:
            rango = int(request.args.get('rango', 30))  # por defecto 30 minutos
        except Exception:
            rango = 30

        # Calcular el rango de tiempo
        ahora = datetime.utcnow()
        desde = ahora - timedelta(minutes=rango)

        # Conectar a InfluxDB y consultar
        import influxdb_client
        INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
        INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "token")
        INFLUX_ORG = os.getenv("INFLUX_ORG", "org")
        INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "voltlogger")

        client = influxdb_client.InfluxDBClient(
            url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG
        )
        query_api = client.query_api()

        query = f'''
        from(bucket: "{INFLUX_BUCKET}")
          |> range(start: {desde.isoformat()}Z, stop: {ahora.isoformat()}Z)
          |> filter(fn: (r) => r._measurement == "tension" and r.device == "{device_id}")
          |> filter(fn: (r) => r._field == "valor")
          |> sort(columns: ["_time"])
        '''

        result = query_api.query(org=INFLUX_ORG, query=query)
        datos = []
        for table in result:
            for record in table.records:
                datos.append({
                    "tiempo": record.get_time().isoformat(),
                    "valor": record.get_value()
                })

        # Calcular estadísticas
        valores = [d["valor"] for d in datos]
        estadisticas = {
            "actual": valores[-1] if valores else None,
            "maximo": max(valores) if valores else None,
            "minimo": min(valores) if valores else None,
            "promedio": sum(valores)/len(valores) if valores else None
        }

        client.close()
        return jsonify({"datos": datos, "estadisticas": estadisticas})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/frecuencia')
@require_login
def api_frecuencia():
    try:
        device_id = session.get('id_dispositivo')
        if not device_id:
            return jsonify({"error": "No hay dispositivo seleccionado"}), 400

        # Leer parámetro de rango (en minutos)
        try:
            rango = int(request.args.get('rango', 30))  # por defecto 30 minutos
        except Exception:
            rango = 30

        # Calcular el rango de tiempo
        ahora = datetime.utcnow()
        desde = ahora - timedelta(minutes=rango)

        # Conectar a InfluxDB y consultar
        import influxdb_client
        INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
        INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "token")
        INFLUX_ORG = os.getenv("INFLUX_ORG", "org")
        INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "voltlogger")

        client = influxdb_client.InfluxDBClient(
            url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG
        )
        query_api = client.query_api()

        query = f'''
        from(bucket: "{INFLUX_BUCKET}")
          |> range(start: {desde.isoformat()}Z, stop: {ahora.isoformat()}Z)
          |> filter(fn: (r) => r._measurement == "frecuencia" and r.device == "{device_id}")
          |> filter(fn: (r) => r._field == "valor")
          |> sort(columns: ["_time"])
        '''

        result = query_api.query(org=INFLUX_ORG, query=query)
        datos = []
        for table in result:
            for record in table.records:
                datos.append({
                    "tiempo": record.get_time().isoformat(),
                    "valor": record.get_value()
                })

        # Calcular estadísticas
        valores = [d["valor"] for d in datos]
        estadisticas = {
            "actual": valores[-1] if valores else None,
            "maximo": max(valores) if valores else None,
            "minimo": min(valores) if valores else None,
            "promedio": sum(valores)/len(valores) if valores else None
        }

        client.close()
        return jsonify({"datos": datos, "estadisticas": estadisticas})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/estado_dispositivo')
@require_login
def api_estado_dispositivo():
    try:
        device_id = session.get('id_dispositivo')
        if not device_id:
            return jsonify({"conectado": False, "error": "No hay dispositivo seleccionado"}), 400
        # Verificar si el worker está activo
        conectado = device_id in active_workers and active_workers[device_id].is_alive()
        # Si no está activo, intentar reconectar
        if not conectado:
            broker_cfg = get_broker_cfg_for_device(device_id)
            if broker_cfg:
                start_device_worker(device_id, broker_cfg)
                # Esperar un poco para que arranque el hilo
                import time
                time.sleep(0.5)
                conectado = device_id in active_workers and active_workers[device_id].is_alive()
        return jsonify({"conectado": conectado})
    except Exception as e:
        return jsonify({"conectado": False, "error": str(e)}), 500
