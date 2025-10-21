from flask import Flask, jsonify, request, make_response, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from datetime import timedelta
import bcrypt
import os
from functools import wraps
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange
from flask_cors import CORS
import logging

# Inicialización de la aplicación Flask
app = Flask(__name__)

# Configurar logging para registrar eventos de la aplicación
logging.basicConfig(filename='app.log', level=logging.INFO)

# Configura CORS para permitir solicitudes desde el frontend
CORS(app, origins=["http://localhost:8000"], methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Content-Type", "X-API-Key"], supports_credentials=True)

# Configuración de la clave secreta para seguridad de Flask y WTF
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'clave_segura_development')
# Deshabilita CSRF para APIs (normalmente manejado por tokens JWT)
app.config['WTF_CSRF_ENABLED'] = False

# Configuración de la base de datos SQLite
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
# Deshabilita el seguimiento de modificaciones de SQLAlchemy para mejor rendimiento
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializa la extensión SQLAlchemy para la base de datos
db = SQLAlchemy(app)
# Configuración de la clave secreta para JWT
app.config['JWT_SECRET_KEY'] = 'super-secret'
# Configuración de expiración para tokens de acceso y refresco JWT
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
# Inicializa la extensión JWTManager
jwt = JWTManager(app)

# --- Modelos de Base de Datos ---

# Modelo de Usuario para la autenticación y autorización
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False) # Contraseña hasheada
    apikey = db.Column(db.String(120), unique=True, nullable=False) # Clave API para autenticación
    role = db.Column(db.String(20), nullable=False, default='user') # Rol del usuario (admin, user)

    def __repr__(self):
        return f'<User {self.username}>'

# Modelo para registrar eventos de auditoría del sistema
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False) # Fecha y hora del evento
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # ID del usuario que realizó la acción
    action = db.Column(db.String(100), nullable=False) # Descripción de la acción realizada
    details = db.Column(db.String(500), nullable=True) # Detalles adicionales del evento
    ip_address = db.Column(db.String(50), nullable=True) # Dirección IP del cliente

    def __repr__(self):
        return f'<AuditLog {self.action} by User {self.user_id}>'

# Nuevo Modelo para Medicamentos en el stock de la farmacia
class Medicamento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.String(500), nullable=True)
    cantidad = db.Column(db.Integer, nullable=False, default=0) # Cantidad en stock
    precio = db.Column(db.Float, nullable=False, default=0.0) # Precio del medicamento
    disponible = db.Column(db.Boolean, default=True) # Indica si el medicamento está disponible

    def __repr__(self):
        return f'<Medicamento {self.nombre}>'

# Crea todas las tablas de la base de datos si no existen
with app.app_context():
    db.create_all()

# --- Funciones de Utilidad ---

# Hashea una contraseña usando bcrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Verifica una contraseña hasheada
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Genera una clave API aleatoria y segura
def generate_apikey():
    import secrets
    return secrets.token_hex(16)

# Registra un evento de auditoría en la base de datos
def log_audit_event(user_id, action, details=None):
    ip_address = request.remote_addr
    log_entry = AuditLog(user_id=user_id, action=action, details=details, ip_address=ip_address)
    db.session.add(log_entry)
    db.session.commit()

# --- Funciones de Seguridad ---

# Agrega encabezados de seguridad HTTP a todas las respuestas
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Redirige automáticamente a HTTPS si la aplicación no está en modo debug
@app.before_request
def enforce_https():
    if not request.is_secure and not app.debug:
        return redirect(request.url.replace('http://', 'https://', 1), code=301)

# Decorador para validar que el Content-Type de la solicitud sea el especificado
def validate_content_type(content_type):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if request.headers.get('Content-Type') != content_type:
                return jsonify({"msg": f"Content-Type debe ser {content_type}"}), 415
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Decorador para requerir una clave API válida en la cabecera X-API-Key
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({"msg": "API Key es requerida"}), 401
        user = User.query.filter_by(apikey=api_key).first()
        if not user:
            return jsonify({"msg": "API Key inválida"}), 401
        # Almacena el objeto de usuario en el contexto de la solicitud para fácil acceso
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function

# Decorador para requerir un rol específico para acceder a la ruta
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Asume que api_key_required ya se ha ejecutado y ha establecido request.current_user
            user = request.current_user # Obtiene el usuario del contexto de la solicitud
            if not user or user.role != role:
                return jsonify({"msg": "Acceso no autorizado"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Formularios WTForms ---

# Formulario para validar datos de Medicamentos
class MedicamentoForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(min=1, max=100)])
    descripcion = StringField('Descripción', validators=[Length(max=500)])
    cantidad = IntegerField('Cantidad', validators=[DataRequired(), NumberRange(min=0)])
    precio = StringField('Precio', validators=[DataRequired()]) # Se valida a float manualmente
    disponible = BooleanField('Disponible')

# Formulario para validar datos de Login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])

# --- Datos Iniciales y Carga en BD ---

# Datos de medicamentos iniciales para cargar en la base de datos
medicamentos_iniciales = [
    {'id': 1, 'nombre': 'Ibuprofeno', 'descripcion': 'Caja de 400mg', 'cantidad': 100, 'precio': 3.50, 'disponible': True},
    {'id': 2, 'nombre': 'Paracetamol', 'descripcion': '500mg genérico', 'cantidad': 250, 'precio': 2.15, 'disponible': True},
]

# Asegura que los medicamentos iniciales se añadan a la base de datos si no existen
with app.app_context():
    for item in medicamentos_iniciales:
        # Verifica si el medicamento ya existe por ID
        if not Medicamento.query.get(item['id']):
            new_medicamento = Medicamento(
                id=item['id'],
                nombre=item['nombre'],
                descripcion=item['descripcion'],
                cantidad=item['cantidad'],
                precio=item['precio'],
                disponible=item['disponible']
            )
            db.session.add(new_medicamento)
    db.session.commit() # Guarda los cambios en la base de datos

# --- Endpoints de la API ---

# Endpoint para registrar un nuevo usuario
@app.route('/register', methods=['POST'])
@validate_content_type('application/json')
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')

    if not username or not password:
        return jsonify({"msg": "Falta usuario o contraseña"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "El usuario ya existe"}), 400

    hashed = hash_password(password)
    apikey = generate_apikey()
    user = User(username=username, password=hashed, apikey=apikey, role=role)
    db.session.add(user)
    db.session.commit()
    log_audit_event(user.id, "user_registered", f"Usuario {username} registrado")
    return jsonify({"msg": "Usuario registrado", "apikey": apikey}), 201

# Endpoint para iniciar sesión y obtener tokens JWT
@app.route('/login', methods=['POST'])
@validate_content_type('application/json')
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(password, user.password):
        return jsonify({"msg": "Credenciales incorrectas"}), 401
    access = create_access_token(identity=username)
    refresh = create_refresh_token(identity=username)
    log_audit_event(user.id, "user_login", f"Usuario {username} inició sesión")
    response = make_response(jsonify(access_token=access, refresh_token=refresh), 200)
    response.set_cookie('access_token', access, httponly=True, secure=True, samesite='Strict')
    response.set_cookie('refresh_token', refresh, httponly=True, secure=True, samesite='Strict')
    return response

# Endpoint para obtener todos los medicamentos en stock
@app.route('/medicamentos', methods=['GET'])
@api_key_required
def get_medicamentos():
    user = request.current_user # Acceso al usuario ya cargado por api_key_required
    medicamentos = Medicamento.query.all()
    output = []
    for medicamento in medicamentos:
        output.append({
            'id': medicamento.id,
            'nombre': medicamento.nombre,
            'descripcion': medicamento.descripcion,
            'cantidad': medicamento.cantidad,
            'precio': medicamento.precio,
            'disponible': medicamento.disponible
        })
    log_audit_event(user.id, "medicamentos_retrieved", "Lista de medicamentos consultada")
    return jsonify({'medicamentos': output}), 200

# Endpoint para añadir un nuevo medicamento al stock
@app.route('/medicamentos', methods=['POST'])
@api_key_required
@role_required('admin') # Solo administradores pueden añadir medicamentos
@validate_content_type('application/json')
def add_medicamento():
    form = MedicamentoForm(data=request.get_json())
    if not form.validate():
        return jsonify({"msg": "Datos inválidos", "errors": form.errors}), 400

    try:
        precio_float = float(form.precio.data)
    except ValueError:
        return jsonify({"msg": "El precio debe ser un número válido"}), 400

    new_medicamento = Medicamento(
        nombre=form.nombre.data,
        descripcion=form.descripcion.data,
        cantidad=form.cantidad.data,
        precio=precio_float,
        disponible=form.disponible.data if form.disponible.data is not None else True # Asegura que siempre tenga un valor
    )
    db.session.add(new_medicamento)
    db.session.commit()
    user = request.current_user
    log_audit_event(user.id, "medicamento_added", f"Medicamento {new_medicamento.nombre} (ID: {new_medicamento.id}) añadido")
    return jsonify({
        'msg': 'Medicamento añadido con éxito',
        'medicamento': {
            'id': new_medicamento.id,
            'nombre': new_medicamento.nombre,
            'descripcion': new_medicamento.descripcion,
            'cantidad': new_medicamento.cantidad,
            'precio': new_medicamento.precio,
            'disponible': new_medicamento.disponible
        }
    }), 201

# Endpoint para obtener un medicamento específico por su ID
@app.route('/medicamentos/<int:medicamento_id>', methods=['GET'])
@api_key_required
def get_medicamento_by_id(medicamento_id):
    user = request.current_user
    medicamento = Medicamento.query.get(medicamento_id)
    if not medicamento:
        return jsonify({"msg": "Medicamento no encontrado"}), 404
    log_audit_event(user.id, "medicamento_retrieved_by_id", f"Medicamento {medicamento_id} consultado")
    return jsonify({
        'id': medicamento.id,
        'nombre': medicamento.nombre,
        'descripcion': medicamento.descripcion,
        'cantidad': medicamento.cantidad,
        'precio': medicamento.precio,
        'disponible': medicamento.disponible
    }), 200

# Endpoint para actualizar un medicamento existente
@app.route('/medicamentos/<int:medicamento_id>', methods=['PUT'])
@api_key_required
@role_required('admin') # Solo administradores pueden actualizar medicamentos
@validate_content_type('application/json')
def update_medicamento(medicamento_id):
    medicamento = Medicamento.query.get(medicamento_id)
    if not medicamento:
        return jsonify({"msg": "Medicamento no encontrado"}), 404

    form = MedicamentoForm(data=request.get_json())
    # Para PUT parciales, no todos los campos son obligatorios.
    # Se validan solo los campos que están presentes en el JSON.
    # WTForms por defecto requiere todos los DataRequired, se puede ajustar
    # o validar manualmente el `request.get_json()`
    data = request.get_json()

    if 'nombre' in data:
        medicamento.nombre = data['nombre']
    if 'descripcion' in data:
        medicamento.descripcion = data['descripcion']
    if 'cantidad' in data:
        if not isinstance(data['cantidad'], int) or data['cantidad'] < 0:
            return jsonify({"msg": "La cantidad debe ser un número entero no negativo"}), 400
        medicamento.cantidad = data['cantidad']
    if 'precio' in data:
        try:
            precio_float = float(data['precio'])
            if precio_float < 0:
                return jsonify({"msg": "El precio no puede ser negativo"}), 400
            medicamento.precio = precio_float
        except ValueError:
            return jsonify({"msg": "El precio debe ser un número válido"}), 400
    if 'disponible' in data:
        if not isinstance(data['disponible'], bool):
            return jsonify({"msg": "El estado 'disponible' debe ser un valor booleano"}), 400
        medicamento.disponible = data['disponible']

    db.session.commit()
    user = request.current_user
    log_audit_event(user.id, "medicamento_updated", f"Medicamento {medicamento_id} actualizado")
    return jsonify({
        'msg': 'Medicamento actualizado con éxito',
        'medicamento': {
            'id': medicamento.id,
            'nombre': medicamento.nombre,
            'descripcion': medicamento.descripcion,
            'cantidad': medicamento.cantidad,
            'precio': medicamento.precio,
            'disponible': medicamento.disponible
        }
    }), 200

# Endpoint para eliminar un medicamento del stock
@app.route('/medicamentos/<int:medicamento_id>', methods=['DELETE'])
@api_key_required
@role_required('admin') # Solo administradores pueden eliminar medicamentos
def delete_medicamento(medicamento_id):
    medicamento = Medicamento.query.get(medicamento_id)
    if not medicamento:
        return jsonify({"msg": "Medicamento no encontrado"}), 404

    db.session.delete(medicamento)
    db.session.commit()
    user = request.current_user
    log_audit_event(user.id, "medicamento_deleted", f"Medicamento {medicamento_id} eliminado")
    return jsonify({"msg": "Medicamento eliminado con éxito"}), 204

# Endpoint para obtener los registros de auditoría
@app.route('/audit-logs', methods=['GET'])
@api_key_required
@role_required('admin') # Solo administradores pueden ver los logs de auditoría
def get_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    # Formatea la salida de logs para JSON
    return jsonify([{ "id": l.id, "timestamp": l.timestamp.isoformat(), "user_id": l.user_id, "action": l.action, "details": l.details, "ip_address": l.ip_address } for l in logs]), 200

# --- Manejo de Errores Personalizados ---

# Manejador para el error 400 Bad Request
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"msg": "Solicitud incorrecta", "error": str(error)}), 400

# Manejador para el error 401 Unauthorized
@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"msg": "No autorizado", "error": str(error)}), 401

# Manejador para el error 403 Forbidden
@app.errorhandler(403)
def forbidden(error):
    return jsonify({"msg": "Acceso prohibido", "error": str(error)}), 403

# Manejador para el error 404 Not Found
@app.errorhandler(404)
def not_found(error):
    return jsonify({"msg": "No encontrado", "error": str(error)}), 404

# Manejador para el error 415 Unsupported Media Type
@app.errorhandler(415)
def unsupported_media_type(error):
    return jsonify({"msg": "Tipo de contenido no soportado", "error": str(error)}), 415

# Manejador para el error 500 Internal Server Error
@app.errorhandler(500)
def internal_error(error):
    logging.exception("Internal Server Error") # Registra la excepción completa
    return jsonify({"msg": "Error interno del servidor", "error": str(error)}), 500

# --- Ejecución de la Aplicación ---

# Punto de entrada principal para ejecutar la aplicación Flask
if __name__ == '__main__':
    # Inicia el servidor en modo debug para desarrollo (recarga automática, más verboso)
    app.run(host='127.0.0.1', port=5001, debug=True)
