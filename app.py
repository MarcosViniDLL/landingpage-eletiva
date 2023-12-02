from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask import jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False)  # CPF no formato XXX.XXX.XXX-XX
    birth_date = db.Column(db.Date, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, username, password, cpf, birth_date, is_admin=False):
        self.username = username
        self.password = password
        self.cpf = cpf
        self.birth_date = birth_date
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

authenticated_user = {
    'username':'usuarioteste',
    'password':'senhateste'
}

def is_admin_authenticated():
    return session.get('is_admin')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cpf = request.form['cpf']
        birth_date = datetime.strptime(request.form['birth_date'], '%Y-%m-%d').date()

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Usuário já existe. Tente outro nome de usuário.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, cpf=cpf, birth_date=birth_date)

        db.session.add(new_user)
        db.session.commit()
        flash('Registro realizado com sucesso. Faça login!')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            error = 'Credenciais inválidas. Tente novamente.'
    return render_template('login.html', error=error)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    if 'is_admin' in session:
        session.pop('is_admin')
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if 'is_admin' in session and session['is_admin']:
        if request.method == 'POST':
            if request.form['_method'] == 'DELETE':
                user_id = int(request.form['user_id'])
                user_to_delete = User.query.get_or_404(user_id)
                db.session.delete(user_to_delete)
                db.session.commit()
                return redirect(url_for('admin_panel'))

            elif request.form['_method'] == 'PUT':
                user_id = int(request.form['user_id'])
                user_to_update = User.query.get_or_404(user_id)
                new_username = request.form['new_username']
                user_to_update.username = new_username
                db.session.commit()
                return redirect(url_for('admin_panel'))

        users = User.query.all()
        return render_template('admin.html', users=users)
    else:
        return redirect(url_for('admin_login'))


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_username = request.form['admin_username']
        admin_password = request.form['admin_password']

        if admin_username == 'admin' and admin_password == 'adminpassword':
            session['is_admin'] = True
            return redirect(url_for('admin_panel'))
        else:
            flash('Credenciais de administrador incorretas. Tente novamente.')

            
    return render_template('admin_login.html')


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    users = User.query.all()
    return render_template('dashboard.html', users=users)

@app.route('/add_training', methods=['POST'])
def add_training():
    if request.method == 'POST':
        training_name = request.form['training_name']

        return redirect(url_for('dashboard'))
    
@app.route('/add_diet', methods=['POST'])
def add_diet():
    if request.method == 'POST':
        diet_name = request.form['diet_name']

        return redirect(url_for('dashboard'))
    
@app.route('/add_pshysical_assessment', methods=['POST'])
def add_physical_assessment():
    if request.method == 'POST':
        weight = request.form['weight']
        height = request.form['height']

        return redirect(url_for('dashboard'))

@app.route('/beneficios_mensal')
def beneficios_mensal():
    return render_template('beneficios_mensal.html')

@app.route('/beneficios_familia')
def beneficios_familia():
    return render_template('beneficios_familia.html')

@app.route('/beneficios_anual')
def beneficios_anual():
    return render_template('beneficios_anual.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
