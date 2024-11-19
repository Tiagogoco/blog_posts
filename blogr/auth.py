from flask import Blueprint, render_template, request, url_for, redirect, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from blogr import db
import functools

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validación de datos
        error = None
        if not username:
            error = 'Nombre de usuario es requerido.'
        elif not email:
            error = 'Correo es requerido.'
        elif not password:
            error = 'Contraseña es requerida.'

        # Comprobar si el correo ya existe en la base de datos
        user_email = User.query.filter_by(email=email).first()

        if user_email is not None:
            error = 'Este correo ya está registrado.'

        # Si no hay errores, crea el nuevo usuario
        if error is None:
            user = User(username=username, email=email, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        error = None
        user = User.query.filter_by(email = email).first()
        
        if user == None or not check_password_hash(user.password, password):
            error = 'Correo o contraseña incorrecta'
        
        if error is None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('post.posts')) 
        flash(error)
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get_or_404(user_id)

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home.index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

@bp.route('/profile')
def profile():
    return render_template('auth/profile.html')



