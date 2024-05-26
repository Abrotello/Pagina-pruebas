from flask import Flask, render_template, request, redirect, url_for, flash
import mysql.connector
from config import db_config
import hashlib
import re

app = Flask(__name__)
app.secret_key = 'prueba'

# Index
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = encriptar(request.form['pass'])
        try:
            con = mysql.connector.connect(**db_config)
            cursor = con.cursor()
            query = "SELECT * FROM usuarios WHERE usuario = %s AND passwrd = %s"
            cursor.execute(query, (usuario, password))
            user = cursor.fetchone()
            if user:
                flash('Inicio de sesion exitoso')
                return redirect(url_for('index'))
            else:
                flash('Usuario incorrecto')
        except mysql.connector.Error as err:
            flash(f'Error al iniciar sesion: {err}')
        finally:
            if 'con' in locals() and con.is_connected():
                con.close()
    return render_template('index.html')

# Registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        usuario = request.form['usuario']
        patron = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'
        if not re.search(patron, request.form['pass']):
            flash(f'La contraseña debe tener:\n Al menos 1 mayúscula\nAl menos 1 minuscula\nAl menos 1 digito\n Al menos 1 caracter[!@#$%^&*]')
        if not re.search(request.form['pass'], request.form['conf_pass']):
            flash('Las contraseñas con coinciden')
        else:
            password = encriptar(request.form['pass'])
            try:
                con = mysql.connector.connect(**db_config)
                cursor = con.cursor()
                qeury = "INSERT INTO usuarios(usuario, passwrd) VALUES (%s, %s)"
                cursor.execute(qeury, (usuario, password))
                con.commit()
                flash('Usuario registrado')
                return redirect(url_for('index'))
            except mysql.connector.Error as err:
                flash(f'Error al registrar usuario: {err}')
            finally:
                if 'con' in locals() and con.is_connected():
                    con.close()
    return render_template('registro.html')

def encriptar(password: str):
    contrasena_bytes = password.encode('utf-8')
    hash_obj = hashlib.sha256()
    hash_obj.update(contrasena_bytes)
    contrasena_encriptada = hash_obj.hexdigest()
    print(contrasena_encriptada)
    return contrasena_encriptada

if __name__ == "__main__":
    app.run(debug=True)