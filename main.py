from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from random import randint
app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(1000))
    name = db.Column(db.String(100))


# Line below only required once, when creating DB.
db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Create a user and get the values from the HTML form
        user = User()
        user.name = request.form['name']
        user.email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))


        # Check if the email is already registered
        if User.query.filter_by(email=user.email).first():
            flash(f"User {user.email} already exists!", 'info')
            flash("Log in instead.")
            return render_template("login.html")

        # Salting and Hashing Passwords
        salt_length = randint(16, 32)
        user.password = generate_password_hash(
            password,
            method='pbkdf2:sha3_512:100000',
            salt_length=salt_length
        )

        # Save the user in the database
        db.session.add(user)
        db.session.commit()

        # Log in and authenticate the user after adding details to database.
        login_user(user)
        flash('Logged in successfully.', 'info')
        return redirect(url_for('secrets', username=user.name))
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        # Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    return send_from_directory(directory=app.static_folder, filename='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
