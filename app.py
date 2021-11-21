import bcrypt
from flask import Flask,render_template,url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY']='thisisasecertkey'

login_manager  = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key = True)
    username = db.Column(db.String(20),unique = True,nullable= False)
    password = db.Column(db.String(80),unique = True,nullable = False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min = 4,max=20)],render_kw={"placeholder":"username"})
    password = PasswordField(validators=[InputRequired(),Length(min = 4,max=20)],render_kw={"placeholder":"password"})
    submit = SubmitField('Register')
    def validate_user(self,username):
        existingusername = User.query.filter_by(username = username.data).first()
        if existingusername:
            raise ValidationError("the user already exists")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min = 4,max=20)],render_kw={"placeholder":"username"})
    password = PasswordField(validators=[InputRequired(),Length(min = 4,max=20)],render_kw={"placeholder":"password"})
    submit = SubmitField('Login in')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login',methods = ['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        temp = User.query.filter_by(username= form.username.data).first()
        if temp:
            if bcrypt.check_password_hash(temp.password,form.password.data):
                login_user(temp)
                return redirect(url_for('dashboard'))
    return render_template('login.html',form = form)

@app.route('/logout',methods = ['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard',methods = ['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/register',methods = ['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashedpassword = bcrypt.generate_password_hash(form.password.data)
        newuser = User(username = form.username.data,password = hashedpassword)
        db.session.add(newuser)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form = form)

if __name__ == '__main__':
    app.run(debug=True)
