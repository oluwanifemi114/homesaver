from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, SelectField, BooleanField, IntegerField, DateField  # Updated import
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mortgage.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'youremail@gmail.com'
app.config['MAIL_PASSWORD'] = 'yourpassword'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    address = db.Column(db.String(200))
    password_hash = db.Column(db.String(200), nullable=False)
    mortgages = db.relationship('Mortgage', backref='owner', lazy=True)
    goals = db.relationship('Goal', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Mortgage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bank = db.Column(db.String(100), nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    loan_amount = db.Column(db.Float, nullable=False)
    monthly_payment = db.Column(db.Float, nullable=False)
    term_years = db.Column(db.Integer, nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    payments_made = db.Column(db.Float, default=0.0)
    remaining_balance = db.Column(db.Float, default=0.0)
    paid_amount = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    goal_amount = db.Column(db.Float, nullable=False)
    saved_amount = db.Column(db.Float, default=0.0)
    weekly_savings = db.Column(db.Float, default=0.0)
    month = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Forms
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class MortgageForm(FlaskForm):
    bank = SelectField('Bank', choices=[('Barclays', 'Barclays'), ('HSBC', 'HSBC'), 
                                        ('Lloyds', 'Lloyds Bank'), ('NatWest', 'NatWest'), 
                                        ('Santander', 'Santander'), ('Halifax', 'Halifax'), 
                                        ('Nationwide', 'Nationwide Building Society'), 
                                        ('Virgin', 'Virgin Money')], validators=[DataRequired()])
    interest_rate = FloatField('Interest Rate (%)', validators=[DataRequired()])
    loan_amount = FloatField('Loan Amount (£)', validators=[DataRequired()])
    monthly_payment = FloatField('Monthly Payment (£)', validators=[DataRequired()])
    term_years = IntegerField('Term (Years)', validators=[DataRequired()])
    due_date = DateField('Due Date (YYYY-MM-DD)', format='%Y-%m-%d', validators=[DataRequired()])
    payments_made = FloatField('Payments Made (£)', default=0.0)
    remaining_balance = FloatField('Remaining Balance (£)', default=0.0)
    submit = SubmitField('Add Mortgage')

class GoalForm(FlaskForm):
    goal_amount = FloatField('Goal Amount (£)', validators=[DataRequired()])
    saved_amount = FloatField('Already Saved (£)', default=0.0)
    weekly_savings = FloatField('Weekly Savings (£)', default=0.0)
    month = SelectField('Month', choices=[('January', 'January'), ('February', 'February'), ('March', 'March'),
                                          ('April', 'April'), ('May', 'May'), ('June', 'June'), 
                                          ('July', 'July'), ('August', 'August'), ('September', 'September'), 
                                          ('October', 'October'), ('November', 'November'), ('December', 'December')],
                        validators=[DataRequired()])
    submit = SubmitField('Set Goal')

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Error: Email already exists. Please use a different email.', 'danger')
            return redirect(url_for('register'))

        user = User(name=form.name.data, address=form.address.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/payment_tracker', methods=['GET'])
@login_required
def payment_tracker():
    mortgages = Mortgage.query.filter_by(user_id=current_user.id).all()
    return render_template('payment_tracker.html', mortgages=mortgages)

@app.route('/dashboard')
@login_required
def dashboard():
    mortgages = Mortgage.query.filter_by(user_id=current_user.id).all()
    goals = Goal.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', mortgages=mortgages, goals=goals)

@app.route('/add_mortgage', methods=['GET', 'POST'])
@login_required
def add_mortgage():
    form = MortgageForm()
    if form.validate_on_submit():
        try:
            print(f"payments_made: {form.payments_made.data}")  # Debug: Check the form data
            print(f"remaining_balance: {form.remaining_balance.data}")
            
            mortgage = Mortgage(
                bank=form.bank.data,
                interest_rate=form.interest_rate.data,
                loan_amount=form.loan_amount.data,
                monthly_payment=form.monthly_payment.data,
                term_years=form.term_years.data,
                due_date=form.due_date.data,
                payments_made=form.payments_made.data or 0.0,  # Handle missing values
                remaining_balance=form.remaining_balance.data or 0.0,  # Handle missing values
                user_id=current_user.id
            )
            db.session.add(mortgage)
            db.session.commit()
            flash('Mortgage added successfully.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    else:
        print(form.errors)  # Log form errors for debugging

    return render_template('add_mortgage.html', form=form)


@app.route('/set_goal', methods=['GET', 'POST'])
@login_required
def set_goal():
    form = GoalForm()
    if form.validate_on_submit():
        goal = Goal(goal_amount=form.goal_amount.data, 
                    saved_amount=form.saved_amount.data,
                    weekly_savings=form.weekly_savings.data,
                    month=form.month.data,
                    user_id=current_user.id)
        db.session.add(goal)
        db.session.commit()
        flash('Goal set successfully.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('set_goal.html', form=form)

# Load user for login manager
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Updated for SQLAlchemy 2.0

if __name__ == '__main__':
    app.run(debug=True)
