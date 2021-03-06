from wtforms import Form, StringField, DateField, SelectField, TextAreaField,\
    validators, PasswordField, BooleanField, ValidationError
# from django import forms
# from wtforms_components import DateRange
from wtforms.validators import InputRequired, Email
from wtforms.fields.html5 import EmailField
# from datetime import date, datetime


class RegistrationForm(Form):
    first_name = StringField('First Name', [validators.Length(min=2)], render_kw={"placeholder": "John"})
    last_name = StringField('Last Name', [validators.Length(min=2)],render_kw={"placeholder": "Doe"})
    email = EmailField("Email",  validators=[InputRequired("Please enter your email address."), Email("Please enter your email address.")],render_kw={"placeholder": "test@test"})
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Invalid Password. Passwords must match.')
    ], render_kw={"placeholder": "Password"})
    confirm = PasswordField('Repeat Password',render_kw={"placeholder": "Confirm Password"})
    accept_tos = BooleanField('', [validators.DataRequired()] )


class LoginForm(Form):
    email = StringField("Email",render_kw={"placeholder": "test@test.test"})
    password = PasswordField('Password', [validators.DataRequired()], render_kw={"placeholder": "Password"})

class ResetForm(Form):
        email = EmailField("Email",  validators=[InputRequired("Please enter your email address."), Email("Please enter your email address.")],render_kw={"placeholder": "test@test"})


