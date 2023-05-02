from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from sweater import db, login_manager
from datetime import *
    
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    user_name = db.Column(db.String(50), nullable = False, unique=True)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    question_answer = db.Column(db.String(50), nullable=False)
    question = db.Column(db.String(50), nullable=False)
    profile_image = db.Column(db.LargeBinary(length = (2 ** 32) - 1), nullable=False)
    profile_image_text = db.Column(db.Text, nullable=False)
    mimetype = db.Column(db.Text, nullable=False)
    register_time = db.Column(db.DateTime, default=datetime.now())
    info = db.Column(db.Text, nullable=True)

class mehsullar(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    ad = db.Column(db.String(50), nullable=False)
    kateqoriya = db.Column(db.String(50), nullable=False)
    info = db.Column(db.Text, nullable=False)
    qiymet = db.Column(db.Integer, nullable=False)
    seller = db.Column(db.String(50), nullable=False)
    preview = db.Column(db.LargeBinary(length = (2 ** 32) - 1), nullable=False)
    preview_text = db.Column(db.Text, nullable=False)
    mimetype = db.Column(db.Text, nullable=False)

class comment(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    author = db.Column(db.String(50), nullable=False)
    text = db.Column(db.Text, nullable=False)
    mehsul_id = db.Column(db.String(50), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))