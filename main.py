import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.exceptions import RequestEntityTooLarge
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = '2QR3WTYGYUIJ;OOUYWT5Q32767YIUOUO6756DR6YU'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'videos'
app.config['MAX_CONTENT_LENGTH'] = 100000 * 1024 * 1024  # 100 MB
app.config['ALLOWED_EXTENSIONS'] = {'mp4', 'webm', 'ogg'}

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    videos = db.relationship('Video', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    comments = db.relationship('Comment', backref='video', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='video', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)

with app.app_context():
    db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if current_user is None:  # Если пользователь не найден
                return redirect(url_for('login'))
        except:
            return redirect(url_for('login'))
        return f(current_user, *args, **kwargs)
    return decorated

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    videos = Video.query.all()
    return render_template('index.html', videos=videos)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, app.config['SECRET_KEY'])
            
            response = redirect(url_for('index'))
            response.set_cookie('token', token)
            return response
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    response = redirect(url_for('index'))
    response.delete_cookie('token')
    return response

@app.route('/upload', methods=['GET', 'POST'])
@token_required
def upload(current_user):
    if request.method == 'POST':
        # проверяем наличие файла
        if 'file' not in request.files:
            flash('Файл не выбран.', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('Файл не выбран.', 'danger')
            return redirect(request.url)

        # проверяем расширение
        if not allowed_file(file.filename):
            flash('Можно загружать только видео форматов: mp4, webm, ogg.', 'danger')
            return redirect(request.url)

        # сохраняем файл с уникальным именем
        extension = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{extension}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(save_path)

        # создаём запись в БД
        video = Video(
            title=request.form['title'],
            description=request.form['description'],
            filename=unique_filename,
            user_id=current_user.id
        )
        db.session.add(video)
        db.session.commit()

        flash('Видео успешно загружено!', 'success')
        return redirect(url_for('index'))

    return render_template('upload.html')

@app.route('/video/<int:video_id>')
def video(video_id):
    video = Video.query.get_or_404(video_id)
    comments = Comment.query.filter_by(video_id=video_id).order_by(Comment.timestamp.desc()).all()
    likes = Like.query.filter_by(video_id=video_id).count()
    return render_template('video.html', video=video, comments=comments, likes=likes)

@app.route('/comment/<int:video_id>', methods=['POST'])
@token_required
def comment(current_user, video_id):
    content = request.form['content']
    comment = Comment(content=content, user_id=current_user.id, video_id=video_id)
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('video', video_id=video_id))

@app.route('/like/<int:video_id>', methods=['POST'])
@token_required
def like(current_user, video_id):
    existing_like = Like.query.filter_by(user_id=current_user.id, video_id=video_id).first()
    if existing_like:
        db.session.delete(existing_like)
    else:
        like = Like(user_id=current_user.id, video_id=video_id)
        db.session.add(like)
    db.session.commit()
    return redirect(url_for('video', video_id=video_id))

@app.route('/admin')
@token_required
def admin(current_user):
    if current_user.username != "admin":
        flash("Доступ запрещен", "danger")
        return redirect(url_for('index'))

    videos = Video.query.all()
    users = User.query.all()
    return render_template('admin.html', videos=videos, users=users)


@app.route('/admin/delete/<int:video_id>', methods=['POST'])
@token_required
def delete_video(current_user, video_id):
    if current_user.username != "admin":
        flash("Доступ запрещен", "danger")
        return redirect(url_for('index'))

    video = Video.query.get_or_404(video_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], video.filename)

    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(video)
        db.session.commit()
        flash("Видео удалено", "success")
    except Exception as e:
        flash(f"Ошибка удаления: {e}", "danger")

    return redirect(url_for('admin'))

@app.route('/videos/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    flash('Файл слишком большой. Максимальный размер — 100 МБ.', 'danger')
    return redirect(request.url)

@app.route('/admin/edit_video/<int:video_id>', methods=['POST'])
@token_required
def edit_video(current_user, video_id):
    if current_user.username != "admin":
        flash("Доступ запрещен", "danger")
        return redirect(url_for('index'))
    
    video = Video.query.get_or_404(video_id)
    video.title = request.form['title']
    video.description = request.form['description']
    db.session.commit()
    flash("Видео обновлено", "success")
    return redirect(url_for('admin'))

@app.route('/admin/edit_comment/<int:comment_id>', methods=['POST'])
@token_required
def edit_comment(current_user, comment_id):
    if current_user.username != "admin":
        flash("Доступ запрещен", "danger")
        return redirect(url_for('index'))
    
    comment = Comment.query.get_or_404(comment_id)
    comment.content = request.form['content']
    db.session.commit()
    flash("Комментарий обновлен", "success")
    return redirect(url_for('admin'))

@app.route('/admin/delete_comment/<int:comment_id>', methods=['POST'])
@token_required
def delete_comment(current_user, comment_id):
    if current_user.username != "admin":
        flash("Доступ запрещен", "danger")
        return redirect(url_for('index'))

    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash("Комментарий удален", "success")
    return redirect(url_for('admin'))

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@token_required
def edit_user(current_user, user_id):
    if current_user.username != "admin":
        flash("Доступ запрещен", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    new_username = request.form['username']
    new_password = request.form.get('password')

    if new_username:
        user.username = new_username
    if new_password:
        user.password = generate_password_hash(new_password)
    
    db.session.commit()
    flash("Пользователь обновлен", "success")
    return redirect(url_for('admin'))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@token_required
def delete_user(current_user, user_id):
    if current_user.username != "admin":
        flash("Доступ запрещен", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    # Защита от удаления самого себя
    if user.id == current_user.id:
        flash("Нельзя удалить самого себя", "warning")
        return redirect(url_for('admin'))

    db.session.delete(user)
    db.session.commit()
    flash("Пользователь удален", "success")
    return redirect(url_for('admin'))

@app.context_processor
def inject_user():
    token = request.cookies.get('token')
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user = User.query.get(data['user_id'])
            return {'current_user': user}
        except:
            pass
    return {'current_user': None}

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=False)