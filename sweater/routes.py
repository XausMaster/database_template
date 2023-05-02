from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sweater import db, app, login_manager
from sweater.models import User, mehsullar, comment
import base64, uuid


mehsul = []

@app.route('/')
def main():
    return redirect('/home')


@app.route('/home', methods=['POST', 'GET'])
def home():
    flash('Xos gelmisiniz !', 'info')
    return render_template('index.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    questions = ['Yaşadığınız Şəhər', 'Sevdiyiniz Yemək', 'Sizin Yaşınız']
    if request.method == 'POST':
        # if request.files['file']:
        file = request.files['file']
        file.save('static/img/'+ request.form['user_name'] +'.jpg')
        password = request.form['password']
        hash_password = generate_password_hash(password, method='sha256')
        userr = User(user_name = request.form['user_name'], password = hash_password, info = request.form['info'], email = request.form['email'], question = request.form['question'], question_answer = request.form['question_answer'], profile_image = request.form['user_name'] +'.jpg')
        try:
            db.session.add(userr)
            db.session.commit()
        except Exception as a:
            print(a)
            return "Error"
        return redirect('/profil')
    else:
        return render_template('register.html', questions=questions)


@app.route('/reset_password', methods=['POST', 'GET'])
def reset_password():
    if request.method == 'POST':
        user_name_email = request.form['user_name_email']
        data = User.query.filter((User.user_name == user_name_email) | (User.email == user_name_email)).first()
        if data is not None:
            if (data.user_name == user_name_email or data.email == user_name_email):
                return redirect(url_for('reset_pass', id=data.id))
            else:
                flash('Login Duzgun deyil !')
                return redirect('/reset_password')
        flash('Zehmet Olmaza Hesaba Daxil Olun', 'error')
        return redirect('/login')
    else:
        return render_template('reset_password.html')


@app.route('/reset_pass/<int:id>', methods=['POST', 'GET'])
def reset_pass(id):
    if request.method == 'POST':
        new_password = request.form['new_password']
        question_answer = request.form['question_answer']
        data = User.query.filter_by(id=int(id)).first()
        hash_password = generate_password_hash(new_password, method='sha256')
        if data:
            if question_answer == data.question_answer:
                data.password = hash_password
                db.session.commit()
                return redirect('/login')
        flash('Zehmet Olmaza Hesaba Daxil Olun', 'error')
        return redirect('/login')
    else:
        data = User.query.filter_by(id=int(id)).first()
        question = data.question
        return render_template('reset_pass.html', question=question)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        user_name_email = request.form['user_name_email']
        password = request.form['password']
        data = User.query.filter((User.user_name == user_name_email) | (User.email == user_name_email)).first()
        if data:
            if check_password_hash(data.password, password):
                login_user(data)
                return redirect('/show')
            else:
                flash('Login Duzgun deyil !')
                return redirect('/login')
        flash('Zehmet Olmaza Hesaba Daxil Olun', 'error')
        return redirect('/login')
    else:
        return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


@app.route('/profil', methods=['POST', 'GET'])
@login_required
def profil():
    if request.method == 'POST':
        new_info = request.form['new_info']
        file = request.files['profile_image']
        file.save('static/img/' + current_user.user_name + '.jpg')
        file.seek(0)
        current_user.profile_image = file.read()
        current_user.mimetype = file.mimetype
        current_user.profile_image_text = file.filename
        current_user.info = new_info
        db.session.commit()
    melumatlar = mehsullar.query.filter_by(seller = current_user.user_name).all()
    image = base64.b64encode(current_user.profile_image).decode('utf-8')
    return render_template('profil.html', user=current_user, melumatlar=melumatlar, image = image)


@app.route('/profile_image/<int:id>')
def profile_image(id):
    user = User.query.filter_by(id = id).first()
    return user.profile_image


@app.route('/add/<string:user>', methods=['POST', 'GET'])
@login_required
def add(user):
    if request.method == 'POST':
        file = request.files['file']
        mehsul1 = mehsullar(ad = request.form['ad'],
                            kateqoriya = request.form['kateqoriya'],
                            info = request.form['info'],
                            qiymet = request.form['qiymet'],
                            seller = user,
                            preview_text = file.filename,
                            preview = file.read(),
                            mimetype = file.mimetype)
        try:
            db.session.add(mehsul1)
            db.session.commit()
        except:
            return "Error"
        if len(mehsul) == 0:
            id = 1
        else:
            id = mehsul[len(mehsul) - 1][0]
            id += 1
        return redirect('/show')
    else:
        return render_template('add.html')


@app.route('/mehsul_image/<int:id>')
def mehsul_image(id):
    mehsull = mehsullar.query.filter_by(id = id).first()
    return mehsull.preview


@app.route('/edit/<int:id>', methods=['POST', 'GET'])
@login_required
def edit(id):
    if request.method == 'POST':
        object = mehsullar.query.get(id)
        # a = mehsullar.query.order_by(mehsullar.qiymet.asc())
        # b = mehsullar.query.filter_by(kateqoriya = "GPU").order_by(mehsullar.qiymet.desc())
        # c = mehsullar.query.filter(mehsullar.qiymet > 1000)
        # d = mehsullar.query.filter((mehsullar.qiymet > 2) | (mehsullar.qiymet == 1000))
        # e = mehsullar.query.with_entities(mehsullar.ad, mehsullar.qiymet)
        ad = request.form['ad']
        kateqoriya = request.form['kateqoriya']
        qiymet = request.form['qiymet']
        info = request.form['info']
        sil = request.form['delete']
        file = request.files['preview']
        if sil != 'sil':
            if id == int(object.id):
                object.ad = ad
                object.kateqoriya = kateqoriya
                object.qiymet = qiymet
                object.info = info
                object.preview_text = file.filename
                object.preview = file.read()
                object.mimetype = file.mimetype
                db.session.commit()
            return redirect('/show')
        else:
            db.session.delete(object)
            db.session.commit()
            return redirect('/show')
    else:
        return render_template('edit.html')


@app.route('/add_comment/<string:user>', methods = ['POST', 'GET'])
@login_required
def add_comment(user):
    if request.method == 'POST':
        comment.text = request.form['text']
        comment.author = user
        if len(mehsul) == 0:
            comment.id = 1
        else:
            id = mehsul[len(mehsul) - 1][0]
            id += 1
            comment.id = id

    else:
        return render_template('add_comment.html')


@app.route('/comments/<int:mehsul_id>/<string:user>', methods = ['POST', 'GET'])
@login_required
def comments(user, mehsul_id):
    if request.method == 'POST':
        comment_ = comment(text = request.form['text'],
                           author = user,
                           mehsul_id = mehsul_id)
        try:
            db.session.add(comment_)
            db.session.commit()
        except:
            return "Error"
        if len(mehsul) == 0:
            id = 1
        else:
            id = mehsul[len(mehsul) - 1][0]
            id += 1
        return redirect(url_for('comments', user=user, mehsul_id=mehsul_id))
    else:
        comments = comment.query.filter_by(mehsul_id = mehsul_id)
        userr = User.query.filter_by(user_name = user).first()
        return render_template('comments.html', comments = comments, user = userr, mehsul_id = mehsul_id)


@app.route('/comments/delete/<int:comment_id>/<int:mehsul_id>/<string:user>')
@login_required
def comment_delete(comment_id, user, mehsul_id):
    print(user)
    comment_obj = comment.query.filter_by(id = comment_id).first()
    db.session.delete(comment_obj)
    db.session.commit()
    return redirect(url_for('comments', user = user, mehsul_id = mehsul_id))


@app.route('/show')
@login_required
def show():
    melumatlar = mehsullar.query.all()
    users = User
    return render_template('show.html', mehsul=mehsul, melumatlar=melumatlar, users=users)


@app.route('/seller/<user>')
def seller_profile(user):
    user_obj = User.query.filter_by(user_name = user).first()
    products = mehsullar.query.filter_by(seller = user).all()
    return render_template('seller_profile.html', user=user_obj, melumatlar=products)


@app.route('/show', methods=['POST'])
@login_required
def search():
    if request.method == 'POST':
        text = request.form['search']
        mehsull = mehsullar.query.filter(mehsullar.ad.contains(text)).all()
        return render_template('search.html', mehsull=mehsull)
    else:
        return redirect('/show')
    return render_template('show.html', mehsullar=mehsull)


@app.route('/show/filter/<txt>', methods=['POST', 'GET'])
@login_required
def filter(txt):
    # txt = request.args.get('t')
    if txt != '':
        print(txt)
        if txt == 'l-u':
            list2 = mehsullar.query.order_by(mehsullar.qiymet.asc())
        elif txt == 'u-l':
            list2 = mehsullar.query.order_by(mehsullar.qiymet.desc())
        else:
            list2 = mehsullar.query.filter(mehsullar.kateqoriya == txt)

        return render_template('filter.html', mehsullar=list2)
    return render_template('show.html', mehsul=mehsul)


@app.route('/show/statistika', methods=['POST'])
@login_required
def statistika():
    melumatlar = mehsullar.query.all()
    all_sum = 0
    sum = 0
    kateqoriyalar = []
    for mehsul in melumatlar:
        num = int(mehsul.qiymet)
        all_sum += num
    if len(melumatlar) != 0:
        sum = all_sum / len(melumatlar)
    for mehsul in melumatlar:
        if mehsul.kateqoriya not in kateqoriyalar:
            kateqoriya = mehsul.kateqoriya
            kateqoriyalar.append(kateqoriya)
    count = len(list(set(kateqoriyalar)))
    kat = list(set(kateqoriyalar))
    gpu = makbuk = telefon = noutbuk = televizor = 0
    for mehsul in melumatlar:
        if mehsul.kateqoriya == 'GPU':
            gpu += int(mehsul.qiymet)
        elif mehsul.kateqoriya == 'Makbuk':
            makbuk += int(mehsul.qiymet)
        elif mehsul.kateqoriya == 'Telefon':
            telefon += int(mehsul.qiymet)
        elif mehsul.kateqoriya == 'Noutbuk':
            noutbuk += int(mehsul.qiymet)
        elif mehsul.kateqoriya == 'Televizor':
            televizor += int(mehsul.qiymet)
    return render_template('statistika.html', melumatlar=melumatlar, sum=sum, count=count, all_sum=all_sum, kat=kat, gpu=gpu,
                           makbuk=makbuk, telefon=telefon, noutbuk=noutbuk, televizor=televizor)


@app.route('/show/<int:id>/<user>')
@login_required
def info(id, user):
    if id and user:
        user_obj = User.query.filter_by(user_name = user).first()
        data = mehsullar.query.filter_by(id = id).first()
        user_data = mehsullar.query.filter_by(seller = user_obj.user_name).first()
        if user_data.seller == current_user.user_name:
            return render_template('info.html', info=data.info, owner=True)
        else:
            return render_template('info.html', info=data.info, owner=False)


def db_init(app):
    with app.app_context():
        db.create_all()


db_init(app)

if __name__ == '__main__':
    app.run(debug=True)
