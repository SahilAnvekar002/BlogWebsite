from flask import Flask, render_template, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
import json
from datetime import datetime
import base64
import bcrypt

db = SQLAlchemy()

with open('config.json', 'r') as f:
    params = json.load(f)

app = Flask(__name__)
app.secret_key = params['secret_key']
app.config["SQLALCHEMY_DATABASE_URI"] = params['sql_uri']
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
db.init_app(app)

class Blogs(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    title = db.Column(db.String, nullable=False)
    main_heading = db.Column(db.String, nullable=False)
    main_content = db.Column(db.String, nullable=False)
    sub_heading = db.Column(db.String, nullable=False)
    sub_content = db.Column(db.String, nullable=False)
    slug = db.Column(db.String, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.now())
    img = db.Column(db.LargeBinary, nullable=False)
    bg_img = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, default=None)

class Feedbacks(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    phone = db.Column(db.String, nullable=False, unique=True)
    message = db.Column(db.String, nullable=False)

class Users(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

class Admins(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

class Comments(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    comment_text = db.Column(db.String, nullable=False)
    blog_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    parent_username = db.Column(db.String, nullable=True)
    root_username = db.Column(db.String, nullable=True)
    username = db.Column(db.String, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.now())
    root_id = db.Column(db.Integer, nullable=True)

@app.route('/')
def home():
    user = session.get('user')
    blogs = Blogs.query.all()
    imgs = []

    for blog in blogs:
        img = base64.b64encode(blog.bg_img).decode("utf-8")
        imgs.append(img)

    return render_template('home.html', blogs=blogs, imgs = imgs, user=user)

@app.route('/about')
def about():
    user = session.get('user')
    return render_template('about.html', user=user)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    user = session.get('user')
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        message = request.form.get('message')

        feedback = Feedbacks(name=name, email=email, phone=phone, message=message)
        db.session.add(feedback)
        db.session.commit()
        return redirect('/contact')

    else:
        return render_template('contact.html', user=user)

@app.route('/blogs')
def blogs():
    user = session.get('user')
    blogs = Blogs.query.all()
    bg_imgs = []
    usernames = []

    for blog in blogs:
        bg_img = base64.b64encode(blog.bg_img).decode("utf-8")
        bg_imgs.append(bg_img)

    for blog in blogs:
        if blog.user_id:
            u = Users.query.filter_by(id = blog.user_id).first()
            usernames.append(u.username)
        else:
            usernames.append("Admin")
        
    return render_template('blogs.html',blogs=blogs, bg_imgs = bg_imgs, user=user, usernames=usernames)

@app.route('/blogs/category/<string:category>')
def category_blogs(category):
    user = session.get('user')
    blogs = Blogs.query.filter_by(title=category)
    bg_imgs = []
    usernames = []

    for blog in blogs:
        bg_img = base64.b64encode(blog.bg_img).decode("utf-8")
        bg_imgs.append(bg_img)

    for blog in blogs:
        if blog.user_id:
            u = Users.query.filter_by(id = blog.user_id).first()
            usernames.append(u.username)
        else:
            usernames.append("Admin")
        
    return render_template('blogs.html',blogs=blogs, bg_imgs = bg_imgs, user=user, usernames=usernames)

@app.route('/search', methods=['POST'])
def search_blogs():
    if request.method == 'POST':
        user = session.get('user')

        search = request.form.get('search')

        searched_user = Users.query.filter_by(username = search).first()
        if searched_user:
            blogs = Blogs.query.filter((Blogs.title==search) | (Blogs.user_id == searched_user.id) | (Blogs.main_heading.contains(search)))
        else:
            blogs = Blogs.query.filter((Blogs.title==search) | (Blogs.main_heading.contains(search)))

        bg_imgs = []
        usernames = []

        for blog in blogs:
            bg_img = base64.b64encode(blog.bg_img).decode("utf-8")
            bg_imgs.append(bg_img)

        for blog in blogs:
            if blog.user_id:
                u = Users.query.filter_by(id = blog.user_id).first()
                usernames.append(u.username)
            else:
                usernames.append("Admin")
        
        return render_template('blogs.html',blogs=blogs, bg_imgs = bg_imgs, user=user, usernames=usernames)

@app.route('/blogs/<string:slug>', methods=['GET', 'POST'])
def blog(slug):
    if request.method == 'POST':
        email = session.get('user')
        comment_user = Users.query.filter_by(email=email).first()
        comment_blog = Blogs.query.filter_by(slug=slug).first()

        if request.form.get('root_username') == None and request.form.get('parent_username') == None:
            comment = request.form.get('comment')
            new_comment = Comments(comment_text=comment, blog_id=comment_blog.id, user_id=comment_user.id, username = comment_user.username)
        elif request.form.get('root_username') != None and request.form.get('parent_username') != None:
            root_username = request.form.get('root_username')
            root_id = request.form.get('root_id')
            parent_username = request.form.get('parent_username')
            comment = request.form.get('comment')
            new_comment = Comments(comment_text=comment, blog_id=comment_blog.id, user_id=comment_user.id, parent_username=parent_username ,root_username=root_username,username = comment_user.username, root_id=root_id)

        db.session.add(new_comment)
        db.session.commit()
        url = f'/blogs/{slug}'
        return redirect(url)

    else:
        user = session.get('user')
        user_id = ""
        user_obj = Users.query.filter_by(email=user).first()
        if user_obj:
            user_id = user_obj.id

        blog = Blogs.query.filter_by(slug=slug).first()
        img = base64.b64encode(blog.img).decode("utf-8")
        bg_img = base64.b64encode(blog.bg_img).decode("utf-8")
        comments = Comments.query.filter_by(blog_id = blog.id).all()

        main_content_paras = blog.main_content.strip().split('\n')
        
        sub_content_paras = blog.sub_content.strip().split('\n')

        return render_template('article.html', blog=blog, img=img, bg_img =bg_img, user=user, comments=comments, user_id=user_id, main_content_paras=main_content_paras, sub_content_paras=sub_content_paras)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        prev_user = Users.query.filter_by(email=email).first()
        if prev_user:
            return render_template('signup.html', message="User with that email already exists")

        salt = bcrypt.gensalt()
        password = password.encode('utf-8')
        hashed_password = bcrypt.hashpw(password, salt)

        user = Users(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        session['user'] = email

        return redirect('/')
    else:
        return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        password = password.encode('utf-8')

        user = Users.query.filter_by(email=email).first()
        if not user: 
            return render_template('login.html', message="Invalid credentials")

        hashed_password = user.password.encode('utf-8')
        check_password = bcrypt.checkpw(password, hashed_password)
        
        if check_password == False:
            return render_template('login.html', message="Invalid credentials")

        session['user'] = user.email
        return redirect('/')
    else:
        print(bcrypt.checkpw("sneha002".encode(), "$2b$12$uOSlRXe9vqTt/CUs1KafIO0".encode()))
        return render_template('login.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    admin = session.get('admin')

    if(admin):
        if request.method == 'POST':
            title = request.form.get('title')
            main_heading = request.form.get('main_heading')
            main_content = request.form.get('main_content')
            sub_heading = request.form.get('sub_heading')
            sub_content = request.form.get('sub_content')
            image = request.files['image'].read()
            bg_image = request.files['bg_image'].read()
            slug = request.form.get('slug')

            blog = Blogs(title=title, main_heading=main_heading, main_content=main_content, sub_heading=sub_heading, sub_content=sub_content, img=image, bg_img=bg_image, slug=slug)
            db.session.add(blog)
            db.session.commit()
            return redirect('/admin')

        else:
            admin_blogs = Blogs.query.filter_by(user_id = None).all()
            user_blogs = Blogs.query.filter(Blogs.user_id != None).all()
            return render_template('admin.html', admin_blogs=admin_blogs, user_blogs=user_blogs ,admin=admin)
    
    else:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            admin = Admins.query.filter_by(username=username).first()
            if not admin: 
                return render_template('admin_login.html')
            
            if admin.password != password:
                return render_template('admin_login.html')
            
            session['admin'] = admin.username

            return redirect('/admin')

        return render_template('admin_login.html')

@app.route('/admin/blog/<string:id>', methods=['GET', 'POST'])
def edit_blog(id):
    admin = session.get('admin')

    if(admin):
        if request.method == 'POST':
            current_blog = Blogs.query.filter_by(id=id).first()

            title = request.form.get('title')
            main_heading = request.form.get('main_heading')
            main_content = request.form.get('main_content')
            sub_heading = request.form.get('sub_heading')
            sub_content = request.form.get('sub_content')
            if request.files['image']:
                image = request.files['image'].read()
            else:
                image = current_blog.img

            if request.files['bg_image']:
                bg_image = request.files['bg_image'].read()
            else:
                bg_image = current_blog.bg_img

            slug = request.form.get('slug')

            current_blog.title = title
            current_blog.main_heading = main_heading
            current_blog.main_content = main_content
            current_blog.sub_heading =sub_heading
            current_blog.sub_content = sub_content
            current_blog.img = image
            current_blog.bg_img = bg_image
            current_blog.slug = slug
            db.session.commit()
            
            return redirect('/admin')

        else:
            admin_blogs = Blogs.query.filter_by(user_id = None).all()
            user_blogs = Blogs.query.filter(Blogs.user_id != None).all()
            current_blog = Blogs.query.filter_by(id=id).first()
            return render_template('edit_blog.html', admin_blogs=admin_blogs, admin=admin, current_blog=current_blog, user_blogs=user_blogs)
    
    else:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            admin = Admins.query.filter_by(username=username).first()
            if not admin: 
                return render_template('admin_login.html')
            
            if admin.password != password:
                return render_template('admin_login.html')
            
            session['admin'] = admin.username

            return redirect('/admin')

        return render_template('admin_login.html')

@app.route('/logout-admin')
def logout_admin():
    session.pop('admin')
    return redirect('/admin')

@app.route('/logout')
def logout():
    session.pop('user')
    return redirect('/')

@app.route('/delete-blog/<string:id>')
def delete_blog(id):
    blog = Blogs.query.filter_by(id=id).first()
    comments = Comments.query.filter_by(blog_id=id)
    db.session.delete(blog)
    db.session.commit()
    for comment in comments:
        db.session.delete(comment)
        db.session.commit()
    
    return redirect('/admin')

@app.route('/delete-comment/<string:id>/<string:slug>')
def delete_comment(id, slug):
    comment = Comments.query.filter_by(id=id).first()
    db.session.delete(comment)
    db.session.commit()

    return redirect('/blogs/'+slug)

@app.route('/create-blog', methods=['GET', 'POST'])
def create_blog():
    if request.method == 'POST':
        title = request.form.get('title')
        main_heading = request.form.get('main_heading')
        main_content = request.form.get('main_content')
        sub_heading = request.form.get('sub_heading')
        sub_content = request.form.get('sub_content')
        image = request.files['image'].read()
        bg_image = request.files['bg_image'].read()
        slug = request.form.get('slug')
        user_id = request.form.get('user_id')

        blog = Blogs(title=title, main_heading=main_heading, main_content=main_content, sub_heading=sub_heading, sub_content=sub_content, img=image, bg_img=bg_image, slug=slug, user_id=user_id)
        db.session.add(blog)
        db.session.commit()
        return redirect('/create-blog')      

    else:
        user_email = session.get('user')
        user = Users.query.filter_by(email=user_email).first()
        user_id = user.id
        blogs = Blogs.query.filter_by(user_id=user_id)

        return render_template('create_blog.html' , blogs=blogs, user= user)


@app.route('/edit-blog/<string:id>', methods=['GET', 'POST'])
def user_edit_blog(id):

    if request.method == 'POST':
        current_blog = Blogs.query.filter_by(id=id).first()

        title = request.form.get('title')
        main_heading = request.form.get('main_heading')
        main_content = request.form.get('main_content')
        sub_heading = request.form.get('sub_heading')
        sub_content = request.form.get('sub_content')
        if request.files['image']:
            image = request.files['image'].read()
        else:
            image = current_blog.img

        if request.files['bg_image']:
            bg_image = request.files['bg_image'].read()
        else:
            bg_image = current_blog.bg_img

        slug = request.form.get('slug')
        user_id = request.form.get('user_id')

        current_blog.title = title
        current_blog.main_heading = main_heading
        current_blog.main_content = main_content
        current_blog.sub_heading = sub_heading
        current_blog.sub_content = sub_content
        current_blog.img = image
        current_blog.bg_img = bg_image
        current_blog.slug = slug
        current_blog.user_id = user_id

        db.session.commit()
            
        return redirect('/create-blog')

    else:
        user_email = session.get('user')
        user = Users.query.filter_by(email=user_email).first()
        blogs = Blogs.query.filter_by(user_id= user.id)
        current_blog = Blogs.query.filter_by(id=id).first()
        return render_template('user_edit_blog.html', blogs=blogs, user=user, current_blog=current_blog)

@app.route('/delete-user-blog/<string:id>')
def delete_user_blog(id):
    blog = Blogs.query.filter_by(id=id).first()
    comments = Comments.query.filter_by(blog_id=id)
    db.session.delete(blog)
    db.session.commit()
    for comment in comments:
        db.session.delete(comment)
        db.session.commit()
    
    return redirect('/create-blog')

app.run(debug=True)