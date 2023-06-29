import werkzeug.security
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(db.String(250), nullable=False)
    password = Column(db.String(500), nullable=False)
    name = Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", lazy='subquery', back_populates="author")
    comments = relationship("Comment", lazy='subquery', back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    title = Column(db.String(250), unique=True, nullable=False)
    subtitle = Column(db.String(250), nullable=False)
    date = Column(db.String(250), nullable=False)
    body = Column(db.Text, nullable=False)
    img_url = Column(db.String(250), nullable=False)
    author = relationship("User", lazy='subquery', back_populates="posts")
    comments = relationship("Comment", lazy='subquery', back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    post_id = Column(Integer, ForeignKey('blog_posts.id'))
    text = Column(db.Text, nullable=False)
    author = relationship("User", lazy='subquery', back_populates="comments")
    post = relationship("BlogPost", lazy='subquery', back_populates="comments")


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)
    return wrapper


@app.route('/')
def get_all_posts():
    with app.app_context():
        posts = db.session.execute(db.select(BlogPost)).scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        password_hash = werkzeug.security.generate_password_hash(register_form.password.data, salt_length=8)
        new_user = User(name=register_form.name.data,
                        email=register_form.email.data,
                        password=password_hash)
        new_user_email = new_user.email
        # new_user.name = register_form.name.data
        # new_user.email = register_form.email.data
        # new_user.password = password_hash
        with app.app_context():
            if db.session.execute(db.select(User).where(User.email == new_user_email)).scalar():
                flash("This email already exists. Please log in!")
                return redirect(url_for('login'))
            else:
                db.session.add(new_user)
                db.session.commit()
                my_user = db.session.execute(db.select(User).where(User.email == new_user_email)).scalar()
                login_user(my_user)
                return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        with app.app_context():
            my_user = db.session.execute(db.select(User).where(User.email == login_form.email.data)).scalar()
            if my_user:
                pwhash = my_user.password
                if check_password_hash(pwhash=pwhash, password=login_form.password.data):
                    login_user(my_user)
                else:
                    flash("This password is incorrect. Try again")
                    return redirect(url_for('login'))
            else:
                flash("This email does not exist. Try again!")
                return redirect(url_for('login'))
        return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=comment_form.comment.data, post_id=post_id, author_id=current_user.id)
            with app.app_context():
                db.session.add(new_comment)
                db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))
    with app.app_context():
        requested_post = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id
        )
        with app.app_context():
            db.session.add(new_post)
            db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    with app.app_context():
        post = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            author=post.author,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            # post.author = edit_form.author.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

        return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    with app.app_context():
        post_to_delete = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
