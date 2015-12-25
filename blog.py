import os
import re
import random
import hashlib
import hmac
from string import letters
import datetime
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    fullname = db.StringProperty(required=True)
    name = db.StringProperty(required = True)
    mobile = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls,fullname, name, pw,mobile, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    fullname=fullname,
                    name = name,
                    pw_hash = pw_hash,
                    email = email,
                    mobile= mobile)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    created_by = db.StringProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)    

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = db.GqlQuery("select * from Post order by created desc");
        if self.user:
            temp = self.user.name;
            temp += "'";
            temp = "'" + temp;
            userlist = db.GqlQuery("select * from User where name != %s "%temp);
            self.render('front.html', posts = posts,userlist=userlist);
        else :
            userlist = db.GqlQuery("select * from User ");
            self.render('front.html', posts = posts,userlist=userlist);

    def post(self):
        if not self.user:
            self.redirect('/login')
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            created_by = self.user.name
            p = Post(parent = blog_key(), subject = subject, content = content,created_by = created_by)
            p.put()
            self.redirect('/%s' % str(p.key().id()))


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        temp = self.user.name;
        temp += "'";
        temp = "'" + temp;
        userlist = db.GqlQuery("select * from User where name != %s "%temp);
        self.render("permalink.html", post = post,userlist=userlist)



fullname_RE = re.compile(r"^[a-zA-Z ]{3,20}$")
def valid_fullname(fullname):
    return fullname and fullname_RE.match(fullname)

USER_RE = re.compile(r"^[a-zA-Z 0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

mobile_re = re.compile(r"^[0-9]{10,12}")
def valid_mobile(mobile):
    return mobile and mobile_re.match(mobile)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.fullname = self.request.get('fullname')
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        self.mobile = self.request.get('mobile')
        
        self.username = self.username.lower();
        params = dict(username = self.username,
                      email = self.email,
                      mobile = self.mobile,
                      fullname = self.fullname)
        self.fullname = self.fullname.capitalize();


        if not valid_fullname(self.fullname):
            params['fullname'] = "Enter a valid Name"
            have_error = True

        if not valid_mobile(self.mobile):
            params['error_mobile'] = "Enter a valid Contact Number"
            have_error = True

        if not valid_username(self.username):
            params['error_username'] = "Enter a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Enter a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Enter a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError



class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.fullname,self.username, self.password,self.mobile, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        username = username.lower();
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = "The username and password you entered don't match."
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class Profile(BlogHandler):
    def get(self,user_name):
        if self.user:
            temp = self.user.name
            temp += "'"
            temp  = "'" + temp
        check_user = User.by_name(user_name)
        user_name += "'";
        user_name = "'" + user_name;
        if check_user:
            posts = greetings = db.GqlQuery("select * from Post where created_by = %s order by created desc"%user_name);
            if self.user:
                userlist = db.GqlQuery("select * from User where name != %s"%temp);
            else :
                userlist = db.GqlQuery("select * from User");
            self.render('profile.html', posts = posts,userlist=userlist,check_user=check_user)
        else :
            self.redirect('/')


app = webapp2.WSGIApplication([
                               ('/', BlogFront),
                               ('/([0-9]+)', PostPage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/([a-zA-Z0-9_]+)',Profile)
                               ],
                              debug=True)