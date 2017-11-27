from flask import Flask, g, render_template, make_response, redirect
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restful import reqparse, Api
from models import db, User
from flask_restful import Resource



app = Flask(__name__)
api = Api(app)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'

with app.app_context():
    db.init_app(app)
    # db.create_all()


basic_auth = HTTPBasicAuth()


# PARSERS
register_parser = reqparse.RequestParser()
register_parser.add_argument('username', type=str, required=True)
register_parser.add_argument('password', type=str, required=True)

admin_parser = reqparse.RequestParser()
admin_parser.add_argument('delete', type=str, required=True) #user id

class Admin(Resource):
    @basic_auth.login_required
    def get(self):
        # print(g.user)
        if g.user.username == 'admin':

            users = [[i.username, i.password, i.id] for i in db.session.query(User)]
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('admin.html', username=g.user, users=users), 200, headers)
        else:
            return 'Access Denied'
    @basic_auth.login_required
    def post(self):
        args = admin_parser.parse_args()

        try:
            db.session.delete(db.session.query(User).filter_by(id=args['delete']).first())
            db.session.commit()
        except Exception as e:
            return ('Error deleting account' + str(e), 500)
        return redirect('/admin')



class Test(Resource):
    def get(self):
        users_dict = [{i.username: i.password} for i in db.session.query(User)]

        users = [i.username for i in db.session.query(User)]
        # for user in users:
        #     db.session.delete(User.query.filter_by(username=str(user)).first())
        # db.session.commit()
        return users_dict

class Login(Resource):
    @basic_auth.verify_password
    def get(username_or_token, password):
        print(username_or_token, password)
        if not username_or_token or not password:
            return None
        g.user = None
        
        user_id = User.verify_auth_token(username_or_token) #tries to auth with a token
        print(username_or_token)
        if user_id: #if it works then it filters database for user
            user = db.session.query(User).filter_by(id=user_id).one()
        else: #if it doesn't then it attempts to filter database using username
            user = db.session.query(User).filter_by(username = username_or_token).first()
            if not user or not user.verify_password(password, user.password):
                print('FALSE')
                return False#returns false if not user

        g.user = user
        return True


class Logout(Resource):
    def get(self):
        g.user = None
        return ('Logout', 401)


class Register(Resource):


    def get(self):
        return ('Error', 404)
    def post(self):
        args = register_parser.parse_args()
        # print(args['username'])

        username = args['username']
        password = args['password']


        if len(password) < 8:
            return ('password is too short (8 or more characters)', 412)
        

        if User.username_taken(username):
            return ('username is not unique', 412)

        try:
            new_user = User(username=username, password=generate_password_hash(password))
        except:
            return ('Error 500', 500)

        try:
            db.session.add(new_user)
        except:
            return ('Error 500', 500)
        try:
            db.session.commit()
        except:
            return ('Error 500', 500)

        return ('successfully registered', 200)
        


class Index(Resource):
    @basic_auth.login_required
    def get(self):
        return {'Log' : True}

class HelloWorld(Resource):
    def get(self):
        return {'test': 'hello world'}
        
class GetUser(Resource):
    @basic_auth.login_required
    def get(self):
        return g.user

# api.add_resource(HelloWorld, '/')
api.add_resource(Test, '/test')
api.add_resource(Index, '/')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(GetUser, '/getuser')
api.add_resource(Register, '/register')
api.add_resource(Admin, '/admin')

if __name__ == '__main__':
    app.run(debug=True)

