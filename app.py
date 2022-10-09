from flask import Flask
from flask import jsonify
from flask_restful import Resource,reqparse, Api ,abort
from flaskext.mysql import MySQL
import pymysql
from flask_cors import CORS

from flask_jwt_extended import create_access_token , create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

mysql = MySQL()
app = Flask(__name__)

# JWT Authentication
# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)



# MySQL configurations
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'helping'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

api = Api(app)
CORS(app)

class data(Resource):
    @jwt_required()
    def get(self):
        
        conn = mysql.connect()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * from data")
        rows = cursor.fetchall()
        resp = jsonify(rows)
        return resp


addData_args=reqparse.RequestParser()
addData_args.add_argument("name", type=str, help="name", required=True)
addData_args.add_argument("img", type=str, help="image", required=True)

class AddData(Resource):
    def post(self):
        
        conn = mysql.connect()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        args=addData_args.parse_args()

        query='''INSERT INTO data (name, img)
        VALUES (%s,%s)'''
        val=(args['name'],args['img'])
        cursor.execute(query,val)
        conn.commit()
        return 200


#ROUTES DEFINITIONS


# Here is a custom decorator that verifies the JWT is present in the request,
# as well as insuring that the JWT has a claim indicating that this user is
# an Admin

# Request arguments for Admin
login_args = reqparse.RequestParser()
login_args.add_argument("username", type=str, help="Username for Login", required=True)
login_args.add_argument("password", type=str, help="Password for Login", required=True)


class AdminLogin(Resource):
    def post(self):
        conn = mysql.connect()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        request_body = login_args.parse_args() #returns a python dictionary of request body
        cursor.execute("SELECT * FROM admin WHERE username=%s ",(request_body['username']))
        admin = cursor.fetchone()


        if admin:
            access_token = create_access_token(identity=request_body['username'])
            refresh_token =create_refresh_token(identity=request_body['username'])
            return jsonify(access_token=access_token , refresh_token = refresh_token  , status = 200)

        else:
               
               return jsonify ({"status" : 401 , "message" : "Invalid Password"})
            

api.add_resource(AdminLogin, '/Adminlogin')
api.add_resource(data, '/data')
api.add_resource(AddData, '/data/add')

if __name__ == "__main__":
    app.run(debug=True)
   

   