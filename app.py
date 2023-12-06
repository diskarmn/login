import os
from os.path import join, dirname
from dotenv import load_dotenv
from flask import Flask,request,session,url_for,redirect,jsonify,render_template
import jwt  #token bukti akun verifikasi
import hashlib #mengacak kata menjadi kode random
from datetime import datetime,timedelta #alat waktu flask nanti digunakan mengatur kedaluarsa token
from pymongo import MongoClient

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)
app=Flask(__name__)
# client=MongoClient('mongodb://diskarmn:Diska123@ac-sjiapka-shard-00-00.3lnlkgx.mongodb.net:27017,ac-sjiapka-shard-00-01.3lnlkgx.mongodb.net:27017,ac-sjiapka-shard-00-02.3lnlkgx.mongodb.net:27017/?ssl=true&replicaSet=atlas-vnije0-shard-0&authSource=admin&retryWrites=true&w=majority')
# db=client.login
MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME =  os.environ.get("DB_NAME")
client = MongoClient(MONGODB_URI)
db=client[DB_NAME]
SECRET_KEY = 'kunci_token' #agar token bisa masuk


    
@app.route("/")
def home():
    token_receive = request.cookies.get("mytoken")
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        user_info = db.user.find_one({"id": payload["id"]})
        return render_template("index.html", nickname=user_info["nick"])
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="Your login token has expired"))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="There was an issue logging you in"))
    
@app.route('/login',methods=['GET'])
def login():
    msg=request.args.get('msg')
    return render_template('login.html',mgs=msg)
@app.route('/register',methods=['GET'])
def register():
    return render_template('register.html')
#route api register
@app.route('/api/register',methods=['POST'])
def api_register():
    id_receive=request.form.get('id_give')
    pw_receive=request.form.get('pw_give')
    nickname_receive=request.form.get('nickname_give')

    pw_hash=hashlib.sha256(pw_receive.encode('utf-8')).hexdigest() #mengenskripsi pw

    db.user.insert_one({
        'id':id_receive,
        'pw':pw_hash,
        'nick':nickname_receive})
    return  jsonify({'result':'success'})
#route api login
@app.route("/api/login", methods=["POST"])
def api_login():
    id_receive = request.form["id_give"]
    pw_receive = request.form["pw_give"]

    pw_hash = hashlib.sha256(pw_receive.encode("utf-8")).hexdigest()

    result = db.user.find_one({"id": id_receive, "pw": pw_hash})

    if result is not None:
        payload = {
            "id": id_receive,
            "exp": datetime.utcnow() + timedelta(days=1),
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return jsonify({"result": "success", "token": token})

    else:
        return jsonify({"result": "fail", "msg": "Either your email or your password is incorrect"})
    
@app.route('/api/nick',methods=['GET'])
def api_valid():
    token_receive=request.cookies.get('mytoken')
    try:
        payload=jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256'] )
        print (payload)
        user_info=db.user.find_one({'id':payload.get('id')},{'_id':0})
        return jsonify({'result':'success',
                        'nickname':user_info.get('nick')})
    except jwt.ExpiredSignatureError:
        msg='token exp'
        return jsonify({'result':'fail', 'msg':msg})
    except jwt.exceptions.DecodeError:
        msg='issue login/problem'
        return jsonify({'result':'fail', 'msg':msg})





if __name__=='__main__':
    app.run('0.0.0.0',port=5000,debug=True)
