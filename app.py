import os
import time
import yaml
import hashlib
import requests
from flaskext.mysql import MySQL
from flask import Flask, flash, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from services.injections import Injections
from api.virus_total import Call

app = Flask(__name__)

mysql = MySQL()

with open('passwords.yml') as f:
    var = yaml.load(f)

# MySQL configurations
app.config['MYSQL_DATABASE_USER'] = var['DB_USER']
app.config['MYSQL_DATABASE_PASSWORD'] = var['DB_PASS']
app.config['MYSQL_DATABASE_DB'] = var['DB_NAME']
app.config['MYSQL_DATABASE_HOST'] = var['DB_HOST']
mysql.init_app(app)

conn = mysql.connect()
cursor = conn.cursor()

# File upload path
UPLOAD_FOLDER = 'uploads'
if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir('uploads/')

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def main():
	return render_template('index.html')


@app.route('/', methods=['GET','POST'])
def fuzz_post():
	end_point = request.form['text']
	request_case = request.form['options']
	injection_case = request.form['i_options']

	i_types = []
	if injection_case == 'sql_injections':
		i_types.append(Injections.sql_injections())
	elif injection_case == 'command_injections':
		i_types.append(Injections.command_injections())
	elif injection_case == 'xss_injections':
		i_types.append(Injections.xss_injections())
	elif injection_case == 'rce_injections':
		i_types.append(Injections.rce_injections())
	elif injection_case == 'ldap_injections':
		i_types.append(Injections.ldap_injections())
	elif injection_case == 'dast_scan':
		i_types.append(Injections.dast_scan())
	else:
		i_types.append(Injections.url_snoop())

	data = {}
	badInput = ['<','>','--','script','/script']

	booTF = set(list(end_point)) & set(badInput)

	for arr in i_types[0]:
		try:
			time.sleep(1)

			if '[]' in end_point and len(booTF) == 0:
				new_ep = end_point.replace('[]', arr)

				if request_case == 'GET':
					r = requests.get(new_ep)
				elif request_case == 'POST':
					r = requests.post(new_ep)
				elif request_case == 'PUT':
					r = requests.put(new_ep)
				elif request_case == 'DELETE':
					r = requests.delete(new_ep)
				else:
					return request_case
					break

				data.setdefault("Type",[]).append([
					injection_case
					]
				)
				data.setdefault("Results",[]).append([
					request_case,
					new_ep,
					str(r.status_code)
					]
				)

				cursor.execute(
					"""INSERT INTO
						tbl_fuzz (
							request_type,
							url,
							response_code)
					VALUES (%s,%s,%s)""", (request_case, new_ep, str(r.status_code)))
				conn.commit()

			else:
				return '\n[-] Not fuzzable.'
				break

		except Exception as error:
			return '\n[-] Could not make a successful request to that endpoint. {0}'.format(error)

	return render_template("results.html", results=data)


@app.route('/past_runs', methods=['GET', 'POST'])
def past_runs():
    conn = mysql.connect()
    cursor = conn.cursor()

    data = ""

    if request.method == 'GET':

        query = """SELECT request_type, substring(url, 1, 120),
		      response_code, TIME_FORMAT(`created_at`, '%H:%i:%s')
              FROM tbl_fuzz
              WHERE created_at >= DATE_SUB(NOW(),INTERVAL 1 day)
              ORDER BY created_at DESC"""
        cursor.execute(query)
        data = cursor.fetchall()

    elif request.method == 'POST':

        query = "SELECT request_type, substring(url, 1, 120),\
              response_code, TIME_FORMAT(`created_at`, '%%H:%%i:%%s')\
              FROM tbl_fuzz\
              ORDER BY created_at DESC\
              LIMIT %s"
        cursor.execute(query, int(request.form['text']))
        data = cursor.fetchall()

    conn.close()

    return render_template('runs.html', data=data)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    conn = mysql.connect()
    cursor = conn.cursor()
    data = ''

    if request.method == 'GET':
        query = """SELECT file_name, md5_hash, sha1_hash, sha256_hash, ssdeep_hash,
                ssdeep_compare, is_infected,
                DATE_FORMAT(`created_at`, '%W, %M %e, %Y @ %h:%i %p')
              FROM tbl_files
              ORDER BY created_at DESC"""
        cursor.execute(query)
        data = cursor.fetchall()

    elif request.method == 'POST':
        file = request.files['file']
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        # if user does not select file, browser also
        # submit a empty part without filename
        elif file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        elif file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            md5 = hashlib.md5(
                open('uploads/{0}'.format(filename), 'rb').read()).hexdigest()
            sha1 = hashlib.sha1(
                open('uploads/{0}'.format(filename), 'rb').read()).hexdigest()
            sha256 = hashlib.sha256(
                open('uploads/{0}'.format(filename), 'rb').read()).hexdigest()

            try:
                import ssdeep
                ss_hash = ssdeep.hash_from_file(filename)
                ss_hash_compare = ssdeep.compare(md5, sha1)

            except:
                ss_hash = 'NULL'
                ss_hash_compare = 0

            # Start logic here for data insertion for is_infected
            # x = Call('/a', 'a')
            # x.check_hash()

            cursor.execute(
                """INSERT INTO
                    tbl_files (
                        file_name,
                        md5_hash,
                        sha1_hash,
                        sha256_hash,
                        ssdeep_hash,
                        ssdeep_compare,
                        is_infected)
                VALUES (%s,%s,%s,%s,%s,%s,%s)""", (filename, md5, sha1, sha256,
                    ss_hash, str(ss_hash_compare), False)
                )
            conn.commit()
            # Redirect to different path for uniq hash sql data
            return redirect(url_for('upload',
                                    filename=filename, uploaded="successful"))

    conn.close()
    return render_template('upload.html', data=data)


if __name__ == '__main__':
    app.secret_key = var['SECRET_KEY']
    app.config['SESSION_TYPE'] = 'filesystem'

    app.debug = True
    app.run()
