import time
import requests
from flaskext.mysql import MySQL
from flask import Flask, render_template, request
from services.injections import Injections

app = Flask(__name__)

mysql = MySQL()
# MySQL configurations
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'password'
app.config['MYSQL_DATABASE_DB'] = 'DastFuzz'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

conn = mysql.connect()
cursor = conn.cursor()

@app.route('/')
def main():
	return render_template('index.html')
	
@app.route('/past_runs')
def past_runs():
	query = """SELECT request_type, url, response_code 
		FROM tbl_fuzz
		ORDER BY id DESC"""
	cursor.execute(query)
	data = cursor.fetchall()
	conn.close()
	
	return render_template('runs.html', data=data)
	
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
				
				#cursor.callproc('/c/SQL/sp_createFuzz',(
				#	request_case,new_ep,str(r.status_code))
				#)
				
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

if __name__ == '__main__':
	app.run()