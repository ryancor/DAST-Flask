import time
import requests
from flask import Flask, render_template, request
from services.injections import Injections

app = Flask(__name__)

@app.route('/')
def main():
	return render_template('index.html')
	
@app.route('/', methods=['GET','POST'])
def fuzz_post():
	end_point = request.form['text']
	request_case = request.form['options']
	data = {}
	
	for arr in Injections.sql_injections():
		try:
			time.sleep(1)

			if '[]' in end_point:
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
				
				data.setdefault("Results",[]).append([
					request_case, 
					new_ep, 
					str(r.status_code)
					]
				)

			else:
				return '\n[-] Not fuzzable.'
				break

		except Exception as error:
			return '\n[-] Could not make a successful request to that endpoint. {0}'.format(error)
  
	return render_template("results.html", results=data)

if __name__ == '__main__':
	app.run()