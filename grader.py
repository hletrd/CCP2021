from flask import Flask, render_template, send_from_directory, redirect, abort, request, jsonify, session, __version__, Response, make_response
import logging

import os
import zipfile

import sqlite3

import json

import threading
import subprocess
import re
import time
import datetime
import sys
import random

import argon2 #argon2-cffi

app = Flask(__name__)

input_path = './input/'
run_path = './environ/'
temp_path = './temp/'

dbfile = 'ccp.db'

app.secret_key = b'\x06\xdcNB\x93\x9e-N\xf0*\x82\xad\x80\x1e\x95\x0e'
logger = logging.getLogger('werkzeug')
handler = logging.FileHandler('access.log')
logger.addHandler(handler)
app.testing = True

@app.route('/auth', methods=['POST'])
def auth():
	ph = argon2.PasswordHasher()
	password = getconfig('password')
	if password == None:
		password = ph.hash('ccp2021')
	try:
		ph.verify(password, request.form['password'])
		session['auth'] = True
		return redirect('/')
	except:
		pass
	abort(403)

def get_all_list():
	conn = sqlite3.connect(dbfile)
	c = conn.cursor()
	try:
		c.execute('SELECT * FROM `metadata` WHERE `type`="project";')
		metadata = c.fetchone()
		project = json.loads(metadata[2])
	except:
		project = []
	if 'auth' not in session:
		project = list(filter(lambda x: x['public'], project))
	project = list(map(lambda x: x['name'], project))
	try:
		c.execute('SELECT * FROM `metadata` WHERE `type`="hw";')
		metadata = c.fetchone()
		hw = json.loads(metadata[2])
	except:
		hw = []
	if 'auth' not in session:
		hw = list(filter(lambda x: x['public'], hw))
	hw = list(map(lambda x: x['name'], hw))

	return hw + project

def get_all_list_dict():
	conn = sqlite3.connect(dbfile)
	c = conn.cursor()
	try:
		c.execute('SELECT * FROM `metadata` WHERE `type`="project";')
		metadata = c.fetchone()
		project = json.loads(metadata[2])
	except:
		project = []
	if 'auth' not in session:
		project = filter(lambda x: x['public'], project)
	try:
		c.execute('SELECT * FROM `metadata` WHERE `type`="hw";')
		metadata = c.fetchone()
		hw = json.loads(metadata[2])
	except:
		hw = []
	if 'auth' not in session:
		hw = filter(lambda x: x['public'], hw)
	result = dict([(i['name'], i) for i in project]+[(i['name'], i) for i in hw])
	return result

def prepare_data():
	init_db()
	conn = sqlite3.connect(dbfile)
	c = conn.cursor()
	try:
		c.execute('SELECT * FROM `metadata` WHERE `type`="project";')
		metadata = c.fetchone()
		project = json.loads(metadata[2])
	except:
		project = []
	try:
		c.execute('SELECT * FROM `metadata` WHERE `type`="hw";')
		metadata = c.fetchone()
		hw = json.loads(metadata[2])
	except:
		hw = []

	password = getconfig('password')
	pw_notset = password == None
	
	return {'project': project, 'hw': hw, 'version': sys.version_info, 'fversion': __version__, 'auth': 'auth' in session, 'rand': random.random(), 'pw_notset': pw_notset}

def student_init():
	return {
		'log_zip': '',
		'log_zip_detail': [],
		'score': -1,
		'code': '',
		'val': {
			'score': 0
		}
	}

@app.route('/')
def index():
	return render_template('index.html', data={'data': prepare_data()})

@app.route('/details')
def detail():
	deduce_decimal = getconfig('deduce_decimal', 0.1)
	hash_prime = getconfig('hash_prime', 997)
	hashed = 202212345 % hash_prime
	return render_template('details.html', data={'data': prepare_data(), 'deduce_decimal': deduce_decimal*100, 'hash_prime': hash_prime, 'hashed': hashed})

def getconfig(typetext, default=None):
	conn = sqlite3.connect(dbfile)
	c = conn.cursor()
	c.execute('SELECT * FROM `metadata` WHERE `type`=?;', (typetext,))
	result = c.fetchone()
	if result == None:
		return default
	else:
		return json.loads(result[2])

def setconfig(typetext, value):
	conn = sqlite3.connect(dbfile)
	c = conn.cursor()
	c.execute('SELECT * FROM `metadata` WHERE `type`=?;', (typetext,))
	result = c.fetchone()
	value = json.dumps(value)
	if result == None:
		c.execute('INSERT INTO `metadata`(`type`, `value`) VALUES (?,?);', (typetext, value))
	else:
		c.execute('UPDATE `metadata` SET `value`=? WHERE `type`=?;', (value, typetext))
	conn.commit()

@app.route('/settings', methods=['GET', 'POST'])
def settings():
	if not 'auth' in session:
		abort(404)
	if request.method == 'POST':
		setconfig('max_error', float(request.form.get('max_error', 0)))
		setconfig('deduce_decimal', float(request.form.get('deduce_decimal', 0))/100)
		setconfig('deduce_wrong', float(request.form.get('deduce_wrong', 0))/100)
		setconfig('deduce_tle', float(request.form.get('deduce_tle', 0))/100)
		setconfig('deduce_runtime', float(request.form.get('deduce_runtime', 0))/100)
		
		setconfig('time_limit', float(request.form.get('time_limit', 0)))
		setconfig('script', request.form.get('script'))
		setconfig('run_filename', request.form.get('run_filename'))
		
	data = prepare_data()
	deduce_decimal = getconfig('deduce_decimal', 0.1)
	deduce_wrong = getconfig('deduce_wrong', 1.0)
	deduce_tle = getconfig('deduce_tle', 1.0)
	deduce_runtime = getconfig('deduce_runtime', 1.0)

	admin_public_id = getconfig('admin_public_id', True)
	admin_public_name = getconfig('admin_public_name', True)

	script = getconfig('script', 'python3')
	run_filename = getconfig('run_filename', 'main.py')

	hash_prime = getconfig('hash_prime', 997)
	
	deduce_decimal *= 100 #to percentage
	deduce_wrong *= 100 #to percentage
	deduce_tle *= 100 #to percentage
	deduce_runtime *= 100 #to percentage

	max_error = getconfig('max_error', 0.001)
	time_limit = getconfig('time_limit', 1.0)

	data_form = {'data': data, 'deduce_decimal': deduce_decimal, 'deduce_wrong': deduce_wrong, 'deduce_tle': deduce_tle, 'deduce_runtime': deduce_runtime, 'max_error': max_error, 'time_limit': time_limit, 'admin_public_id': admin_public_id, 'admin_public_name': admin_public_name, 'script': script, 'run_filename': run_filename, 'hash_prime': hash_prime}
	return render_template('settings.html', data=data_form)

@app.route('/settings/admin', methods=['POST'])
def settings_admin():
	if not 'auth' in session:
		abort(404)
	if request.form.get('check-public-id') != None:
		setconfig('admin_public_id', True)
	else:
		setconfig('admin_public_id', False)
	if request.form.get('check-public-name') != None:
		setconfig('admin_public_name', True)
	else:
		setconfig('admin_public_name', False)
	setconfig('hash_prime', int(request.form.get('hash_prime')))
	return redirect('/settings')

@app.route('/settings/password', methods=['POST'])
def settings_password():
	if not 'auth' in session:
		abort(404)
	if request.form.get('password') != None and request.form.get('password') != '' and request.form.get('password') == request.form.get('password-re'):
		ph = argon2.PasswordHasher()
		password = ph.hash(request.form.get('password'))
		setconfig('password', password)
		return redirect('/settings')
	abort(418)

@app.route('/logout')
def logout():
	if 'auth' in session:
		del session['auth']
	return redirect('/')

@app.route('/project/<string:project_name>')
def project(project_name):
	if project_name in get_all_list():
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		try:
			c.execute('CREATE TABLE `{}`(`id` INTEGER PRIMARY KEY AUTOINCREMENT, `student_id` TEXT, `student_name` TEXT, `result` INTEGER, `data` TEXT);'.format(project_name))
		except:
			pass
		try:
			c.execute('CREATE TABLE `{}_val`(`id` INTEGER PRIMARY KEY, `INPUT` TEXT, `OUTPUT` TEXT, `data` TEXT);'.format(project_name))
		except:
			pass
		conn.commit()
		c.execute('SELECT * FROM `{}`;'.format(project_name))
		projects = c.fetchall()
		projects = list(map(lambda x: list(x), projects))
		score_sum = 0
		project_count = 1e-8
		score_var = 0
		for i in projects:
			i[4] = json.loads(i[4])
			if 'val' in i[4]:
				score_sum += i[4]['val']['score']
				project_count += 1
		score_avg = score_sum / project_count
		for i in projects:
			if 'val' in i[4]:
				score_var += (i[4]['val']['score']-score_avg)**2
		score_var = score_var / project_count
		score_std = score_var**0.5
		c.execute('SELECT * FROM `{}_val`;'.format(project_name))
		val_set = c.fetchall()
		score_max = 0
		for i in val_set:
			i_decoded = json.loads(i[3])
			score_max += i_decoded['score']
		sample_path = os.path.join(input_path, project_name, 'reference.py')
		sample = ''
		if os.path.exists(sample_path):
			with open(sample_path, 'r') as f:
				sample = f.read()
		admin_public_id = getconfig('admin_public_id')
		admin_public_name = getconfig('admin_public_name')

		if not 'auth' in session:
			pjhw = get_all_list_dict()
			#numbers = list(map(lambda x: x[1][-3:], projects))
			hash_prime = int(getconfig('hash_prime', 997))
			numbers = list(map(lambda x: student_hash(x[1], hash_prime), projects))
			if not 'data_public' in pjhw[project_name]:
				pjhw[project_name]['data_public'] = False
			for i in projects:
				if numbers.count(student_hash(i[1], hash_prime)) > 1:
					i[2] = i[2][0]+'**'
				else:
					i[2] = '***'
				i[1] = student_hash(i[1], hash_prime)
			return render_template('project_public.html', data={'data': prepare_data(), 'project_name': project_name, 'projects': projects, 'score_avg': score_avg, 'score_max': score_max, 'score_std': score_std, 'sample': sample, 'data_public': pjhw[project_name]['data_public']})
		return render_template('project.html', data={'data': prepare_data(), 'project_name': project_name, 'projects': projects, 'score_avg': score_avg, 'score_max': score_max, 'score_std': score_std, 'sample': sample, 'admin_public_id': admin_public_id, 'admin_public_name': admin_public_name})
	else:
		abort(404)

def student_hash(student_id, hash_prime=997):
	student_id_year = str(student_id[0:4])
	student_id_num = str(student_id[5:10])
	return str(int(student_id_year + student_id_num)%hash_prime)

@app.route('/project/add_student/<string:project_name>', methods=['POST'])
def add_student(project_name):
	if project_name in get_all_list():
		if not 'auth' in session:
			abort(404)
		if 'student-id' not in request.form or 'student-name' not in request.form:
			abort(406)
		student_id = request.form.get('student-id')
		student_name = request.form.get('student-name')
		data = student_init()
		data['log_zip'] = 'Unzip succeed'
		data['log_zip_detail'] = ['main.py']
		result = '1' #(unzip result)
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		c.execute('INSERT INTO `{}`(`student_id`, `student_name`, `result`, `data`) VALUES (?,?,?,?)'.format(project_name), (student_id, student_name, result, json.dumps(data)))
		conn.commit()
		return redirect('/project/{}'.format(project_name))
	else:
		abort(404)

@app.route('/project/remove_student/<string:project_name>/<int:student_id>', methods=['POST'])
def remove_student(project_name, student_id):
	if project_name in get_all_list():
		if not 'auth' in session:
			abort(404)
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		c.execute('DELETE FROM `{}` WHERE `id`=?;'.format(project_name), (student_id,))
		conn.commit()
		return 'ok'
	else:
		abort(404)

@app.route('/project/download/<string:project_name>')
def project_download(project_name):
	if project_name in get_all_list():
		if not 'auth' in session:
			abort(401)
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		c.execute('SELECT * FROM `{}`;'.format(project_name))
		projects = c.fetchall()
		projects = list(map(lambda x: list(x), projects))
		score_sum = 0
		project_count = 1e-8
		if request.args['type'] == '0':
			result = '#,student_id,hashed_id,student_name,score(total),'
		else:
			result = '#,hashed_id,student_name,score(total),'

		c.execute('SELECT * FROM `{}_val`;'.format(project_name))
		val_set = c.fetchall()
		score_max = 0

		for k, i in enumerate(val_set):
			i_decoded = json.loads(i[3])
			score_max += i_decoded['score']
			if request.args['type'] == '0':
				result += 'case #{},'.format(k)

		
		result += '\n'
		if request.args['type'] == '0':
			result += '(Max score),,,,{},'.format(score_max)
		else:
			result += '(Max score),,,{},'.format(score_max)

		if request.args['type'] == '0':
			for k, i in enumerate(val_set):
				i_decoded = json.loads(i[3])
				result += '{},'.format(i_decoded['score'])
		result += '\n'

		hash_prime = getconfig('hash_prime', 997)

		for i in projects:
			i[4] = json.loads(i[4])
			if 'val' in i[4]:
				score_sum += i[4]['val']['score']
				project_count += 1
				if request.args['type'] == '0':
					result += '{},{},{},{},'.format(i[0], i[1], student_hash(i[1], hash_prime), i[2])
				else:
					result += '{},{},{},'.format(i[0], student_hash(i[1], hash_prime), '***')
				result += '{},'.format(i[4]['val']['score'])
				if request.args['type'] == '0':
					for j in i[4]['val']['details']:
						result += '{},'.format(j['score'])
				result += '\n'
		score_avg = score_sum / project_count
		
		resp = make_response(result)
		resp.headers['Content-Type'] = 'text/csv;charset=UTF-8'
		resp.headers['Content-Disposition'] = 'attachment;filename={}.csv'.format(project_name)
		return resp
	else:
		abort(404)

@app.route('/project/download-code/<string:project_name>')
def project_download_code(project_name):
	if project_name in get_all_list():
		if not 'auth' in session:
			abort(401)
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		c.execute('SELECT * FROM `{}`;'.format(project_name))
		projects = c.fetchall()
		projects = list(map(lambda x: list(x), projects))

		if not os.path.exists(temp_path):
			os.mkdir(temp_path)
		for i in os.listdir(temp_path):
			os.remove(os.path.join(temp_path, i))
		zipped = zipfile.ZipFile(os.path.join(temp_path, 'temp.zip'), 'w')
		for i in projects:
			i[4] = json.loads(i[4])
			if 'val' in i[4]:
				code = i[4]['code']
				#path_code = os.path.join(temp_path, i[1]+'_'+i[2]+'.py')
				#with open(path_code, 'w') as f:
				#	f.write(code)
				#zipped.write(path_code, i[1]+'_'+i[2]+'.py')
				zipped.writestr(i[1]+'_'+i[2]+'.py', code)
				#os.remove(path_code)
		zipped.close()
		
		with open(os.path.join(temp_path, 'temp.zip'), 'rb') as f:
			result = f.read()

		resp = make_response(result)
		resp.headers['Content-Type'] = 'application/zip;charset=UTF-8'
		resp.headers['Content-Disposition'] = 'attachment;filename={}.zip'.format(project_name)
		return resp
	else:
		abort(404)

@app.route('/project/upload/<string:project_name>')
def project_upload(project_name):
	if not 'auth' in session:
		abort(404)
	if project_name in get_all_list():
		return render_template('upload.html', data={'data': prepare_data(), 'project_name': project_name})

@app.route('/project/load/<string:project_name>', methods=['POST'])
def project_load(project_name):
	if not 'auth' in session:
		abort(404)
	if project_name in get_all_list():
		if 'file' not in request.files:
			abort(406)
		file = request.files['file']
		path = os.path.join(input_path, project_name)
		if not os.path.exists(path):
			os.mkdir(path)
		file.save(os.path.join(path, 'uploaded.zip'))
		with zipfile.ZipFile(os.path.join(path, 'uploaded.zip'), 'r') as zipf:
			content = zipf.namelist()
			for i in content:
				if i.split('.')[-1].lower() == 'zip' or  i.split('.')[-1].lower() == 'py':
					zipf.extract(i, path)

		subs = os.listdir(path)
		processed = {}
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		try:
			c.execute('DROP TABLE `{}`'.format(project_name))
			conn.commit()
			c.execute('CREATE TABLE `{}`(`id` INTEGER PRIMARY KEY AUTOINCREMENT, `student_id` TEXT, `student_name` TEXT, `result` INTEGER, `data` TEXT);'.format(project_name))
		except:
			pass
		conn.commit()
		
		for file in subs:
			if file.split('.')[-1].lower() != 'zip': #new etl: not .zip
				if len(file) >= 3 and file[-3:].lower() == '.py':
					student_name = file.split('_')[0][:-5]
					file_id = file.split('_')[0][-5:] + '_' + file.split('_')[1]
					result = -1
					data = student_init()
					with open(os.path.join(path, file), 'r') as f:
						code = f.read()
					result = 0
					target_path = os.path.join(path, student_name + '_' + file_id)
					#with open(os.path.join(file), 'w') as f:
					#	f.write(code)
					result = 1
					data['log_zip'] = 'file loaded'
					data['log_zip_detail'] = [file]
					log_zip_detail_decoded = []
					for j in data['log_zip_detail']:
						try:
							j = j.encode('437')
						except UnicodeEncodeError:
							j = j.encode('utf8')
						try:
							j = j.decode('utf8')
						except:
							j = j.decode('949')
						log_zip_detail_decoded.append(j)
					data['log_zip_detail'] = log_zip_detail_decoded
					data['code'] = code
					c.execute('INSERT INTO `{}`(`student_id`, `student_name`, `result`, `data`) VALUES (?,?,?,?)'.format(project_name), ('2020-00000', student_name, result, json.dumps(data)))
					conn.commit()
					continue
			if file == 'uploaded.zip': continue #ignore uploaded zip file
			student_name = file.split('_')[0]
			student_id = file.split('_')[1]
			result = -1
			data = student_init()
			try:
				with zipfile.ZipFile(os.path.join(path, file), 'r') as zipf: #old etl: zip
					content = zipf.namelist()
					code = ''
					result = 0
					target_path = os.path.join(path, student_name + '_' + student_id)
					for i in content:
						filename = i.split('/')[-1]
						if len(filename) > 0 and filename[0] == '.':
							#hidden file
							pass
						elif len(i) >= 7 and i[-7:] == 'main.py' and result == 0:
							result = 1
							try:
								os.mkdir(target_path)
							except FileExistsError:
								pass
							data['log_zip_detail'] = [i]
							zipf.extract(i, os.path.join(target_path))
							try:
								with open(os.path.join(target_path, i), 'r') as f:
									code = f.read()
							except UnicodeDecodeError:
								with open(os.path.join(target_path, i), 'r', encoding='ISO-8859-1') as f:
									code = f.read()
							data['log_zip'] = 'Unzip succeed'
						elif result == 1 and i[-7:] == 'main.py':
							result = 2
							data['log_zip'] = '>1 main.py files'
							data['log_zip_detail'].append(i)
					if result == 0: #when no main.py is found
						for j in content:
							if len(j) >= 3 and j[-3:].lower() == '.py':
								filename = j.split('/')[-1]
								if len(filename) > 0 and filename[0] == '.':
									#hidden file
									pass
								else:
									data['log_zip'] = 'no main.py'
									data['log_zip_detail'].append(j)
									zipf.extract(j, os.path.join(target_path))
									try:
										with open(os.path.join(target_path, j), 'r') as f:
											code = f.read()
									except UnicodeDecodeError:
										with open(os.path.join(target_path, j), 'r', encoding='ISO-8859-1') as f:
											code = f.read()
									result = 3
					if result == 0:
						data['log_zip'] = 'no .py found'
						data['log_zip_detail'] = content
			except zipfile.BadZipfile:
				data['log_zip'] = 'Bad zip file'
			log_zip_detail_decoded = []
			for j in data['log_zip_detail']:
				try:
					j = j.encode('437')
				except UnicodeEncodeError:
					j = j.encode('utf8')
				try:
					j = j.decode('utf8')
				except:
					j = j.decode('949')
				log_zip_detail_decoded.append(j)
			data['log_zip_detail'] = log_zip_detail_decoded
			data['code'] = code
			c.execute('INSERT INTO `{}`(`student_id`, `student_name`, `result`, `data`) VALUES (?,?,?,?)'.format(project_name), (student_id, student_name, result, json.dumps(data)))
			conn.commit()
		return redirect('/project/' + project_name)
	else:
		abort(404)

@app.route('/project/data/<string:project_name>')
def project_data(project_name):
	if project_name in get_all_list():
		if not 'auth' in session:
			pjhw = get_all_list_dict()
			if pjhw[project_name]['data_public'] == False:
				abort(404)
			conn = sqlite3.connect(dbfile)
			c = conn.cursor()
			c.execute('SELECT * FROM `{}_val`;'.format(project_name))
			val_set = c.fetchall()
			val_set = list(map(lambda x: list(x), val_set))
			for i in val_set:
				i.append(i[1].count('\n')+1)
				i.append(i[2].count('\n')+1)
				i[3] = json.loads(i[3])
				i[2] = i[2].replace('\n', '\\n')
				i[1] = i[1].replace('\n', '\\n')
			return render_template('validation_public.html', data={'data': prepare_data(), 'val_set': val_set, 'project_name': project_name})
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		c.execute('SELECT * FROM `{}_val`;'.format(project_name))
		val_set = c.fetchall()
		val_set = list(map(lambda x: list(x), val_set))
		for i in val_set:
			i[3] = json.loads(i[3])
			i[2] = i[2].replace('\n', '\\n')
			i[1] = i[1].replace('\n', '\\n')
			if 'val_mode' not in i[3]:
				i[3]['val_mode'] = {
					'check_num': True,
					'check_char': True
				}
		metadata = getconfig('metadata_{}'.format(project_name), {})
		if 'is_val_custom' not in metadata:
			metadata['is_val_custom'] = False
		if 'code_val_custom' not in metadata:
			metadata['code_val_custom'] = ''
		return render_template('validation.html', data={'data': prepare_data(), 'val_set': val_set, 'project_name': project_name, 'is_val_custom': metadata['is_val_custom'], 'code_val_custom': metadata['code_val_custom']})
	else:
		abort(404)

@app.route('/project/validation/<string:project_name>', methods=['POST'])
def validation_save(project_name):
	if project_name in get_all_list():
		if not 'auth' in session:
			abort(403)
		else:
			metadata = getconfig('metadata_{}'.format(project_name), {})
			if request.form.get('check-custom') == 'on':
				metadata['is_val_custom'] = True
				metadata['code_val_custom'] = request.form.get('code')
			else:
				metadata['is_val_custom'] = False
			setconfig('metadata_{}'.format(project_name), metadata)
				
			return redirect('/project/data/{}'.format(project_name))
	else:
		abort(404)

def init_db():
	conn = sqlite3.connect(dbfile)
	c = conn.cursor()
	try:
		c.execute('CREATE TABLE `metadata`(`id` INTEGER PRIMARY KEY AUTOINCREMENT, `type` TEXT, `value` TEXT);')
		conn.commit()
		setconfig('deduce_decimal', 0.1)
		setconfig('deduce_wrong', 1.0)
		setconfig('deduce_tle', 1.0)
		setconfig('deduce_runtime', 1.0)

		setconfig('admin_public_id', True)
		setconfig('admin_public_name', True)

		setconfig('script', 'python3')
		setconfig('run_filename', 'main.py')

		setconfig('max_error', 0.001)
		setconfig('time_limit', 1.0)
	except:
		pass

@app.route('/manage')
def manage():
	if not 'auth' in session:
		abort(404)
	init_db()
	project = getconfig('project', [])
	hw = getconfig('hw', [])
	return render_template('manage.html', data={'data': prepare_data(), 'project': project, 'hw': hw})

@app.route('/manage/save/<string:reqtype>', methods=['POST'])
def manage_save(reqtype):
	if not 'auth' in session:
		abort(404)
	data = []
	for k, i in request.json.items():
		data.append({'id': i['id'], 'name': i['name'], 'public': i['public'], 'data_public': i['data_public']})

	reqtype_table = {
		'0': 'hw',
		'1': 'project'
	}

	setconfig(reqtype_table[reqtype], data)
	
	return 'ok'

@app.route('/project/save/<string:project_name>/<int:index>', methods=['POST'])
def project_code_save(project_name, index):
	if not 'auth' in session:
		abort(401)
	if project_name in get_all_list():
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		c.execute('SELECT * FROM `{}` WHERE `id`=?;'.format(project_name), (index,))
		result = c.fetchone()
		result = json.loads(result[4])
		try:
			result['code'] = request.form.get('code')
			result = json.dumps(result)
			c.execute('UPDATE `{}` SET `data`=? WHERE `id`=?;'.format(project_name), (result, index,))
			conn.commit()
			return 'ok'
		except:
			return 'error'

@app.route('/project/data/save/<string:project_name>', methods=['POST'])
def project_data_save(project_name):
	if not 'auth' in session:
		abort(401)
	if project_name in get_all_list():
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		c.execute('DELETE FROM `{}_val`;'.format(project_name))
		data = request.json
		for k, v in data.items():
			try:
				score = float(v['score'])
			except:
				score = 0
			metadata = json.dumps({
				'score': score,
				'val_mode': {
					'check_num': v['val_mode']['check_num'],
					'check_char': v['val_mode']['check_char'],
				}
				})
			v['output'] = v['output'].replace('\\n', '\n')
			v['input'] = v['input'].replace('\\n', '\n')
			
			c.execute('INSERT INTO `{}_val`(`id`, `INPUT`, `OUTPUT`, `data`) VALUES (?,?,?,?);'.format(project_name), (v['id'], v['input'], v['output'], metadata))
			conn.commit()
		return 'ok'
	else:
		abort(404)

@app.route('/project/view/<string:project_name>/<int:id>')
def view_code(project_name, id):
	if not 'auth' in session:
		abort(404)
	if project_name in get_all_list():
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		try:
			c.execute('SELECT * FROM `{}` WHERE `id`=?;'.format(project_name), (id,))
		except:
			pass
		result = c.fetchone()
		code = json.loads(result[4])['code']
		return Response(code, mimetype='text/plain')

@app.route('/project/result/<string:project_name>/<int:id>')
def view_result(project_name, id):
	if project_name in get_all_list():
		if not 'auth' in session:
			conn = sqlite3.connect(dbfile)
			c = conn.cursor()
			try:
				c.execute('SELECT * FROM `{}` WHERE `id`=?;'.format(project_name), (id,))
			except:
				pass
			result = c.fetchone()
			result = json.loads(result[4])['val']
			hash_prime = getconfig('hash_prime', 997)
			result['student_id'] = student_hash(result['student_id'], hash_prime)
			result['student_name'] = '***'
			
			return jsonify(result)
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		try:
			c.execute('SELECT * FROM `{}` WHERE `id`=?;'.format(project_name), (id,))
		except:
			pass
		result = c.fetchone()
		result = json.loads(result[4])['val']
		hash_prime = getconfig('hash_prime', 997)
		if getconfig('admin_public_id', True) == False:
			result['student_id'] = student_hash(result['student_id'], hash_prime)
		if getconfig('admin_public_name', True) == False:
			result['student_name'] = '***'
		return jsonify(result)

@app.route('/project/run/<string:project_name>', methods=['POST'])
def run_code(project_name):
	if not 'auth' in session:
		abort(404)
	if project_name in get_all_list():
		conn = sqlite3.connect(dbfile)
		c = conn.cursor()
		
		code_id = request.form.get('id')

		student_name = 'sample'
		student_id = '2021-00000'

		if code_id == '-1':
			data_student = {}
			code = request.form.get('code')
		else:
			c.execute('SELECT * FROM `{}` WHERE `id`=?;'.format(project_name), (code_id,))

			result = c.fetchone()
			if result == None:
				return jsonify({'result': False, 'msg': 'student not found'})
			data_student = json.loads(result[4])
			student_name = result[2]
			student_id = result[1]
			code = data_student['code']
		data_student['val'] = {
			'score': 0,
			'details': [],
			'score_total': 0,
			'student_name': student_name,
			'student_id': student_id
		}
		if not os.path.exists(run_path):
			os.mkdir(run_path)
		with open(os.path.join(run_path, getconfig('run_filename', 'main.py')), 'w') as f:
			f.write(code)
		time.sleep(1)
		
		c.execute('SELECT * FROM `{}_val`;'.format(project_name))
		val_set = c.fetchall()
		val_set = list(map(lambda x: list(x), val_set))

		metadata = getconfig('metadata_{}'.format(project_name), {})
		is_val_custom = False
		if 'is_val_custom' in metadata and metadata['is_val_custom']:
			code_validator = metadata['code_val_custom']
			with open(os.path.join(run_path, 'validator_custom.py'), 'w') as f:
				f.write(code_validator)
			is_val_custom = True

		deduce_decimal = getconfig('deduce_decimal')
		deduce_wrong = getconfig('deduce_wrong')
		deduce_tle = getconfig('deduce_tle')
		deduce_runtime = getconfig('deduce_runtime')
		
		max_error = getconfig('max_error')
		time_limit = getconfig('time_limit')

		for i in val_set:
			i[3] = json.loads(i[3])

			result = validator(i[1], i[2], check_num=i[3]['val_mode']['check_num'], check_char=i[3]['val_mode']['check_char'], max_error=max_error, time_limit=time_limit, is_val_custom=is_val_custom, do_validation=(code_id != '-1'))
			if is_val_custom: #custom score for custom validator
				data_student['val']['score'] += result['score']
				data_student['val']['score_total'] += i[3]['score']
			else:
				if result['correct'] == 1:
					data_student['val']['score'] += i[3]['score']
					result['score'] = round(i[3]['score'], 3)
				elif result['correct'] == 0:
					data_student['val']['score'] += i[3]['score']*(1-deduce_wrong)
					result['score'] = round(i[3]['score']*(1-deduce_wrong), 3)
				elif result['correct'] == 3:
					data_student['val']['score'] += i[3]['score']*(1-deduce_tle)
					result['score'] = round(i[3]['score']*(1-deduce_tle), 3)
				elif result['correct'] == 4:
					data_student['val']['score'] += i[3]['score']*(1-deduce_runtime)
					result['score'] = round(i[3]['score']*(1-deduce_runtime), 3)
				elif result['correct'] == 5:
					data_student['val']['score'] += i[3]['score']*(1-deduce_decimal)
					result['score'] = round(i[3]['score']*(1-deduce_decimal), 3)
				
				data_student['val']['score_total'] += i[3]['score']
			data_student['val']['details'].append(result)
			time.sleep(0.05)

		data_student['val']['score_total'] = round(data_student['val']['score_total'], 3)
		data_student['val']['score'] = round(data_student['val']['score'], 3)

		data_student['val']['last'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

		data_json = json.dumps(data_student)
		try:
			os.remove(os.path.join(run_path, getconfig('run_filename', 'main.py')))
		except:
			pass

		if code_id != '-1':
			c.execute('UPDATE `{}` SET `result`=?, `data`=? WHERE `id`=?;'.format(project_name), (4, data_json, code_id,))
			conn.commit()
		if getconfig('admin_public_id', True) == False:
			data_student['val']['student_id'] = '****-**' + data_student['val']['student_id'][-3:]
		if getconfig('admin_public_name', True) == False:
			data_student['val']['student_name'] = '***'
		return jsonify(data_student['val'])
	abort(404)

class PKiller(threading.Thread):
	def __init__(self, timeout, process):
		threading.Thread.__init__(self)
		self.timeout = timeout
		self.process = process
		self.disabled = False
	
	def run(self):
		time.sleep(self.timeout)
		if self.disabled == False:
			print('kill')
			try:
				self.process.terminate()
				self.process.kill()
			except Exception as e:
				print('not killed')
				pass


def execute(input_val='', time_limit=1):
	p = subprocess.Popen([getconfig('script', 'python3'), getconfig('run_filename', 'main.py')], cwd=run_path, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
	input_lines = input_val.split('\n')

	for i in input_lines:
		p.stdin.write((i+'\n').encode())
		p.stdin.flush()

	correct = -1 #initial value
	
	#launch destruction logic
	pk = PKiller(time_limit+0.5, p)
	pk.start()

	try:
		outs, errs = p.communicate(timeout=time_limit)
		pk.disabled = True
	except subprocess.TimeoutExpired: #time limit exceed
		p.terminate()
		p.kill()
		#outs, errs = p.communicate()'
		outs, errs = b'', b''
		correct = 3 #TLE

	outs = outs.decode()
	if errs != None:
		errs = errs.decode()
	else:
		errs = ''
	cwdpath = os.path.abspath(os.path.join(os.getcwd(), run_path))
	errs = errs.replace(cwdpath, '.')

	return outs, errs, p.returncode, correct

def validator_number(output, answer, max_error):
	#remove except numbers
	out = re.sub(r'[^0-9.\-]', r' ', output)
	ref = re.sub(r'[^0-9.\-]', r' ', answer)
	#remove punctuations without number
	while True:
		out, cnt_sub_out = re.subn(r'([^0-9])[.\-]([^0-9])', r'\1 \2', out)
		ref, cnt_sub_ref = re.subn(r'([^0-9])[.\-]([^0-9])', r'\1 \2', ref)
		if cnt_sub_out == 0 and cnt_sub_ref == 0: break
	out = out.strip('.')
	ref = ref.strip('.')
	#remove excessive whitespaces
	out = re.sub(r'\s+', ' ', out).strip()
	ref = re.sub(r'\s+', ' ', ref).strip()

	out = out.split()
	ref = ref.split()
	
	if len(out) != len(ref): #different number of output: wrong!
		correct = 0
	else:
		state = 1 
		for k, i in enumerate(out):
			j = ref[k]
			if i != j: #first, compare as string
				state = 0
				break
		if state == 1: #if all values are exactly the same
			correct = 1 #correct
		else:
			state = 1
			for k, i in enumerate(out):
				j = ref[k]
				i_d = re.sub(r'\.0+', '', i)
				j_d = re.sub(r'\.0+', '', j)
				
				if i_d != j_d: #compare as float
					state = 0
					break
			if state == 1:
				correct = 5 #wrong decimal format (1.0 / 1.000 / 1 type)
			else:
				state = 1
				for k, i in enumerate(out):
					j = ref[k]
					if '.' in i: #if float format
						try:
							i_f = float(i)
						except:
							i_f = -1e+20
					else: #if int format
						i_f = int(i)
					if '.' in j:
						try:
							j_f = float(j)
						except:
							j_f = 1e+20
					else: #if int format
						j_f = int(j)
					if abs(i_f - j_f) > max_error: #compare as float
						state = 0
						break
					i_d = re.sub(r'\.[0-9]+', '', i)
					j_d = re.sub(r'\.[0-9]+', '', j)
					if i_d != j_d: #seems the same as float, but not at int (does not considered floating point error)
						state = 0
						break
				if state == 1:
					correct = 5 #wrong decimal format (1.0001 / 1.000 type)
				else:
					correct = 0 #wrong answer
	return correct

def validator_real(output, answer, check_num, check_char, max_error):
	if check_num == False and check_char == False:
		correct = 1 #correct
	elif check_num == True and check_char == False:
		correct = validator_number(output, answer, max_error)
	elif check_num == False and check_char == True:
		#remove all numbers
		out = re.sub(r'-?[0-9.]', r' ', output)
		ref = re.sub(r'-?[0-9.]', r' ', answer)
		#remove excessive whitespaces
		out = re.sub(r'\s+', ' ', out).strip().lower()
		ref = re.sub(r'\s+', ' ', ref).strip().lower()

		if out == ref:
			correct = 1
		else:
			correct = 0

	elif check_num == True and check_char == True:
		#remove all numbers
		out = re.sub(r'-?[0-9.]', r' ', output)
		ref = re.sub(r'-?[0-9.]', r' ', answer)
		#remove excessive whitespaces
		out = re.sub(r'\s+', ' ', out).strip().lower()
		ref = re.sub(r'\s+', ' ', ref).strip().lower()

		if out == ref:
			correct_char = 1
		else:
			correct_char = 0

		correct_number = validator_number(output, answer, max_error)

		if correct_number == 1 and correct_char == 1:
			correct = 1
		elif correct_char == 1:
			correct = correct_number
		else:
			correct = 0

	return correct

def validator(input_val='', output_val='', check_num=True, check_char=True, max_error=0.001, time_limit=1, is_val_custom=False, do_validation=True):
	outs, errs, returncode, correct = execute(input_val, time_limit)
	score_full = 0
	score = 0
	details = ''

	if correct == -1: #not TLE

		if returncode != 0:
			correct = 4 #runtime error
		else:
			if do_validation == True:
				if is_val_custom == True:
					import importlib
					import environ.validator_custom
					importlib.reload(environ.validator_custom)
					correct, score, score_full, details = environ.validator_custom.validator(outs, output_val)
				else:
					correct = validator_real(outs, output_val, check_num, check_char, max_error)
			else:
				correct = 1

	result = {
		'result': returncode,
		'output': outs,
		'error': errs,
		'correct': correct,
		'answer': output_val,
		'input': input_val,
		'score': score,
		'score_full': score_full,
		'details': details,
	}
	return result

@app.route('/static/<path:path>')
def staticfile(path):
	return send_from_directory('static', path)

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)