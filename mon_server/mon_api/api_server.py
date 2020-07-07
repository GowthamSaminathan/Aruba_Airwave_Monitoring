from flask import Flask, render_template, request , send_file
from flask import jsonify
from flask_cors import CORS


import os
import time
import json
from flask_pymongo import PyMongo
import pymongo
import logging
from logging.handlers import RotatingFileHandler
from logging.handlers import SysLogHandler

import requests
import urllib.parse

import datetime
import base64
import hashlib
import random
import cerberus
import binascii
import ast
import socket
from xml.etree import ElementTree as ET
import numpy


# Reading Environment variable
webr_mongodb = os.environ.get('WEBR_MONGODB')



logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.path.join(os.getcwd(),"api_server.log"), maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("\n ==> Starting API server ...\n")



app = Flask(__name__,static_url_path='/static')
CORS(app)
#app.config['MONGO_DBNAME'] = 'accounts'
#app.config['MONGO_URI'] = 'mongodb://127.0.0.1:27017/'

mongoc = PyMongo(app,uri='mongodb://'+webr_mongodb+':27017/mon')
mdb = mongoc.db
mcollection = mdb['mon']


@app.route('/portal')
def main():
	 return "API IS UP :"+str(datetime.datetime.utcnow())

@app.route('/portal/collect_api/air_post',methods = ['POST'])
def air_agent_post():
	try:
		if request.method == 'POST':

			# Reading file and form data
			doc = request.files['file']
			result = request.form
			
			agentname = result.get("agentname")
			airwave_ip = result.get("airwave_ip")
			agent_type = result.get("agent_type")

			dnow = datetime.datetime.utcnow()

			if agent_type == "air_amp":
				xml = doc.read()
				try:
					xml_dic = {}
					xml_data = ET.fromstring(xml)
					for xd in xml_data:
						xml_dic.update({xd.tag:xd.text})

					if bool(xml_dic) == True:
						xml_dic.update({"agent_date":dnow,"agentname":agentname,"agent_type":agent_type,"airwave_ip":airwave_ip})
						result = mcollection.insert(xml_dic)
						return jsonify({"results":"success","DB":str(result),"message":"DB response"})
					else:
						return jsonify({"results":"failed","message":"not inserted to DB"})

				except Exception as e:
					return jsonify({"results":"error","message":str(e)})

			return jsonify({"results":"success","message":str(agentname+" "+airwave_ip+" "+agent_type)})
		else:
			return jsonify({"results":"error","message":"Post method required"})
	except Exception as e:
		return jsonify({"results":"error","message":str(e)})

def validate_results(all_dbval):
	try:

		msg = dict()

		alerts = list()

		down = list()
		down_wired = list()
		down_wireless = list()

		up = list()
		up_wired = list()
		up_wireless = list()

		#return all_dbval
		
		for dbval in all_dbval:
			alerts.append(int(dbval.get("alerts")))

			down.append(int(dbval.get("down")))
			down_wired.append(int(dbval.get("down_wired")))
			down_wireless.append(int(dbval.get("down_wireless")))

			up.append(int(dbval.get("up")))
			up_wired.append(int(dbval.get("up_wired")))
			up_wireless.append(int(dbval.get("up_wireless")))

		if len(alerts) > 0:
			if numpy.amin(alerts) == numpy.amax(alerts):
				msg.update({"alerts":0})
			else:
				t = numpy.amax(alerts) - numpy.amin(alerts) 
				msg.update({"alerts":int(t)})

		if len(down) > 0:
			if numpy.amin(down) == numpy.amax(down):
				msg.update({"down":0})
			else:
				t = numpy.amax(down) - numpy.amin(down) 
				msg.update({"down":int(t)})

		if len(down_wired) > 0:
			if numpy.amin(down_wired) == numpy.amax(down_wired):
				msg.update({"wired down":0})
			else:
				t = numpy.amax(down_wired) - numpy.amin(down_wired) 
				msg.update({"wired down":int(t)})

		if len(down_wireless) > 0:
			if numpy.amin(down_wireless) == numpy.amax(down_wireless):
				msg.update({"wireless down":0})
			else:
				t = numpy.amax(down_wireless) - numpy.amin(down_wireless) 
				msg.update({"wireless down":int(t)})

		if len(up) > 0:
			if numpy.amin(up) == numpy.amax(up):
				msg.update({"up":0})
			else:
				t = numpy.amax(up) - numpy.amin(up) 
				msg.update({"up":int(t)})

		if len(up_wired) > 0:
			if numpy.amin(up_wired) == numpy.amax(up_wired):
				msg.update({"wired up":0})
			else:
				t = numpy.amax(up_wired) - numpy.amin(up_wired) 
				msg.update({"wired up":int(t)})

		if len(up_wireless) > 0:
			if numpy.amin(up_wireless) == numpy.amax(up_wireless):
				msg.update({"wireless up":0})
			else:
				t = numpy.amax(up_wireless) - numpy.amin(up_wireless) 
				msg.update({"wireless up":int(t)})

		return msg


	except Exception:
		logger.exception("validate_results")
		return "Error"

@app.route('/portal/collect_api/air_get',methods = ['GET'])
def air_agent_get():
	try:
		result = mcollection.distinct("agentname")
		all_results = []
		start_time = datetime.datetime.utcnow()
		time_between = 5 # Get report between 5 min
		end_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=time_between)
		
		# Get the range of minutes
		for x in range(5):
			# forward back to time
			if len(result) > 0:
				for agent in result:

					# Check air_amp
					query = {"agentname":agent,"agent_date":{'$lt': start_time, '$gte': end_time}}
					find_result = mcollection.find(query,{"_id":0})
					v_data = validate_results(list(find_result))
					#find_result = list(find_result)

					all_results.append({"agentname":agent,"visual":v_data,"type":"air_amp","history":x})
					#logger.info(all_results)

			start_time = start_time - datetime.timedelta(minutes=time_between)
			end_time = end_time - datetime.timedelta(minutes=time_between)


		return jsonify({"results":"success","data":all_results,"message":"Calculated DB response"})
	except Exception as e:
		return jsonify({"results":"error","message":str(e)})



# if __name__ == '__main__':
# 	app.run()
if __name__ == '__main__':
	app.run(host="0.0.0.0", port=int("88888"), debug=True)
