# Monitoring Agent for Aiwave

import os
import logging
from logging.handlers import RotatingFileHandler
import yaml # From pyyaml
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests_toolbelt import MultipartEncoder
import time
import re
import io


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.adapters.DEFAULT_RETRIES = 0

logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.path.join(os.getcwd(),"Aiwave_Agent.log"), maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = True

logger.info("\n =================== Starting Airwave Agent ======================== \n")


class Airwave_fetch():

	def __init__(self):
		self.config_file_name = "config.yaml"
		self.air_login = "https://{}/LOGIN"
		self.air_amp_status = "https://{}/amp_stats.xml"

	def read_yaml_config_file(self):
		# Read the YAML config file fro current directory
		config_file = open(self.config_file_name)
		self.config = yaml.load(config_file,Loader=yaml.Loader)

	def airwave_login(self):
		try:
			# Create login session with airwave
			self.air_session = None
			self.read_yaml_config_file()
			login_url = self.air_login.format(self.config.get("airwave_ip"))
			u_name = self.config.get("username")
			password = self.config.get("password")
			login_post = {"credential_0":u_name ,"credential_1": password,"destination":"/api"}
			
			self.air_session = requests.Session()
			res = self.air_session.post(login_url, data = login_post,verify=False)
			if res.status_code != 200:
				print("Login failed")
				logger.warning("Login failed")
			else:
				print("Login success")
				logger.info("Login success")
				return True
		except Exception:
			logger.exception("airwave_login")

	def collect_amp_status(self):
		try:
			logger.info("Collecting amp status... ")
			url = self.air_amp_status.format(self.config.get("airwave_ip"))
			res = self.air_session.get(url,verify=False)
			if res.status_code == 200:
				logger.info("Collecting amp status Success.....")
				return res.content
			elif res.status_code == 403 or  res.status_code == 401:
				logger.error("Airwave Status Code"+str(res.status_code))
				return "invalid_session"
			else:
				logger.error("Airwave unknown Status Code"+str(res.status_code))
				return "unknown"
		except Exception:
			logger.exception("collect_ap_status")

	def post_to_server(self,data,agent_type):
		try:
			xml_file = io.BytesIO(data)

			url = self.config.get("collector_url")
			#headers = {'Content-type': 'multipart/form-data'}
			
			files = {'file': ("file",xml_file)}

			files.update({"agentname":(None,self.config.get("agent_name"))})
			files.update({"airwave_ip":(None,self.config.get("airwave_ip"))})
			files.update({"agent_type":(None,agent_type)})
			
			res = requests.post(url, files=files)
			
			if res.status_code == 200:
				logger.info("Post accepted by server")
				print(res.content)
			else:
				logger.info("Post not accepted by server")
		except Exception:
			logger.exception("post_to_server")



	def main_execute(self):
		while True:
			try:
				login_status = self.airwave_login()
				if login_status == True:
					# If login success - Collect the amp status
					collect_amp_success = True
					while collect_amp_success == True:
						collect_amp_response = self.collect_amp_status()
						#print(type(collect_amp_response))
						#print(collect_amp_response)
						if collect_amp_response == None:
							# Unknown error
							logger.error("unknown issue , sleeping 30 sec")
							time.sleep(30)
						elif collect_amp_response == "invalid_session":
							collect_amp_success = False
							logger.error("Login session expire, sleeping 60sec")
							time.sleep(60)
						elif collect_amp_response == "unknown":
							collect_amp_success = False
							logger.error("unknown status code, sleeping 120 sec")
							time.sleep(120)
						else:
							self.post_to_server(collect_amp_response,"air_amp")
							logger.info("Sleeping (60 sec) for next collection ")
							time.sleep(60)
				else:
					# Login not success trying after 10 sec
					logger.warning("Login failed: trying after 30 sec")
					time.sleep(30)
			except Exception:
				logger.exception("main_execute")
				time.sleep(30)


if __name__ == '__main__':
	print("Starting Airwave Agent...")
	logger.info("Starting Airwave Agent...")
	air = Airwave_fetch()
	air.main_execute()
