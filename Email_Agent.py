
from datetime import timedelta
from exchangelib import UTC_NOW
import yaml
import os
import logging
from logging.handlers import RotatingFileHandler
import yaml # From pyyaml
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests_toolbelt import MultipartEncoder
from exchangelib import Credentials, Account, DELEGATE,Configuration,EWSTimeZone,EWSDateTime
import time
import io

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.adapters.DEFAULT_RETRIES = 0

logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.path.join(os.getcwd(),"Email_Agent.log"), maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = True

logger.info("\n =================== Starting Email Agent ======================== \n")



class Email_agent():

	def __init__(self):
		self.config_file_name = "email_agent_config.yaml"

	def post_to_server(self,data):
		try:
			#xml_file = io.BytesIO(data)

			url = self.config.get("collector_url")
			#headers = {'Content-type': 'multipart/form-data'}
			
			files = dict()
			#files = {'file': ("file",xml_file)}

			files.update({"agentname":(None,self.config.get("agent_name"))})
			files.update({"agent_type":(None,"email_agent")})
			files.update({"data":(None,str(data))})
			
			res = requests.post(url, files=files)
			
			if res.status_code == 200:
				logger.info("Post accepted by server")
				print(res.content)
			else:
				logger.info("Post not accepted by server")
		except Exception:
			logger.exception("post_to_server")

	def read_config(self):
		try:
			config_file = open(self.config_file_name)
			self.config = yaml.load(config_file,Loader=yaml.Loader)
			
			if self.config.get("email_server") == None:
				logger.error("primary_smtp_address missed")
				exit(0)

			if self.config.get("email") == None:
				logger.error("email missed")
				exit(0)

			if self.config.get("password") == None:
				logger.error("email missed")
				exit(0)

			if self.config.get("filter time") == None:
				logger.error("filter time missed")
				exit(0)

			if self.config.get("customers") == None:
				logger.error("customers time missed")
				exit(0)


		except Exception:
			logger.exception("read_config")
			exit(0)

	def connect_mail_server(self):
		while True:
			try:
				print("Connecting Email Server")
				credentials = Credentials(self.config.get('email'), self.config.get('password'))
				conf = Configuration(server=self.config.get("email_server"), credentials=credentials)
				self.account = Account(primary_smtp_address=self.config.get('email'), credentials=credentials,
					config=conf,autodiscover=False,access_type=DELEGATE)
				print("Connected...")
				return True
			except Exception:
				logger.exception("connect_mail_server")
				logger.info("Sleeping")
			time.sleep(30)
			

	def read_email(self):
		while True:
			try:
				print("Reading emails....")
				tz = EWSTimeZone.localzone()
				since = UTC_NOW() - timedelta(hours=self.config.get("filter time"))
				filtered_emails = self.account.inbox.all().filter(datetime_received__gt=since).order_by('-datetime_received')
				data = self.validate_emails(filtered_emails)
				print(data)
				self.post_to_server(data)
			except Exception:
				logger.exception("read_email")
			finally:
				print("Sleeping for 5 Sec")
				time.sleep(5)

	def validate_emails(self,filtered_emails):
		#print("Total Mails: "+str(len(filtered_emails)))
		try:
			tz = EWSTimeZone.localzone()
			missed_mails = []
			customers = self.config.get("customers")
			not_responded_mail = dict()

			#Read older mail first
			print("Validing emails...")
			for mail in filtered_emails.reverse():
				#print(mail.sender)
				subject = mail.subject.lower().replace('re: ', '')
				sender_address = mail.sender.email_address
				from_name = mail.sender.name
				datetime_received = mail.datetime_received

				# Convert to local datetime
				datetime_received = datetime_received + timedelta(hours=5.50)
				
				sender_address = sender_address.lower()

				customers_matched = False
				for cus in customers:
					cus_email = cus.get("email")
					if sender_address.find(cus_email.lower()) != -1:
						customers_matched = True

				if customers_matched == True:
					# Last mail from customer
					m = {"from":sender_address,"alise":cus.get("alise"),"subject":subject}
					datetime_received = m.update({"datetime":str(datetime_received)})
					m.update({"name":from_name})

					not_responded_mail.update({subject:m})
				else:
					# Last mail from HPE
					not_responded_mail.pop(subject,"None")

			# Removing subject key from dict
			for nrm in not_responded_mail:
				missed_mails.append(not_responded_mail.get(nrm))


			return missed_mails
		except Exception:
			logger.exception("validate_emails")



if __name__ == '__main__':
	print("** Starting **")
	ea = Email_agent()
	ea.read_config()
	ea.connect_mail_server()
	ea.read_email()



#(datetime_received__range=(tz.localize(EWSDateTime(2020,7, 10)),tz.localize(EWSDateTime(2020,7, 11))))
#.order_by('-datetime_received')