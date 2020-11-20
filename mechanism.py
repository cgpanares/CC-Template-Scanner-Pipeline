import os
import gc
import subprocess
import sys
import threading
import logging
import socket
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def auto_install():
    print("Just installing required modules")
    print("if they do not already exist")
    os.system("pip3 install boto3")
    main()

try:
    import datetime
    from datetime import datetime
    import time
    import requests
    import json
    import boto3
except:
	auto_install()


def TS_scan(api_Key, f_path, reg):
	# Please substitute filePath, apiKey, and region
	# Cloud Conformity API Key
	apiKey=api_Key
	# Path to CloudFormation template file Yaml or JSON file
	filePath=f_path
	# Region in which Cloud Conformity serves your organisation
	region=reg

	endpoint = 'https://' + region + '-api.cloudconformity.com'
	url = endpoint + '/v1/template-scanner/scan'

	headers = {
		'Content-Type': 'application/vnd.api+json',
		'Authorization': 'ApiKey ' + apiKey
	}

	contents = open(filePath, 'r').read()

	payload =  {
		'data': {
			'attributes': {
				'type': 'cloudformation-template',
				'contents': contents
			}
		}
	}
	#print('Request:\n' + json.dumps(payload, indent=2))
	resp = requests.post(url, headers=headers, data=json.dumps(payload))
	#print('Response:\n' + json.dumps(resp.json(), indent=2, sort_keys=True))
	json_string = json.loads(json.dumps(resp.json(), indent=2, sort_keys=True, ensure_ascii=False).encode('utf-8'))
	
	return json_string

#def deleteS3files():
	#os.system("aws s3 rm s3://<s3-bucketname>/ --recursive")

def deleteS3fileversions():
	s3 = boto3.resource('s3')
	bucket = s3.Bucket('<s3-bucketname>')
	bucket.object_versions.all().delete()
	print("Deleting objects inside <s3-bucketname> bucket...")

def main():
	api_Key = sys.argv[1]
	region = sys.argv[2]
	# retrieve list of the cf templates currently uploaded
	cmdlist = "ls -d $PWD/* | grep 'CCTS' > cflist.txt"
	output1 = subprocess.check_output(cmdlist, shell=True)

	# get the full path of the list text file
	filepath = "ls -d $PWD/* | grep 'cflist'"
	output2 = subprocess.check_output(filepath, shell=True)
	output2decoded = str(output2)[2:-3]

	# open the text file and grab its contents to be used for loop
	txtfile = open(output2decoded)
	paths = txtfile.readlines()

	#get the filename of the script that will contain the AWS command for the stack
	filepath2 = "ls -d $PWD/* | grep 'C1CC-stack-call'"
	output3 = subprocess.check_output(filepath2, shell=True)
	output3decoded = str(output3)[2:-3]

	txtfile2 = open(output3decoded)
	paths2 = txtfile2.readlines()

	# create the loop function 
	for cfpath in paths:
		cfpathdecoded = str(cfpath)[0:-1]
		#execute the Template Scanner in each stack template
		result = TS_scan(api_Key, cfpathdecoded, region)
		#initialize the variable for couting the errors based on the condition
		count_vh = 0
		count_h = 0
		count_m = 0
		count_l = 0
		#get the specific filename with extension of the full path of the template
		split_stackname = cfpathdecoded.split("/")
		stackname = str(split_stackname[-1])

		#create a log file for recording all the checks that were done in the template
		now = datetime.now()
		datetoday = now.strftime("%m-%d-%Y-%H:%M:%S")
		logfilename = datetoday + "_" + stackname + "-output.log"
		with open(logfilename, "w") as f:
			f.write("=============LOG==============\n")
        
        #query the checks made for the template
		print()
		try:
			for x in result['data']:
				if ("VERY_HIGH" in str(x)) and ("FAILURE" in str(x)):
					count_vh+=1
					with open(logfilename, "a") as f:
						f.write(str(x) + "\n\n")
				elif ("HIGH" in str(x)) and ("FAILURE" in str(x)):
					count_h+=1
					with open(logfilename, "a") as f:
						f.write(str(x) + "\n\n")
				elif ("MEDIUM" in str(x)) and ("FAILURE" in str(x)):
					count_m+=1
					with open(logfilename, "a") as f:
						f.write(str(x) + "\n\n")
				elif ("LOW" in str(x)) and ("FAILURE" in str(x)):
					count_l+=1
					with open(logfilename, "a") as f:
						f.write(str(x) + "\n\n")
				else:
					with open(logfilename, "a") as f:
						f.write(str(x) + "\n\n")
					pass
			print("Number of failed rules with risk of VERY HIGH for template " + stackname + ": " + str(count_vh))
			print("Number of failed rules with risk of HIGH for template " + stackname + ": " + str(count_h))
			print("Number of failed rules with risk of MEDIUM for template " + stackname + ": " + str(count_m))
			print("Number of failed rules with risk of LOW for template " + stackname + ": " + str(count_l))
    	#If template scanner would fail to check the template, it will be logged in the log file created.
		except KeyError:
			with open(logfilename, "a") as f:
				f.write(str(result) + "\n\n")
			pass

		#if number of counts is equal or more than based on the condition below, it will not create the stack. Else, it will based on the text file that contains the command uploaded together with the template.
		if count_vh > 0:
			print("Template will not be processed for stack creation. The number of risks for VERY HIGH are more than 1.")
			pass
		elif count_h >= 3:
			print("Template will not be processed for stack creation. The number of risks for HIGH are more than 3.")
			pass
		elif count_m >= 5:
			print("Template will not be processed for stack creation. The number of risks for MEDIUM are more than 5.")
			pass
		elif count_l >= 7:
			print("Template will not be processed for stack creation. The number of risks for LOW are more than 7.")
			pass
		else:
			#get the name of the stack in the json result and use it on the for loop
			for stackcommand in paths2:
				if str(stackname) in str(stackcommand):
					#execute the command inside the script if the stackname exists
					os.system(stackcommand)
				else:
					print("Invalid command. Please check it again.")
					pass
		#locate the output log files for s3 uploading
		filepathlog = "ls -d $PWD/* | grep 'output.log'"
		logoutput1 = subprocess.check_output(filepathlog, shell=True)
		logoutput1decoded = str(logoutput1)[2:-3]
		log_upload_command = "aws s3 cp " + logoutput1decoded + " s3://<s3-bucketname>/template-logs/"
		#execute the aws command and delete the log files created in the build machine
		try:
			os.system(log_upload_command)
			os.system("rm -rf " + logoutput1decoded)
		except:
			os.system("rm -rf " + logoutput1decoded)
			pass


	txtfile.close()
	txtfile2.close()

	#execute aws command to delete the files inside the pipeline-files folder
	deleteS3fileversions()
	#deleteS3files()

main()