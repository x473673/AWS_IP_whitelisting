import boto3
import botocore
import csv
import json
  
FILENAME = 'IPwhitelists.csv'
  
s3 = boto3.client('s3')
  
buckets = s3.list_buckets()['Buckets']
with open(FILENAME,'w') as file:
	fieldnames = ['bucket','effect','white IPs','black IPs']
	writer = csv.DictWriter(file, fieldnames=fieldnames)
	writer.writeheader()
	for bucket in buckets:
		try:
			policy = s3.get_bucket_policy(Bucket=bucket['Name'])['Policy']
		except botocore.exceptions.ClientError as e:
			policy = '{}'
		try:
			statements = json.loads(policy)['Statement']
		except KeyError as e:
			statements = []
		for statement in statements:
			try:
				effect = statement['Effect']
			except KeyError as e:
				effect = ""
			try:
				IPs = statement['Condition']['IpAddress']['aws:SourceIp']
			except KeyError as e:
				IPs = []
			try:
				notIPs = statement['Condition']['NotIpAddress']['aws:SourceIp']
			except KeyError as e:
				notIPs = []
			if IPs or notIPs:
				writer.writerow({'bucket': bucket['Name'],
						'effect': effect,
						'white IPs': IPs,
					'black IPs': notIPs})	
