#!/usr/bin/env python3

import argparse
import validators
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment


parser = argparse.ArgumentParser(description= 'The Achilles HTML Vulnerability Analyser version 1.0') 
parser.add_argument('-v', '--version', action = 'version', version = '%(prog)s 1.0')
parser.add_argument('url', type=str, help= 'The URL of the HTML to analyse')
parser.add_argument('--config', help= 'The path to configuration file')
parser.add_argument('-o', '--output', help='Report file path')

args = parser.parse_args()

config= {'forms': True, 'comments': True, 'passwords': True}

if (args.config):
	print('using configuration file: '+ args.config)
	config_file = open(args.config, 'r')
	config_from_file = yaml.safe_load(config_file)
	
	if (config_from_file):
		config ={**config, **config_from_file}
url = args.url
	
report = ''

if (validators.url(url)):
	result_html = requests.get(url).text
	parsed_html = BeautifulSoup(result_html, 'html.parser')
	
	
	forms = (parsed_html.find_all('form'))
	comments = parsed_html.find_all(string = lambda text: isinstance(text,Comment))
	password_inputs = parsed_html.find_all('input', {'name' : 'password'})
	
	if (config['forms']):
		for form in forms:
			if((form.get('action').find('https')<0)  and (urlparse(url).scheme != 'https')):
				report += 'Form Issue: Insecure form action ' + form.get('action') + 'found in doucment\n'
			
	if (config['comments']):
		for comment in comments:
			if(comment.find('key: ') > -1):
				report += 'Comment Issue:key found in comment\n'
	
	if (config['passwords']):		
		for password_input in password_inputs:
			if(password_input.get('type') != 'password'):
				report+= 'Input issue: Plaintext password input was found:please change to password type input\n'
	
else:
	print('Invalid URL')
	


if (report == ''):
	report+='Good job: your html document is secure\n'
else:
	header='Following vulnerability issues were found in your html document\n'
	header+= '*******************************************************************\n'
	report= header+report
print(report)

if(args.output):
	f=open(args.output, 'w')
	f.write(report)
	f.close
	print('report saved to :' + args.output)
	

