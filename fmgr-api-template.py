#!/usr/bin/python3

# FortiManager api template
# Howto: https://community.fortinet.com/t5/FortiManager/Technical-Tip-Using-FortiManager-API/ta-p/221089
# Attention: API requests must be explicitly allowed per user
# dj0Nz mar 2024

# Basic modules needed to query mgmt api
import os, requests, json, netrc

# Next two lines needed to suppress warnings if self signed certificates are used
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

###########
# Variables

# FortiManager host IP address and netrc file with credentials
host = '192.168.1.13'
auth_file = '/home/api/.netrc'

# Check credentials file, quit if not there
exists = os.path.isfile(auth_file)
if not exists:
    quit('Credentials file not found. Exiting.')

# Get login credentials from .netrc file
auth = netrc.netrc(auth_file)
token = auth.authenticators(host)
if token:
    user = token[0]
    password = token[2]
else:
    quit('Host not found in netrc file. Exiting.')

# Header and base url for each request
request_headers = {'Content-Type' : 'application/json'}
base_url = 'https://' + host + '/jsonrpc'

# Variables end
###############

###########
# Functions

def api_call(method,url,sid):
    payload = {
        "method" : method,
        "params" : [
            {
                "url" : url
            }
        ],
        "session": sid,
        "verbose": 1,
        "id": 1
    }
    response = requests.post(base_url,data=json.dumps(payload),headers=request_headers,verify = False)
    if response.ok:
        return(response.json())
    else:
        quit('API error.')

# Functions section end
#######################

###############
# Login section

login_payload = {
    "method" : "exec",
    "params" : [
        {
            "data" : {
                "passwd" : password,
                "user" : user
            },
            "url" : "/sys/login/user"
        }
    ],
    "session" : "string",
    "id" : "1"
}
response = requests.post(base_url,data=json.dumps(login_payload),headers=request_headers,verify = False)
if response.ok:
    sid = response.json()['session']
else:
    print('Status:',str(response.status_code))
    quit('Login error.')

# Login section end
###################

##############
# main program

# POC: Get fmgr status
method = 'get'
url = '/sys/status'
status = api_call(method,url,sid)

# pretty-print. either with json.dumps or pipe output to 'tr "'" '"'|jq .'
# print(json.dumps(status, indent=2))
# print(status)
data = status['result'][0]['data']

# end main
##########

########
# Logout
logout_payload = {
    "id": 1,
    "method": "exec",
    "params": [
        {
            "url": "/sys/logout"
        }
    ],
    "session": sid
}
response = requests.post(base_url,data=json.dumps(logout_payload),headers=request_headers,verify = False)
status = response.json()['result'][0]['status']['message']
if not status == 'OK':
   print('Logout error.')
