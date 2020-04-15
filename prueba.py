import getpass
import re
import requests
from requests_ntlm import HttpNtlmAuth
from pprint import pprint

# Ask for password
user = getpass.getuser()
password = getpass.getpass("Password for "+user+": ")
user =  user

# Get a authorization code
headers = {"User-Agent": "Mozilla/5.0"}

params = {
    'response_type': ['code'], 
    'client_id': ['487d8ff7-80a8-4f62-b926-c2852ab06e94'], 
    'resource': 'web.example.com', 
    'redirect_uri': 'https://localhost:8000/oauth2/callback', 
    
}

response = requests.get(
    "https://adfs.example.com/adfs/oauth2/authorize/wia",
    auth=HttpNtlmAuth(user, password),
    headers=headers,
    allow_redirects=False,
    params=params,
)
response.raise_for_status()
pprint(response.headers['location'])

'''

code = re.search('code=(.*)', response.headers['location']).group(1)

# Get an access token
data = {
    'grant_type': 'authorization_code',
    'client_id': '84c99e8f-6c77-4024-a7fb-4e6c14e0d2c6',
    'redirect_uri': 'https://suite_stage.intellignos.com/oauth2/callback',
    'code': code,
}
response = requests.post(
    "https://gb-svc003.globalservs.com/adfs/oauth2/token/",
    data,
)
response.raise_for_status()
response_data = response.json()
access_token = response_data['access_token']

# Make a request towards this API
headers = {
    'Accept': 'application/json',
    'Authorization': 'Bearer %s' % access_token,
}
pprint('pablo')
response = requests.get(
    'https://djangoapp.example.com/v1/pets?name=rudolf',
    headers=headers
)
pprint(response.json())'''