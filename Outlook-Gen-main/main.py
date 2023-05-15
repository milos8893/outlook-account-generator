import base64
import json
import os
from socket import gethostbyname
import ssl
import string
import requests
from tls_client   import Session
from re           import findall
from json         import loads, dumps, load
from datetime     import datetime
from utils.crypto import Crypto
from utils.solver import Funcaptcha
from random       import randint, choice
from names        import get_first_name, get_last_name
from os           import urandom
from time         import time
from threading    import Thread
from time     import sleep
import random
import re
import urllib.parse
from urllib3.exceptions import InsecureRequestWarning

class Outlook:
    def __init__(this, proxy: str = None):

        #this.languageWebsite = "en-US"
        #this.country = "US"
        #this.acceptLangString = "en-US,en;q=0.9"

        this.languageWebsite = "it-IT"
        this.country = "IT"
        this.acceptLangString = "it-IT, en-US,en;q=0.9"

        this.userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
        this.secUA = '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"'
        this.sessionClientUA = 'chrome_112'

        #this.userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.23 Safari/537.36"
        #this.secUA = '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"'
        #this.sessionClientUA = 'chrome_108'

        this.client          = Session(client_identifier=this.sessionClientUA)
        #this.client          = requests.Session()
        this.client.proxies  = {'http' : f'http://{proxy}','https': f'http://{proxy}'} if proxy else None

        this.client2          = requests.Session()
        this.client2.proxies  = {'http' : f'http://{proxy}','https': f'http://{proxy}'} if proxy else None
        this.client2.verify = False
        this.proxy = proxy

        # Suppress only the single warning from urllib3 needed.
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        
        ips = ["174.239.82.207", "174.215.113.111", "166.161.22.158", "97.136.198.20", "174.216.147.5", "174.40.14.170", "174.40.76.170", "174.202.227.131", "174.243.178.114", "174.243.178.61", "174.205.107.155", "174.203.108.30", "174.202.169.122", "174.203.8.41", "174.203.42.112", "174.209.192.220", "174.198.130.85", "174.215.144.248", "174.195.143.17", "174.202.164.18", "174.239.82.216", "174.215.113.115", "166.161.22.154", "97.136.198.27", "174.216.147.8", "174.40.14.179", "174.40.76.176", "174.202.227.133", "174.243.178.112", "174.243.178.61", "174.205.107.157", "174.203.108.38", "174.202.169.125", "174.203.8.48", "174.203.42.116", "174.209.192.225", "174.198.130.87", "174.215.144.248", "174.195.143.15", "174.202.164.14", "174.239.82.214", "174.215.113.114", "166.161.22.154", "97.136.198.24", "174.216.147.4", "174.40.14.174", "174.40.76.177", "174.202.227.134", "174.243.178.117", "174.243.178.64", "174.205.107.154", "174.203.108.34", "174.202.169.124", "174.203.8.44", "174.203.42.114", "174.209.192.224", "174.198.130.84", "174.215.144.244", "174.195.143.14", "174.202.164.14", "174.239.82.21", "174.215.113.11", "166.161.22.15", "97.136.198.2", "174.216.147.49", "174.40.14.17", "174.40.76.17", "174.202.227.13", "174.243.178.11", "174.243.178.6", "174.205.107.15", "174.203.108.3", "174.202.169.12", "174.203.8.4", "174.203.42.11", "174.209.192.22", "174.198.130.8", "174.215.144.24", "174.195.143.1", "174.202.164.12"]
        random.shuffle(ips)
        this.ips = ips
        this.nextIP          = 0

        this.Key             = None
        this.randomNum       = None
        this.SKI             = None
        this.uaid            = None
        this.tcxt            = None
        this.apiCanary       = None
        this.encAttemptToken = ""
        this.dfpRequestId    = ""

        this.siteKey         = 'B7D8911C-5CC8-A9A3-35B0-554ACEE604DA'

        this.__start__       = this.__init_client()
        this.account_info    = this.__account_info()
        
        this.cipher          = Crypto.encrypt(this.account_info['password'], this.randomNum, this.Key)
    

    @staticmethod
    def log(message: str):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
    def __init_client(this):

        content = this._request(
            method="GET",
            url='https://signup.live.com/signup?lic=1',
            headers={
                "host"            : "signup.live.com",
                "accept"          : "*/*",
                "accept-encoding" : "gzip, deflate, br",
                "accept-language" : this.acceptLangString,
                "connection"      : "keep-alive",
                "user-agent"      : this.userAgent
            }
        )   


        #contentR.text
        #content.text


        #"X-Forwarded-For"   : this.ips[this.nextIP],
        
        this.Key, this.randomNum, this.SKI = findall(r'Key="(.*?)"; var randomNum="(.*?)"; var SKI="(.*?)"', content.text)[0]
        json_data = loads(findall(r't0=([\s\S]*)w\["\$Config"]=', content.text)[0].replace(';', ''))
        
        this.uaid       = json_data['clientTelemetry']['uaid']
        this.tcxt       = json_data['clientTelemetry']['tcxt']
        this.apiCanary  = json_data['apiCanary']
    
    def __handle_error(this, code: str) -> str:
        errors = {
            "403" : "Bad Username",
            "1040": "SMS Needed",
            "1041": "Enforcement Captcha",
            "1042": "Text Captcha",
            "1043": "Invalid Captcha",
            "1312": "Captcha Error",
            "450" : "Daily Limit Reached",
            "1304": "OTP Invalid",
            "1324": "Verification SLT Invalid",
            "1058": "Username Taken",
            "1117": "Domain Blocked",
            "1181": "Reserved Domain",
            "1002": "Incorrect Password",
            "1009": "Password Conflict",
            "1062": "Invalid Email Format",
            "1063": "Invalid Phone Format",
            "1039": "Invalid Birth Date",
            "1243": "Invalid Gender",
            "1240": "Invalid first name",
            "1241": "Invalid last name",
            "1204": "Maximum OTPs reached",
            "1217": "Banned Password",
            "1246": "Proof Already Exists",
            "1184": "Domain Blocked",
            "1185": "Domain Blocked",
            "1052": "Email Taken",
            "1242": "Phone Number Taken",
            "1220": "Signup Blocked",
            "1064": "Invalid Member Name Format",
            "1330": "Password Required",
            "1256": "Invalid Email",
            "1334": "Eviction Warning Required",
            "100" : "Bad Register Request"
        }
        
        return errors[code]
    
    def __account_info(this) -> dict:
        
        random3      = ''.join(random.choices(string.ascii_letters + string.digits, k=3))
        first_name = get_first_name().replace(" ", "")
        last_name  = get_last_name().replace(" ", "")
        #email      = f"{first_name}.{last_name}.{token}@outlook.com".lower()
        email      = hotmail_generate(first_name, last_name).lower()
        #password   = email.encode('utf-8').hex()[:8] + 'T1x@'
        password   = get_first_name() + random3.capitalize()
        if len(password) < 8:
            password   += ''.join(random.choices(string.ascii_letters + string.digits, k=8-len(password)))

        Outlook.log(f'email:  [{email}]')
        
        return {
            "password"          : password,
            "CheckAvailStateMap": [
                f"{email}:undefined"
            ],
            "MemberName": email,
            "FirstName" : first_name,
            "LastName"  : last_name,
            "BirthDate" : f"{randint(1, 27)}:0{randint(1, 9)}:{randint(1969, 2000)}",
            "cookiess" : ""
        }

    def __base_headers(this):

        #this.nextIP += 1
        #Outlook.log(f'using IP:  [{this.ips[this.nextIP]}...]')

        return {
            "accept"            : "application/json",
            "accept-encoding"   : "gzip, deflate, br",
            "accept-language"   : this.acceptLangString,
            "cache-control"     : "no-cache",
            "canary"            : this.apiCanary,
            "content-type"      : "application/json",
            "dnt"               : "1",
            "hpgid"             : f"2006{randint(10, 99)}",
            "origin"            : "https://signup.live.com",
            "pragma"            : "no-cache",
            "scid"              : "100118",
            "sec-ch-ua"         : this.secUA,
            "sec-ch-ua-mobile"  : "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest"    : "empty",
            "sec-fetch-mode"    : "cors",
            "sec-fetch-site"    : "same-origin",
            "tcxt"              : this.tcxt,
            "uaid"              : this.uaid,
            "uiflvr"            : "1001",
            "user-agent"        : this.userAgent,
            "x-ms-apitransport" : "xhr",
            "x-ms-apiversion"   : "2",
            "referrer"          : "https://signup.live.com/?lic=1&uaid=" + this.uaid
        }
        #            "X-Forwarded-For"   : this.ips[this.nextIP],
    
    def __base_payload(this, captcha_solved: bool) -> dict:
        payload = {
            **this.account_info,
            "RequestTimeStamp"          : str(datetime.now()).replace(" ", "T")[:-3] + "Z",
            "EvictionWarningShown"      : [],
            "UpgradeFlowToken"          : {},
            "MemberNameChangeCount"     : 1,
            "MemberNameAvailableCount"  : 1,
            "MemberNameUnavailableCount": 0,
            "CipherValue"               : this.cipher,
            "SKI"                       : this.SKI,
            "Country"                   : this.country,#ovde stao. treba IT
            "AltEmail"                  : None,
            "IsOptOutEmailDefault"      : True,
            "IsOptOutEmailShown"        : True,
            "IsOptOutEmail"             : True,
            "LW"                        : True,
            "SiteId"                    : 68692,
            "IsRDM"                     : 0,
            "WReply"                    : None,
            "ReturnUrl"                 : None,
            "SignupReturnUrl"           : None,
            "uiflvr"                    : 1001,
            "uaid"                      : this.uaid,
            "SuggestedAccountType"      : "OUTLOOK",
            "SuggestionType"            : "Locked",
            "encAttemptToken"           : this.encAttemptToken,
            "dfpRequestId"              : this.dfpRequestId,
            "scid"                      : 100118,
            "hpgid"                     : 201040,
        }
        
        if not captcha_solved:
            cap_token = Funcaptcha.getKey(proxies)
            Outlook.log(f'solved captcha: [{cap_token[:100]}...]')
            
            #ocvde stao, resenje za novu captchau https://github.com/cloudyyoung/ms-account/blob/master/sign-up/sign-up.md
            payload.update({
                #"HType" : "visual",
                "HType" : "enforcement",
                "HSol"  : cap_token,
                "HPId"  : this.siteKey,
            })
        
        return payload

    def register_account(this, captcha_solved: bool = False) -> (dict and str):

        #print(this.__base_headers2())
        
        try:
            for _ in range(3):
                try:

                    #response = this.client.post('https://signup.live.com/API/CreateAccount?lic=1',
                    #        json = this.__base_payload(captcha_solved), headers = this.__base_headers())
                    

                    response = this._request(
                        method = "POST",
                        url = 'https://signup.live.com/API/CreateAccount?lic=1',
                        headers = this.__base_headers(),
                        json=this.__base_payload(captcha_solved)
                    )
                    
                    
                    #Outlook.log(f'register resp:  [{str(response.json())[:100]}...]'); break
                    Outlook.log(f'register resp:  [{str(response.json())}...]'); break
                
                except Exception as e:
                    Outlook.log(f'http error: [{e}]')
                    continue

            error = response.json().get("error")
            if error:
                code = error.get("code")
                if '1041' in code:
                    error_data  = loads(error.get("data"))
                    
                    this.encAttemptToken = error_data['encAttemptToken']
                    this.dfpRequestId    = error_data['dfpRequestId']
                    return this.register_account(True)
                
                else:
                    return {}, this.__handle_error(code)
            
            else:
                url = str(response.json().get("redirectUrl"))

                #Outlook.log('----------------')
                #print('RedirectURL: ' + url)
                #Outlook.log('----------------')

                #response = this.client.get(response.json().get("redirectUrl"))
                #Outlook.log(f'slt:  [{str(response.json().get("slt"))}...]')
                #rheaders = this.__base_headers2()
                #rdata = f'slt={urllib.parse.quote(str(response.json().get("slt")))}'
                rdata = {"slt" :str(response.json().get("slt"))}

                #Outlook.log(f'data:  [{str(rdata)}...]')

                

                response = this._request(
                    method="POST",
                    #cookies=response.cookies,
                    url=url,
                    headers={
                        "Connection": "keep-alive",
                        "DNT": "1",
                        "sec-ch-ua-mobile": "?0",
                        "User-Agent": this.userAgent,
                        "Accept": "application/json",
                        "sec-ch-ua": this.secUA,
                        "sec-ch-ua-platform": '"Windows"',
                        "Origin": "https://signup.live.com",
                        "Sec-Fetch-Site": "same-origin",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-User": "?1",
                        "Sec-Fetch-Dest": "document",
                        "Referer": "https://signup.live.com/",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": this.acceptLangString
                    },
                    data=rdata
                )

                #Outlook.log('----------------')
                #Outlook.log(f'second resp h:  [{str(response.headers)}...]')
                #Outlook.log('----------------')
                #Outlook.log(f'second resp:  [{str(response.text)}...]')



                url = find_inbetween(response.text, "urlPost:'", "'")
                ppft = find_inbetween(response.text, "sFT:'", "'")
                rdata={
                    "LoginOptions": "1",
                    "type": "28",
                    "ctx": "",
                    "hpgrequestid": "",
                    "PPFT": ppft,
                    "i19": "6291"
                    #"i19": "1997"
                }

                response = this._request(
                    method="POST",
                    #cookies=response.cookies,
                    url=url,
                    headers={
                        "Connection": "keep-alive",
                        "DNT": "1",
                        "sec-ch-ua-mobile": "?0",
                        "User-Agent": this.userAgent,
                        "Accept": "application/json",
                        "sec-ch-ua": this.secUA,
                        "sec-ch-ua-platform": '"Windows"',
                        "Origin": "https://login.live.com",
                        "Sec-Fetch-Site": "same-origin",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-User": "?1",
                        "Sec-Fetch-Dest": "document",
                        "Referer": response.url,
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": this.acceptLangString
                    },
                    data=rdata
                )
                #response.raise_for_status()
                Outlook.log('----------------')
                #Outlook.log(f'third resp h:  [{str(response.headers)}...]')
                #Outlook.log('----------------')
                Outlook.log(f'third resp:  [{str(response.text)}...]')
                Outlook.log('----------------')




                NAPExp = find_inbetween(response.text, '"NAPExp" value="', '"')
                NAP = find_inbetween(response.text, '"NAP" value="', '"')
                ANON = find_inbetween(response.text, '"ANON" value="', '"')
                ANONExp = find_inbetween(response.text, '"ANONExp" value="', '"')
                t = find_inbetween(response.text, '"t" value="', '"')

                Outlook.log('-------- IN BETWEEN OK --------')
                
                response = this._request(
                    method="POST",
                    allow_redirects=False,
                    #cookies=response.cookies,
                    url=f"https://account.microsoft.com/?lang={this.languageWebsite}&wa=wsignin1.0",
                    headers={
                        "Connection": "keep-alive",
                        "sec-ch-ua-mobile": "?0",
                        "User-Agent": this.userAgent,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                        "sec-ch-ua": this.secUA,
                        "sec-ch-ua-platform": '"Windows"',
                        "Origin": "https://login.live.com",
                        "Sec-Fetch-Site": "cross-site",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-Dest": "document",
                        "Referer": "https://login.live.com/",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": this.acceptLangString
                    },
                    data={
                        "t": t,
                        "NAPExp": NAPExp,
                        "NAP": NAP,
                        "ANONExp": ANONExp,
                        "ANON": ANON
                    }
                )
                loc = response.headers['Location']
                #response.raise_for_status()
                #Outlook.log('----------------')
                #Outlook.log(f'forth resp:  [{str(response.text)}...]')
                #Outlook.log('----------------')
                #Outlook.log(f'forth resp:  [{str(response.text)}...]')
                #Outlook.log('----------------')
                #Outlook.log(f'-------redirecting: {loc}---------')
                
                
                response = this._request(
                    method="GET",
                    allow_redirects=False,
                    #cookies=response.cookies,
                    url=loc,
                    #hostToIP=False,
                    headers={
                        "Connection": "keep-alive",
                        "sec-ch-ua-mobile": "?0",
                        "Cache-Control": "max-age=0",
                        "Upgrade-Insecure-Requests": "1",
                        "User-Agent": this.userAgent,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                        "sec-ch-ua": this.secUA,
                        "sec-ch-ua-platform": '"Windows"',
                        "Sec-Fetch-Site": "cross-site",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-Dest": "document",
                        "Referer": "https://login.live.com/",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": this.acceptLangString
                    }
                )
                #response.raise_for_status()
                #Outlook.log('----------------')
                #Outlook.log(f'fifth resp:  [{str(response.text)}...]')
                #Outlook.log('----------------')
                #Outlook.log(f'fifth resp:  [{str(response.text)}...]')
                #Outlook.log('----------------')
                

                """
                #ovo je login user/pass
                response = this._request(
                    method="POST",
                    #cookies=response.cookies,
                    url="https://login.live.com/ppsecure/post.srf",
                    headers={
                        "Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                        "Accept-Language":  this.acceptLangString
                    },
                    data={
                        "i13": "0",
                        "login": this.account_info["MemberName"],
                        "loginfmt": this.account_info["MemberName"],
                        "type": "11",
                        "LoginOptions": "3",
                        "lrt": "",
                        "lrtPartition": "",
                        "hisRegion": "",
                        "hisScaleUnit": "",
                        "passwd": this.account_info["password"],
                        "ps": "2",
                        "psRNGCDefaultType": "",
                        "psRNGCEntropy": "",
                        "psRNGCSLK": "",
                        "canary": "",
                        "ctx": "",
                        "hpgrequestid": "",
                        "PPFT": ppft,
                        "PPSX": "Passpor",
                        "NewUser": "1",
                        "FoundMSAs": "",
                        "fspost": "0",
                        "i21": "0",
                        "CookieDisclosure": "0",
                        "IsFidoSupported": "1",
                        "i2": "1",
                        "i17": "0",
                        "i18": "",
                        "i19": "1668743"
                    }
                )
                #response.raise_for_status()
                Outlook.log('----------------')
                Outlook.log(f'sixth resp h:  [{str(response.headers)}...]')
                Outlook.log('----------------')
                Outlook.log(f'sixth resp:  [{str(response.text)}...]')
                Outlook.log('----------------')
                """

                allCookies = ''
                #print(response.cookies)
                requestscookiejar = response.cookies
                cookieCounter = 0
                for cattribs in requestscookiejar:
                    cookieCounter += 1
                    #print('Cookie name: ' + cattribs.name )
                    jsonCookie = {
                                    "domain": (str)(cattribs.domain),
                                    "expirationDate": str(cattribs.expires).lower(),
                                    "hostOnly": False,
                                    "httpOnly": False,
                                    "name": (str)(cattribs.name),
                                    "path": (str)(cattribs.path),
                                    "sameSite": "unspecified",
                                    "secure": cattribs.secure,
                                    "session": False,
                                    "storeId": cookieCounter,
                                    "value": (str)(cattribs.value),
                                    "id": cookieCounter
                                }
                    allCookies += json.dumps(jsonCookie)+ ','
                
                #allCookies = '[' + json.dumps(allCookies[:-1]) + ']'
                allCookies = '[' + allCookies[:-1] + ']'
                allCookies = allCookies.replace(': False', ': false').replace(': True', ': true').replace('"none"', '"0"')
                this.account_info['cookiess'] = urllib.parse.quote(allCookies)
                #this.account_info['cookiess'] = allCookies

                #Outlook.log('----------------')
                #print("Cookies: ")
                #print(allCookies)
                #Outlook.log('----------------')

                try:
                    this.IPChange()
                except:
                    print("An Proxy exception occurred") 

                return this.account_info, 'Success'
            
        except Exception as e:
            return {}, str(e)


#https://github.com/exploitxd/xbox-promo-puller/blob/0bf327128d4a559eb514890f3602cf5618f976c9/main.py
#user/pass login if we need it

#https://github.com/emmett97/heh/blob/f8bf96c16f5d4480a02ee325eba6f190837f8e12/core/microsoft/clients.py
#ako bude trebao login

    def IPChange(this):
        if not this.proxy.__contains__("airproxy"):
            return
        proxyID = this.proxy.split('@', 1)[1]
        response = this._request(method="GET",url="https://airproxy.io/api/proxy/change_ip/?format=json&key=T0Reg8GDTHaNqEg28sJBrL4SRXiqjzFb&async=true&id=" + proxyID)
        print(f"Proxy: {str(response.text)}")

    def _request(this,
        url: str,
        headers: dict = {},
        method="GET",
        allow_redirects = True,
        _retry = None,
        hostToIP=True,
        **kwargs
    ):
        _retry = _retry or 0
        
        hostname = urllib.parse.urlparse(url).hostname
        host = gethostbyname(hostname)

        if hostToIP:
            url = url.replace(hostname, host, 1)
        headers["Host"] = hostname

        try:

            if method == "POST":
                response = this.client2.post(
                    url=url,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    #cookies=cookies,
                    **kwargs)
            else:
                response = this.client2.get(
                    url=url,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    #cookies=cookies,
                    **kwargs)
        except requests.exceptions.ProxyError:
            if _retry > 1:
                raise
            #return _request(
            #    method, url, headers, allow_redirects, _retry=_retry+1, **kwargs)

        if allow_redirects and response is not None and response.status_code in (301, 302):
            return this._request(
                "GET", response.headers["location"], headers, **kwargs)

        return response




def parse_spintax(rnd, string):
    pattern = r'{[^{}]*}'
    match = re.search(pattern, string)
    while match:
        seg = string[match.start() + 1 : match.end() - 1]
        choices = seg.split('|')
        string = string[:match.start()] + choices[rnd.randint(0, len(choices) - 1)] + string[match.end():]
        match = re.search(pattern, string)
    return string


def find_inbetween(
    source: str,
    substring: str,
    substring2: str,
    json_parse: bool = False
):
    value = source \
        .split(substring, 1)[1] \
        .split(substring2, 1)[0]
    if json_parse:
        value = json.loads(value)
    return value




def hotmail_generate(name, surname):
    random3 = urandom(3).hex()
    random4 = urandom(4).hex()
    month = "{0:02d}".format(random.randint(1, 12))
    year = random.randint(1978, 2000)
    year2 = random.randint(78, 99)

    #spintax = f"{{{name}{{|.}}{surname}|{surname}{{|.}}{name}}}{{{month}{year}|{month}{year2}|{year}|{year2}|{random3}|{random4}|{random3}|{random4}}}@{{outlook.it|outlook.com|hotmail.com}}"
    spintax = f"{{{name}{{|.}}{surname}|{surname}{{|.}}{name}}}{{{month}{year}|{month}{year2}|{year}|{year2}|{random3}|{random4}|{random3}|{random4}}}@{{outlook.it|outlook.com|hotmail.com}}"
    username = parse_spintax(random, spintax.lower())
    return username







def register_loop(proxies: list):

    nextIP = 0

    while True:
        for x in range(len(proxies)):  
            start           = time()
            #proxy = choice(proxies)
            proxy = proxies[x]
            outlook         = Outlook(proxy)

            outlook.nextIP = nextIP
            nextIP += 1
            #continue


            account, status = outlook.register_account()
            stop            = time() - start

            if status == 'Success':
                Outlook.log(f'registered acc: [{account["MemberName"]}:...] {round(stop, 2)}s')
                with open('C:/Users/Milos/source/Repos/outlook-account-generator/Outlook-Gen-main/data/accounts.txt', 'a') as f:
                    f.write(f'{account["MemberName"]}\t{account["password"]}\t{proxy}\t{account["cookiess"]}\n')
            else:
                Outlook.log(f'register error: [{status}] {round(stop, 2)}s')
            #sleep(3)


if __name__ == "__main__":
    proxies = open('C:/Users/Milos/source/Repos/outlook-account-generator/Outlook-Gen-main/data/proxies.txt').read().splitlines()
    config  = load(open('C:/Users/Milos/source/Repos/outlook-account-generator/Outlook-Gen-main/data/config.json'))
    
    for _ in range(config['threads']):
        Thread(target = register_loop, args = (proxies,)).start()
        #Thread(target = register_loop, args = (proxies,)).start()
