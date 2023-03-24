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

class Outlook:
    def __init__(this, proxy: str = None):
        this.client          = Session(client_identifier='chrome_108')
        this.client.proxies  = {'http' : f'http://{proxy}','https': f'http://{proxy}'} if proxy else None
        
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
        this.userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        
        this.__start__       = this.__init_client()
        this.account_info    = this.__account_info()
        
        this.cipher          = Crypto.encrypt(this.account_info['password'], this.randomNum, this.Key)
    

    @staticmethod
    def log(message: str):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
    def __init_client(this):
        content = this.client.get('https://signup.live.com/signup?lic=1', headers = {
            "host"            : "signup.live.com",
            "accept"          : "*/*",
            "accept-encoding" : "gzip, deflate, br",
            "connection"      : "keep-alive",
            "user-agent"      : this.userAgent
        })
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
        
        token      = urandom(3).hex()
        first_name = get_first_name()
        last_name  = get_last_name()
        email      = f"{first_name}.{last_name}.{token}@outlook.com".lower()
        password   = email.encode('utf-8').hex()[:8] + ':Tek01sdsa12x@'
        
        return {
            "password"          : password,
            "CheckAvailStateMap": [
                f"{email}:undefined"
            ],
            "MemberName": email,
            "FirstName" : first_name,
            "LastName"  : last_name,
            "BirthDate" : f"{randint(1, 27)}:0{randint(1, 9)}:{randint(1969, 2000)}"
        }
        
    def __base_headers(this):

        #this.nextIP += 1
        Outlook.log(f'using IP:  [{this.ips[this.nextIP]}...]')

        return {
            "accept"            : "application/json",
            "accept-encoding"   : "gzip, deflate, br",
            "accept-language"   : "en-US,en;q=0.9",
            "cache-control"     : "no-cache",
            "canary"            : this.apiCanary,
            "content-type"      : "application/json",
            "dnt"               : "1",
            "hpgid"             : f"2006{randint(10, 99)}",
            "origin"            : "https://signup.live.com",
            "pragma"            : "no-cache",
            "scid"              : "100118",
            "sec-ch-ua"         : '" Not A;Brand";v="107", "Chromium";v="96", "Google Chrome";v="96"',
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
            "referrer"          : "https://signup.live.com/?lic=1"
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
            "Country"                   : "CA",
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
            
            payload.update({
                "HType" : "enforcement",
                "HSol"  : cap_token,
                "HPId"  : this.siteKey,
            })
        
        return payload

    def register_account(this, captcha_solved: bool = False) -> (dict and str):
        
        try:
            for _ in range(3):
                try:
                    response = this.client.post('https://signup.live.com/API/CreateAccount?lic=1',
                            json = this.__base_payload(captcha_solved), headers = this.__base_headers())
                    
                    Outlook.log(f'register resp:  [{str(response.json())[:100]}...]'); break
                
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
                return this.account_info, 'Success'
            
        except Exception as e:
            return {}, str(e)

def register_loop(proxies: list):

    nextIP = 0

    while True:
        start           = time()
        outlook         = Outlook(choice(proxies))

        outlook.nextIP = nextIP
        nextIP += 1
        #continue


        account, status = outlook.register_account()
        stop            = time() - start

        if status == 'Success':
            Outlook.log(f'registered acc: [{account["MemberName"]}:...] {round(stop, 2)}s')
            with open('C:/Users/Milos/source/Repos/outlook-account-generator/Outlook-Gen-main/data/accounts.txt', 'a') as f:
                f.write(f'{account["MemberName"]}:{account["password"]}\n')
        else:
            Outlook.log(f'register error: [{status}] {round(stop, 2)}s')
        #sleep(3)

if __name__ == "__main__":
    proxies = open('C:/Users/Milos/source/Repos/outlook-account-generator/Outlook-Gen-main/data/proxies.txt').read().splitlines()
    config  = load(open('C:/Users/Milos/source/Repos/outlook-account-generator/Outlook-Gen-main/data/config.json'))
    
    for _ in range(config['threads']):
        Thread(target = register_loop, args = (proxies,)).start()
        #Thread(target = register_loop, args = (proxies,)).start()
