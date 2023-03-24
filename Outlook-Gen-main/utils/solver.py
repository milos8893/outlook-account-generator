from requests import post
from time     import sleep
from json     import load
import json
from random       import randint, choice

class Funcaptcha:
    key = load(open("C:/Users/Milos/source/Repos/outlook-account-generator/Outlook-Gen-main/data/config.json"))['captcha_key']

    def getKey(proxy) -> str:
        proxy_selected = choice(proxy);

        payload = json.dumps({
                "clientKey": Funcaptcha.key,
                "task": {
                    "type"            : "FunCaptchaTask",
                    "websitePublicKey": "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
                    "websiteURL"      : "https://signup.live.com/API/CreateAccount?lcid=1033&wa=wsignin1.0&rpsnv=13&ct=1667394016&rver=7.0.6737.0&wp=MBI_SSL&wreply=https%3a%2f%2foutlook.live.com%2fowa%2f%3fnlp%3d1%26signup%3d1%26RpsCsrfState%3d7f6d4048-5351-f65f-8b93-409ba7e7e4e4&id=292841&CBCXT=out&lw=1&fl=dob%2cflname%2cwld&cobrandid=90015&lic=1&uaid=93bc3e1fb03c42568561df0711c6d450",
                    "funcaptchaApiJSSubdomain": "https://client-api.arkoselabs.com",
                    "proxy": proxy_selected
                }
                }
                )

        headers = {"Content-Type": "application/json; charset=utf-8"}

        req = post("https://api.anycaptcha.com/createTask", data = payload, headers = headers )
        status = ""
        #print(f'solved resp: [{req.text}]')

        while status == "" or status == "processing":
            sleep(0.3)
            task = post("https://api.anycaptcha.com/getTaskResult", json = {
                "clientKey" : Funcaptcha.key,
                "taskId"    : req.json()["taskId"]
            })
            status = task.json()["status"]
            if task.json()["status"] == "ready":
                return task.json()["solution"]["token"]
