from execjs import compile


class Crypto:
    script = compile(open("C:/Users/Milos/source/Repos/outlook-account-generator/Outlook-Gen-main/utils/enc.js").read())

    def encrypt(password: str, randomNum: str, Key: str) -> str:

        return Crypto.script.call(
            "encrypt", password, randomNum, Key)