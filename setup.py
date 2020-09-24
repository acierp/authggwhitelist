import os
import time
import requests
import subprocess
import tkinter
from tkinter import messagebox
import sys
import hashlib


root = tkinter.Tk()
root.withdraw()
hwid = str(subprocess.check_output('wmic csproduct get uuid')).split('\\r\\n')[1].strip('\\r').strip()
BUF_SIZE = 65536
md5 = hashlib.md5()
clear = lambda: os.system('cls')
try:
    with open(sys.argv[0], 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
except:
    messagebox.showerror('Ethereal | Licensing System', 'Hash Calculating Failed')
    os._exit(0)
filehash = md5.hexdigest()

login_status = 0
register_status = 0
apikey = ""
secret = ""
aid = ""
version = "1.0"
random = "python"

def main():
    clear()
    os.system("title Auth Menu")
    print("[1] Login")
    print("[2] Register")
    print("[3] Extend Subscription")
    option = input("\n[?] ")
    if option == "1":
        login()
    elif option == "2":
        register()
    elif option == "3":
        redeem()
    else:
        print("\n[!] Invalid Option")
        time.sleep(2)
        os._exit(0)


def integrity_check():
    global login_status, register_status
    headers = {"User-Agent": "AuthGG"}
    data = {
        "type": "start",
        "random": random,
        "secret": secret,
        'aid': aid,
        'apikey': apikey
    }
    try:
        with requests.Session() as sess:
            request_1 = sess.post("https://api.auth.gg/version2/api.php", data=data, headers=headers)
            if request_1.json()["status"] == 'Failed':
                messagebox.showerror("Ethereal Licensing System", "This application is disabled!")
                os._exit(0)
            if request_1.json()['status'] == "Disabled":
                messagebox.showerror("Ethereal | Licensing System", "This application is disabled!")
                os._exit(0)
            if request_1.json()['developermode'] == 'Disabled':
                if request_1.json()['version'] != version:
                    messagebox.showinfo("Ethereal | Licensing System", "Update [{}] is available!".format(request_1.json()['version']))
                    os.system('start {}'.format(request_1.json()['downloadlink']))
                    os._exit(0)
                if request_1.json()['hash'] != filehash:
                    messagebox.showerror("Ethereal | Licensing System", "Hashes do not match, file tampering possible!")
                    os._exit(0)
                if request_1.json()['login'] != "Enabled":
                    login_status = 1
                if request_1.json()['register'] != "Enabled":
                    register_status = 1
            else:
                pass
    except:
            messagebox.showerror("Ethereal Licensing System", "Something went wrong!")
            os._exit(0)     
def login():
    if login_status == 0:
        os.system('cls')
        os.system("title Login Menu")
        username = input("[?] Enter Username: ")
        password = input("[?] Enter Password: ")
        data = {
            "type": "login",
            "aid": aid,
            "random": random,
            'apikey': apikey,
            "secret": secret,
            "username": username,
            "password": password,
            "hwid": hwid
        }
        headers = {"User-Agent": "AuthGG"}
        try:
            with requests.Session() as sess:
                request_2 = sess.post('https://api.auth.gg/version2/api.php', headers=headers, data=data)
                if "success" in request_2.text:
                    print("\n[!] Successfully logged into {}!".format(username))
                    time.sleep(2)
                    pass
                else:
                    if "invalid_details" in request_2.text:
                        print("\n[!] Please check your credentials!")
                    elif "invalid_hwid" in request_2.text:
                        print("\n[!] Invalid HWID, please do not attempt to share accounts!")
                    elif "hwid_updated" in request_2.text:
                        print("\n[!] Your HWID has been updated, relogin!")
                    elif "time_expired" in request_2.text:
                        print("\n[!] Your subscription has expired!")
                    elif "net_error" in request_2.text:
                        print("\n[!] Something went wrong!")
                    else:
                        print("\n[!] Something went wrong!")
                    time.sleep(2)
                    os._exit(0)

        except:
            messagebox.showerror("Ethereal Licensing System", "Something went wrong!")
            os._exit(0) 
    else:
        messagebox.showerror("Ethereal Licensing System", "Login is not available at this time!")
        os._exit(0)  
def register():
    os.system('cls')
    os.system("title Register Menu")
    if register_status == 0:
        token = input("[?] Please enter token: ")
        email = input("[?] Please enter email: ")
        username = input("[?] Please enter username: ")
        password = input("[?] Please enter password: ")
        headers = {"User-Agent": "AuthGG"}
        data = {
            "type": "register",
            "aid": aid,
            "random": random,
            'apikey': apikey,
            "secret": secret,
            "username": username,
            "password": password,
            "email": email,
            "token": token,
            "hwid": hwid
        }
        try:
            with requests.Session() as sess:
                request_3 = sess.post('https://api.auth.gg/version2/api.php', data=data, headers=headers)
                if "success" in request_3.text:
                    print("\n[!] {}, you have successfully registered!".format(username))
                    time.sleep(2)
                    os._exit(0)
                else:
                    if "invalid_token" in request_3.text:
                        print("\n[!] Token invalid or already used")
                    elif "invalid_username" in request_3.text:
                        print("\n[!] Username already taken, please choose another one")
                    elif "email_used" in request_3.text:
                        print('\n[!] Email is invalid or in use!')
                    else:
                        print("\n[!] Something went wrong!")
                    time.sleep(2)
                    os._exit(0)
        except:
            messagebox.showerror("Ethereal Licensing System", "Something went wrong!")
            os._exit(0)      
    else:
        messagebox.showerror("Ethereal Licensing System", "Register is not available at this time!")
        os._exit(0)  
def redeem():
    os.system('cls')
    os.system("title Redeem Menu") 
    username = input("[?] Enter Username: ")
    password = input("[?] Enter Password: ")
    token = input("[?] Please enter token: ")
    headers = {"User-Agent": "AuthGG"}
    data = {
            "type": "redeem",
            "aid": aid,
            "random": random,
            'apikey': apikey,
            "secret": secret,
            "username": username,
            "password": password,
            "token": token,
    }
    try:
        with requests.Session() as sess:
            request_4 = sess.post("https://api.auth.gg/version2/api.php", data=data, headers=headers)
            if "success" in request_4.text:
                print("\n[!] Successfully redeemed license & extended subscription!")
            elif "invalid_token" in request_4.text:
                print('\n[!] Invalid Credentials!')
            elif "net_error" in request_4.text:
                print('\n[!] Something went wrong!')
            time.sleep(2)
            os._exit(0)
    except:
        messagebox.showerror("Ethereal Licensing System", "Something went wrong!")
        os._exit(0)
            
                
integrity_check()
main()

# CODE HERE
    
