"""
Created on Sun Oct 25 13:26:58 2020
Project Lady of Shalott
@author: A F Forughi
"""

import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import PySimpleGUI as sg # pip install PySimpleGUI

backend = default_backend()
iterations = 100_000

# %% Functions
def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


# %%  GUI
layout = [  [sg.Text('Basic Text Crypter')],[sg.Text('Which one?')], 
            [sg.Button('Encrypt'), sg.Button('Decrypt')]] 
window = sg.Window('Mode!', layout)
mode_1, values = window.read()
window.close()
if mode_1 == None:
    sys.exit("Cancelled") 

message=sg.popup_get_text("Massage:",title=None,default_text="",password_char="",size=(None, None),
    button_color=None,background_color=None,text_color=None,icon=None,font=None,no_titlebar=False,
    grab_anywhere=False,keep_on_top=False,location=(None, None),image=None,modal=True)

if message == None:
    sys.exit("Cancelled") 

password=sg.popup_get_text("Password",title=None,default_text="",password_char="☣",size=(None, None),
    button_color=None,background_color=None,text_color=None,icon=None,font=None,no_titlebar=False,
    grab_anywhere=False,keep_on_top=False,location=(None, None),image=None,modal=True)

if password == None:
    # BUG!: over write the variables here and after window.close() lines if you want them not remain in memory
    sys.modules[__name__].__dict__.clear()
    sys.exit("Cancelled")

if mode_1=='Encrypt':
    token=password_encrypt(message.encode(), password)
    layout = [  [sg.Text('Token:')],
                [sg.Multiline(default_text=token,size=(60, 20))],[sg.Button('Close Window')]]
    window = sg.Window('Encrypted Message', layout).Finalize()
    while True:
        event, values = window.read()
        if event in (None, 'Close Window'): break
    window.close()
    sys.modules[__name__].__dict__.clear()
    
elif mode_1=='Decrypt':
    try:
        d_message=password_decrypt(message, password).decode()
        
    except:
        d_message="Wrong Password!"
        
    layout = [  [sg.Text('Message:')],
                [sg.Multiline(default_text=d_message,size=(60, 20))],[sg.Button('Close Window')]]
    window = sg.Window('Decrypted Message', layout).Finalize()
    while True:
        event, values = window.read()
        if event in (None, 'Close Window'): break
    window.close()
    sys.modules[__name__].__dict__.clear()


