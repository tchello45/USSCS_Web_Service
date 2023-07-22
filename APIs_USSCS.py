import APIs
from usscs import db_api
from usscs_enc import enc_db_api
import rsa
import json

def add_client(client:str, regsistration_password:str, login_password:str, enc=False):
    da = open("forbidden.json", "r")
    forbidden = json.load(da)
    da.close()
    for i in forbidden["clients"]:
        if i.upper() in client.upper():
            return ValueError("Client name is forbidden")
    id_ = APIs.add_client(client, regsistration_password, login_password, enc)
    if id_ == False:
        return ValueError("Client name is forbidden")
    if not enc:
        db_api.add_user("sys_default", "sys_default", path=f"DATABASE/APIs/{id_}/")
    else:
        (pub, priv) = rsa.newkeys(512)
        enc_db_api.add_user("sys_default", "sys_default",pub, priv, path=f"DATABASE/APIs/{id_}/")
