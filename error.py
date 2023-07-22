import datetime
error_groups = {
    "4xx": {
        "4xx": "Client Error",
        "40x": "Authentication Error",
        "41x": "User interaction Error",
        "42x": "Registration Error"
    },
    "2xx": {
        "2xx": "Success"
    }
}


_4xx = {
    400: "Authentication failed",
    401: "Wrong Token",
    402: "Wrong login password",
    403: "Wrong registration password",
    404: "API Server not found",
    410: "target not found",
    411: "privacy error",
    420: "username already exists",
    421: "forbidden username",
    423: "rsa_key failed"
}

_2xx = {
    200: "login",
    201: "register",
    202: "send_message",
    203: "get_message",
    204: "add_contact",
    205: "remove_contact",
    206: "get_contacts",
    207: "set_privacy",
    208: "get_privacy",
    209: "other",
    210: "token check",
    211: "password check",
}
flags = ["send_message", "get_mesages", "login", "register", "add_contact", "remove_contact", "get_contacts", "set_privacy", "get_privacy", "check", "other"]

def gen_err_id(code:int, flag:str, username:str, API_server:str):
    now = datetime.datetime.now()
    return f"{now.year}-{now.month}-{now.day}-{now.hour}-{now.minute}-{now.second}#{code}#{flag}#{username}@{API_server}"
def gen_status_message(succes:bool, code:int, flag:int, username:str, API_server:str, message:str):
    if succes:
        mes = f"Success: {_2xx[code]} - {message} | flag: {flags[flag]}"
    else:
        mes = f"Error: {_4xx[code]} - {message} | flag: {flags[flag]}"
    status = {
        "succes": succes,
        "code": code,
        "flag": flags[flag],
        "message": mes,
        "err_id": gen_err_id(code, flag, username, API_server)
    }
    return status
