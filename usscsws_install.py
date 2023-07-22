import os
if not os.path.exists('DATABASE'):
    os.makedirs('DATABASE')
os.system("pip3 install -r requirements.txt")
def APIs_install():
    import APIs
    APIs.create_main_db()
    os.mkdir("DATABASE/APIs")
def usscs_install():
    import APIs_USSCS
    APIs_USSCS.add_client("sys_default", "sys_default", "sys_default")
def usscs_enc_install():
    import APIs_USSCS
    APIs_USSCS.add_client("sys_default_enc", "sys_default", "sys_default", enc=True)
APIs_install()
usscs_install()
usscs_enc_install()