import os
if not os.path.exists('DATABASE'):
    os.makedirs('DATABASE')
os.system("pip3 install -r requirements.txt")
def APIs_install():
    import APIs
    APIs.create_main_db()
    os.mkdir("DATABASE/APIs")
    APIs.add_client("EDC", "EDC", "EDC")
APIs_install()