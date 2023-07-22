import APIs_USSCS
name = input("Client name: ")
reg_pass = input("Registration password: ")
log_pass = input("Login password: ")
enc = input("Encryption (y/n): ")
if enc == "y":
    enc = True
elif enc == "n":
    enc = False
else:
    print("Invalid input")
    exit()
try:
    re = APIs_USSCS.add_client(name, reg_pass, log_pass, enc)
except ValueError as e:
    print(e)
    exit()
if re == None:
    print("Client added")
else:
    print("Error")
    print(re)