import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

f = open("users_db.txt", "w")

users = ["antónio", "joaquim","josé", "miguel"]

passwords = ["pass", "word", "palavra", "chave"]

permission = ["TRUE", "FALSE", "FALSE","FALSE"]

cc_number = ["111111111", "222222222" ,"333333333" , "444444444"]

j = 0 
for i in users:
    salt = os.urandom(32)
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(passwords[j].encode())
    digest.update(salt)
    
    hash = digest.finalize()
    
    f.write(users[j] + "," + base64.b64encode(hash).decode() + "," + base64.b64encode(salt).decode() + "," + permission[j] + "," + cc_number[j] + "," + "\n")
    
    j += 1

f.close()
