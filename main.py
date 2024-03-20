from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib
import tkinter
from tkinter import filedialog
from tkinter import messagebox

root = tkinter.Tk()
root.wm_attributes("-topmost", 1)
root.withdraw()

def generateKeyPair():
    key = RSA.generate(2048)
    privateKey = key.export_key()
    publicKey = key.public_key().export_key()

    return privateKey, publicKey

def getHash(hash_type):
    messagebox.showinfo("File Selection", "Select the file you'd like to check the hash for.")
    file = filedialog.askopenfilename()

    fi = open(file, "rb")
    fileData = fi.read()
    fi.close()

    hashFunction = getattr(hashlib, hash_type)

    return hashFunction(fileData).hexdigest()

def checkSum(hash_type, hash_value):
    fileHash = getHash(hash_type)

    if hash_value == fileHash:
        return "Hashes match."
    else:
        return "Hashes do not match."


programLoop = True
hashTypeList = ["md5", "sha1", "sha256"]

while programLoop:
    selection = input("Which hashing function would you like to perform?\n"
                      "1) Retrieve a file hash\n"
                      "2) Checksum\n"
                      "0) Exit\n")

    while not selection.isnumeric() and int(selection) < 0 or int(selection) > 2:
        selection = input("Input must be a number that is between 0-1.")

    if selection == "1":
        hashType = input("Which hash would you like to retrieve? (Type the hash without the dash)")

        while not hashType.lower() in hashTypeList:
            hashType = input("Hash not recognized. Try again.\n")

        print("The hash for the file is: " + getHash(hashType))
    elif selection == "2":
        hashType = input("Which hash would you like to compare? (Type the hash without the dash)")

        while not hashType.lower() in hashTypeList:
            hashType = input("Hash not recognized. Try again.\n")

        hashValue = input("Enter the hash value you'd like to compare.\n")

        print(checkSum(hashType, hashValue))
    else:
        programLoop = False
