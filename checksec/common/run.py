#!/usr/bin/env python3

import glob
import zipfile
import os
import shutil
import json
from time import sleep
from tool import TOOL_FOLDER, READABLE_TOE, run_tool
from cestcrypto import generate_ECDH_key, to_pub, dohash

import base64
from tinyec import registry
from tinyec import ec
from Crypto.Cipher import AES

POLL_FOLDER = TOOL_FOLDER + "toes/"
MISC_DATA_FOLDER = TOOL_FOLDER + "toe-miscdata/"
TOOLS_ARE_SILENT = False

os.makedirs(POLL_FOLDER, exist_ok=True)
os.makedirs(MISC_DATA_FOLDER, exist_ok=True)

# generate an ephemeral key
(key, ecdh_priv) = generate_ECDH_key()
public_key = to_pub(key)
public_key_string = json.dumps(public_key)
public_hash = dohash(public_key_string.encode('ascii'))
print("DEBUG privateKey:" + key["d"], flush=True)
curve = registry.get_curve('secp256r1')  # AKA "P-256"

def ecc_point_to_256_bit_key(point):
    return point.x

def get_key_from_json(pub):
    print("1", flush=True)
    pubx = int.from_bytes(base64.urlsafe_b64decode(pub["x"] + '=='), byteorder="big")
    puby = int.from_bytes(base64.urlsafe_b64decode(pub["y"] + '=='), byteorder="big")
    print("2", flush=True)
    pub_point = ec.Point(curve, x=pubx, y=puby)
    return ec.Keypair(curve, pub=pub_point)


with open("/dev/attestation/user_report_data", "wb") as user_report_data:
    user_report_data.write(public_hash)

# generating the quote
with open("/dev/attestation/quote", "rb") as q:
    quote = q.read()

with open(MISC_DATA_FOLDER + "pubKey" + "", "w") as f:
    f.write(public_key_string)

with open(MISC_DATA_FOLDER + "quote" + "", "wb") as f:
    f.write(quote)

while True:
    print("Started loop", flush=True)

    # Check if there is new toe to test
    toe_list = glob.glob(POLL_FOLDER + "*")

    sleep(1)
    if len(toe_list) == 0:
        sleep(20)
        continue

    # Unzip toe
    toe_raw = toe_list[0]
    print('toe_raw:{}'.format(toe_raw))
    test_run_id = toe_raw.split("/")[-1]

    # Create result file structure in shared storage
    result_folder = TOOL_FOLDER + test_run_id
    os.makedirs(result_folder, exist_ok=True)

    # Check for arguments
    MISC_DATA = MISC_DATA_FOLDER + test_run_id

    #/pod-storage/redactions/toe-miscdata/thingiling
    print("file: {}".format(MISC_DATA), flush=True)
    argument = ""
    encryptedSymetricInfo = {}
    encryptSymetricKey = {}
    if os.path.exists(MISC_DATA):
        with open(MISC_DATA, "r") as f:
            miscdata = json.load(f)
            encryptedSymetricInfo = miscdata["encryptedSymetricInfo"]
            encryptSymetricKey = miscdata["encryptSymetricKey"]
            if miscdata["argument"]:
                argument = miscdata["argument"]
    else:
        print("file NOT EXISTS {}:".format(MISC_DATA)) 

    with open(toe_raw, "rb") as f:
        encrypted_message = f.read()

    try:
        alls = encryptedSymetricInfo
        print(alls, flush=True)
        pub_keypair = get_key_from_json(alls["userPublicKey"])

        print("3", flush=True)
        secret = ecdh_priv.get_secret(pub_keypair)
        k = ecc_point_to_256_bit_key(secret)
        sharedKey = k.to_bytes(32, byteorder='big')
        print("4", flush=True)
        base64K = base64.urlsafe_b64encode(sharedKey).decode('ascii')
        print("sharedKey:"+base64K, flush=True)

        print("iv:" + alls["iv"], flush=True)
        iv = base64.urlsafe_b64decode(alls["iv"] + "==")

        cipher_and_auth_tag = base64.urlsafe_b64decode(alls["cipher"])
        print("cipher:" + alls["cipher"], flush=True)
        cipher = cipher_and_auth_tag[:-16]
        auth_tag = cipher_and_auth_tag[-16:]

        aes = AES.new(sharedKey, AES.MODE_GCM, nonce=iv)
        
        plain_text = aes.decrypt_and_verify(cipher, auth_tag)
    except Exception as e:
        print('this is bad {}'.format(e), flush=True)
        os.remove(toe_raw)
        with open(result_folder + "/progress", "w") as progress_file:
            progress_file.write("Failed to decrypt TOE, this is probably because a new version of the enclave has been released. Please reupload the TOE again to perform an analysis.")
        with open(result_folder + "/decryptfailed", "w") as progress_file:
            progress_file.write("True")
         
        # Go back to start of the loop
        continue

    symKeyRaw = json.loads(plain_text)
    symKey = base64.urlsafe_b64decode(symKeyRaw["k"] + "==")
    print("iv3:{}".format(symKeyRaw["iv"]), flush=True)
    myNonce = base64.urlsafe_b64decode(symKeyRaw["iv"] + "==")
    print("iv4 i make it this far myNonce{}".format(myNonce), flush=True)
    symKeyUsable = AES.new(symKey, AES.MODE_GCM, nonce=myNonce)

    print("{} {} {} hahahahah".format(myNonce, type(myNonce), len(myNonce)), flush=True)

    toe_cipher = encrypted_message[:-16]
    toe_auth_tag = encrypted_message[-16:]

    plain_toe = symKeyUsable.decrypt_and_verify(toe_cipher, toe_auth_tag)
    print('plain toe aint that the truth', flush=True)

    with open(READABLE_TOE + "decrypted.zip", "wb") as f:
        f.write(plain_toe)

    with zipfile.ZipFile(READABLE_TOE + "decrypted.zip", "r") as zip_ref:
        zip_ref.extractall(READABLE_TOE)

    with os.scandir(READABLE_TOE) as entries:
        for entry in entries:
            print(entry.name)

    # Start analysis
    with open(result_folder + "/progress", "w") as progress_file:
        progress_file.write("Started\n")

    try:
        full_report = run_tool(result_folder, argument, TOOLS_ARE_SILENT)
        full_report_string = json.dumps(full_report).encode('utf-8')
        reader_public_key = get_key_from_json(encryptSymetricKey)

        readerSharedKey = ecdh_priv.get_secret(reader_public_key)
        k = ecc_point_to_256_bit_key(readerSharedKey)
        sharedKey = k.to_bytes(32, byteorder='big')
        print("4", flush=True)
        aes = AES.new(sharedKey, AES.MODE_GCM, nonce=myNonce)
        ciphertext, authTag = aes.encrypt_and_digest(full_report_string)

        dsa = dict();

        dsa["iv"] = base64.urlsafe_b64encode(myNonce).decode('ascii')
        dsa["cipher"] = base64.urlsafe_b64encode(ciphertext + authTag).decode('ascii')  
        dsa["enclavePublicKey"] = public_key_string

        #Encrypt before writing
        with open(result_folder + "/result", "w") as result_file:
            json.dump(dsa, result_file)
        
        output_hash = dohash(full_report_string)

        with open("/dev/attestation/user_report_data", "wb") as user_report_data:
            user_report_data.write(output_hash)

        # generating the quote
        with open("/dev/attestation/quote", "rb") as q:
            quote = q.read()

        with open(result_folder + "/quote", "wb") as f:
            f.write(quote)

        with open(result_folder + "/progress", "w") as progress_file:
            progress_file.write("Done\n")
    except Exception as e:
        with open(result_folder + "/progress", "w") as progress_file:
            progress_file.write(str(e))

    # Clean up
    os.remove(toe_raw)
    #
    #toes_to_be_removed = glob.glob(READABLE_TOE + "*")
    #for toe in toes_to_be_removed:
    #    if os.path.isfile(toe):
    #        os.remove(toe)
    #    else:
    #        shutil.rmtree(toe)
