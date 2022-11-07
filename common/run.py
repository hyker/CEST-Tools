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

print("DEBUG privateKey:" + key["d"])

def ecc_point_to_256_bit_key(point):
    return point.x

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
    # Check if there is new toe to test
    toe_list = glob.glob(POLL_FOLDER + "*")

    if len(toe_list) == 0:
        sleep(20)
        continue

    # Unzip toe
    toe_raw = toe_list[0]
    test_run_id = toe_raw.split("/")[-1]

    # Create result file structure in shared storage
    result_folder = TOOL_FOLDER + test_run_id
    os.makedirs(result_folder, exist_ok=True)

    # Check for arguments
    MISC_DATA = MISC_DATA_FOLDER + test_run_id
    argument = ""
    encryptedSymetricInfo = {}
    if os.path.exists(MISC_DATA):
        with open(MISC_DATA, "r") as f:
            miscdata = json.load(f)
            encryptedSymetricInfo = miscdata["encryptedSymetricInfo"]
            if miscdata["argument"]:
                argument = miscdata["argument"]

    with open(toe_raw, "rb") as f:
        encrypted_message = f.read()

    try:
        alls = encryptedSymetricInfo
        pub = alls['userPublicKey']

        pubx = int.from_bytes(base64.urlsafe_b64decode(
            pub["x"] + '=='), byteorder="big")
        puby = int.from_bytes(base64.urlsafe_b64decode(
            pub["y"] + '=='), byteorder="big")
        curve = registry.get_curve('secp256r1')  # AKA "P-256"
        pub_point = ec.Point(curve, x=pubx, y=puby)
        pub_keypair = ec.Keypair(curve, pub=pub_point)

        secret = ecdh_priv.get_secret(pub_keypair)
        k = ecc_point_to_256_bit_key(secret)
        sharedKey = k.to_bytes(32, byteorder='big')

        base64K = base64.urlsafe_b64encode(sharedKey).decode('ascii')
        print("sharedKey:"+base64K)

        iv = base64.urlsafe_b64decode(alls["iv"] + "==")
        print("iv:" + alls["iv"])

        cipher_and_auth_tag = base64.urlsafe_b64decode(alls["cipher"])
        print("cipher:" + alls["cipher"])
        cipher = cipher_and_auth_tag[:-16]
        auth_tag = cipher_and_auth_tag[-16:]

        aes = AES.new(sharedKey, AES.MODE_GCM, nonce=iv)
        
        plain_text = aes.decrypt_and_verify(cipher, auth_tag)
    except Exception as e:
        os.remove(toe_raw)
        with open(result_folder + "/progress", "w") as progress_file:
            progress_file.write("Failed to decrypt TOE, this is probably because a new version of the enclave has been released. Please reupload the TOE again to perform an analysis.")
        with open(result_folder + "/decryptfailed", "w") as progress_file:
            progress_file.write("True")
        
        # Go back to start of the loop
        continue


    symKeyRaw = json.loads(plain_text)
    symKey = base64.urlsafe_b64decode(symKeyRaw["k"] + "==")
    symKeyUsable = AES.new(symKey, AES.MODE_GCM, nonce=bytes(32))

    toe_cipher = encrypted_message[:-16]
    toe_auth_tag = encrypted_message[-16:]

    plain_toe = symKeyUsable.decrypt_and_verify(toe_cipher, toe_auth_tag)

    with open(toe_raw + "decrypted", "wb") as f:
        f.write(plain_toe)

    with zipfile.ZipFile(toe_raw + "decrypted", "r") as zip_ref:
        zip_ref.extractall(READABLE_TOE)

    # Start analysis
    with open(result_folder + "/progress", "w") as progress_file:
        progress_file.write("Started\n")

    try:
        run_tool(result_folder, argument, TOOLS_ARE_SILENT)
        with open(result_folder + "/progress", "w") as progress_file:
            progress_file.write("Done\n")
    except Exception as e:
        with open(result_folder + "/progress", "w") as progress_file:
            progress_file.write(str(e))

    # Clean up
    os.remove(toe_raw)
    os.remove(toe_raw + "decrypted")

    toes_to_be_removed = glob.glob(READABLE_TOE + "*")
    for toe in toes_to_be_removed:
        if os.path.isfile(toe):
            os.remove(toe)
        else:
            shutil.rmtree(toe)
