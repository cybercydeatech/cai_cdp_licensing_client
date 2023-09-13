import base64
import json
from datetime import datetime

import requests
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad


def get_token():
    url = "https://localhost:8553/security/login"

    payload = json.dumps({
        "username": "teye_admin",
        "password": "admin@TRIAM_TI"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)

    ou = json.loads(response.text)
    return ou.get('token')


def verify_license(license):
    print('verifying the key')
    url = "https://localhost:8553/license/license-verify"
    import uuid
    mac = uuid.getnode()
    mac_address_hex = ':'.join(
        ['{:02x}'.format((mac >> elements) & 0xff) for elements in range(0, 8 * 6, 8)][::-1])
    print(mac_address_hex)

    # import subprocess
    # serial = subprocess.check_output('wmic bios get serialnumber').decode("utf-8")
    # print('mac is:' + str(mac) + ' serial is:' + serial)
    body = {'licenseKey': str(base64.b64encode(license.encode("utf-8")).decode("utf-8")), 'machineMac': mac_address_hex,

            'machineSerial': 'kjkjkhj'}

    headers = {'Authorization': 'Bearer ' + get_token()}
    response = requests.post(url, json=body, headers=headers, verify=False)
    print(response.text)
    if response.status_code == 200:
        response = json.loads(response.text)
        if 'verified' in response:
            limit = abs((datetime.strptime(response.get('deactivation'),
                                           "%Y-%m-%d") - datetime.now()).days)
            if limit > 0:
                store_to_file(encrypt_data(limit), encrypt_data(response.get('deactivation')),
                              encrypt_data(datetime.now()))


def encrypt_data(data):
    key = b'keyti31@march$TI'
    data = str(data)
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    padded_data = pad(data.encode(), cipher.block_size)
    return str(base64.b64encode(cipher.encrypt(padded_data)), encoding='utf-8')


def store_to_file(limit, deactivation, test_date):
    f = open("license.lic", "w")
    f.write(encrypt_data('limit') + ':' + limit + '\n')
    f.write(encrypt_data('deactivation') + ':' + deactivation + '\n')
    f.write(encrypt_data('test_date') + ':' + test_date + '\n')
    f.close()
    print("Congratulations: License file generated successfully")


license = input("Enter the license key: ")
if len(license) == 49:
    verify_license(license)
