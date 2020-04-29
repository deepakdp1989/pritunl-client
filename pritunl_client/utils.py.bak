from pritunl_client.constants import *
from pritunl_client.exceptions import *

if PLATFORM != SHELL:
    from pritunl_client import interface

import json
import time
import uuid
import hmac
import hashlib
import base64
import requests
import subprocess
import re

_disk_device_match = re.compile(r'(\/dev\/[a-z0-9]*)')
_disk_size_match = re.compile(r'([0-9]*) bytes')

def check_output(*args, **kwargs):
    if 'stdout' in kwargs or 'stderr' in kwargs:
        raise ValueError('Output arguments not allowed, it will be overridden')

    process = subprocess.Popen(
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,  *args, **kwargs)

    stdoutdata, stderrdata = process.communicate()
    return_code = process.poll()

    if return_code:
        raise subprocess.CalledProcessError(
            return_code, kwargs.get('args', args[0]), output=stdoutdata)

    return stdoutdata

def check_call_silent(*args, **kwargs):
    if 'stdout' in kwargs or 'stderr' in kwargs:
        raise ValueError('Output arguments not allowed, it will be overridden')

    process = subprocess.Popen(stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        *args, **kwargs)
    return_code = process.wait()

    if return_code:
        cmd = kwargs.get('args', args[0])
        raise subprocess.CalledProcessError(return_code, cmd)

def auth_request(method, host, path, token, secret,
        json_data=None, timeout=None):
    if json_data:
        headers = {'Content-Type', 'application/json'}
        data = json.dumps(json_data)
    else:
        headers = None
        data = None
    auth_timestamp = str(int(time.time()))
    auth_nonce = uuid.uuid4().hex
    auth_string = '&'.join([token, auth_timestamp, auth_nonce,
        method.upper(), path] + ([data] if data else []))

    auth_signature = base64.b64encode(hmac.new(
        secret.encode(), auth_string, hashlib.sha512).digest())
    auth_headers = {
        'Auth-Token': token,
        'Auth-Timestamp': auth_timestamp,
        'Auth-Nonce': auth_nonce,
        'Auth-Signature': auth_signature,
    }
    if headers:
        auth_headers.update(headers)
    return getattr(requests, method.lower())(
        host + path,
        headers=auth_headers,
        data=data,
        timeout=timeout,
        verify=False,
    )

def get_logo():
    if PLATFORM == LINUX:
        logo_path = interface.lookup_icon('pritunl_client')
        if logo_path:
            return logo_path
    return LOGO_DEFAULT_PATH

def get_connected_logo():
    if PLATFORM == LINUX:
        logo_path = interface.lookup_icon('pritunl_client_connected')
        if logo_path:
            return logo_path
    return CONNECTED_LOGO_DEFAULT_PATH

def get_disconnected_logo():
    if PLATFORM == LINUX:
        logo_path = interface.lookup_icon('pritunl_client_disconnected')
        if logo_path:
            return logo_path
    return DISCONNECTED_LOGO_DEFAULT_PATH

def write_env(env_data):
    env_data['PRITUNL_CLIENT_ENV'] = True
    env_path = os.path.join(TMP_DIR, uuid.uuid4().hex)
    with open(env_path, 'w') as env_file:
        os.chmod(env_path, 0200)
        env_file.write(json.dumps(env_data))
    return '--env=' + env_path

def generate_secret():
    return re.sub(r'[\W_]+', '', base64.b64encode(os.urandom(64)))[:32]
