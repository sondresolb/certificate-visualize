import requests
import json
import visualize_exceptions as vis_ex
from requests.exceptions import HTTPError


def evaluate_cipher(cipher, cipher_info):
    return cipher_info[cipher] if cipher in cipher_info else "unknown"


def get_cipher_suite_info():
    cipher_info = {}
    req_url = f"https://ciphersuite.info/api/cs/software/openssl"

    try:
        req_res = requests.get(req_url)
        req_res.raise_for_status()

        complete_cipher_list = json.loads(req_res.content)["ciphersuites"]

        for cipher_dict in complete_cipher_list:
            for _, val in cipher_dict.items():
                items = {}
                items["security"] = val["security"]
                items["kex_algorithm"] = val["kex_algorithm"]
                items["auth_algorithm"] = val["auth_algorithm"]
                items["enc_algorithm"] = val["enc_algorithm"]
                items["hash_algorithm"] = val["hash_algorithm"]
                cipher_info[val["openssl_name"]] = items

        return cipher_info

    except HTTPError as httpe:
        raise vis_ex.RequestResponseError(
            f"Failed to fetch cipher information from {req_url}: {str(httpe)}")
    except Exception as e:
        raise vis_ex.CipherFetchingError(
            ("Unhandled exception occured while processing cipher"
             f"information: {str(e)}"))
