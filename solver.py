import requests
import base64
import logging
import re
import json
import msgpack
import click

logging.basicConfig(
    level="INFO",
    format="[%(asctime)s]: %(name)s - %(levelname)s:%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler()],
)

ENCRYPTED_PATH = "encrypted_path"
ENCRYPTION_METHOD = "encryption_method"    

class DecryptionHelper:
    def nothing(self, data: str, **kwargs):
        return data
    
    def b64(self, data: str, **kwargs) -> str:
        return base64.b64decode(data).decode()

    def non_hex_character(self, data: str, **kwargs) -> str:
        return re.sub(r'[^0-9a-fA-F]', '', data)

    def ascii_mover(self, data: str, **kwargs):
        encryption_method = kwargs["encryption_method"]
        moved_by = int(encryption_method.split(" to ASCII value of each")[0].split(" ")[1])
        cache = {}
        ans = ""
        for char in data:
            ans += cache.setdefault(char, chr(ord(char)-moved_by))
        return ans

    def custom_hexset(self, data: str, **kwargs):
        encryption_method = kwargs["encryption_method"]
        hexset = encryption_method.split("encoded it with custom hex character set ")[1]
        standard_hex_set = "0123456789abcdef"

        # Create a mapping dictionary
        custom_to_standard = {custom: standard for custom, standard in zip(hexset, standard_hex_set)}
        
        # Replace characters in the encrypted path using the mapping
        return ''.join(custom_to_standard.get(char, char) for char in data)


    def scrambled_b64_msgpack(self, data: str, **kwargs):
        encryption_method = kwargs["encryption_method"]
        scrambled_msgpack = encryption_method.split(": ")[1]
        # TODO: Add msgpack b64 decoding and 
        return "abcdefghijklmnopqrstuvywxyz"


class Solver:
    url = "https://google.com"
    decryptor = DecryptionHelper()

    encryption_dict = {
        "nothing": decryptor.nothing,
        "encoded as base64": decryptor.b64,
        "inserted some non-hex characters": decryptor.non_hex_character,
        "ASCII mover": decryptor.ascii_mover,
        "custom hex set": decryptor.custom_hexset,
        "scrambled_b64_msgpack": decryptor.scrambled_b64_msgpack,
    }

    def __init__(self, url) -> None:
        self.url = url
    
    def decrypt(self, encrypted_path: str, encryption_method: str, **kwargs):
        x = self.encryption_dict.get(encryption_method, None)
        if x is not None:
            return self.encryption_dict[encryption_method](encrypted_path)

        if "ASCII value of each character" in encryption_method:
            return self.encryption_dict["ASCII mover"](encrypted_path, encryption_method=encryption_method)
        elif "encoded it with custom hex" in encryption_method:
            return self.encryption_dict["custom hex set"](encrypted_path, encryption_method=encryption_method)
        elif "scrambled! original positions as base64 encoded messagepack: " in encryption_method:
            return self.encryption_dict["scrambled_b64_msgpack"](encrypted_path, encryption_method=encryption_method)
        else:
            raise TypeError(f"Unknown {encryption_method=}!")
            
    
    def _print_response(self, response: dict):
        print ("###")
        print (json.dumps(response, indent=4))
        print ("###")

    def _http_get(self, url: str) -> dict:
        try:
            resp = requests.get(url=url)
            if resp.status_code != 200:
                raise Exception(f"Failed to connect to {self.url=}")
            return resp.json()
        except Exception as e:
            raise

    def _get_path_and_method(self, url: str, split_task=True) -> dict:
        try:
            resp = requests.get(url=url)
            if resp.status_code != 200:
                raise Exception(f"Failed to connect to {self.url=}")
            data = resp.json()
            if split_task:
                data[ENCRYPTED_PATH] = self._split_task_name(data[ENCRYPTED_PATH])

            return data[ENCRYPTED_PATH], data[ENCRYPTION_METHOD]
        except Exception as e:
            raise

    def _split_task_name(self, task_name):
        return task_name.split("_")[1]

    def get_level1(self, email: str) -> tuple[str, str]:
        return self._get_path_and_method(url=f"{self.url}/{email}", split_task=False)
    
    def get_level2(self, path: str) -> tuple[str, str]:
        return self._get_path_and_method(url=f"{self.url}/{path}")

    def get_level_with_path_prefix(self, path: str) -> tuple[str, str]:
        return self._get_path_and_method(f"{self.url}/task_{path}")
   
@click.command()
@click.option('--url', required=True, help="Please provide the URL")
@click.option('--email', required=True, help="Please provide the email")
def main(url, email):
    exercise = Solver(url)
    level1_path = exercise.decrypt(*exercise.get_level1(email))
    level2_path = exercise.decrypt(*exercise.get_level2(level1_path))
    level3_path = exercise.decrypt(*exercise.get_level_with_path_prefix(level2_path))
    level4_path = exercise.decrypt(*exercise.get_level_with_path_prefix(level3_path))
    level5_path = exercise.decrypt(*exercise.get_level_with_path_prefix(level4_path))
    level6_path = exercise.decrypt(*exercise.get_level_with_path_prefix(level5_path))
    print (f"{level6_path=}")

if __name__ == '__main__':
    main()