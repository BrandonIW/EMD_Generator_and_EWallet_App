import hashlib
import pyfiglet
import re
import termcolor

from Crypto.Cipher import AES
from time import sleep


def main():
    ascii_title = pyfiglet.figlet_format("EMD Token Generator", font="standard")
    print(termcolor.colored(ascii_title, color='blue'))

    while True:
        dollar_hex = _dollar_to_32bithex(input("Input Dollar Amount to Create an EMD HEX Token: "))
        wallet_key_hex = _create_wallet_hex_key(input("Input Student ID of Wallet Owner: "))
        emd_token = _create_emd(dollar_hex, wallet_key_hex)

        print(f"Your EMD Token is: {emd_token}")
        sleep(2)

        if not _continue():
            print("Exiting program..."); sleep(2)
            break


def _continue():
    while True:
        response = input("Do you want to generate another EMD Token? (y/n): ").lower()
        if response in ['n', 'no']:
            return False
        elif response in ['y', 'yes']:
            return True
        else:
            print("Input Yes/Y or No/N"); sleep(1)


def _create_wallet_hex_key(student_id):
    return hashlib.sha256(student_id.encode()).hexdigest()


def _create_emd(dollars_hex, wallet_key_hex):
    wallet_key_bytes = bytes.fromhex(wallet_key_hex)
    dollars_bytes = bytes.fromhex(dollars_hex)

    cipher = AES.new(wallet_key_bytes, AES.MODE_ECB)
    print("Creating EMD Token..."); sleep(2)
    ciphertext = cipher.encrypt(dollars_bytes)

    return ciphertext.hex()


def _dollar_to_32bithex(value):
    validated_value = _validate_integer(value)

    while not validated_value:
        print("Invalid Dollar Amount. Please select a positive dollar amount e.g. $99, $50, 10")
        sleep(2)
        value = input("Input Dollar Amount to Create an EMD HEX Token: ")
        validated_value = _validate_integer(value)

    return hex(int(validated_value))[2:].zfill(32)


def _validate_integer(value):
    regex = re.compile(r'\$?(?<!-)([0-9]+[.,0-9]*)')

    if not _check_positive(value):
        return False
    try:
        extracted_value = regex.search(value).group(1)
    except AttributeError:
        return False
    return extracted_value


def _check_positive(num):
    try:
        num = num.strip("$")
        ivalue = int(num)
    except ValueError:
        return False
    if ivalue < 0:
        return False
    return ivalue


if __name__ == "__main__":
    main()
