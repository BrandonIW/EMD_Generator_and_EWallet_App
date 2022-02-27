import hashlib
import pyfiglet
import re
import termcolor

from collections import defaultdict
from Crypto.Cipher import AES
from functools import wraps
from time import sleep

#TODO: Do we need a check to see if we can withdraw more than we have in the bank
#TODO: Test sending and receiving multiple back & forth amounts to test the counter

def main():
    ascii_title = pyfiglet.figlet_format("E-Transfer Wallet App", font="slant")
    print(termcolor.colored(ascii_title, color='green'))

    wallet_list = []
    wallet_functions = {
        1: _add_wallet,
        2: _show_wallet_menu,
        3: _list_wallets,
    }

    print("Please choose an option below\n")
    while True:
        _print_main_menu()
        option = input("Enter your choice: ")
        if option not in ["1", "2", "3", "4"]:
            print("Invalid option. Choose 1, 2, 3, or 4\n")
            sleep(2)
            continue
        elif option == "4":
            print("Exiting Program...")
            quit(0)

        wallet_functions[int(option)](wallet_list)


#####________Wallet Functions________######

def _show_wallet_menu(wallet_list):
    if not wallet_list:
        print("You must create at least one wallet before performing these functions")
        sleep(2)
        return
    wallet_choice = _print_wallet_menu(wallet_list)
    option_choice = _print_wallet_functions_menu(wallet_choice)
    _wallet_additional_functions(option_choice, wallet_choice)


def _list_wallets(wallet_list):
    for wallet in wallet_list:
        print(wallet)
    print("\n")
    sleep(2)


def _add_wallet(wallet_list):
    student_number = input("Please input your student number: ")
    bank_key = "F25D58A0E3E4436EC646B58B1C194C6B505AB1CB6B9DE66C894599222F07B893"
    wallet_key = _create_wallet_hex_key(student_number)
    wallet_id = student_number[-4::]
    wallet = Wallet(wallet_id, bank_key, wallet_key)
    wallet_list.append(wallet)
    print(f"New Wallet Created. Your Wallet ID is: {wallet_id}\n")
    sleep(1)


def _wallet_additional_functions(option, wallet):
    if option == 1:
        emd_token = input("Please enter EMD Token: ")
        wallet.recieve_from_bank(emd_token)
        sleep(1)

    elif option == 2:
        wallet.send_to_wallet()

    elif option == 3:
        sender_token = input("Please enter sender Wallet's token: ")
        wallet.receive_from_wallet(sender_token)

    elif option == 4:
        print(f"ID: {wallet.id}\nBalance: ${wallet.balance}\nKey: {wallet.wallet_key}\n"
              f"Synced Wallets: {[f'Wallet ID: {wal}, Counter: {count}' for wal, count in wallet.synced_wallets.items()]}")
        sleep(1)

    elif option == 5:
        return


#####________Menu Printing Functions________######

def _print_wallet_functions_menu(wallet):
    print(f"Working with: {wallet}\n")

    menu_options = {
        1: 'Deposit Bank EMD',
        2: 'Send Funds to another Wallet',
        3: 'Receive Funds from another Wallet',
        4: 'Show Information About Wallet',
        5: 'Back',
    }

    for key in menu_options.keys():
        print(key, '-', menu_options[key])
    print("\n")

    while True:
        option = int(input("Enter your choice: "))
        if option not in menu_options.keys():
            print("Invalid option. Choose the wallet number i.e. 0, 1, 2 etc.\n")
            sleep(1)
            continue
        return option


def _print_wallet_menu(wallet_list):
    print("Please select a wallet\n")

    menu_options = {num: wallet for num, wallet in enumerate(wallet_list)}
    for key in menu_options.keys():
        print(key, '-', menu_options[key])
    print("\n")

    while True:
        wallet_choice = int(input("Enter your choice: "))
        if wallet_choice not in menu_options.keys():
            print("Invalid option. Choose the wallet number i.e. 0, 1, 2 etc.\n")
            sleep(1)
            continue
        return menu_options[wallet_choice]


def _print_main_menu():
    menu_options = {
        1: 'Create a New Wallet',
        2: 'Send/Receive Funds or Show Information about a Wallet',
        3: 'List all Wallets',
        4: 'Exit Application',
    }

    for key in menu_options.keys():
        print(key, '-', menu_options[key])
    print("\n")


#####________Helper Functions________######

def hex_creator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        new_args = []
        for arg in [*args]:
            try:
                new_args.append(hex(int(arg))[2:].zfill(8))
            except ValueError:
                new_args.append(arg)
        return func(*new_args, **kwargs)

    return wrapper


def _create_wallet_hex_key(student_id):
    return hashlib.sha256(student_id.encode()).hexdigest()


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


def _validate_wallet_id(wallet_id):
    regex = re.compile(r'\d{4}')
    return True if regex.fullmatch(wallet_id) else False


class Wallet:

    def __init__(self, wallet_id, bank_key, wallet_key):
        self.id = wallet_id
        self.bank_key = bank_key
        self.wallet_key = wallet_key
        self.balance = 0
        self.synced_wallets = defaultdict(int)

    def __repr__(self):
        return f"Wallet-{self.id}"

    def sync_wallets(self, receiver_id):
        if receiver_id not in self.synced_wallets.keys():
            print("Wallet not yet synced. Syncing Wallet...")
            sleep(1)

            self.synced_wallets[receiver_id] = 0
            sync_token = self._token_generator(self.id, receiver_id, 0, 0, self.bank_key)

            print(f"Your Sync Token for Wallet {receiver_id} is: {sync_token}. Run this Token on the Recipient Wallet "
                  f"before proceeding with sending cash, else the recipient will not receive the cash\n")
            return False

        self.synced_wallets[receiver_id] += 1
        return self.synced_wallets[receiver_id]

    def recieve_from_bank(self, emd_token_hex):
        dollars_hex = self._decrypt_emd(emd_token_hex, self.wallet_key)
        self.balance += int(dollars_hex, 16)
        print(f"Deposited ${int(dollars_hex, 16)}. New wallet balance is ${self.balance}")

    def send_to_wallet(self):
        receiver_id = input("Input Wallet ID of Recipient: ")
        while True:
            if not _validate_wallet_id(receiver_id):
                receiver_id = input("Invalid Wallet ID. Must be 4 digits i.e. 7171. Try again: ")
                continue
            break

        counter = self.sync_wallets(receiver_id)
        if not counter:
            return

        dollar_amount = input(f"Input Amount to transfer (Current Balance is ${self.balance}): ")
        validated_dollar_amount = _validate_integer(dollar_amount)
        while not validated_dollar_amount:
            print("Invalid Dollar Amount. Please select a positive, whole dollar amount e.g. $99, $50, 10")
            sleep(2)
            dollar_amount = input("Input Dollar Amount to Create an EMD HEX Token: ")
            validated_dollar_amount = _validate_integer(dollar_amount)

        self.balance -= int(validated_dollar_amount)
        token = self._token_generator(self.id, receiver_id, validated_dollar_amount, counter, self.bank_key)
        print(f"Your token is: {token} | New account balance is ${self.balance}")

    def receive_from_wallet(self, token):
        token_bytes = bytes.fromhex(token)
        bank_key_bytes = bytes.fromhex(self.bank_key)

        cipher = AES.new(bank_key_bytes, AES.MODE_ECB)
        plaintext = cipher.decrypt(token_bytes).hex()
        sender_id, receiver_id, amount, counter = [int(plaintext[idex:idex + 8], 16) for idex in range(0, 32, 8)]

        if sender_id not in self.synced_wallets:
            self.synced_wallets[sender_id] = 1
            print(f"Wallet {sender_id} has been added to list of synced wallets")
            sleep(2)
            return

        if not self._validate_counter(sender_id, counter):
            print(f"Token contains counter of {counter}. Does not match wallet {sender_id}'s counter of "
                  f"{self.synced_wallets[sender_id]}. Possible replay attack.")
            sleep(1)
            print(f"Dropping data and will not deposit. Current Wallet Balance: ${self.balance}")
            return

        if str(receiver_id) != self.id:
            print(f"Token's recipient ID of {receiver_id} does not match Wallet ID of {self.id}. Dropping Token")
            return

        self.synced_wallets[sender_id] += 1
        self.balance += amount
        print(f"Deposited ${amount}")
        sleep(1)
        print(f"Your new Wallet balance is: {self.balance}")

    def _validate_counter(self, sender_id, counter):
        return True if self.synced_wallets[sender_id] == counter else False

    @staticmethod
    @hex_creator
    def _token_generator(sender_id, receiver_id, amount, counter, bank_key):
        pt_block = sender_id + receiver_id + amount + counter

        pt_block_bytes = bytes.fromhex(pt_block)
        bank_key_bytes = bytes.fromhex(bank_key)

        cipher = AES.new(bank_key_bytes, AES.MODE_ECB)
        print("Creating Token...")
        sleep(1)
        ciphertext = cipher.encrypt(pt_block_bytes)

        return ciphertext.hex()

    @staticmethod
    def _decrypt_emd(emd_token_hex, wallet_key_hex):
        wallet_key_bytes = bytes.fromhex(wallet_key_hex)
        emd_in_bytes = bytes.fromhex(emd_token_hex)

        cipher = AES.new(wallet_key_bytes, AES.MODE_ECB)
        plaintext = cipher.decrypt(emd_in_bytes)

        return plaintext.hex()


if __name__ == "__main__":
    main()
