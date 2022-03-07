# What is EMD_Generator & E-Wallet App?
These are two complimentary programs running in Python 3.9 built to simulate the transfer of cash between wallets. 

The EMD_Token generator is a program made to simulate the creation of a bank's Electronic Money Draft. It functions by creating an encrypted hex value that represents a recipient Wallet, and the amount of money to be deposited into that specific Wallet. This program primarily functions to complement the E-Wallet App.

The E-Wallet App allows the user to create a Wallet in an Object-Orientated approach. Each Wallet is given a balance, ID, Wallet and bank keys (used for encryption and decryption of tokens), and a list of synchronized Wallets with which we can transfer funds to and from. This program simulates the transfer of money between Wallets by allowing the user to first synchronize with a recpient Wallet ID. Once synchronized, we can simulate the transfer of money by encrypting a token value that represents the recipient Wallet, amount of money, and the sending Wallet. We also add in an addional Counter value that is checked between fund transfers to simulate checking for replay attacks.

The recipient Wallet then decrypts the token, runs through various checks, and deposites the money into that Wallet's balance. 

## Compatability
Runs on Python 3.9


## Options
* No options needed. Just run the program directly 

## Quickstart
1) Download .ZIP File and extract to a directory of your choice
2) ```python3 E-WalletApp.py``` or ```python3 emd_creator.py```


### Example Output
![image](https://user-images.githubusercontent.com/77559638/157113402-0c05cf02-4056-4e47-8d74-6850603aca2f.png)

![image](https://user-images.githubusercontent.com/77559638/157113468-b1914146-f29f-476b-bb24-bc46302a7557.png)



