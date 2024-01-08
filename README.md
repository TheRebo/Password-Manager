# Password-Manager

This script is useful for storing your Passwords.


The features of this script are:

- Stores Passwords and then encrypts them with the strongest method.
- View Passwords that you have saved.
- Delete Passwords that you have saved.
- Have Master Passwords (which you must create first) to access all these features.


Installation:

- Requires Python (maybe all versions will work, but I don't know (I'm using Python 3.11)).
1. git clone https://github.com/TheRebo/Password-Manager.git
2. pip install -r requirements.txt / pip3 install -r requirements.txt


Possible known bugs(?):

- Sometimes each device may have different encryption and decryption algorithms, so sometimes passwords that have been encrypted on certain devices, when transferred to other devices will be detected or not detected.

- Sometimes the master password that we have created after some time, somehow can not be detected.

The above bug is not necessarily true, because I still haven't done tests to explore it, but there is a possibility that the bug is true. If the bug is true, please let me know in the "Issues" section, and I apologize for the inconvenience =(


Changelog:

- 1.1.0 = Added Color and A Little Improvement
- 1.0.2 = A Little Bugfix and A Little Improvement
- 1.0.1 = A Little Bugfix
- 1.0.0 = Initial Release


NOTES!!! (Please read this so that there is no misunderstanding) :

This Script will create 3 files after you create your Master Password.
The list of files created by the Script are:

- key.dat (To save the key that will be used when decrypting the password)
- master_password.dat (To save the Master Password you entered)
- passwords.dat (To save a list of your saved passwords, along with encrypted passwords)

So... DON'T DELETE THE FILES, IF YOU DON'T WANT TO LOSE YOUR PASSWORDS DATA!!!.

DISCLAIMER!!! - THIS SCRIPT WAS CREATED WITH THE HELP OF AI!!!
