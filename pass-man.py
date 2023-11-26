# Smart Password Manager
# A Python script that lets you store, view, and delete passwords for different services

# Import the modules we need
import os # For file operations
import time
import hashlib # For hashing the master password
import cryptography # For encrypting and decrypting the passwords
from cryptography.fernet import Fernet # For generating the encryption key
import pickle # For saving and loading the passwords file
import random # For generating random passwords
import string # For creating the password characters

# Define some constants
PASSWORDS_FILE = "passwords.dat" # The name of the file where we store the passwords
MASTER_PASSWORD_FILE = "master_password.dat" # The name of the file where we store the hashed master password
KEY_FILE = "key.dat" # The name of the file where we store the encryption key

def clear_and_sleep():
    time.sleep(1)
    os.system('clear')
    time.sleep(1)

# Define some functions
def hash_password(password):
    # This function takes a password and returns its hashed value using SHA-256 algorithm
    # We use this function to create and verify the master password
    password = password.encode() # Convert the password to bytes
    hashed_password = hashlib.sha256(password).hexdigest() # Hash the password using SHA-256 and get the hexadecimal value
    return hashed_password # Return the hashed password

def generate_key():
    # This function generates a random encryption key using Fernet
    # We use this function to create the key file when the script runs for the first time
    key = Fernet.generate_key() # Generate a random key
    return key # Return the key

def load_key():
    # This function loads the encryption key from the key file
    # We use this function to access the key when we need to encrypt or decrypt the passwords
    with open(KEY_FILE, "rb") as file: # Open the key file in binary mode
        key = file.read() # Read the key
    return key # Return the key

def encrypt_password(password):
    # This function takes a password and returns its encrypted value using Fernet
    # We use this function to encrypt the passwords before saving them to the passwords file
    key = load_key() # Load the key
    f = Fernet(key) # Create a Fernet object
    password = password.encode() # Convert the password to bytes
    encrypted_password = f.encrypt(password) # Encrypt the password using the key
    return encrypted_password # Return the encrypted password

def decrypt_password(encrypted_password):
    # This function takes an encrypted password and returns its decrypted value using Fernet
    # We use this function to decrypt the passwords when we want to view them
    key = load_key() # Load the key
    f = Fernet(key) # Create a Fernet object
    decrypted_password = f.decrypt(encrypted_password) # Decrypt the password using the key
    decrypted_password = decrypted_password.decode() # Convert the password to string
    return decrypted_password # Return the decrypted password

def generate_password(length):
    # This function generates a random password of a given length
    # We use this function to create a strong password for the user if they want
    characters = string.ascii_letters + string.digits + string.punctuation # Create a string of all possible characters
    password = "" # Initialize an empty password
    for i in range(length): # Loop for the given length
        password += random.choice(characters) # Add a random character to the password
    return password # Return the password

def save_passwords(passwords):
    # This function saves the passwords dictionary to the passwords file
    # We use this function to update the passwords file whenever we add or delete a password
    with open(PASSWORDS_FILE, "wb") as file: # Open the passwords file in binary mode
        pickle.dump(passwords, file) # Dump the passwords dictionary to the file

def load_passwords():
    # This function loads the passwords dictionary from the passwords file
    # We use this function to access the passwords whenever we need them
    with open(PASSWORDS_FILE, "rb") as file: # Open the passwords file in binary mode
        passwords = pickle.load(file) # Load the passwords dictionary from the file
    return passwords # Return the passwords

def create_master_password():
    # This function creates the master password and saves its hashed value to the master password file
    # We use this function when the script runs for the first time
    clear_and_sleep()
    print("[•] Welcome to the Smart Password Manager! 🙌") # Greet the user
    print("[•] This is a Python script that lets you store, view, and delete passwords for different services.") # Explain the purpose of the script
    print("[•] To get started, you need to create a Master Password. This password will be used to access your stored passwords later.") # Explain the need for a master password
    print("[•] Please make sure you remember your Master Password, as there is no way to recover it if you forget it. 😬\n") # Warn the user about the importance of the master password
    while True: # Loop until the user enters a valid master password
        time.sleep(1)
        master_password = input("[?] Enter your Master Password: ") # Ask the user to enter the master password
        if len(master_password) < 8: # Check if the master password is too short
            time.sleep(1)
            print("\n[!] Your Master Password is too weak. It should be at least 8 characters long. 😕\n") # Tell the user to enter a longer password
        else: # If the master password is long enough
            confirm_password = input("[?] Confirm your Master Password: ") # Ask the user to confirm the master password
            if master_password == confirm_password: # Check if the confirmation matches the master password
                time.sleep(3)
                print("\n[✓] Your Master Password has been created successfully! 🎉") # Congratulate the user
                time.sleep(2)
                clear_and_sleep()
                hashed_password = hash_password(master_password) # Hash the master password
                with open(MASTER_PASSWORD_FILE, "w") as file: # Open the master password file in write mode
                    file.write(hashed_password) # Write the hashed master password to the file
                break # Break the loop
            else: # If the confirmation does not match the master password
                time.sleep(1)
                print("\n[!] Your Master Passwords do not match. Please try again. 😞\n") # Tell the user to enter the master password again

def verify_master_password():
    # This function verifies the master password and returns True or False
    # We use this function to check if the user enters the correct master password
    with open(MASTER_PASSWORD_FILE, "r") as file: # Open the master password file in read mode
        hashed_password = file.read() # Read the hashed master password from the file
    time.sleep(1)
    master_password = input("\n[?] Enter your Master Password: ") # Ask the user to enter the master password
    if hash_password(master_password) == hashed_password: # Check if the hashed master password matches the stored one
        time.sleep(1)
        print("\n[✓] Your Master Password is correct. 👍") # Tell the user that the master password is correct
        time.sleep(1)
        return True # Return True
    else: # If the hashed master password does not match the stored one
        time.sleep(1)
        print("\n[!] Your Master Password is wrong. 😟") # Tell the user that the master password is wrong
        time.sleep(1)
        return False # Return False

def add_password():
    # This function adds a new password to the passwords dictionary and saves it to the passwords file
    # We use this function to let the user store a new password for a new service
    passwords = load_passwords() # Load the passwords dictionary
    time.sleep(1)
    service = input("\n[?] Enter the name of the service: ") # Ask the user to enter the name of the service
    if service in passwords: # Check if the service already exists in the passwords dictionary
        time.sleep(1)
        print(f"\n[!] You already have a password for {service}. 😮") # Tell the user that they already have a password for the service
        time.sleep(1)
        print(f"[!] Your password for {service} is {decrypt_password(passwords[service])} 🔑") # Show the user their password for the service
        time.sleep(1)
        print("\n[!] If you want to change your password for this service, please delete it first and then add a new one. 🙏") # Tell the user how to change their password for the service
        time.sleep(1)
    else: # If the service does not exist in the passwords dictionary
        time.sleep(1)
        choice = input("\n[?] Do you want to create a random password for this service? (y/n): ") # Ask the user if they want to create a random password for the service
        time.sleep(1)
        if choice.lower() == "y": # If the user wants to create a random password
            length = int(input("\n[?] Enter the length of the password (8-32): ")) # Ask the user to enter the length of the password
            if length < 8 or length > 32: # Check if the length is valid
                time.sleep(1)
                print("\n[!] The length of the password should be between 8 and 32. 😕") # Tell the user that the length is invalid
                time.sleep(1)
                return # Return from the function
            password = generate_password(length) # Generate a random password of the given length
            time.sleep(1)
            print(f"\n[✓] Your random password for {service} is {password} 🎲") # Show the user their random password for the service
            time.sleep(1)
        elif choice.lower() == "n": # If the user does not want to create a random password
            time.sleep(1)
            password = input("\n[?] Enter your password for this service: ") # Ask the user to enter their password for the service
            time.sleep(1)
        else: # If the user enters something else
            print("\n[!] Invalid choice. Please enter y or n. 😕") # Tell the user that their choice is invalid
            return # Return from the function
        encrypted_password = encrypt_password(password) # Encrypt the password
        passwords[service] = encrypted_password # Add the service and the encrypted password to the passwords dictionary
        save_passwords(passwords) # Save the passwords dictionary to the passwords file
        time.sleep(1)
        print(f"\n[✓] Your password for {service} has been saved successfully! 🙌") # Congratulate the user

def view_passwords():
    # This function shows the user the list of services and passwords they have saved
    # We use this function to let the user see their stored passwords
    passwords = load_passwords() # Load the passwords dictionary
    if passwords: # Check if the passwords dictionary is not empty
        time.sleep(1)
        print("\n[•] Here are your stored passwords: 📝\n") # Tell the user that they have stored passwords
        time.sleep(1)
        print("-" * 50) # Print a separator line
        for service, encrypted_password in passwords.items(): # Loop through the passwords dictionary
            password = decrypt_password(encrypted_password) # Decrypt the password
            print(f"{service}: {password}") # Print the service and the password
        print("-" * 50) # Print a separator line
        time.sleep(1)
        choice = input("\n[?] Done? (y or any key): ")
        time.sleep(1)
        if choice.lower == "y":
            return
        else:
            return
    else: # If the passwords dictionary is empty
        time.sleep(1)
        print("\n[!] You have no stored passwords. 😢") # Tell the user that they have no stored passwords

def delete_passwords():
    # This function deletes one or more passwords from the passwords dictionary and saves it to the passwords file
    # We use this function to let the user delete their passwords for the services they no longer use
    passwords = load_passwords() # Load the passwords dictionary
    if passwords: # Check if the passwords dictionary is not empty
        time.sleep(1)
        print("\n[•] Here are your stored passwords: 📝\n") # Tell the user that they have stored passwords
        print("-" * 50) # Print a separator line
        for i, (service, encrypted_password) in enumerate(passwords.items(), 1): # Loop through the passwords dictionary with index
            password = decrypt_password(encrypted_password) # Decrypt the password
            print(f"{i}. {service}: {password}") # Print the index, the service and the password
        print("-" * 50) # Print a separator line
        print("")
        time.sleep(1)
        choice = input("[?] Enter the number(s) of the password(s) you want to delete (separated by comma): ") # Ask the user to enter the number(s) of the password(s) they want to delete
        numbers = choice.split(",") # Split the choice by comma
        services = [] # Initialize an empty list of services
        for number in numbers: # Loop through the numbers
            try: # Try to
                number = int(number) # Convert the number to integer
                service = list(passwords.keys())[number - 1] # Get the service name by the index
                services.append(service) # Add the service name to the list of services
            except: # If there is an error
                time.sleep(1)
                print(f"\n[!] {number} is not a valid number. 😕") # Tell the user that the number is invalid
                time.sleep(1)
                return # Return from the function
        time.sleep(1)
        confirm = input(f"\n[?] Are you sure you want to delete the password(s) for {', '.join(services)}? (y/n): ") # Ask the user to confirm their choice
        if confirm.lower() == "y": # If the user confirms
            for service in services: # Loop through the services
                passwords.pop(service) # Remove the service and the password from the passwords dictionary
            save_passwords(passwords) # Save the passwords dictionary to the passwords file
            time.sleep(1)
            print(f"\n[✓] The password(s) for {', '.join(services)} have been deleted successfully! 🗑️") # Congratulate the user
            time.sleep(1)
        elif confirm.lower() == "n": # If the user cancels
            time.sleep(1)
            print("\n[✓] The deletion has been canceled. 😌") # Tell the user that the deletion has been canceled
            time.sleep(1)
        else: # If the user enters something else
            time.sleep(1)
            print("\n[!] Invalid choice. Please enter y or n. 😕") # Tell the user that their choice is invalid
            time.sleep(1)
    else: # If the passwords dictionary is empty
        time.sleep(1)
        print("\n[!] You have no stored passwords. 😢") # Tell the user that they have no stored passwords

def main():
    # This function is the main entry point of the script
    # We use this function to run the script and handle the user's choices
    if not os.path.exists(MASTER_PASSWORD_FILE): # Check if the master password file does not exist
        create_master_password() # Create the master password
        key = generate_key() # Generate the encryption key
        with open(KEY_FILE, "wb") as file: # Open the key file in binary mode
            file.write(key) # Write the key to the file
        passwords = {} # Initialize an empty passwords dictionary
        save_passwords(passwords) # Save the passwords dictionary to the passwords file
    while True: # Loop until the user exits the script
        clear_and_sleep()
        print("[•] Welcome to the Smart Password Manager! 🙌") # Greet the user
        print("[•] What do you want to do?\n") # Ask the user what they want to do
        print("1. Add a new password") # Print the first option
        print("2. View your stored passwords") # Print the second option
        print("3. Delete a password") # Print the third option
        print("4. Exit the script") # Print the fourth option
        time.sleep(1)
        choice = input("\n[?] Enter your choice (1-4): ") # Ask the user to enter their choice
        if choice == "1": # If the user chooses the first option
            if verify_master_password(): # Verify the master password
                add_password() # Add a new password
        elif choice == "2": # If the user chooses the second option
            if verify_master_password(): # Verify the master password
                view_passwords() # View the stored passwords
        elif choice == "3": # If the user chooses the third option
            if verify_master_password(): # Verify the master password
                delete_passwords() # Delete a password
        elif choice == "4": # If the user chooses the fourth option
            time.sleep(1)
            print("\n[•] Thank you for using the Smart Password Manager! 😊") # Thank the user
            time.sleep(2)
            print("[•] Have a nice day! 👋") # Wish the user a nice day
            time.sleep(1)
            break # Break the loop
        else: # If the user enters something else
            time.sleep(1)
            print("\n[!] Invalid choice. Please enter 1, 2, 3, or 4. 😕") # Tell the user that their choice is invalid
            time.sleep(2)

# Run the main function
if __name__ == "__main__":
    main()