'''
Python script to check if a password has ever been hacked and generate passwords
'''

# pylint: disable=invalid-name

import sys
import hashlib
import random
import requests


def request_api_data(hash_chars):
    '''
    Requests the data from the API and gives the response
    '''
    url = f'https://api.pwnedpasswords.com/range/{hash_chars}'
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the API.')

    return res


def hash_password(password):
    '''
    Check password if it exists in the API response

    pwned uses SHA1 hex with all uppercase
    '''
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    sha1_password, tail = sha1_password[:5], sha1_password[5:]

    return sha1_password, tail


def get_password_leaks_count(hashes, hash_to_check):
    '''
    Loops through all the response hashes, and checks with our own
    '''
    hashes = (line.split(':') for line in hashes.text.splitlines())

    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def check_bool(passwords):
    '''
    Returns True if the password was found
    '''
    is_found = False
    for password in passwords:
        sha1_pass, tail = hash_password(password)
        count = get_password_leaks_count(request_api_data(sha1_pass), tail)
        if count:
            print(f'{password} was leaked {count} times.')
            is_found = True
        else:
            print(f'{password} has not been leaked.')

    return is_found


def generata_secure_password(length=12, numbers=True, uppercase_letters=True,
                             symbols=r"!#$%&'()*+,-./:;<=>?@[\]^_`{|}~"):
    '''
    Generates a secure password with specific parameters, or default settings
    '''
    numbers = "0123456789"
    letters = "abcdefghijklmnopqrstuvwxyz"
    if uppercase_letters:
        upper_letters = letters.upper()

    choice_set = [numbers, letters, symbols]
    if upper_letters:
        choice_set.append(upper_letters)

    password = ""
    while True:
        for _ in range(length):
            password += random.choice(random.choice(choice_set))

        if not check_bool([password]):
            return password


def main(args):
    '''
    requests api data
    returns encoded password
    '''
    if args:
        check_bool(args)

    wants_password = input("Do you want a new password? (y/n)")
    if wants_password.upper() == "Y":
        generata_secure_password()


if __name__ == "__main__":
    main(sys.argv[1:])
