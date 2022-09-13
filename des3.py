# Then import DES3 for Encryption and md5 for key
import hashlib
from Crypto.Cipher import DES3
from hashlib import md5

# For selecting operation from given choice
while True:
    print('Choose operation to be done:\n\t1- Encryption\n\t2- Decryption')
    operation = input('Your Choice: ')
    if operation not in ['1', '2']:
        break
    
    # Image / File Path for operation
    file_path = input('File path: ')
    
    # Key for performing Triple DES algorithm
    key = input('TDES key: ')

    # Encode given key to 16 byte ascii key with md5 operation
    key_hash = md5(key.encode('ascii')).digest()

    # Adjust key parity of generated Hash Key for Final Triple DES Key
    tdes_key = DES3.adjust_key_parity(key_hash)
    
    #  Cipher with integration of Triple DES key, MODE_EAX for Confidentiality & Authentication
    #  and nonce for generating random / pseudo random number which is used for authentication protocol
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

    # Open & read file from given path
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        
        if operation == '1':
            # Perform Encryption operation
            new_file_bytes = cipher.encrypt(file_bytes)
        else:
            # Perform Decryption operation
            new_file_bytes = cipher.decrypt(file_bytes)
    
    # Write updated values in file from given path
    with open(file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)
        print('Operation Done!')
        
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as get_file_hash:
    # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: get_file_hash.read(4096),b""):
            sha256_hash.update(byte_block)
        hash = sha256_hash.hexdigest()

    with open("file_path.hash", "a+") as file_hash:
        file_hash.seek(0)
        # If file is not empty then append '\n'
        data = file_hash.read(100)
        if len(data) > 0:
            file_hash.write("\n")
        # Append text at the end of file
        file_hash.write(hash)
        break
