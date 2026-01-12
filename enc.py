import sys
from lib.Arguments import Argument
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.fernet import Fernet

a= Argument(sys.argv)

def print_help():
    print("=============================== HELP ===============================================\n" 
          "usage: "+sys.argv[0]+" --file=<filename> --algorithm=<AES or CHACHA> --key=<your secret key>\n"
          "====================================================================================\n"
          "this tool only have encryption, decrypt on ur own\n")
    exit(-1)


def main():
    if(a.hasOptions(['--help','-h'])):
        print_help()
        
    #checking for file option
    if(a.hasOptionValue('--file')):
        file_path=os.path.expanduser(a.getOptionValue('--file'))
        #checking for key option if not present exit
        if not a.hasOptionValue('--algorithm'):
            print("Please provide an algorithm using --algorithm option check via -h")
            exit(-1)
        algo = a.getOptionValue('--algorithm').upper()
        
        if not a.hasOptionValue('--key'):
            print("Please provide a key using --key option")
            exit(-1)
        key = a.getOptionValue('--key')
        #checking if file exists    
        if not os.path.exists(file_path):
            print(f"File not found at {file_path}")
        else:
            print(f"Opening the file {file_path}....")
            try:
                with open(file_path,'rb') as f:
                    content = f.read()
                    print(content)
                    
                salt = os.urandom(16) # Generate random salt
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100_000,
                )
                key = kdf.derive(key.encode())  # Derive key
                
                #encrypting the content
                if algo == "AES":
                    cipher = AESGCM(key)
                    print("Using AES encryption")
                elif algo == "CHACHA":
                    cipher = ChaCha20Poly1305(key)
                    print("Using ChaCha20 encryption")
                else:
                    print(f"Algorithm {algo} not supported")
                    sys.exit(-1)
                nonce = os.urandom(12) # Generate random nonce
                encrypted_data = cipher.encrypt(nonce, content, None)
                
                #saving the encrypted content to a new file
                # en=file_path.split('.') 
                # print(en[1])
                root,ext = os.path.splitext(file_path) #replacing .txt with .enc
                # print(root,ext)
                output_path = root + ".enc"
                # output_path = file_path + ".enc"
                with open(output_path, 'wb') as f_out:
                    f_out.write(salt + nonce + encrypted_data)
                    
                print(f"Success! Encrypted file saved to: {output_path}")
            
            except Exception as e:
                print(f"Error processing file: {e}")
                sys.exit(-1)
        # key = a.getOptionValue('--key')
        # algorithm = a.getOptionValue('--algorithm','fernet')
        # print(f"Using algorithm: {algorithm} with key: {key}")
        # cipher = None
        # if(algorithm=='fernet'):
        #     cipher = Fernet(key)
        # else:
        #     print(f"Algorithm {algorithm} not supported")
        # if(cipher):
        #     encrypted = cipher.encrypt(content)
        #     print("Encrypted content:", encrypted)
            
        # data = open(a.getOptionValue('--file'))
        # print(data)
        # if(a.hasCommand(''))
    else:
        print_help()
        
if __name__ == "__main__":
    main()