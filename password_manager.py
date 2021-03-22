import pickle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import string
class PasswordManager:
    MAX_PASSWORD_LEN = 64

    def __init__(self, password, data = None, checksum = None):
        """Constructor for the password manager.
        Args:
            password (str) : master password for the manager
            data (str) [Optional] : a hex-encoded serialized representation to load
                                                            (defaults to None, which initializes an empty password
                                                            manager)
            checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                                                    possible rollback attacks (defaults to None, in which
                                                                    case, no rollback protection is guaranteed)

        Raises:
            ValueError : malformed serialized format
        """
        self.invalid = False
        if data is not None: # If there's already a store to load, do this
            # Check checksum first
            digest = hashes.Hash(hashes.SHA256())
            digest.update(bytes.fromhex(data))

            if digest.finalize() != bytes.fromhex(checksum):
                self.invalid = True
                raise ValueError("Malformed serialized data")
            self.register, self.salt = pickle.loads(bytes.fromhex(data)) # The register is currently hex-encrypted
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length = 32, salt = self.salt, iterations=2000000, backend=default_backend())
            self.key = kdf.derive(bytes(password, 'ascii'))

        else:                # If we need to generate a new store, do this
            self.salt = os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length = 32, salt = self.salt, iterations=2000000, backend=default_backend())
            self.key = kdf.derive(bytes(password, 'ascii'))
            self.register = {}

    def dump(self):
        """Computes a serialized representation of the password manager
       together with a checksum.
        
        Returns: 
            data (str) : a hex-encoded serialized representation of the contents of the password
                   manager (that can be passed to the constructor)
            checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
        """
        self.check_status()
        data = pickle.dumps((self.register, self.salt)).hex()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes.fromhex(data))
        return data, digest.finalize().hex()

    def get(self, domain):
        """Fetches the password associated with a domain from the password
       manager.
        
        Args:
            domain (str) : the domain to fetch
        
        Returns: 
            password (str) : the password associated with the requested domain if
                       it exists and otherwise None
        """
        print("getting", domain)
        self.check_status()
        dom_hash = self.to_hash(domain)
        if dom_hash in self.register:
            (enc_passwd, nonce) = self.register[dom_hash]
            aesgsm = AESGCM(self.key)
            password = aesgsm.decrypt(nonce=nonce, data=enc_passwd, associated_data=dom_hash)
            return password.decode('ascii')
        return None

    def set(self, domain, password):
        """Associates a password with a domain and adds it to the password
       manager. Raises an error if the domain already exists in the
       password manager.
       
       Args:
         domain (str) : the domain to set
         password (str) : the password associated with the domain

       Returns:
         None

       Raises:
         ValueError : if password length exceeds the maximum
        """
        print("setting", domain)
        self.check_status()
        if len(password) > self.MAX_PASSWORD_LEN:
            raise ValueError('Maximum password length exceeded')
        dom_hash = self.to_hash(domain)
        if dom_hash in self.register:
            raise ValueError("Domain already in manager")

        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        enc_passwd = aesgcm.encrypt(nonce=nonce, data=bytes(password, 'ascii'), associated_data=dom_hash)
        self.register[dom_hash] = (enc_passwd, nonce)


    def remove(self, domain):
        """Removes the password for the requested domain from the password
       manager.
       
       Args:
         domain (str) : the domain to remove

       Returns:
         success (bool) : True if the domain was removed and False if the domain was
                                                    not found
        """
        self.check_status()
        dom_hash = self.to_hash(domain)
        if dom_hash in self.register:
            del self.register[dom_hash]
            return True

        return False

    def generate_new(self, domain, desired_len):
        """Generates a password for a particular domain. The password
       is a random string with characters drawn from [A-Za-z0-9].
       The password is automatically added to the password manager for
       the associated domain.
       
       Args:
         domain (str) : the domain to generate a password for
         desired_len (int) : length of the password to generate (in characters)

       Returns:
         password (str) : the generated password

       Raises:
         ValueError : if a password already exists for the provided domain
         ValueError : if the requested password length exceeds the maximum
        """
        self.check_status()
        if domain in self.register:
            raise ValueError('Domain already in database')
        if desired_len > self.MAX_PASSWORD_LEN:
            raise ValueError('Maximum password length exceeded')
        alphabet = string.ascii_letters + string.digits
        new_password = ''.join(secrets.choice(alphabet) for _ in range(desired_len))
        self.set(domain, new_password)

        return new_password

    # helper functions
    def to_hash(self, str):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes(str, 'ascii'))
        return digest.finalize()

    def check_status(self):
        if self.invalid:
            raise ValueError("Inconsistent state")
