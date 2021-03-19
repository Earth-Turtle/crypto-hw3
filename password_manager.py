import pickle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
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
        self.kvs = {}
        if data is not None:
            self.kvs = pickle.loads(bytes.fromhex(data))
        else:
            self.salt = os.random(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length = 32, salt = os.urandom(16), iterations=2000000, backend=default_backend())

    def dump(self):
        """Computes a serialized representation of the password manager
       together with a checksum.
        
        Returns: 
            data (str) : a hex-encoded serialized representation of the contents of the password
                   manager (that can be passed to the constructor)
            checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
        """
        return pickle.dumps(self.kvs).hex(), ''

    def get(self, domain):
        """Fetches the password associated with a domain from the password
       manager.
        
        Args:
            domain (str) : the domain to fetch
        
        Returns: 
            password (str) : the password associated with the requested domain if
                       it exists and otherwise None
        """
        if domain in self.kvs:
            return self.kvs[domain]
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
        if len(password) > self.MAX_PASSWORD_LEN:
            raise ValueError('Maximum password length exceeded')
        
        self.kvs[domain] = password


    def remove(self, domain):
        """Removes the password for the requested domain from the password
       manager.
       
       Args:
         domain (str) : the domain to remove

       Returns:
         success (bool) : True if the domain was removed and False if the domain was
                                                    not found
        """
        if domain in self.kvs:
            del self.kvs[domain]
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
        if domain in self.kvs:
            raise ValueError('Domain already in database')
        if desired_len > self.MAX_PASSWORD_LEN:
            raise ValueError('Maximum password length exceeded')

        new_password = '0'*desired_len
        self.set(domain, new_password)

        return new_password
