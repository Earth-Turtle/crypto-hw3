from password_manager import PasswordManager

import re

def error(s):
  print('=== ERROR: %s' % s)

print('Initializing password maanger')
password_manager = PasswordManager('123456')

print('Adding passwords to password manager')
kvs = { 'domain1': 'password1', 
        'domain2': 'password2',
        'domain3': 'password3' }
for domain in kvs:
  password_manager.set(domain, kvs[domain])

print('Trying to fetch passwords from password manager')
for domain in kvs:
  pw = password_manager.get(domain)
  if pw != kvs[domain]:
    error('get failed for domain %s (expected %s, received %s)' % (domain, kvs[domain], pw))
pw = password_manager.get('non-existent')
if pw is not None:
  error('get failed for domain non-existent (expected None, received %s)' % pw)

print('Trying to remove passwords from password manager')
if not password_manager.remove('domain1'):
  error('remove failed for domain domain1')
pw = password_manager.get('domain1')
if pw is not None:
  error('get failed for domain domain1 (expected None, received %s)' % pw)
if password_manager.remove('non-existent'):
  error('remove failed for domain non-existent')

print('Serializing contents of the password manager')
data, checksum = password_manager.dump()

print('Loading contents of password manager from disk')
new_manager = PasswordManager('123456', data, checksum)
for domain in kvs:
  pw1 = password_manager.get(domain)
  pw2 = new_manager.get(domain)
  if pw1 != pw2:
    error('get mismatch for domain %s (received values %s and %s)' % (domain, pw1, pw2))

print('Generating new password for domain domain_new')
new_password = password_manager.generate_new('domain_new', 20)
if len(new_password) != 20 or not re.match(r'[0-9a-zA-z]+', new_password):
  error('invalid password: %s' % new_password)
print('Generated password:', new_password)

print('Testing complete')
