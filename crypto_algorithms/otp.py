import random
class Extras():

	# constructor in python is __init__(), which is also called special or dunder function in python 
	def __init__(self, message):
		self.message = message
	
	#Normal member funtion
	def print_message(self):
		print(self.message)

class Encryption(Extras):

	def __init__(self, message):
		Extras.__init__(self, message)
		self.encrypted_message = ''
		self.key = random.sample(list(range(len(message))), len(message))

	def encrypt(self):
		for i in range(len(self.message)):
			if self.message[i] == ' ':
				self.encrypted_message += '.'
			elif self.message[i].isupper():
				self.encrypted_message += chr((ord(self.message[i]) - 65 + self.key[i]) % 26 + 65)
			else:
				self.encrypted_message += chr((ord(self.message[i]) - 97 + self.key[i]) % 26 + 97)
				
		return self.encrypted_message

class OTP(Encryption):
	def __init__(self, message):
		Encryption.__init__(self, message)
		self.decrypted_message = ''

	def decrypt(self, encrypted_message, key):
		for i in range(len(encrypted_message)):
			char = encrypted_message[i]
			if char == '.':
				self.decrypted_message += ' '
			elif char.isupper():
				self.decrypted_message += chr((ord(char) - 65 + 26 - key[i]) % 26 + 65)
			else:
				self.decrypted_message += chr((ord(char) - 97 + 26 - key[i]) % 26 + 97)
		return self.decrypted_message

