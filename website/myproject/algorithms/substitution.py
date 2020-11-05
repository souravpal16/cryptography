import random 
#doesnt work on sentences. just words
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
		self.key = []

	def encrypt(self):
		A = list(range(26))
		B = random.sample(A, 26)
		self.key = B

		for i in range(len(self.message)):
			if self.message[i] == ' ':
				self.encrypted_message += '.'
			elif self.message[i].isupper():
				self.encrypted_message += chr(B[ord(self.message[i]) - 65] + 65)
			else:
				self.encrypted_message += chr(B[ord(self.message[i]) - 97] + 97)
		return self.encrypted_message

class SubstitutionCipher(Encryption):
	def __init__(self, message, key=None):
		Encryption.__init__(self, message)
		self.decrypted_message = ''
		self.key = key

	def decrypt(self, encrypted_message):
		for i in range(len(encrypted_message)):
			if encrypted_message[i] == '.':
				self.decrypted_message += ' '
				continue
			for x in range(26):
				num = 0
				if encrypted_message[i].isupper():
					num = ord(encrypted_message[i]) - 65
				else:
					num = ord(encrypted_message[i]) - 97 
				if num == self.key[x]:
					if encrypted_message[i].isupper():
						self.decrypted_message += chr(65 + x)
					else:
						self.decrypted_message += chr(97 + x)
		return self.decrypted_message


