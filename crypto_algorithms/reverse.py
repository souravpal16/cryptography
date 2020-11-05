class Extras():

	def __init__(self, message):
		self.message = message

	def print_message(self):
		print(self.message)

class ReverseCipher(Extras):

	encrypted_message = ''
	decrypted_message = ''
	def __init__(self, message):
		Extras.__init__(self, message)
		

	def encrypt(self):
		i = len(self.message) - 1
		while i >= 0:
			self.encrypted_message += self.message[i]
			i -= 1

class ReverseCipherDecrypt():

	def __init__(self, message):
		self.encrypted_message = message
		self.decrypted_message = ''

	def decrypt(self):
		i = len(self.encrypted_message) - 1
		while i >= 0:
			self.decrypted_message += self.encrypted_message[i]
			i -= 1
		return self.decrypted_message

