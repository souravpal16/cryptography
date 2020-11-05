class Extras():

	def __init__(self, message):
		self.message = message
	
	def print_message(self):
		print(self.message)

class CaesarCipher(Extras):

	encrypted_message = ''
	decrypted_message = ''
	
	def __init__(self, message):
		Extras.__init__(self, message)

	def encrypt(self, num):

		for i in range(len(self.message)):
			char = self.message[i]

			if char == ' ':
				self.encrypted_message += '.'
			elif(char.isupper()):
				self.encrypted_message += chr((ord(char) + num - 65) % 26 +65) 

			else:
				self.encrypted_message += chr((ord(char) + num -97) % 26 + 97)
				
		return self.encrypted_message

class CaesarCipherDecrypt():
	def __init__(self, message):
		self.encrypted_message = message
		self.decrypted_message = ''

	def decrypt(self, num):
		for i in range(len(self.encrypted_message)):
			char = self.encrypted_message[i]

			if char == '.':
				self.decrypted_message += ' '
			elif(char.isupper()):
				self.decrypted_message += chr((ord(char) + 26 - num - 65) % 26 +65) # ord converts the char into its ascii value

			else:
				self.decrypted_message += chr((ord(char) + 26 - num -97) % 26 + 97)
		return self.decrypted_message

