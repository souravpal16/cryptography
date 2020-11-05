class Extras():
	
	def __init__(self, message):
		self.message = message

	def print_message(self):
		print(self.message)

class Encryption(Extras):

	encrypted_message = ''
	
	def __init__(self, message, num):
		Extras.__init__(self, message)
		self.num = num

	def encrypt(self):
		for char in self.message:
			if char == ' ':
				self.encrypted_message += '.'
			elif char.isupper():
				self.encrypted_message += chr((((ord(char) - 65)*self.num) % 26) + 65)
			else:
				self.encrypted_message += chr((((ord(char) - 97)*self.num) % 26) + 97)

		return self.encrypted_message

class MultiplicativeCipher(Encryption):
	def __init__(self, message, num = 5):
		Encryption.__init__(self, message, num)
		self.decrypted_message = ''

	def decrypt(self, encrypted_message):
		x = 0
		for i in range(26):
			if (self.num * i) % 26 == 1:
				x = i
				break
		for char in encrypted_message:
			if(char == '.'):
				self.decrypted_message += ' '
			elif char.isupper():
				self.decrypted_message += chr((((ord(char) - 65) * x) % 26) + 65)
			else:
				self.decrypted_message += chr((((ord(char) - 97) * x) % 26) + 97)
		return self.decrypted_message


