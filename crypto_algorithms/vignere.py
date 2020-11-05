class Extras():

	def __init__(self, message):
		self.message = message

	def print_message(self):
		print(self.message)


class Encryption(Extras):

	def __init__(self, message, key):
		Extras.__init__(self, message)
		self.key = key
		self.encrypted_message = ''

	def encrypt(self):
		l = 0
		while l < len(self.message):
			for i in range(len(self.key)):
				c = 0
				if self.key[i].isupper():
					c = ord(self.key[i]) - 65
				else:
					c = ord(self.key[i]) - 97
				d = self.message[l]

				if d == ' ':
					self.encrypted_message += '.'
				elif d.isupper():
					self.encrypted_message += chr((ord(d) - 65 + c)%26 + 65)
				else:
					self.encrypted_message += chr((ord(d) - 97 + c)%26 + 97)
				
				l = l + 1
				if l >= len(self.message):
					break
					
		return self.encrypted_message

class VignereCipher(Encryption):

	def __init__(self, message, key):
		Encryption.__init__(self, message, key)
		self.decrypted_message = ''

	def decrypt(self, encrypted_message):
		l = 0
		while l<len(encrypted_message):
			for i in range(len(self.key)):
				c = 0
				if self.key[i].isupper():
					c = ord(self.key[i]) - 65
				else:
					c = ord(self.key[i]) - 97
				d = encrypted_message[l]

				if d == '.':
					self.decrypted_message += ' '
				elif d.isupper():
					self.decrypted_message += chr((ord(d) - 65 + 26 - c)%26 + 65)
				else:
					self.decrypted_message += chr((ord(d) - 97 + 26 - c)%26 + 97)
				l = l + 1
				if(l >= len(encrypted_message)):
					break
		return self.decrypted_message


