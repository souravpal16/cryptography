class Extras():
	def __init__(self, message):
		self.message = message

	def print_message(self):
		print(self.message)

class Encryption(Extras):
	
	def __init__(self, message):
		Extras.__init__(self, message)
		self._key = 'HACK'
		self._d = {}
		self.encrypted_message = ''
		self.decrypted_message = ''
	
	def encrypt(self):
		keys = list(self._key)
		self._d = {key:[] for key in keys}
		x = 0
		length = len(self.message)
		while(x < length):
			for key in keys:
				if(x < length):
					self._d[key].append(self.message[x])
				else:
					self._d[key].append(' ')
				x = x + 1
		for key in sorted(self._d.keys()):
			self.encrypted_message += ''.join(self._d[key])
		return self.encrypted_message, self._d

class TranspositionCipher(Encryption):
	def __init__(self, message):
		Encryption.__init__(self, message)

	def decrypt(self, d, encrypted_message):
		length = 0
		l = 0
		while(length < len(encrypted_message)):
			for x in self._key:
				self.decrypted_message += d[x][l]
				length += 1
			l += 1
		return self.decrypted_message
