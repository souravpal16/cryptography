from django.shortcuts import render, redirect
from algorithms.reverse import ReverseCipher, ReverseCipherDecrypt
from algorithms.caesar import CaesarCipher, CaesarCipherDecrypt
from algorithms.transposition import TranspositionCipher
from algorithms.vignere import VignereCipher
from algorithms.multiplicative import MultiplicativeCipher
from algorithms.otp import OTP
from algorithms.substitution import SubstitutionCipher
from django.core.mail import send_mail


# Create your views here.
def home(request):
	return render(request, 'home.html')

def encrypted(request):
	context = {}
	context['encrypted_message'] = encrypted_message
	context['algo'] = algo
	context['message']= message
	if request.method == 'POST':
		subject = 'text alert'
		email_from = 'souravpal.4916@gmail.com'
		email = request.POST['email']
		message_to_be_sent ='Encrypted message: ' encrypted_message + '\nalgo: {}'.format(algo)
		send_mail(subject, message_to_be_sent, email_from, [email])
	return render(request, 'encrypted.html', context)

def encrypt(request):
	if request.method == 'POST':
		
		global message
		message = request.POST['message']

		global algo
		global encrypted_message
		global cache
		cache = {}
		algo = request.POST['algo']
		
		if algo == 'reverse':
			reverse_algo = ReverseCipher(message)
			reverse_algo.encrypt()
			encrypted_message = reverse_algo.encrypted_message
		
		elif algo == 'caesar':
			caesar_cipher = CaesarCipher(message)
			caesar_cipher.encrypt(5)
			encrypted_message = caesar_cipher.encrypted_message

		elif algo == 'transposition':
			transposition_cipher = TranspositionCipher(message)
			encrypted_message, d = transposition_cipher.encrypt()
			cache['dict'] = d
		
		elif algo == 'vignere':
			cache['key'] = 'lambo'
			vignere = VignereCipher(message, cache['key'])
			encrypted_message = vignere.encrypt()
		
		elif algo == 'substitution':
			sub = SubstitutionCipher(message)
			encrypted_message = sub.encrypt()
			cache['key'] = sub.key

		elif algo == 'multiplicative':
			multi = MultiplicativeCipher(message)
			encrypted_message = multi.encrypt()

		elif algo == 'otp':
			otp = OTP(message)
			encrypted_message = otp.encrypt()
			cache['key'] = otp.key
		
		####file handling####
		file1 = open("../data/"+algo+".txt", "w")
		file1.write(encrypted_message)
		file1.close()

		if 'key' in cache:
			file2 = open("../data/key.txt", "w")
			file2.write(str(cache['key']))
			file2.close()
		if 'dict' in cache:
			file2 = open("../data/key.txt", "w")
			file2.write(str(cache['dict']))
			file2.close()

		return redirect('encrypted')
	
	return render(request, 'encrypt.html')

def decrypt(request):
	if request.method == 'POST':
		message_X = request.POST['message']
		algo = request.POST['algo']
		
		global decrypted_message
		if algo == 'reverse':
			reverse_decrypt = ReverseCipherDecrypt(message_X)
			decrypted_message = reverse_decrypt.decrypt()
		
		elif algo == 'caesar':
			caesar_decrypt = CaesarCipherDecrypt(message_X)			
			decrypted_message = caesar_decrypt.decrypt(5)
		
		elif algo == 'transposition':
			d = cache['dict']
			transposition_cipher = TranspositionCipher(message_X)
			decrypted_message = transposition_cipher.decrypt(d, encrypted_message)

		elif algo == 'vignere':
			vignere = VignereCipher(' ', cache['key'])
			decrypted_message = vignere.decrypt(message_X)

		elif algo == 'substitution':
			sub = SubstitutionCipher(' ', cache['key'])
			decrypted_message = sub.decrypt(message_X)

		elif algo == 'multiplicative':
			multi = MultiplicativeCipher(' ')
			decrypted_message = multi.decrypt(message_X)

		elif algo == 'otp':
			otp = OTP(' ')
			decrypted_message = otp.decrypt(message_X, cache['key'])

		return redirect('decrypted')
	return render(request, 'decrypt.html')

def decrypted(request):
	context = {}
	context['decrypted_message'] = decrypted_message
	return render(request, 'decrypted.html', context)
