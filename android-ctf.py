from flask import Flask
from flask import request
from flask import jsonify
import os
import base64
import ctypes
import itertools
import math

app = Flask(__name__)

def encrypt(plaintext, key):
    """
    Encrypts a message using a 16-character key.
    :param plaintext:
        The message to encode.  *Must* be a utf8 string but can have any length.
    :param key:
        The encryption key used to encode the plaintext message.  *Must* be a utf8 string and 16 characters long.
    :return:
        A base64 utf8 string of the encrypted message.
    """
    if not plaintext:
        return ''

    v = _str2vec(plaintext.encode())
    k = _str2vec(key.encode()[:16])

    bytearray = b''.join(_vec2str(_encipher(chunk, k))
                         for chunk in _chunks(v, 2))

    return base64.b64encode(bytearray).decode()
def decrypt(ciphertext, key):
    """
    Decrypts a message using a 16-character key.
    :param ciphertext:
        The encrypted message to decode as a base64 utf8 string.
    :param key:
        The encryption key used to encode the plaintext message.  *Must* be a utf8 string and 16 characters long.
    :return:
        A utf8 string of the decrypted message.
    """
    if not ciphertext:
        return ''

    k = _str2vec(key.encode()[:16])
    v = _str2vec(base64.b64decode(ciphertext.encode()))

    return b''.join(_vec2str(_decipher(chunk, k))
                    for chunk in _chunks(v, 2)).decode()


def _encipher(v, k):
    """
    TEA encipher algorithm.  Encodes a length-2 vector using a length-4 vector as a length-2 vector.

    Compliment of _decipher.
    :param v:
        A vector representing the information to be enciphered.  *Must* have a length of 2.
    :param k:
        A vector representing the encryption key.  *Must* have a length of 4.
    :return:
        A length-2 vector representing the encrypted information v.
    """
    y, z = [ctypes.c_uint32(x)
            for x in v]
    sum = ctypes.c_uint32(0)
    delta = 0x9E3779B9

    for n in range(32, 0, -1):
        sum.value += delta
        y.value += (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]
        z.value += (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]

    return [y.value, z.value]


def _decipher(v, k):
    """
    TEA decipher algorithm.  Decodes a length-2 vector using a length-4 vector as a length-2 vector.

    Compliment of _encipher.
    :param v:
        A vector representing the information to be deciphered.  *Must* have a length of 2.
    :param k:
        A vector representing the encryption key.  *Must* have a length of 4.
    :return:
        The original message.
    """
    y, z = [ctypes.c_uint32(x)
            for x in v]
    sum = ctypes.c_uint32(0xC6EF3720)
    delta = 0x9E3779B9

    for n in range(32, 0, -1):
        z.value -= (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]
        y.value -= (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]
        sum.value -= delta

    return [y.value, z.value]


def _chunks(iterable, n):
    """
    Iterates through an iterable in chunks of size n.
    :param iterable:
        Any iterable.  Must have a length which is a multiple of n, or the last element will not contain n elements.
    :param n:
        The size of the chunks.
    :return:
        A generator that yields elements in chunks of size n.
    """
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk


def _str2vec(value, l=4):
    """
    Encodes a binary string as a vector.  The string is split into chunks of length l and each chunk is encoded as 2
    elements in the return value.

    Compliment of _str2vec.
    :param value:
        A binary string to encode.
    :param l:
        An optional length value of chunks.
    :return:
        A vector containing ceil(n / l) elements where n is the length of the value parameter.
    """
    n = len(value)

    # Split the string into chunks
    num_chunks = math.ceil(n / l)
    chunks = [value[l * i:l * (i + 1)]
              for i in range(num_chunks)]

    return [sum([character << 8 * j
                 for j, character in enumerate(chunk)])
            for chunk in chunks]


def _vec2str(vector, l=4):
    """
    Decodes a vector to a binary string.  The string is composed by chunks of size l for every two elements in the
    vector.

    Compliment of _str2vec.

    :param vector:
        An even-length vector.
    :param l:
        The length of the chunks to compose the returned string.  This should match the value for l used by _str2vec.
        If the value used is smaller, than characters will be lost.
    :return:
    """
    return bytes((element >> 8 * i) & 0xff
                 for element in vector
                 for i in range(l)).replace(b'\x00', b'')

@app.route("/")
def home():
    sig = request.headers.get('XY')
    if sig == 'a':
        key = 'bssYsEGWARvWapv1'
        message = 'braindead{sSL-pINN9-4nD-3nCrYp7in9-7R4fFiC-n07-3n0U9H}'
        resposne = encrypt(message, key)
        return jsonify(resposne)
    else:
        return jsonify("auth failed")

@app.route("/db")
def sqlitedb():
    sig = request.headers.get('XY')
    if sig == 'a':
        return jsonify("fqIqxv1mBRdK+xD5PCeLA2n5pgz3Ee3NlM6YGmkTQC8K/SsiM8NyxkU+7A53KP1XfXOP+F1Y1g7O3/jiH86cnJODIbvA1vLc88h+9P5vuzo=")
    else:
        return jsonify("auth failed")
@app.route("/sp")
def sharedpref():
    sig = request.headers.get('XY')
    if sig == 'a':
        return jsonify("braindead{1n53CUr3-w38v13W-1mpl3M3n74710n-l34D1n9-70-lf1}")
    else:
        return jsonify("auth failed")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0',port=port,ssl_context=('cert.pem', 'key.pem'))
