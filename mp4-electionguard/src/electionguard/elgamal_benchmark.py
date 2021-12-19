# this is a simple benchmark that just measures how fast ElGamal encryption runs
import time
from secrets import randbelow
from typing import Optional

from tqdm import tqdm

from electionguard.elgamal import (
    elgamal_encrypt,
    ElGamalCiphertext,
    elgamal_keypair_random,
)
from electionguard.group import rand_q, ElementModQ
from electionguard.nonces import Nonces

N = 1000

keypair = elgamal_keypair_random()
nonces = Nonces(rand_q(), "benchmark-nonces")

start_time = time.perf_counter()
for i in tqdm(range(0, N)):
    nonce: ElementModQ = nonces[i]
    message = randbelow(1000)
    ciphertext: ElGamalCiphertext = elgamal_encrypt(message, nonce, keypair.public_key)
    plaintext: Optional[int] = ciphertext.decrypt(keypair.secret_key)
    if plaintext is None:
        print("Unexpected decryption failure")
        exit(1)
    if plaintext != message:
        print("Decryption isn't the inverse of encryption?")
        exit(1)
end_time = time.perf_counter()
delta_time = end_time - start_time

print(
    "%d ElGamal encryption/decryption operations in %.2f seconds\n  = %.5f ops/sec"
    % (N, delta_time, N / delta_time)
)
