"""
# Zero Knowledge Proofs in Python

Examples of discrete-log zero-knowledge proofs implemented in Python

More specifically, these are non-interactive, zero-knowledge,
proofs of knowledge. They can be analyzed and proven secure
in the random oracle model (the random oracle here is instantiated
with the SHA2 hash function).

Lecture notes:
   https://www.cs.jhu.edu/~susan/600.641/scribes/lecture10.pdf
   https://www.cs.jhu.edu/~susan/600.641/scribes/lecture11.pdf

You must fill in the portions labelled #TODO. See the README.md in this
directory for submission instructions. Points are awarded as marked.
Total possible points: 100
"""


"""
## Import Elliptic Curves

The zero-knowledge proof schemes we work through here
 can work with any DLog group. This implementation makes use of
the secp256k1 elliptic curve group. We call an element of this group
(i.e., a point on the curve), simply a Point.

The order of this group, p, is a 256-bit prime number. Furthermore, p
happens to be extremely close to 2^256. Because of this, we can sample
exponents easily by choosing a random 32-byte number, and with high probability,
will be within [0,p).
   uint256_from_str(rnd_bytes(32)) is an exponent.

Sometimes this will be represented by the object Fp, which automatically handles
arithmetic modulo p. The underlying 'long' value can be extracted as `p.n` if 
`type(p) is Fp`.
"""

import secp256k1
from secp256k1 import Point, q, Fq, order, p, Fp, G, curve, ser, deser, uint256_from_str, uint256_to_str
import os, random

# p is the order (the # of elements in) the group, i.e., the number of points on the curve
# order = p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
print(order)
print(Fp)  # Fp is the group of exponents (integers mod p)

# ser/deser: convert Point -> string and vice versa
#   ser : Point -> str, deser : str -> Point

"""
"""
print(repr(G))
print(repr(p * G))
print(deser(ser(G)))

Hx = Fq(0xbc4f48d7a8651dc97ae415f0b47a52ef1a2702098202392b88bc925f6e89ee17)
Hy = Fq(0x361b27b55c10f94ec0630b4c7d28f963221a0031632092bf585825823f6e27df)
H = Point(curve, Hx,Hy)
# H = random_point(seed=sha2("H")) # An alternate generator


## Pick a random point on the curve (given a seed)
def random_point(seed=None, rnd_bytes=os.urandom):

    def sha2_to_long(x):
        from Crypto.Hash import SHA256
        return int(SHA256.new(x).hexdigest(),16)
    
    if seed is None: seed = rnd_bytes(32)
    # assert type(seed) == str and len(seed) == 32
    x = sha2_to_long(seed)
    while True:
        try:
            p = secp256k1.solve(Fq(x))
        except ValueError:
            seed = sha2(('random_point:' + str(seed)))
            x = sha2_to_long(seed)
            continue
        break
    return p




"""
## Honest verifier model

In our three-round interactive proof protocols, we will always have the verifier
choose a random challenge.

In practice, it's more convenient to use the Random Oracle model and instantiate
this with a hash function.

This codebase allows the use of either option. The Prover function takes in a 
 "getChallenge" method, which it can invoke after generating its Commit message.
 The Verifier takes in a "getTranscript" message, which it can use to check that
 the commitment was chosen before the challenge.
"""

## Interactive challenger
def make_honest_verifier_challenger():
    """
    Returns:
    - a function "getChallenge(Commit)" that returns a 32-byte string

       This function can be passed to the Prover, which it can use to request
       the challenge from the verifier.

    - a function "getTranscript(Commit)" that checks the right commitment
       was queried and returns the same 32-byte string

       This function can be passed to the Verifier, which it can use to inspect
       the Commit message.
    """
    transcript = []
    def getChallenge(Commit):
        assert transcript == []
        assert type(Commit) is str
        result = os.urandom(32)
        transcript.extend((Commit, result))
        return result

    def getTranscript(Commit):
        assert transcript != []
        assert transcript[0] == Commit
        return transcript[1]
        
    return getChallenge, getTranscript


## Random Oracle Model

# Find sha2 hash of a string
def sha2(x):
    from Crypto.Hash import SHA256
    return SHA256.new(x.encode("utf-8")).digest()





"""
## Preliminary example: Proof of knowledge of discrete logarithm

In this part, we provide a scheme offers a discrete log proof of `ZKP{ (a): A = a*G }`.

Note that the statement `A` is a parameter to the scheme, as it must
be known to both the prover and verifier.

The Prover takes several additional arguments:

 - `rnd_bytes`, such that `rnd_bytes(n)` returns an `n`-byte random string. By default, will use the operating system os.urandom. 

    (Note: as this function is non-blocking, may be a poor choice if the OS runs out of entropy)

 - getChallenge, a function that requests the challenge from the verifier. 
   This takes in `Commit`, an arbitrary length string, and returns a randomly chosen value.

   By default, we will use the sha2 hash as a heuristic Random Oracle, giving us the Non-Interactive
    version of this protocol.

These can be overridden in later section as part of the security proof constructions.
"""
def dlog_prover(A, a, getChallenge=sha2, rnd_bytes=os.urandom):
    assert a*G == A

    # blinding factor
    k = uint256_from_str(rnd_bytes(32)) % order

    # commitment
    K = k*G

    # Invoke the random oracle to receive a challenge
    c = uint256_from_str(getChallenge(ser(K)))

    # response
    s = Fp(k + c*a)

    return (K,s)


def dlog_verifier(A, prf, getTranscript=sha2):
    (K,s) = prf
    assert type(A) is type(K) is Point
    assert type(s) is Fp

    # Recompute c w/ the information given
    c = uint256_from_str(getTranscript(ser(K)))

    # Check the verification condition
    assert s.n *G == K + c*A
    return True


def dlog_test():
    a = uint256_from_str(os.urandom(32))
    A = a*G
    getChallenge, getTranscript = make_honest_verifier_challenger()
    prf = dlog_prover(A, a, getChallenge)
    assert dlog_verifier(A, prf, getTranscript)
    print('Dlog correctness test complete!')

dlog_test()

"""
## Part 1: Make a Pedersen commitment to your secret key.
 Provide a ZK proof that your commitment is correct.

   Zk{ (x,r): X = x*G, C = x*G + r*H }

By completing this proof, you prove you still have knowledge of your key!

The verifier is provided for you. (Since we will publicly verify the proofs). You must complete the prover.
"""

def make_pedersen_commitment(x, rnd_bytes=os.urandom):
    r = uint256_from_str(rnd_bytes(32))
    C = x * G + r * H
    return C, r

def pedersen_prover(C, X, x, r, getChallenge=sha2, rnd_bytes=os.urandom):
    """
    Params: 
       x and r are elements of Fp
       C,X are Points
    Returns:
       prf, of the form (KX,KC,sx,sr)
    """
    assert X == x * G
    assert C == x * G + r * H

    # TODO: fill in your code here (10 points)
    # blinding factor
    t_1 = uint256_from_str(rnd_bytes(32)) % order
    t_2 = uint256_from_str(rnd_bytes(32)) % order

    # commitment
    KX = t_1*G
    KC = t_1*G + t_2*H

    # Invoke the random oracle to receive a challenge
    c = uint256_from_str(getChallenge(ser(KX) + ser(KC)))

    # response
    sx = Fp(t_1 + c*x)
    sr = Fp(t_2 + c*r)

    return (KX,KC,sx,sr)

def pedersen_verifier(C, X, prf, getTranscript=sha2):
    (KX,KC,sx,sr) = prf
    assert type(KX) == type(KC) == Point
    assert type(sx) == type(sr) == Fp

    # Recompute c w/ the information given
    c = uint256_from_str(getTranscript(ser(KX) + ser(KC)))

    assert sx.n *G            == KX + c*X
    assert sx.n *G + sr.n *H  == KC + c*C
    return True

def pedersen_test():
    getChallenge, getTranscript = make_honest_verifier_challenger()
    x = uint256_from_str(os.urandom(32))
    X = x * G
    C,r = make_pedersen_commitment(x)
    prf = pedersen_prover(C, X, x, r, getChallenge)
    (KX, KC, sx, sr) = prf
    print(repr((ser(C), ser(KX),ser(KC),uint256_to_str(sx.n).hex(),uint256_to_str(sr.n).hex())))

    assert pedersen_verifier(C, X, prf, getTranscript)
    print("Pedersen correctness test complete!")

pedersen_test()


"""
## Part 1 b): Make a single Pedersen commitment to a vector of secrets

   Zk{ (x1...xn,r1...rn): C1 = x1*G + r1*H, C2 = x2*G + r2*H, .. Cn = xn*G + rn*H }

The verifier is provided for you. (Since we will publicly verify the proofs). You must complete the prover.
"""

def pedersen_vector_prover(C_arr, x_arr, r_arr, getChallenge=sha2, rnd_bytes=os.urandom):
    """
    Params: 
       x_arr, r_arr are arrays of elements in Fp
       C_arr are arrays of Points
    Returns:
       prf, of the form (K,sx,sr) where K is points and sx and sr are points in Fp 
       Note that here you are able to prove that knowledge of n points with only communicating 1 ppints and 2 scalars.
    """

    # Make sure all commitments are correct
    for C_elem, x_elem, r_elem in zip(C_arr,x_arr,r_arr):
        assert C_elem == x_elem*G + r_elem*H

    # TODO: Your code goes here: 10 points
    assert len(C_arr) == len(x_arr) == len(r_arr)
    # blinding factor
    t = uint256_from_str(rnd_bytes(32)) % order

    # commitment
    C0 = t*G

    # Invoke the random oracle to receive a challenge
    c = uint256_from_str(getChallenge(ser(C0)))

    # response
    sx, sr = t, 0
    e = c
    for _, x_elem, r_elem in zip(C_arr, x_arr, r_arr):
        sx += Fp(e*x_elem)
        sr += Fp(e*r_elem)
        e *= c

    return (C0, sx, sr)

def pedersen_vector_verifier(C_arr, prf, getTranscript=sha2, rnd_bytes=os.urandom):
    (C0, sx, sr) = prf

    assert type(C0) == Point
    assert type(sx) == type(sr) == Fp

    c = Fp(uint256_from_str(getTranscript(ser(C0))))
    
    e = c
    C_final = C0
    for C_elem in C_arr:
        C_final = C_final + e.n*C_elem
        e = Fp(e*c)

    assert C_final == sx.n*G + sr.n*H

    return True

def pedersen_vector_test():
    x_arr, r_arr, C_arr = [], [], []
    for _ in range(10):
        x_elem = uint256_from_str(os.urandom(32))
        C_elem, r_elem = make_pedersen_commitment(x_elem)
        x_arr.append(x_elem)
        C_arr.append(C_elem)
        r_arr.append(r_elem)

    getChallenge, getTranscript = make_honest_verifier_challenger()
    prf = pedersen_vector_prover(C_arr, x_arr, r_arr, getChallenge)

    assert pedersen_vector_verifier(C_arr, prf, getTranscript)
    print("Pedersen vector correctness test complete!")

pedersen_vector_test()

"""
## Part 2. Arithmetic relations

Example: a more complicated discrete log proof
      Zk{ (a, b):  A=a*G, B=b*G,  C = (a*(b-3)) * G }

First rewrite as:
      Zk{ (a, b):  A=a*G, B=b*G,  (C + 3*A) = b*A) }

You need to implement a prover and verifier for the above scheme.
"""

def arith_prover(a, b, A, B, C, getChallenge=sha2, rnd_bytes=os.urandom):
    """
    Params: 
       a and b are elements of Fp
       A, B, C are Points
    Returns:
       prf, of the form (KA,KB,KC,sa,sb)

    Must satisfy verify_proof2(A, B, C, prf)
    Must be zero-knowledge
    """
    assert a*G == A
    assert b*G == B
    assert (a*(b-3))*G == C

    # TODO: fill in your code here (10 points)
    # blinding factor
    t_1 = uint256_from_str(rnd_bytes(32)) % order
    t_2 = uint256_from_str(rnd_bytes(32)) % order

    # commitment
    KA = t_1*G
    KB = t_2*G
    KC = t_2*a*G

    # Invoke the random oracle to receive a challenge
    c = uint256_from_str(getChallenge(ser(KA) + ser(KB) + ser(KC)))

    # response
    sa = Fp(t_1 + c*a)
    sb = Fp(t_2 + c*b)

    return (KA,KB,KC,sa,sb)


def arith_verifier(A, B, C, prf, getTranscript=sha2, rnd_bytes=os.urandom):
    (KA,KB,KC,sa,sb) = prf
    assert type(KA) == type(KB) == type(KC) == Point
    assert type(sa) == type(sb) == Fp

    # TODO: fill in your code here (10 points)
    c = uint256_from_str(getTranscript(ser(KA) + ser(KB) + ser(KC)))

    assert sa.n *G  == KA + c*A
    assert sb.n *G  == KB + c*B
    assert sb.n *A  == KC + c*(C+3*A)
    return True

def arith_test():
    # Randomly choose "a" and "b"
    a = uint256_from_str(os.urandom(32))
    b = uint256_from_str(os.urandom(32))
    A = a*G
    B = b*G
    C = (a*(b-3)) * G

    prf = arith_prover(a, b, A, B, C)
    assert arith_verifier(A, B, C, prf)
    print("Arithmetic Relation correctness test complete")

arith_test()

"""
## Part 3. OR composition

In this part you will need to combine two

   Zk{ (a,b): A = a*G    OR    B = b*G }

without revealing which one it is you know.

The verifier is provided for you.
"""

def OR_prover(A, B, x, getChallenge=sha2, rnd_bytes=os.urandom):
    assert x*G == A or x*G == B

    # TODO: Fill your code in here (20 points)
    if x*G == A:
        # blinding factor
        cb = uint256_from_str(rnd_bytes(32)) % order
        sb = uint256_from_str(rnd_bytes(32)) % order
        t_1 = uint256_from_str(rnd_bytes(32)) % order

        # commitment
        KA = t_1*G
        KB = sb*G - B*cb

        # Invoke the random oracle to receive a challenge
        c = uint256_from_str(getChallenge(ser(KA) + ser(KB)))

        # response
        ca = (c - cb) % p 
        sa = Fp(t_1 + ca*x)
        sb = Fp(sb)

        return (KA, KB, sa, sb, ca, cb)

    if x*G == B:
        # blinding factor
        ca = uint256_from_str(rnd_bytes(32)) % order
        sa = uint256_from_str(rnd_bytes(32)) % order
        t_2 = uint256_from_str(rnd_bytes(32)) % order

        # commitment
        KA = sa*G - A*ca 
        KB = t_2*G

        # Invoke the random oracle to receive a challenge
        c = uint256_from_str(getChallenge(ser(KA) + ser(KB)))

        # response
        cb = (c - ca) % p 
        sb = Fp(t_2 + cb*x)
        sa = Fp(sa)
        
        return (KA, KB, sa, sb, ca, cb)


def OR_verifier(A, B, prf, getTranscript=sha2):
    (KA,KB,sa,sb,ca,cb) = prf
    assert type(KA) is type(KB) is Point
    assert type(sa) is type(sb) is Fp

    # Check the challenges are correctly constrained
    c = uint256_from_str(getTranscript(ser(KA) + ser(KB)))
    assert (ca + cb) % p == c

    # Check each proof the same way
    assert sa.n *G == KA + ca*A
    assert sb.n *G == KB + cb*B

    return True

def OR_test1():
    # Try first way
    a = uint256_from_str(os.urandom(32))
    A = a*G
    B = random_point()

    getChallenge, getTranscript = make_honest_verifier_challenger()    
    prf = OR_prover(A, B, a, getChallenge)
    assert OR_verifier(A, B, prf, getTranscript)
    print("OR composition correctness 1 test complete!")

def OR_test2():
    # Try second way
    b = uint256_from_str(os.urandom(32))
    A = random_point()
    B = b*G

    getChallenge, getTranscript = make_honest_verifier_challenger()    
    prf = OR_prover(A, B, b, getChallenge)
    assert OR_verifier(A, B, prf, getTranscript)
    print("OR composition correctness 2 test complete!")

OR_test1()
OR_test2()


"""
## Part 4. Schnorr signature

  We can write a Schnor signature as:

     SoK[m] { (x): X = x*G }

  Similar to part 1, except the challenge is derived in part from the message.
"""
def schnorr_sign(x, m, getChallenge=sha2, rnd_bytes=os.urandom):
    assert type(x) is bytes
    assert type(m) is str

    # TODO: Your code goes here (10 points)
    # blinding factor
    k = uint256_from_str(rnd_bytes(32)) % order
    # commitment
    K = k*G
    # Invoke the random oracle to receive a challenge
    c = uint256_from_str(getChallenge(ser(K) + sha2(m).hex()))
    # response
    s = Fp(k + c*uint256_from_str(x))

    sig = bytes.fromhex(ser(K)) + uint256_to_str(int(s))
    return sig

def schnorr_verify(X, m, sig, getTranscript=sha2):
    assert type(X) is Point
    assert type(sig) is bytes and len(sig) is 65
    (K,s) = deser(sig[:33].hex()), uint256_from_str(sig[33:])
    c = uint256_from_str(getTranscript(ser(K) + sha2(m).hex()))
    assert s *G == K + c*X
    return True

def schnorr_test():
    msg = "hello"

    x = os.urandom(32)
    X = uint256_from_str(x) * G
    
    sig = schnorr_sign(x, msg)
    assert schnorr_verify(X, msg, sig)
    print("Schnorr Test complete")

schnorr_test()


"""
## Part 5. Range proofs

- Create a proof that C = g^a*h^r, and a is in the range [0,64).

    Zk{ (a, r): C = g^a*h^r and  0 <= a <= 63 }

  Hint: You can implement this by creating commitments to the binary expansion
    of A, and then proving the following:

    Zk{ (b0, b1, ... b4,b5, r0, r1, ..., r4, r5, r'): A = g^(b0 + 2*b1 + ... + 16*b4 + 32*b5)*g^(r0 + 2*r1 + ... + 16*r4 + 32*r5)*h(r')
                                    and  (C0 = g^(b0) h^r0) ....
                                    and  (C0 = g h^r0 OR C0 = h^r0) ... }
"""
def range_prover(a, r, C, getChallenge=sha2, rnd_bytes=os.urandom):
    assert type(C) is Point
    assert a*G + r*H == C

    # TODO: fill in your code here (10 points)
    # Peterson Commitment
    t_1 = uint256_from_str(rnd_bytes(32)) % order
    t_2 = uint256_from_str(rnd_bytes(32)) % order
    KC = t_1*G + t_2*H
    c = uint256_from_str(getChallenge(ser(KC)))
    sx = Fp(t_1 + c*a)
    sr = Fp(t_2 + c*r)
    
    # 6 OR proofs
    assert a>=0 and a<=63
    [b5, b4, b3, b2, b1, b0] = [i for i in (6-len(bin(a)[2:]))*"0"+bin(a)[2:]]
    if (r>=0) and (r<=63):
        [r5, r4, r3, r2, r1, r0] = [i for i in (6-len(bin(r)[2:]))*"0"+bin(r)[2:]]
    else:
        [r5, r4, r3, r2, r1, r0] = [i for i in bin(r)[-6:]]
    
    C0 = b0*G + r0*H 
    C1 = b1*G + r*H 
    C2 = b2*G + r2*H 
    C3 = b3*G + r3*H 
    C4 = b4*G + r4*H 
    C5 = b5*G + r5*H 

    p0 = OR_prover(C0, Fp(C0-G), r0)
    p1 = OR_prover(C1, Fp(C1-G), r1)
    p2 = OR_prover(C2, Fp(C2-G), r2)
    p3 = OR_prover(C3, Fp(C3-G), r3)
    p4 = OR_prover(C4, Fp(C4-G), r4)
    p5 = OR_prover(C5, Fp(C5-G), r5)

    # prove b0 + 2*b1 + ... + 16*b4 + 32*b5 == a


    return (KC,sx,sr), C0, p0, C1, p1, C2, p2, C3, p3, C4, p4, C5, p5



def range_verifier(C, prf, getTranscript=sha2, rnd_bytes=os.urandom):
    assert type(C) is Point

    # TODO: fill in your code here (10 points)
    (KC,sx,sr), C0, p0, C1, p1, C2, p2, C3, p3, C4, p4, C5, p5 = prf
    # assert Peterson Commitment
    assert type(KC) == Point
    assert type(sx) == type(sr) == Fp
    c = uint256_from_str(getTranscript(ser(KC)))
    assert sx.n *G + sr.n *H  == KC + c*C

    # assert 6 OR_proof
    assert OR_verifier(C0, Fp(C0-G), p0)
    assert OR_verifier(C1, Fp(C1-G), p1)
    assert OR_verifier(C2, Fp(C2-G), p2)
    assert OR_verifier(C3, Fp(C3-G), p3)
    assert OR_verifier(C4, Fp(C4-G), p4)
    assert OR_verifier(C5, Fp(C5-G), p5)

    # assert b0 + 2*b1 + ... + 16*b4 + 32*b5 == a

    return True




"""
## Part 6: Extractor and simulator

In this part, you will implement in code a portion of the security proof
for the discrete log proof scheme from the Preliminary.
"""
def dlog_extractor(A, Adv):
    assert type(A) is Point

    ## Step 1: run the adversary once to generate a commit, challenge, and response.
    ## Generate random bytes on demand, and save the Commit and the Verifier's challenge.
    ## 

    # TODO: Fill your code in here
    def _get_challenge(inp):
        nonlocal __challenge
        return __challenge

    def _rnd_bytes(inp):
        nonlocal __rnd_bytes
        return __rnd_bytes

    __challenge = os.urandom(32)
    __rnd_bytes = os.urandom(32)
    K1, s1 = Adv(A, getChallenge=_get_challenge, rnd_bytes=_rnd_bytes)
    c1 = uint256_from_str(_get_challenge(ser(K1)))
    ## Step 2: Run the adversary again, passing in the same random bits 
    ## but generating a fresh challenge.

    # TODO: Fill your code in here (5 points)
    __challenge = os.urandom(32)
    K2, s2 = Adv(A, getChallenge=_get_challenge, rnd_bytes=_rnd_bytes)
    c2 = uint256_from_str(_get_challenge(ser(K2)))

    ## Step 3: Extract a witness from the two responses and challenges

    # TODO: Fill your code in here (5 points)
    return Fp(s1 - s2) / Fp(c1 - c2)

def dlog_test_extractor():
    import os
    # Make a test case based on running the real prover
    a = uint256_from_str(os.urandom(32))
    A = a * G
    
    def Adv(A, getChallenge, rnd_bytes):
        assert A == a * G
        return dlog_prover(A, a, getChallenge, rnd_bytes)

    a_ = dlog_extractor(A, Adv)
    assert a == a_
    print('Extractor test complete!')

dlog_test_extractor()


def dlog_simulator(A, rnd_bytes):
    """
    Returns:
    - (prf, transcript)
    - prf, a tuple of the form (K,s),
        where K is a Point
        and s is an element of Fp
    - transcript is an array consisting of elements of the form
        [...(q,h)...]
      where each q is a query (a string)
      and each h is the response (a 32-byte string)
    """
    # TODO: Fill in your code here (10 points)
    s = Fp(uint256_from_str(rnd_bytes(32)) % order)
    h = rnd_bytes(32)
    c = uint256_from_str(h)

    K = s.n *G - c*A

    prf = (K, s)
    transcript = [(ser(K), h)]
    return (prf, transcript)

def dlog_test_simulator():
    rnd_bytes = os.urandom
    # Test with a randomly generated point on curve
    A = random_point(rnd_bytes=rnd_bytes)

    (prf, transcript) = dlog_simulator(A, rnd_bytes)

    # Unpack the proof
    K,s = prf
    assert type(K) is Point
    assert type(s) is Fp

    # Unpack oracle transcript (there should be just one query)
    assert len(transcript) == 1
    (q,h) = transcript[0]

    assert q == ser(K)
    c = uint256_from_str(h)

    # Check the verification condition
    assert s.n *G == K + c*A

    print("DLOG simulator test complete!")

dlog_test_simulator()

