import random
from secretsharing import Fp, Poly


def isPowerOfTwo(n):
    # bit-arithmetic trick
    return n & (n-1) == 0


def nearestPowerOfTwo(n):
    if isPowerOfTwo(n): return n
    return 2 ** n.bit_length()


###############################################
# Problem 4.1: Roots of unity in a finite field [5pts]]
###############################################


def isNthRootOfUnity(omega, n):
    assert isPowerOfTwo(n)
    # Check that omega is an nth root of unity, omega^n == 1
    return pow(omega, n) == 1


def isPrimitiveNthRootOfUnity(omega, n):
    assert isPowerOfTwo(n)
    if not isNthRootOfUnity(omega, n): return False
    # Check that n is the *smallest* power so that omega^n == 1
    return pow(omega, n // 2) != 1 or omega == n == 1


def get_omega(Fp, n, seed=None):
    """
    Given a field, this method returns an n^th root of unity.
    If the seed is not None then this method will return the
    same n'th root of unity for every run with the same seed

    This only makes sense if n is a power of 2!
    """
    assert isPowerOfTwo(n), "n must be power of 2"
    rnd = random.Random(seed)

    y = Fp(0)
    
    # TODO: Your code goes here
    while True:
        _temp = rnd.randint(1, Fp.p-1)
        x = pow(Fp(_temp), (Fp.p-1)//n)
        if isPrimitiveNthRootOfUnity(x, n):
            break
    y = x

    assert isNthRootOfUnity(y, n), "omega must be 2n'th root of unity"
    assert isPrimitiveNthRootOfUnity(y, n), "omega must be primitive 2n'th root of unity"
    return y


###################################################
# Problem 4.2: Fourier transform over finite fields [10pts]
###################################################

def evaluate_fft(f, omega, n):
    """
    Evaluates the polynomial on n powers of omega,
    such that f(omega^i) for i in 0 through n-1
    """
    assert isPowerOfTwo(n), "n must be power of two"
    assert type(omega) is Fp
    assert isPrimitiveNthRootOfUnity(omega, n), "omega must be primitive 2n'th root of unity"

    # Pad coefficients to degree-n with zeros
    coeffs = f.coefficients
    coeffs = coeffs + [Fp(0)] * (n - len(coeffs))

    # Run fft
    result = []
    # TODO: Your code goes here
    result = _fft_finiteField(n, coeffs, omega)

    assert type(result) is list
    return result

def _fft_finiteField(n, coeffs, omega):
    if n == 1:
        f = Poly(coeffs)
        try:
            return [f(omega)]
        except IndexError:
            return coeffs
    else:
        _sub_even_B = [coeffs[2*i] for i in range(n//2)]
        _sub_odd_C = [coeffs[1+2*i] for i in range(n//2)]
        B = _fft_finiteField(n//2, _sub_even_B, pow(omega, 2))
        C = _fft_finiteField(n//2, _sub_odd_C, pow(omega, 2))

        A = [None for _ in range(n)]

        m, i, k2 = 1, 0, n//2
        A[i] = B[i] + m * C[i]
        A[i+k2] = B[i] - m * C[i]
        i += 1
        m *= omega
        while (m != 1 and i < n//2):
            A[i] = B[i] + m * C[i]
            A[i+k2] = B[i] - m * C[i]
            i += 1
            m *= omega

        return A

##################################################
# Problem 4.3: Interpolate a polynomial using IFFT [5pts]
##################################################


def interpolate_fft(ys, omega):
    """
    Returns a polynoial f of given degree,
    such that f(omega^i) == ys[i]
    """
    n = len(ys)
    assert isPowerOfTwo(n), "n must be power of two"
    assert type(omega) is Fp
    assert isPrimitiveNthRootOfUnity(omega, n), "omega must be primitive 2n'th root of unity"

    coeffs = []

    # TODO: Your code goes here
    # Hint: interpolate should use *inverse* fft
    # print(ys)
    ys = [ys[0]] + ys[-1:0:-1]
    # print(ys)
    coeffs = _fft_finiteField(n, ys, omega)
    # print(coeffs)
    coeffs = [coeffs[i]/Fp(n) for i in range(n)]
    # print(coeffs)

    poly = Poly(coeffs)
    return poly


if __name__ == "__main__":

    # Problem 4.1: Finding roots of unity
    # Try to find the 8th root of unity
    n = 2**3
    omega = get_omega(Fp, n)        

    # Example polynomial with degree t=6
    poly = Poly([1, 5, 3, 15, 0, 3])
    
    # Problem 4.2: Evaluate the polynomial using FFT
    ys = evaluate_fft(poly, omega, n)
    assert ys == [poly(omega**i) for i in range(n)], "Problem 4.2 check"

    # Problem 4.3: Interpolate polynomial using Inverse FFT
    poly2 = interpolate_fft(ys, omega)
    print(poly2)
    print(poly)
    assert poly == poly2, "Problem 4.3 check"
