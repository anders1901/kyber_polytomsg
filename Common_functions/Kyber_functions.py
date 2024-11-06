import numpy as np
import math 

from Kyber_parameters import *


def reduce_modQ(a):
    """
    Reduces a coefficient in ZZ to [0, Q[
    
    Inputs:
    --------
    a (int): coefficient in ZZ
    
    Outputs:
    --------
      (int): representation of a in [0, Q[
    """
    return a % Q


def montgomery_reduce(a):
    """
    Computes montgomery reduction of a coefficient in ZZ 
    
    Inputs:
    --------
    a (int): coefficient in ZZ
    
    Outputs:
    --------
      (int): representation of a in [0, Q[
    """
    return a * 169 % Q


def fqmul(a, b):
    """
    Multiplies two coefficient in ZZ and performs montgomery reduction
    
    Inputs:
    --------
    a (int): coefficient in ZZ
    b (int): coefficient in ZZ
    
    Outputs:
    --------
    c (int): representation of a*b in [0, Q[
    """
    c = a * b
    return montgomery_reduce(c)


def poly_reduce(poly):
    """
    Centers the coefficients of a polynomial from [0, Q[ to ]-Q//2, Q//2[
    
    Inputs:
    --------
    poly (list[int]): polynomial with N coefficient in [0, Q[
    
    Outputs:
    --------
         (list[int]): polynomial with N coefficient in ]-Q//2, Q//2[
    """
    return [int(math.remainder(coeff,Q)) for coeff in poly]


def poly_frommont(poly):
    """
    Performs conversion out of montgomery domain on a polynomial
    
    Inputs:
    --------
    poly (list[int]): polynomial with N coefficient in ZZ
    
    Outputs:
    --------
         (list[int]): polynomial with N coefficient in [0, Q[
    """
    return [coeff*pow(pow(2, 16), -1, Q)%Q for coeff in poly]


def poly_frombytes(a):
    """
    De-serializes bytes to a polynomial of N coefficients 
    
    Inputs:
    --------
    a (list[bytes]): bytes encoding the polynomail
    
    Outputs:
    --------
    r (list[int]): polynomial with N coefficient in [0, Q[
    """
    r = [0 for _ in range(N)]
    for i in range(N // 2):
        r[2 * i] = ((a[3 * i] >> 0) | (a[3 * i + 1] << 8)) & 0xFFF
        r[2 * i + 1] = ((a[3 * i + 1] >> 4) | (a[3 * i + 2] << 4)) & 0xFFF 
    return r


def invntt(poly):
    """
    Performs the in-place invers NTT and multiplies with the montgomery factor 2^{16}
    
    Inputs:
    --------
    poly (list[int]): polynomial with N coefficient in [0, Q[
    
    Outputs:
    --------

    """
    f = 1441
    
    l, l_upper = 2, 128
    k = l_upper - 1

    while l <= 128:
        start = 0
        while start < N:
            zeta = zetas[k]
            k = k - 1
            for j in range(start, start+l):
                t = poly[j]
                poly[j]   = reduce_modQ(t + poly[j+l])
                poly[j+l] = poly[j+l] - t
                poly[j+l] = fqmul(zeta, poly[j+l])
            start = j + l + 1
        l = l << 1
    for j in range(N):
        poly[j] = fqmul(poly[j], f)


def compress(x, d):
    """
    Maps a coefficient in [0, Q[ to [0, 2^{d}[
    
    Inputs:
    --------
    x (int): coefficient in [0, Q[
    d (int): compression rate 
    
    Outputs:
    --------
    y (int): representation of x in [0, 2^{d}[
    """
    q1 = 2**d
    y = np.round(q1 / Q * x).astype(int)
    y = np.remainder(y, q1)
    return y


def poly_compress(a):
    """
    Maps a polynomial of N coefficients in [0, Q[ to [0, 2^{d}[
    Only considers the input v from Kyber PKE Encrypt
    
    Inputs:
    --------
    a (list[int]): in [0, Q[
    
    Outputs:
    --------
    y (list[int]): representation in [0, 2^{d}[    
    """
    t = np.zeros(8, dtype=np.uint8)
    if DV == 4:
        r = [0 for _ in range(N * DV//8)]
        for i in range(N // 8):
            for j in range(8):
                # map to positive standard representatives
                t[j] = compress(a[8 * i + j], d = DV)

            r[4 * i] = t[0] | (t[1] << 4)
            r[4 * i + 1] = t[2] | (t[3] << 4)
            r[4 * i + 2] = t[4] | (t[5] << 4)
            r[4 * i + 3] = t[6] | (t[7] << 4)

    elif DV == 5:
        r = [0 for _ in range((N * DV) // 8)]
        for i in range(N // 8):
            for j in range(8):
                # map to positive standard representatives
                t[j] = compress(a[8 * i + j], d = DV)

            r[5 * i] = (t[0] >> 0) | (t[1] << 5)
            r[5 * i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7)
            r[5 * i + 2] = (t[3] >> 1) | (t[4] << 4)
            r[5 * i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6)
            r[5 * i + 4] = (t[6] >> 2) | (t[7] << 3)
    else:
        raise ValueError("poly_compress: d needs compression rate in {4, 5}")
    return r


def polyvec_compress(a):
    """
    Maps a vector of polynomials of N coefficients in [0, Q[ to [0, 2^{d}[
    Only considers the input u from Kyber PKE Encrypt
    
    Inputs:
    --------
    a (list[list[int]]): in [0, Q[
    
    Outputs:
    --------
    y (list[list[int]]): representation in [0, 2^{d}[       
    """
    if DU == 11:
        r = [0 for _ in range((N * 11) // 8 * K)]
        t = np.zeros(8, dtype=np.uint16)
        for i in range(K):
            for j in range(N // 8):
                for k in range(8):
                    t[k] = compress(a[i][8 * j + k], d = DU)

                r[11 * (i * (N // 8) + j) + 0] = (t[0] >> 0)
                r[11 * (i * (N // 8) + j) + 1] = (t[0] >> 8) | (t[1] << 3)
                r[11 * (i * (N // 8) + j) + 2] = (t[1] >> 5) | (t[2] << 6)
                r[11 * (i * (N // 8) + j) + 3] = (t[2] >> 2)
                r[11 * (i * (N // 8) + j) + 4] = (t[2] >> 10) | (t[3] << 1)
                r[11 * (i * (N // 8) + j) + 5] = (t[3] >> 7) | (t[4] << 4)
                r[11 * (i * (N // 8) + j) + 6] = (t[4] >> 4) | (t[5] << 7)
                r[11 * (i * (N // 8) + j) + 7] = (t[5] >> 1)
                r[11 * (i * (N // 8) + j) + 8] = (t[5] >> 9) | (t[6] << 2)
                r[11 * (i * (N // 8) + j) + 9] = (t[6] >> 6) | (t[7] << 5)
                r[11 * (i * (N // 8) + j) + 10] = (t[7] >> 3)

    elif DU == 10:
        r = [0 for _ in range((N * 5) // 4 * K)]
        t = np.zeros(4, dtype=np.uint16)
        for i in range(K):
            for j in range(N // 4):
                for k in range(4):
                    t[k] = a[i][4 * j + k]
                    t[k] = compress(a[i][4 * j + k], d = DU)

                r[5 * (i * (N // 4) + j) + 0] = (t[0] >> 0)
                r[5 * (i * (N // 4) + j) + 1] = (t[0] >> 8) | (t[1] << 2)
                r[5 * (i * (N // 4) + j) + 2] = (t[1] >> 6) | (t[2] << 4)
                r[5 * (i * (N // 4) + j) + 3] = (t[2] >> 4) | (t[3] << 6)
                r[5 * (i * (N // 4) + j) + 4] = (t[3] >> 2)

    else:
        raise ValueError("polyvec_compress: d needs to be in {10, 11}")
    return r


def decompress(x, d):
    """
    Maps a coefficient in [0, 2^{d}[ to [0, Q[
    
    Inputs:
    --------
    x (int): coefficient in [0, 2^{d}[
    d (int): compression rate 
    
    Outputs:
    --------
    y (int): representation of x in [0, Q[ 
    """
    q1 = 2**d
    y = np.round(Q / q1 * x).astype(int)
    y = np.remainder(y, Q)
    return y


def poly_decompress(a):
    """
    Maps a polynomial of N coefficients in [0, 2^{d}[ to [0, Q[
    Only considers the input v from Kyber PKE Encrypt
    
    Inputs:
    --------
    a (list[int]): in [0, 2^{d}[
    
    Outputs:
    --------
    y (list[int]): representation in [0, Q[     
    """
    r = [0 for _ in range(N)]
    if DV == 4:
        for i in range(N // 2):
            r[2 * i + 0] = (((a[0] & 15) * Q) + 8) >> 4
            r[2 * i + 1] = (((a[0] >> 4) * Q) + 8) >> 4
            a = a[1:]

    elif DV == 5:
        for i in range(N // 8):
            t = [0] * 8
            t[0] = (a[0] >> 0) & 0xFF
            t[1] = ((a[0] >> 5) | (a[1] << 3)) & 0xFF
            t[2] = (a[1] >> 2) & 0xFF
            t[3] = ((a[1] >> 7) | (a[2] << 1)) & 0xFF
            t[4] = ((a[2] >> 4) | (a[3] << 4)) & 0xFF
            t[5] = (a[3] >> 1) & 0xFF
            t[6] = ((a[3] >> 6) | (a[4] << 2)) & 0xFF
            t[7] = (a[4] >> 3) & 0xFF
            a = a[5:]

            for j in range(8):
                r[8 * i + j] = ((t[j] & 31) * Q + 16) >> 5
    else:
        raise ValueError("poly_decompress: d needs to be in {4, 5}")
    return r

def polyvec_decompress(a):
    """
    Maps a vector of polynomials of N coefficients in [0, 2^{d}[ to [0, Q[
    Only considers the input u from Kyber PKE Encrypt
    
    Inputs:
    --------
    a (list[list[int]]): in [0, 2^{d}[
    
    Outputs:
    --------
    y (list[list[int]]): representation in [0, Q[     
    """
    r = [[0 for _ in range(N)] for j in range(K)]
    if DU == 11:
        for i in range(K):
            for j in range(N // 8):
                t = [0] * 8
                t[0] = (a[0] >> 0) | (a[1] << 8)
                t[1] = (a[1] >> 3) | (a[2] << 5)
                t[2] = (a[2] >> 6) | (a[3] << 2) | (a[4] << 10)
                t[3] = (a[4] >> 1) | (a[5] << 7)
                t[4] = (a[5] >> 4) | (a[6] << 4)
                t[5] = (a[6] >> 7) | (a[7] << 1) | (a[8] << 9)
                t[6] = (a[8] >> 2) | (a[9] << 6)
                t[7] = (a[9] >> 5) | (a[10] << 3)
                a = a[11:]

                for k in range(8):
                    r[i][8 * j + k] = ((t[k] & 0x7FF) * Q + 1024) >> 11
    elif DU == 10:
        for i in range(K):
            for j in range(N // 4):
                t = [0] * 4
                t[0] = (a[0] >> 0) | (a[1] << 8)
                t[1] = (a[1] >> 2) | (a[2] << 6)
                t[2] = (a[2] >> 4) | (a[3] << 4)
                t[3] = (a[3] >> 6) | (a[4] << 2)
                a = a[5:]

                for k in range(4):
                    r[i][4 * j + k] = ((t[k] & 0x3FF) * Q + 512) >> 10
    else:
        raise ValueError("polyvec_decompress: d needs to be in {10, 11}")
    return r

