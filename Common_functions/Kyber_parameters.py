# Setting the parameters of Kyber
 
# Size in bytes of hashes and seeds
SYM_BYTES  = 32

# Size in bytes of one compressed polynomial of N coefficients 
POLY_BYTES = 384

# Size in bytes of a Kyber PKE message 
M_BYTES  = 32

# Kyber module
Q = 3329
 
# Kyber polynomial degree
N = 256

# According to the security level of Kyber, adjust the following parameter
# Module size 
K = 4

if K == 2:
    # Secret parameter
    ETA1 = 3

    # Noise parameter
    ETA2 = 2

    # Compress rate of u 
    DU = 10

    # Compress rate of v
    DV = 4
    
    # Kyber PKE public key size
    PK_BYTES = K*POLY_BYTES + SYM_BYTES
    
    # Kyber PKE secret key size
    SK_BYTES = K*POLY_BYTES

    # Kyber PKE compressed ciphertext size
    C1_BYTES = K * (N * DU) // 8 
    C2_BYTES = (N * DV) // 8
    C_BYTES  = C1_BYTES + C2_BYTES

    # Kyber KEM public key size 
    KEM_PK_BYTES = PK_BYTES
    
    # Kyber KEM secret key size 
    KEM_SK_BYTES = SK_BYTES + PK_BYTES + 2*SYM_BYTES
    
elif K == 3:
    # Secret parameter
    ETA1 = 2

    # Noise parameter
    ETA2 = 2

    # Compress rate of u 
    DU = 10

    # Compress rate of v
    DV = 4
    
    # Kyber PKE public key size
    PK_BYTES = K*POLY_BYTES + SYM_BYTES
    
    # Kyber PKE secret key size
    SK_BYTES = K*POLY_BYTES

    # Kyber PKE compressed ciphertext size
    C1_BYTES = K * (N * DU) // 8 
    C2_BYTES = (N * DV) // 8
    C_BYTES  = C1_BYTES + C2_BYTES

    # Kyber KEM public key size 
    KEM_PK_BYTES = PK_BYTES
    
    # Kyber KEM secret key size 
    KEM_SK_BYTES = SK_BYTES + PK_BYTES + 2*SYM_BYTES
    
elif K == 4:
    # Secret parameter
    ETA1 = 2  

    # Noise parameter
    ETA2 = 2
    
    # Compress rate of u 
    DU = 11

    # Compress rate of v
    DV = 5  

    # Kyber PKE public key size
    PK_BYTES = K*POLY_BYTES + SYM_BYTES
    
    # Kyber PKE secret key size
    SK_BYTES = K*POLY_BYTES

    # Kyber PKE compressed ciphertext size
    C1_BYTES = K * (N * DU) // 8 
    C2_BYTES = (N * DV) // 8
    C_BYTES  = C1_BYTES + C2_BYTES
    
    # Kyber KEM public key size 
    KEM_PK_BYTES = PK_BYTES
    
    # Kyber KEM secret key size 
    KEM_SK_BYTES = SK_BYTES + PK_BYTES + 2*SYM_BYTES
    
else:
    raise ValueError("Wrong value of K, either {2, 3, 4}")
    
# Twiddle factors used for the  ntt and invntt
zetas = [2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 
         573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758, 
         1223, 652, 2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 
         2476, 3239, 3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 
         2226, 430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 
         778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 
         1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 
         1799, 2051, 794, 1819, 2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628]