import os 

from binascii import unhexlify
# from Kyber_functions import *

# Parameters

# Start of the first poly_tomsg
start_compress_0 = 92

# Length of the first poly_tomsg
op_len_ = 56

# Shift for loop on bytes
byte_jump_ = 28

# Shift for loop on bits
compress_len_ = 44

# def get_indexes(compress_index):
def get_compress_index_window(compress_index):
    """
    Gets the intervall where poly_tomsg(compress_index) is executed
    
    Inputs:
    --------
    compress_index       (int): index of compress between [0, N]
    
    Outputs:
    --------
    start_compress_index (int): index where the poly_tomsg(compress_index) starts
    end_compress_index   (int): index where the poly_tomsg(compress_index) ends
    """
    start_compress_index = (compress_index//8)*byte_jump_ + start_compress_0 + compress_index*op_len_
    end_compress_index   = (compress_index//8)*byte_jump_ + start_compress_0 + compress_index*op_len_ + compress_len_
    return start_compress_index, end_compress_index

def read_keys_from_KAT(nb_keys = 1, keys_file_name = f"../Common_functions/PQCkemKAT_{KEM_SK_BYTES}.rsp"):
    """
    Reads #nb_keys Kyber KEM keys from the KAT file keys_file_name 
                
    Inputs:
    --------
    nb_keys        (int): Number of keys to read from the keys file
    keys_file_name (str): Name of the file containing the keys to read 

    Outputs:
    --------
    PK   (dict{int:str}): Dict containg in the index i, the public key i read from the file
    SK   (dict{int:str}): Dict containg in the index i, the secret key i read from the file
    """
    
    nb_lines_per_KAT = 6
    index_of_pk      = 2
    index_of_sk      = 3
    offset           = 0
    SK = {}
    PK = {}
    
    #with open(f"{os.getcwd()}/{keys_file_name}", "r") as file:
    with open(f"{keys_file_name}", "r") as file:
        # We discard the first flag for the version of Dilithium as well as the first and last \n
        lines = file.read().splitlines()[2:-1]

        # Raise an error when there is not enough keys in the KAT file
        if len(lines) < nb_keys*6:
            raise ValueError("Not enough keys in the KAT file")

        for key_ in range(nb_keys):
            key_index = int(lines[offset + 0].split("=")[-1])

            pk = lines[offset + index_of_pk].split("=")[-1][1:]
            if len(pk) != 2*KEM_PK_BYTES:
                raise ValueError(f"Wrong len of pk in the Kat file for key #{key_index}")

            sk = lines[offset + index_of_sk].split("=")[-1][1:]
            if len(sk) != 2*KEM_SK_BYTES:
                raise ValueError(f"Wrong len of sk in the Kat file for key #{key_index}")
                 
            PK[key_index] = pk
            SK[key_index] = sk
            offset += 1
            offset += nb_lines_per_KAT

    return PK, SK


def hex_sk_to_int_sk(hex_sk):
    """
    """
    s = []
    for poly_index in range(K):
        s_ = poly_frombytes(unhexlify(hex_sk[(poly_index)*POLY_BYTES*2:(poly_index+1)*POLY_BYTES*2]))
        invntt(s_)
        s_ = poly_frommont(s_)
        s_ = poly_reduce(s_)
        s.append(s_)
    return s


