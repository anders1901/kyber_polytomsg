def disconnect_cw():
    """
    Disconnects the Chipwhisperer
    
    Inputs:
    --------

    Outputs:
    --------

    """
    scope.dis()
    target.dis()
    
    
def int_to_cw(num, bytes_ = 4):
    """
    Converts an integer num into a format compatible with the Chipwhisperer
    
    Inputs:
    --------
    num  (int): integer to convert
    
    Outputs:
    --------
    beh  (hes str): hex string representing the num
    """
    leb = num.to_bytes(bytes_, "big", signed=True)
    beh = "".join(format(byte, "02x") for byte in reversed(leb))
    return beh

def bytes_to_hex_str(bytess):
    """
    
    
    Inputs:
    --------
    
    
    Outputs:
    --------
    
    """
    return ''.join('{:02x}'.format(x) for x in bytess)

def hex_str_to_binary_str(hex_str):
    """
    
    
    Inputs:
    --------
    
    
    Outputs:
    --------
    
    """
    binary_str = "".join([f'{int(msg_hex[i:i+2], 16):08b}'[::-1] for i in range(0, len(msg_hex), 2)])
    return binary_str

commands = {"reset_offset_c":"a", 
            "reset_offset_sk":"b", 
            "send_c":"c", 
            "send_sk":"s", 
            "receive_c":"e", 
            "receive_sk":"f", 
            "kyber_decrypt":"d"}

def reset_c():
    """
    Resets the ciphertext 
    """
    target.simpleserial_write(commands["reset_offset_c"], bytes())
    
def serialize_c(C1, C2):
    """
    
    """
    C_ = np.array(C1 + C2).astype(np.uint8)
    
    C_serial = []
    for len_ in range(0, C_BYTES, SERIAL_BYTES):
        c_list_int = C_[len_:len_ + SERIAL_BYTES]
        c_serial = np.ndarray.tobytes(np.array(c_list_int), 'C')
        C_serial.append(c_serial)
    return C_serial

def send_c(serialized_c, reset = False):
    """
    
    """
    if reset:
        reset_c()
    time.sleep(1)
    for c_serial in serialized_c:
        target.simpleserial_write(commands["send_c"], c_serial)
        time.sleep(0.5)
        
def get_full_c_hex_str():
    """
    
    """
    command = "receive_c"

    full_str = ""
    for indx in trange(0, C_BYTES, 64, desc= "Receiving data"):
        indx_hex_str = int_to_cw(indx)
        indx_list_int = np.fromiter((int(x, 16) for x in [indx_hex_str[idx:idx+2] for idx in range(0, len(indx_hex_str), 2)] ), dtype=np.uint8)
        indx_serial = np.ndarray.tobytes(np.array(indx_list_int), 'C')
        target.simpleserial_write(commands[command], indx_serial)
        time.sleep(0.5)
        c_slice_bytes = target.simpleserial_read("r", 64)
        c_slice_hex = bytes_to_hex_str(c_slice_bytes)
        full_str += c_slice_hex
    return full_str

def hex_c_to_int_c1_c2(hex_c):
    """
    
    """
    c1 = polyvec_decompress(unhexlify(hex_c[:K*C1_BYTES]))
        
    c2 = poly_decompress(unhexlify(hex_c[K*C1_BYTES:]))
    return c1, c2   


def reset_sk():
    """
    
    """
    target.simpleserial_write(commands["reset_offset_sk"], bytes())
    
def serialize_sk(SK):
    """
    
    """
    SK_serial = []
    for len_ in range(0, 2*SK_BYTES, 2*SERIAL_BYTES):
        sk_hex_str = SK[len_:len_ + 2*SERIAL_BYTES]
        sk_list_int = np.fromiter((int(x, 16) for x in [sk_hex_str[idx:idx+2] for idx in range(0, len(sk_hex_str), 2)] ), dtype=np.uint8)
        sk_serial = np.ndarray.tobytes(np.array(sk_list_int), 'C')
        SK_serial.append(sk_serial)
    return SK_serial

def send_sk(serialized_sk, reset = False):
    """
    
    """
    if reset:
        reset_sk()
        
    time.sleep(1)   
    for sk_serial in serialized_sk:
        target.simpleserial_write(commands["send_sk"], sk_serial)
        time.sleep(0.5)
        
def get_full_sk_hex_str():
    """
    
    """
    command = "receive_sk"

    full_str = ""
    for indx in trange(0, SK_BYTES, 64, desc= "Receiving data"):
        indx_hex_str = int_to_cw(indx)
        indx_list_int = np.fromiter((int(x, 16) for x in [indx_hex_str[idx:idx+2] for idx in range(0, len(indx_hex_str), 2)] ), dtype=np.uint8)
        indx_serial = np.ndarray.tobytes(np.array(indx_list_int), 'C')
        target.simpleserial_write(commands[command], indx_serial)
        time.sleep(1)
        sk_slice_bytes = target.simpleserial_read("r", 64)
        sk_slice_hex = bytes_to_hex_str(sk_slice_bytes)
        full_str += sk_slice_hex
    return full_str


def kyber_decrypt(u, v, read = True, capture = False):
    """
    Maps a vector of polynomials of N coefficients in [0, 2^{d}[ to [0, Q[
    Only considers the input u from Kyber PKE Encrypt
    
    Inputs:
    --------
    u       (list[list[int]]): u vector from Kyber Encrypt with coeffs in ZZ_q
    v       (list[int])      : v polynomial from Kyber Encrypt with coeffs in ZZ_q
    read    (bool | True)    : Flag to read outputed Kyber PKE ciphertext or not
    capture (bool | False)   : Flag to capture trace during Kyber PKE decrypt or not
    
    Outputs:
    --------
    msg_bytes (bytes[32])  : If read = True Kyber PKE ciphertext, else None
    trace     (list[float]): If capture = True Execution trace, else None 
    """
    # compress u and v 
    c1 = polyvec_compress(u)
    c2 = poly_compress(v)
    
    # pack compressed versions of u and v
    serialized_c = serialize_c(c1, c2) 
    
    # send ciphertext to the chipwhisperer
    send_c(serialized_c, reset = True)
    time.sleep(0.4)
    
    if capture:
        scope.arm()
        
    # call to the decrypt function of kyber
    target.simpleserial_write(commands["kyber_decrypt"], bytes())
    
    if capture:
        ret = scope.capture()
        if ret:
            print("Target times out!")

    if read:
        msg_bytes = target.simpleserial_read("r", 32)
    
    if capture:
        trace = scope.get_last_trace()
        if not read:    
            return None, trace
        else:
            return msg_bytes, trace
    else:
        if read:    
            return msg_bytes, None
        else:
            return None, None        