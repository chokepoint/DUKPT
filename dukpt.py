from bitstring import BitArray
from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes

class InvalidDUKPTArguments(Exception):
    pass

class DUKPT:
    """Base DUKPT class with common functions of both client and server"""
    _pin_mask      = BitArray(hex="0x00000000000000FF00000000000000FF")
    _mac_req_mask  = BitArray(hex="0x000000000000FF00000000000000FF00")
    _mac_resp_mask = BitArray(hex="0x00000000FF00000000000000FF000000")
    _mac_data_req  = BitArray(hex="0x0000000000FF00000000000000FF0000")
    _mac_data_resp = BitArray(hex="0x000000FF00000000000000FF00000000")
    _ipek          = None
    _tdes_key      = None
    _cur_key       = None
    _ksn           = None
    BDK_LEN        = 16
    KSN_LEN        = 10

    def __init__(self, bdk=None, ksn=None, ipek=None):
        """Initialization
        Keyword arguments:
        bdk (raw or BitArray)  -- Base Derivation Key (16 bytes)
        ksn (raw or BitArray)  -- Key Serial Number (10 bytes)
        ipek (raw or BitArray) -- Initial Pin Encryption Key (16 bytes)
        """
        if ipek:
            if isinstance(ipek, BitArray):
                self._ipek = ipek
            else:
                self._ipek = BitArray(bytes=ipek)
            if isinstance(ksn, BitArray):
                self._ksn = ksn
            else:
                self._ksn  = BitArray(bytes=ksn)
        else:
            if not bdk:
                raise InvalidDUKPTArguments("Must have either ipek or bdk")
            if len(bdk) != self.BDK_LEN:
                raise InvalidDUKPTArguments("BDK must have a length of %d" % self.BDK_LEN)
            self._bdk = BitArray(bytes=bdk)
        
    def derive_key(self, ipek, ksn):
        """Derive a unique key given the ipek and ksn

        Keyword arguments:
        ipek (BitArray) -- Initial Pin Encryption Key
        ksn (BitArray)  -- Key Serial Number
        """
        c_mask       = BitArray(hex='0xc0c0c0c000000000c0c0c0c000000000')
        ksn_offset   = 2
        ctr_offset   = -3
        right_offset = 8

        # Registers taken from documentation
        curkey = ipek
        ksnr   = BitArray(bytes=ksn.bytes[ksn_offset:])
        r3     = self.copy_counter(ksnr)
        r8     = self.reset_counter(ksnr.bytes)
        sr     = BitArray(hex='0x100000')
       
        while (sr.bytes[0] != '\x00') or (sr.bytes[1] != '\x00') or (sr.bytes[2] != '\x00'):
            tmp = self.copy_counter(sr)
            tmp = tmp & r3
            if (tmp.bytes[0] != '\x00') or (tmp.bytes[1] != '\x00') or (tmp.bytes[2] != '\x00'): 
                # Step 2
                n_ctr = BitArray(bytes=r8.bytes[ctr_offset:]) | sr
                r8    = BitArray(bytes=r8.bytes[:ctr_offset]+n_ctr.bytes)
                
                # Step 3
                r8a   = r8 ^ BitArray(bytes=curkey.bytes[right_offset:])
                
                # Step 4
                cipher = DES.new(curkey.bytes[:DES.key_size], DES.MODE_ECB)
                r8a    = BitArray(bytes=cipher.encrypt(r8a.bytes))
                
                # Step 5
                r8a = BitArray(bytes=curkey.bytes[right_offset:]) ^ r8a

                # Step 6
                curkey = curkey ^ c_mask
                
                # Step 7
                r8b = BitArray(bytes=curkey.bytes[right_offset:]) ^ r8
                
                # Step 8
                cipher = DES.new(curkey.bytes[:DES.key_size], DES.MODE_ECB)
                r8b    = BitArray(bytes=cipher.encrypt(r8b.bytes))
                
                # Step 9
                r8b = BitArray(bytes=curkey.bytes[right_offset:]) ^ r8b

                # Step 10 / 11
                curkey = BitArray(bytes=r8b.bytes+r8a.bytes)

            sr >>= 1
        self._cur_key = curkey
        return curkey

    def reset_counter(self, data):
        """Reset the counter to zero

        Keyword arguments:
        data (raw or BitArray) -- Must be at least 3 bytes
        
        Return:
        BitArray of the data passed in
        """
        if isinstance(data, BitArray):
            data = data.bytes
        if len(data) < 3:
            return None
        mask = BitArray(hex='0xe00000')
        ctr  = BitArray(bytes=data[len(data)-3:])
        return BitArray(bytes=data[:-3] + (mask & ctr).bytes)

    def copy_counter(self, data):
        """Copy only the counter bytes from a given string or BitArray

        Keyword arguments:
        data (raw or BitArray) -- Must be at least 3 bytes

        Return:
        BitArray of only the counter bytes
        """
        mask = BitArray(hex='0x1fffff')
        if len(data.bytes) > 3:
            ctr = BitArray(bytes=data.bytes[-3:])
        else:
            ctr = data

        return mask & ctr

    def increase_counter(self):
        """Increase the counter bytes of the stored ksn by one"""
        ctr = self._ksn.cut(21, start=59).next().int + 1
        self._ksn.overwrite('0b'+BitArray(int=ctr, length=21).bin, 59)

class Server(DUKPT):
    def __init__(self, bdk=None):
        if bdk:
            DUKPT.__init__(self, bdk=bdk)
        else:
            self.bdk = self.generate_bdk()
            DUKPT.__init__(self, bdk=self.bdk)

    def generate_ksn(self):
        """Genereate a new random KSN with counter bits zeroed
        Return:
        BitArray of the new KSN
        """
        return self.reset_counter(get_random_bytes(self.KSN_LEN))
    def generate_bdk(self):
        """Generate a new random BDK
        Return:
        bytes of the new KSN
        """
        return get_random_bytes(self.BDK_LEN)

    def generate_ipek(self, ksn):
        """Generate a new IPEK based on the given KSN

        Keyword arguments:
        ksn (raw or BitArray) -- Key Serial Number

        Return:
        BitArray of the new IPEK
        """
        if isinstance(ksn, str):
            ksn = BitArray(bytes=ksn)
        self._tdes_key = self._bdk.bytes + self._bdk.bytes[:DES.key_size]
        self.generate_left_ipek(ksn)
        self.generate_right_ipek(ksn)
        return self._ipek

    def generate_left_ipek(self, ksn):
        """Generate the left portion of the IPEK (8 bytes)

        Keyword arguments:
        ksn (raw or BitArray) -- Key Serial Number)
        """
        ksn        = self.reset_counter(ksn.bytes)
        cipher     = DES3.new(self._tdes_key, DES3.MODE_ECB)
        self._ipek = BitArray(bytes=cipher.encrypt(ksn.bytes[:8]))

    def generate_right_ipek(self, ksn):
        """Generate the right portion of the IPEK (8 bytes)

        Keyword arguments:
        ksn (raw or BitArray) -- Key Serial Number
        """
        mask       = BitArray(hex="0xc0c0c0c000000000c0c0c0c000000000c0c0c0c000000000")
        key        = mask ^ BitArray(bytes=self._tdes_key)
        cipher     = DES3.new(key.bytes, DES3.MODE_ECB)
        self._ipek = BitArray(bytes=self._ipek.bytes + cipher.encrypt(ksn.bytes[:8]))

    def gen_key(self, ksn):
        """Generate the next key given the KSN
        
        Keyword arguments:
        ksn (raw or BitArray) -- Key Serial Number (10 bytes)
        
        Return:
        key in bytes
        """
        ipek = self.generate_ipek(ksn)
        key  = self.derive_key(ipek, BitArray(bytes=ksn))
        return key.bytes

class Client(DUKPT):
    def __init__(self, ipek, ksn):
        """Initialization of client
        
        Keyword arguments:
        ipek (raw or BitArray) -- Initial Pin Encryption Key
        ksn  (raw or BitArray) -- Key Serial Number
        """
        DUKPT.__init__(self, ipek=ipek, ksn=ksn)
        self.increase_counter()

    def gen_key(self):
        """Generate the next key in the sequence

        Return:
        key in bytes
        """
        key = self.derive_key(self._ipek, self._ksn)
        info = {'ksn': self._ksn.bytes, 'key': key.bytes}
        self.increase_counter()
        return info
