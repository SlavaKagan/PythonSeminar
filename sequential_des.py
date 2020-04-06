###################################
# Team Members:
# Viatcheslav Kagan 	311763213
# Liad Khamdadash		313299877
###################################

# This class execute Data Encryption standard algorithm while using sequential implementation (the regular way)
# Encryption of a long text (famous story) and after that decryption to the initial text

from typing import Tuple, List, Iterable
from enum import Enum
from AlgorithmTables import Tables


class Cryptography(Enum):
    ENCRYPT = 1  # For encrypting
    DECRYPT = 0  # For decrypting


class Des:

    def __init__(self, des_key: str):
        if len(des_key) < 8:
            raise Exception("Key Should be 8 bytes long")
        elif len(des_key) > 8:
            des_key = des_key[:8]  # If key size is above 8bytes, cut to be 8bytes long

        self._keys = self.generate_keys(des_key)  # Generate all the keys

    def encrypt(self, plaintext: str) -> str:            # Encrypting
        return self.run(plaintext, Cryptography.ENCRYPT)

    def decrypt(self, ciphertext: str) -> str:           # Decrypting
        return self.run(ciphertext, Cryptography.DECRYPT)

    def run(self, text1: str, action: Cryptography) -> str:
        chunks, chunk_size = len(text1), 8
        # join() method takes all items in an iterable and joins them into one string
        return "".join([self.run_block(text1[i:i + chunk_size], action) for i in range(0, chunks, chunk_size)])

    def run_block(self, des_text: str, action=Cryptography.ENCRYPT) -> str:

        if action == Cryptography.ENCRYPT and len(des_text) != 8:
            des_text = self.add_padding(des_text)
        elif len(des_text) % 8 != 0:  # If not padding specified data size must be multiple of 8 bytes
            raise Exception("Data size should be multiple of 8")

        text_blocks = self.n_split(des_text, 8)  # Split the text in blocks of 8 bytes so 64 bits
        result = list()
        for block in text_blocks:  # Loop over all the blocks of data
            block = self.string_to_bit_array(block)  # Convert the block in bit array
            block = self.permutation_expand(block, Tables.IP_TABLE)  # Apply the initial permutation
            left, right = self.n_split(block, 32)  # LEFT, RIGHT
            tmp = None
            for i in range(16):  # Do the 16 rounds
                d_e = self.permutation_expand(right, Tables.E_BIT_SELECTION_TABLE)  # Expand right to match
                # Ki size (48bits)
                if action == Cryptography.ENCRYPT:
                    tmp = self.xor(self._keys[i], d_e)  # If encrypt use Ki
                else:
                    tmp = self.xor(self._keys[15 - i], d_e)  # If decrypt start by the last key
                tmp = self.substitute(tmp)  # Method that will apply the SBOXes
                tmp = self.permutation_expand(tmp, Tables.P_TABLE)
                tmp = self.xor(left, tmp)
                left = right
                right = tmp
            result += self.permutation_expand(right + left, Tables.IP_1_TABLE)  # Do the last permutation
            # and append the result to result
        final_res = self.bit_array_to_string(result)
        if action == Cryptography.DECRYPT and final_res[7] == '\0':
            return self.remove_padding(final_res)  # Remove the padding if decrypt and padding is true
        else:
            return final_res  # Return the final string of data ciphered/deciphered

    "##################### CLASS METHODS #####################"
    # @class method - returns a class method for the given function
    # methods that are bound to a class rather than its object.
    @classmethod
    def generate_keys(cls, des_key: str) -> List[list]:
        """
        Algorithm that generates all the keys
        :param cls: string
        :param des_key: string
        :return: list of keys after generation
        """

        keys = []
        des_key = cls.string_to_bit_array(des_key)
        des_key = cls.permutation_expand(des_key, Tables.PC_1_TABLE)  # Apply the initial Permutation on the key
        left, right = cls.n_split(des_key, 28)  # Split it in to LEFT,RIGHT
        for i in range(16):  # Apply the 16 rounds
            left, right = cls.shift(left, right,
                                    Tables.SHIFT_ARRAY[i])  # Apply the shift associated with the round (not always 1)
            tmp = left + right  # Merge them
            keys.append(cls.permutation_expand(tmp, Tables.PC_2_TABLE))  # Apply the Permutation to get the Ki
        return keys

    "##################### STATIC METHODS #####################"

    # @staticmethod - returns a static method for a given function
    # methods that are bound to a class rather than its object.
    @staticmethod
    def permutation_expand(block, table: List) -> List[chr]:
        """
        Permutation the given block using the given table
        :param block: block list
        :param table: some table
        :return: list after permutation
        """
        return [block[x - 1] for x in table]

    @staticmethod
    def shift(left: str, right: str, n: int) -> Tuple[str, str]:
        """
        Shift a list of the given value
        :param left: some string
        :param right: some string
        :param n: integer
        :return: a tuple after shifting
        """

        return left[n:] + left[:n], right[n:] + right[:n]

    @staticmethod
    def add_padding(text1: str) -> str:
        """
        Add padding to the data using PKCS5 spec
        :param text1: string data
        :return: string after padding
        """

        pad_len = 8 - (len(text1) % 8)
        return text1 + (pad_len * '\0')

    @staticmethod
    def remove_padding(data: str) -> str:
        """
        Remove the padding of the plain text (it assume there is padding)
        :param data: a string
        :return: string without padding
        """

        # find() method finds the first occurrence of the specified value
        return data[:data.find('\0')]

    @staticmethod
    def bin_value(val: str, bits_size: int) -> str:
        """
        Get the value and size expected of a string and convert it to binary with padding '0'
        :param val: The value need to convert to binary
        :param bits_size: The size is expected to get
        :raise exception: If no binary value is larger than the expected size
        :return: The binary value of a given string with padding '0'
        """

        # ord() function returns an integer representing the Unicode character.
        # bin() method converts and returns the binary equivalent string of a given integer.
        # isinstance() function checks if the object (first argument) is an instance or subclass
        # of class info class (second argument).
        # len() function returns the number of items (length) in an object.

        bin_val = (bin(val) if isinstance(val, int) else bin(ord(val)))[2:]

        if len(bin_val) > bits_size:
            raise Exception("Binary value larger than the expected size")
        while len(bin_val) < bits_size:
            bin_val = "0" + bin_val  # Add as many 0 as needed to get the wanted size
        return bin_val

    @staticmethod
    def n_split(text1: Iterable, n: int) -> list:
        """
        Split a list into sub lists of size n
        :param text1: get list
        :param n: size of sublist
        :return: sub lists of the general list
        """

        # range() function returns a sequence of numbers, starting from 0 by default, and increments
        # by 1 (by default), and ends at a specified number.
        # len() function returns the number of items (length) in an object.

        return [text1[k:k + n] for k in range(0, len(text1), n)]

    @staticmethod
    def xor(t1, t2):
        """
        Apply a xor and return the resulting list
        :param t1: object
        :param t2: object
        :return: list after implementing xor function
        """

        # The zip() function takes iterables (can be zero or more), aggregates them in a tuple, and return it
        return [x ^ y for x, y in zip(t1, t2)]

    @staticmethod
    def string_to_bit_array(text_string: str) -> list:
        """
        Convert a string into a list of bits
        :param text_string: string that need to convert to list of bits
        :return: list of bits
        """

        # list() constructor returns a list in Python
        # int() method returns an integer object from any number or string

        array = list()
        for char in text_string:
            bin_val = Des.bin_value(char, 8)  # Get the char value on one byte
            array.extend([int(x) for x in list(bin_val)])  # Add the bits to the final list
        return array

    @staticmethod
    def substitute(d_e: Iterable) -> List[int]:
        """
        Substitute bytes using S_BOX table
        :param d_e: bit array
        :return: list of bits
        """

        sub_blocks = Des.n_split(d_e, 6)  # Split bit array into sublist of 6 bits
        result = list()
        for i in range(len(sub_blocks)):  # For all the subLists
            block = sub_blocks[i]
            row = int(str(block[0]) + str(block[5]), 2)  # Get the row with the first and last bit
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2)  # Column is the 2,3,4,5th bits
            val = Tables.S_BOX_TABLES[i][row][column]  # Take the value in the S_BOX appropriated for the round (i)
            bin_attr = Des.bin_value(val, 4)  # Convert the value to binary
            result += [int(x) for x in bin_attr]  # And append it to the resulting list
        return result

    @staticmethod
    def bit_array_to_string(array: Iterable) -> str:
        """
        Recreate the string from the bit list
        :param array: Iterable, list of bit
        :return: string from bit list
        """

        # int() method returns an integer object from any number or string
        # chr() method returns a character (a string) from an integer (represents unicode code point of the character).
        # str() function returns the string version of the given object.

        res = ''.join(
            [chr(int(y, 2)) for y in [''.join([str(x) for x in _bytes]) for _bytes in Des.n_split(array, 8)]])
        return res
