###################################
# Authors:
# Slava Kagan
# Liad Khamdadash
###################################

# This class execute data encryption standard algorithm while using parallel implementation with thread pool
# Encryption of a long text (famous story) and after that decryption to the initial text

#####################
# General python functions we used in this file:
# int() method returns an integer object from any number or string
# chr() method returns a character (a string) from an integer (represents unicode code
# point of the character).
# str() function returns the string version of the given object.
# range() function returns a sequence of numbers, starting from 0 by default, and increments by 1.
# (by default), and ends at a specified number.
# len() function returns the number of items (length) in an object.
# list() constructor returns a list in Python
# zip() function takes iterables (can be zero or more), aggregates them in a tuple, and return it
# ord() function returns an integer representing the Unicode character.
# bin() method converts and returns the binary equivalent string of a given integer.
# isinstance() function checks if the object (first argument) is an instance or subclass
# of class info class (second argument).
# find() method finds the first occurrence of the specified value.
# join() method takes all items in an iterable and joins them into one string.
# raise Exception() allows to force a specified exception to occur.
#####################

from typing import Tuple, List, Iterable
from enum import Enum
from multiprocessing.pool import ThreadPool
from AlgorithmTables import Tables


class Cryptography(Enum):
    ENCRYPT = 1  # For encrypting
    DECRYPT = 0  # For decrypting


class Des:

    def __init__(self, des_key: str):
        """
        :param des_key: string
        """

        if len(des_key) < 8:
            raise Exception("Key Should be 8 bytes long")
        elif len(des_key) > 8:
            # If key size is above 8bytes, cut to be 8bytes long
            des_key = des_key[:8]

        # Generate all the keys
        self._keys = self.generate_keys(des_key)

    # Encrypting
    def encrypt(self, plaintext: str) -> str:
        """
        Encryption of a given text
        :param plaintext: string
        :return: return the cipher text
        """

        return self.run(plaintext, Cryptography.ENCRYPT)

    # Decrypting
    def decrypt(self, ciphertext: str) -> str:
        """
        Decryption of a given ciphertext
        :param ciphertext: string
        return: return the given story text
        """

        return self.run(ciphertext, Cryptography.DECRYPT)

    def run(self, text1: str, action: Cryptography):
        """
        Run the algorithm with threads pool way
        :param text1: string
        :param action: Enum
        """

        chunks, chunk_size = len(text1), 8
        """
        ThreadPool().map - The multiprocessing module also introduces APIs which do not have 
        analogs in the threading module. A prime example of this is the Pool object which offers
        a convenient means of parallelizing the execution of a function across multiple input 
        values, distributing the input data across processes (data parallelism)
        """
        return "".join(ThreadPool().map(lambda s: self.run_block(s, action),
                                        [text1[i:i + chunk_size] for i in range(0, chunks, 8)]))

    def run_block(self, dec_text: str, action=Cryptography.ENCRYPT):
        """
        Implement the algorithm
        :param dec_text: string
        :param action: Enum
        """

        if action == Cryptography.ENCRYPT and len(dec_text) != 8:
            dec_text = self.add_padding(dec_text)
        # If not padding specified data size must be multiple of 8 bytes
        elif len(dec_text) % 8 != 0:
            raise Exception("Data size should be multiple of 8")

        # Split the text in blocks of 8 bytes so 64 bits
        text_blocks = self.n_split(dec_text, 8)
        result = list()
        # Loop over all the blocks of data
        for block in text_blocks:
            # Convert the block in bit array
            block = self.string_to_bit_array(block)
            # Apply the initial permutation
            block = self.permutation_expand(block, Tables.IP_TABLE)
            left, right = self.n_split(block, 32)
            tmp = None
            # Do the 16 rounds
            for i in range(16):
                d_e = self.permutation_expand(right, Tables.E_BIT_SELECTION_TABLE)
                # Expand right to match Ki size (48bits)
                if action == Cryptography.ENCRYPT:
                    # If encrypt use Ki
                    tmp = self.xor(self._keys[i], d_e)
                else:
                    # If decrypt start by the last key
                    tmp = self.xor(self._keys[15 - i], d_e)
                # Method that will apply the SBOXes
                tmp = self.substitute(tmp)
                tmp = self.permutation_expand(tmp, Tables.P_TABLE)
                tmp = self.xor(left, tmp)
                left = right
                right = tmp
            # Do the last permutation and append the result to result
            result += self.permutation_expand(right + left, Tables.IP_1_TABLE)
        final_res = self.bit_array_to_string(result)
        if action == Cryptography.DECRYPT and final_res[7] == '\0':
            # Remove the padding if decrypt and padding is true
            return self.remove_padding(final_res)
        else:
            # Return the final string of data ciphered/deciphered
            return final_res

    "##################### CLASS METHODS #####################"
    # @class method - returns a class method for the given function methods
    # that are bound to a class rather than its object.
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
        # Apply the initial Permutation on the key
        des_key = cls.permutation_expand(des_key, Tables.PC_1_TABLE)
        # Split it in to LEFT,RIGHT
        left, right = cls.n_split(des_key, 28)
        # Apply the 16 rounds
        for i in range(16):
            # Apply the shift associated with the round (not always 1)
            left, right = cls.shift(left, right, Tables.SHIFT_ARRAY[i])
            # Merge them
            tmp = left + right
            # Apply the Permutation to get the Ki
            keys.append(cls.permutation_expand(tmp, Tables.PC_2_TABLE))
        return keys

    "##################### STATIC METHODS #####################"
    # @staticmethod - returns a static method for a given function methods
    # that are bound to a class rather than its object.
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

        return data[:data.find('\0')]

    @staticmethod
    def bin_value(val: str, bits_size: int) -> str:
        """
        Get the value and size expected of a string and convert
        it to binary with padding '0'
        :param val: The value need to convert to binary
        :param bits_size: The size is expected to get
        :raise exception: If no binary value is larger than the expected size
        :return: The binary value of a given string with padding '0'
        """

        bin_val = (bin(val) if isinstance(val, int) else bin(ord(val)))[2:]

        if len(bin_val) > bits_size:
            raise Exception("Binary value larger than the expected size")
        while len(bin_val) < bits_size:
            # Add as many 0 as needed to get the wanted size
            bin_val = "0" + bin_val
        return bin_val

    @staticmethod
    def n_split(text1: Iterable, n: int) -> list:
        """
        Split a list into sub lists of size n
        :param text1: get list
        :param n: size of sublist
        :return: sub lists of the general list
        """

        return [text1[k:k + n] for k in range(0, len(text1), n)]

    @staticmethod
    def xor(t1, t2):
        """
        Apply a xor and return the resulting list
        :param t1: object
        :param t2: object
        :return: list after implementing xor function
        """

        return [x ^ y for x, y in zip(t1, t2)]

    @staticmethod
    def string_to_bit_array(text_string: str) -> list:
        """
        Convert a string into a list of bits
        :param text_string: string that need to convert to list of bits
        :return: list of bits
        """

        array = list()
        for char in text_string:
            # Get the char value on one byte
            bin_val = Des.bin_value(char, 8)
            # Add the bits to the final list
            array.extend([int(x) for x in list(bin_val)])
        return array

    @staticmethod
    def substitute(d_e: Iterable) -> List[int]:
        """
        Substitute bytes using S_BOX table
        :param d_e: bit array
        :return: list
        """

        # Split bit array into sublist of 6 bits
        sub_blocks = Des.n_split(d_e, 6)
        result = list()
        # For all the subLists
        for i in range(len(sub_blocks)):
            block = sub_blocks[i]
            #  Get the row with the first and last bit
            row = int(str(block[0]) + str(block[5]), 2)
            # Column is the 2,3,4,5th bits
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2)
            # Take the value in the S_BOX appropriated for the round (i)
            val = Tables.S_BOX_TABLES[i][row][column]
            # Convert the value to binary
            bin_attr = Des.bin_value(val, 4)
            # And append it to the resulting list
            result += [int(x) for x in bin_attr]
        return result

    @staticmethod
    def bit_array_to_string(array: Iterable) -> str:
        """
        Recreate the string from the bit list
        :param array: Iterable, list of bit
        :return: string from bit list
        """

        res = ''.join(
            [chr(int(y, 2)) for y in [''.join([str(x) for x in _bytes])
                                      for _bytes in Des.n_split(array, 8)]])
        return res
