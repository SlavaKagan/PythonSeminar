###################################
# Team Members:
# Viatcheslav Kagan 	311763213
# Liad Khamdadash		313299877
###################################

from typing import Tuple, List, Iterable
from enum import Enum


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
            block = self.permutation_expand(block, self.IP_TABLE)  # Apply the initial permutation
            left, right = self.n_split(block, 32)  # LEFT, RIGHT
            tmp = None
            for i in range(16):  # Do the 16 rounds
                d_e = self.permutation_expand(right, self.E_BIT_SELECTION_TABLE)  # Expand right to match
                # Ki size (48bits)
                if action == Cryptography.ENCRYPT:
                    tmp = self.xor(self._keys[i], d_e)  # If encrypt use Ki
                else:
                    tmp = self.xor(self._keys[15 - i], d_e)  # If decrypt start by the last key
                tmp = self.substitute(tmp)  # Method that will apply the SBOXes
                tmp = self.permutation_expand(tmp, self.P_TABLE)
                tmp = self.xor(left, tmp)
                left = right
                right = tmp
            result += self.permutation_expand(right + left, self.IP_1_TABLE)  # Do the last permutation
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
        des_key = cls.permutation_expand(des_key, cls.PC_1_TABLE)  # Apply the initial Permutation on the key
        left, right = cls.n_split(des_key, 28)  # Split it in to LEFT,RIGHT
        for i in range(16):  # Apply the 16 rounds
            left, right = cls.shift(left, right,
                                    cls.SHIFT_ARRAY[i])  # Apply the shift associated with the round (not always 1)
            tmp = left + right  # Merge them
            keys.append(cls.permutation_expand(tmp, cls.PC_2_TABLE))  # Apply the Permutation to get the Ki
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
            val = Des.S_BOX_TABLES[i][row][column]  # Take the value in the S_BOX appropriated for the round (i)
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

    "##################### TABLES #####################"
    # Initial permutation made on the key
    # The 64-bit key is permuted according to the following table, PC-1
    PC_1_TABLE = [57, 49, 41, 33, 25, 17, 9,
                  1, 58, 50, 42, 34, 26, 18,
                  10, 2, 59, 51, 43, 35, 27,
                  19, 11, 3, 60, 52, 44, 36,
                  63, 55, 47, 39, 31, 23, 15,
                  7, 62, 54, 46, 38, 30, 22,
                  14, 6, 61, 53, 45, 37, 29,
                  21, 13, 5, 28, 20, 12, 4]

    # Array that determine the shift for each round of keys
    # To do a left shift, move each bit one place to the left, except for the first bit,
    # which is cycled to the end of the block.
    SHIFT_ARRAY = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # Permutation applied on shifted key to get Ki+1
    # We now form the keys Kn, for 1<=n<=16, by applying the following permutation table
    # to each of the concatenated pairs CnDn. Each pair has 56 bits, but PC-2 only uses 48 of these.
    PC_2_TABLE = [14, 17, 11, 24, 1, 5, 3, 28,
                  15, 6, 21, 10, 23, 19, 12, 4,
                  26, 8, 16, 7, 27, 20, 13, 2,
                  41, 52, 31, 37, 47, 55, 30, 40,
                  51, 45, 33, 48, 44, 49, 39, 56,
                  34, 53, 46, 42, 50, 36, 29, 32]

    # Initial permutation matrix of the 64 bits of the message data M
    IP_TABLE = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

    # E- BIT-SELECTION TABLE Expand matrix to get a 48bits matrix of data to apply the xor with Ki
    # Let E be such that the 48 bits of its output, written as 8 blocks of 6 bits each,
    # are obtained by selecting the bits in its inputs in order according to the following table:
    E_BIT_SELECTION_TABLE = [32, 1, 2, 3, 4, 5,
                             4, 5, 6, 7, 8, 9,
                             8, 9, 10, 11, 12, 13,
                             12, 13, 14, 15, 16, 17,
                             16, 17, 18, 19, 20, 21,
                             20, 21, 22, 23, 24, 25,
                             24, 25, 26, 27, 28, 29,
                             28, 29, 30, 31, 32, 1]

    # S_BOX: The tables defining the functions S1,...,S8 are the following:
    S_BOX_TABLES = [

        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
         ],

        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
         ],

        # S3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
         ],

        # S4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
         ],

        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
         ],

        # S6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
         ],

        # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
         ],

        # S8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
         ]
    ]

    # Permutation made after each S_Box substitution for each round
    # P yields a 32-bit output from a 32-bit input by permuting the bits of the input block.
    P_TABLE = [16, 7, 20, 21, 29, 12, 28, 17,
               1, 15, 23, 26, 5, 18, 31, 10,
               2, 8, 24, 14, 32, 27, 3, 9,
               19, 13, 30, 6, 22, 11, 4, 25]

    # IP^-1 Final permutation for data after the 16 rounds:
    IP_1_TABLE = [40, 8, 48, 16, 56, 24, 64, 32,
                  39, 7, 47, 15, 55, 23, 63, 31,
                  38, 6, 46, 14, 54, 22, 62, 30,
                  37, 5, 45, 13, 53, 21, 61, 29,
                  36, 4, 44, 12, 52, 20, 60, 28,
                  35, 3, 43, 11, 51, 19, 59, 27,
                  34, 2, 42, 10, 50, 18, 58, 26,
                  33, 1, 41, 9, 49, 17, 57, 25]
