# Viatcheslav Kagan 	311763213
# Liad Khamdadash		313299877

import time

ENCRYPT = 1  # For encrypting
DECRYPT = 0  # For decrypting

# Initial permutation matrix of the 64 bits of the message data M
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Initial permutation made on the key
# The 64-bit key is permuted according to the following table, PC-1
PC_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Permutation applied on shifted key to get Ki+1
# We now form the keys Kn, for 1<=n<=16, by applying the following permutation table
# to each of the concatenated pairs CnDn. Each pair has 56 bits, but PC-2 only uses 48 of these.
PC_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

# E- BIT-SELECTION TABLE Expand matrix to get a 48bits matrix of data to apply the xor with Ki
# Let E be such that the 48 bits of its output, written as 8 blocks of 6 bits each,
# are obtained by selecting the bits in its inputs in order according to the following table:
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S_BOX: The tables defining the functions S1,...,S8 are the following:
S_BOX = [

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
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# IP^-1 Final permutation for data after the 16 rounds:
IP_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

# Matrix that determine the shift for each round of keys
# To do a left shift, move each bit one place to the left, except for the first bit,
# which is cycled to the end of the block.
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


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
        bin_val = bin_value(char, 8)  # Get the char value on one byte
        array.extend([int(x) for x in list(bin_val)])  # Add the bits to the final list
    return array


def n_split(list1: list, n: int) -> list:
    """
    Split a list into sub lists of size n
    :param list1: get list
    :param n: size of sublist
    :return: sub lists
    """

    # range() function returns a sequence of numbers, starting from 0 by default, and increments
    # by 1 (by default), and ends at a specified number.
    # len() function returns the number of items (length) in an object.

    return [list1[k:k + n] for k in range(0, len(list1), n)]


def bit_array_to_string(array: list) -> str:
    """
    Recreate the string from the bit array
    :param array: list of bit
    :return: string from bit array
    """

    # int() method returns an integer object from any number or string
    # chr() method returns a character (a string) from an integer (represents unicode code point of the character).
    # str() function returns the string version of the given object.

    res = ''.join([chr(int(y, 2)) for y in [''.join([str(x) for x in _bytes]) for _bytes in n_split(array, 8)]])
    return res


class Des:

    def __init__(self):
        """
        __init__ method  to initialize the object
        """
        self.password = None
        self.text = None
        self.keys = list()

    def run(self, des_key, des_text, action=ENCRYPT, padding=False):
        """
        The main method
        :param des_key: the key used for the algorithm
        :param des_text: the string to encrypt/decrypt
        :param action: encrypt/decrypt functions
        :param padding: padding with '0'
        :return:
        """

        if len(des_key) < 8:
            raise Exception("Key Should be 8 bytes long")
        elif len(des_key) > 8:
            des_key = des_key[:8]  # If key size is above 8bytes, cut to be 8bytes long

        self.password = des_key
        self.text = des_text

        if padding and action == ENCRYPT:
            self.add_padding()
        elif len(self.text) % 8 != 0:  # If not padding specified data size must be multiple of 8 bytes
            raise Exception("Data size should be multiple of 8")

        self.generate_keys()  # Generate all the keys
        text_blocks = n_split(self.text, 8)  # Split the text in blocks of 8 bytes so 64 bits
        result = list()
        for block in text_blocks:  # Loop over all the blocks of data
            block = string_to_bit_array(block)  # Convert the block in bit array
            block = self.permutation(block, IP)  # Apply the initial permutation
            left, right = n_split(block, 32)  # LEFT, RIGHT
            tmp = None
            for i in range(16):  # Do the 16 rounds
                d_e = self.expand(right, E)  # Expand right to match Ki size (48bits)
                if action == ENCRYPT:
                    tmp = self.xor(self.keys[i], d_e)  # If encrypt use Ki
                else:
                    tmp = self.xor(self.keys[15 - i], d_e)  # If decrypt start by the last key
                tmp = self.substitute(tmp)  # Method that will apply the SBOXes
                tmp = self.permutation(tmp, P)
                tmp = self.xor(left, tmp)
                left = right
                right = tmp
            result += self.permutation(right + left, IP_1)  # Do the last permutation and append the result to result
        final_res = bit_array_to_string(result)
        if padding and action == DECRYPT:
            return self.remove_padding(final_res)  # Remove the padding if decrypt and padding is true
        else:
            return final_res  # Return the final string of data ciphered/deciphered

    @staticmethod
    def substitute(d_e):
        """
        Substitute bytes using S_BOX
        :param d_e:
        :return:
        """
        sub_blocks = n_split(d_e, 6)  # Split bit array into sublist of 6 bits
        result = list()
        for i in range(len(sub_blocks)):  # For all the subLists
            block = sub_blocks[i]
            row = int(str(block[0]) + str(block[5]), 2)  # Get the row with the first and last bit
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2)  # Column is the 2,3,4,5th bits
            val = S_BOX[i][row][column]  # Take the value in the S_BOX appropriated for the round (i)
            bin_attr = bin_value(val, 4)  # Convert the value to binary
            result += [int(x) for x in bin_attr]  # And append it to the resulting list
        return result

    @staticmethod
    def permutation(block, table):
        """
        Permutation the given block using the given table
        :param block:
        :param table:
        :return:
        """
        return [block[x - 1] for x in table]

    @staticmethod
    def expand(block, table):
        """
        Permutation the given block using the given table
        Do the exact same thing than Permutation but for more clarity has been renamed
        :param block:
        :param table:
        :return:
        """
        return [block[x - 1] for x in table]

    @staticmethod
    def xor(t1, t2):
        """
        Apply a xor and return the resulting list
        :param t1:
        :param t2:
        :return:
        """
        return [x ^ y for x, y in zip(t1, t2)]

    def generate_keys(self):
        """
        Algorithm that generates all the keys
        """
        self.keys = []
        des_key = string_to_bit_array(self.password)
        des_key = self.permutation(des_key, PC_1)  # Apply the initial Permutation on the key
        left, right = n_split(des_key, 28)  # Split it in to LEFT,RIGHT
        for i in range(16):  # Apply the 16 rounds
            left, right = self.shift(left, right, SHIFT[i])  # Apply the shift associated with the round (not always 1)
            tmp = left + right  # Merge them
            self.keys.append(self.permutation(tmp, PC_2))  # Apply the Permutation to get the Ki

    @staticmethod
    def shift(left, right, n):
        """
        Shift a list of the given value
        :param left:
        :param right:
        :param n:
        :return:
        """
        return left[n:] + left[:n], right[n:] + right[:n]

    def add_padding(self):
        """
        Add padding to the data using PKCS5 spec
        """
        pad_len = 8 - (len(self.text) % 8)
        self.text += pad_len * chr(pad_len)

    @staticmethod
    def remove_padding(data):
        """
        Remove the padding of the plain text (it assume there is padding)
        :param data:
        :return:
        """
        pad_len = ord(data[-1])
        return data[:-pad_len]

    def encrypt(self, des_key, des_text, padding=False):
        """
        Encryption text with DES algorithm
        :param des_key: the key used for the algorithm
        :param des_text: the string to encrypt/decrypt
        :param padding: padding with '0'
        :return:
        """
        return self.run(des_key, des_text, ENCRYPT, padding)

    def decrypt(self, des_key, des_text, padding=False):
        """
        Decryption ciphered text with DES algorithm
        :param des_key: the key used for the algorithm
        :param des_text: the string to encrypt/decrypt
        :param padding: padding with '0'
        :return:
        """
        return self.run(des_key, des_text, DECRYPT, padding)


if __name__ == '__main__':

    # open() function opens a file, and returns it as a file object
    # float() method returns a floating point number from a number or a string
    # print() function prints the specified message to the screen, or other standard output device
    # "w" - Write - will overwrite any existing content
    # time() returns the time as a floating point number expressed in seconds since the epoch, in UTC

    key = "secret_k"
    text = "Hello wo"
    d = Des()

    file = open("results.txt", "w+")
    start = time.time()
    r = d.encrypt(key, text)        # encryption text with DES algorithm
    end = time.time()
    total_time = float(end)-float(start)
    file.write('Sequential time encryption result: %f sec' % total_time)
    print("Ciphered: %r" % r)
    print("Time: %s" % total_time)

    start = time.time()
    r2 = d.decrypt(key, r)          # decryption ciphered text with DES algorithm
    end = time.time()
    total_time = float(end) - float(start)
    file.write('\nSequential time decryption result: %f sec' % total_time)
    print("\nDeciphered: ", r2)
    print("Time: %s" % total_time)

    file.close()
