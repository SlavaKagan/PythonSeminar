from textToEnc import text
import time
from sequential_des import Des as Sequential_Des
from parallel_des import Des as Parallel_Des

# open() function opens a file, and returns it as a file object
# float() method returns a floating point number from a number or a string
# print() function prints the specified message to the screen, or other standard output device
# "w" - Write - will overwrite any existing content
# time() returns the time as a floating point number expressed in seconds since the epoch, in UTC


# Execute the main method now that all the dependencies have been defined.
# The if __name__ is so that pydoc works and we can still run on the command line.
if __name__ == '__main__':
    key = "pySeminar"       # 56 bits

    "##################### Sequential #####################"

    des_seq = Sequential_Des(key)

    start_enc_seq = time.time()
    encrypted_text_seq = des_seq.encrypt(text)  # encryption text with DES algorithm
    end_enc_seq = time.time()
    total_time_enc_seq = float(end_enc_seq) - float(start_enc_seq)

    print(f"Sequential time encryption result: {total_time_enc_seq}")

    start_dec_seq = time.time()
    decrypted_text_seq = des_seq.decrypt(encrypted_text_seq)  # decryption ciphered text with DES algorithm
    end_dec_seq = time.time()
    total_time_dec_seq = float(end_dec_seq) - float(start_dec_seq)

    print(f'Sequential time decryption result: {total_time_dec_seq}')

    "##################### Parallel #####################"

    des_para = Parallel_Des(key)

    start_enc_para = time.time()
    encrypted_text_para = des_seq.encrypt(text)  # encryption text with DES algorithm
    end_enc_para = time.time()
    total_time_enc_para = float(end_enc_para) - float(start_enc_para)

    print(f"Parallel time encryption result: {total_time_enc_para}")

    start_dec_para = time.time()
    decrypted_text_para = des_seq.decrypt(encrypted_text_para)  # decryption ciphered text with DES algorithm
    end_dec_para = time.time()
    total_time_dec_para = float(end_dec_para) - float(start_dec_para)

    print(f'Parallel time decryption result: {total_time_dec_para}')

    with open("results.txt", "w") as file:
        file.write("sequential\n")
        file.write(f"Deciphered Text: {text}")
        file.write("\nCiphered: %r" % encrypted_text_seq)
        file.write(f"\nSequential time encryption result: {total_time_enc_seq} sec")

        file.write("\n\nCiphered: %r" % encrypted_text_seq)
        file.write("\nDeciphered text: %r" % decrypted_text_seq)
        file.write("\nSequential time decryption result: %f sec\n\n" % total_time_dec_seq)

        file.write("parallel\n")
        file.write(f"Deciphered Text: {text}")
        file.write("\nCiphered: %r" % encrypted_text_para)
        file.write(f"\nParallel time encryption result: {total_time_enc_para} sec")

        file.write("\n\nCiphered: %r" % encrypted_text_para)
        file.write("\nDeciphered text: %r" % decrypted_text_para)
        file.write("\nParallel time decryption result: %f sec\n\n" % total_time_dec_para)
