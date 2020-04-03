###################################
# Team Members:
# Viatcheslav Kagan 	311763213
# Liad Khamdadash		313299877
###################################

from textToEnc import text
import time
from sequential_des import Des as Sequential_Des
from parallel_des import Des as Parallel_Des

# open() function opens a file, and returns it as a file object
# float() method returns a floating point number from a number or a string
# round() function returns a floating-point number rounded to the specified number of decimals
# print() function prints the specified message to the screen, or other standard output device
# "w" - Write - will overwrite any existing content
# time() returns the time as a floating point number expressed in seconds since the epoch, in UTC


# Execute the main method now that all the dependencies have been defined.
# The if __name__ is so that pydoc works and we can still run on the command line.
if __name__ == '__main__':
    key = "pySeminar"       # 56 bits

    print('Data itself appears in the "data_results.txt" file:\n')
    print('Time results for DES algorithm Enc+Dec')
    print(f"The secret key: {key}\n")

    "##################### Sequential Section #####################"
    print('############## Sequential Section ###########')
    des_seq = Sequential_Des(key)

    start_enc_seq = time.time()
    encrypted_text_seq = des_seq.encrypt(text)  # encryption text with DES algorithm
    end_enc_seq = time.time()
    total_time_enc_seq = round(float(end_enc_seq) - float(start_enc_seq), 3)

    print(f"Sequential time Encryption result: {total_time_enc_seq} sec")

    start_dec_seq = time.time()
    decrypted_text_seq = des_seq.decrypt(encrypted_text_seq)  # decryption ciphered text with DES algorithm
    end_dec_seq = time.time()
    total_time_dec_seq = round(float(end_dec_seq) - float(start_dec_seq), 3)

    print(f'Sequential time Decryption result: {total_time_dec_seq} sec\n')

    "##################### Parallel Section #####################"
    print('############## Parallel Section ###########')
    des_para = Parallel_Des(key)

    start_enc_para = time.time()
    encrypted_text_para = des_para.encrypt(text)  # encryption text with DES algorithm
    end_enc_para = time.time()
    total_time_enc_para = round(float(end_enc_para) - float(start_enc_para), 3)

    print(f"Parallel time Encryption result: {total_time_enc_para} sec")

    start_dec_para = time.time()
    decrypted_text_para = des_para.decrypt(encrypted_text_para)  # decryption ciphered text with DES algorithm
    end_dec_para = time.time()
    total_time_dec_para = round(float(end_dec_para) - float(start_dec_para), 3)

    print(f'Parallel time Decryption result: {total_time_dec_para} sec\n')

    difference_enc = round(total_time_enc_seq - total_time_enc_para, 3)
    difference_dec = round(total_time_dec_seq - total_time_dec_para, 3)

    print(f"The Encrypted text in both ways are the same? {encrypted_text_seq == encrypted_text_para}")
    print(f"The Decrypted text in both ways are the same? {decrypted_text_seq == decrypted_text_para}\n")

    print('############# Difference Time #########')
    print(f"Time difference Encryption: {difference_enc} sec")
    print(f"Time difference Decryption: {difference_dec} sec")

    "##################### File Section #####################"
    with open("data_results.txt", "w") as file:
        file.write("#### Results for Data Encryption Standard Algorithm ####\n\n")
        file.write(f"The secret key: {key}\n\n")

        file.write("########### Sequential Section ##############:\n")
        file.write(f"Deciphered Text:\n {text}\n\n")
        file.write(f"Encryption-Ciphered:\n {encrypted_text_seq}\n\n")
        file.write(f"Decryption-Deciphered text:\n {decrypted_text_seq}\n")

        file.write("########### Parallel Section ##############:\n")
        file.write(f"Deciphered Text: \n {text}\n\n")
        file.write(f"Encryption-Ciphered: \n {encrypted_text_para}\n\n")
        file.write(f"Decryption-Deciphered text:\n {decrypted_text_para}")

    with open("time_results.txt", "w") as file2:
        file2.write("########### Difference Time ###############:\n")
        file2.write(f"Sequential time Encryption result: {total_time_enc_seq} sec\n")
        file2.write(f"Sequential time Decryption result: {total_time_dec_seq} sec\n\n")
        file2.write(f"Parallel time Encryption result: {total_time_enc_para} sec\n")
        file2.write(f"Parallel time Decryption result: {total_time_dec_para} sec\n\n")

        file2.write(f"Time difference Encryption: {difference_enc} sec\n")
        file2.write(f"Time difference Decryption: {difference_dec} sec")
