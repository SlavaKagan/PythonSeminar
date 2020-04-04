###################################
# Team Members:
# Viatcheslav Kagan 	311763213
# Liad Khamdadash		313299877
###################################

from textToEnc import text
import time
from sequential_des import Des as Sequential_Des
from parallel_des_fork import Des as Parallel_Des1
from parallel_des_pool import Des as Parallel_Des2

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

    print('Data itself appears in the "data_results_fork.txt/data_results_pool.txt" files:\n')
    print('Time results for DES algorithm Enc+Dec')
    print(f"The secret key: {key}\n")

    "##################### Sequential Section #####################"
    print('############## Sequential Section ###########')
    des_seq = Sequential_Des(key)

    start_enc_seq = time.time()
    encrypted_text_seq = des_seq.encrypt(text)  # sequential encryption text with DES algorithm
    end_enc_seq = time.time()
    total_time_enc_seq = round(float(end_enc_seq) - float(start_enc_seq), 3)

    print(f"Sequential time Encryption result: {total_time_enc_seq} sec")

    start_dec_seq = time.time()
    decrypted_text_seq = des_seq.decrypt(encrypted_text_seq)  # sequential decryption ciphered text with DES algorithm
    end_dec_seq = time.time()
    total_time_dec_seq = round(float(end_dec_seq) - float(start_dec_seq), 3)

    print(f'Sequential time Decryption result: {total_time_dec_seq} sec\n')

    "##################### Parallel Section #####################"
    print('############## Parallel Section ###########')
    des_para_fork = Parallel_Des1(key)
    des_para_pool = Parallel_Des2(key)

    start_enc_para_fork = time.time()
    encrypted_text_para_fork = des_para_fork.encrypt(text)  # parallel fork encryption text with DES algorithm
    end_enc_para_fork = time.time()
    total_time_enc_para_fork = round(float(end_enc_para_fork) - float(start_enc_para_fork), 3)

    print(f"Parallel time Encryption fork way result: {total_time_enc_para_fork} sec")

    start_enc_para_pool = time.time()
    encrypted_text_para_pool = des_para_pool.encrypt(text)  # parallel pool encryption text with DES algorithm
    end_enc_para_pool = time.time()
    total_time_enc_para_pool = round(float(end_enc_para_pool) - float(start_enc_para_pool), 3)

    print(f"Parallel time Encryption pool way result: {total_time_enc_para_pool} sec")

    start_dec_para_fork = time.time()
    decrypted_text_para_fork = des_para_fork.decrypt(encrypted_text_para_fork)  # parallel fork decryption ciphered text with DES algorithm
    end_dec_para_fork = time.time()
    total_time_dec_para_fork = round(float(end_dec_para_fork) - float(start_dec_para_fork), 3)

    print(f'Parallel time Decryption fork way result: {total_time_dec_para_fork} sec')

    start_dec_para_pool = time.time()
    decrypted_text_para_pool = des_para_pool.decrypt(encrypted_text_para_pool)  # parallel pool decryption ciphered text with DES algorithm
    end_dec_para_pool = time.time()
    total_time_dec_para_pool = round(float(end_dec_para_pool) - float(start_dec_para_pool), 3)

    print(f'Parallel time Decryption pool way result: {total_time_dec_para_pool} sec\n')

    difference_enc_fork = round(total_time_enc_seq - total_time_enc_para_fork, 3)
    difference_enc_pool = round(total_time_enc_seq - total_time_enc_para_pool, 3)
    difference_dec_fork = round(total_time_dec_seq - total_time_dec_para_fork, 3)
    difference_dec_pool = round(total_time_dec_seq - total_time_dec_para_pool, 3)

    print('############# Difference Time #########')
    print(f"Time difference Encryption fork way: {difference_enc_fork} sec")
    print(f"Time difference Encryption pool way: {difference_enc_pool} sec")
    print(f"Time difference Decryption fork way: {difference_dec_fork} sec")
    print(f"Time difference Decryption pool way: {difference_dec_pool} sec\n")

    print('############## Comparing Section ###########')
    print(f"Are the Decrypted text in Sequential the same as the initial text? {decrypted_text_seq == text}")
    print(f"Are the Decrypted text in Parallel fork way the same as the initial text? {decrypted_text_para_fork == text}")
    print(f"Are the Decrypted text in Parallel pool way the same as the initial text? {decrypted_text_para_pool == text}")

    print(f"Are the Encrypted text in both (seq+fork) ways the same? {encrypted_text_seq == encrypted_text_para_fork}")
    print(f"Are the Encrypted text in both (seq+pool) ways the same? {encrypted_text_seq == encrypted_text_para_pool}")
    print(f"Are the Decrypted text in both (seq+fork) ways the same? {decrypted_text_seq == decrypted_text_para_fork}")
    print(f"Are the Decrypted text in both (seq+pool) ways the same? {decrypted_text_seq == decrypted_text_para_pool}")

    "##################### File Section #####################"
    with open("data_results_fork.txt", "w") as file_fork:
        file_fork.write("#### Results for Data Encryption Standard Algorithm ####\n\n")
        file_fork.write(f"The secret key: {key}\n\n")

        file_fork.write("########### Sequential Section ##############:\n")
        file_fork.write(f"Deciphered Text:\n {text}\n\n")
        file_fork.write(f"Encryption-Ciphered:\n {encrypted_text_seq}\n\n")
        file_fork.write(f"Decryption-Deciphered text:\n {decrypted_text_seq}\n")

        file_fork.write("########### Parallel Section ##############:\n")
        file_fork.write(f"Deciphered Text: \n {text}\n\n")
        file_fork.write(f"Encryption-Ciphered: \n {encrypted_text_para_fork}\n\n")
        file_fork.write(f"Decryption-Deciphered text:\n {decrypted_text_para_fork}")

    with open("data_results_pool.txt", "w") as file_pool:
        file_pool.write("#### Results for Data Encryption Standard Algorithm ####\n\n")
        file_pool.write(f"The secret key: {key}\n\n")

        file_pool.write("########### Sequential Section ##############:\n")
        file_pool.write(f"Deciphered Text:\n {text}\n\n")
        file_pool.write(f"Encryption-Ciphered:\n {encrypted_text_seq}\n\n")
        file_pool.write(f"Decryption-Deciphered text:\n {decrypted_text_seq}\n")

        file_pool.write("########### Parallel Section ##############:\n")
        file_pool.write(f"Deciphered Text: \n {text}\n\n")
        file_pool.write(f"Encryption-Ciphered: \n {encrypted_text_para_pool}\n\n")
        file_pool.write(f"Decryption-Deciphered text:\n {decrypted_text_para_pool}")

    with open("time_results.txt", "w") as file_time:
        file_time.write("########### Difference Time ###############:\n")
        file_time.write(f"Sequential time Encryption result: {total_time_enc_seq} sec\n")
        file_time.write(f"Sequential time Decryption result: {total_time_dec_seq} sec\n\n")
        file_time.write(f"Parallel time Encryption fork way result: {total_time_enc_para_fork} sec\n")
        file_time.write(f"Parallel time Encryption pool way result: {total_time_enc_para_pool} sec\n")
        file_time.write(f"Parallel time Decryption fork way result: {total_time_dec_para_fork} sec\n")
        file_time.write(f"Parallel time Decryption fork way result: {total_time_dec_para_pool} sec\n\n")

        file_time.write(f"Time difference Encryption fork way: {difference_enc_fork} sec\n")
        file_time.write(f"Time difference Encryption pool way: {difference_enc_pool} sec\n")
        file_time.write(f"Time difference Decryption fork way: {difference_dec_fork} sec\n")
        file_time.write(f"Time difference Decryption pool way: {difference_dec_pool} sec\n\n")

        file_time.write('############## Comparing Section ###########\n')
        file_time.write(f"Are the Decrypted text in Sequential the same as the initial text? {decrypted_text_seq == text}\n")
        file_time.write(f"Are the Decrypted text in Parallel fork way the same as the initial text? {decrypted_text_para_fork == text}\n")
        file_time.write(f"Are the Decrypted text in Parallel pool way the same as the initial text? {decrypted_text_para_pool == text}\n")

        file_time.write(f"Are the Encrypted text in both (seq+fork) ways the same? {encrypted_text_seq == encrypted_text_para_fork}\n")
        file_time.write(f"Are the Encrypted text in both (seq+pool) ways the same? {encrypted_text_seq == encrypted_text_para_pool}\n")
        file_time.write(f"Are the Decrypted text in both (seq+fork) ways the same? {decrypted_text_seq == decrypted_text_para_fork}\n")
        file_time.write(f"Are the Decrypted text in both (seq+pool) ways the same? {decrypted_text_seq == decrypted_text_para_pool}")
