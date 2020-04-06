###################################
# Team Members:
# Viatcheslav Kagan 	311763213
# Liad Khamdadash		313299877
###################################

# The system executes Data Encryption standard algorithm in parallel and sequential approaches
# Encryption of a long text (famous story) and after that decryption to the initial text

from StoryForEncrypt.textToEnc import text
import time
from sequential_des import Des as Sequential_Des
from parallel_des_fork import Des as Parallel_Des_Fork
from parallel_des_pool import Des as Parallel_Des_Pool
import multiprocessing

# open() function opens a file, and returns it as a file object
# float() method returns a floating point number from a number or a string
# round() function returns a floating-point number rounded to the specified number of decimals
# print() function prints the specified message to the screen, or other standard output device
# "w" - Write - will overwrite any existing content
# time() returns the time as a floating point number expressed in seconds since the epoch, in UTC


# Execute the main method now that all the dependencies have been defined.
# The if __name__ is so that pydoc works and we can still run on the command line.
if __name__ == '__main__':
    num_processors = multiprocessing.cpu_count()
    maximum_num_of_threads = num_processors*2
    key = "pySeminar"       # 56 bits

    print('Data itself appears in the "data_results_fork.txt and data_results_pool.txt" files:\n')
    print('Time results for DES algorithm Enc+Dec')
    print(f"The secret key: {key}\n")

    "##################### Sequential Section #####################"
    print('############## Sequential Section ###########')
    print('Please Wait...')
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

    "##################### Parallel Section - Fork #####################"
    print('############## Parallel Section - Fork ###########')
    print('Please Wait...')

    headers = ['Number of threads', 'fork join run time', 'Data the same as in sequential?']
    with open("Text Files/encryption_fork_file.txt", "w") as file_encryption:
        file_encryption.write("########### Encryption Results ###############:\n")
        file_encryption.write(''.join(column.rjust(10) for column in headers))
        file_encryption.write("\n")
        for num_threads in range(2, maximum_num_of_threads+1):
            des_para_fork = Parallel_Des_Fork(key, num_threads)
            start_enc_para_fork = time.time()
            encrypted_text_para_fork = des_para_fork.encrypt(text, num_threads)  # parallel fork encryption text with DES algorithm
            end_enc_para_fork = time.time()
            total_time_enc_para_fork = round(float(end_enc_para_fork) - float(start_enc_para_fork), 3)
            file_encryption.write(f"{num_threads}\t\t{total_time_enc_para_fork}\t\t{encrypted_text_seq == encrypted_text_para_fork}")
            file_encryption.write("\n")
        file_encryption.write(f"Run time without multi threading:\t{total_time_enc_seq}\n")

    with open("Text Files/decryption_fork_file.txt", "w") as file_decryption:
        file_decryption.write("########### Decryption Results ###############:\n")
        file_decryption.write(''.join(column.rjust(10) for column in headers))
        file_decryption.write("\n")
        for num_threads in range(2, maximum_num_of_threads+1):
            des_para_fork = Parallel_Des_Fork(key, num_threads)
            start_dec_para_fork = time.time()
            decrypted_text_para_fork = des_para_fork.decrypt(text, num_threads)  # parallel fork decryption text with DES algorithm
            end_dec_para_fork = time.time()
            total_time_dec_para_fork = round(float(end_dec_para_fork) - float(start_dec_para_fork), 3)
            file_decryption.write(f"{num_threads}\t\t{total_time_dec_para_fork}\t\t{decrypted_text_seq == decrypted_text_para_fork}")
            file_decryption.write("\n")
        file_decryption.write(f"Run time without multi threading:\t{total_time_dec_seq}\n")

    "##################### Parallel Section - Pool #####################"
    print('############## Parallel Section - Pool ###########')
    print('Please Wait...')

    des_para_pool = Parallel_Des_Pool(key)
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

    "##################### File Data Section #####################"
    with open("Text Files/data_results_fork.txt", "w") as file_fork:
        file_fork.write("#### Results for Data Encryption Standard Algorithm ####\n\n")
        file_fork.write(f"The secret key: {key}\n\n")

        file_fork.write("########### Sequential Section ##############:\n")
        file_fork.write(f"Deciphered Text:\n {text}\n\n")
        file_fork.write(f"Encryption-Ciphered:\n {encrypted_text_seq}\n\n")
        file_fork.write(f"Decryption-Deciphered text:\n {decrypted_text_seq}\n")

        file_fork.write("########### Parallel Section Showing data for the last operation in parallel #############:\n")
        file_fork.write(f"Deciphered Text: \n {text}\n\n")
        file_fork.write(f"Encryption-Ciphered: \n {encrypted_text_para_fork}\n\n")
        file_fork.write(f"Decryption-Deciphered text:\n {decrypted_text_para_fork}")

    with open("Text Files/data_results_pool.txt", "w") as file_pool:
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
