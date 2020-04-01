# Viatcheslav Kagan 	311763213
# Liad Khamdadash		313299877

########## Exmaple of threads Python #############3
from threading import *
import time

def sqr(n):
    for x in n:
        time.sleep(1)
        print('Remainder after dividing by 2', x % 2)


def cube(n):
    for x in n:
        time.sleep(1)
        print('Remainder after dividing by 3', x % 3)


n = [1, 2, 3, 4, 5, 6, 7, 8]
start = time.time()
t1 = Thread(target=sqr, args=(n,))
t2 = Thread(target=cube, args=(n,))
t1.start()
time.sleep(1)
t2.start()
t1.join()
t2.join()
end = time.time()
print(end-start)


#!/usr/bin/python

import threading
import time

class myThread (threading.Thread):
   def __init__(self, threadID, name, counter):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name
      self.counter = counter
   def run(self):
      print("Starting " + self.name)
      # Get lock to synchronize threads
      threadLock.acquire()
      print_time(self.name, self.counter, 3)
      # Free lock to release next thread
      threadLock.release()

def print_time(threadName, delay, counter):
   while counter:
      time.sleep(delay)
      print("%s: %s" % (threadName, time.ctime(time.time())))
      counter -= 1

threadLock = threading.Lock()
threads = []

# Create new threads
thread1 = myThread(1, "Thread-1", 1)
thread2 = myThread(2, "Thread-2", 2)

# Start new Threads
thread1.start()
thread2.start()

# Add threads to thread list
threads.append(thread1)
threads.append(thread2)

# Wait for all threads to complete
for t in threads:
    t.join()
print("Exiting Main Thread")
