#!/usr/bin/env python3
#coding: utf-8

from set3_21 import seed_mt, extract_number
from time import sleep, time_ns
import random
from datetime import datetime

random.seed()
wait_time = random.randint(2, 15)

print(f"sleeping {wait_time}")
#sleep(wait_time)
for i in range(0, wait_time):
    print(f'\r{i}', end='')
    sleep(1)
print('')

unix_timestamp = time_ns()
#print(f"unix_timestamp: {unix_timestamp}")

seed_mt(unix_timestamp)
rand_num = extract_number()
print(f"our random number is {rand_num}")

## Challenge part !

print("Let's find the seed")

current_timestamp = time_ns()

time_range = 1100000
first_timestamp = current_timestamp - time_range

print(f"first_timestamp: {first_timestamp}")

for i in range (first_timestamp, first_timestamp + time_range):
    print(f"\rTesting timestamp: {i}", end='')
    seed_mt(i)
    test_num = extract_number()

    if test_num == rand_num :
        print(f"\nThe seed is {i}")
        exit()




