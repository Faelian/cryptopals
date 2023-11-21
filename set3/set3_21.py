#!/usr/bin/env python3
# coding: utf-8

# coefficients for MT19937
w, n, m, r = 32, 624, 397, 31
a = 0x9908b0df
u, d = 11, 0xffffffff
s, b =  7, 0x9d2c5680
t, c = 15, 0xefc60000
l = 18
f = 1812433253

# Create a length n array to store the state of the generator
MT = [None] * n

index = n+1
lower_w_bits = (1 << w) - 1 # 0xffffffff

lower_mask = (1 << r) - 1 # That is, the binary number of r 1's
upper_mask = 0x80000000 # lowest w bits of (not lower_mask)

# Initialize the generator from a seed
def seed_mt(seed):
	global index
	global MT
	index = n
	MT[0] = seed

	for i in range(1, n):
		MT[i] = lower_w_bits & (
			f * (
				MT[i-1]
				^ 
				(MT[i-1] >> (w-2))
				)
			+ i
			) 

# Extract a tempered value based on MT[index]
# calling twist() every n numbers

def extract_number():
	global index, MT

	if index >= n:
		if index > n:
			print(f"index: {index}")
			print(f"n: {n}")
			raise Exception("Error, generator was never seeded")
		twist()

	y = MT[index]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)

	index = index + 1
	return y & lower_w_bits

def twist():
	global index, MT

	for i in range(0, n):
		x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)

		xA = x >> 1
		if (x % 2) != 0: # lowest bit of x is 1
			xA = xA ^ a

		MT[i] = MT[(i + m) % n] ^ xA

		index = 0

if __name__ == '__main__':
	
	seed_mt(0)
	rand1 = extract_number()
	print(rand1)