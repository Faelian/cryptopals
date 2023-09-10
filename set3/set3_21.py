#!/usr/bin/env python3
# coding: utf-8

# w, n, m, r, a, u, d, s, b, t, c, l, f

w, n, m, r = 32, 624, 397, 31
a = 0x9908b0df
u, d = 11, 0xffffffff
s, b =  7, 0x9d2c5680
t, c = 15, 0xefc60000
l = 18

print(f"w:{w}, n:{n}, m:{m}, r:{r}")
print(f"a:{a}")
print(f"u:{u}, d:{d}")
print(f"s:{s}, b:{b}")
print(f"t:{t}, c:{c}")
print(f"l:{l}")

# Create a length n array to store the state of the generator
MT = [None] * n
print(repr(MT))
print(len(MT))