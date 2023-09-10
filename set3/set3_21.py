#!/usr/bin/env python3
# coding: utf-8

# w, n, m, r, a, u, d, s, b, t, c, l, f

w, n, m, r = 64, 312, 156, 31
a = 0xb5026f5aa96619e9
u, d = 29, 0x5555555555555555
s, b = 17, 0x71d67fffeda60000
t, c = 37, 0xfff7eee000000000
l = 43

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