#!/usr/bin/env python3
#coding: utf-8

import string

string = string.ascii_lowercase
print (string)

a = [[]] * 5

print (repr(a))

for i in range(0, len(string)):
	a [i % 5].append(string[i])

print (repr(a[7%5]))