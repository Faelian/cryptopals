#!/usr/bin/env python3

import string
from colorama import Fore, Style 
import itertools as it

HEADER = '┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐'
FOOTER = '└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘'
LINE_FORMATTER = '│' + Style.DIM + '{:08x}' + Style.RESET_ALL + '│ {}' + Style.RESET_ALL + '│{}' + Style.RESET_ALL + '│'

def hexmod(b: int) -> str:
    '''10 -> "0xa" -> "0a"'''
    return hex(b)[2:].rjust(2, '0')

def colored(b: int) -> (str, str):
    '''add terminal color to given number like 0x00 - 0xff'''
    ch = chr(b)
    hx = hexmod(b)
    if '\x00' == ch:
        # NULL bytes
        return Fore.RESET + Style.DIM + hx + Style.RESET_ALL, Fore.RESET + Style.DIM + '0' + Style.RESET_ALL
    elif ch in string.ascii_letters + string.digits + string.punctuation:
        # printable ASCII characters
        return Fore.CYAN + hx, Fore.CYAN + ch
    elif ch in string.whitespace:
        # ASCII whitespace characters
        return Fore.GREEN + hx, ' ' if ' ' == ch else Fore.GREEN + '_'
    elif b in range(128):
        # other ASCII characters
        return Fore.MAGENTA + hx, Fore.MAGENTA + '•'
    else:
        # non-ASCII characters
        return Fore.YELLOW + hx, Fore.YELLOW + '×'

def split_into_chunks(byte_string, chunk_size=16):
    for i in range(0, len(byte_string), chunk_size):
        yield byte_string[i:i + chunk_size]


def hexdump(data, length=None, skip=0):
    cache = {hexmod(b): colored(b) for b in range(256)} #0x00 - 0xff
    cache['  '] = ('  ', ' ')    

    print(HEADER)
    
    row = skip

    if length == None:
        data = data[skip:]

    else:
        data = data[skip:skip+length]

    lines = split_into_chunks(data)

    for line in lines:
        line_hex = line.hex().ljust(32)

        hexbytes = ''
        printable = ''
        for i in range(0, len(line_hex), 2):
            hbyte, abyte = cache[line_hex[i:i+2]]
            hexbytes += hbyte + ' ' if i != 14 else hbyte + Style.RESET_ALL + ' ┊ '
            printable += abyte if i != 14 else abyte + Style.RESET_ALL + '┊'

        print(LINE_FORMATTER.format(row, hexbytes, printable))
        
        row += 0x10
    print(FOOTER)
