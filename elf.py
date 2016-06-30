#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import os

ELF_ENDIAN_LITTLE = 1
ELF_ENDIAN_BIG = 2

class ElfCtx:
    filename = ''
    data = '' # self.data's type is str
    bitness = 0
    endian = 0

    def __init__(self, filename):
        # read from file
        self.filename = filename
        fp = open(filename, mode='rb')
        self.data = fp.read(os.path.getsize(filename))
        fp.close()
        # check if file is ELF
        if not (self.data[0:4] == "\x7F\x45\x4C\x46"):
            print "[ERR] {0} is not ELF File!".format(self.filename)
            exit(1)
        # get ELF's bitness
        if (self.data[4] == "\x01"):
            self.bitness = 32
        elif (self.data[4] == "\x02"):
            self.bitness = 64
        else:
            print "[ERR] Wrong ELF bitness : {0}".format(hex(int(self.data[4])))
            exit(1)
        # get endian
        if (self.data[5] == "\x01"):
            self.endian = ELF_ENDIAN_LITTLE
        elif (self.data[5] == "\x02"):
            self.endian = ELF_ENDIAN_BIG
        else:
            print "[ERR] Wrong ELF endian : {0}"
            exit(1)

        # currently this only support amd64

    def print_elf_info(self):
        print "Filename : {0}".format(self.filename)
        print "Bitness  : {0}".format(self.bitness)