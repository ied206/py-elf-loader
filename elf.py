#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import os

ELF_ENDIAN_LITTLE = 1
ELF_ENDIAN_BIG = 2
ELF_FILETYPE_EXEC = 2
ELF_FILETYPE_SHARED = 3
ELF_MACHINE_IA32 = 0x03
ELF_MACHINE_AMD64 = 0x3E

class ElfCtx:
    filename = ''
    data = '' # self.data's type is str
    bitness = 0
    endian = 0
    filetype = 0
    machine = 0
    entrypoint = 0

    def __init__(self, filename):
        # read from file
        self.filename = filename
        fp = open(filename, mode='rb')
        self.data = fp.read(os.path.getsize(filename))
        fp.close()
        # check if file is ELF
        if not (self.data[0x00:0x04] == "\x7F\x45\x4C\x46"):
            print "[ERR] {0} is not ELF File!".format(self.filename)
            exit(1)
        # get ELF's bitness
        if (self.data[0x04] == "\x01"):
            self.bitness = 32
            print "[ERR] This does not support ELF32"
            exit(1)
        elif (self.data[0x04] == "\x02"):
            self.bitness = 64
        else:
            print "[ERR] Wrong ELF bitness : {0}".format(ord(self.data[4]))
            exit(1)
        # get endian
        if (self.data[0x05] == "\x01"):
            self.endian = ELF_ENDIAN_LITTLE
        elif (self.data[0x05] == "\x02"):
            self.endian = ELF_ENDIAN_BIG
            print "[ERR] Do not support BIG ENDIAN"
            exit(1)
        else:
            print "[ERR] Wrong ELF endian : {0}".format(ord(self.data[0x05]))
            exit(1)
        # read ELF file type
        if (self.data[0x10] == "\x02"):
            self.filetype = ELF_FILETYPE_EXEC
        elif (self.data[0x10] == "\x03"):
            self.filetype = ELF_FILETYPE_SHARED
        else:
            print "[ERR] Wrong ELF type : {0}".format(ord(self.data[0x10]))
            exit(1)
        # read ELF machine type
        if (self.data[0x12] == "\x03"):
            self.machine = ELF_MACHINE_IA32
            print "[ERR] This does not support IA32"
            exit(1)
        elif (self.data[0x12] == "\x3E"):
            self.machine = ELF_MACHINE_AMD64
        else:
            print "[ERR] Wrong ELF arch : {0}".format(ord(self.data[0x12]))
            exit(1)

        # read entry point

        # currently this only support amd64

    def print_elf_info(self):
        tmp = ''
        print "Filename : {0}".format(self.filename)
        print "Bitness  : {0}".format(self.bitness)
        if self.endian == ELF_ENDIAN_LITTLE:
            tmp = 'Little Endian'
        print "Endian   : {0}".format(tmp)
        tmp = ''
        if self.filetype == ELF_FILETYPE_EXEC:
            tmp = 'Executable'
        elif self.filetype == ELF_FILETYPE_SHARED:
            tmp = 'Shared'
        print "Type     : {0}".format(tmp)
        tmp = ''
        if self.machine == ELF_MACHINE_AMD64:
            tmp = 'AMD64'
        print "Machine  : {0}".format(tmp)