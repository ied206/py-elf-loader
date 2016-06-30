#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import os
import struct
from ctypes import *

ELF_e_endian_LITTLE = 1
ELF_e_endian_BIG = 2
ELF_e_type_EXEC = 2
ELF_e_type_SHARED = 3
ELF_e_machine_IA32 = 0x03
ELF_e_machine_AMD64 = 0x3E

class ElfCtx:
    filename = ''
    data = ''  # self.data's type is str
    # ELF Header
    e_class = 0
    e_endian = 0
    e_type = 0
    e_machine = 0
    e_entry = 0
    e_phoff = 0
    e_shoff = 0
    e_ehsize = 0
    e_phentsize = 0
    e_phnum = 0
    e_shentsize = 0
    e_shnum = 0
    e_shstrndx = 0

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
        # get ELF's e_class
        if (self.data[0x04] == "\x01"):
            self.e_class = 32
            print "[ERR] This does not support ELF32"
            exit(1)
        elif (self.data[0x04] == "\x02"):
            self.e_class = 64
        else:
            print "[ERR] Wrong ELF e_class : {0}".format(ord(self.data[4]))
            exit(1)
        # get e_endian
        if (self.data[0x05] == "\x01"):
            self.e_endian = ELF_e_endian_LITTLE
        elif (self.data[0x05] == "\x02"):
            self.e_endian = ELF_e_endian_BIG
            print "[ERR] Do not support BIG e_endian"
            exit(1)
        else:
            print "[ERR] Wrong ELF e_endian : {0}".format(ord(self.data[0x05]))
            exit(1)
        # read ELF file type
        if (self.data[0x10] == "\x02"):
            self.e_type = ELF_e_type_EXEC
        elif (self.data[0x10] == "\x03"):
            self.e_type = ELF_e_type_SHARED
        else:
            print "[ERR] Wrong ELF type : {0}".format(ord(self.data[0x10]))
            exit(1)
        # read ELF e_machine type
        if (self.data[0x12] == "\x03"):
            self.e_machine = ELF_e_machine_IA32
            print "[ERR] This does not support IA32"
            exit(1)
        elif (self.data[0x12] == "\x3E"):
            self.e_machine = ELF_e_machine_AMD64
        else:
            print "[ERR] Wrong ELF arch : {0}".format(ord(self.data[0x12]))
            exit(1)
        # read entry point
        self.e_entry = c_void_p(struct.unpack("<Q", self.data[0x18:0x20])[0])
        # program header table offset
        self.e_phoff = c_void_p(struct.unpack("<Q", self.data[0x20:0x28])[0])
        # section header table offset
        self.e_shoff = c_void_p(struct.unpack("<Q", self.data[0x28:0x30])[0])
        # size of this ELF header
        self.e_ehsize = struct.unpack("<H", self.data[0x34:0x36])[0]
        # info about program header table
        self.e_phentsize = struct.unpack("<H", self.data[0x36:0x38])[0]
        self.e_phnum = struct.unpack("<H", self.data[0x38:0x3A])[0]
        # info about section header table
        self.e_shentsize = struct.unpack("<H", self.data[0x3A:0x3C])[0]
        self.e_shnum = struct.unpack("<H", self.data[0x3C:0x3E])[0]
        self.e_shstrndx = struct.unpack("<H", self.data[0x3E:0x40])[0]

        # currently this only support amd64

    def print_elf_info(self):
        tmp = ''
        print "Filename    : {0}".format(self.filename)
        print "e_class     : {0}".format(self.e_class)
        if self.e_endian == ELF_e_endian_LITTLE:
            tmp = 'Little e_endian'
        print "e_endian      : {0}".format(tmp)
        tmp = ''
        if self.e_type == ELF_e_type_EXEC:
            tmp = 'Executable'
        elif self.e_type == ELF_e_type_SHARED:
            tmp = 'Shared'
        print "Type        : {0}".format(tmp)
        tmp = ''
        if self.e_machine == ELF_e_machine_AMD64:
            tmp = 'AMD64'
        print "e_machine     : {0}".format(tmp)
        print "EntryPorint : 0x%012X" % (self.e_entry.value)