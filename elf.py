#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import os
import struct
from ctypes import *

ELF_ENDIAN_LITTLE = 1
ELF_ENDIAN_BIG = 2
ELF_FILETYPE_EXEC = 2
ELF_FILETYPE_SHARED = 3
ELF_MACHINE_IA32 = 0x03
ELF_MACHINE_AMD64 = 0x3E
ELF_NOALIGN = 0x00
ELF_NOALIGN = 1
ELF_PT_LOAD = 'LOAD' # 0x00000001
ELF_PT_DYNAMIC = 'DYNAMIC' # 0x00000002
ELF_PT_INTERP = 'INTERP' # 0x00000003
ELF_PT_NOTE = 'NOTE' # 0x00000004
ELF_PT_SHLIB = 'SHLIB' # 0x00000005
ELF_PT_PHDR = 'PHDR' # 0x00000006
ELF_PT_LOOS = 'LOOS' # 0x60000000 
ELF_PT_HIOS = 'HIOS' # 0x6FFFFFFF
ELF_PT_LOPROC = 'LOPROC' # 0x70000000
ELF_PT_HIPROC = 'HIPROC' # 0x7FFFFFFF


class ElfCtx:
    filename = ''
    data = '' # self.data's type is str
    bitness = 0
    endian = 0
    filetype = 0
    machine = 0
    entrypoint = 0
    e_phoff = 0
    shdroff = 0
    p_type = 0
    p_offset = 0
    p_vaddr = 0
    p_paddr = 0
    p_filesz = 0
    p_memsz = 0
    p_flag = ''
    p_align = 0

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
        self.entrypoint = c_void_p(struct.unpack("<Q", self.data[0x18:0x20])[0])
        # program header table
        self.e_phoff = c_void_p(struct.unpack("<Q", self.data[0x20:0x28])[0])
        # section header table
        self.shdroff = c_void_p(struct.unpack("<Q", self.data[0x28:0x30])[0])

        # currently this only support amd64


    def print_elf_info(self):
        tmp = ''
        print "Filename    : {0}".format(self.filename)
        print "Bitness     : {0}".format(self.bitness)
        if self.endian == ELF_ENDIAN_LITTLE:
            tmp = 'Little Endian'
        print "Endian      : {0}".format(tmp)
        tmp = ''
        if self.filetype == ELF_FILETYPE_EXEC:
            tmp = 'Executable'
        elif self.filetype == ELF_FILETYPE_SHARED:
            tmp = 'Shared'
        print "Type        : {0}".format(tmp)
        tmp = ''
        if self.machine == ELF_MACHINE_AMD64:
            tmp = 'AMD64'
        print "Machine     : {0}".format(tmp)
        print "EntryPorint : 0x%012X" % (self.entrypoint.value)


    def parse_section_header(self):
        # Program Header type of the segment
        self.p_type = c_void_p(struct.unpack("<Q", self.data[self.e_phoff : self.e_phoff + 0x04])[0])
        # Program Header Offset
        self.p_offset = c_void_p(struct.unpack("<Q", self.data[self.e_phoff + 0x04 : self.e_phoff + 0x08])[0])
        # Program Header Virtual Address
        self.p_vaddr = c_void_p(struct.unpack("<Q", self.data[self.e_phoff + 0x08 : self.e_phoff + 0x0C])[0])
        # Program Physical Address
        self.p_paddr = c_void_p(struct.unpack("<Q", self.data[self.e_phoff + 0x0C : self.e_phoff + 0x10])[0])
        # Program File Size (Almost 0)
        self.p_filesz = c_void_p(struct.unpack("<Q", self.data[self.e_phoff + 0x10 : self.e_phoff + 0x14])[0])
        # Program Memory Size (Almost 0)
        self.p_memsz = c_void_p(struct.unpack("<Q", self.data[self.e_phoff + 0x14 : self.e_phoff + 0x18])[0])
        # Program Flags
        self.p_flag = c_void_p(struct.unpack("<Q", self.data[self.e_phoff + 0x18 : self.e_phoff + 0x1C])[0])
        # Program Align
        if(self.data[self.e_phoff + 0x1C : self.e_phoff + 0x20] == "\0x00" or self.data[self.e_phoff + 0x1C : self.e_phoff + 0x20] == "\0x01"):
            self.p_align = ELF_NOALIGN
        else:
            self.p_align = c_void_p(struct.unpack("<Q", self.data[self.e_phoff + 0x1C : self.e_phoff + 0x20])[0])