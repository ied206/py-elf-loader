#!/usr/bin/env python
#-*- coding: utf-8 -*-
import sys
import argparse
import os
import hexdump
import struct

import elf

# I hate euc-kr!
reload(sys)
sys.setdefaultencoding('utf-8')


# parse arguments
def parse_argument():
    parser = argparse.ArgumentParser(
        prog='elf-loader.py',
        formatter_class=argparse.RawTextHelpFormatter,
        description='''ELF loader''')
    parser.add_argument('target', help='ELF file to load')
    args = parser.parse_args()
    if not vars(args):
        parser.print_help()
    else:
        return args


# Good. Now How to parse elf?
def main():
    # read argv
    args = parse_argument()
    target = args.target
    if not (os.path.exists(target) and os.path.isfile(target)):
        print '{0} is not a file'.format(target)
        exit(1)

    # read elf file
    ctx = elf.ElfCtx(target)
    ctx.print_elf_info()

    # manipulate binary data - use struct


if __name__ == "__main__":
    main()