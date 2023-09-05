#! /usr/bin/python
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2023 RackTop Systems, Inc.
#

#
# Convert an NIST GCMVS test vector file into arrays for crypto-test.
# Filters for 'plaintextlen' == 0, and uses 'AAD' for DATA arrays,
# so that the result is a GMAC test.
#

from dataclasses import dataclass, field
import argparse

@dataclass(frozen=True)
class TestVector:
    """Class tracking individual vectors"""

    key: list
    iv: list
    pt: list
    aad: list
    ct: list
    tag: list

@dataclass
class TestSet:
    """Class tracking vectors with particular parameters"""

    keylen: int
    ivlen: int
    ptlen: int
    aadlen: int
    taglen: int
    ctlen: int = field(init=False)
    vectors: list = field(default_factory=list)

    def __post_init__(self):
        self.ctlen = self.ptlen + self.taglen

    def add_case(self, key, iv, pt, aad, ct, tag):
        if len(key) * 8 != self.keylen:
            raise ValueError(f'Key \'{" ".join(key)}\' is length {len(key) * 8} but expected length {self.keylen}')
        if len(iv) * 8 != self.ivlen:
            raise ValueError(f'Iv \'{" ".join(iv)}\' is length {len(iv) * 8} but expected length {self.ivlen}')
        if len(pt) * 8 != self.ptlen:
            raise ValueError(f'Pt \'{" ".join(pt)}\' is length {len(pt) * 8} but expected length {self.ptlen}')
        if len(aad) * 8 != self.aadlen:
            raise ValueError(f'Aad \'{" ".join(aad)}\' is length {len(aad) * 8} but expected length {self.aadlen}')
        if len(ct) * 8 != self.ptlen:
            raise ValueError(f'Ct \'{" ".join(ct)}\' is length {len(ct) * 8} but expected length {self.ptlen}')
        if len(tag) * 8 != self.taglen:
            raise ValueError(f'Tag \'{" ".join(tag)}\' is length {len(tag) * 8} but expected length {self.taglen}')
        if self.ptlen == 0 and self.taglen == 128 and self.ivlen == 96:
            #For Decrypt, the tag needs to be part of the ciphertext
            self.vectors.append(TestVector(key, iv, pt, aad, ct + tag, []))

    def __iter__(self):
        return iter(self.vectors)

    def __len__(self):
        return len(self.vectors)

def genhex(string):
    off = 0
    strlen = len(string)
    if strlen % 2 != 0:
        yield '0x0' + string[0]
        off += 1

    while off < strlen:
        yield '0x' + string[off:off+2]
        off += 2

def main():
    parser = argparse.ArgumentParser(description=
        'Convert an NIST GCM Test Vector File to a C header on stdout')

    parser.add_argument('input_file',
        type=argparse.FileType('r'),
        help='The NIST .rsp file containing test vectors')
    args = parser.parse_args()

    input_file = args.input_file

    tests = []
    tset = None
    for line in input_file:
        val = line.strip('[]\n').split(' = ')
        if not val[0] and tset != None:
            tset.add_case(key, iv, pt, aad, ct, tag)

        if val[0] == 'Keylen':
            keylen = int(val[1])
            tset = None
        elif val[0] == 'IVlen':
            ivlen = int(val[1])
        elif val[0] == 'PTlen':
            ptlen = int(val[1])
        elif val[0] == 'AADlen':
            aadlen = int(val[1])
        elif val[0] == 'Taglen':
            taglen = int(val[1])
        elif val[0] == 'Count':
            if val[1] == '0':
                tset = TestSet(keylen, ivlen, ptlen, aadlen, taglen)
                tests.append(tset)
        elif val[0] == 'Key':
            key = list(genhex(val[1]))
        elif val[0] == 'IV':
            iv = list(genhex(val[1]))
        elif val[0] == 'PT':
            pt = list(genhex(val[1]))
        elif val[0] == 'AAD':
            aad = list(genhex(val[1]))
        elif val[0] == 'CT':
            ct = list(genhex(val[1]))
        elif val[0] == 'Tag':
            tag = list(genhex(val[1]))


    def print_hexbuf(buf, buflen):
        for ind, byte in enumerate(buf):
            if ind % 8 == 0:
                print(end='\t')
            print(f'{byte},', end=' ' if (ind + 1) % 8 != 0 and (ind + 1) != buflen else '\n')

    i = 0
    datastr = 'uint8_t *DATA[] = {'
    datalenstr = 'size_t DATALEN[] = {'
    resstr = 'uint8_t *RES[] = {'
    reslenstr = 'size_t RESLEN[] = {'
    ivstr = 'uint8_t *IV[] = {'
    ivlenstr = 'size_t IVLEN[] = {'
    keystr = 'uint8_t *KEY[] = {'
    keylenstr = 'size_t KEYLEN[] = {'
    for test in tests:
        for vec in test:
            print(f'uint8_t GMAC_KEY{i}[] = {{')
            print_hexbuf(vec.key, test.keylen / 8)
            print('};\n')

            # For GMAC, there should be no plaintext; use AAD instead
            if len(vec.pt) != 0:
                raise ValueError(f'case {i} has plaintext data')

            print(f'uint8_t GMAC_DATA{i}[] = {{')
            print_hexbuf(vec.aad, test.aadlen / 8)
            print('};\n')

            print(f'uint8_t GMAC_IV{i}[] = {{')
            print_hexbuf(vec.iv, test.ivlen / 8 )
            print('};\n')

            print(f'uint8_t GMAC_RES{i}[] = {{')
            print_hexbuf(vec.ct, test.ctlen / 8)
            print('};\n')

            if i % 3 == 0:
                datalenstr += '\n\t'
                reslenstr += '\n\t'
                ivlenstr += '\n\t'
                keylenstr += '\n\t'
            elif i != 0:
                datalenstr += ' '
                reslenstr += ' '
                ivlenstr += ' '
                keylenstr += ' '

            if i % 5 == 0:
                datastr += '\n\t'
            elif i != 0:
                datastr += ' '

            if i % 6 == 0:
                resstr += '\n\t'
                ivstr += '\n\t'
                keystr += '\n\t'
            elif i != 0:
                resstr += ' '
                ivstr += ' '
                keystr += ' '

            datastr += f'GMAC_DATA{i},'
            datalenstr += f'sizeof (GMAC_DATA{i}),'

            resstr += f'GMAC_RES{i},'
            reslenstr += f'sizeof (GMAC_RES{i}),'

            ivstr += f'GMAC_IV{i},'
            ivlenstr += f'sizeof (GMAC_IV{i}),'

            keystr += f'GMAC_KEY{i},'
            keylenstr += f'sizeof (GMAC_KEY{i}),'

            i += 1

    print(datastr + '\n};\n')
    print(datalenstr + '\n};\n')
    print(resstr + '\n};\n')
    print(reslenstr + '\n};\n')
    print(ivstr + '\n};\n')
    print(ivlenstr + '\n};\n')
    print(keystr + '\n};\n')
    print(keylenstr + '\n};\n')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Terminated by KeyboardInterrupt.')
