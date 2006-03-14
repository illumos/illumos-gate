/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <dwarf.h>
#include <sys/types.h>
#include <sys/elf.h>

/*
 * Little Endian Base 128 (LEB128) numbers.
 * ----------------------------------------
 *
 * LEB128 is a scheme for encoding integers densely that exploits the
 * assumption that most integers are small in magnitude. (This encoding
 * is equally suitable whether the target machine architecture represents
 * data in big-endian or little- endian
 *
 * Unsigned LEB128 numbers are encoded as follows: start at the low order
 * end of an unsigned integer and chop it into 7-bit chunks. Place each
 * chunk into the low order 7 bits of a byte. Typically, several of the
 * high order bytes will be zero; discard them. Emit the remaining bytes in
 * a stream, starting with the low order byte; set the high order bit on
 * each byte except the last emitted byte. The high bit of zero on the last
 * byte indicates to the decoder that it has encountered the last byte.
 * The integer zero is a special case, consisting of a single zero byte.
 *
 * Signed, 2s complement LEB128 numbers are encoded in a similar except
 * that the criterion for discarding high order bytes is not whether they
 * are zero, but whether they consist entirely of sign extension bits.
 * Consider the 32-bit integer -2. The three high level bytes of the number
 * are sign extension, thus LEB128 would represent it as a single byte
 * containing the low order 7 bits, with the high order bit cleared to
 * indicate the end of the byte stream.
 *
 * Note that there is nothing within the LEB128 representation that
 * indicates whether an encoded number is signed or unsigned. The decoder
 * must know what type of number to expect.
 *
 * DWARF Exception Header Encoding
 * -------------------------------
 *
 * The DWARF Exception Header Encoding is used to describe the type of data
 * used in the .eh_frame_hdr section. The upper 4 bits indicate how the
 * value is to be applied. The lower 4 bits indicate the format of the data.
 *
 * DWARF Exception Header value format
 *
 * Name		Value Meaning
 * DW_EH_PE_omit	    0xff No value is present.
 * DW_EH_PE_absptr	    0x00 Value is a void*
 * DW_EH_PE_uleb128	    0x01 Unsigned value is encoded using the
 *				 Little Endian Base 128 (LEB128)
 * DW_EH_PE_udata2	    0x02 A 2 bytes unsigned value.
 * DW_EH_PE_udata4	    0x03 A 4 bytes unsigned value.
 * DW_EH_PE_udata8	    0x04 An 8 bytes unsigned value.
 * DW_EH_PE_signed          0x08 bit on for all signed encodings
 * DW_EH_PE_sleb128	    0x09 Signed value is encoded using the
 *				 Little Endian Base 128 (LEB128)
 * DW_EH_PE_sdata2	    0x0A A 2 bytes signed value.
 * DW_EH_PE_sdata4	    0x0B A 4 bytes signed value.
 * DW_EH_PE_sdata8	    0x0C An 8 bytes signed value.
 *
 * DWARF Exception Header application
 *
 * Name	    Value Meaning
 * DW_EH_PE_absptr	   0x00 Value is used with no modification.
 * DW_EH_PE_pcrel	   0x10 Value is reletive to the location of itself
 * DW_EH_PE_textrel	   0x20
 * DW_EH_PE_datarel	   0x30 Value is reletive to the beginning of the
 *				eh_frame_hdr segment ( segment type
 *			        PT_GNU_EH_FRAME )
 * DW_EH_PE_funcrel        0x40
 * DW_EH_PE_aligned        0x50 value is an aligned void*
 * DW_EH_PE_indirect       0x80 bit to signal indirection after relocation
 * DW_EH_PE_omit	   0xff No value is present.
 *
 */

uint64_t
uleb_extract(unsigned char *data, uint64_t *dotp)
{
	uint64_t	dot = *dotp;
	uint64_t	res = 0;
	int		more = 1;
	int		shift = 0;
	int		val;

	data += dot;

	while (more) {
		/*
		 * Pull off lower 7 bits
		 */
		val = (*data) & 0x7f;

		/*
		 * Add prepend value to head of number.
		 */
		res = res | (val << shift);

		/*
		 * Increment shift & dot pointer
		 */
		shift += 7;
		dot++;

		/*
		 * Check to see if hi bit is set - if not, this
		 * is the last byte.
		 */
		more = ((*data++) & 0x80) >> 7;
	}
	*dotp = dot;
	return (res);
}

int64_t
sleb_extract(unsigned char *data, uint64_t *dotp)
{
	uint64_t	dot = *dotp;
	int64_t		res = 0;
	int		more = 1;
	int		shift = 0;
	int		val;

	data += dot;

	while (more) {
		/*
		 * Pull off lower 7 bits
		 */
		val = (*data) & 0x7f;

		/*
		 * Add prepend value to head of number.
		 */
		res = res | (val << shift);

		/*
		 * Increment shift & dot pointer
		 */
		shift += 7;
		dot++;

		/*
		 * Check to see if hi bit is set - if not, this
		 * is the last byte.
		 */
		more = ((*data++) & 0x80) >> 7;
	}
	*dotp = dot;

	/*
	 * Make sure value is properly sign extended.
	 */
	res = (res << (64 - shift)) >> (64 - shift);

	return (res);
}

uint64_t
dwarf_ehe_extract(unsigned char *data, uint64_t *dotp, uint_t ehe_flags,
    unsigned char *eident, uint64_t pcaddr)
{
	uint64_t    dot = *dotp;
	uint_t	    lsb;
	uint_t	    wordsize;
	uint_t	    fsize;
	uint64_t    result;

	if (eident[EI_DATA] == ELFDATA2LSB)
		lsb = 1;
	else
		lsb = 0;

	if (eident[EI_CLASS] == ELFCLASS64)
		wordsize = 8;
	else
		wordsize = 4;

	switch (ehe_flags & 0x0f) {
	case DW_EH_PE_omit:
		return (0);
	case DW_EH_PE_absptr:
		fsize = wordsize;
		break;
	case DW_EH_PE_udata8:
	case DW_EH_PE_sdata8:
		fsize = 8;
		break;
	case DW_EH_PE_udata4:
	case DW_EH_PE_sdata4:
		fsize = 4;
		break;
	case DW_EH_PE_udata2:
	case DW_EH_PE_sdata2:
		fsize = 2;
		break;
	case DW_EH_PE_uleb128:
		return (uleb_extract(data, dotp));
	case DW_EH_PE_sleb128:
		return ((uint64_t)sleb_extract(data, dotp));
	default:
		return (0);
	}

	if (lsb) {
		/*
		 * Extract unaligned LSB formated data
		 */
		uint_t	cnt;

		result = 0;
		for (cnt = 0; cnt < fsize;
		    cnt++, dot++) {
			uint64_t val;
			val = data[dot];
			result |= val << (cnt * 8);
		}
	} else {
		/*
		 * Extract unaligned MSB formated data
		 */
		uint_t	cnt;
		result = 0;
		for (cnt = 0; cnt < fsize;
		    cnt++, dot++) {
			uint64_t	val;
			val = data[dot];
			result |= val << ((fsize - cnt - 1) * 8);
		}
	}
	/*
	 * perform sign extension
	 */
	if ((ehe_flags & DW_EH_PE_signed) &&
	    (fsize < sizeof (uint64_t))) {
		int64_t	sresult;
		uint_t	bitshift;
		sresult = result;
		bitshift = (sizeof (uint64_t) - fsize) * 8;
		sresult = (sresult << bitshift) >> bitshift;
		result = sresult;
	}

	/*
	 * If pcrel and we have a value (ie: we've been
	 * relocated), then adjust the value.
	 */
	if (result && (ehe_flags & DW_EH_PE_pcrel)) {
		result = pcaddr + result;
	}
	*dotp = dot;
	return (result);
}
