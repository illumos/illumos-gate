/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CRC32_H
#define	_SYS_CRC32_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CRC32, the 32-bit Cyclic Redundancy Check, is a well-known way to
 * generate checksums or hashes.  Extensive literature on the theory
 * behind CRC is available on the web; we won't recapitulate it here.
 * We must, however, cover a few basics to explain the services we're
 * providing.
 *
 * A CRC function is defined by two parameters: an initial value and a
 * 32-bit integer that encodes its generating polynomial (explained later).
 * Given these values, the CRC of any bitstream is defined as follows:
 *
 *	crc = CRC32_INITIAL;
 *	foreach (bit of data)
 *		if (bit == (crc & 1))
 *			crc = (crc >> 1);
 *		else
 *			crc = (crc >> 1) ^ CRC32_POLY;
 *
 * That's it.  The algorithm is both simple and surprisingly powerful:
 * CRC32 has been proven to detect all single-bit errors, all double-bit
 * errors, and all burst errors up to 32 bits long.
 *
 * The most common values for the CRC parameters are:
 *
 *	CRC32_INITIAL:	0 or -1
 *	CRC32_POLY	0xEDB88320
 *
 * There is no particular constraint on the initial value; any will yield a
 * valid CRC.  (OK, then why not always use zero?  Because CRC was originally
 * designed for serial transmission, in which one common form of error
 * was a burst of zeroes.  Note that if crc == 0, and we fold in a zero bit,
 * we still have crc == 0.  Therefore, if the CRC's initial value is zero,
 * an arbitrarily long run of zeroes can be prepended to a packet without
 * being detected.)
 *
 * The constraint on the polynomial is that it must be of degree 32
 * and must be primitive in the Galois field of polynomials modulo 2.
 * Any such polynomial will yield a valid CRC.  There's no particular
 * advantage to one such polynomial over another, so the world has
 * largely standardized on a particular one, 0xEDB88320.  [The nth bit
 * of this integer is the coefficient of x^n; the coefficient of x^32
 * is implicitly 1.]
 *
 * Of course, we rarely process data bitwise in software.  When processing
 * data bytewise, the following calculation is equivalent to the bitwise one:
 *
 *	crc = CRC32_INITIAL;
 *	foreach (byte of data)
 *		for (crc ^= byte, i = 8; i > 0; i--)
 *			crc = (crc >> 1) ^ (-(crc & 1) & CRC32_POLY);
 *
 * Note that we still have a bitwise loop in there.  We can avoid this
 * by precomputing the CRC of each possible byte [i.e. 0-255] using the
 * algorithm above and storing the results in a lookup table.  Given
 * such a table, the CRC can be computed quite efficiently as follows:
 *
 *	crc = CRC32_INITIAL;
 *	foreach (byte of data)
 *		crc = (crc >> 8) ^ crc32_table[(crc ^ byte) & 0xFF];
 *
 * The macros below support this form of CRC computation.
 *
 * We also define a pre-computed crc32_table[] for the polynomial 0xEDB88320.
 * This is the only CRC polynomial we actually use in Solaris.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Initialize a CRC table [256 uint32_t's] with the given polynomial.
 */
#define	CRC32_INIT(table, poly)						\
{									\
	uint32_t Xi, Xj, *Xt;						\
	for (Xi = 0; Xi < 256; Xi++)					\
		for (Xt = (table) + Xi, *Xt = Xi, Xj = 8; Xj > 0; Xj--)	\
			*Xt = (*Xt >> 1) ^ (-(*Xt & 1) & (poly));	\
}

/*
 * Compute a 32-bit CRC using the specified starting value and table.
 * Typical usage: CRC32(crc, buf, size, -1U, crc32_table).
 */
#define	CRC32(crc, buf, size, start, table)				\
{									\
	uint32_t Xcrc = start;						\
	const uint8_t *Xcp = (const uint8_t *)(buf);			\
	const uint8_t *Xcpend = Xcp + (size);				\
	while (Xcp < Xcpend)						\
		Xcrc = (Xcrc >> 8) ^ (table)[(Xcrc ^ *Xcp++) & 0xFF];	\
	crc = Xcrc;							\
}

/*
 * As above, but operate on a null-terminated string instead of an
 * array of known size.  Computes both the crc and the string length.
 * Typical usage: CRC32_STRING(crc, len, str, -1U, crc32_table).
 */
#define	CRC32_STRING(crc, len, str, start, table)			\
{									\
	uint32_t Xcrc = start;						\
	const uint8_t *Xcp;						\
	uint8_t Xc;							\
	for (Xcp = (const uint8_t *)(str); (Xc = *Xcp) != 0; Xcp++)	\
		Xcrc = (Xcrc >> 8) ^ (table)[(Xcrc ^ Xc) & 0xFF];	\
	(crc) = Xcrc;							\
	(len) = Xcp - (const uint8_t *)(str);				\
}

/*
 * The polynomial we generally use in Solaris.
 */
#define	CRC32_POLY	0xEDB88320U

/*
 * The pre-computed table values for CRC32_POLY.
 */
#define	CRC32_TABLE						\
	0x00000000U, 0x77073096U, 0xEE0E612CU, 0x990951BAU,	\
	0x076DC419U, 0x706AF48FU, 0xE963A535U, 0x9E6495A3U,	\
	0x0EDB8832U, 0x79DCB8A4U, 0xE0D5E91EU, 0x97D2D988U,	\
	0x09B64C2BU, 0x7EB17CBDU, 0xE7B82D07U, 0x90BF1D91U,	\
	0x1DB71064U, 0x6AB020F2U, 0xF3B97148U, 0x84BE41DEU,	\
	0x1ADAD47DU, 0x6DDDE4EBU, 0xF4D4B551U, 0x83D385C7U,	\
	0x136C9856U, 0x646BA8C0U, 0xFD62F97AU, 0x8A65C9ECU,	\
	0x14015C4FU, 0x63066CD9U, 0xFA0F3D63U, 0x8D080DF5U,	\
	0x3B6E20C8U, 0x4C69105EU, 0xD56041E4U, 0xA2677172U,	\
	0x3C03E4D1U, 0x4B04D447U, 0xD20D85FDU, 0xA50AB56BU,	\
	0x35B5A8FAU, 0x42B2986CU, 0xDBBBC9D6U, 0xACBCF940U,	\
	0x32D86CE3U, 0x45DF5C75U, 0xDCD60DCFU, 0xABD13D59U,	\
	0x26D930ACU, 0x51DE003AU, 0xC8D75180U, 0xBFD06116U,	\
	0x21B4F4B5U, 0x56B3C423U, 0xCFBA9599U, 0xB8BDA50FU,	\
	0x2802B89EU, 0x5F058808U, 0xC60CD9B2U, 0xB10BE924U,	\
	0x2F6F7C87U, 0x58684C11U, 0xC1611DABU, 0xB6662D3DU,	\
	0x76DC4190U, 0x01DB7106U, 0x98D220BCU, 0xEFD5102AU,	\
	0x71B18589U, 0x06B6B51FU, 0x9FBFE4A5U, 0xE8B8D433U,	\
	0x7807C9A2U, 0x0F00F934U, 0x9609A88EU, 0xE10E9818U,	\
	0x7F6A0DBBU, 0x086D3D2DU, 0x91646C97U, 0xE6635C01U,	\
	0x6B6B51F4U, 0x1C6C6162U, 0x856530D8U, 0xF262004EU,	\
	0x6C0695EDU, 0x1B01A57BU, 0x8208F4C1U, 0xF50FC457U,	\
	0x65B0D9C6U, 0x12B7E950U, 0x8BBEB8EAU, 0xFCB9887CU,	\
	0x62DD1DDFU, 0x15DA2D49U, 0x8CD37CF3U, 0xFBD44C65U,	\
	0x4DB26158U, 0x3AB551CEU, 0xA3BC0074U, 0xD4BB30E2U,	\
	0x4ADFA541U, 0x3DD895D7U, 0xA4D1C46DU, 0xD3D6F4FBU,	\
	0x4369E96AU, 0x346ED9FCU, 0xAD678846U, 0xDA60B8D0U,	\
	0x44042D73U, 0x33031DE5U, 0xAA0A4C5FU, 0xDD0D7CC9U,	\
	0x5005713CU, 0x270241AAU, 0xBE0B1010U, 0xC90C2086U,	\
	0x5768B525U, 0x206F85B3U, 0xB966D409U, 0xCE61E49FU,	\
	0x5EDEF90EU, 0x29D9C998U, 0xB0D09822U, 0xC7D7A8B4U,	\
	0x59B33D17U, 0x2EB40D81U, 0xB7BD5C3BU, 0xC0BA6CADU,	\
	0xEDB88320U, 0x9ABFB3B6U, 0x03B6E20CU, 0x74B1D29AU,	\
	0xEAD54739U, 0x9DD277AFU, 0x04DB2615U, 0x73DC1683U,	\
	0xE3630B12U, 0x94643B84U, 0x0D6D6A3EU, 0x7A6A5AA8U,	\
	0xE40ECF0BU, 0x9309FF9DU, 0x0A00AE27U, 0x7D079EB1U,	\
	0xF00F9344U, 0x8708A3D2U, 0x1E01F268U, 0x6906C2FEU,	\
	0xF762575DU, 0x806567CBU, 0x196C3671U, 0x6E6B06E7U,	\
	0xFED41B76U, 0x89D32BE0U, 0x10DA7A5AU, 0x67DD4ACCU,	\
	0xF9B9DF6FU, 0x8EBEEFF9U, 0x17B7BE43U, 0x60B08ED5U,	\
	0xD6D6A3E8U, 0xA1D1937EU, 0x38D8C2C4U, 0x4FDFF252U,	\
	0xD1BB67F1U, 0xA6BC5767U, 0x3FB506DDU, 0x48B2364BU,	\
	0xD80D2BDAU, 0xAF0A1B4CU, 0x36034AF6U, 0x41047A60U,	\
	0xDF60EFC3U, 0xA867DF55U, 0x316E8EEFU, 0x4669BE79U,	\
	0xCB61B38CU, 0xBC66831AU, 0x256FD2A0U, 0x5268E236U,	\
	0xCC0C7795U, 0xBB0B4703U, 0x220216B9U, 0x5505262FU,	\
	0xC5BA3BBEU, 0xB2BD0B28U, 0x2BB45A92U, 0x5CB36A04U,	\
	0xC2D7FFA7U, 0xB5D0CF31U, 0x2CD99E8BU, 0x5BDEAE1DU,	\
	0x9B64C2B0U, 0xEC63F226U, 0x756AA39CU, 0x026D930AU,	\
	0x9C0906A9U, 0xEB0E363FU, 0x72076785U, 0x05005713U,	\
	0x95BF4A82U, 0xE2B87A14U, 0x7BB12BAEU, 0x0CB61B38U,	\
	0x92D28E9BU, 0xE5D5BE0DU, 0x7CDCEFB7U, 0x0BDBDF21U,	\
	0x86D3D2D4U, 0xF1D4E242U, 0x68DDB3F8U, 0x1FDA836EU,	\
	0x81BE16CDU, 0xF6B9265BU, 0x6FB077E1U, 0x18B74777U,	\
	0x88085AE6U, 0xFF0F6A70U, 0x66063BCAU, 0x11010B5CU,	\
	0x8F659EFFU, 0xF862AE69U, 0x616BFFD3U, 0x166CCF45U,	\
	0xA00AE278U, 0xD70DD2EEU, 0x4E048354U, 0x3903B3C2U,	\
	0xA7672661U, 0xD06016F7U, 0x4969474DU, 0x3E6E77DBU,	\
	0xAED16A4AU, 0xD9D65ADCU, 0x40DF0B66U, 0x37D83BF0U,	\
	0xA9BCAE53U, 0xDEBB9EC5U, 0x47B2CF7FU, 0x30B5FFE9U,	\
	0xBDBDF21CU, 0xCABAC28AU, 0x53B39330U, 0x24B4A3A6U,	\
	0xBAD03605U, 0xCDD70693U, 0x54DE5729U, 0x23D967BFU,	\
	0xB3667A2EU, 0xC4614AB8U, 0x5D681B02U, 0x2A6F2B94U,	\
	0xB40BBE37U, 0xC30C8EA1U, 0x5A05DF1BU, 0x2D02EF8DU

#ifdef _KERNEL

/*
 * The kernel's pre-computed table for CRC32_POLY.
 */
extern const uint32_t crc32_table[256];

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CRC32_H */
