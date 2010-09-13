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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Descriptor parsing functions
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/inttypes.h>
#include <sys/ib/mgt/ibmf/ibmf_utils.h>
#include <sys/debug.h>

#define	INCREMENT_BUF(buf) \
		if ((buf)[0] == 0) { \
			break; \
		} else { \
			(buf) += (buf)[0]; \
		}
#define	isdigit(ch) ((ch >= '0') && (ch <= '9'))

/*
 * ibmf_utils_unpack_data:
 *
 * parser function which takes a format string, a void pointer, and a character
 * buffer and parses the buffer according to the identifiers in the format
 * string.  Copies the data from the buffer and places into the structure,
 * taking care of byte swapping and any padding due to 64-bit Solaris.  Modified
 * from /ws/on81-gate/usr/src/uts/common/io/usb/usba/parser.c.
 *
 * The data and structure length parameters can be larger than the number of
 * bytes specified in the format.  unpack_data will use the smallest of the
 * three values, stopping when it finishes parsing the format string or reaches
 * the end of one of the two buffers.
 */
void
ibmf_utils_unpack_data(char *format,
	uchar_t *data,
	size_t datalen,
	void *structure,
	size_t structlen)
{
	int	fmt;
	int	multiplier = 0;
	uchar_t	*dataend = data + datalen;
	char	*structstart = (char *)structure;
	void	*structend = (void *)((intptr_t)structstart + structlen);

	while ((fmt = *format) != '\0') {

		if (fmt == 'c') {
			uint8_t	*cp = (uint8_t *)structure;

			/*
			 * account for possible hole in structure
			 * due to unaligned data
			 */
			cp = (uint8_t *)
			    (((uintptr_t)cp + _CHAR_ALIGNMENT - 1) &
			    ~(_CHAR_ALIGNMENT - 1));

			if (((data + 1) > dataend) ||
			    ((cp + 1) > (uint8_t *)structend))
				break;

			*cp++ = *data++;
			structure = (void *)cp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 's') {
			uint16_t	*sp = (uint16_t *)structure;

			/*
			 * account for possible hole in structure
			 * due to unaligned data
			 */
			sp = (uint16_t *)
			    (((uintptr_t)sp + _SHORT_ALIGNMENT - 1) &
			    ~(_SHORT_ALIGNMENT - 1));

			if (((data + 2) > dataend) ||
			    ((sp + 1) > (uint16_t *)structend))
				break;

			*sp++ = (data[0] << 8) + data[1];
			data += 2;
			structure = (void *)sp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 'l') {
			uint32_t 	*lp = (uint32_t *)structure;

			/*
			 * account for possible hole in structure
			 * due to unaligned data
			 */
			lp = (uint32_t *)
			    (((uintptr_t)lp + _INT_ALIGNMENT - 1) &
			    ~(_INT_ALIGNMENT - 1));

			if (((data + 4) > dataend) ||
			    ((lp + 1) > (uint32_t *)structend))
				break;

			*lp++ = ((((((uint32_t)data[0] << 8) | data[1]) << 8)
			    | data[2]) << 8) | data[3];

			data += 4;
			structure = (void *)lp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 'L') {
			uint64_t	*llp = (uint64_t *)structure;

			/*
			 * account for possible hole in structure
			 * due to unaligned data
			 */
			llp = (uint64_t *)
			    (((uintptr_t)llp + _LONG_LONG_ALIGNMENT - 1) &
			    ~(_LONG_LONG_ALIGNMENT - 1));

			if (((data + 8) > dataend) ||
			    ((llp + 1) > (uint64_t *)structend))
				break;
			/*
			 * note: data[0] is cast to uint64_t so that the
			 * compiler wouldn't treat the results of the shifts
			 * as a 32bit quantity; we really want to get 64bits
			 * out of this.
			 */
			*llp++ = ((((((((((((((uint64_t)data[0] << 8) |
				data[1]) << 8) | data[2]) << 8) |
				data[3]) << 8) | data[4]) << 8) |
				data[5]) << 8) | data[6]) << 8) |
				data[7];

			data += 8;
			structure = (void *)llp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (isdigit(fmt)) {
			multiplier = (multiplier * 10) + (fmt - '0');
			format++;
		} else {
			multiplier = 0;
			break;
		}
	}
}

/*
 * ibmf_utils_pack_data:
 *
 * parser function which takes a format string, a void pointer, and a character
 * buffer and parses the structure according to the identifiers in the format
 * string.  Copies the data from the structure and places in the buffer, taking
 * care of byte swapping and any padding due to 64-bit Solaris.  Modified from
 * /ws/on81-gate/usr/src/uts/common/io/usb/usba/parser.c.
 *
 */
void
ibmf_utils_pack_data(char *format, void *structure,
    size_t structlen, uchar_t *data, size_t datalen)
{
	int	fmt;
	int	multiplier = 0;
	uchar_t	*dataend = data + datalen;
	char	*structend = (void *)((uchar_t *)structure + structlen);

	while ((fmt = *format) != '\0') {
		if (fmt == 'c') {
			uint8_t	*cp = (uint8_t *)structure;

			/*
			 * account for possible hole in structure
			 * due to unaligned data
			 */
			cp = (uint8_t *)
			    (((uintptr_t)cp + _CHAR_ALIGNMENT - 1) &
			    ~(_CHAR_ALIGNMENT - 1));

			if (((data + 1) > dataend) ||
			    ((cp + 1) > (uint8_t *)structend)) {
				break;
			}

			*data++ = *cp++;
			structure = (void *)cp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 's') {
			uint16_t	*sp = (uint16_t *)structure;

			/*
			 * account for possible hole in structure
			 * due to unaligned data
			 */
			sp = (uint16_t *)
			    (((uintptr_t)sp + _SHORT_ALIGNMENT - 1) &
			    ~(_SHORT_ALIGNMENT - 1));

			if (((data + 2) > dataend) ||
			    ((sp + 1) > (uint16_t *)structend))
				break;

			/* do an endian-independent copy */
			data[0] = (uchar_t)(*sp >> 8);
			data[1] = (uchar_t)(*sp);

			sp++;
			data += 2;

			structure = (void *)sp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 'l') {
			uint32_t 	*lp = (uint32_t *)structure;

			/*
			 * account for possible hole in structure
			 * due to unaligned data
			 */
			lp = (uint32_t *)
			    (((uintptr_t)lp + _INT_ALIGNMENT - 1) &
			    ~(_INT_ALIGNMENT - 1));

			if (((data + 4) > dataend) ||
			    ((lp + 1) > (uint32_t *)structend))
				break;

			/* do an endian-independent copy */
			data[0] = (uchar_t)(*lp >> 24);
			data[1] = (uchar_t)(*lp >> 16);
			data[2] = (uchar_t)(*lp >> 8);
			data[3] = (uchar_t)(*lp);

			lp++;
			data += 4;

			structure = (void *)lp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 'L') {
			uint64_t	*llp = (uint64_t *)structure;

			/*
			 * account for possible hole in structure
			 * due to unaligned data
			 */
			llp = (uint64_t *)
			    (((uintptr_t)llp + _LONG_LONG_ALIGNMENT - 1) &
			    ~(_LONG_LONG_ALIGNMENT - 1));

			if (((data + 8) > dataend) ||
			    ((llp + 1) > (uint64_t *)structend))
				break;

			/* do an endian-independent copy */
			data[0] = (uchar_t)(*llp >> 56);
			data[1] = (uchar_t)(*llp >> 48);
			data[2] = (uchar_t)(*llp >> 40);
			data[3] = (uchar_t)(*llp >> 32);
			data[4] = (uchar_t)(*llp >> 24);
			data[5] = (uchar_t)(*llp >> 16);
			data[6] = (uchar_t)(*llp >> 8);
			data[7] = (uchar_t)(*llp);
			llp++;
			data += 8;

			structure = (void *)llp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (isdigit(fmt)) {
			multiplier = (multiplier * 10) + (fmt - '0');
			format++;
		} else {
			multiplier = 0;
			break;
		}
	}
}
