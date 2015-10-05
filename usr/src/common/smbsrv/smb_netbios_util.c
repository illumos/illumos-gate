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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <string.h>
#endif
#include <smbsrv/string.h>
#include <smbsrv/netbios.h>

/*
 * Routines than support name compression.
 *
 *   The NetBIOS name representation in all NetBIOS packets (for NAME,
 *   SESSION, and DATAGRAM services) is defined in the Domain Name
 *   Service RFC 883[3] as "compressed" name messages.  This format is
 *   called "second-level encoding" in the section entitled
 *   "Representation of NetBIOS Names" in the Concepts and Methods
 *   document.
 *
 *   For ease of description, the first two paragraphs from page 31,
 *   the section titled "Domain name representation and compression",
 *   of RFC 883 are replicated here:
 *
 *        Domain names messages are expressed in terms of a sequence
 *        of labels.  Each label is represented as a one octet length
 *        field followed by that number of octets.  Since every domain
 *        name ends with the null label of the root, a compressed
 *        domain name is terminated by a length byte of zero.  The
 *        high order two bits of the length field must be zero, and
 *        the remaining six bits of the length field limit the label
 *        to 63 octets or less.
 *
 *        To simplify implementations, the total length of label
 *        octets and label length octets that make up a domain name is
 *        restricted to 255 octets or less.
 *
 *   The following is the uncompressed representation of the NetBIOS name
 *   "FRED ", which is the 4 ASCII characters, F, R, E, D, followed by 12
 *   space characters (0x20).  This name has the SCOPE_ID: "NETBIOS.COM"
 *
 *           EGFCEFEECACACACACACACACACACACACA.NETBIOS.COM
 *
 *   This uncompressed representation of names is called "first-level
 *   encoding" in the section entitled "Representation of NetBIOS Names"
 *   in the Concepts and Methods document.
 *
 *   The following is a pictographic representation of the compressed
 *   representation of the previous uncompressed Domain Name
 *   representation.
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |      0x20     |    E (0x45)   |    G (0x47)   |    F (0x46)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    C (0x43)   |    E (0x45)   |    F (0x46)   |    E (0x45)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    E (0x45)   |    C (0x43)   |    A (0x41)   |    C (0x43)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    A (0x41)   |    C (0x43)   |    A (0x41)   |    C (0x43)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    A (0x41)   |    C (0x43)   |    A (0x41)   |    C (0x43)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    A (0x41)   |    C (0x43)   |    A (0x41)   |    C (0x43)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    A (0x41)   |    C (0x43)   |    A (0x41)   |    C (0x43)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    A (0x41)   |    C (0x43)   |    A (0x41)   |    C (0x43)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    A (0X41)   |      0x07     |    N (0x4E)   |    E (0x45)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    T (0x54)   |    B (0x42)   |    I (0x49)   |    O (0x4F)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    S (0x53)   |      0x03     |    C (0x43)   |    O (0x4F)   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    M (0x4D)   |      0x00     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   Each section of a domain name is called a label [7 (page 31)].  A
 *   label can be a maximum of 63 bytes.  The first byte of a label in
 *   compressed representation is the number of bytes in the label.  For
 *   the above example, the first 0x20 is the number of bytes in the
 *   left-most label, EGFCEFEECACACACACACACACACACACACA, of the domain
 *   name.  The bytes following the label length count are the characters
 *   of the label.  The following labels are in sequence after the first
 *   label, which is the encoded NetBIOS name, until a zero (0x00) length
 *   count.  The zero length count represents the root label, which is
 *   always null.
 *
 *   A label length count is actually a 6-bit field in the label length
 *   field.  The most significant 2 bits of the field, bits 7 and 6, are
 *   flags allowing an escape from the above compressed representation.
 *   If bits 7 and 6 are both set (11), the following 14 bits are an
 *   offset pointer into the full message to the actual label string from
 *   another domain name that belongs in this name.  This label pointer
 *   allows for a further compression of a domain name in a packet.
 *
 *   NetBIOS implementations can only use label string pointers in Name
 *   Service packets.  They cannot be used in Session or Datagram Service
 *   packets.
 *
 *   The other two possible values for bits 7 and 6 (01 and 10) of a label
 *   length field are reserved for future use by RFC 883[2 (page 32)].
 *
 *   Note that the first octet of a compressed name must contain one of
 *   the following bit patterns.  (An "x" indicates a bit whose value may
 *   be either 0 or 1.):
 *
 *           00100000 -  Netbios name, length must be 32 (decimal)
 *           11xxxxxx -  Label string pointer
 *           10xxxxxx -  Reserved
 *           01xxxxxx -  Reserved
 */

/*
 * netbios_first_level_name_encode
 *
 * Put test description here.
 *
 * Inputs:
 *	char *	in	-> Name to encode
 *	char *	out	-> Buffer to encode into.
 *	int	length	-> # of bytes to encode.
 *
 * Returns:
 *	Nothing
 */
int
netbios_first_level_name_encode(unsigned char *name, unsigned char *scope,
    unsigned char *out, int max_out)
{
	unsigned char	ch, len;
	unsigned char	 *in;
	unsigned char	 *lp;
	unsigned char	 *op = out;

	if (max_out < 0x21)
		return (-1);

	in = name;
	*op++ = 0x20;
	for (len = 0; len < NETBIOS_NAME_SZ; len++) {
		ch = *in++;
		*op++ = 'A' + ((ch >> 4) & 0xF);
		*op++ = 'A' + ((ch) & 0xF);
	}

	max_out -= 0x21;

	in = scope;
	len = 0;
	lp = op++;
	while (((ch = *in++) != 0) && (max_out-- > 1)) {
		if (ch == 0) {
			if ((*lp = len) != 0)
				*op++ = 0;
			break;
		}
		if (ch == '.') {
			*lp = len;
			lp = op++;
			len = 0;
		} else {
			*op++ = ch;
			len++;
		}
	}
	*lp = len;
	if (len != 0)
		*op = 0;

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (op - out);
}

/*
 * smb_first_level_name_decode
 *
 * The null terminated string "in" is the name to decode. The output
 * is placed in the name_entry structure "name".
 *
 * The scope field is a series of length designated labels as described
 * in the "Domain name representation and compression" section of RFC883.
 * The two high order two bits of the length field must be zero, the
 * remaining six bits contain the field length. The total length of the
 * domain name is restricted to 255 octets but note that the trailing
 * root label and its dot are not printed. When converting the labels,
 * the length fields are replaced by dots.
 *
 * Returns the number of bytes scanned or -1 to indicate an error.
 */
int
netbios_first_level_name_decode(char *in, char *name, char *scope)
{
	unsigned int	length;
	char		c1, c2;
	char		*cp;
	char		*out;

	cp = in;

	if ((length = *cp++) != 0x20) {
		return (-1);
	}

	out = name;
	while (length > 0) {
		c1 = *cp++;
		c2 = *cp++;

		if ('A' <= c1 && c1 <= 'P' && 'A' <= c2 && c2 <= 'P') {
			c1 -= 'A';
			c2 -= 'A';
			*out++ = (c1 << 4) | (c2);
		} else {
			return (-1);		/* conversion error */
		}
		length -= 2;
	}

	/*
	 * Don't bother decoding the scope.  Not supported.
	 */
	if ((length = *cp++) != 0)
		return (-1);
	scope[0] = '\0';

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (cp - in);
}

/*
 * smb_netbios_name_isvalid
 *
 * This function is provided to be used by session service
 * which runs in kernel in order to hide name_entry definition.
 *
 * It returns the decoded name in the provided buffer as 'out'
 * if it's not null.
 *
 * Returns 0 if decode fails, 1 if it succeeds.
 */
int
netbios_name_isvalid(char *in, char *out)
{
	char name[NETBIOS_NAME_SZ];
	char scope[NETBIOS_DOMAIN_NAME_MAX];

	if (netbios_first_level_name_decode(in, name, scope) < 0)
		return (0);

	if (out)
		(void) strlcpy(out, name, NETBIOS_NAME_SZ);

	return (1);
}
