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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Function implementations to convert between link layer addresses and
 * ascii representations of the form "x:x:x:...:x:x:x" where x is a hex
 * number between 0x00 and 0xff; the bytes are always in network order.
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <net/if_dl.h>

/*
 * Converts a "size" bytes long mac address to its string representation.
 * Currently, the "mactype" is unused, but in the future, the string
 * can be modulated by "mactype" (IFT_* value from <net/if_types.h>)
 */
/* ARGSUSED */
char *
_link_ntoa(const unsigned char *macaddr, char *str, int size, int mactype)
{
	char *buf;
	int i, n;

	if (((buf = str) == NULL) &&
	    ((buf = malloc(3 * size)) == NULL))
		return (NULL);
	n = sprintf(buf, "%x", *macaddr++);
	for (i = 0; i < (size - 1); i++)
		n += sprintf(buf+n, ":%x", *macaddr++);
	return (buf);
}

/*
 * Converts a string possibly representing a link address into its
 * bit format, returning length of the address in bytes.
 */
uchar_t *
_link_aton(const char *ascaddr, int *maclen)
{
	unsigned char cval, num = 0;
	int idx = 0, numcolons = 0, digits = 0;
	uchar_t *netaddr;
	const char *cptr;
	char lastc = ':';

	while (isspace(*ascaddr))
		ascaddr++;

	/*
	 * Find how many :'s in the string. Also sanity check
	 * the string for valid hex chars, absence of white
	 * spaces, not starting or ending with :, absence of
	 * consecutive :'s, excessive digits per element
	 * and non-null string.
	 */
	cptr = ascaddr;
	while ((cval = *cptr++) != '\0') {
		if (cval == ':') {
			if (lastc == ':')
				break;
			numcolons++;
			digits = 0;
		} else if (!isxdigit(cval)) {
			break;
		} else {
			digits++;
		}

		if (digits > 2)
			break;

		lastc = cval;
	}
	if ((lastc == ':') || (cval != '\0' && !isspace(cval)) ||
	    (digits > 2)) {
		*maclen = -1;
		return (NULL);
	}

	if ((netaddr = malloc(numcolons + 1)) == NULL) {
		*maclen = 0;
		return (NULL);
	}

	for (;;) {
		cval = *ascaddr++;
		if (isdigit(cval)) {
			num = (num << 4) | (cval - '0');
		} else if (isxdigit(cval)) {
			num = (num << 4) |
			    (cval - (isupper(cval) ? 'A' : 'a') + 10);
		} else if (cval == ':') {
			netaddr[idx++] = num;
			num = 0;
		} else {
			/*
			 * We must have hit a whitespace. Stop
			 * parsing now.
			 */
			netaddr[idx++] = num;
			break;
		}
	}
	*maclen = idx;
	return (netaddr);
}
