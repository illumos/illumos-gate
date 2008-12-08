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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <errno.h>
#include <ctype.h>

#include <cryptoutil.h>

/*
 * tohexstr
 * IN	bytes
 *	blen
 *	hexlen should be 2 * blen + 1
 * OUT
 *	hexstr
 */
void
tohexstr(uchar_t *bytes, size_t blen, char *hexstr, size_t hexlen)
{
	size_t i;
	char hexlist[] = "0123456789abcdef";

	for (i = 0; i < blen; i++) {
		if (hexlen < (2 * i + 1))
			break;
		hexstr[2 * i] = hexlist[(bytes[i] >> 4) & 0xf];
		hexstr[2 * i + 1] = hexlist[bytes[i] & 0xf];
	}
	hexstr[2 * blen] = '\0';
}

/*
 * This function takes a char[] and length of hexadecimal values and
 * returns a malloc'ed byte array with the length of that new byte array.
 * The caller needs to provide a pointer to where this new malloc'ed byte array
 * will be passed back; as well as, a pointer for the length of the new
 * byte array.
 *
 * The caller is responsible for freeing the malloc'ed array when done
 *
 * The return code is 0 if successful, otherwise the errno value is returned.
 */
int
hexstr_to_bytes(char *hexstr, size_t hexlen, uchar_t **bytes, size_t *blen)
{
	int i, ret = 0;
	unsigned char ch;
	uchar_t *b = NULL;

	*bytes = NULL;
	*blen = 0;

	if (hexstr == NULL || (hexlen % 2 == 1))
		return (EINVAL);

	if (hexstr[0] == '0' && ((hexstr[1] == 'x') || (hexstr[1] == 'X'))) {
		hexstr += 2;
		hexlen -= 2;
	}

	*blen = (hexlen / 2);

	b = malloc(*blen);
	if (b == NULL) {
		*blen = 0;
		return (errno);
	}

	for (i = 0; i < hexlen; i++) {
		ch = (unsigned char) *hexstr;

		if (!isxdigit(ch)) {
			ret = EINVAL;
			goto out;
		}

		hexstr++;

		if ((ch >= '0') && (ch <= '9'))
			ch -= '0';
		else if ((ch >= 'A') && (ch <= 'F'))
			ch = ch - 'A' + 10;
		else if ((ch >= 'a') && (ch <= 'f'))
			ch = ch - 'a' + 10;

		if (i & 1)
			b[i/2] |= ch;
		else
			b[i/2] = (ch << 4);
	}

out:
	if (b != NULL && ret != 0) {
		free(b);
		*blen = 0;
	} else
		*bytes = b;

	return (ret);
}
