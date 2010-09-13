/*
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <k5-int.h>

/*
 * Note, there is no memset() in kernel land.  This code is a replacement for
 * use in the kerberos kernel mech.
 * As a performance enhancement, bzero is called if the fill pattern is 0.
 */
void *
krb5_memset(void *sp1, int c, size_t n)
{
	if (n > 0) {
		if (c == 0) {
			bzero(sp1, n);
		} else {
			unsigned char *sp = sp1;
			do {
				*sp++ = (unsigned char)c;
			} while (--n != 0);
		}
	}

	return (sp1);
}
