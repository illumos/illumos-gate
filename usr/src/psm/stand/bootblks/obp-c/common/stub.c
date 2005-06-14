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
 * Copyright 1999, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Stub for deprecated OBP V0 and V2 systems (sun4c).
 */

#include <sys/param.h>
#include <sys/promif.h>
#include "romp.h"

/*
 * XXX	Should be 'static'; 'extern' definition in header files prevent this
 */
union sunromvec *romp;

#define	OBP_V0_ROMVEC_VERSION	0
#define	OBP_ROMVEC_VERSION	(romp->obp.op_romvec_version)
#define	OBP_V0_PRINTF		(*romp->obp.v_printf)
#define	OBP_V2_WRITE		(*romp->obp.op2_write)
#define	OBP_V2_STDOUT		(*romp->obp.op2_stdout)
#define	OBP_EXIT_TO_MON		(*romp->obp.op_exit)

static void
fw_init(void *ptr)
{
	romp = ptr;
}

void
exit()
{
	OBP_EXIT_TO_MON();
}

static void
putchar(char c)
{
	while (OBP_V2_WRITE(OBP_V2_STDOUT, &c, 1) != 1)
		;
}

static void
puts(char *msg)
{
	char c;

	if (OBP_ROMVEC_VERSION == OBP_V0_ROMVEC_VERSION)
		OBP_V0_PRINTF(msg);
	else {
		/* prepend carriage return to linefeed */
		while ((c = *msg++) != '\0') {
			if (c == '\n')
				putchar('\r');
			putchar(c);
		}
	}
}

void
main(void *ptr)
{
	fw_init(ptr);
	puts("This hardware platform is not supported by this "
	    "release of Solaris.\n");
}

void
bzero(void *p, size_t n)
{
	char	zeero	= 0;
	char	*cp	= p;

	while (n != 0)
		*cp++ = zeero, n--;	/* Avoid clr for 68000, still... */
}
