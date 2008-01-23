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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak uadmin = _uadmin

/*
 * Wrapper function to implement reboot w/ arguments on x86
 * platforms. Extract reboot arguments and place them in
 * in a transient entry in /[stub]boot/grub/menu.lst
 * All other commands are passed through.
 */

#include "synonyms.h"
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uadmin.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <zone.h>

static int
legal_arg(char *bargs)
{
	int i;

	for (i = 0; i < BOOTARGS_MAX; i++, bargs++) {
		if (*bargs == 0 && i > 0)
			return (i);
		if (!isprint(*bargs))
			break;
	}
	return (-1);
}

static char quote[] = "\'";

int
uadmin(int cmd, int fcn, uintptr_t mdep)
{
	extern int __uadmin(int cmd, int fcn, uintptr_t mdep);
	char *bargs, cmdbuf[256];
	struct stat sbuf;
	char *altroot;

	bargs = (char *)mdep;
	if (geteuid() == 0 && getzoneid() == GLOBAL_ZONEID &&
	    (cmd == A_SHUTDOWN || cmd == A_REBOOT)) {
		switch (fcn) {
		case AD_IBOOT:
		case AD_SBOOT:
		case AD_SIBOOT:
			/*
			 * These functions fabricate appropriate bootargs.
			 * If bootargs are passed in, map these functions
			 * to AD_BOOT.
			 */
			if (bargs == 0) {
				switch (fcn) {
				case AD_IBOOT:
					bargs = "-a";
					break;
				case AD_SBOOT:
					bargs = "-s";
					break;
				case AD_SIBOOT:
					bargs = "-sa";
					break;
				}
			}
			/*FALLTHROUGH*/
		case AD_BOOT:
			if (bargs == 0)
				break;	/* no args */
			if (legal_arg(bargs) < 0)
				break;	/* bad args */

			/* avoid cancellation in system() */
			(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
			    NULL);

			/* check for /stubboot */
			if (stat("/stubboot/boot/grub/menu.lst", &sbuf) == 0) {
				altroot = "-R /stubboot ";
			} else {
				altroot = "";
			}

			/* are we rebooting to a GRUB menu entry? */
			if (isdigit(bargs[0])) {
				int entry = strtol(bargs, NULL, 10);
				(void) snprintf(cmdbuf, sizeof (cmdbuf),
				    "/sbin/bootadm set-menu %sdefault=%d",
				    altroot, entry);
			} else {
				(void) snprintf(cmdbuf, sizeof (cmdbuf),
				    "/sbin/bootadm -m update_temp %s"
				    "-o %s%s%s", altroot, quote, bargs, quote);
			}
			(void) system(cmdbuf);
		}
	}
	return (__uadmin(cmd, fcn, mdep));
}
