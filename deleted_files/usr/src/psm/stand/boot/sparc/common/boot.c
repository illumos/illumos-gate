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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/salib.h>
#include <sys/stat.h>
#include <sys/promif.h>
#include <sys/bootvfs.h>
#include <sys/boot_redirect.h>
#include "boot_plat.h"

/*
 * This implementation of bootprog() is used by all bootloaders except wanboot.
 */

#define	SUCCESS		0
#define	FAILURE		-1

/*
 * bpath is the boot device path buffer.
 * bargs is the boot arguments buffer.
 */
/*ARGSUSED*/
int
bootprog(char *bpath, char *bargs, boolean_t user_specified_filename)
{
	boolean_t	once = B_FALSE;

	systype = set_fstype(v2path, bpath);

loop:
	/*
	 * Beware: the following code may be executed twice, with different
	 * bpath's if we discover a redirection file.
	 */

	if (verbosemode) {
		printf("device path '%s'\n", bpath);
		if (strcmp(bpath, v2path) != 0)
			printf("client path '%s'\n", v2path);
	}

	if (mountroot(bpath) != SUCCESS)
		prom_panic("Could not mount filesystem.");

	/*
	 * kernname (default-name) might have changed if mountroot() called
	 * boot_nfs_mountroot(), and it called set_default_filename().
	 */
	if (!user_specified_filename)
		(void) strcpy(filename, kernname);

	if (verbosemode)
		printf("standalone = `%s', args = `%s'\n", filename, bargs);

	set_client_bootargs(filename, bargs);

	if (!once &&
	    (strcmp(systype, "ufs") == 0 || strcmp(systype, "hsfs") == 0)) {
		char redirect[OBP_MAXPATHLEN];

		post_mountroot(filename, redirect);

		/*
		 * If we return at all, it's because we discovered
		 * a redirection file - the 'redirect' string now contains
		 * the name of the disk slice we should be looking at.
		 *
		 * Unmount the filesystem, tweak the boot path and retry
		 * the whole operation one more time.
		 */
		closeall(1);
		once = B_TRUE;
		redirect_boot_path(bpath, redirect);
		if (verbosemode)
			printf("%sboot: using '%s'\n", systype, bpath);

		goto loop;
		/*NOTREACHED*/
	}

	return (0);
}
