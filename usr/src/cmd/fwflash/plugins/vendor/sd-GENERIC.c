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
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <sys/condvar.h>
#include <string.h>
#include <strings.h>

#include <sys/byteorder.h>

#include <libintl.h> /* for gettext(3c) */
#include <fwflash/fwflash.h>

char vendor[] = "GENERIC \0";

/* MAXIMGSIZE = 1.4 * 1024 * 1024 bytes */
/* Currently the largest firmware image size is 1.4 MB */
/* 1468006 = 1.4 * 1024 * 1024 */
#define	MAXIMGSIZE	((unsigned int)(1468006))

extern struct vrfyplugin *verifier;

/* required functions for this plugin */
int vendorvrfy(struct devicelist *devicenode);

/*
 * Important information about how this verification plugin works
 *
 * Direct-attached disks (sd instances) which support firmware
 * download accept image files up to 1.4 * 1024 * 1024 bytes in
 * size, and do their own verification of the image, rejecting the
 * file if it is not appropriate for them.
 *
 * All that we need to do here is set the various verifier fields
 * correctly, and check that the filesize as read from the filesystem
 * is less than 1.4 * 1024 * 1024 bytes.
 */

int
vendorvrfy(struct devicelist *devicenode)
{
	if (verifier->imgsize > MAXIMGSIZE) {
		logmsg(MSG_ERROR,
		    gettext("\nsd-GENERIC firmware image verifier: "
		    "supplied filename %s exceeds maximum allowable "
		    "size of %d bytes\n"),
		    verifier->imgfile, MAXIMGSIZE);
		return (FWFLASH_FAILURE);
	}

	logmsg(MSG_INFO,
	    "sd-GENERIC verifier for device\n"
	    "vid %s, pid %s, rev %s\npath %s\n",
	    devicenode->ident->vid,
	    devicenode->ident->pid,
	    devicenode->ident->revid,
	    devicenode->addresses[0]);
	verifier->flashbuf = 0;

	return (FWFLASH_SUCCESS);
}
