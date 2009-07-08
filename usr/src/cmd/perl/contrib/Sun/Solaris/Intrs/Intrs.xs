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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>
#include <errno.h>

/* Non-shipping header - see Makefile.PL */
#include <pci_tools.h>

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

static int
open_dev(char *path)
{
	char intrpath[MAXPATHLEN];

	(void) strcpy(intrpath, "/devices");
	(void) strcat(intrpath, path);
	(void) strcat(intrpath, ":intr");
	return (open(intrpath, O_RDWR));
}

MODULE = Sun::Solaris::Intrs		PACKAGE = Sun::Solaris::Intrs
PROTOTYPES: ENABLE

int
intrmove(path, ino, cpu, num_ino)
	char *path
	int ino
	int cpu
	int num_ino
    INIT:
	int fd, ret;
	pcitool_intr_set_t iset;

    CODE:
	if ((fd = open_dev(path)) == -1) {
		XSRETURN_UNDEF;
	}
	iset.ino = ino;
	iset.cpu_id = cpu;
	iset.flags = (num_ino > 1) ? PCITOOL_INTR_FLAG_SET_GROUP : 0;
	iset.user_version = PCITOOL_VERSION;

	ret = ioctl(fd, PCITOOL_DEVICE_SET_INTR, &iset);

	if (ret == -1) {
		XSRETURN_UNDEF;
	}
	(void) close(fd);
	XSRETURN_YES;

int
is_pcplusmp(path)
	char *path

    INIT:
	int fd, ret;
	pcitool_intr_info_t iinfo;

    CODE:
	if ((fd = open_dev(path)) == -1) {
		XSRETURN_UNDEF;
	}
	iinfo.user_version = PCITOOL_VERSION;

	ret = ioctl(fd, PCITOOL_SYSTEM_INTR_INFO, &iinfo);
	(void) close(fd);

	if (ret == -1) {
		XSRETURN_UNDEF;
	}

	if (iinfo.ctlr_type == PCITOOL_CTLR_TYPE_PCPLUSMP) {
		XSRETURN_YES;
	}

	XSRETURN_NO;
