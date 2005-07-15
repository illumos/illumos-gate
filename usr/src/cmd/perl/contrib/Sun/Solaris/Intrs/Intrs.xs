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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>
#include <errno.h>

#include "../../../../../../../uts/common/sys/pci_tools.h"

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

MODULE = Sun::Solaris::Intrs		PACKAGE = Sun::Solaris::Intrs
PROTOTYPES: ENABLE

int
intrmove(path, ino, cpu)
	char *path
	int ino
	int cpu
    INIT:
	int i, ret;
	pcitool_intr_set_t iset;
	static int fd = -1;
	static char intrpath[MAXPATHLEN];

    CODE:
	if (fd == -1 || strcmp(path, intrpath)) {
		(void) strcpy(intrpath, "/devices");
		(void) strcat(intrpath, path);
		(void) strcat(intrpath, ":intr");
		if (fd != -1)
			(void) close(fd);
		fd = open(intrpath, O_RDONLY);
		if (fd == -1) {
			XSRETURN_UNDEF;
		}
	}
	iset.ino = ino;
	iset.cpu_id = cpu;
	iset.user_version = PCITOOL_USER_VERSION;

	ret = ioctl(fd, PCITOOL_DEVICE_SET_INTR, &iset);

	if (ret == -1) {
		XSRETURN_UNDEF;
	}
	XSRETURN_YES;
