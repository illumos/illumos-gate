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

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * Common functions for helper provider loading both compiled into the
 * executable via drti.o and dtrace(8) -G, and the libdaudit.so library.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dlink.h>

/*
 * In Solaris 10 GA, the only mechanism for communicating helper information
 * is through the DTrace helper pseudo-device node in /devices; there is
 * no /dev link. Because of this, USDT providers and helper actions don't
 * work inside of non-global zones. This issue was addressed by adding
 * the /dev and having this initialization code use that /dev link. If the
 * /dev link doesn't exist it falls back to looking for the /devices node
 * as this code may be embedded in a binary which runs on Solaris 10 GA.
 */
const char *devname = "/dev/dtrace/helper";
static const char *olddevname = "/devices/pseudo/dtrace@0:helper";

static boolean_t dof_init_debug = B_FALSE;

void
dprintf(int debug, const char *fmt, ...)
{
	va_list ap;

	if (debug && !dof_init_debug)
		return;

	va_start(ap, fmt);

	(void) fprintf(stderr, "dtrace DOF: ");

	(void) vfprintf(stderr, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(stderr, ": %s\n", strerror(errno));

	va_end(ap);
}

/*
 * Users may set the following environment variable to affect the way
 * helper initialization takes place:
 *
 *	DTRACE_DOF_INIT_DEBUG		enable debugging output
 *	DTRACE_DOF_INIT_DISABLE		disable helper loading
 *	DTRACE_DOF_INIT_DEVNAME		set the path to the helper node
 */
void
dtrace_link_init(void)
{
	if (getenv("DTRACE_DOF_INIT_DEBUG") != NULL)
		dof_init_debug = B_TRUE;
}

void
dtrace_link_dof(dof_hdr_t *dof, Lmid_t lmid, const char *name, uintptr_t addr)
{
	const char *modname;
	const char *p;
#ifdef _LP64
	Elf64_Ehdr *elf;
#else
	Elf32_Ehdr *elf;
#endif
	dof_helper_t dh;
	int fd;

	if (getenv("DTRACE_DOF_INIT_DISABLE") != NULL)
		return;

	if ((modname = strrchr(name, '/')) == NULL)
		modname = name;
	else
		modname++;

	if (dof->dofh_ident[DOF_ID_MAG0] != DOF_MAG_MAG0 ||
	    dof->dofh_ident[DOF_ID_MAG1] != DOF_MAG_MAG1 ||
	    dof->dofh_ident[DOF_ID_MAG2] != DOF_MAG_MAG2 ||
	    dof->dofh_ident[DOF_ID_MAG3] != DOF_MAG_MAG3) {
		dprintf(0, ".SUNW_dof section corrupt for %s\n", modname);
		return;
	}

	elf = (void *)addr;

	dh.dofhp_dof = (uintptr_t)dof;
	dh.dofhp_addr = elf->e_type == ET_DYN ? addr : 0;

	if (lmid == LM_ID_BASE) {
		(void) snprintf(dh.dofhp_mod, sizeof (dh.dofhp_mod),
		    "%s", modname);
	} else {
		(void) snprintf(dh.dofhp_mod, sizeof (dh.dofhp_mod),
		    "LM%lu`%s", lmid, modname);
	}

	if ((p = getenv("DTRACE_DOF_INIT_DEVNAME")) != NULL)
		devname = p;

	if ((fd = open64(devname, O_RDWR)) < 0) {
		dprintf(1, "failed to open helper device %s", devname);

		/*
		 * If the device path wasn't explicitly set, try again with
		 * the old device path.
		 */
		if (p != NULL)
			return;

		devname = olddevname;

		if ((fd = open64(devname, O_RDWR)) < 0) {
			dprintf(1, "failed to open helper device %s", devname);
			return;
		}
	}

	if (ioctl(fd, DTRACEHIOC_ADDDOF, &dh) == -1) {
		dprintf(1, "DTrace ioctl failed for DOF at %p in %s", dof,
		    name);
	} else {
		dprintf(1, "DTrace ioctl succeeded for DOF at %p in %s\n", dof,
		    name);
	}
	(void) close(fd);
}
