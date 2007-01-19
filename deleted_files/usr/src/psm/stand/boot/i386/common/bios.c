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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/controlregs.h>
#include <sys/bootconf.h>
#include <sys/bootvfs.h>
#include <sys/psw.h>
#include "biosint.h"
#include "machine.h"
#include "standalloc.h"
#include "console.h"
#include "util.h"
#include "debug.h"

#define	PCI_FUNCTION_ID		0xB1
#define	PCI_BIOS_PRESENT	0x1
#define	dprintf	if (debug & D_BIOS) printf

int bios_free;	/* i.e. no BIOS */

extern int openfile(char *, char *);
int (*bios_doint)(int, struct int_pb *);

static void
pci_check_bios(void)
{
	int ret;
	struct int_pb ic = {0};

	ic.ax = (PCI_FUNCTION_ID << 8) | PCI_BIOS_PRESENT;
	ret = bios_doint(0x1a, &ic);
	if (ret & PS_C)
		printf("bios_doint failed: %d\r\n", ret);
	dprintf("bios_doint returned: %d\r\n", ret);
	dprintf("ic.ax = 0x%x\r\n", (int)ic.ax);
	dprintf("ic.dx = 0x%x\r\n", (int)ic.dx);
}

/* dummy bios routine when no BIOS is present */
/*ARGSUSED*/
static int
bios_doint_none(int a, struct int_pb *p)
{
	dprintf("bios_doint_none: fail 0x%x\n", a);
	return (PS_C);
}

void
init_biosprog()
{
	int fd;
	char *buf = (char *)0x2000;
	ssize_t count;

	if (bios_free) {
		bios_doint = bios_doint_none;
		return;
	}

	/* read biosint program to pfn 2 */
	fd = openfile("biosint", NULL);
	if (fd == -1) {
		printf("cannot open biosint\n");
		return;
	}

	count = read(fd, buf, PAGESIZE);
	if (count <= 0) {
		printf("cannot read biosint\n");
		return;
	}

	bios_doint = (int (*)(int, struct int_pb *))(buf);
	dprintf("biosint loaded at 0x%p: %ld bytes\r\n", (void *)buf, count);
	if (debug & D_BIOS)	/* run a check if debug */
		pci_check_bios();
	if (verbosemode)
		printf("bios service program installed\n");
}
