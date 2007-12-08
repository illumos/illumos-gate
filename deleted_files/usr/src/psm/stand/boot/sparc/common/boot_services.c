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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions of interfaces that provide services from the secondary
 * boot program to its clients (primarily unix, krtld and their successors.)
 * This interface replaces the bootops (BOP) implementation as the interface
 * to be called by boot clients. The BOP macros are still used to make the
 * integration easier.
 *
 * The bootops vector is vestigial.
 *
 * The kern_* routines used to implement many of the services here
 * are in the usr/src/stand/lib/ modules.
 *
 */

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/reboot.h>
#include <sys/param.h>
#include <sys/varargs.h>
#include <sys/obpdefs.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include <sys/stat.h>
#include <sys/bootvfs.h>

extern void	kern_killboot(void);
extern int	bgetprop(struct bootops *, char *name, void *buf);
extern int	bgetproplen(struct bootops *, char *name);
extern char	*bnextprop(struct bootops *, char *prev);
extern caddr_t	resalloc_virt(caddr_t virt, size_t size);

static int boot1275_serviceavail(void *p);

static struct boot_nm2svc *nm2svcp(char *name);

/*
 * Implementation of the "version" service.
 * Return the compiled version number of this implementation of boot.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] Res0: returned version number
 */
static int boot_version = BO_VERSION;
static int
boot1275_getversion(void *p)
{
	boot_cell_t *args = (boot_cell_t *)p;

	args[3] = boot_int2cell(boot_version);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "open" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] filename string
 * args[4] flags
 * args[5] Res0: returned result
 *
 */
static int
boot1275_open(void *p)
{
	int rc;
	int flags;
	char *name;
	boot_cell_t *args = (boot_cell_t *)p;

	name = boot_cell2ptr(args[3]);
	flags = boot_cell2int(args[4]);
	rc = kern_open(name, flags);
	args[5] = boot_int2cell(rc);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "read" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] boot-opened file descriptor
 * args[4] client's buffer
 * args[5] size of read request
 * args[6] Res0: returned result
 *
 */
static int
boot1275_read(void *p)
{
	int rc;
	boot_cell_t *args = (boot_cell_t *)p;

	/* XXX use different routine to support larger I/O ? */
	int fd;
	caddr_t buf;
	size_t size;

	fd = boot_cell2int(args[3]);
	buf = boot_cell2ptr(args[4]);
	size = boot_cell2size(args[5]);
	rc = kern_read(fd, buf, size);
	args[6] = boot_int2cell(rc);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "seek" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] boot-opened file descriptor
 * args[4] offset hi		XXX just use one cell for offset?
 * args[5] offset lo
 * args[6] Res0: returned result
 *
 */
static int
boot1275_seek(void *p)
{
	off_t rc;
	int fd;
	off_t hi, lo;
	boot_cell_t *args = (boot_cell_t *)p;

	fd = boot_cell2int(args[3]);
	hi = boot_cell2offt(args[4]);
	lo = boot_cell2offt(args[5]);
	rc = kern_lseek(fd, hi, lo);
	args[6] = boot_offt2cell(rc);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "close" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] boot-opened file descriptor
 * args[4] Res0: returned result
 *
 */
static int
boot1275_close(void *p)
{
	int rc;
	int fd;
	boot_cell_t *args = (boot_cell_t *)p;

	fd = boot_cell2int(args[3]);
	rc = kern_close(fd);
	args[4] = boot_int2cell(rc);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "alloc" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] virtual hint
 * args[4] size to allocate
 * args[5] alignment
 * args[6] Res0: returned result
 */
static int
boot1275_alloc(void *p)
{
	caddr_t virthint, addr;
	size_t size;
	int align;
	boot_cell_t *args = (boot_cell_t *)p;

	virthint = boot_cell2ptr(args[3]);
	size = boot_cell2size(args[4]);
	align = boot_cell2int(args[5]);
	addr = kern_resalloc(virthint, size, align);
	args[6] = boot_ptr2cell(addr);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "alloc_virt" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #arguments cells
 * args[2] #result cells
 * args[3] virtual address
 * args[4] size to allocate
 * args[5] Res0: returned result
 */
static int
boot1275_alloc_virt(void *p)
{
	caddr_t virt, addr;
	size_t size;
	boot_cell_t *args = (boot_cell_t *)p;

	virt = boot_cell2ptr(args[3]);
	size = boot_cell2size(args[4]);
	addr  = resalloc_virt(virt, size);
	args[5] = boot_ptr2cell(addr);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "free" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] virtual addr
 * args[4] size to free
 * args[5] Res0: returned result
 */
/*ARGSUSED*/
static int
boot1275_free(void *p)
{
	caddr_t virtaddr;
	size_t size;
	boot_cell_t *args = (boot_cell_t *)p;

	virtaddr = boot_cell2ptr(args[3]);
	size = boot_cell2size(args[4]);
	kern_resfree(virtaddr, size);
	args[5] = (boot_cell_t)0;
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "map" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] virtual address
 * args[4] space of phys addr
 * args[5] phys addr
 * args[6] size
 * args[7] Res0: returned result
 */
/*ARGSUSED*/
static int
boot1275_map(void *p)
{
	boot_cell_t *args = (boot_cell_t *)p;

	args[6] = (boot_cell_t)0;
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "unmap" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] virtual address
 * args[4] size of chunk
 * args[5] Res0: returned result
 */
/*ARGSUSED*/
static int
boot1275_unmap(void *p)
{
	boot_cell_t *args = (boot_cell_t *)p;

	args[5] = (boot_cell_t)0;
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "quiesce" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] Res0: returned result
 */
/*ARGSUSED*/
static int
boot1275_quiesce(void *p)
{
	boot_cell_t *args = (boot_cell_t *)p;

	kern_killboot();
	args[3] = (boot_cell_t)0;
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "getproplen" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] property name string
 * args[4] Res0: returned result
 */
/*ARGSUSED*/
static int
boot1275_getproplen(void *p)
{
	int rc;
	char *name;
	boot_cell_t *args = (boot_cell_t *)p;


	name = boot_cell2ptr(args[3]);
	rc = bgetproplen((struct bootops *)0, name);
	args[4] = boot_int2cell(rc);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "getprop" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] property name string
 * args[4] buffer pointer to hold value of the property
 * args[5] Res0: returned result
 */
/*ARGSUSED*/
static int
boot1275_getprop(void *p)
{
	int rc;
	char *name;
	void *buf;
	boot_cell_t *args = (boot_cell_t *)p;


	name = boot_cell2ptr(args[3]);
	buf = boot_cell2ptr(args[4]);
	rc = bgetprop((struct bootops *)0, name, buf);
	args[5] = boot_int2cell(rc);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "putsarg" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] string to print (with '%*' format)
 * args[4] 64-bit thing to print
 *
 * The bootops interface can only pass one additional
 * argument.  Abusing the format string can cause failures
 * in interesting ways that could be hard to debug when
 * an argument is pulled off the stack or dereferenced,
 * so if the format string indicates more than one argument,
 * we note the problem rather print garbage or panic.
 */
/*ARGSUSED*/
static int
boot1275_putsarg(void *p)
{
	const char	*string;
	boot_cell_t	*args = (boot_cell_t *)p;
	const char	*fmt;
	int		ells = 0;
	int		arg_is_ptr = 0;
	int		nargs = 0;
	uint64_t	arg;


	string = boot_cell2ptr(args[3]);
	arg = boot_cell2uint64(args[4]);

	/*
	 * We need to do the minimum printf-like stuff here to figure
	 * out the size of argument, if present.
	 */
	for (fmt = string; *fmt; fmt++) {
		if (*fmt != '%')
			continue;
		if (*(++fmt) == '%')
			continue;

		nargs++;
		while (*fmt >= '0' && *fmt <= '9')
			fmt++;
		for (ells = 0; *fmt == 'l'; fmt++)
			ells++;

		switch (*fmt) {
		case 's':
		case 'p':
			arg_is_ptr = 1;
			break;
		}
	}

	if (nargs > 1) {
		printf("boot1275_putsarg: unsupported format: \"%s\"\n",
			string);
	} else if (arg_is_ptr) {
		printf(string, (void *)arg);
	} else {
		switch (ells) {
		case 0:
			printf(string, (uint_t)arg);
			break;
		case 1:
			printf(string, (ulong_t)arg);
			break;
		default:
			printf(string, arg);
			break;
		}
	}

	return (BOOT_SVC_OK);
}
/*
 * Implementation of the "puts" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] string to print
 */
/*ARGSUSED*/
static int
boot1275_puts(void *p)
{
	char *string;
	boot_cell_t *args = (boot_cell_t *)p;


	string = boot_cell2ptr(args[3]);
	printf("%s", string);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "nextprop" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] previous property name string
 * args[4] Res0: returned result
 */
/*ARGSUSED*/
static int
boot1275_nextprop(void *p)
{
	char *name, *np;
	boot_cell_t *args = (boot_cell_t *)p;

	name = boot_cell2ptr(args[3]);
	np = bnextprop((struct bootops *)0, name);
	args[4] = boot_ptr2cell(np);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "mount" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] pathname string
 * args[4] Res0: returned result
 */
/*ARGSUSED*/
static int
boot1275_mountroot(void *p)
{
	int rc;
	char *name;
	boot_cell_t *args = (boot_cell_t *)p;

	name = boot_cell2ptr(args[3]);
	rc = kern_mountroot(name);
	args[4] = boot_cell2int(rc);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "unmount" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] Res0: returned result
 */
/*ARGSUSED*/
static int
boot1275_unmountroot(void *p)
{
	int rc;
	boot_cell_t *args = (boot_cell_t *)p;

	rc = kern_unmountroot();
	args[3] = boot_cell2int(rc);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "fstat" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] fd
 * args[4] client's stat structure
 */
int
boot1275_fstat(void *p)
{
	boot_cell_t *args = (boot_cell_t *)p;
	int fd = boot_cell2int(args[3]);
	struct bootstat *st = boot_cell2ptr(args[4]);
	int rc = kern_fstat(fd, st);

	args[5] = boot_int2cell(rc);
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "interpret" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells (1)
 * args[2] #result cells (0)
 * args[3] string to interpret
 */
int
boot1275_interpret(void *p)
{
	boot_cell_t *args = (boot_cell_t *)p;
	char *str = boot_cell2ptr(args[3]);

	prom_interpret(str, 0, 0, 0, 0, 0);

	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "enter_mon" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells (0)
 * args[2] #result cells (0)
 */
/*ARGSUSED*/
int
boot1275_enter_mon(void *p)
{
	prom_enter_mon();

	return (BOOT_SVC_OK);
}

/*
 * The lookup table akin to the old bootops vec
 * for boot. Not part of the exported interface.
 */
static struct boot_nm2svc {
	char *b_name;
	int (*b_funcptr)(void *);
	int b_svcversion;
} boot_nm2svc[] = {
	{ "version",		boot1275_getversion,	1 },
	{ "open",		boot1275_open,		1 },
	{ "read",		boot1275_read,		1 },
	{ "seek",		boot1275_seek,		1 },
	{ "close",		boot1275_close,		1 },
	{ "alloc",		boot1275_alloc,		1 },
	{ "alloc_virt",		boot1275_alloc_virt,	1 },
	{ "free",		boot1275_free,		1 },
	{ "map",		boot1275_map,		1 },
	{ "unmap",		boot1275_unmap,		1 },
	{ "quiesce",		boot1275_quiesce,	1 },
	{ "getproplen",		boot1275_getproplen,	1 },
	{ "getprop",		boot1275_getprop,	1 },
	{ "nextprop",		boot1275_nextprop,	1 },
	{ "mountroot",		boot1275_mountroot,	1 },
	{ "unmountroot",	boot1275_unmountroot,	1 },
	{ "serviceavail",	boot1275_serviceavail,	1 },
	{ "puts",		boot1275_puts,		1 },
	{ "putsarg",		boot1275_putsarg,	1 },
	{ "fstat",		boot1275_fstat,		1 },
	{ "interpret",		boot1275_interpret,	1 },
	{ "enter_mon",		boot1275_enter_mon,	1 },
	{ 0, 0, 0 }
};

static struct boot_nm2svc *
nm2svcp(char *name)
{
	struct boot_nm2svc *pnm2svc = &boot_nm2svc[0];

	while (pnm2svc->b_name != 0) {
		if (strcmp(pnm2svc->b_name, name))
			pnm2svc++;
		else {
			return (pnm2svc);
		}
	}
	return (NULL);
}

/*
 * Implementation of the "serviceavail" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] name string of service to be tested for
 * args[4] Res0: returned version number or 0
 */
/*ARGSUSED*/
static int
boot1275_serviceavail(void *p)
{
	boot_cell_t *args = (boot_cell_t *)p;
	char *name;
	struct boot_nm2svc *pnm2svc;
	int version = 0;			/* 0 means service not avail */

	name = boot_cell2ptr(args[3]);
	pnm2svc = nm2svcp(name);
	if (pnm2svc != 0)
		version = pnm2svc->b_svcversion;
	args[4] = boot_int2cell(version);
	return (BOOT_SVC_OK);
}

int
boot1275_entry(void *p)
{
	int	rc = 0;
	char *name;
	int (*fp)();
	boot_cell_t *args = (boot_cell_t *)p;
	struct boot_nm2svc *pnm2svc;

	name = boot_cell2ptr(args[0]);
	pnm2svc = nm2svcp(name);
	if (pnm2svc != NULL) {
		fp = (int(*)())(pnm2svc->b_funcptr);
		rc = (*fp)(args);
	} else {
		prom_printf("call to undefined service \"%s\"\n", name);
	}
	return (rc);
}
