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

/*
 * Definitions of interfaces that provide services from the secondary
 * boot program to its clients (primarily Solaris, krtld, kmdb and their
 * successors.) This interface replaces the bootops (BOP) implementation
 * as the interface to be called by boot clients.
 *
 */

#include <sys/types.h>
#include <sys/reboot.h>
#include <sys/param.h>
#include <sys/varargs.h>
#include <sys/obpdefs.h>
#include <sys/promif.h>
#include <sys/bootconf.h>
#include <sys/bootstat.h>

/*
 * Implementation of the "version" boot service.
 * Return the compiled version number of this implementation.
 *
 * Note: An individual service can be tested for and versioned with
 * bop_serviceavail();
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] Res0: returned version number
 */
uint_t
bop_getversion(struct bootops *bop)
{
	return (bop->bsys_version);
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
int
bop_open(struct bootops *bop, char *name, int flags)
{
	boot_cell_t args[6];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("open");
	args[1] = 2;
	args[2] = 1;

	args[3] = boot_ptr2cell(name);
	args[4] = boot_int2cell(flags);
	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[5]));
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
int
bop_read(struct bootops *bop, int fd, caddr_t buf, size_t size)
{
	boot_cell_t args[7];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("read");
	args[1] = 3;
	args[2] = 1;

	args[3] = boot_int2cell(fd);
	args[4] = boot_ptr2cell(buf);
	args[5] = boot_uint2cell(size);
	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[6]));
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
 */
int
bop_seek(struct bootops *bop, int fd, off_t hi, off_t lo)
{
	boot_cell_t args[7];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("seek");
	args[1] = 3;
	args[2] = 1;

	args[3] = boot_int2cell(fd);
	args[4] = boot_offt2cell(hi);
	args[5] = boot_offt2cell(lo);
	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[6]));
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
 */
int
bop_close(struct bootops *bop, int fd)
{
	boot_cell_t args[5];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("close");
	args[1] = 1;
	args[2] = 1;

	args[3] = boot_int2cell(fd);
	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[4]));
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
caddr_t
bop_alloc(struct bootops *bop, caddr_t virthint, size_t size, int align)
{
	boot_cell_t args[7];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("alloc");
	args[1] = 3;
	args[2] = 1;

	args[3] = boot_ptr2cell(virthint);
	args[4] = boot_size2cell(size);
	args[5] = boot_int2cell(align);
	(void) (bsys_1275_call)(args);
	return ((caddr_t)boot_ptr2cell(args[6]));
}

/*
 * Implementation of the "alloc_virt" boot service
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] virtual address
 * args[4] size to allocate
 * args[5] Resi: returned result
 */
caddr_t
bop_alloc_virt(struct bootops *bop, caddr_t virt, size_t size)
{
	boot_cell_t args[6];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("alloc_virt");
	args[1] = 2;
	args[2] = 1;

	args[3] = boot_ptr2cell(virt);
	args[4] = boot_size2cell(size);
	(void) (bsys_1275_call)(args);
	return ((caddr_t)boot_ptr2cell(args[5]));
}

/*
 * Implementation of the "free" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] virtual hint
 * args[4] size to free
 * args[5] Res0: returned result
 */
/*ARGSUSED*/
void
bop_free(struct bootops *bop, caddr_t virt, size_t size)
{
	boot_cell_t args[6];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("free");
	args[1] = 2;
	args[2] = 1;

	args[3] = boot_ptr2cell(virt);
	args[4] = boot_size2cell(size);
	(void) (bsys_1275_call)(args);
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
caddr_t
bop_map(struct bootops *bop, caddr_t virt, int space,
	caddr_t phys, size_t size)
{
	boot_cell_t args[8];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("map");
	args[1] = 3;
	args[2] = 1;

	args[3] = boot_ptr2cell(virt);
	args[4] = boot_int2cell(space);
	args[5] = boot_ptr2cell(phys);
	args[6] = boot_size2cell(size);
	(void) (bsys_1275_call)(args);
	return ((caddr_t)boot_cell2ptr(args[7]));
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
void
bop_unmap(struct bootops *bop, caddr_t virt, size_t size)
{
	boot_cell_t args[6];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("unmap");
	args[1] = 2;
	args[2] = 1;

	args[3] = boot_ptr2cell(virt);
	args[4] = boot_size2cell(size);
	(void) (bsys_1275_call)(args);
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
void
bop_quiesce_io(struct bootops *bop)
{
	boot_cell_t args[4];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("quiesce");
	args[1] = 0;
	args[2] = 1;

	(void) (bsys_1275_call)(args);
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
int
bop_getproplen(struct bootops *bop, char *name)
{
	boot_cell_t args[7];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("getproplen");
	args[1] = 1;
	args[2] = 1;

	args[3] = boot_ptr2cell(name);
	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[4]));
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
int
bop_getprop(struct bootops *bop, char *name, void *value)
{
	boot_cell_t args[6];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("getprop");
	args[1] = 2;
	args[2] = 1;

	args[3] = boot_ptr2cell(name);
	args[4] = boot_ptr2cell(value);
	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[5]));
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
char *
bop_nextprop(struct bootops *bop, char *prevprop)
{
	boot_cell_t args[5];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("nextprop");
	args[1] = 1;
	args[2] = 1;

	args[3] = boot_ptr2cell(prevprop);
	(void) (bsys_1275_call)(args);
	return ((char *)boot_cell2ptr(args[4]));
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
void
bop_puts(struct bootops *bop, char *string)
{
	boot_cell_t	args[6];
	int	(*bsys_1275_call)(void *);
	void	(*bsys_printf)(struct bootops *, char *, ...);

	/* so new kernel, old boot can print a message before dying */
	if (!BOOTOPS_ARE_1275(bop)) {
		/* use uintptr_t to suppress the gcc warning */
		bsys_printf = (void (*)(struct bootops *, char *, ...))
		    (uintptr_t)bop->bsys_printf;
		(*bsys_printf)(bop, string);
		return;
	}
	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("puts");
	args[1] = 1;
	args[2] = 0;

	args[3] = boot_ptr2cell(string);
	(void) (bsys_1275_call)(args);

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
 */
/*ARGSUSED*/
void
bop_putsarg(struct bootops *bop, const char *string, ...)
{
	boot_cell_t	args[6];
	int	(*bsys_1275_call)(void *);
	void	(*bsys_printf)(struct bootops *, char *, ...);
	va_list		ap;
	const char	*fmt = string;
	int		ells = 0;
	uint64_t	arg;

	/*
	 * We need to do the minimum printf-like stuff here to figure
	 * out the size of argument, if present.
	 */
	while (*fmt) {
		if (*fmt++ != '%')
			continue;
		if (*fmt == '%') {
			fmt++;
			continue;
		}

		while (*fmt >= '0' && *fmt <= '9')
			fmt++;
		for (ells = 0; *fmt == 'l'; fmt++)
			ells++;
		va_start(ap, string);
		switch (*fmt) {
		case 's':
			arg = (uint64_t)va_arg(ap, char *);
			break;
		case 'p':
			arg = (uint64_t)va_arg(ap, void *);
			break;
		case 'd':
		case 'D':
		case 'x':
		case 'X':
		case 'u':
		case 'U':
		case 'o':
		case 'O':
			if (ells == 0)
				arg = (uint64_t)va_arg(ap, uint_t);
			else if (ells == 1)
				arg = (uint64_t)va_arg(ap, ulong_t);
			else
				arg = (uint64_t)va_arg(ap, uint64_t);
			break;
		default:
			arg = (uint64_t)va_arg(ap, uint_t);
			break;
		}
		va_end(ap);
		break;
	}

	/* so new kernel, old boot can print a message before dying */
	if (!BOOTOPS_ARE_1275(bop)) {
		/* use uintptr_t to suppress the gcc warning */
		bsys_printf = (void (*)(struct bootops *, char *, ...))
		    (uintptr_t)bop->bsys_printf;
		(*bsys_printf)(bop, (char *)string, arg);
		return;
	}

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("putsarg");
	args[1] = 2;
	args[2] = 0;
	args[3] = boot_ptr2cell(string);
	args[4] = boot_uint642cell(arg);

	(void) (bsys_1275_call)(args);
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
int
bop_mountroot(struct bootops *bop, char *path)
{
	boot_cell_t args[5];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("mountroot");
	args[1] = 2;
	args[2] = 1;

	args[3] = boot_ptr2cell(path);
	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[4]));
}

/*
 * Implementation of the "unmountroot" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells
 * args[2] #result cells
 * args[3] Res0: returned result
 */
/*ARGSUSED*/
int
bop_unmountroot(struct bootops *bop)
{
	boot_cell_t args[4];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("unmountroot");
	args[1] = 0;
	args[2] = 1;

	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[3]));
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
int
bop_serviceavail(struct bootops *bop, char *name)
{
	boot_cell_t args[5];
	int	(*bsys_1275_call)(void *) =
	    (int (*)(void *))bop->bsys_1275_call;

	args[0] = boot_ptr2cell("serviceavail");
	args[1] = 1;
	args[2] = 1;

	args[3] = boot_ptr2cell(name);
	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[4]));
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
bop_fstat(struct bootops *bop, int fd, struct bootstat *st)
{
	boot_cell_t args[6];
	int	(*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("fstat");
	args[1] = 2;
	args[2] = 1;
	args[3] = boot_int2cell(fd);
	args[4] = boot_ptr2cell(st);
	(void) (bsys_1275_call)(args);
	return (boot_cell2int(args[5]));
}

/*
 * Implementation of the "enter_mon" boot service.
 *
 * Calling spec:
 * args[0] Service name string
 * args[1] #argument cells (0)
 * args[2] #result cells (0)
 */
void
bop_enter_mon(struct bootops *bop)
{
	boot_cell_t args[4];
	int (*bsys_1275_call)(void *);

	bsys_1275_call = (int (*)(void *))bop->bsys_1275_call;
	args[0] = boot_ptr2cell("enter_mon");
	args[1] = 0;
	args[2] = 0;
	(void) (bsys_1275_call)(args);
}
