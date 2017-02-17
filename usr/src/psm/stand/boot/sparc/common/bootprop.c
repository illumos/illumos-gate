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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/promif.h>
#include <sys/bootconf.h>
#include <sys/salib.h>
#include <sys/boot.h>
#include "boot_plat.h"

char *v2path, *kernname, *systype;
char *my_own_name = "boot";
char v2args_buf[V2ARGS_BUF_SZ];
char *v2args = v2args_buf;
char *mfg_name;
char *impl_arch_name;
char *bootp_response;
char *module_path;
int  cache_state;
uint64_t memlistextent;		/* replacement for old member of bootops */

/*  These are the various memory lists */
struct memlist	*pfreelistp, /* physmem available */
		*vfreelistp, /* virtmem available */
		*pinstalledp;   /* physmem installed */

char *boot_message;

char *netdev_path;

/*
 * Support new boot properties "boot-start" and "boot-end" for
 * Freeze/Thaw project.
 */
caddr_t start_addr, end_addr;

#define	BOOT_BADPROP	-1
#define	BOOT_SUCCESS	0
#define	BOOT_FAILURE	-1
#define	NIL		0

#define	strequal(p, q)	(strcmp((p), (q)) == 0)


/*
 * This routine is used by stand/lib/$PROC/libnfs.a in case it comes up with a
 * default filename, and by bootflags() if a default filename is specified in
 * the boot arguments.
 */
void
set_default_filename(char *filename)
{
	kernname = filename;
}


static const struct bplist {
	char	*name;
	void	*val;
	uint_t	size;
} bprop_tab[] = {
	"boot-args",		&v2args,		0,
	"boot-path",		&v2path,		0,
	"fstype",		&systype,		0,
	"whoami",		&my_own_name,		0,
	"mfg-name",		&mfg_name,		0,
	"impl-arch-name",	&impl_arch_name,	0,
	"module-path",		&module_path,		0,
	"virt-avail",		&vfreelistp,		0,
	"phys-avail",		&pfreelistp,		0,
	"phys-installed",	&pinstalledp,		0,
	"default-name",		&kernname,		0,
	"extent",		&memlistextent,		sizeof (memlistextent),
	"vac",			&vac,			sizeof (vac),
	"cache-on?",		&cache_state,		sizeof (int),
	"memory-update",	0,			0,
	"boot-start",		&start_addr,		sizeof (start_addr),
	"boot-end",		&scratchmemp,		sizeof (scratchmemp),
	"boot-message",		&boot_message,		0,
	"bootp-response",	&bootp_response,	0,
	"netdev-path",		&netdev_path,		0,
	0,			0,			0
};

/*
 *  These routines implement the boot getprop interface.
 *  They are designed to mimic the corresponding devr_{getprop,getproplen}
 *  functions.
 *  The assumptions is that the basic property is an unsigned int.  Other
 *  types (including lists) are special cases.
 */

/*ARGSUSED*/
int
bgetproplen(struct bootops *bop, char *name)
{
	int size = 0;
	struct bplist *p;
	struct memlist *ml;

	/* this prop has side effects only.  No length.  */
	if (strequal(name, "memory-update"))
		return (BOOT_SUCCESS);

	for (p = (struct bplist *)bprop_tab; p->name != (char *)0; p++) {

		/* got a linked list?  */
		if ((strequal(name, "virt-avail") && strequal(name, p->name)) ||
		    (strequal(name, "phys-avail") && strequal(name, p->name)) ||
		    (strequal(name, "phys-installed") &&
		    strequal(name, p->name))) {

			for (ml = *((struct memlist **)p->val);
			    ml != NIL;
			    ml = ml->ml_next)

				/*
				 *  subtract out the ptrs for our local
				 *  linked list.  The application will
				 *  only see an array.
				 */
				size += (int)(sizeof (struct memlist) -
				    2*sizeof (struct memlist *));
			return (size);

		} else if (strequal(name, p->name)) {

			/* if we already know the size, return it */
			if (p->size != 0)
				return (p->size);
			else {
				if (*((char **)p->val) == NIL)
					return (0);	/* NULL is allowed */

				/* don't forget the null termination */
				return (strlen(*((char **)p->val)) + 1);
			}
		}
	}
	return (BOOT_BADPROP);
}

/*ARGSUSED*/
int
bgetprop(struct bootops *bop, char *name, void *buf)
{
	struct bplist *p;
	struct memlist *ml;

	if (strequal(name, "memory-update")) {
/*
 *		dprintf("bgetprop:  updating memlists.\n");
 */
		update_memlist("virtual-memory", "available", &vfreelistp);
		update_memlist("memory", "available", &pfreelistp);
		return (BOOT_SUCCESS);
	}

	if (strequal(name, "boot-start")) {
		start_addr = (caddr_t)_start;
		bcopy((char *)(&start_addr), buf, sizeof (start_addr));
		return (BOOT_SUCCESS);
	}

	if (strequal(name, "boot-end")) {
		/*
		 * The true end of boot should be scratchmemp,
		 * boot gets its dynamic memory from the scratchmem
		 * which is the first 4M of the physical memory,
		 * and they are mapped 1:1.
		 */
		end_addr = scratchmemp;
		bcopy((char *)(&end_addr), buf, sizeof (scratchmemp));
		return (BOOT_SUCCESS);
	}

	for (p = (struct bplist *)bprop_tab; p->name != (char *)0; p++) {

		/* gotta linked list? */
		if ((strequal(name, "virt-avail") && strequal(name, p->name)) ||
		    (strequal(name, "phys-avail") && strequal(name, p->name)) ||
		    (strequal(name, "phys-installed") &&
		    strequal(name, p->name))) {

			u_longlong_t *t = buf;

			for (ml = *((struct memlist **)p->val);
			    ml != NIL;
			    ml = ml->ml_next) {

				/* copy out into an array */
				*t++ = ml->ml_address;
				*t++ = ml->ml_size;
			}
			return (BOOT_SUCCESS);
		} else if (strequal(name, p->name)) {
			if (p->size != 0) {
				bcopy(p->val, buf, p->size);
			} else {
				(void) strcpy((char *)buf, *((char **)p->val));
			}
			return (BOOT_SUCCESS);
		}
	}
	return (BOOT_FAILURE);
}

/*
 *  If the user wants the first property in the list, they pass in a
 *  null string.  The routine will always return a ptr to the name of the
 *  next prop, except when there are no more props.  In that case, it will
 *  return a null string.
 */

/*ARGSUSED*/
char *
bnextprop(struct bootops *bop, char *prev)
{
	struct bplist *p;

	/* user wants the firstprop */
	if (*prev == 0)
		return (bprop_tab->name);

	for (p = (struct bplist *)bprop_tab; p->name != (char *)0; p++) {

		if (strequal(prev, p->name))
			/*
			 * if prev is the last valid prop,
			 * we will return our terminator (0).
			 */
			return ((++p)->name);


	}
	return ((char *)0);
}
