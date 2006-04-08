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
#include <sys/fcntl.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/salib.h>

int pagesize = PAGESIZE;

void
fiximp(void)
{
	extern int use_align;

	use_align = 1;
}

void
setup_aux(void)
{
	pnode_t node;
	/* big enough for OBP_NAME and for a reasonably sized OBP_COMPATIBLE. */
	static char cpubuf[5 * OBP_MAXDRVNAME];
	char dname[OBP_MAXDRVNAME];
	extern uint_t icache_flush;
	extern char *cpulist;

	icache_flush = 1;
	node = prom_findnode_bydevtype(prom_rootnode(), OBP_CPU);
	if (node != OBP_NONODE && node != OBP_BADNODE) {
		int nlen, clen, i;

		if ((nlen = prom_getproplen(node, OBP_NAME)) <= 0 ||
		    nlen > sizeof (cpubuf) ||
		    prom_getprop(node, OBP_NAME, cpubuf) <= 0)
			prom_panic("no name in cpu node");

		/* nlen includes the terminating null character */

		/*
		 * For the CMT case, need check the parent "core"
		 * node for the compatible property.
		 */
		if ((clen = prom_getproplen(node, OBP_COMPATIBLE)) > 0 ||
		    ((node = prom_parentnode(node)) != OBP_NONODE &&
		    node != OBP_BADNODE &&
		    (clen = prom_getproplen(node, OBP_COMPATIBLE)) > 0 &&
		    prom_getprop(node, OBP_DEVICETYPE, dname) > 0 &&
		    strcmp(dname, "core") == 0)) {
			if ((clen + nlen) > sizeof (cpubuf))
				prom_panic("cpu node \"compatible\" too long");
			/* read in compatible, leaving space for ':' */
			if (prom_getprop(node, OBP_COMPATIBLE,
			    &cpubuf[nlen]) != clen)
				prom_panic("cpu node \"compatible\" error");
			clen += nlen;	/* total length */
			/* convert all null characters to ':' */
			clen--;	/* except the final one... */
			for (i = 0; i < clen; i++)
				if (cpubuf[i] == '\0')
					cpubuf[i] = ':';
		}
		cpulist = cpubuf;
	} else
		prom_panic("no cpu node");
}


#ifdef MPSAS

void sas_symtab(int start, int end);
extern int sas_command(char *cmdstr);

/*
 * SAS support - inform SAS of new symbols being dynamically added
 * during simulation via the first standalone.
 */

#ifndef	BUFSIZ
#define	BUFSIZ	1024		/* for cmd string buffer allocation */
#endif

int	sas_symdebug = 0;		/* SAS support */

void
sas_symtab(int start, int end)
{
	char *addstr = "symtab add $LD_KERNEL_PATH/%s%s 0x%x 0x%x\n";
	char *file, *prefix, cmdstr[BUFSIZ];
	extern char filename[];

	file = filename;
	prefix = *file == '/' ? "../../.." : "";

	(void) sprintf(cmdstr, addstr, prefix, file, start, end);

	/* add the symbol table */
	if (sas_symdebug) (void) printf("sas_symtab: %s", cmdstr);
	sas_command(cmdstr);
}

void
sas_bpts()
{
	sas_command("file $KERN_SCRIPT_FILE\n");
}
#endif	/* MPSAS */

/*
 * Allocate a region of virtual address space, unmapped.
 */
caddr_t
resalloc_virt(caddr_t virt, size_t size)
{
	if (prom_claim_virt(size, virt) == (caddr_t)-1)
		return ((caddr_t)0);

	return (virt);
}
