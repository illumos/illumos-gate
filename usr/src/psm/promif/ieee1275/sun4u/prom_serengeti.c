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

#include <sys/promif.h>
#include <sys/promimpl.h>

/* All Serengeti only promif routines */

char *
prom_serengeti_set_console_input(char *new_value)
{
	cell_t ci[5];
	int rv;

	ci[0] = p1275_ptr2cell("SUNW,set-console-input");
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #return cells */
	ci[3] = p1275_ptr2cell(new_value);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (NULL);

	return (p1275_cell2ptr(ci[4]));
}

/*
 * These interfaces allow the client to attach/detach board.
 */
int
prom_serengeti_attach_board(uint_t node, uint_t board)
{
	cell_t ci[6];
	int rv;

	ci[0] = p1275_ptr2cell("SUNW,Serengeti,add-board");	/* name */
	ci[1] = (cell_t)2;				/* #argument cells */
	ci[2] = (cell_t)1;				/* #result cells */
	ci[3] = p1275_uint2cell(board);
	ci[4] = p1275_uint2cell(node);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (rv);
	if (p1275_cell2int(ci[5]) != 0)			/* Res1: Catch result */
		return (-1);

	return (0);
}

int
prom_serengeti_detach_board(uint_t node, uint_t board)
{
	cell_t ci[6];
	int rv;

	ci[0] = p1275_ptr2cell("SUNW,Serengeti,remove-board");	/* name */
	ci[1] = (cell_t)2;				/* #argument cells */
	ci[2] = (cell_t)1;				/* #result cells */
	ci[3] = p1275_uint2cell(board);
	ci[4] = p1275_uint2cell(node);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (rv);
	if (p1275_cell2int(ci[5]) != 0)			/* Res1: Catch result */
		return (-1);

	return (0);
}

int
prom_serengeti_tunnel_switch(uint_t node, uint_t board)
{
	cell_t ci[6];
	int rv;

	ci[0] = p1275_ptr2cell("SUNW,Serengeti,switch-tunnel");	/* name */
	ci[1] = (cell_t)2;				/* #argument cells */
	ci[2] = (cell_t)1;				/* #result cells */
	ci[3] = p1275_uint2cell(board);
	ci[4] = p1275_uint2cell(node);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (rv);
	if (p1275_cell2int(ci[5]) != 0)			/* Res1: Catch result */
		return (-1);

	return (0);
}

int
prom_serengeti_cpu_off(pnode_t node)
{
	cell_t ci[5];
	int rv;

	ci[0] = p1275_ptr2cell("SUNW,Serengeti,park-cpu");
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #return cells */
	ci[3] = p1275_dnode2cell(node);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (-1);

	return (p1275_cell2int(ci[4]));
}

/*
 * This service converts the given physical address into a text string,
 * representing the name of the field-replacable part for the given
 * physical address. In other words, it tells the kernel which ecache
 * module got the (un)correctable ECC error.
 */
int
prom_serengeti_get_ecacheunum(int cpuid, unsigned long long physaddr, char *buf,
		uint_t buflen, int *ustrlen)
{
	cell_t ci[12];
	int rv;
	ihandle_t imemory = prom_memory_ihandle();

	*ustrlen = -1;
	if ((imemory == (ihandle_t)-1))
		return (-1);

	if (prom_test_method("SUNW,Serengeti,get-ecache-unum",
	    prom_getphandle(imemory)) != 0)
		return (-1);

	ci[0] = p1275_ptr2cell("call-method");		/* Service name */
	ci[1] = (cell_t)7;				/* #argument cells */
	ci[2] = (cell_t)2;				/* #result cells */
	ci[3] = p1275_ptr2cell("SUNW,Serengeti,get-ecache-unum");
							/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(imemory);		/* Arg2: mem. ihandle */
	ci[5] = p1275_uint2cell(buflen);		/* Arg3: buflen */
	ci[6] = p1275_ptr2cell(buf);			/* Arg4: buf */
	ci[7] = p1275_ull2cell_high(physaddr);		/* Arg5: physhi */
	ci[8] = p1275_ull2cell_low(physaddr);		/* Arg6: physlo */
	ci[9] = p1275_int2cell(cpuid);			/* Arg7: cpuid */
	ci[10] = (cell_t)-1;				/* ret1: catch result */
	ci[11] = (cell_t)-1;				/* ret2: length */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (rv);
	if (p1275_cell2int(ci[10]) != 0)	/* Res1: catch result */
		return (-1);	/* "SUNW,Serengeti,get-ecache-unum" failed */
	*ustrlen = p1275_cell2uint(ci[11]);	/* Res2: unum str length */
	return (0);
}

int
prom_serengeti_wakeupcpu(pnode_t node)
{
	cell_t ci[5];
	int	rv;

	ci[0] = p1275_ptr2cell("SUNW,Serengeti,wakeup-cpu"); /* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_dnode2cell(node);		/* Arg1: nodeid to wakeup */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (rv);
	else
		return (p1275_cell2int(ci[4])); /* Res1: Catch result */
}
