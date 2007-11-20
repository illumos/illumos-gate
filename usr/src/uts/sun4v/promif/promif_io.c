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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif_impl.h>
#include <sys/systm.h>
#include <sys/hypervisor_api.h>
#ifndef _KMDB
#include <sys/kmem.h>
#endif

#define	PROM_REG_TO_UNIT_ADDR(r)	((r) & ~(0xful << 28))

static pnode_t instance_to_package(ihandle_t ih);

/* cached copies of IO params */
static phandle_t pstdin;
static phandle_t pstdout;

static ihandle_t istdin;
static ihandle_t istdout;

int
promif_instance_to_package(void *p)
{
	cell_t		*ci = (cell_t *)p;
	ihandle_t	ih;
	phandle_t	ph;

	ih = p1275_cell2ihandle(ci[3]);

	ph = instance_to_package(ih);

	ci[4] = p1275_phandle2cell(ph);

	return (0);
}

int
promif_write(void *p)
{
	cell_t	*ci = (cell_t *)p;
	uint_t	fd;
	char	*buf;
	size_t	len;
	size_t	rlen;

	ASSERT(ci[1] == 3);

	fd  = p1275_cell2uint(ci[3]);
	buf = p1275_cell2ptr(ci[4]);
	len = p1275_cell2size(ci[5]);

	/* only support stdout (console) */
	ASSERT(fd == istdout);

	for (rlen = 0; rlen < len; rlen++) {
		while (hv_cnputchar((uint8_t)buf[rlen]) == H_EWOULDBLOCK)
			/* try forever */;
	}

	/* return the length written */
	ci[6] = p1275_size2cell(rlen);

	return (0);
}

int
promif_read(void *p)
{
	cell_t	*ci = (cell_t *)p;
	uint_t	fd;
	char	*buf;
	size_t	len;
	size_t	rlen;

	ASSERT(ci[1] == 3);

	/* unpack arguments */
	fd  = p1275_cell2uint(ci[3]);
	buf = p1275_cell2ptr(ci[4]);
	len = p1275_cell2size(ci[5]);

	/* only support stdin (console) */
	ASSERT(fd == istdin);

	for (rlen = 0; rlen < len; rlen++) {
		if (hv_cngetchar((uint8_t *)&buf[rlen]) != H_EOK)
			break;
	}

	/* return the length read */
	ci[6] = p1275_size2cell(rlen);

	return (0);
}

static pnode_t
instance_to_package(ihandle_t ih)
{
	/* only support stdin and stdout */
	ASSERT((ih == istdin) || (ih == istdout));

	if (ih == istdin)
		return (pstdin);

	if (ih == istdout)
		return (pstdout);

	return (OBP_BADNODE);
}

#ifdef _KMDB

void
promif_io_init(ihandle_t in, ihandle_t out, phandle_t pin, phandle_t pout)
{
	istdin = in;
	istdout = out;
	pstdin = pin;
	pstdout = pout;
}

#else

void
promif_io_init(void)
{
	/*
	 * Cache the mapping between the stdin and stdout
	 * ihandles and their respective phandles.
	 */
	pstdin = prom_stdin_node();
	pstdout = prom_stdout_node();

	istdin = prom_stdin_ihandle();
	istdout = prom_stdout_ihandle();
}

int
promif_instance_to_path(void *p)
{
	cell_t		*ci = (cell_t *)p;
	pnode_t		node;
	ihandle_t	ih;
	char		*buf;
	int		rlen;
	char		*regval;
	uint_t		*csaddr;
	char		name[OBP_MAXPROPNAME];
	char		scratch[OBP_MAXPATHLEN];
	int		rvlen;

	ih = p1275_cell2ihandle(ci[3]);
	buf = p1275_cell2ptr(ci[4]);

	ci[6] = p1275_uint2cell(0);

	node = instance_to_package(ih);

	*buf = '\0';

	while (node != prom_rootnode()) {
		if (prom_getprop(node, OBP_NAME, name) == -1) {
			prom_printf("instance_to_path: no name property "
			    "node=0x%x\n", node);
			return (-1);
		}

		/* construct the unit address from the 'reg' property */
		if ((rlen = prom_getproplen(node, OBP_REG)) == -1)
			return (-1);

		/*
		 * Make sure we don't get dispatched onto a different
		 * cpu if we happen to sleep.  See kern_postprom().
		 */
		thread_affinity_set(curthread, CPU_CURRENT);
		regval = kmem_zalloc(rlen, KM_SLEEP);
		thread_affinity_clear(curthread);

		(void) prom_getprop(node, OBP_REG, regval);

		csaddr = (uint_t *)regval;

		(void) prom_sprintf(scratch, "/%s@%lx%s", name,
		    PROM_REG_TO_UNIT_ADDR(*csaddr), buf);

		kmem_free(regval, rlen);

		(void) prom_strcpy(buf, scratch);

		node = prom_parentnode(node);
	}

	rvlen = prom_strlen(buf);
	ci[6] = p1275_uint2cell(rvlen);

	return (0);
}

#endif	/* _KMDB */
