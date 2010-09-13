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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * Test for existance of a specific P1275 client interface service
 */
int
prom_test(char *service)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("test");		/* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_ptr2cell(service);	/* Arg1: requested svc name */
	ci[4] = (cell_t)-1;			/* Res1: Prime result */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2int(ci[4]));		/* Res1: missing flag */
}

int
prom_test_method(char *method, pnode_t node)
{
	cell_t ci[6];
	int rv;
	char buf[80];

	if (prom_test("test-method") == 0) {
		ci[0] = p1275_ptr2cell("test-method");	/* service */
		ci[1] = (cell_t)2;			/* #argument cells */
		ci[2] = (cell_t)1;			/* #result cells */
		ci[3] = p1275_dnode2cell(node);
		ci[4] = p1275_ptr2cell(method);
		ci[5] = (cell_t)-1;

		promif_preprom();
		(void) p1275_cif_handler(&ci);
		promif_postprom();
		rv = p1275_cell2int(ci[5]);
	} else {
		(void) prom_sprintf(buf,
		    "\" %s\" h# %x find-method invert h# %p l!",
		    method, node, (void *)&rv);
		prom_interpret(buf, 0, 0, 0, 0, 0);
	}
	return (rv);
}
