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
 */
/*
 * Copyright 2019 Peter Tribble.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/salib.h>

extern int is_sun4v;

/*
 * Check if the CPU should default to 64-bit or not.
 * UltraSPARC-1's default to 32-bit mode.
 * Everything else defaults to 64-bit mode.
 */

/*
 * Manufacturer codes for the CPUs we're interested in
 */
#define	TI_JEDEC	0x17
#define	SUNW_JEDEC	0x22

/*
 * Implementation codes for the CPUs we're interested in
 */
#define	IMPL_US_I	0x10

static pnode_t
visit(pnode_t node)
{
	int impl, manu;
	char name[32];
	static char ultrasparc[] = "SUNW,UltraSPARC";
	static char implementation[] = "implementation#";
	static char manufacturer[] = "manufacturer#";

	/*
	 * if name isn't 'SUNW,UltraSPARC', continue.
	 */
	if (prom_getproplen(node, "name") != sizeof (ultrasparc))
		return ((pnode_t)0);
	(void) prom_getprop(node, "name", name);
	if (strncmp(name, ultrasparc, sizeof (ultrasparc)) != 0)
		return ((pnode_t)0);

	if (prom_getproplen(node, manufacturer) != sizeof (int))
		return ((pnode_t)0);
	(void) prom_getprop(node, manufacturer, (caddr_t)&manu);

	if ((manu != SUNW_JEDEC) && (manu != TI_JEDEC))
		return ((pnode_t)0);

	if (prom_getproplen(node, implementation) != sizeof (int))
		return ((pnode_t)0);
	(void) prom_getprop(node, implementation, (caddr_t)&impl);

	if (impl != IMPL_US_I)
		return ((pnode_t)0);

	return (node);
}

/*
 * visit each node in the device tree, until we get a non-null answer
 */
static pnode_t
walk(pnode_t node)
{
	pnode_t id;

	if (visit(node))
		return (node);

	for (node = prom_childnode(node); node; node = prom_nextnode(node))
		if ((id = walk(node)) != (pnode_t)0)
			return (id);

	return ((pnode_t)0);
}

/*
 * Check if the CPU is an UltraSPARC-1 or not.
 */
int
cpu_is_ultrasparc_1(void)
{
	static int cpu_checked;
	static int cpu_default;

	/*
	 * If we already checked or the machine is
	 * a sun4v, we already know the answer.
	 */
	if (!is_sun4v || cpu_checked == 0) {
		if (walk(prom_rootnode()))
			cpu_default = 1;
		cpu_checked = 1;
	}

	return (cpu_default);
}

/*
 * Retain a page or reclaim a previously retained page of physical
 * memory for use by the prom upgrade. If successful, leave
 * an indication that a page was retained by creating a boolean
 * property in the root node.
 *
 * XXX: SUNW,retain doesn't work as expected on server systems,
 * so we don't try to retain any memory on those systems.
 *
 * XXX: do a '0 to my-self' as a workaround for 4160914
 */

int dont_retain_memory;

void
retain_nvram_page(void)
{
	unsigned long long phys = 0;
	int len;
	char name[32];
	static char create_prop[] =
	    "0 to my-self dev / 0 0 \" boot-retained-page\" property";
	static char ue[] = "SUNW,Ultra-Enterprise";
	extern int verbosemode;

	if (dont_retain_memory)
		return;

	if (!is_sun4v) {
		len = prom_getproplen(prom_rootnode(), "name");
		if ((len != -1) && (len <= sizeof (name))) {
			(void) prom_getprop(prom_rootnode(), "name", name);
			if (strcmp(name, ue) == 0)
				return;
		}
	}

	if (prom_retain("OBPnvram", PAGESIZE, PAGESIZE, &phys) != 0) {
		printf("prom_retain failed\n");
		return;
	}
	if (verbosemode)
		printf("retained OBPnvram page at 0x%llx\n", phys);

	prom_interpret(create_prop, 0, 0, 0, 0, 0);
}
