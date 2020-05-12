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

/*
 * PROM interface
 */

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define	_KERNEL
#define	_BOOT
#include <sys/promif.h>
#undef _BOOT
#undef _KERNEL

#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <kmdb/kmdb_promif_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb.h>

#ifndef sun4v
int kmdb_prom_preserve_kctx = 0;
#endif /* sun4v */

ssize_t
kmdb_prom_obp_writer(caddr_t buf, size_t len)
{
	return (prom_write(prom_stdout_ihandle(), buf, len, 0, 0));
}

ihandle_t
kmdb_prom_get_handle(char *name)
{
	if (strcmp(name, "stdin") == 0)
		return (prom_stdin_ihandle());
	else if (strcmp(name, "stdout") == 0 || strcmp(name, "stderr") == 0)
		return (prom_stdout_ihandle());
	else
		return (-1);
}

/*ARGSUSED*/
char *
kmdb_prom_get_ddi_prop(kmdb_auxv_t *kav, char *propname)
{
	pnode_t node;
	ssize_t len;
	char *val;

	if ((node = prom_finddevice("/options")) == 0)
		return (NULL);

	if ((len = prom_getproplen(node, propname)) < 0)
		return (NULL);

	val = mdb_alloc(len + 1, UM_SLEEP);

	if (prom_bounded_getprop(node, propname, val, len) != len) {
		mdb_free(val, len);
		return (NULL);
	}
	val[len] = '\0';

	return (val);
}

void
kmdb_prom_free_ddi_prop(char *val)
{
	strfree(val);
}

int
kmdb_prom_getprop(pnode_t node, char *name, caddr_t value)
{
	return (prom_getprop(node, name, value));
}

/*ARGSUSED*/
void
kmdb_prom_get_tem_size(kmdb_auxv_t *kav, ushort_t *rows, ushort_t *cols)
{
	/* We fall back to defaults for now. */
}

typedef struct walk_cpu_data {
	int (*wcd_cb)(pnode_t, void *, void *);
	void *wcd_arg;
} walk_cpu_data_t;

static int
walk_cpus_cb(pnode_t node, void *arg, void *result)
{
	walk_cpu_data_t *wcd = arg;

	/*
	 * Sun4v doesn't support port_id on guest.
	 */
#ifndef	sun4v
	int port_id;
#endif	/* sun4v */

	if (!prom_devicetype(node, OBP_CPU))
		return (PROM_WALK_CONTINUE);

#ifndef	sun4v
	if ((prom_getprop(node, "portid", (caddr_t)&port_id) == -1) &&
	    (prom_getprop(node, "upa-portid", (caddr_t)&port_id) == -1) &&
	    (prom_getprop(node, "cpuid", (caddr_t)&port_id) == -1)) {
		warn("cpu node %x has no identifying properties\n",
		    node);
		return (PROM_WALK_CONTINUE);
	}
#endif	/* sun4v */

	if (wcd->wcd_cb(node, wcd->wcd_arg, result) != 0)
		return (PROM_WALK_TERMINATE);

	return (PROM_WALK_CONTINUE);
}

void
kmdb_prom_walk_cpus(int (*cb)(pnode_t, void *, void *), void *arg, void *result)
{
	walk_cpu_data_t wcd;

	wcd.wcd_cb = cb;
	wcd.wcd_arg = arg;

	prom_walk_devs(prom_rootnode(), walk_cpus_cb, &wcd, result);
}

void
kmdb_prom_enter_mon(void)
{
	prom_enter_mon();
}

#ifndef	sun4v
pnode_t
kmdb_prom_getcpu_propnode(pnode_t node)
{
	int val;
	pnode_t pnode;
	char name[OBP_MAXPROPNAME];


	/*
	 * Check for the CMT case where cpu nodes are "strand" nodes
	 * In this case, the "cpu node" properties are contained in
	 * its parent "core" node.
	 */
	if (prom_getprop(node, "portid", (caddr_t)&val) == -1 &&
	    prom_getprop(node, "upa-portid", (caddr_t)&val) == -1 &&
	    prom_getprop((pnode = prom_parentnode(node)), "name", name) != -1 &&
	    strcmp(name, "core") == 0)
		return (pnode);

	return (node);
}
#endif	/* sun4v */

void
kmdb_prom_exit_to_mon(void)
{
	prom_exit_to_mon();
}

void
kmdb_prom_interpret(const char *str)
{
	prom_interpret((char *)str, 0, 0, 0, 0, 0);
}

/*ARGSUSED*/
int
kmdb_prom_translate_virt(uintptr_t virt, physaddr_t *pap)
{
	extern int prom_translate_virt(caddr_t, int *, u_longlong_t *, int *);

	int valid, mode;
	uintptr_t vabase = virt & ~(mdb.m_pagesize - 1);
	uintptr_t off = virt - vabase;
	u_longlong_t pa;

	mdb_dprintf(MDB_DBG_DPI, "using OBP for vtop of %p\n", (void *)virt);

	if (prom_translate_virt((caddr_t)vabase, &valid, &pa, &mode) != 0)
		return (set_errno(EMDB_NOMAP));

	*pap = pa + off;
	return (0);
}

/*ARGSUSED*/
int
kmdb_prom_stdout_is_framebuffer(kmdb_auxv_t *kav)
{
	return (prom_stdout_is_framebuffer());
}

#ifndef sun4v
#define	PROM_KCTX_PRESERVED_PROPNAME	"context0-page-size-preserved"
void
kmdb_prom_preserve_kctx_init(void)
{
	pnode_t	pnode;
	int	val;

	pnode = (pnode_t)prom_getphandle(prom_mmu_ihandle());
	if (prom_getprop(pnode, PROM_KCTX_PRESERVED_PROPNAME,
	    (caddr_t)&val) == 0) {
		kmdb_prom_preserve_kctx = 1;
	}
}
#endif /* sun4v */
