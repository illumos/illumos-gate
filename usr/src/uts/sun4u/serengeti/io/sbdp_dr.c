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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/autoconf.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/promif.h>
#include <sys/conf.h>
#include <sys/obpdefs.h>
#include <sys/sgsbbc_mailbox.h>
#include <sys/cpuvar.h>
#include <vm/seg_kmem.h>
#include <sys/prom_plat.h>
#include <sys/machsystm.h>
#include <sys/cheetahregs.h>

#include <sys/sbd_ioctl.h>
#include <sys/sbd.h>
#include <sys/sbdp_priv.h>

static int sbdp_detach_nodes(attach_pkt_t *);
static void
sbdp_walk_prom_tree_worker(
	pnode_t node,
	int(*f)(pnode_t, void *, uint_t),
	void *arg)
{
	/*
	 * Ignore return value from callback. Return value from callback
	 * does NOT indicate subsequent walk behavior.
	 */
	(void) (*f)(node, arg, 0);

	if (node != OBP_NONODE) {
		sbdp_walk_prom_tree_worker(prom_childnode(node), f, arg);
		sbdp_walk_prom_tree_worker(prom_nextnode(node), f, arg);
	}
}

struct sbdp_walk_prom_tree_args {
	pnode_t	node;
	int	(*f)(pnode_t, void *, uint_t);
	void	*arg;
};

/*ARGSUSED*/
static int
sbdp_walk_prom_tree_start(void *arg, int has_changed)
{
	struct sbdp_walk_prom_tree_args *argbp = arg;

	sbdp_walk_prom_tree_worker(argbp->node, argbp->f, argbp->arg);
	return (0);
}

void
sbdp_walk_prom_tree(pnode_t node, int(*f)(pnode_t, void *, uint_t), void *arg)
{
	struct sbdp_walk_prom_tree_args arg_block;

	arg_block.node = node;
	arg_block.f = f;
	arg_block.arg = arg;
	(void) prom_tree_access(sbdp_walk_prom_tree_start, &arg_block, NULL);
}

static void
sbdp_attach_branch(dev_info_t *pdip, pnode_t node, void *arg)
{
	attach_pkt_t	*apktp = (attach_pkt_t *)arg;
	pnode_t		child;
	dev_info_t	*dip = NULL;
	static int	err = 0;
	static int	len = 0;
	char		name[OBP_MAXDRVNAME];
#if OBP_MAXDRVNAME == OBP_MAXPROPNAME
#define	buf	name
#else
	char		buf[OBP_MAXPROPNAME];
#endif
	static fn_t	f = "sbdp_attach_branch";

	SBDP_DBG_FUNC("%s\n", f);

	if (node == OBP_NONODE)
		return;

	/*
	 * Get the status for this node
	 * If it has failed we imitate boot by not creating a node
	 * in solaris. We just warn the user
	 */
	if (check_status(node, buf, pdip) != DDI_SUCCESS) {
		SBDP_DBG_STATE("status failed skipping this node\n");
		return;
	}

	len = prom_getproplen(node, OBP_REG);
	if (len <= 0) {
		return;
	}

	(void) prom_getprop(node, OBP_NAME, (caddr_t)name);
	err = ndi_devi_alloc(pdip, name, node, &dip);
	if (err != NDI_SUCCESS) {
		return;
	}
	SBDP_DBG_STATE("attaching %s\n", name);
	err = ndi_devi_online(dip, NDI_DEVI_BIND);
	if (err != NDI_SUCCESS) {
		(void) ndi_devi_free(dip);
		return;
	}
	child = prom_childnode(node);
	if (child != OBP_NONODE) {
		for (; child != OBP_NONODE;
		    child = prom_nextnode(child)) {
			sbdp_attach_branch(dip, child, (void *)apktp);
		}
	}
#undef buf
}

static int
sbdp_find_ssm_dip(dev_info_t *dip, void *arg)
{
	attach_pkt_t	*apktp;
	int		node;
	static fn_t	f = "sbdp_find_ssm_dip";

	SBDP_DBG_FUNC("%s\n", f);

	apktp = (attach_pkt_t *)arg;

	if (apktp == NULL) {
		SBDP_DBG_STATE("error on the argument\n");
		return (DDI_WALK_CONTINUE);
	}

	if ((node = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "nodeid", -1)) == -1)
		return (DDI_WALK_CONTINUE);

	if (node == apktp->node) {
		ndi_hold_devi(dip);
		apktp->top_node = dip;
		return (DDI_WALK_TERMINATE);
	}
	return (DDI_WALK_CONTINUE);
}

/*ARGSUSED*/
int
sbdp_select_top_nodes(pnode_t node, void *arg, uint_t flags)
{
	int		board, bd;
	attach_pkt_t    *apktp = (attach_pkt_t *)arg;
	char		devtype[OBP_MAXDRVNAME];
	char		devname[OBP_MAXDRVNAME];
	int		i;
	sbd_devattr_t	*sbdp_top_nodes;
	int		wnode;
	static fn_t	f = "sbdp_select_top_nodes";

	SBDP_DBG_FUNC("%s\n", f);

	if (apktp == NULL) {
		SBDP_DBG_STATE("error on the argument\n");
		return (DDI_FAILURE);
	}

	board = apktp->board;
	sbdp_top_nodes = sbdp_get_devattr();

	if (sbdp_get_bd_and_wnode_num(node, &bd, &wnode) < 0)
		return (DDI_FAILURE);

	if (bd != board)
		return (DDI_FAILURE);

	SBDP_DBG_MISC("%s: board is %d\n", f, bd);

	(void) prom_getprop(node, OBP_DEVICETYPE, (caddr_t)devtype);
	(void) prom_getprop(node, OBP_NAME, (caddr_t)devname);

	if (strcmp(devname, "cmp") == 0) {
		apktp->nodes[apktp->num_of_nodes] = node;
		apktp->num_of_nodes++;

		/* We want this node */
		return (DDI_SUCCESS);
	}

	for (i = 0; sbdp_top_nodes[i].s_obp_type != NULL; i++) {
		if (strcmp(devtype, sbdp_top_nodes[i].s_obp_type) == 0) {
			if (strcmp(devtype, "cpu") == 0) {
				int		cpuid;
				int		impl;

				/*
				 * Check the status of the cpu
				 * If it is failed ignore it
				 */
				if (sbdp_get_comp_status(node) != SBD_COND_OK)
					return (DDI_FAILURE);

				if (prom_getprop(node, "cpuid",
				    (caddr_t)&cpuid) == -1) {

					if (prom_getprop(node, "portid",
					    (caddr_t)&cpuid) == -1) {

						return (DDI_WALK_TERMINATE);
					}
				}

				if (sbdp_set_cpu_present(wnode, bd,
				    SG_CPUID_TO_CPU_UNIT(cpuid)) == -1)
					return (DDI_WALK_TERMINATE);

				(void) prom_getprop(node, "implementation#",
				    (caddr_t)&impl);
				/*
				 * If it is a CPU under CMP, don't save
				 * the node as we will be saving the CMP
				 * node.
				 */
				if (CPU_IMPL_IS_CMP(impl))
					return (DDI_FAILURE);
			}

			/*
			 * Check to make sure we haven't run out of bounds
			 */
			if (apktp->num_of_nodes >= SBDP_MAX_NODES)
				return (DDI_FAILURE);

			/* Save node */
			apktp->nodes[apktp->num_of_nodes] = node;
			apktp->num_of_nodes++;

			/* We want this node */
			return (DDI_SUCCESS);
		}
	}

	return (DDI_FAILURE);
}

void
sbdp_attach_bd(int node, int board)
{
	devi_branch_t	b = {0};
	attach_pkt_t    apkt, *apktp = &apkt;
	static fn_t	f = "sbdp_attach_bd";

	SBDP_DBG_FUNC("%s\n", f);

	apktp->node = node;
	apktp->board = board;
	apktp->num_of_nodes = 0;
	apktp->flags = 0;

	apktp->top_node = NULL;

	/*
	 * Root node doesn't have to be held for ddi_walk_devs()
	 */
	ddi_walk_devs(ddi_root_node(), sbdp_find_ssm_dip, (void *) apktp);

	if (apktp->top_node == NULL) {
		SBDP_DBG_STATE("BAD Serengeti\n");
		return;
	}

	b.arg = (void *)apktp;
	b.type = DEVI_BRANCH_PROM;
	b.create.prom_branch_select = sbdp_select_top_nodes;
	b.devi_branch_callback = NULL;

	(void) e_ddi_branch_create(apktp->top_node, &b, NULL, 0);

	/*
	 * Release hold acquired in sbdp_find_ssm_dip()
	 */
	ndi_rele_devi(apktp->top_node);

	sbdp_cpu_in_reset(node, board, SBDP_ALL_CPUS, 1);
}

int
sbdp_detach_bd(int node, int board, sbd_error_t *sep)
{
	int		rv;
	attach_pkt_t	apkt, *apktp = &apkt;
	static fn_t	f = "sbdp_detach_bd";

	SBDP_DBG_FUNC("%s\n", f);

	apktp->node = node;
	apktp->board = board;
	apktp->num_of_nodes = 0;
	apktp->error = 0;
	apktp->errstr = NULL;
	sbdp_walk_prom_tree(prom_rootnode(), sbdp_select_top_nodes,
	    (void *) apktp);

	if (rv = sbdp_detach_nodes(apktp)) {
		sbdp_set_err(sep, ESBD_IO, NULL);
		return (rv);
	}

	sbdp_cpu_in_reset(node, board, SBDP_ALL_CPUS, 1);
	/*
	 * Clean up this board struct
	 */
	sbdp_cleanup_bd(node, board);

	return (0);
}

static int
sbdp_detach_nodes(attach_pkt_t *apktp)
{
	dev_info_t	**dip;
	dev_info_t	**dev_list;
	int		dev_list_len = 0;
	int		i, rv = 0;

	dev_list =  kmem_zalloc(sizeof (dev_info_t *) * SBDP_MAX_NODES,
	    KM_SLEEP);

	for (i = 0, dip = dev_list; i < apktp->num_of_nodes; i++) {
		*dip = e_ddi_nodeid_to_dip(apktp->nodes[i]);
		if (*dip != NULL) {
			/*
			 * The branch rooted at dip should already be held,
			 * so release hold acquired in e_ddi_nodeid_to_dip()
			 */
			ddi_release_devi(*dip);
			dip++;
			++dev_list_len;
		}
	}

	for (i = dev_list_len, dip = &dev_list[i - 1]; i > 0; i--, dip--) {
		dev_info_t	*fdip = NULL;

		ASSERT(e_ddi_branch_held(*dip));
		rv = e_ddi_branch_destroy(*dip, &fdip, 0);
		if (rv) {
			char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

			/*
			 * If non-NULL, fdip is held and must be released.
			 */
			if (fdip != NULL) {
				(void) ddi_pathname(fdip, path);
				ddi_release_devi(fdip);
			} else {
				(void) ddi_pathname(*dip, path);
			}

			cmn_err(CE_WARN, "failed to remove node %s (%p): %d",
			    path, fdip ? (void *)fdip : (void *)*dip, rv);

			kmem_free(path, MAXPATHLEN);

			apktp->error = apktp->error ? apktp->error : rv;
			break;
		}
	}

	kmem_free(dev_list, sizeof (dev_info_t *) * SBDP_MAX_NODES);

	return (rv);
}
