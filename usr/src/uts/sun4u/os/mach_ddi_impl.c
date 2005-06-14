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
 * sun4u specific DDI implementation
 */
#include <sys/bootconf.h>
#include <sys/conf.h>
#include <sys/ddi_subrdefs.h>
#include <sys/ethernet.h>
#include <sys/idprom.h>
#include <sys/machsystm.h>
#include <sys/modhash.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/sunndi.h>
#include <sys/systeminfo.h>
#include <sys/fpu/fpusystm.h>
#include <sys/vm.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/snode.h>

/*
 * Favored drivers of this implementation
 * architecture.  These drivers MUST be present for
 * the system to boot at all.
 */
char *impl_module_list[] = {
	"rootnex",
	"options",
	"sad",		/* Referenced via init_tbl[] */
	"pseudo",
	"clone",
	"scsi_vhci",
	(char *)0
};

/*
 * These strings passed to not_serviced in locore.s
 */
const char busname_ovec[] = "onboard ";
const char busname_svec[] = "SBus ";
const char busname_vec[] = "";


static uint64_t *intr_map_reg[32];

/*
 * Forward declarations
 */
static int getlongprop_buf();
static int get_boardnum(int nid, dev_info_t *par);

/*
 * Check the status of the device node passed as an argument.
 *
 *	if ((status is OKAY) || (status is DISABLED))
 *		return DDI_SUCCESS
 *	else
 *		print a warning and return DDI_FAILURE
 */
/*ARGSUSED*/
int
check_status(int id, char *buf, dev_info_t *parent)
{
	char status_buf[64];
	char devtype_buf[OBP_MAXPROPNAME];
	char board_buf[32];
	char path[OBP_MAXPATHLEN];
	int boardnum;
	int retval = DDI_FAILURE;
	extern int status_okay(int, char *, int);

	/*
	 * is the status okay?
	 */
	if (status_okay(id, status_buf, sizeof (status_buf)))
		return (DDI_SUCCESS);

	/*
	 * a status property indicating bad memory will be associated
	 * with a node which has a "device_type" property with a value of
	 * "memory-controller". in this situation, return DDI_SUCCESS
	 */
	if (getlongprop_buf(id, OBP_DEVICETYPE, devtype_buf,
	    sizeof (devtype_buf)) > 0) {
		if (strcmp(devtype_buf, "memory-controller") == 0)
			retval = DDI_SUCCESS;
	}

	/*
	 * get the full OBP pathname of this node
	 */
	if (prom_phandle_to_path((phandle_t)id, path, sizeof (path)) < 0)
		cmn_err(CE_WARN, "prom_phandle_to_path(%d) failed", id);

	/*
	 * get the board number, if one exists
	 */
	if ((boardnum = get_boardnum(id, parent)) >= 0)
		(void) sprintf(board_buf, " on board %d", boardnum);
	else
		board_buf[0] = '\0';

	/*
	 * print the status property information
	 */
	cmn_err(CE_WARN, "status '%s' for '%s'%s",
		status_buf, path, board_buf);
	return (retval);
}

/*
 * determine the board number associated with this nodeid
 */
static int
get_boardnum(int nid, dev_info_t *par)
{
	int board_num;

	if (prom_getprop((dnode_t)nid, OBP_BOARDNUM,
	    (caddr_t)&board_num) != -1)
		return (board_num);

	/*
	 * Look at current node and up the parent chain
	 * till we find a node with an OBP_BOARDNUM.
	 */
	while (par) {
		nid = ddi_get_nodeid(par);

		if (prom_getprop((dnode_t)nid, OBP_BOARDNUM,
		    (caddr_t)&board_num) != -1)
			return (board_num);

		par = ddi_get_parent(par);
	}
	return (-1);
}

/*
 * Note that this routine does not take into account the endianness
 * of the host or the device (or PROM) when retrieving properties.
 */
static int
getlongprop_buf(int id, char *name, char *buf, int maxlen)
{
	int size;

	size = prom_getproplen((dnode_t)id, name);
	if (size <= 0 || (size > maxlen - 1))
		return (-1);

	if (-1 == prom_getprop((dnode_t)id, name, buf))
		return (-1);

	/*
	 * Workaround for bugid 1085575 - OBP may return a "name" property
	 * without null terminating the string with '\0'.  When this occurs,
	 * append a '\0' and return (size + 1).
	 */
	if (strcmp("name", name) == 0) {
		if (buf[size - 1] != '\0') {
			buf[size] = '\0';
			size += 1;
		}
	}

	return (size);
}

/*
 * Routines to set/get UPA slave only device interrupt mapping registers.
 * set_intr_mapping_reg() is called by the UPA master to register the address
 * of an interrupt mapping register. The upa id is that of the master. If
 * this routine is called on behalf of a slave device, the framework
 * determines the upa id of the slave based on that supplied by the master.
 *
 * get_intr_mapping_reg() is called by the UPA nexus driver on behalf
 * of a child device to get and program the interrupt mapping register of
 * one of it's child nodes.  It uses the upa id of the child device to
 * index into a table of mapping registers.  If the routine is called on
 * behalf of a slave device and the mapping register has not been set,
 * the framework determines the devinfo node of the corresponding master
 * nexus which owns the mapping register of the slave and installs that
 * driver.  The device driver which owns the mapping register must call
 * set_intr_mapping_reg() in its attach routine to register the slaves
 * mapping register with the system.
 */
void
set_intr_mapping_reg(int upaid, uint64_t *addr, int slave)
{
	int affin_upaid;

	/* For UPA master devices, set the mapping reg addr and we're done */
	if (slave == 0) {
		intr_map_reg[upaid] = addr;
		return;
	}

	/*
	 * If we get here, we're adding an entry for a UPA slave only device.
	 * The UPA id of the device which has affinity with that requesting,
	 * will be the device with the same UPA id minus the slave number.
	 * If the affin_upaid is negative, silently return to the caller.
	 */
	if ((affin_upaid = upaid - slave) < 0)
		return;

	/*
	 * Load the address of the mapping register in the correct slot
	 * for the slave device.
	 */
	intr_map_reg[affin_upaid] = addr;
}

uint64_t *
get_intr_mapping_reg(int upaid, int slave)
{
	int affin_upaid;
	dev_info_t *affin_dip;
	uint64_t *addr = intr_map_reg[upaid];

	/* If we're a UPA master, or we have a valid mapping register. */
	if (!slave || addr != NULL)
		return (addr);

	/*
	 * We only get here if we're a UPA slave only device whose interrupt
	 * mapping register has not been set.
	 * We need to try and install the nexus whose physical address
	 * space is where the slaves mapping register resides.  They
	 * should call set_intr_mapping_reg() in their xxattach() to register
	 * the mapping register with the system.
	 */

	/*
	 * We don't know if a single- or multi-interrupt proxy is fielding
	 * our UPA slave interrupt, we must check both cases.
	 * Start out by assuming the multi-interrupt case.
	 * We assume that single- and multi- interrupters are not
	 * overlapping in UPA portid space.
	 */

	affin_upaid = upaid | 3;

	/*
	 * We start looking for the multi-interrupter affinity node.
	 * We know it's ONLY a child of the root node since the root
	 * node defines UPA space.
	 */
	for (affin_dip = ddi_get_child(ddi_root_node()); affin_dip;
	    affin_dip = ddi_get_next_sibling(affin_dip))
		if (ddi_prop_get_int(DDI_DEV_T_ANY, affin_dip,
		    DDI_PROP_DONTPASS, "upa-portid", -1) == affin_upaid)
			break;

	if (affin_dip) {
		if (i_ddi_attach_node_hierarchy(affin_dip) == DDI_SUCCESS) {
			/* try again to get the mapping register. */
			addr = intr_map_reg[upaid];
		}
	}

	/*
	 * If we still don't have a mapping register try single -interrupter
	 * case.
	 */
	if (addr == NULL) {

		affin_upaid = upaid | 1;

		for (affin_dip = ddi_get_child(ddi_root_node()); affin_dip;
		    affin_dip = ddi_get_next_sibling(affin_dip))
			if (ddi_prop_get_int(DDI_DEV_T_ANY, affin_dip,
			    DDI_PROP_DONTPASS, "upa-portid", -1) == affin_upaid)
				break;

		if (affin_dip) {
			if (i_ddi_attach_node_hierarchy(affin_dip)
			    == DDI_SUCCESS) {
				/* try again to get the mapping register. */
				addr = intr_map_reg[upaid];
			}
		}
	}
	return (addr);
}


static struct upa_dma_pfns {
	pfn_t hipfn;
	pfn_t lopfn;
} upa_dma_pfn_array[MAX_UPA];

static int upa_dma_pfn_ndx = 0;

/*
 * Certain UPA busses cannot accept dma transactions from any other source
 * except for memory due to livelock conditions in their hardware. (e.g. sbus
 * and PCI). These routines allow devices or busses on the UPA to register
 * a physical address block within it's own register space where DMA can be
 * performed.  Currently, the FFB is the only such device which supports
 * device DMA on the UPA.
 */
void
pf_set_dmacapable(pfn_t hipfn, pfn_t lopfn)
{
	int i = upa_dma_pfn_ndx;

	upa_dma_pfn_ndx++;

	upa_dma_pfn_array[i].hipfn = hipfn;
	upa_dma_pfn_array[i].lopfn = lopfn;
}

void
pf_unset_dmacapable(pfn_t pfn)
{
	int i;

	for (i = 0; i < upa_dma_pfn_ndx; i++) {
		if (pfn <= upa_dma_pfn_array[i].hipfn &&
		    pfn >= upa_dma_pfn_array[i].lopfn) {
			upa_dma_pfn_array[i].hipfn =
			    upa_dma_pfn_array[upa_dma_pfn_ndx - 1].hipfn;
			upa_dma_pfn_array[i].lopfn =
			    upa_dma_pfn_array[upa_dma_pfn_ndx - 1].lopfn;
			upa_dma_pfn_ndx--;
			break;
		}
	}
}

/*
 * This routine should only be called using a pfn that is known to reside
 * in IO space.  The function pf_is_memory() can be used to determine this.
 */
int
pf_is_dmacapable(pfn_t pfn)
{
	int i, j;

	/* If the caller passed in a memory pfn, return true. */
	if (pf_is_memory(pfn))
		return (1);

	for (i = upa_dma_pfn_ndx, j = 0; j < i; j++)
		if (pfn <= upa_dma_pfn_array[j].hipfn &&
		    pfn >= upa_dma_pfn_array[j].lopfn)
			return (1);

	return (0);
}


/*
 * Find cpu_id corresponding to the dip of a CPU device node
 */
int
dip_to_cpu_id(dev_info_t *dip, processorid_t *cpu_id)
{
	dnode_t		nodeid;
	int		i;

	nodeid = (dnode_t)ddi_get_nodeid(dip);
	for (i = 0; i < NCPU; i++) {
		if (cpunodes[i].nodeid == nodeid) {
			*cpu_id = i;
			return (DDI_SUCCESS);
		}
	}
	return (DDI_FAILURE);
}

/*
 * Platform independent DR routines
 */

static int
ndi2errno(int n)
{
	int err = 0;

	switch (n) {
		case NDI_NOMEM:
			err = ENOMEM;
			break;
		case NDI_BUSY:
			err = EBUSY;
			break;
		case NDI_FAULT:
			err = EFAULT;
			break;
		case NDI_FAILURE:
			err = EIO;
			break;
		case NDI_SUCCESS:
			break;
		case NDI_BADHANDLE:
		default:
			err = EINVAL;
			break;
	}
	return (err);
}

/*
 * Prom tree node list
 */
struct ptnode {
	dnode_t		nodeid;
	struct ptnode	*next;
};

/*
 * Prom tree walk arg
 */
struct pta {
	dev_info_t	*pdip;
	devi_branch_t	*bp;
	uint_t		flags;
	dev_info_t	*fdip;
	struct ptnode	*head;
};

static void
visit_node(dnode_t nodeid, struct pta *ap)
{
	struct ptnode	**nextp;
	int		(*select)(dnode_t, void *, uint_t);

	ASSERT(nodeid != OBP_NONODE && nodeid != OBP_BADNODE);

	select = ap->bp->create.prom_branch_select;

	ASSERT(select);

	if (select(nodeid, ap->bp->arg, 0) == DDI_SUCCESS) {

		for (nextp = &ap->head; *nextp; nextp = &(*nextp)->next)
			;

		*nextp = kmem_zalloc(sizeof (struct ptnode), KM_SLEEP);

		(*nextp)->nodeid = nodeid;
	}

	if ((ap->flags & DEVI_BRANCH_CHILD) == DEVI_BRANCH_CHILD)
		return;

	nodeid = prom_childnode(nodeid);
	while (nodeid != OBP_NONODE && nodeid != OBP_BADNODE) {
		visit_node(nodeid, ap);
		nodeid = prom_nextnode(nodeid);
	}
}

/*ARGSUSED*/
static int
set_dip_offline(dev_info_t *dip, void *arg)
{
	ASSERT(dip);

	if (!DEVI_IS_DEVICE_OFFLINE(dip))
		DEVI_SET_DEVICE_OFFLINE(dip);

	return (DDI_WALK_CONTINUE);
}

/*ARGSUSED*/
static int
create_prom_branch(void *arg, int has_changed)
{
	int		circ, c;
	int		exists, rv;
	dnode_t		nodeid;
	struct ptnode	*tnp;
	dev_info_t	*dip;
	struct pta	*ap = arg;
	devi_branch_t	*bp;

	ASSERT(ap);
	ASSERT(ap->fdip == NULL);
	ASSERT(ap->pdip && ndi_dev_is_prom_node(ap->pdip));

	bp = ap->bp;

	nodeid = ddi_get_nodeid(ap->pdip);
	if (nodeid == OBP_NONODE || nodeid == OBP_BADNODE) {
		cmn_err(CE_WARN, "create_prom_branch: invalid "
		    "nodeid: 0x%x", nodeid);
		return (EINVAL);
	}

	ap->head = NULL;

	nodeid = prom_childnode(nodeid);
	while (nodeid != OBP_NONODE && nodeid != OBP_BADNODE) {
		visit_node(nodeid, ap);
		nodeid = prom_nextnode(nodeid);
	}

	if (ap->head == NULL)
		return (ENODEV);

	rv = 0;
	while ((tnp = ap->head) != NULL) {
		ap->head = tnp->next;

		ndi_devi_enter(ap->pdip, &circ);

		/*
		 * Check if the branch already exists.
		 */
		exists = 0;
		dip = e_ddi_nodeid_to_dip(tnp->nodeid);
		if (dip != NULL) {
			exists = 1;

			/* Parent is held busy, so release hold */
			ndi_rele_devi(dip);
#ifdef	DEBUG
			cmn_err(CE_WARN, "create_prom_branch: dip(%p) exists"
			    " for nodeid 0x%x", (void *)dip, tnp->nodeid);
#endif
		} else {
			dip = i_ddi_create_branch(ap->pdip, tnp->nodeid);
		}

		kmem_free(tnp, sizeof (struct ptnode));

		if (dip == NULL) {
			ndi_devi_exit(ap->pdip, circ);
			rv = EIO;
			continue;
		}

		ASSERT(ddi_get_parent(dip) == ap->pdip);

		/*
		 * Hold the branch if it is not already held
		 */
		if (!exists)
			e_ddi_branch_hold(dip);

		ASSERT(e_ddi_branch_held(dip));

		/*
		 * Set all dips in the branch offline so that
		 * only a "configure" operation can attach
		 * the branch
		 */
		(void) set_dip_offline(dip, NULL);

		ndi_devi_enter(dip, &c);
		ddi_walk_devs(ddi_get_child(dip), set_dip_offline, NULL);
		ndi_devi_exit(dip, c);

		ndi_devi_exit(ap->pdip, circ);

		if (ap->flags & DEVI_BRANCH_CONFIGURE) {
			int error = e_ddi_branch_configure(dip, &ap->fdip, 0);
			if (error && rv == 0)
				rv = error;
		}

		/*
		 * Invoke devi_branch_callback() (if it exists) only for
		 * newly created branches
		 */
		if (bp->devi_branch_callback && !exists)
			bp->devi_branch_callback(dip, bp->arg, 0);
	}

	return (rv);
}

static int
sid_node_create(dev_info_t *pdip, devi_branch_t *bp, dev_info_t **rdipp)
{
	int			rv, circ, len;
	int			i, flags;
	dev_info_t		*dip;
	char			*nbuf;
	static const char	*noname = "<none>";

	ASSERT(pdip);
	ASSERT(DEVI_BUSY_OWNED(pdip));

	flags = 0;

	/*
	 * Creating the root of a branch ?
	 */
	if (rdipp) {
		*rdipp = NULL;
		flags = DEVI_BRANCH_ROOT;
	}

	ndi_devi_alloc_sleep(pdip, (char *)noname, DEVI_SID_NODEID, &dip);
	rv = bp->create.sid_branch_create(dip, bp->arg, flags);

	nbuf = kmem_alloc(OBP_MAXDRVNAME, KM_SLEEP);

	if (rv == DDI_WALK_ERROR) {
		cmn_err(CE_WARN, "e_ddi_branch_create: Error setting"
		    " properties on devinfo node %p",  (void *)dip);
		goto fail;
	}

	len = OBP_MAXDRVNAME;
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "name", nbuf, &len)
	    != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "e_ddi_branch_create: devinfo node %p has"
		    "no name property", (void *)dip);
		goto fail;
	}

	ASSERT(i_ddi_node_state(dip) == DS_PROTO);
	if (ndi_devi_set_nodename(dip, nbuf, 0) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "e_ddi_branch_create: cannot set name (%s)"
		    " for devinfo node %p", nbuf, (void *)dip);
		goto fail;
	}

	kmem_free(nbuf, OBP_MAXDRVNAME);

	/*
	 * Ignore bind failures just like boot does
	 */
	(void) ndi_devi_bind_driver(dip, 0);

	switch (rv) {
	case DDI_WALK_CONTINUE:
	case DDI_WALK_PRUNESIB:
		ndi_devi_enter(dip, &circ);

		i = DDI_WALK_CONTINUE;
		for (; i == DDI_WALK_CONTINUE; ) {
			i = sid_node_create(dip, bp, NULL);
		}

		ASSERT(i == DDI_WALK_ERROR || i == DDI_WALK_PRUNESIB);
		if (i == DDI_WALK_ERROR)
			rv = i;
		/*
		 * If PRUNESIB stop creating siblings
		 * of dip's child. Subsequent walk behavior
		 * is determined by rv returned by dip.
		 */

		ndi_devi_exit(dip, circ);
		break;
	case DDI_WALK_TERMINATE:
		/*
		 * Don't create children and ask our parent
		 * to not create siblings either.
		 */
		rv = DDI_WALK_PRUNESIB;
		break;
	case DDI_WALK_PRUNECHILD:
		/*
		 * Don't create children, but ask parent to continue
		 * with siblings.
		 */
		rv = DDI_WALK_CONTINUE;
		break;
	default:
		ASSERT(0);
		break;
	}

	if (rdipp)
		*rdipp = dip;

	/*
	 * Set device offline - only the "configure" op should cause an attach
	 */
	(void) set_dip_offline(dip, NULL);

	return (rv);
fail:
	(void) ndi_devi_free(dip);
	kmem_free(nbuf, OBP_MAXDRVNAME);
	return (DDI_WALK_ERROR);
}

static int
create_sid_branch(
	dev_info_t	*pdip,
	devi_branch_t	*bp,
	dev_info_t	**dipp,
	uint_t		flags)
{
	int		rv = 0, state = DDI_WALK_CONTINUE;
	dev_info_t	*rdip;

	while (state == DDI_WALK_CONTINUE) {
		int	circ;

		ndi_devi_enter(pdip, &circ);

		state = sid_node_create(pdip, bp, &rdip);
		if (rdip == NULL) {
			ndi_devi_exit(pdip, circ);
			ASSERT(state == DDI_WALK_ERROR);
			break;
		}

		e_ddi_branch_hold(rdip);

		ndi_devi_exit(pdip, circ);

		if (flags & DEVI_BRANCH_CONFIGURE) {
			int error = e_ddi_branch_configure(rdip, dipp, 0);
			if (error && rv == 0)
				rv = error;
		}

		/*
		 * devi_branch_callback() is optional
		 */
		if (bp->devi_branch_callback)
			bp->devi_branch_callback(rdip, bp->arg, 0);
	}

	ASSERT(state == DDI_WALK_ERROR || state == DDI_WALK_PRUNESIB);

	return (state == DDI_WALK_ERROR ? EIO : rv);
}

int
e_ddi_branch_create(
	dev_info_t	*pdip,
	devi_branch_t	*bp,
	dev_info_t	**dipp,
	uint_t		flags)
{
	int prom_devi, sid_devi, error;

	if (pdip == NULL || bp == NULL || bp->type == 0)
		return (EINVAL);

	prom_devi = (bp->type == DEVI_BRANCH_PROM) ? 1 : 0;
	sid_devi = (bp->type == DEVI_BRANCH_SID) ? 1 : 0;

	if (prom_devi && bp->create.prom_branch_select == NULL)
		return (EINVAL);
	else if (sid_devi && bp->create.sid_branch_create == NULL)
		return (EINVAL);
	else if (!prom_devi && !sid_devi)
		return (EINVAL);

	if (flags & DEVI_BRANCH_EVENT)
		return (EINVAL);

	if (prom_devi) {
		struct pta pta = {0};

		pta.pdip = pdip;
		pta.bp = bp;
		pta.flags = flags;

		error = prom_tree_access(create_prom_branch, &pta, NULL);

		if (dipp)
			*dipp = pta.fdip;
		else if (pta.fdip)
			ndi_rele_devi(pta.fdip);
	} else {
		error = create_sid_branch(pdip, bp, dipp, flags);
	}

	return (error);
}

int
e_ddi_branch_configure(dev_info_t *rdip, dev_info_t **dipp, uint_t flags)
{
	int		circ, rv;
	char		*devnm;
	dev_info_t	*pdip;

	if (dipp)
		*dipp = NULL;

	if (rdip == NULL || flags != 0 || (flags & DEVI_BRANCH_EVENT))
		return (EINVAL);

	pdip = ddi_get_parent(rdip);

	ndi_devi_enter(pdip, &circ);

	if (!e_ddi_branch_held(rdip)) {
		ndi_devi_exit(pdip, circ);
		cmn_err(CE_WARN, "e_ddi_branch_configure: "
		    "dip(%p) not held", (void *)rdip);
		return (EINVAL);
	}

	if (i_ddi_node_state(rdip) < DS_INITIALIZED) {
		/*
		 * First attempt to bind a driver. If we fail, return
		 * success (On some platforms, dips for some device
		 * types (CPUs) may not have a driver)
		 */
		if (ndi_devi_bind_driver(rdip, 0) != NDI_SUCCESS) {
			ndi_devi_exit(pdip, circ);
			return (0);
		}

		if (ddi_initchild(pdip, rdip) != DDI_SUCCESS) {
			rv = NDI_FAILURE;
			goto out;
		}
	}

	ASSERT(i_ddi_node_state(rdip) >= DS_INITIALIZED);

	devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);

	(void) ddi_deviname(rdip, devnm);

	if ((rv = ndi_devi_config_one(pdip, devnm+1, &rdip,
	    NDI_DEVI_ONLINE | NDI_CONFIG)) == NDI_SUCCESS) {
		/* release hold from ndi_devi_config_one() */
		ndi_rele_devi(rdip);
	}

	kmem_free(devnm, MAXNAMELEN + 1);
out:
	if (rv != NDI_SUCCESS && dipp) {
		ndi_hold_devi(rdip);
		*dipp = rdip;
	}
	ndi_devi_exit(pdip, circ);
	return (ndi2errno(rv));
}

void
e_ddi_branch_hold(dev_info_t *rdip)
{
	if (e_ddi_branch_held(rdip)) {
		cmn_err(CE_WARN, "e_ddi_branch_hold: branch already held");
		return;
	}

	mutex_enter(&DEVI(rdip)->devi_lock);
	if ((DEVI(rdip)->devi_flags & DEVI_BRANCH_HELD) == 0) {
		DEVI(rdip)->devi_flags |= DEVI_BRANCH_HELD;
		DEVI(rdip)->devi_ref++;
	}
	ASSERT(DEVI(rdip)->devi_ref > 0);
	mutex_exit(&DEVI(rdip)->devi_lock);
}

int
e_ddi_branch_held(dev_info_t *rdip)
{
	int rv = 0;

	mutex_enter(&DEVI(rdip)->devi_lock);
	if ((DEVI(rdip)->devi_flags & DEVI_BRANCH_HELD) &&
	    DEVI(rdip)->devi_ref > 0) {
		rv = 1;
	}
	mutex_exit(&DEVI(rdip)->devi_lock);

	return (rv);
}
void
e_ddi_branch_rele(dev_info_t *rdip)
{
	mutex_enter(&DEVI(rdip)->devi_lock);
	DEVI(rdip)->devi_flags &= ~DEVI_BRANCH_HELD;
	DEVI(rdip)->devi_ref--;
	mutex_exit(&DEVI(rdip)->devi_lock);
}

int
e_ddi_branch_unconfigure(
	dev_info_t *rdip,
	dev_info_t **dipp,
	uint_t flags)
{
	int	circ, rv;
	int	destroy;
	char	*devnm;
	uint_t	nflags;
	dev_info_t *pdip;

	if (dipp)
		*dipp = NULL;

	if (rdip == NULL)
		return (EINVAL);

	pdip = ddi_get_parent(rdip);

	ASSERT(pdip);

	/*
	 * Check if caller holds pdip busy - can cause deadlocks during
	 * devfs_clean()
	 */
	if (DEVI_BUSY_OWNED(pdip)) {
		cmn_err(CE_WARN, "e_ddi_branch_unconfigure: failed: parent"
		    " devinfo node(%p) is busy held", (void *)pdip);
		return (EINVAL);
	}

	destroy = (flags & DEVI_BRANCH_DESTROY) ? 1 : 0;

	devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);

	ndi_devi_enter(pdip, &circ);
	(void) ddi_deviname(rdip, devnm);
	ndi_devi_exit(pdip, circ);

	/*
	 * ddi_deviname() returns a component name with / prepended.
	 */
	rv = devfs_clean(pdip, devnm + 1, DV_CLEAN_FORCE);
	if (rv) {
		kmem_free(devnm, MAXNAMELEN + 1);
		return (rv);
	}

	ndi_devi_enter(pdip, &circ);

	/*
	 * Recreate device name as it may have changed state (init/uninit)
	 * when parent busy lock was dropped for devfs_clean()
	 */
	(void) ddi_deviname(rdip, devnm);

	if (!e_ddi_branch_held(rdip)) {
		kmem_free(devnm, MAXNAMELEN + 1);
		ndi_devi_exit(pdip, circ);
		cmn_err(CE_WARN, "e_ddi_%s_branch: dip(%p) not held",
		    destroy ? "destroy" : "unconfigure", (void *)rdip);
		return (EINVAL);
	}

	/*
	 * Release hold on the branch. This is ok since we are holding the
	 * parent busy. If rdip is not removed, we must do a hold on the
	 * branch before returning.
	 */
	e_ddi_branch_rele(rdip);

	nflags = NDI_DEVI_OFFLINE;
	if (destroy || (flags & DEVI_BRANCH_DESTROY)) {
		nflags |= NDI_DEVI_REMOVE;
		destroy = 1;
	} else {
		nflags |= NDI_UNCONFIG;		/* uninit but don't remove */
	}

	if (flags & DEVI_BRANCH_EVENT)
		nflags |= NDI_POST_EVENT;

	if (i_ddi_node_state(pdip) == DS_READY &&
	    i_ddi_node_state(rdip) >= DS_INITIALIZED) {
		rv = ndi_devi_unconfig_one(pdip, devnm+1, dipp, nflags);
	} else {
		rv = e_ddi_devi_unconfig(rdip, dipp, nflags);
		if (rv == NDI_SUCCESS) {
			ASSERT(!destroy || ddi_get_child(rdip) == NULL);
			rv = ndi_devi_offline(rdip, nflags);
		}
	}

	if (!destroy || rv != NDI_SUCCESS) {
		/* The dip still exists, so do a hold */
		e_ddi_branch_hold(rdip);
	}
out:
	kmem_free(devnm, MAXNAMELEN + 1);
	ndi_devi_exit(pdip, circ);
	return (ndi2errno(rv));
}

int
e_ddi_branch_destroy(dev_info_t *rdip, dev_info_t **dipp, uint_t flag)
{
	return (e_ddi_branch_unconfigure(rdip, dipp,
	    flag|DEVI_BRANCH_DESTROY));
}

/*
 * Number of chains for hash table
 */
#define	NUMCHAINS	17

/*
 * Devinfo busy arg
 */
struct devi_busy {
	int dv_total;
	int s_total;
	mod_hash_t *dv_hash;
	mod_hash_t *s_hash;
	int (*callback)(dev_info_t *, void *, uint_t);
	void *arg;
};

static int
visit_dip(dev_info_t *dip, void *arg)
{
	uintptr_t sbusy, dvbusy, ref;
	struct devi_busy *bsp = arg;

	ASSERT(bsp->callback);

	/*
	 * A dip cannot be busy if its reference count is 0
	 */
	if ((ref = e_ddi_devi_holdcnt(dip)) == 0) {
		return (bsp->callback(dip, bsp->arg, 0));
	}

	if (mod_hash_find(bsp->dv_hash, dip, (mod_hash_val_t *)&dvbusy))
		dvbusy = 0;

	/*
	 * To catch device opens currently maintained on specfs common snodes.
	 */
	if (mod_hash_find(bsp->s_hash, dip, (mod_hash_val_t *)&sbusy))
		sbusy = 0;

#ifdef	DEBUG
	if (ref < sbusy || ref < dvbusy) {
		cmn_err(CE_WARN, "dip(%p): sopen = %lu, dvopen = %lu "
		    "dip ref = %lu\n", (void *)dip, sbusy, dvbusy, ref);
	}
#endif

	dvbusy = (sbusy > dvbusy) ? sbusy : dvbusy;

	return (bsp->callback(dip, bsp->arg, dvbusy));
}

static int
visit_snode(struct snode *sp, void *arg)
{
	uintptr_t sbusy;
	dev_info_t *dip;
	int count;
	struct devi_busy *bsp = arg;

	ASSERT(sp);

	/*
	 * The stable lock is held. This prevents
	 * the snode and its associated dip from
	 * going away.
	 */
	dip = NULL;
	count = spec_devi_open_count(sp, &dip);

	if (count <= 0)
		return (DDI_WALK_CONTINUE);

	ASSERT(dip);

	if (mod_hash_remove(bsp->s_hash, dip, (mod_hash_val_t *)&sbusy))
		sbusy = count;
	else
		sbusy += count;

	if (mod_hash_insert(bsp->s_hash, dip, (mod_hash_val_t)sbusy)) {
		cmn_err(CE_WARN, "%s: s_hash insert failed: dip=0x%p, "
		    "sbusy = %lu", "e_ddi_branch_referenced",
		    (void *)dip, sbusy);
	}

	bsp->s_total += count;

	return (DDI_WALK_CONTINUE);
}

static void
visit_dvnode(struct dv_node *dv, void *arg)
{
	uintptr_t dvbusy;
	uint_t count;
	struct vnode *vp;
	struct devi_busy *bsp = arg;

	ASSERT(dv && dv->dv_devi);

	vp = DVTOV(dv);

	mutex_enter(&vp->v_lock);
	count = vp->v_count;
	mutex_exit(&vp->v_lock);

	if (!count)
		return;

	if (mod_hash_remove(bsp->dv_hash, dv->dv_devi,
	    (mod_hash_val_t *)&dvbusy))
		dvbusy = count;
	else
		dvbusy += count;

	if (mod_hash_insert(bsp->dv_hash, dv->dv_devi,
	    (mod_hash_val_t)dvbusy)) {
		cmn_err(CE_WARN, "%s: dv_hash insert failed: dip=0x%p, "
		    "dvbusy=%lu", "e_ddi_branch_referenced",
		    (void *)dv->dv_devi, dvbusy);
	}

	bsp->dv_total += count;
}

/*
 * Returns reference count on success or -1 on failure.
 */
int
e_ddi_branch_referenced(
	dev_info_t *rdip,
	int (*callback)(dev_info_t *dip, void *arg, uint_t ref),
	void *arg)
{
	int circ;
	char *path;
	dev_info_t *pdip;
	struct devi_busy bsa = {0};

	ASSERT(rdip);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	ndi_hold_devi(rdip);

	pdip = ddi_get_parent(rdip);

	ASSERT(pdip);

	/*
	 * Check if caller holds pdip busy - can cause deadlocks during
	 * devfs_walk()
	 */
	if (!e_ddi_branch_held(rdip) || DEVI_BUSY_OWNED(pdip)) {
		cmn_err(CE_WARN, "e_ddi_branch_referenced: failed: "
		    "devinfo branch(%p) not held or parent busy held",
		    (void *)rdip);
		ndi_rele_devi(rdip);
		kmem_free(path, MAXPATHLEN);
		return (-1);
	}

	ndi_devi_enter(pdip, &circ);
	(void) ddi_pathname(rdip, path);
	ndi_devi_exit(pdip, circ);

	bsa.dv_hash = mod_hash_create_ptrhash("dv_node busy hash", NUMCHAINS,
	    mod_hash_null_valdtor, sizeof (struct dev_info));

	bsa.s_hash = mod_hash_create_ptrhash("snode busy hash", NUMCHAINS,
	    mod_hash_null_valdtor, sizeof (struct snode));

	if (devfs_walk(path, visit_dvnode, &bsa)) {
		cmn_err(CE_WARN, "e_ddi_branch_referenced: "
		    "devfs walk failed for: %s", path);
		kmem_free(path, MAXPATHLEN);
		bsa.s_total = bsa.dv_total = -1;
		goto out;
	}

	kmem_free(path, MAXPATHLEN);

	/*
	 * Walk the snode table to detect device opens, which are currently
	 * maintained on specfs common snodes.
	 */
	spec_snode_walk(visit_snode, &bsa);

	if (callback == NULL)
		goto out;

	bsa.callback = callback;
	bsa.arg = arg;

	if (visit_dip(rdip, &bsa) == DDI_WALK_CONTINUE) {
		ndi_devi_enter(rdip, &circ);
		ddi_walk_devs(ddi_get_child(rdip), visit_dip, &bsa);
		ndi_devi_exit(rdip, circ);
	}

out:
	ndi_rele_devi(rdip);
	mod_hash_destroy_ptrhash(bsa.s_hash);
	mod_hash_destroy_ptrhash(bsa.dv_hash);
	return (bsa.s_total > bsa.dv_total ? bsa.s_total : bsa.dv_total);
}
