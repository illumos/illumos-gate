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
 * sun4u specific DDI implementation
 */
#include <sys/bootconf.h>
#include <sys/conf.h>
#include <sys/ddi_subrdefs.h>
#include <sys/ethernet.h>
#include <sys/idprom.h>
#include <sys/machsystm.h>
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

	if (prom_getprop((pnode_t)nid, OBP_BOARDNUM,
	    (caddr_t)&board_num) != -1)
		return (board_num);

	/*
	 * Look at current node and up the parent chain
	 * till we find a node with an OBP_BOARDNUM.
	 */
	while (par) {
		nid = ddi_get_nodeid(par);

		if (prom_getprop((pnode_t)nid, OBP_BOARDNUM,
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

	size = prom_getproplen((pnode_t)id, name);
	if (size <= 0 || (size > maxlen - 1))
		return (-1);

	if (-1 == prom_getprop((pnode_t)id, name, buf))
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
	pnode_t		nodeid;
	int		i;

	nodeid = (pnode_t)ddi_get_nodeid(dip);
	for (i = 0; i < NCPU; i++) {
		if (cpunodes[i].nodeid == nodeid) {
			*cpu_id = i;
			return (DDI_SUCCESS);
		}
	}
	return (DDI_FAILURE);
}
