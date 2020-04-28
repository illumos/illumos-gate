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
/*
 * Copyright 2019 Peter Tribble.
 */

/*
 * sun4u root nexus driver
 */
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/sysiosbus.h>
#include <sys/intreg.h>
#include <sys/ddi_subrdefs.h>
#include <sys/sunndi.h>
#include <sys/async.h>

/* Useful debugging Stuff */
#include <sys/nexusdebug.h>
#define	ROOTNEX_MAP_DEBUG		0x1
#define	ROOTNEX_INTR_DEBUG		0x2

/*
 * Extern declarations
 */
extern uint_t	root_phys_addr_lo_mask;
extern int rootnex_name_child(dev_info_t *child, char *name, int namelen);
extern int rootnex_ctl_uninitchild(dev_info_t *dip);

uint_t	root_phys_addr_hi_mask = 0xffffffff;

/*
 * config information
 */
int
rootnex_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);

int
rootnex_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);

int
rootnex_get_intr_pri(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);

ddi_iblock_cookie_t rootnex_err_ibc;

/*
 * rootnex_add_intr_impl:
 */
/*ARGSUSED*/
int
rootnex_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	volatile uint64_t	*intr_mapping_reg;
	volatile uint64_t	mondo_vector;
	int32_t			r_upaid = -1;
	int32_t			slave = 0;
	int32_t			portid;
	int			len, ret;

	if (((portid = ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "upa-portid", -1)) != -1) ||
	    ((portid = ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "portid", -1)) != -1)) {
		if (ddi_getprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
		    "upa-interrupt-slave", 0) != 0) {

			/* Give slave devices pri of 5. e.g. fb's */
			hdlp->ih_pri = 5;
		}

		/*
		 * Translate the interrupt property by stuffing in the
		 * portid for those devices which have a portid.
		 */
		hdlp->ih_vector |= (UPAID_TO_IGN(portid) << 6);
	}

	/*
	 * Hack to support the UPA slave devices before the 1275
	 * support for imap was introduced.
	 */
	if (ddi_getproplen(DDI_DEV_T_ANY, dip, 0, "interrupt-map",
	    &len) != DDI_PROP_SUCCESS && ddi_getprop(DDI_DEV_T_ANY,
	    rdip, DDI_PROP_DONTPASS, "upa-interrupt-slave", 0) != 0 &&
	    ddi_get_parent(rdip) == dip) {
		slave = 1;

		if ((r_upaid = ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, "upa-portid", -1)) != -1) {
			extern uint64_t *get_intr_mapping_reg(int, int);

			if ((intr_mapping_reg = get_intr_mapping_reg(
			    r_upaid, 1)) == NULL)
				return (DDI_FAILURE);
		} else
			return (DDI_FAILURE);
	}

	if ((ret = i_ddi_add_ivintr(hdlp)) != DDI_SUCCESS)
		return (ret);

	/*
	 * Hack to support the UPA slave devices before the 1275
	 * support for imap was introduced.
	 */
	if (slave) {
		/*
		 * Program the interrupt mapping register.
		 * Interrupts from the slave UPA devices are
		 * directed at the boot CPU until it is known
		 * that they can be safely redirected while
		 * running under load.
		 */
		mondo_vector = cpu0.cpu_id << IMR_TID_SHIFT;
		mondo_vector |= (IMR_VALID | (uint64_t)hdlp->ih_vector);

		/* Set the mapping register */
		*intr_mapping_reg = mondo_vector;

		/* Flush write buffers */
		mondo_vector = *intr_mapping_reg;
	}

	return (ret);
}

/*
 * rootnex_remove_intr_impl:
 */
/*ARGSUSED*/
int
rootnex_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	int32_t		portid;
	int		len;

	if (((portid = ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "upa-portid", -1)) != -1) ||
	    ((portid = ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "portid", -1)) != -1)) {
		/*
		 * Translate the interrupt property by stuffing in the
		 * portid for those devices which have a portid.
		 */
		hdlp->ih_vector |= (UPAID_TO_IGN(portid) << 6);
	}

	/*
	 * Hack to support the UPA slave devices before the 1275
	 * support for imap was introduced.
	 */
	if (ddi_getproplen(DDI_DEV_T_ANY, dip, 0, "interrupt-map",
	    &len) != DDI_PROP_SUCCESS && ddi_getprop(DDI_DEV_T_ANY,
	    rdip, DDI_PROP_DONTPASS, "upa-interrupt-slave", 0) != 0) {
		int32_t r_upaid = -1;

		if ((r_upaid = ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, "upa-portid", -1)) != -1 &&
		    ddi_get_parent(rdip) == dip) {
			volatile uint64_t *intr_mapping_reg;
			volatile uint64_t flush_data;
			extern uint64_t *get_intr_mapping_reg(int, int);

			if ((intr_mapping_reg = get_intr_mapping_reg(
			    r_upaid, 1)) == NULL)
				return (DDI_SUCCESS);

			/* Clear the mapping register */
			*intr_mapping_reg = 0x0ull;

			/* Flush write buffers */
			flush_data = *intr_mapping_reg;
#ifdef lint
			flush_data = flush_data;
#endif /* lint */
		}
	}

	i_ddi_rem_ivintr(hdlp);

	return (DDI_SUCCESS);
}

/*
 * rootnex_get_intr_pri:
 */
/*ARGSUSED*/
int
rootnex_get_intr_pri(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	int	pri = hdlp->ih_pri;

	if (ddi_prop_get_int(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
	    "upa-portid", -1) != -1) {
		if (ddi_getprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
		    "upa-interrupt-slave", 0) != 0) {

			/* Give slave devices pri of 5. e.g. fb's */
			pri = 5;
		}
	}

	return (pri);
}

int
rootnex_ctl_reportdev_impl(dev_info_t *dev)
{
	struct regspec *rp;
	char buf[80];
	char *p = buf;
	register int n;
	int	portid;
	int	nodeid;

	(void) sprintf(p, "%s%d at root", ddi_driver_name(dev),
	    ddi_get_instance(dev));
	p += strlen(p);

	if ((n = sparc_pd_getnreg(dev)) > 0) {
		rp = sparc_pd_getreg(dev, 0);

		(void) strcpy(p, ": ");
		p += strlen(p);

		/*
		 * This stuff needs to be fixed correctly for the FFB
		 * devices and the UPA add-on devices.
		 */
		portid = ddi_prop_get_int(DDI_DEV_T_ANY, dev,
		    DDI_PROP_DONTPASS, "upa-portid", -1);
		if (portid != -1)
			(void) sprintf(p, "UPA 0x%x 0x%x%s",
			    portid,
			    rp->regspec_addr, (n > 1 ? "" : " ..."));
		else {
			portid = ddi_prop_get_int(DDI_DEV_T_ANY, dev,
			    DDI_PROP_DONTPASS, "portid", -1);
			nodeid = ddi_prop_get_int(DDI_DEV_T_ANY, dev,
			    DDI_PROP_DONTPASS, "nodeid", -1);
			if (portid == -1 && nodeid == -1)
				printf("could not find portid "
				    "or nodeid property in %s\n",
				    DEVI(dev)->devi_node_name);

			if (portid != -1)
				(void) sprintf(p, "SAFARI 0x%x 0x%x%s",
				    portid,
				    rp->regspec_addr &
				    root_phys_addr_lo_mask,
				    (n > 1 ? "" : " ..."));
			if (nodeid != -1)
				(void) sprintf(p, "SSM Node %d", nodeid);
		}
		p += strlen(p);
	}

	/*
	 * This is where we need to print out the interrupt specifications
	 * for the FFB device and any UPA add-on devices.  Not sure how to
	 * do this yet?
	 */
	cmn_err(CE_CONT, "?%s\n", buf);
	return (DDI_SUCCESS);
}

int
rootnex_name_child_impl(dev_info_t *child, char *name, int namelen)
{
	struct ddi_parent_private_data *pdptr;
	int portid, nodeid;
	char *node_name;
	struct regspec *rp;

	extern uint_t root_phys_addr_lo_mask;
	extern void make_ddi_ppd(
	    dev_info_t *, struct ddi_parent_private_data **);

	/*
	 * Fill in parent-private data and this function returns to us
	 * an indication if it used "registers" to fill in the data.
	 */
	if (ddi_get_parent_data(child) == NULL) {
		make_ddi_ppd(child, &pdptr);
		ddi_set_parent_data(child, pdptr);
	}

	/*
	 * No reg property, return null string as address (e.g. pseudo)
	 */
	name[0] = '\0';
	if (sparc_pd_getnreg(child) == 0) {
		return (DDI_SUCCESS);
	}
	rp = sparc_pd_getreg(child, 0);
	ASSERT(rp != NULL);

	/*
	 * Create portid property for fhc node under root(/fhc).
	 */
	node_name = ddi_node_name(child);
	if ((strcmp(node_name, "fhc") == 0) ||
	    (strcmp(node_name, "mem-unit") == 0) ||
	    (strcmp(node_name, "central") == 0)) {
		portid = (rp->regspec_bustype >> 1) & 0x1f;

		/*
		 * The port-id must go on the hardware property list,
		 * otherwise, initchild may fail.
		 */
		if (ndi_prop_update_int(DDI_DEV_T_NONE, child, "upa-portid",
		    portid) != DDI_SUCCESS)
			cmn_err(CE_WARN,
			    "Error in creating upa-portid property for fhc.\n");
	}

	/*
	 * Name node on behalf of child nexus.
	 */
	if (ddi_get_parent(child) != ddi_root_node()) {
		(void) snprintf(name, namelen, "%x,%x",
		    rp->regspec_bustype, rp->regspec_addr);
		return (DDI_SUCCESS);
	}

	/*
	 * On sun4u, the 'name' of children of the root node
	 * is foo@<upa-mid>,<offset>, which is derived from,
	 * but not identical to the physical address.
	 */
	portid = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "upa-portid", -1);
	if (portid == -1)
		portid = ddi_prop_get_int(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "portid", -1);
	nodeid = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "nodeid", -1);

	/*
	 * Do not log message, to handle cases where OBP version
	 * does not have "portid" property for the root i2c node.
	 *
	 * Platforms supporting root i2c node (potentially without
	 * "portid" property) are :
	 *	SunBlade 1500, SunBlade 2500, V240, V250
	 */
	if (portid == -1 && nodeid == -1 &&
	    strncmp(node_name, "i2c", strlen("i2c")) != 0)
		cmn_err(CE_WARN,
		    "could not find portid or nodeid property in %s\n",
		    DEVI(child)->devi_node_name);
	if (nodeid != -1)
		(void) snprintf(name, namelen, "%x,0", nodeid);
	else
		(void) snprintf(name, namelen, "%x,%x", portid,
		    rp->regspec_addr & root_phys_addr_lo_mask);

	return (DDI_SUCCESS);
}

int
rootnex_ctl_initchild_impl(dev_info_t *dip)
{
	struct regspec *rp;
	struct ddi_parent_private_data *pd;
	char name[MAXNAMELEN];

	extern struct ddi_parent_private_data *init_regspec_64(dev_info_t *dip);

	/* Name the child */
	(void) rootnex_name_child(dip, name, MAXNAMELEN);
	ddi_set_name_addr(dip, name);

	/*
	 * Try to merge .conf node. If merge is successful, return
	 * DDI_FAILURE to allow caller to remove this node.
	 */
	if (ndi_dev_is_persistent_node(dip) == 0 &&
	    (ndi_merge_node(dip, rootnex_name_child) == DDI_SUCCESS)) {
		(void) rootnex_ctl_uninitchild(dip);
		return (DDI_FAILURE);
	}

	/*
	 * If there are no "reg"s in the child node, return.
	 */
	pd = init_regspec_64(dip);
	if ((pd == NULL) || (pd->par_nreg == 0))
		return (DDI_SUCCESS);

	/*
	 * If this is a slave device sitting on the UPA, we assume that
	 * This device can accept DMA accesses from other devices.  We need
	 * to register this fact with the system by using the highest
	 * and lowest physical pfns of the devices register space.  This
	 * will then represent a physical block of addresses that are valid
	 * for DMA accesses.
	 */
	if ((ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "upa-portid",
	    -1) != -1) && ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "upa-interrupt-slave", 0)) {
		pfn_t lopfn = (pfn_t)-1;
		pfn_t hipfn = 0;
		int i;
		extern void pf_set_dmacapable(pfn_t, pfn_t);

		/* Scan the devices highest and lowest physical pfns */
		for (i = 0, rp = pd->par_reg; i < pd->par_nreg; i++, rp++) {
			uint64_t addr;
			pfn_t tmphipfn, tmplopfn;

			addr = (unsigned long long)((unsigned long long)
			    rp->regspec_bustype << 32);
			addr |= (uint64_t)rp->regspec_addr;
			tmplopfn = (pfn_t)(addr >> MMU_PAGESHIFT);
			addr += (uint64_t)(rp->regspec_size - 1);
			tmphipfn = (pfn_t)(addr >> MMU_PAGESHIFT);

			hipfn = (tmphipfn > hipfn) ? tmphipfn : hipfn;
			lopfn = (tmplopfn < lopfn) ? tmplopfn : lopfn;
		}
		pf_set_dmacapable(hipfn, lopfn);
	}

	return (DDI_SUCCESS);
}

void
rootnex_ctl_uninitchild_impl(dev_info_t *dip)
{
	if ((ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "upa-portid",
	    -1) != -1) && (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "upa-interrupt-slave", 0))) {
		struct regspec *rp;
		extern void pf_unset_dmacapable(pfn_t);
		unsigned long long addr;
		pfn_t pfn;
		struct ddi_parent_private_data *pd;

		pd = ddi_get_parent_data(dip);
		ASSERT(pd != NULL);
		rp = pd->par_reg;
		addr = (unsigned long long) ((unsigned long long)
		    rp->regspec_bustype << 32);
		addr |= (unsigned long long) rp->regspec_addr;
		pfn = (pfn_t)(addr >> MMU_PAGESHIFT);

		pf_unset_dmacapable(pfn);
	}
}
