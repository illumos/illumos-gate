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
 * sun4v root nexus driver
 */
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/ivintr.h>
#include <sys/intreg.h>
#include <sys/ddi_subrdefs.h>
#include <sys/sunndi.h>
#include <sys/async.h>

/* Useful debugging Stuff */
#include <sys/nexusdebug.h>
#define	ROOTNEX_MAP_DEBUG		0x1
#define	ROOTNEX_INTR_DEBUG		0x2

extern uint_t	root_phys_addr_lo_mask;
extern int rootnex_name_child(dev_info_t *child, char *name, int namelen);
extern int rootnex_ctl_uninitchild(dev_info_t *dip);

uint_t	root_phys_addr_hi_mask = 0xfffffff;

#define	BUS_ADDRTYPE_CONFIG		0xc

#define	BUSTYPE_TO_ADDRTYPE(bustype)	((bustype >> 28) & 0xf)

static char *bus_addrtype[16] = {
	"m", NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	"i", NULL, NULL, NULL, "", NULL, NULL, NULL
};

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
	return (i_ddi_add_ivintr(hdlp));
}

/*
 * rootnex_remove_intr_impl:
 */
/*ARGSUSED*/
int
rootnex_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
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
	return (hdlp->ih_pri);
}

int
rootnex_ctl_reportdev_impl(dev_info_t *dev)
{
	struct regspec *rp;
	char buf[80];
	char *p = buf;

	(void) sprintf(p, "%s%d at root", ddi_driver_name(dev),
	    ddi_get_instance(dev));
	p += strlen(p);

	if (sparc_pd_getnreg(dev) > 0) {
		rp = sparc_pd_getreg(dev, 0);

		(void) strcpy(p, ": ");
		p += strlen(p);

		(void) snprintf(p, sizeof (buf) - (buf - p),
		    "0x%x 0x%x", rp->regspec_bustype & root_phys_addr_hi_mask,
		    rp->regspec_addr & root_phys_addr_lo_mask);

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
	uint_t addrtype;
	uint_t addrlow;
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
	 * Name node on behalf of child nexus.
	 */
	if (ddi_get_parent(child) != ddi_root_node()) {
		(void) snprintf(name, namelen, "%x,%x",
		    rp->regspec_bustype, rp->regspec_addr);
		return (DDI_SUCCESS);
	}

	/*
	 * On sun4v, the 'name' of a root node device depends upon
	 * the first reg property, which contains two 32-bit address
	 * cells as follows:
	 *
	 *  bit# 63-32: ssss.hhhh.hhhh.hhhh.hhhh.hhhh.hhhh.hhhh
	 *  bit# 31-00: llll.llll.llll.llll.llll.llll.llll.llll
	 *
	 * where 'ssss' defines the address type and naming convention
	 * as follows:
	 *
	 *    0000  -> cacheable address space
	 *		foo@m<high-addr>[,<low-addr>]
	 *    1000  -> non-cacheable IO address space
	 *		foo@i<high-addr>[,<low-addr>]
	 *    1100  -> non-cacheable configuration address space
	 *		foo@<high-addr>
	 *
	 * where <hish-addr> is hex-ASCII reprensation of the hh...hh
	 * bits and <low-addr> is hex-ASCII represenation of the
	 * ll...ll bits.
	 *
	 * Note that the leading zeros are omitted here. Also, if the
	 * <low-addr> bits are zero, then the trailing component is
	 * omitted as well.
	 */
	addrtype = BUSTYPE_TO_ADDRTYPE(rp->regspec_bustype);
	addrlow = rp->regspec_addr & root_phys_addr_lo_mask;
	if (bus_addrtype[addrtype] == NULL)
		cmn_err(CE_PANIC, "rootnex: wrong bustype: %x child: %s\n",
		    rp->regspec_bustype, ddi_node_name(child));
	else if (addrtype == BUS_ADDRTYPE_CONFIG || addrlow == 0)
		(void) snprintf(name, namelen, "%s%x",
		    bus_addrtype[addrtype],
		    rp->regspec_bustype & root_phys_addr_hi_mask);
	else
		(void) snprintf(name, namelen, "%s%x,%x",
		    bus_addrtype[addrtype],
		    rp->regspec_bustype & root_phys_addr_hi_mask, addrlow);

	return (DDI_SUCCESS);
}


int
rootnex_ctl_initchild_impl(dev_info_t *dip)
{
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

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
rootnex_ctl_uninitchild_impl(dev_info_t *dip)
{
}
