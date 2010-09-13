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


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/spl.h>
#include <sys/async.h>
#include <sys/dvma.h>
#include <sys/upa64s.h>
#include <sys/machsystm.h>

/*
 * driver global data:
 */
static void *per_upa64s_state;		/* soft state pointer */

/*
 * function prototypes for bus ops routines:
 */
static int
upa64s_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *addrp);
static int
upa64s_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t op, void *arg, void *result);
static int
upa64_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result);
static int
upa64s_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);
static int
upa64s_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);

/*
 * function prototypes for dev ops routines:
 */
static int upa64s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int upa64s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int upa64s_power(dev_info_t *dip, int component, int level);

/*
 * bus ops and dev ops structures:
 */
static struct bus_ops upa64s_bus_ops = {
	BUSO_REV,
	upa64s_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	ddi_no_dma_map,
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,
	ddi_no_dma_bindhdl,
	ddi_no_dma_unbindhdl,
	ddi_no_dma_flush,
	ddi_no_dma_win,
	ddi_no_dma_mctl,
	upa64s_ctlops,
	ddi_bus_prop_op,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	upa64_intr_ops
};

static struct dev_ops upa64s_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,
	0,
	upa64s_attach,
	upa64s_detach,
	nodev,
	(struct cb_ops *)0,
	&upa64s_bus_ops,
	upa64s_power,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * module definitions:
 */
#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops, 		/* type of module */
	"UPA64S nexus driver",	/* name of module */
	&upa64s_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int e;

	/*
	 * Initialize per instance bus soft state pointer.
	 */
	if (e = ddi_soft_state_init(&per_upa64s_state,
	    sizeof (upa64s_devstate_t), 2))
		return (e);
	/*
	 * Install the module.
	 */
	if (e = mod_install(&modlinkage))
		ddi_soft_state_fini(&per_upa64s_state);
	return (e);
}

int
_fini(void)
{
	int e = mod_remove(&modlinkage);
	if (e)
		return (e);
	ddi_soft_state_fini(&per_upa64s_state);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * forward declarations:
 */
static void upa64s_intrdist(void *arg);
static int init_child(dev_info_t *child);
static int report_dev(dev_info_t *dip);
static int get_properties(upa64s_devstate_t *upa64s_p, dev_info_t *dip);
static void save_state(upa64s_devstate_t *upa64s_p);
static void restore_state(upa64s_devstate_t *upa64s_p);
static int xlate_reg_prop(dev_info_t *dip, upa64s_regspec_t *upa64s_rp,
    off_t off, off_t len, struct regspec *rp);
static int get_reg_set(dev_info_t *dip, dev_info_t *child, int rnumber,
    off_t off, off_t len, struct regspec *rp);
static off_t get_reg_set_size(dev_info_t *child, int rnumber);
static uint_t get_nreg_set(dev_info_t *child);


/* device driver entry points */

/*
 * attach entry point:
 */
static int
upa64s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	upa64s_devstate_t *upa64s_p;	/* per upa64s state pointer */
	ddi_device_acc_attr_t attr;
	int instance;
	char *pmc[] = { "NAME=Framebuffer Power", "0=Off", "1=On", NULL };

	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * Allocate and get the per instance soft state structure.
		 */
		instance = ddi_get_instance(dip);
		if (alloc_upa64s_soft_state(instance) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't allocate upa64s state",
			    ddi_get_name(dip), instance);
			return (DDI_FAILURE);
		}
		upa64s_p = get_upa64s_soft_state(instance);
		upa64s_p->dip = dip;

		/*
		 * Get key properties of the bridge node.
		 */
		if (get_properties(upa64s_p, dip) != DDI_SUCCESS)
			goto fail;

		/*
		 * Create "pm-components" property for the purpose of
		 * doing Power Management.
		 */
		if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
		    "pm-components", pmc, ((sizeof (pmc)/sizeof (char *)) - 1))
		    != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: failed to create pm-components "
			    "property.", ddi_get_name(dip), instance);
			goto fail;
		}

		/* Map in the UPA's registers */
		attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
		attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
		attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
		if (ddi_regs_map_setup(dip, 0,
		    (caddr_t *)&upa64s_p->config_base, 0, 0, &attr,
		    &upa64s_p->config_base_ah) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: failed to map reg1.",
			    ddi_get_name(dip), instance);
			goto fail;
		}

		upa64s_p->upa0_config = (uint64_t *)(upa64s_p->config_base +
		    UPA64S_UPA0_CONFIG_OFFSET);
		upa64s_p->upa1_config = (uint64_t *)(upa64s_p->config_base +
		    UPA64S_UPA1_CONFIG_OFFSET);
		upa64s_p->if_config = (uint64_t *)(upa64s_p->config_base +
		    UPA64S_IF_CONFIG_OFFSET);
		upa64s_p->estar = (uint64_t *)(upa64s_p->config_base +
		    UPA64S_ESTAR_OFFSET);

		if (ddi_regs_map_setup(dip, 1, (caddr_t *)&upa64s_p->imr[0],
		    0, 0, &attr, &upa64s_p->imr_ah[0]) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: failed to map reg2.",
			    ddi_get_name(dip), instance);
			goto fail1;
		}

		if (ddi_regs_map_setup(dip, 2, (caddr_t *)&upa64s_p->imr[1],
		    0, 0, &attr, &upa64s_p->imr_ah[1]) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: failed to map reg3.",
			    ddi_get_name(dip), instance);
			goto fail2;
		}

		/*
		 * Power level of a component is unknown at attach time.
		 * Bring the power level to what is needed for normal operation.
		 */
		upa64s_p->power_level = UPA64S_PM_UNKNOWN;
		if (pm_raise_power(dip, UPA64S_PM_COMP, UPA64S_PM_NORMOP) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: failed to raise the power.",
			    ddi_get_name(dip), instance);
			goto fail3;
		}

		intr_dist_add(upa64s_intrdist, dip);

		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:

		upa64s_p = get_upa64s_soft_state(ddi_get_instance(dip));
		DBG(D_ATTACH, dip, "DDI_RESUME\n");
		restore_state(upa64s_p);

		/*
		 * Power level of a component is unknown at resume time.
		 * Bring the power level to what it was before suspend.
		 */
		upa64s_p->power_level = UPA64S_PM_UNKNOWN;
		if (pm_raise_power(dip, UPA64S_PM_COMP,
		    upa64s_p->saved_power_level) != DDI_SUCCESS)
			cmn_err(CE_WARN, "%s%d: failed to change power level "
			    "during resume!", ddi_get_name(dip), instance);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

fail3:
	ddi_regs_map_free(&upa64s_p->imr_ah[1]);
fail2:
	ddi_regs_map_free(&upa64s_p->imr_ah[0]);
fail1:
	ddi_regs_map_free(&upa64s_p->config_base_ah);
fail:
	free_upa64s_soft_state(instance);
	return (DDI_FAILURE);
}


/*
 * detach entry point:
 */
static int
upa64s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	upa64s_devstate_t *upa64s_p = get_upa64s_soft_state(instance);

	switch (cmd) {
	case DDI_DETACH:

		DBG(D_DETACH, dip, "DDI_DETACH\n");

		/*
		 * Power down the device.
		 */
		if (pm_lower_power(dip, UPA64S_PM_COMP, UPA64S_PM_RESET) !=
		    DDI_SUCCESS)
			DBG(D_DETACH, dip, "failed to power off!\n");

		intr_dist_rem(upa64s_intrdist, dip);

		ddi_regs_map_free(&upa64s_p->config_base_ah);
		ddi_regs_map_free(&upa64s_p->imr_ah[0]);
		ddi_regs_map_free(&upa64s_p->imr_ah[1]);
		free_upa64s_soft_state(instance);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:

		DBG(D_DETACH, dip, "DDI_SUSPEND\n");
		save_state(upa64s_p);
		upa64s_p->saved_power_level = upa64s_p->power_level;
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*
 * power entry point:
 *
 * This entry point is called by Power Management framework to
 * reset upa bus and slow down/speed up the upa interface of
 * Schizo chip.
 */
static int
upa64s_power(dev_info_t *dip, int component, int level)
{
	int instance = ddi_get_instance(dip);
	upa64s_devstate_t *upa64s_p = get_upa64s_soft_state(instance);
	volatile uint64_t uint64_data;

	DBG2(D_POWER, dip, "component=%d, level=%d\n", component, level);
	if (component != UPA64S_PM_COMP ||
	    level < UPA64S_PM_RESET || level > UPA64S_PM_NORMOP)
		return (DDI_FAILURE);

	/*
	 * We can't set the hardware to the state that it is
	 * already in.  So if the power state is not known, inquire the
	 * state of the hardware.  If it is already in that state,
	 * record and return, otherwise make the state change.
	 */
	if (upa64s_p->power_level == UPA64S_PM_UNKNOWN) {
		uint64_data = ddi_get64(upa64s_p->config_base_ah,
		    upa64s_p->if_config);
		if ((level == UPA64S_PM_RESET &&
		    uint64_data == UPA64S_NOT_POK_RST_L) ||
		    (level == UPA64S_PM_NORMOP &&
		    uint64_data == UPA64S_POK_NOT_RST_L)) {
			upa64s_p->power_level = level;
			return (DDI_SUCCESS);
		}
	}

	if (level == upa64s_p->power_level) {
		DBG1(D_POWER, dip, "device is already at power level %d\n",
		    level);
		return (DDI_SUCCESS);
	}


	if (level == UPA64S_PM_RESET) {
		/*
		 * Assert UPA64S_RESET
		 */
		ddi_put64(upa64s_p->config_base_ah, upa64s_p->if_config,
		    UPA64S_POK_RST_L);

		/*
		 * Deassert UPA64S_POK.  Flush the store buffer.
		 */
		ddi_put64(upa64s_p->config_base_ah, upa64s_p->if_config,
		    UPA64S_NOT_POK_RST_L);
		uint64_data = ddi_get64(upa64s_p->config_base_ah,
		    upa64s_p->if_config);

		/*
		 * Internal UPA clock to 1/2 speed
		 */
		ddi_put64(upa64s_p->config_base_ah, upa64s_p->estar,
		    UPA64S_1_2_SPEED);

		/*
		 * Internal UPA clock to 1/64 speed.  Flush the store buffer.
		 */
		ddi_put64(upa64s_p->config_base_ah, upa64s_p->estar,
		    UPA64S_1_64_SPEED);
		uint64_data = ddi_get64(upa64s_p->config_base_ah,
		    upa64s_p->estar);
	} else {
		/*
		 * Internal UPA clock to 1/2 speed
		 */
		ddi_put64(upa64s_p->config_base_ah, upa64s_p->estar,
		    UPA64S_1_2_SPEED);

		/*
		 * Internal UPA clock to full speed.  Flush the store buffer.
		 */
		ddi_put64(upa64s_p->config_base_ah, upa64s_p->estar,
		    UPA64S_FULL_SPEED);
		uint64_data = ddi_get64(upa64s_p->config_base_ah,
		    upa64s_p->estar);

		/*
		 * Assert UPA64S_POK.  Flush the store buffer before
		 * the wait delay.
		 */
		ddi_put64(upa64s_p->config_base_ah, upa64s_p->if_config,
		    UPA64S_POK_RST_L);
		uint64_data = ddi_get64(upa64s_p->config_base_ah,
		    upa64s_p->if_config);

		/*
		 * Delay 20 milliseconds for the signals to settle down.
		 */
		delay(drv_usectohz(20*1000));

		/*
		 * Deassert UPA64S_RESET.  Flush the store buffer.
		 */
		ddi_put64(upa64s_p->config_base_ah, upa64s_p->if_config,
		    UPA64S_POK_NOT_RST_L);
		uint64_data = ddi_get64(upa64s_p->config_base_ah,
		    upa64s_p->if_config);
	}
	upa64s_p->power_level = level;

	return (DDI_SUCCESS);
}

/* bus driver entry points */

/*
 * bus map entry point:
 *
 * 	if map request is for an rnumber
 *		get the corresponding regspec from device node
 * 	build a new regspec in our parent's format
 *	build a new map_req with the new regspec
 *	call up the tree to complete the mapping
 */
static int
upa64s_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t off, off_t len, caddr_t *addrp)
{
	struct regspec regspec;
	ddi_map_req_t p_map_request;
	int rnumber, rval;

	DBG4(D_MAP, dip, "upa64s_map() mp=%x.%x addrp=%x.%08x\n",
	    HI32(mp), LO32(mp), HI32(addrp), LO32(addrp));

	/*
	 * User level mappings are not supported yet.
	 */
	if (mp->map_flags & DDI_MF_USER_MAPPING) {
		DBG2(D_MAP, dip, "rdip=%s%d: no user level mappings yet!\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		return (DDI_ME_UNIMPLEMENTED);
	}

	/*
	 * Now handle the mapping according to its type.
	 */
	switch (mp->map_type) {
	case DDI_MT_REGSPEC:

		/*
		 * We assume the register specification is in PCI format.
		 * We must convert it into a regspec of our parent's
		 * and pass the request to our parent.
		 */
		DBG3(D_MAP, dip, "rdip=%s%d: REGSPEC - handlep=%x\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip),
		    mp->map_handlep);
		rval = xlate_reg_prop(dip, (upa64s_regspec_t *)mp->map_obj.rp,
		    off, len, &regspec);
		break;

	case DDI_MT_RNUMBER:

		/*
		 * Get the "reg" property from the device node and convert
		 * it to our parent's format.
		 */
		DBG4(D_MAP, dip, "rdip=%s%d: rnumber=%x handlep=%x\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip),
		    mp->map_obj.rnumber, mp->map_handlep);
		rnumber = mp->map_obj.rnumber;
		if (rnumber < 0)
			return (DDI_ME_RNUMBER_RANGE);
		rval = get_reg_set(dip, rdip,  rnumber, off, len, &regspec);
		break;

	default:
		return (DDI_ME_INVAL);

	}
	if (rval != DDI_SUCCESS) {
		DBG(D_MAP, dip, "failed on regspec\n\n");
		return (rval);
	}

	/*
	 * Now we have a copy of the upa64s regspec converted to our parent's
	 * format.  Build a new map request based on this regspec and pass
	 * it to our parent.
	 */
	p_map_request = *mp;
	p_map_request.map_type = DDI_MT_REGSPEC;
	p_map_request.map_obj.rp = &regspec;
	rval = ddi_map(dip, &p_map_request, 0, 0, addrp);
	DBG3(D_MAP, dip, "ddi_map returns: rval=%x addrp=%x.%08x\n\n",
	    rval, HI32(*addrp), LO32(*addrp));
	return (rval);
}

/*
 * Translate the UPA devices interrupt property.  This is the only case I
 * know of where the interrupts property is meaningless.  As a result, we
 * just use UPA_BASE_INO as our interrupt value and add to it the upa port id.
 * UPA portid is returned too.
 */
#define	UPA_BASE_INO	0x2a

static int
upa64s_xlate_intr(dev_info_t *rdip, int32_t safariport, uint32_t *intr)
{
	uint32_t ino = UPA_BASE_INO;
	int32_t portid;

	/* Clear the ffb's interrupts property, it's meaningless */
	*intr = 0;

	if ((portid = ddi_getprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
	    "upa-portid", -1)) == -1)
		return (-1);

	ino += portid;

	*intr = UPA64S_MAKE_MONDO(safariport, ino);

	DBG5(D_A_ISPEC, rdip, "upa64s_xlate_intr: rdip=%s%d: upa portid %d "
	    "ino=%x mondo 0x%x\n", ddi_get_name(rdip), ddi_get_instance(rdip),
	    portid, ino, *intr);

	return (portid);
}

/*
 * bus add intrspec entry point:
 */
static int
upa64s_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	int upaport, instance = ddi_get_instance(dip);
	upa64s_devstate_t *upa64s_p = get_upa64s_soft_state(instance);
#ifdef DEBUG
	uint_t (*int_handler)(caddr_t, caddr_t) = hdlp->ih_cb_func;
	caddr_t int_handler_arg1 = hdlp->ih_cb_arg1;
#endif /* DEBUG */
	uint_t cpu_id;
	volatile uint64_t imr_data;

	upaport = upa64s_xlate_intr(rdip, upa64s_p->safari_id,
	    (uint32_t *)&hdlp->ih_vector);

	if (hdlp->ih_vector == 0)
		return (DDI_FAILURE);

	DBG3(D_A_ISPEC, dip,
	    "rdip=%s%d - IDDI_INTR_TYPE_NORMAL, mondo=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), hdlp->ih_vector);

	/*
	 * Make sure an interrupt handler isn't already installed.
	 */
	if (upa64s_p->ino_state[upaport] != INO_FREE) {
		return (DDI_FAILURE);
	}

	/*
	 * Install the handler in the system table.
	 */
#ifdef	DEBUG
	DBG2(D_A_ISPEC, dip, "i_ddi_add_ivintr: hdlr=%p arg=%p\n",
	    int_handler, int_handler_arg1);
#endif
	if (i_ddi_add_ivintr(hdlp) != DDI_SUCCESS)
		return (DDI_FAILURE);

	cpu_id = intr_dist_cpuid();

	/*
	 * Enable the interrupt through its interrupt mapping register.
	 */
	imr_data = UPA64S_CPUID_TO_IMR(cpu_id);
	imr_data = UPA64S_GET_MAP_REG(hdlp->ih_vector, imr_data);

	DBG4(D_A_ISPEC, dip, "IMR [upaport=%d mapping reg 0x%p] = %x.%x\n",
	    upaport, upa64s_p->imr[upaport], HI32(imr_data), LO32(imr_data));

	ddi_put64(upa64s_p->imr_ah[upaport], upa64s_p->imr[upaport], imr_data);
	/* Read the data back to flush store buffers. */
	imr_data = ddi_get64(upa64s_p->imr_ah[upaport], upa64s_p->imr[upaport]);
	upa64s_p->ino_state[upaport] = INO_INUSE;

	DBG(D_A_ISPEC, dip, "add_intr success!\n");
	return (DDI_SUCCESS);
}


/*
 * bus remove intrspec entry point
 */
static int
upa64s_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	upa64s_devstate_t *upa64s_p =
	    get_upa64s_soft_state(ddi_get_instance(dip));
	int upaport;
#ifndef lint
	volatile uint64_t tmp;
#endif

	/*
	 * Make sure the mondo is valid.
	 */
	upaport = upa64s_xlate_intr(rdip, upa64s_p->safari_id,
	    (uint32_t *)&hdlp->ih_vector);

	if (hdlp->ih_vector == 0)
		return (DDI_FAILURE);

	DBG3(D_R_ISPEC, dip,
	    "rdip=%s%d - IDDI_INTR_TYPE_NORMAL, mondo=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), hdlp->ih_vector);

	if (upa64s_p->ino_state[upaport] != INO_INUSE) {
		return (DDI_FAILURE);
	}

	/* Call up to our parent to handle the removal */
	i_ddi_rem_ivintr(hdlp);

	ddi_put64(upa64s_p->imr_ah[upaport], upa64s_p->imr[upaport], 0);
#ifndef lint
	/* Flush store buffers */
	tmp = ddi_get64(upa64s_p->imr_ah[upaport], upa64s_p->imr[upaport]);
#endif

	upa64s_p->ino_state[upaport] = INO_FREE;
	return (DDI_SUCCESS);
}


/* new intr_ops structure */
static int
upa64_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int	ret = DDI_SUCCESS;

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		*(int *)result = DDI_INTR_FLAG_EDGE;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		/*
		 * We only have slave UPA devices so force the PIL to 5.
		 * this is done since all slave UPA devices have historically
		 * had their PILs set to 5.  Only do it if the PIL is not
		 * being preset.
		 */
		*(int *)result = hdlp->ih_pri ? hdlp->ih_pri : 5;
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
		ret = upa64s_add_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_REMISR:
		ret = upa64s_remove_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_ENABLE:
	case DDI_INTROP_DISABLE:
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
		break;
	case DDI_INTROP_SETCAP:
	case DDI_INTROP_SETMASK:
	case DDI_INTROP_CLRMASK:
	case DDI_INTROP_GETPENDING:
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_SUPPORTED_TYPES:
		/* only support fixed interrupts */
		*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
		    DDI_INTR_TYPE_FIXED : 0;
		break;
	default:
		ret = i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result);
		break;
	}

	return (ret);
}

#ifdef DEBUG
uint_t upa64s_debug_flags = (uint_t)0;

extern void prom_printf(const char *, ...);
#endif

/*
 * control ops entry point:
 *
 * Requests handled completely:
 *	DDI_CTLOPS_INITCHILD	see init_child() for details
 *	DDI_CTLOPS_UNINITCHILD
 *	DDI_CTLOPS_REPORTDEV	see report_dev() for details
 *	DDI_CTLOPS_REGSIZE
 *	DDI_CTLOPS_NREGS
 *
 * All others passed to parent.
 */
static int
upa64s_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t op, void *arg, void *result)
{
	DBG5(D_CTLOPS, dip, "dip=%x.%x rdip=%x.%x op=%x",
	    HI32(dip), LO32(dip), HI32(rdip), LO32(rdip), op);
	DBG4(D_CTLOPS|D_CONT, dip, " arg=%x.%x result=%x.%x\n",
	    HI32(arg), LO32(arg), HI32(result), LO32(result));

	switch (op) {
	case DDI_CTLOPS_INITCHILD:
		DBG2(D_CTLOPS, dip, "DDI_CTLOPS_INITCHILD: rdip=%s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		return (init_child((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		DBG2(D_CTLOPS, dip, "DDI_CTLOPS_UNINITCHILD: rdip=%s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		ddi_set_name_addr((dev_info_t *)arg, NULL);
		ddi_remove_minor_node((dev_info_t *)arg, NULL);
		impl_rem_dev_props((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REPORTDEV:
		DBG2(D_CTLOPS, dip, "DDI_CTLOPS_REPORTDEV: rdip=%s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		return (report_dev(rdip));

	case DDI_CTLOPS_REGSIZE:
		DBG2(D_CTLOPS, dip, "DDI_CTLOPS_REGSIZE: rdip=%s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		*((off_t *)result) = get_reg_set_size(rdip, *((int *)arg));
		return (*((off_t *)result) == -1 ? DDI_FAILURE : DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:
		DBG2(D_CTLOPS, dip, "DDI_CTLOPS_NREGS: rdip=%s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		*((uint_t *)result) = get_nreg_set(rdip);
		return (DDI_SUCCESS);
	}

	/*
	 * Now pass the request up to our parent.
	 */
	DBG3(D_CTLOPS, dip, "passing request to parent: rdip=%s%d op=%x\n\n",
	    ddi_get_name(rdip), ddi_get_instance(rdip), op);
	return (ddi_ctlops(dip, rdip, op, arg, result));
}


/* support routines */

/*
 * get_properties
 *
 * This function is called from the attach routine to get the key
 * properties of the upa64s node.
 *
 * used by: upa64s_attach()
 *
 * return value: none
 */
static int
get_properties(upa64s_devstate_t *upa64s_p, dev_info_t *dip)
{
	int safari_id;

	/*
	 * Get the device's safari id.
	 */
	safari_id = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "portid", -1);
	if (safari_id == -1) {
		int instance = ddi_get_instance(dip);
		panic("%s%d: no portid property", ddi_get_name(dip), instance);
	}
	upa64s_p->safari_id = safari_id;

	return (DDI_SUCCESS);
}


/*
 * save_state
 *
 * This routine saves a copy of the upa64s register state.
 *
 * used by: upa64s_detach() on a suspend operation
 */
static void
save_state(upa64s_devstate_t *upa64s_p)
{
	upa64s_p->imr_data[0] = ddi_get64(upa64s_p->imr_ah[0],
	    upa64s_p->imr[0]);
	upa64s_p->imr_data[1] = ddi_get64(upa64s_p->imr_ah[1],
	    upa64s_p->imr[1]);
}


/*
 * restore_state
 *
 * This routine restores a copy of the upa64s register state.
 *
 * used by: upa64s_attach() on a resume operation
 */
static void
restore_state(upa64s_devstate_t *upa64s_p)
{
#ifndef lint
	volatile uint64_t tmp;
#endif
	ddi_put64(upa64s_p->imr_ah[0], upa64s_p->imr[0],
	    upa64s_p->imr_data[0]);
	ddi_put64(upa64s_p->imr_ah[1], upa64s_p->imr[1],
	    upa64s_p->imr_data[1]);
#ifndef lint
	/* Flush the store buffer */
	tmp = ddi_get64(upa64s_p->imr_ah[0], upa64s_p->imr[0]);
	tmp = ddi_get64(upa64s_p->imr_ah[1], upa64s_p->imr[1]);
#endif
}


/*
 * get_reg_set
 *
 * This routine will get a upa64s format regspec for a given
 * device node and register number.
 *
 * used by: upa64s_map()
 *
 * return value:
 *
 *	DDI_SUCCESS		- on success
 *	DDI_ME_INVAL		- regspec is invalid
 *	DDI_ME_RNUMBER_RANGE	- rnumber out of range
 */
static int
get_reg_set(dev_info_t *dip, dev_info_t *child, int rnumber,
    off_t off, off_t len, struct regspec *rp)
{
	upa64s_regspec_t *upa64s_rp;
	int i, n, rval;

	/*
	 * Get child device "reg" property
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&upa64s_rp, &i) != DDI_SUCCESS)
		return (DDI_ME_RNUMBER_RANGE);

	n = i / (int)sizeof (upa64s_regspec_t);
	if (rnumber >= n) {
		kmem_free(upa64s_rp, i);
		return (DDI_ME_RNUMBER_RANGE);
	}

	/*
	 * Convert each the upa64s format register specification to
	 * out parent format.
	 */
	rval = xlate_reg_prop(dip, &upa64s_rp[rnumber], off, len, rp);
	kmem_free(upa64s_rp, i);
	return (rval);
}


/*
 * xlate_reg_prop
 *
 * This routine converts a upa64s format regspec to a standard
 * regspec containing the corresponding system address.
 *
 * used by: upa64s_map()
 *
 * return value:
 *
 *	DDI_SUCCESS
 *	DDI_FAILURE	- off + len is beyond device address range
 *	DDI_ME_INVAL	- regspec is invalid
 */
static int
xlate_reg_prop(dev_info_t *dip, upa64s_regspec_t *child_rp, off_t off,
    off_t len, struct regspec *rp)
{
	int n_ranges, ranges_len, i;
	uint64_t child_beg, child_end;
	upa64s_ranges_t *range_p, *rng_p;

	DBG4(D_MAP, dip, "upa64s regspec - ((%x,%x) (%x,%x))\n",
	    HI32(child_rp->upa64s_phys), LO32(child_rp->upa64s_phys),
	    HI32(child_rp->upa64s_size), LO32(child_rp->upa64s_size));
	DBG2(D_MAP, dip, "upa64s xlate_reg_prp - off=%lx len=%lx\n", off, len);
#if 0
	/*
	 * both FFB and AFB have broken "reg" properties, all mapping
	 * requests are done through reg-0 with very long offsets.
	 * Hence this safety check is always violated.
	 */
	if (off + len > child_rp->upa64s_size) {
		DBG(D_MAP, dip, "upa64s xlate_reg_prp: bad off + len\n");
		return (DDI_FAILURE);
	}
#endif
	/*
	 * current "struct regspec" only supports 32-bit sizes.
	 */
	if (child_rp->upa64s_size >= (1ull << 32))
		panic("upa64s: reg size must be less than 4 Gb");

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "ranges", (caddr_t)&range_p, &ranges_len) != DDI_SUCCESS) {
		ranges_len = 0;
		cmn_err(CE_WARN, "%s%d: no ranges property",
		    ddi_get_name(dip), ddi_get_instance(dip));
	}

	n_ranges = ranges_len / sizeof (upa64s_regspec_t);
	child_beg = child_rp->upa64s_phys;
#if 0
	/*
	 * again, this safety checking can not be performed.
	 * Hack by adding a pratical max child reg bank length.
	 */
	child_end = child_beg + child_rp->upa64s_size;
#else
#define	UPA64S_MAX_CHILD_LEN	0xe000000
	child_end = child_beg + UPA64S_MAX_CHILD_LEN;
#endif
	for (i = 0, rng_p = range_p; i < n_ranges; i++, rng_p++) {
		uint64_t rng_beg = rng_p->upa64s_child;
		uint64_t rng_end = rng_beg + rng_p->upa64s_size;
		if ((rng_beg <= child_beg) && (rng_end >= child_end)) {
			uint64_t addr = child_beg - rng_beg + off;
			addr += rng_p->upa64s_parent;
			rp->regspec_bustype = HI32(addr);
			rp->regspec_addr = LO32(addr);
			rp->regspec_size = len ? len : child_rp->upa64s_size;
			break;
		}
	}
	if (ranges_len)
		kmem_free(range_p, ranges_len);
	DBG4(D_MAP, dip, "regspec (%x,%x,%x) i=%x\n",
	    rp->regspec_bustype, rp->regspec_addr, rp->regspec_size, i);
	return (i < n_ranges? DDI_SUCCESS : DDI_ME_INVAL);
}


/*
 * report_dev
 *
 * This function is called from our control ops routine on a
 * DDI_CTLOPS_REPORTDEV request.
 */
static int
report_dev(dev_info_t *dip)
{
	if (dip == (dev_info_t *)0)
		return (DDI_FAILURE);
	cmn_err(CE_CONT, "?UPA64S-device: %s@%s, %s #%d\n",
	    ddi_node_name(dip), ddi_get_name_addr(dip),
	    ddi_get_name(dip), ddi_get_instance(dip));
	return (DDI_SUCCESS);
}


/*
 * init_child
 *
 * This function is called from our control ops routine on a
 * DDI_CTLOPS_INITCHILD request.  It builds and sets the device's
 * parent private data area.
 *
 * used by: upa64s_ctlops()
 *
 * return value: none
 */
static int
init_child(dev_info_t *child)
{
	upa64s_regspec_t *child_rp;
	int i;
	char addr[256];
	int32_t portid;

	if ((portid = ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "upa-portid", -1)) == -1)
		return (DDI_FAILURE);

	/*
	 * Set the address portion of the node name based on
	 * the function and device number.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&child_rp, &i) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	(void) sprintf(addr, "%x,%x", portid, LO32(child_rp->upa64s_phys));
	ddi_set_name_addr(child, addr);

	ddi_set_parent_data(child, NULL);
	kmem_free(child_rp, i);
	return (DDI_SUCCESS);
}


/*
 * get_reg_set_size
 *
 * Given a dev info pointer to a child and a register number, this
 * routine returns the size element of that reg set property.
 *
 * used by: upa64s_ctlops() - DDI_CTLOPS_REGSIZE
 *
 * return value: size of reg set on success, -1 on error
 */
static off_t
get_reg_set_size(dev_info_t *child, int rnumber)
{
	upa64s_regspec_t *upa64s_rp;
	uint_t size;
	int i;

	if (rnumber < 0)
		return (-1);

	/*
	 * Get the reg property for the device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&upa64s_rp, &i) != DDI_SUCCESS)
		return (-1);

	if (rnumber >= (i / (int)sizeof (upa64s_regspec_t))) {
		kmem_free(upa64s_rp, i);
		return (-1);
	}

	/*  >4G reg size not supported */
	size = (uint32_t)upa64s_rp[rnumber].upa64s_size;
	kmem_free(upa64s_rp, i);
	return (size);
}


/*
 * get_nreg_set
 *
 * Given a dev info pointer to a child, this routine returns the
 * number of sets in its "reg" property.
 *
 * used by: upa64s_ctlops() - DDI_CTLOPS_NREGS
 *
 * return value: # of reg sets on success, zero on error
 */
static uint_t
get_nreg_set(dev_info_t *child)
{
	upa64s_regspec_t *upa64s_rp;
	int i, n;

	/*
	 * Get the reg property for the device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&upa64s_rp, &i) != DDI_SUCCESS)
		return (0);

	n =  i / (int)sizeof (upa64s_regspec_t);
	kmem_free(upa64s_rp, i);
	return (n);
}


/*
 * upa64s_intrdist
 *
 * The following routine is the callback function for this nexus driver
 * to support interrupt distribution on sun4u systems. When this
 * function is called by the interrupt distribution framework, it will
 * reprogram all the active the mondo registers.
 */
static void
upa64s_intrdist(void *arg)
{
	dev_info_t *dip = (dev_info_t *)arg;
	int instance = ddi_get_instance(dip);
	upa64s_devstate_t *upa64s_p = get_upa64s_soft_state(instance);
	uint_t upaport;

	for (upaport = 0; upaport < UPA64S_PORTS; upaport++) {
		volatile uint64_t *imr;
		volatile uint64_t imr_dat;
		uint_t mondo;
		uint32_t cpuid;

		if (upa64s_p->ino_state[upaport] != INO_INUSE)
			continue;

		imr = upa64s_p->imr[upaport];
		mondo = UPA64S_IMR_TO_MONDO(*imr);
		cpuid = intr_dist_cpuid();
		imr_dat = UPA64S_CPUID_TO_IMR(cpuid);
		imr_dat = UPA64S_GET_MAP_REG(mondo, imr_dat);

		/* Check and re-program cpu target if necessary */
		DBG2(D_INTRDIST, dip, "mondo=%x cpuid=%x\n", mondo, cpuid);
		if (UPA64S_IMR_TO_CPUID(*imr) == cpuid) {
			DBG(D_INTRDIST, dip, "same cpuid\n");
			continue;
		}
		ddi_put64(upa64s_p->imr_ah[upaport], (uint64_t *)imr, imr_dat);
		imr_dat = ddi_get64(upa64s_p->imr_ah[upaport], (uint64_t *)imr);
	}
}


#ifdef DEBUG
static void
upa64s_debug(uint_t flag, dev_info_t *dip, char *fmt,
    uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	char *s = NULL;
	uint_t cont = 0;
	if (flag & D_CONT) {
		flag &= ~D_CONT;
		cont = 1;
	}
	if (!(upa64s_debug_flags & flag))
		return;

	switch (flag) {
	case D_ATTACH:		s = "attach";		break;
	case D_DETACH:		s = "detach";		break;
	case D_POWER:		s = "power";		break;
	case D_MAP:		s = "map";		break;
	case D_CTLOPS:		s = "ctlops";		break;
	case D_G_ISPEC:		s = "get_intrspec";	break;
	case D_A_ISPEC:		s = "add_intrspec";	break;
	case D_R_ISPEC:		s = "remove_intrspec";	break;
	case D_INIT_CLD:	s = "init_child";	break;
	case D_INTRDIST:	s = "intrdist";		break;
	}

	if (s && cont == 0) {
		prom_printf("%s(%d): %s: ", ddi_get_name(dip),
		    ddi_get_instance(dip), s);
	}
	prom_printf(fmt, a1, a2, a3, a4, a5);
}
#endif
