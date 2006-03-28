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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/file.h>
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>
#include <sys/sunndi.h>
#include <fpc.h>
#include <fpc-impl.h>
#include <fpc-impl-4v.h>

#define	PCIE_ROOTNEX_COMPATIBLE_NAME	"SUNW,sun4v-pci"

#define	FPC_MODULE_NAME			"fpc"
#define	FPC_REQ_MAJOR_VER		1
#define	FPC_REQ_MINOR_VER		0

static hsvc_info_t fpc_hsvc = {
	HSVC_REV_1,
	NULL,
	HSVC_GROUP_FIRE_PERF,
	FPC_REQ_MAJOR_VER,
	FPC_REQ_MINOR_VER,
	FPC_MODULE_NAME
};

static int hyp_regd_users = 0;
static uint64_t	fpc_sup_minor;

/*
 * The following typedef is used to represent a
 * 1275 "reg" property of a PCI nexus.
 */
typedef struct nexus_regspec {
	uint64_t phys_addr;
	uint64_t size;
} nexus_regspec_t;

static uint64_t counter_select_index[] = {
	HVIO_FIRE_PERFREG_JBC_SEL,
	HVIO_FIRE_PERFREG_PCIE_IMU_SEL,
	HVIO_FIRE_PERFREG_PCIE_MMU_SEL,
	HVIO_FIRE_PERFREG_PCIE_TLU_SEL,
	HVIO_FIRE_PERFREG_PCIE_LNK_SEL
};

/*
 * The following event and offset arrays is organized by grouping in major
 * order the fire_perfcnt_t register types, and in minor order the register
 * numbers within that type.
 */

/*
 * This table maps the above order into the hypervisor interface register
 * indices.
 */
static uint64_t counter_reg_index[] = {
	HVIO_FIRE_PERFREG_JBC_CNT0,
	HVIO_FIRE_PERFREG_JBC_CNT1,
	HVIO_FIRE_PERFREG_PCIE_IMU_CNT0,
	HVIO_FIRE_PERFREG_PCIE_IMU_CNT1,
	HVIO_FIRE_PERFREG_PCIE_MMU_CNT0,
	HVIO_FIRE_PERFREG_PCIE_MMU_CNT1,
	HVIO_FIRE_PERFREG_PCIE_TLU_CNT0,
	HVIO_FIRE_PERFREG_PCIE_TLU_CNT1,
	HVIO_FIRE_PERFREG_PCIE_TLU_CNT2,
	HVIO_FIRE_PERFREG_PCIE_LNK_CNT1,
	HVIO_FIRE_PERFREG_PCIE_LNK_CNT2
};

/* Called by _init to determine if it is OK to install driver. */
int
fpc_platform_check()
{
	int regstat;

	if ((regstat = hsvc_register(&fpc_hsvc, &fpc_sup_minor)) == SUCCESS) {
		(void) hsvc_unregister(&fpc_hsvc);
	}
	fpc_sup_minor = 0;
	return (regstat);
}

/* Called during attach to do module-wide initialization. */
/*ARGSUSED*/
int
fpc_platform_module_init(dev_info_t *dip)
{
	return (DDI_SUCCESS);
}

int
fpc_platform_node_init(dev_info_t *dip, int *avail)
{
	nexus_regspec_t	*rp;
	uint_t reglen;
	devhandle_t dev_hdl;
	int regstat;
	int index;
	boolean_t is_root_pcie_nexus;
	uint64_t dummy_data;
	char *name = NULL;
	boolean_t jbus_regs_avail;
	boolean_t pcie_regs_avail;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "compatible", &name) != DDI_PROP_SUCCESS)
		return (DDI_SUCCESS);

	is_root_pcie_nexus = (strcmp(name, PCIE_ROOTNEX_COMPATIBLE_NAME) == 0);
	ddi_prop_free(name);
	if (!is_root_pcie_nexus)
		return (DDI_SUCCESS);

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (uchar_t **)&rp, &reglen) !=
	    DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Initilize device handle. The device handle uniquely
	 * identifies a SUN4V device. It consists of the lower 28-bits
	 * of the hi-cell of the first entry of the SUN4V device's
	 * "reg" property as defined by the SUN4V Bus Binding to Open
	 * Firmware.
	 */
	dev_hdl = (devhandle_t)((rp->phys_addr >> 32) & DEVHDLE_MASK);

	ddi_prop_free(rp);

	/*
	 * If this is the first time through here, negotiate with hypervisor
	 * that it has the services needed to operate.  Don't do this in _init
	 * since we may want to modload the driver without attaching,
	 * for debugging purposes.
	 *
	 * Note that this is another way of weeding out unsupported platforms
	 */
	if (hyp_regd_users == 0) {
		regstat = hsvc_register(&fpc_hsvc, &fpc_sup_minor);
		if (regstat != SUCCESS) {
			/*
			 * Fail silently since we don't want to print an error
			 * on future platforms which don't support this driver.
			 */
			return (DDI_FAILURE);
		}
	}
	hyp_regd_users++;

	/* See which register sets are usable from this node. */
	jbus_regs_avail = (fpc_event_io(
	    (fire_perfreg_handle_t)dev_hdl, jbc, &dummy_data, IS_READ) ==
	    SUCCESS);
	pcie_regs_avail = (fpc_event_io(
	    (fire_perfreg_handle_t)dev_hdl, imu, &dummy_data, IS_READ) ==
	    SUCCESS);

	/* Nothing usable at this node. */
	if ((!jbus_regs_avail) && (!pcie_regs_avail))
		return (DDI_SUCCESS);

	fpc_common_node_setup(dip, &index);
	if (pcie_regs_avail)
		*avail |=
		    ((index == 0) ? PCIE_A_REGS_AVAIL : PCIE_B_REGS_AVAIL);
	if (jbus_regs_avail) {
		*avail |= JBUS_REGS_AVAIL;
		if (index != 0)
			cmn_err(CE_WARN,
			    "fpc: JBUS regs available on device idx %d!\n",
			    index);
	}

	(void) fpc_set_platform_data_by_number(index, (void *)dev_hdl);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
fpc_platform_node_fini(void *arg)
{
	if (--hyp_regd_users == 0)
		(void) hsvc_unregister(&fpc_hsvc);
}

/*ARGSUSED*/
void
fpc_platform_module_fini(dev_info_t *dip)
{
}

fire_perfreg_handle_t
fpc_get_perfreg_handle(int devnum)
{
	void *platform_specific_data;

	if ((platform_specific_data =
	    fpc_get_platform_data_by_number(devnum)) == NULL)
		return ((fire_perfreg_handle_t)-1);
	else
		return ((fire_perfreg_handle_t)platform_specific_data);
}

/*ARGSUSED*/
int
fpc_free_counter_handle(fire_perfreg_handle_t handle)
{
	return (SUCCESS);
}

static int
fpc_hv_perfreg_io(fire_perfreg_handle_t handle, uint64_t hv_if_index,
    uint64_t *reg_data, boolean_t is_write)
{
	int rval;
	devhandle_t dev_hdl = (devhandle_t)handle;

	if (is_write)
		rval = fpc_set_fire_perfreg(dev_hdl, hv_if_index, *reg_data);
	else
		rval = fpc_get_fire_perfreg(dev_hdl, hv_if_index, reg_data);

	return ((rval == H_EOK) ? SUCCESS : EIO);
}

int
fpc_event_io(fire_perfreg_handle_t handle, fire_perfcnt_t group,
    uint64_t *reg_data, boolean_t is_write)
{
	uint64_t hv_if_index = counter_select_index[group];
	return (fpc_hv_perfreg_io(handle, hv_if_index, reg_data, is_write));
}


/*ARGSUSED*/
int
fpc_counter_io(fire_perfreg_handle_t handle, fire_perfcnt_t group,
    int counter_index, uint64_t *reg_data, boolean_t is_write)
{
	uint64_t hv_if_index = counter_reg_index[counter_index];
	return (fpc_hv_perfreg_io(handle, hv_if_index, reg_data, is_write));
}
