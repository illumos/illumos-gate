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

#include <sys/file.h>
#include <sys/sunndi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <io/px/px_regs.h>
#include <sys/pci_tools.h>
#include <fpc.h>
#include <fpc-impl.h>

#define	CHIP_COMPATIBLE_NAME	"pciex108e,80f0"
#define	BANK_ADDR_MASK		0x7FFFFF

#define	OPEN_FLAGS (FREAD | FWRITE)

#define	PCIE_BANK	0
#define	JBUS_BANK	1

typedef struct px_regs {
	uint32_t addr_hi;
	uint32_t addr_lo;
	uint32_t size_hi;
	uint32_t size_lo;
} px_regs_t;

/* There is one of these for every root nexus device found */
typedef struct fire4u_specific {
	char *nodename;
	uintptr_t jbus_bank_base;
} fire4u_specific_t;

typedef struct fire_counter_handle_impl {
	ldi_handle_t devhandle;
	fire4u_specific_t *devspec; /* Points to proper one for specific dev. */
} fire_counter_handle_impl_t;

static uint64_t counter_select_offsets[] = {
	JBC_PERFORMANCE_COUNTER_SELECT,
	IMU_PERFORMANCE_COUNTER_SELECT,
	MMU_PERFORMANCE_COUNTER_SELECT,
	TLU_PERFORMANCE_COUNTER_SELECT,
	LPU_LINK_PERFORMANCE_COUNTER_SELECT
};

/*
 * The following event and offset arrays is organized by grouping in major
 * order the fire_perfcnt_t register types, and in minor order the register
 * numbers within that type.
 */

static uint64_t counter_reg_offsets[] = {
	JBC_PERFORMANCE_COUNTER_ZERO,
	JBC_PERFORMANCE_COUNTER_ONE,
	IMU_PERFORMANCE_COUNTER_ZERO,
	IMU_PERFORMANCE_COUNTER_ONE,
	MMU_PERFORMANCE_COUNTER_ZERO,
	MMU_PERFORMANCE_COUNTER_ONE,
	TLU_PERFORMANCE_COUNTER_ZERO,
	TLU_PERFORMANCE_COUNTER_ONE,
	TLU_PERFORMANCE_COUNTER_TWO,
	LPU_LINK_PERFORMANCE_COUNTER1,
	LPU_LINK_PERFORMANCE_COUNTER2
};

/*
 * Add the following to one of the LPU_LINK_PERFORMANCE_COUNTERx offsets to
 * write a value to that counter.
 */
#define	LPU_LINK_PERFCTR_WRITE_OFFSET	0x8

/*
 * Note that LPU_LINK_PERFORMANCE_COUNTER_CONTROL register is hard-reset to
 * zeros and this is the value we want.  This register isn't touched by this
 * module, and as long as it remains untouched by other modules we're OK.
 */

static ldi_ident_t ldi_identifier;
static boolean_t ldi_identifier_valid = B_FALSE;
static cred_t *credentials = NULL;

/* Called by _init to determine if it is OK to install driver. */
int
fpc_platform_check()
{
	return (SUCCESS);
}

/* Called during attach to do module-wide initialization. */
int
fpc_platform_module_init(dev_info_t *dip)
{
	int status;

	credentials = crget();
	status = ldi_ident_from_dip(dip, &ldi_identifier);
	if (status == 0)
		ldi_identifier_valid = B_TRUE;
	return ((status == 0) ? DDI_SUCCESS : DDI_FAILURE);
}

int
fpc_platform_node_init(dev_info_t *dip, int *avail)
{
	int index;
	char *name;
	int nodename_size;
	char *nodename = NULL;
	fire4u_specific_t *platform_specific_data = NULL;
	char *compatible = NULL;
	px_regs_t *regs_p = NULL;
	int regs_length = 0;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "compatible", &compatible) != DDI_PROP_SUCCESS)
		return (DDI_SUCCESS);

	if (strcmp(compatible, CHIP_COMPATIBLE_NAME) != 0) {
		ddi_prop_free(compatible);
		return (DDI_SUCCESS);
	}
	ddi_prop_free(compatible);

	fpc_common_node_setup(dip, &index);

	name = fpc_get_dev_name_by_number(index);
	nodename_size = strlen(name) + strlen(PCI_MINOR_REG) + 2;
	nodename = kmem_zalloc(nodename_size, KM_SLEEP);

	platform_specific_data =
	    kmem_zalloc(sizeof (fire4u_specific_t), KM_SLEEP);

	(void) strcpy(nodename, name);
	(void) strcat(nodename, ":");
	(void) strcat(nodename, PCI_MINOR_REG);
	platform_specific_data->nodename = nodename;

	/* Get register banks. */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&regs_p, &regs_length) != DDI_SUCCESS) {
		goto bad_regs_p;
	}

	if ((regs_length / sizeof (px_regs_t)) < 2) {
		goto bad_regs_length;
	}

	platform_specific_data->jbus_bank_base =
	    regs_p[JBUS_BANK].addr_lo & BANK_ADDR_MASK;

	kmem_free(regs_p, regs_length);

	if (index == 0)
		*avail |= (PCIE_A_REGS_AVAIL | JBUS_REGS_AVAIL);
	else
		*avail |= PCIE_B_REGS_AVAIL;

	(void) fpc_set_platform_data_by_number(index, platform_specific_data);

	return (DDI_SUCCESS);

bad_regs_length:
	if (regs_p)
		kmem_free(regs_p, regs_length);
bad_regs_p:
	kmem_free(platform_specific_data, sizeof (fire4u_specific_t));
	if (nodename)
		kmem_free(nodename, nodename_size);

	return (DDI_FAILURE);
}

void
fpc_platform_node_fini(void *arg)
{
	fire4u_specific_t *plat_arg = (fire4u_specific_t *)arg;
	if (plat_arg == NULL)
		return;
	if (plat_arg->nodename)
		kmem_free(plat_arg->nodename, strlen(plat_arg->nodename)+1);
	kmem_free(plat_arg, sizeof (fire4u_specific_t));
}

/*ARGSUSED*/
void
fpc_platform_module_fini(dev_info_t *dip)
{
	if (ldi_identifier_valid)
		ldi_ident_release(ldi_identifier);
	if (credentials)
		crfree(credentials);
}

fire_perfreg_handle_t
fpc_get_perfreg_handle(int devnum)
{
	int rval = EINVAL;

	fire_counter_handle_impl_t *handle_impl =
	    kmem_zalloc(sizeof (fire_counter_handle_impl_t), KM_SLEEP);

	if ((handle_impl->devspec =
	    fpc_get_platform_data_by_number(devnum)) != NULL) {
		rval = ldi_open_by_name(handle_impl->devspec->nodename,
		    OPEN_FLAGS, credentials, &handle_impl->devhandle,
		    ldi_identifier);
	}

	if (rval != SUCCESS) {
		kmem_free(handle_impl, sizeof (fire_counter_handle_impl_t));
		return ((fire_perfreg_handle_t)-1);
	} else {
		return ((fire_perfreg_handle_t)handle_impl);
	}
}

int
fpc_free_counter_handle(fire_perfreg_handle_t handle)
{
	fire_counter_handle_impl_t *handle_impl =
	    (fire_counter_handle_impl_t *)handle;
	(void) ldi_close(handle_impl->devhandle, OPEN_FLAGS, credentials);
	kmem_free(handle_impl, sizeof (fire_counter_handle_impl_t));
	return (SUCCESS);
}

int
fpc_event_io(fire_perfreg_handle_t handle, fire_perfcnt_t group,
    uint64_t *reg_data, boolean_t is_write)
{
	int rval;
	int ioctl_rval;
	pcitool_reg_t prg;
	fire_counter_handle_impl_t *handle_impl =
	    (fire_counter_handle_impl_t *)handle;
	int cmd = is_write ? PCITOOL_NEXUS_SET_REG : PCITOOL_NEXUS_GET_REG;

	prg.user_version = PCITOOL_VERSION;

	if (group == jbc) {
		prg.barnum = JBUS_BANK;
		prg.offset = counter_select_offsets[group] -
		    handle_impl->devspec->jbus_bank_base;
	} else {
		prg.barnum = PCIE_BANK;

		/*
		 * Note that a pcie_bank_base isn't needed.  Pcie register
		 * offsets are already relative to the start of their bank.  No
		 * base needs to be subtracted to get the relative offset that
		 * pcitool ioctls want.
		 */
		prg.offset = counter_select_offsets[group];
	}
	prg.acc_attr = PCITOOL_ACC_ATTR_SIZE_8 | PCITOOL_ACC_ATTR_ENDN_BIG;
	prg.data = *reg_data;

	/* Read original value. */
	if (((rval = ldi_ioctl(handle_impl->devhandle, cmd, (intptr_t)&prg,
	    FKIOCTL, credentials, &ioctl_rval)) == SUCCESS) && (!is_write)) {
		*reg_data = prg.data;
	}

	return (rval);
}

int
fpc_counter_io(fire_perfreg_handle_t handle, fire_perfcnt_t group,
    int counter_index, uint64_t *value, boolean_t is_write)
{
	int rval;
	int ioctl_rval;
	pcitool_reg_t prg;
	fire_counter_handle_impl_t *handle_impl =
	    (fire_counter_handle_impl_t *)handle;
	int command =
	    (is_write) ? PCITOOL_NEXUS_SET_REG : PCITOOL_NEXUS_GET_REG;

	prg.user_version = PCITOOL_VERSION;
	/*
	 * Note that stated PCIE offsets are relative to the beginning of their
	 * register bank, while JBUS offsets are absolute.
	 */
	if (group == jbc) {
		prg.barnum = JBUS_BANK;
		prg.offset = counter_reg_offsets[counter_index] -
		    handle_impl->devspec->jbus_bank_base;
	} else {
		prg.barnum = PCIE_BANK;
		prg.offset = counter_reg_offsets[counter_index];
	}

	if ((group == lpu) && (is_write)) {
		prg.offset += LPU_LINK_PERFCTR_WRITE_OFFSET;
	}

	prg.acc_attr = PCITOOL_ACC_ATTR_SIZE_8 | PCITOOL_ACC_ATTR_ENDN_BIG;
	prg.data = *value;

	if (((rval = ldi_ioctl(handle_impl->devhandle, command, (intptr_t)&prg,
	    FKIOCTL, credentials, &ioctl_rval)) == SUCCESS) && (!is_write)) {
		*value = prg.data;
	}

	return (rval);
}
