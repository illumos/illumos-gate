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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/cpuvar.h>
#include <sys/ddi_implfuncs.h>
#include <px_csr.h>
#include <px_regs.h>
#include <px_obj.h>
#include <sys/pci_tools.h>
#include <px_tools_var.h>
#include <px_asm_4u.h>
#include <px_lib4u.h>
#include <px_tools_ext.h>

/*
 * Delay needed to have a safe environment envelop any error which could
 * surface.  The larger the number of bridges and switches, the larger the
 * number needed here.
 *
 * The way it works is as follows:
 *
 * An access is done which causes an error.  Fire errors are handled with
 * ontrap protection and usually come in first.  Fabric errors can come in
 * later.
 *
 * px_phys_peek_4u() disables interrupts.  Interrupts are reenabled at the end
 * of that function if no errors have been caught by the trap handler, or by
 * peek_fault() which executes when a fire error occurs.
 *
 * Fabric error messages get put on an event queue but are not processed until
 * interrupts are reenabled.
 *
 * The delay gives time for the fabric errors to be processed by FMA before
 * changing the fm error flag back to DDI_FM_ERR_UNEXPECTED.  If this isn't
 * done, then the fabric error which should be safe can panic the system.
 *
 * Note: this is a workaround until a better solution is found.  While this
 * number is high, given enough bridges and switches in the device path, this
 * workaround can break.  Also, other PIL 15 interrupts besides the ones we are
 * enveloping could delay processing of the interrupt we are trying to protect.
 */

/*
 * Set delay to 10 ms
 */
int pxtool_delay_usec = 10000;

/* Number of inos per root complex. */
int pxtool_num_inos = INTERRUPT_MAPPING_ENTRIES;

/* Mechanism for getting offsets of smaller datatypes aligned in 64 bit long */
typedef union {
	uint64_t u64;
	uint32_t u32;
	uint16_t u16;
	uint8_t u8;
} peek_poke_value_t;

/*
 * Safe C wrapper around assy language routine px_phys_peek_4u
 *
 * Type is TRUE for big endian, FALSE for little endian.
 * Size is 1, 2, 4 or 8 bytes.
 * paddr is the physical address in IO space to access read.
 * value_p is where the value is returned.
 */
static int
pxtool_safe_phys_peek(px_t *px_p, boolean_t type, size_t size, uint64_t paddr,
    uint64_t *value_p)
{
	px_pec_t *pec_p = px_p->px_pec_p;
	pxu_t *pxu_p = (pxu_t *)px_p->px_plat_p;
	on_trap_data_t otd;
	peek_poke_value_t peek_value;
	int err = DDI_SUCCESS;

	mutex_enter(&pec_p->pec_pokefault_mutex);
	pec_p->pec_safeacc_type = DDI_FM_ERR_PEEK;

	pxu_p->pcitool_addr = (caddr_t)(paddr & px_paddr_mask);

	/*
	 * Set up trap handling to make the access safe.
	 *
	 * on_trap works like setjmp.
	 * Set it up to not panic on data access error,
	 * but to call peek_fault instead.
	 * Call px_phys_peek_4u after trap handling is setup.
	 * When on_trap returns FALSE, it has been setup.
	 * When it returns TRUE, an it has caught an error.
	 */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		otd.ot_trampoline = (uintptr_t)&peek_fault;
		err = px_phys_peek_4u(size, paddr, &peek_value.u64, type);
	} else
		err = DDI_FAILURE;

	no_trap();

	/*
	 * Workaround: delay taking down safe access env.
	 * For more info, see comments where pxtool_delay_usec is declared.
	 */
	if ((err == DDI_FAILURE) && (pxtool_delay_usec > 0))
		delay(drv_usectohz(pxtool_delay_usec));

	pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
	pxu_p->pcitool_addr = NULL;
	mutex_exit(&pec_p->pec_pokefault_mutex);

	if (err != DDI_FAILURE) {
		switch (size) {
		case 8:
			*value_p = peek_value.u64;
			break;
		case 4:
			*value_p = (uint64_t)peek_value.u32;
			break;
		case 2:
			*value_p = (uint64_t)peek_value.u16;
			break;
		case 1:
			*value_p = (uint64_t)peek_value.u8;
			break;
		default:
			err = DDI_FAILURE;
		}
	}

	return (err);
}

/*
 * Safe C wrapper around assy language routine px_phys_poke_4u
 *
 * Type is TRUE for big endian, FALSE for little endian.
 * Size is 1,2,4 or 8 bytes.
 * paddr is the physical address in IO space to access read.
 * value contains the value to be written.
 */
static int
pxtool_safe_phys_poke(px_t *px_p, boolean_t type, size_t size, uint64_t paddr,
    uint64_t value)
{
	on_trap_data_t otd;
	pxu_t *pxu_p = (pxu_t *)px_p->px_plat_p;
	px_pec_t *pec_p = px_p->px_pec_p;
	peek_poke_value_t poke_value;
	int err = DDI_SUCCESS;

	switch (size) {
	case 8:
		poke_value.u64 = value;
		break;
	case 4:
		poke_value.u32 = (uint32_t)value;
		break;
	case 2:
		poke_value.u16 = (uint16_t)value;
		break;
	case 1:
		poke_value.u8 = (uint8_t)value;
		break;
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&pec_p->pec_pokefault_mutex);
	pec_p->pec_ontrap_data = &otd;
	pec_p->pec_safeacc_type = DDI_FM_ERR_POKE;
	pxu_p->pcitool_addr = (caddr_t)(paddr & px_paddr_mask);

	/*
	 * on_trap works like setjmp.
	 * Set it up to not panic on data access error,
	 * but to call poke_fault instead.
	 * Call px_phys_poke_4u after trap handling is setup.
	 * When on_trap returns FALSE, it has been setup.
	 * When it returns TRUE, an it has caught an error.
	 */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {

		otd.ot_trampoline = (uintptr_t)&poke_fault;
		err = px_phys_poke_4u(size, paddr, &poke_value.u64, type);
	} else
		err = DDI_FAILURE;

	px_lib_clr_errs(px_p, 0, paddr);

	if (otd.ot_trap & OT_DATA_ACCESS)
		err = DDI_FAILURE;

	/* Take down protected environment. */
	no_trap();
	pec_p->pec_ontrap_data = NULL;

	/*
	 * Workaround: delay taking down safe access env.
	 * For more info, see comments where pxtool_delay_usec is declared.
	 */
	if (pxtool_delay_usec > 0)
		delay(drv_usectohz(pxtool_delay_usec));

	pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
	pxu_p->pcitool_addr = NULL;
	mutex_exit(&pec_p->pec_pokefault_mutex);

	return (err);
}


/*
 * Wrapper around pxtool_safe_phys_peek/poke.
 *
 * Validates arguments and calls pxtool_safe_phys_peek/poke appropriately.
 *
 * Dip is of the nexus,
 * phys_addr is the address to write in physical space.
 * pcitool_status returns more detailed status in addition to a more generic
 * errno-style function return value.
 * other args are self-explanatory.
 *
 * This function assumes that offset, bdf, and acc_attr are current in
 * prg_p.  It also assumes that prg_p->phys_addr is the final phys addr,
 * including offset.
 * This function modifies prg_p status and data.
 */
/*ARGSUSED*/
static int
pxtool_access(px_t *px_p, pcitool_reg_t *prg_p, uint64_t *data_p,
    boolean_t is_write)
{
	dev_info_t *dip = px_p->px_dip;
	uint64_t phys_addr = prg_p->phys_addr;
	boolean_t endian = PCITOOL_ACC_IS_BIG_ENDIAN(prg_p->acc_attr);
	size_t size = PCITOOL_ACC_ATTR_SIZE(prg_p->acc_attr);
	int rval = SUCCESS;

	/* Alignment checking.  Assumes base address is 8-byte aligned. */
	if (!IS_P2ALIGNED(phys_addr, size)) {
		DBG(DBG_TOOLS, dip, "not aligned.\n");
		prg_p->status = PCITOOL_NOT_ALIGNED;

		rval = EINVAL;

	} else if (is_write) {	/* Made it through checks.  Do the access. */

		DBG(DBG_PHYS_ACC, dip,
		    "%d byte %s pxtool_safe_phys_poke at addr 0x%" PRIx64 "\n",
		    size, (endian ? "BE" : "LE"), phys_addr);

		if (pxtool_safe_phys_poke(px_p, endian, size, phys_addr,
		    *data_p) != DDI_SUCCESS) {
			DBG(DBG_PHYS_ACC, dip,
			    "%d byte %s pxtool_safe_phys_poke at addr "
			    "0x%" PRIx64 " failed\n",
			    size, (endian ? "BE" : "LE"), phys_addr);
			prg_p->status = PCITOOL_INVALID_ADDRESS;

			rval = EFAULT;
		}

	} else {	/* Read */

		DBG(DBG_PHYS_ACC, dip,
		    "%d byte %s pxtool_safe_phys_peek at addr 0x%" PRIx64 "\n",
		    size, (endian ? "BE" : "LE"), phys_addr);

		if (pxtool_safe_phys_peek(px_p, endian, size, phys_addr,
		    data_p) != DDI_SUCCESS) {
			DBG(DBG_PHYS_ACC, dip,
			    "%d byte %s pxtool_safe_phys_peek at addr "
			    "0x%" PRIx64 " failed\n",
			    size, (endian ? "BE" : "LE"), phys_addr);
			prg_p->status = PCITOOL_INVALID_ADDRESS;

			rval = EFAULT;
		}
	}
	return (rval);
}


int
pxtool_pcicfg_access(px_t *px_p, pcitool_reg_t *prg_p,
    uint64_t *data_p, boolean_t is_write)
{
	return (pxtool_access(px_p, prg_p, data_p, is_write));
}

int
pxtool_pciiomem_access(px_t *px_p, pcitool_reg_t *prg_p,
    uint64_t *data_p, boolean_t is_write)
{
	return (pxtool_access(px_p, prg_p, data_p, is_write));
}

int
pxtool_dev_reg_ops_platchk(dev_info_t *dip, pcitool_reg_t *prg_p)
{
	/*
	 * Guard against checking a root nexus which is empty.
	 * On some systems this will result in a Fatal Reset.
	 */
	if (ddi_get_child(dip) == NULL) {
		DBG(DBG_TOOLS, dip,
		    "pxtool_dev_reg_ops set/get reg: nexus has no devs!\n");
		prg_p->status = PCITOOL_IO_ERROR;
		return (ENXIO);
	}

	return (SUCCESS);
}

/*
 * Perform register accesses on the nexus device itself.
 */
int
pxtool_bus_reg_ops(dev_info_t *dip, void *arg, int cmd, int mode)
{
	pcitool_reg_t		prg;
	uint64_t		base_addr;
	uint32_t		reglen;
	px_t			*px_p = DIP_TO_STATE(dip);
	px_nexus_regspec_t	*px_rp = NULL;
	uint32_t		numbanks = 0;
	boolean_t		write_flag = B_FALSE;
	uint32_t		rval = 0;

	if (cmd == PCITOOL_NEXUS_SET_REG)
		write_flag = B_TRUE;

	DBG(DBG_TOOLS, dip, "pxtool_bus_reg_ops set/get reg\n");

	/* Read data from userland. */
	if (ddi_copyin(arg, &prg, sizeof (pcitool_reg_t), mode) !=
	    DDI_SUCCESS) {
		DBG(DBG_TOOLS, dip, "Error reading arguments\n");
		return (EFAULT);
	}

	/* Read reg property which contains starting addr and size of banks. */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&px_rp, &reglen) == DDI_SUCCESS) {
		if (((reglen * sizeof (int)) %
		    sizeof (px_nexus_regspec_t)) != 0) {
			DBG(DBG_TOOLS, dip, "reg prop not well-formed");
			prg.status = PCITOOL_REGPROP_NOTWELLFORMED;
			rval = EIO;
			goto done;
		}
	}

	numbanks = (reglen * sizeof (int)) / sizeof (px_nexus_regspec_t);

	/* Bounds check the bank number. */
	if (prg.barnum >= numbanks) {
		prg.status = PCITOOL_OUT_OF_RANGE;
		rval = EINVAL;
		goto done;
	}

	base_addr = px_rp[prg.barnum].phys_addr;
	prg.phys_addr = base_addr + prg.offset;

	DBG(DBG_TOOLS, dip, "pxtool_bus_reg_ops: nexus: base:0x%" PRIx64 ", "
	    "offset:0x%" PRIx64 ", addr:0x%" PRIx64 ", max_offset:"
	    "0x%" PRIx64 "\n",
	    base_addr, prg.offset, prg.phys_addr, px_rp[prg.barnum].size);

	if (prg.offset >= px_rp[prg.barnum].size) {
		prg.status = PCITOOL_OUT_OF_RANGE;
		rval = EINVAL;
		goto done;
	}

	/* Access device.  prg.status is modified. */
	rval = pxtool_access(px_p, &prg, &prg.data, write_flag);

done:
	if (px_rp != NULL)
		ddi_prop_free(px_rp);

	prg.drvr_version = PCITOOL_VERSION;
	if (ddi_copyout(&prg, arg, sizeof (pcitool_reg_t),
	    mode) != DDI_SUCCESS) {
		DBG(DBG_TOOLS, dip, "Copyout failed.\n");
		return (EFAULT);
	}

	return (rval);
}
