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

#include <sys/sunddi.h>
#include <sys/amd_iommu.h>
#include "amd_iommu_impl.h"

extern int servicing_interrupt(void);

static void
amd_iommu_wait_for_completion(amd_iommu_t *iommu)
{
	ASSERT(MUTEX_HELD(&iommu->aiomt_cmdlock));
	while (AMD_IOMMU_REG_GET64(REGADDR64(
	    iommu->aiomt_reg_status_va), AMD_IOMMU_COMWAIT_INT) != 1) {
		AMD_IOMMU_REG_SET64(REGADDR64(iommu->aiomt_reg_ctrl_va),
		    AMD_IOMMU_CMDBUF_ENABLE, 1);
		WAIT_SEC(1);
	}
}

static int
create_compl_wait_cmd(amd_iommu_t *iommu, amd_iommu_cmdargs_t *cmdargsp,
    amd_iommu_cmd_flags_t flags, uint32_t *cmdptr)
{
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "create_compl_wait_cmd";

	ASSERT(cmdargsp == NULL);

	if (flags & AMD_IOMMU_CMD_FLAGS_COMPL_WAIT_S) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: 'store' completion "
		    "not supported for completion wait command",
		    f, driver, instance, iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	AMD_IOMMU_REG_SET32(&cmdptr[0], AMD_IOMMU_CMD_COMPL_WAIT_S, 0);
	AMD_IOMMU_REG_SET32(&cmdptr[0], AMD_IOMMU_CMD_COMPL_WAIT_I, 1);
	AMD_IOMMU_REG_SET32(&cmdptr[0], AMD_IOMMU_CMD_COMPL_WAIT_F,
	    (flags & AMD_IOMMU_CMD_FLAGS_COMPL_WAIT_F) != 0);
	AMD_IOMMU_REG_SET32(&cmdptr[0], AMD_IOMMU_CMD_COMPL_WAIT_STORE_ADDR_LO,
	    0);
	AMD_IOMMU_REG_SET32(&cmdptr[1], AMD_IOMMU_CMD_OPCODE, 0x01);
	AMD_IOMMU_REG_SET32(&cmdptr[1], AMD_IOMMU_CMD_COMPL_WAIT_STORE_ADDR_HI,
	    0);
	cmdptr[2] = 0;
	cmdptr[3] = 0;

	return (DDI_SUCCESS);
}

static int
create_inval_devtab_entry_cmd(amd_iommu_t *iommu, amd_iommu_cmdargs_t *cmdargsp,
    amd_iommu_cmd_flags_t flags, uint32_t *cmdptr)
{
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "create_inval_devtab_entry_cmd";
	uint16_t deviceid;

	ASSERT(cmdargsp);

	if (flags != AMD_IOMMU_CMD_FLAGS_NONE) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: invalidate devtab entry "
		    "no flags supported", f, driver, instance,
		    iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	deviceid = cmdargsp->ca_deviceid;

	AMD_IOMMU_REG_SET32(&cmdptr[0], AMD_IOMMU_CMD_INVAL_DEVTAB_DEVICEID,
	    deviceid);
	AMD_IOMMU_REG_SET32(&cmdptr[1], AMD_IOMMU_CMD_OPCODE, 0x02);
	cmdptr[2] = 0;
	cmdptr[3] = 0;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
create_inval_iommu_pages_cmd(amd_iommu_t *iommu, amd_iommu_cmdargs_t *cmdargsp,
    amd_iommu_cmd_flags_t flags, uint32_t *cmdptr)
{
	uint32_t addr_lo;
	uint32_t addr_hi;

	ASSERT(cmdargsp);

	addr_lo = AMD_IOMMU_REG_GET64(REGADDR64(&cmdargsp->ca_addr),
	    AMD_IOMMU_CMD_INVAL_PAGES_ADDR_LO);
	addr_hi = AMD_IOMMU_REG_GET64(REGADDR64(&cmdargsp->ca_addr),
	    AMD_IOMMU_CMD_INVAL_PAGES_ADDR_HI);

	cmdptr[0] = 0;
	AMD_IOMMU_REG_SET32(&cmdptr[1], AMD_IOMMU_CMD_INVAL_PAGES_DOMAINID,
	    cmdargsp->ca_domainid);
	AMD_IOMMU_REG_SET32(&cmdptr[1], AMD_IOMMU_CMD_OPCODE, 0x03);
	AMD_IOMMU_REG_SET32(&cmdptr[2], AMD_IOMMU_CMD_INVAL_PAGES_PDE,
	    (flags & AMD_IOMMU_CMD_FLAGS_PAGE_PDE_INVAL) != 0);
	AMD_IOMMU_REG_SET32(&cmdptr[2], AMD_IOMMU_CMD_INVAL_PAGES_S,
	    (flags & AMD_IOMMU_CMD_FLAGS_PAGE_INVAL_S) != 0);
	AMD_IOMMU_REG_SET32(&cmdptr[2], AMD_IOMMU_CMD_INVAL_PAGES_ADDR_LO,
	    addr_lo);
	cmdptr[3] = addr_hi;

	return (DDI_SUCCESS);

}

/*ARGSUSED*/
static int
create_inval_iotlb_pages_cmd(amd_iommu_t *iommu, amd_iommu_cmdargs_t *cmdargsp,
    amd_iommu_cmd_flags_t flags, uint32_t *cmdptr)
{
	uint32_t addr_lo;
	uint32_t addr_hi;

	ASSERT(cmdargsp);

	addr_lo = AMD_IOMMU_REG_GET64(REGADDR64(&cmdargsp->ca_addr),
	    AMD_IOMMU_CMD_INVAL_IOTLB_ADDR_LO);

	addr_hi = AMD_IOMMU_REG_GET64(REGADDR64(&cmdargsp->ca_addr),
	    AMD_IOMMU_CMD_INVAL_IOTLB_ADDR_HI);

	AMD_IOMMU_REG_SET32(&cmdptr[0], AMD_IOMMU_CMD_INVAL_IOTLB_DEVICEID,
	    cmdargsp->ca_deviceid);
	AMD_IOMMU_REG_SET32(&cmdptr[0], AMD_IOMMU_CMD_INVAL_IOTLB_MAXPEND,
	    AMD_IOMMU_DEFAULT_MAXPEND);
	AMD_IOMMU_REG_SET32(&cmdptr[1], AMD_IOMMU_CMD_OPCODE, 0x04);
	AMD_IOMMU_REG_SET32(&cmdptr[1], AMD_IOMMU_CMD_INVAL_IOTLB_QUEUEID,
	    cmdargsp->ca_deviceid);
	AMD_IOMMU_REG_SET32(&cmdptr[2], AMD_IOMMU_CMD_INVAL_IOTLB_ADDR_LO,
	    addr_lo);
	AMD_IOMMU_REG_SET32(&cmdptr[2], AMD_IOMMU_CMD_INVAL_IOTLB_S,
	    (flags & AMD_IOMMU_CMD_FLAGS_IOTLB_INVAL_S) != 0);
	cmdptr[3] = addr_hi;

	return (DDI_SUCCESS);
}

static int
create_inval_intr_table_cmd(amd_iommu_t *iommu, amd_iommu_cmdargs_t *cmdargsp,
    amd_iommu_cmd_flags_t flags, uint32_t *cmdptr)
{
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "create_inval_intr_table_cmd";

	ASSERT(cmdargsp);

	if (flags != AMD_IOMMU_CMD_FLAGS_NONE) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: flags not supported "
		    "for invalidate interrupt table command",
		    f, driver, instance, iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	AMD_IOMMU_REG_SET32(&cmdptr[0], AMD_IOMMU_CMD_INVAL_INTR_DEVICEID,
	    cmdargsp->ca_deviceid);
	AMD_IOMMU_REG_SET32(&cmdptr[1], AMD_IOMMU_CMD_OPCODE, 0x05);
	cmdptr[2] = 0;
	cmdptr[3] = 0;

	return (DDI_SUCCESS);
}

int
amd_iommu_cmd(amd_iommu_t *iommu, amd_iommu_cmd_t cmd,
    amd_iommu_cmdargs_t *cmdargs, amd_iommu_cmd_flags_t flags, int lock_held)
{
	int error;
	int i;
	uint32_t cmdptr[4] = {0};
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	uint64_t cmdhead_off;
	uint64_t cmdtail_off;
	const char *f = "amd_iommu_cmd";

	ASSERT(lock_held == 0 || lock_held == 1);
	ASSERT(lock_held == 0 || MUTEX_HELD(&iommu->aiomt_cmdlock));

	if (!lock_held)
		mutex_enter(&iommu->aiomt_cmdlock);

	/*
	 * Prepare the command
	 */
	switch (cmd) {
	case AMD_IOMMU_CMD_COMPL_WAIT:
		if (flags & AMD_IOMMU_CMD_FLAGS_COMPL_WAIT) {
			cmn_err(CE_WARN, "%s: %s%d: idx=%d: No completion wait "
			    " after completion wait command",
			    f, driver, instance, iommu->aiomt_idx);
			error = DDI_FAILURE;
			goto out;
		}
		error = create_compl_wait_cmd(iommu, cmdargs, flags, cmdptr);
		break;
	case AMD_IOMMU_CMD_INVAL_DEVTAB_ENTRY:
		error = create_inval_devtab_entry_cmd(iommu, cmdargs,
		    flags & ~AMD_IOMMU_CMD_FLAGS_COMPL_WAIT, cmdptr);
		break;
	case AMD_IOMMU_CMD_INVAL_IOMMU_PAGES:
		error = create_inval_iommu_pages_cmd(iommu, cmdargs,
		    flags & ~AMD_IOMMU_CMD_FLAGS_COMPL_WAIT, cmdptr);
		break;
	case AMD_IOMMU_CMD_INVAL_IOTLB_PAGES:
		error = create_inval_iotlb_pages_cmd(iommu, cmdargs,
		    flags & ~AMD_IOMMU_CMD_FLAGS_COMPL_WAIT, cmdptr);
		break;
	case AMD_IOMMU_CMD_INVAL_INTR_TABLE:
		error = create_inval_intr_table_cmd(iommu, cmdargs,
		    flags & ~AMD_IOMMU_CMD_FLAGS_COMPL_WAIT, cmdptr);
		break;
	default:
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: Unsupported cmd: %d",
		    f, driver, instance, iommu->aiomt_idx, cmd);
		error = DDI_FAILURE;
		goto out;
	}

	if (error != DDI_SUCCESS) {
		error = DDI_FAILURE;
		goto out;
	}

	AMD_IOMMU_REG_SET64(REGADDR64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_CMDBUF_ENABLE, 1);

	ASSERT(iommu->aiomt_cmd_tail != NULL);

	for (i = 0; i < 4; i++) {
		iommu->aiomt_cmd_tail[i] = cmdptr[i];
	}

wait_for_drain:
	cmdhead_off = AMD_IOMMU_REG_GET64(
	    REGADDR64(iommu->aiomt_reg_cmdbuf_head_va),
	    AMD_IOMMU_CMDHEADPTR);

	cmdhead_off = CMD2OFF(cmdhead_off);

	ASSERT(cmdhead_off < iommu->aiomt_cmdbuf_sz);

	/* check for overflow */
	if ((caddr_t)iommu->aiomt_cmd_tail <
	    (cmdhead_off + iommu->aiomt_cmdbuf)) {
		if ((caddr_t)iommu->aiomt_cmd_tail + 16 >=
		    (cmdhead_off + iommu->aiomt_cmdbuf))
#ifdef DEBUG
			cmn_err(CE_WARN, "cmdbuffer overflow: waiting for "
			    "drain");
#endif
			goto wait_for_drain;
	}

	SYNC_FORDEV(iommu->aiomt_dmahdl);

	/*
	 * Update the tail pointer in soft state
	 * and the tail pointer register
	 */
	iommu->aiomt_cmd_tail += 4;
	if ((caddr_t)iommu->aiomt_cmd_tail >= (iommu->aiomt_cmdbuf
	    + iommu->aiomt_cmdbuf_sz)) {
		/* wraparound */
		/*LINTED*/
		iommu->aiomt_cmd_tail = (uint32_t *)iommu->aiomt_cmdbuf;
		cmdtail_off = 0;
	} else {
		cmdtail_off = (caddr_t)iommu->aiomt_cmd_tail
		/*LINTED*/
		    - iommu->aiomt_cmdbuf;
	}

	ASSERT(cmdtail_off < iommu->aiomt_cmdbuf_sz);

	AMD_IOMMU_REG_SET64(REGADDR64(iommu->aiomt_reg_cmdbuf_tail_va),
	    AMD_IOMMU_CMDTAILPTR, OFF2CMD(cmdtail_off));

	if (cmd == AMD_IOMMU_CMD_COMPL_WAIT) {
		amd_iommu_wait_for_completion(iommu);
	} else if (flags & AMD_IOMMU_CMD_FLAGS_COMPL_WAIT) {
		error = amd_iommu_cmd(iommu, AMD_IOMMU_CMD_COMPL_WAIT,
		    NULL, 0, 1);
	}

out:
	if (!lock_held)
		mutex_exit(&iommu->aiomt_cmdlock);
	return (error);
}
