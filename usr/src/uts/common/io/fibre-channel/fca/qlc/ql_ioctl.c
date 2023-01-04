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

/* Copyright 2010 QLogic Corporation */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver source file.
 * Fibre Channel Adapter (FCA) driver IOCTL source file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2010 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#include <ql_apps.h>
#include <ql_api.h>
#include <ql_debug.h>
#include <ql_init.h>
#include <ql_ioctl.h>
#include <ql_mbx.h>
#include <ql_xioctl.h>

/*
 * Local Function Prototypes.
 */
static int ql_busy_notification(ql_adapter_state_t *);
static int ql_idle_notification(ql_adapter_state_t *);
static int ql_get_feature_bits(ql_adapter_state_t *ha, uint16_t *features);
static int ql_set_feature_bits(ql_adapter_state_t *ha, uint16_t features);
static int ql_set_nvram_adapter_defaults(ql_adapter_state_t *ha);
static void ql_load_nvram(ql_adapter_state_t *ha, uint8_t addr,
    uint16_t value);
static int ql_24xx_load_nvram(ql_adapter_state_t *, uint32_t, uint32_t);
static int ql_adm_op(ql_adapter_state_t *, void *, int);
static int ql_adm_adapter_info(ql_adapter_state_t *, ql_adm_op_t *, int);
static int ql_adm_extended_logging(ql_adapter_state_t *, ql_adm_op_t *);
static int ql_adm_device_list(ql_adapter_state_t *, ql_adm_op_t *, int);
static int ql_adm_update_properties(ql_adapter_state_t *);
static int ql_adm_prop_update_int(ql_adapter_state_t *, ql_adm_op_t *, int);
static int ql_adm_loop_reset(ql_adapter_state_t *);
static int ql_adm_fw_dump(ql_adapter_state_t *, ql_adm_op_t *, void *, int);
static int ql_adm_nvram_dump(ql_adapter_state_t *, ql_adm_op_t *, int);
static int ql_adm_nvram_load(ql_adapter_state_t *, ql_adm_op_t *, int);
static int ql_adm_flash_load(ql_adapter_state_t *, ql_adm_op_t *, int);
static int ql_adm_vpd_dump(ql_adapter_state_t *, ql_adm_op_t *, int);
static int ql_adm_vpd_load(ql_adapter_state_t *, ql_adm_op_t *, int);
static int ql_adm_vpd_gettag(ql_adapter_state_t *, ql_adm_op_t *, int);
static int ql_adm_updfwmodule(ql_adapter_state_t *, ql_adm_op_t *, int);
static uint8_t *ql_vpd_findtag(ql_adapter_state_t *, uint8_t *, int8_t *);

/* ************************************************************************ */
/*				cb_ops functions			    */
/* ************************************************************************ */

/*
 * ql_open
 *	opens device
 *
 * Input:
 *	dev_p = device pointer
 *	flags = open flags
 *	otype = open type
 *	cred_p = credentials pointer
 *
 * Returns:
 *	0 = success
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
int
ql_open(dev_t *dev_p, int flags, int otyp, cred_t *cred_p)
{
	ql_adapter_state_t	*ha;
	int			rval = 0;

	ha = ddi_get_soft_state(ql_state, (int32_t)getminor(*dev_p));
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter\n");
		return (ENXIO);
	}

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Allow only character opens */
	if (otyp != OTYP_CHR) {
		QL_PRINT_2(CE_CONT, "(%d): failed, open type\n",
		    ha->instance);
		return (EINVAL);
	}

	ADAPTER_STATE_LOCK(ha);
	if (flags & FEXCL && ha->flags & QL_OPENED) {
		ADAPTER_STATE_UNLOCK(ha);
		rval = EBUSY;
	} else {
		ha->flags |= QL_OPENED;
		ADAPTER_STATE_UNLOCK(ha);
	}

	if (rval != 0) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_close
 *	opens device
 *
 * Input:
 *	dev_p = device pointer
 *	flags = open flags
 *	otype = open type
 *	cred_p = credentials pointer
 *
 * Returns:
 *	0 = success
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
int
ql_close(dev_t dev, int flags, int otyp, cred_t *cred_p)
{
	ql_adapter_state_t	*ha;
	int			rval = 0;

	ha = ddi_get_soft_state(ql_state, (int32_t)getminor(dev));
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter\n");
		return (ENXIO);
	}

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (otyp != OTYP_CHR) {
		QL_PRINT_2(CE_CONT, "(%d): failed, open type\n",
		    ha->instance);
		return (EINVAL);
	}

	ADAPTER_STATE_LOCK(ha);
	ha->flags &= ~QL_OPENED;
	ADAPTER_STATE_UNLOCK(ha);

	if (rval != 0) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_ioctl
 *	control a character device
 *
 * Input:
 *	dev = device number
 *	cmd = function to perform
 *	arg = data type varies with request
 *	mode = flags
 *	cred_p = credentials pointer
 *	rval_p = pointer to result value
 *
 * Returns:
 *	0 = success
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
int
ql_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
	ql_adapter_state_t	*ha;
	int			rval = 0;

	if (ddi_in_panic()) {
		QL_PRINT_2(CE_CONT, "ql_ioctl: ddi_in_panic exit\n");
		return (ENOPROTOOPT);
	}

	ha = ddi_get_soft_state(ql_state, (int32_t)getminor(dev));
	if (ha == NULL)	{
		QL_PRINT_2(CE_CONT, "failed, no adapter\n");
		return (ENXIO);
	}

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/*
	 * Quick clean exit for qla2x00 foapi calls which are
	 * not supported in qlc.
	 */
	if (cmd >= QL_FOAPI_START && cmd <= QL_FOAPI_END) {
		QL_PRINT_9(CE_CONT, "failed, fo api not supported\n");
		return (ENOTTY);
	}

	/* PWR management busy. */
	rval = ql_busy_notification(ha);
	if (rval != FC_SUCCESS)	 {
		EL(ha, "failed, ql_busy_notification\n");
		return (ENXIO);
	}

	rval = ql_xioctl(ha, cmd, arg, mode, cred_p, rval_p);
	if (rval == ENOPROTOOPT || rval == EINVAL) {
		switch (cmd) {
		case QL_GET_ADAPTER_FEATURE_BITS: {
			uint16_t bits;

			rval = ql_get_feature_bits(ha, &bits);

			if (!rval && ddi_copyout((void *)&bits, (void *)arg,
			    sizeof (bits), mode)) {
				rval = EFAULT;
			}
			break;
		}

		case QL_SET_ADAPTER_FEATURE_BITS: {
			uint16_t bits;

			if (ddi_copyin((void *)arg, (void *)&bits,
			    sizeof (bits), mode)) {
				rval = EFAULT;
				break;
			}

			rval = ql_set_feature_bits(ha, bits);
			break;
		}

		case QL_SET_ADAPTER_NVRAM_DEFAULTS:
			rval = ql_set_nvram_adapter_defaults(ha);
			break;

		case QL_UTIL_LOAD:
			rval = ql_nv_util_load(ha, (void *)arg, mode);
			break;

		case QL_UTIL_DUMP:
			rval = ql_nv_util_dump(ha, (void *)arg, mode);
			break;

		case QL_ADM_OP:
			rval = ql_adm_op(ha, (void *)arg, mode);
			break;

		default:
			EL(ha, "unknown command = %d\n", cmd);
			rval = ENOTTY;
			break;
		}
	}

	/* PWR management idle. */
	(void) ql_idle_notification(ha);

	if (rval != 0) {
		/*
		 * Don't show failures caused by pps polling for
		 * non-existant virtual ports.
		 */
		if (cmd != EXT_CC_VPORT_CMD) {
			EL(ha, "failed, cmd=%d rval=%d\n", cmd, rval);
		}
	} else {
		/*EMPTY*/
		QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_busy_notification
 *	Adapter busy notification.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	FC_SUCCESS
 *	FC_FAILURE
 *
 * Context:
 *	Kernel context.
 */
static int
ql_busy_notification(ql_adapter_state_t *ha)
{
	if (!ha->pm_capable) {
		return (FC_SUCCESS);
	}

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	QL_PM_LOCK(ha);
	ha->busy++;
	QL_PM_UNLOCK(ha);

	if (pm_busy_component(ha->dip, 0) != DDI_SUCCESS) {
		QL_PM_LOCK(ha);
		ha->busy--;
		QL_PM_UNLOCK(ha);

		EL(ha, "pm_busy_component failed = %xh\n", FC_FAILURE);
		return (FC_FAILURE);
	}

	QL_PM_LOCK(ha);
	if (ha->power_level != PM_LEVEL_D0) {
		QL_PM_UNLOCK(ha);
		if (pm_raise_power(ha->dip, 0, 1) != DDI_SUCCESS) {
			QL_PM_LOCK(ha);
			ha->busy--;
			QL_PM_UNLOCK(ha);
			return (FC_FAILURE);
		}
	} else {
		QL_PM_UNLOCK(ha);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (FC_SUCCESS);
}

/*
 * ql_idle_notification
 *	Adapter idle notification.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	FC_SUCCESS
 *	FC_FAILURE
 *
 * Context:
 *	Kernel context.
 */
static int
ql_idle_notification(ql_adapter_state_t *ha)
{
	if (!ha->pm_capable) {
		return (FC_SUCCESS);
	}

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (pm_idle_component(ha->dip, 0) != DDI_SUCCESS) {
		EL(ha, "pm_idle_component failed = %xh\n", FC_FAILURE);
		return (FC_FAILURE);
	}

	QL_PM_LOCK(ha);
	ha->busy--;
	QL_PM_UNLOCK(ha);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (FC_SUCCESS);
}

/*
 * Get adapter feature bits from NVRAM
 */
static int
ql_get_feature_bits(ql_adapter_state_t *ha, uint16_t *features)
{
	int			count;
	volatile uint16_t	data;
	uint32_t		nv_cmd;
	uint32_t		start_addr;
	int			rval;
	uint32_t		offset = offsetof(nvram_t, adapter_features);

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_24258081)) {
		EL(ha, "Not supported for 24xx\n");
		return (EINVAL);
	}

	/*
	 * The offset can't be greater than max of 8 bits and
	 * the following code breaks if the offset isn't at
	 * 2 byte boundary.
	 */
	rval = ql_lock_nvram(ha, &start_addr, LNF_NVRAM_DATA);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, ql_lock_nvram=%xh\n", rval);
		return (EIO);
	}

	/*
	 * Have the most significant 3 bits represent the read operation
	 * followed by the 8 bits representing the offset at which we
	 * are going to perform the read operation
	 */
	offset >>= 1;
	offset += start_addr;
	nv_cmd = (offset << 16) | NV_READ_OP;
	nv_cmd <<= 5;

	/*
	 * Select the chip and feed the command and address
	 */
	for (count = 0; count < 11; count++) {
		if (nv_cmd & BIT_31) {
			ql_nv_write(ha, NV_DATA_OUT);
		} else {
			ql_nv_write(ha, 0);
		}
		nv_cmd <<= 1;
	}

	*features = 0;
	for (count = 0; count < 16; count++) {
		WRT16_IO_REG(ha, nvram, NV_SELECT | NV_CLOCK);
		ql_nv_delay();

		data = RD16_IO_REG(ha, nvram);
		*features <<= 1;
		if (data & NV_DATA_IN) {
			*features = (uint16_t)(*features | 0x1);
		}

		WRT16_IO_REG(ha, nvram, NV_SELECT);
		ql_nv_delay();
	}

	/*
	 * Deselect the chip
	 */
	WRT16_IO_REG(ha, nvram, NV_DESELECT);

	ql_release_nvram(ha);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

/*
 * Set adapter feature bits in NVRAM
 */
static int
ql_set_feature_bits(ql_adapter_state_t *ha, uint16_t features)
{
	int		rval;
	uint32_t	count;
	nvram_t		*nv;
	uint16_t	*wptr;
	uint8_t		*bptr;
	uint8_t		csum;
	uint32_t	start_addr;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_24258081)) {
		EL(ha, "Not supported for 24xx\n");
		return (EINVAL);
	}

	nv = kmem_zalloc(sizeof (*nv), KM_SLEEP);
	if (nv == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (ENOMEM);
	}

	rval = ql_lock_nvram(ha, &start_addr, LNF_NVRAM_DATA);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, ql_lock_nvram=%xh\n", rval);
		kmem_free(nv, sizeof (*nv));
		return (EIO);
	}
	rval = 0;

	/*
	 * Read off the whole NVRAM
	 */
	wptr = (uint16_t *)nv;
	csum = 0;
	for (count = 0; count < sizeof (nvram_t) / 2; count++) {
		*wptr = (uint16_t)ql_get_nvram_word(ha, count + start_addr);
		csum = (uint8_t)(csum + (uint8_t)*wptr);
		csum = (uint8_t)(csum + (uint8_t)(*wptr >> 8));
		wptr++;
	}

	/*
	 * If the checksum is BAD then fail it right here.
	 */
	if (csum) {
		kmem_free(nv, sizeof (*nv));
		ql_release_nvram(ha);
		return (EBADF);
	}

	nv->adapter_features[0] = (uint8_t)((features & 0xFF00) >> 8);
	nv->adapter_features[1] = (uint8_t)(features & 0xFF);

	/*
	 * Recompute the chesksum now
	 */
	bptr = (uint8_t *)nv;
	for (count = 0; count < sizeof (nvram_t) - 1; count++) {
		csum = (uint8_t)(csum + *bptr++);
	}
	csum = (uint8_t)(~csum + 1);
	nv->checksum = csum;

	/*
	 * Now load the NVRAM
	 */
	wptr = (uint16_t *)nv;
	for (count = 0; count < sizeof (nvram_t) / 2; count++) {
		ql_load_nvram(ha, (uint8_t)(count + start_addr), *wptr++);
	}

	/*
	 * Read NVRAM and verify the contents
	 */
	wptr = (uint16_t *)nv;
	csum = 0;
	for (count = 0; count < sizeof (nvram_t) / 2; count++) {
		if (ql_get_nvram_word(ha, count + start_addr) != *wptr) {
			rval = EIO;
			break;
		}
		csum = (uint8_t)(csum + (uint8_t)*wptr);
		csum = (uint8_t)(csum + (uint8_t)(*wptr >> 8));
		wptr++;
	}

	if (csum) {
		rval = EINVAL;
	}

	kmem_free(nv, sizeof (*nv));
	ql_release_nvram(ha);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * Fix this function to update just feature bits and checksum in NVRAM
 */
static int
ql_set_nvram_adapter_defaults(ql_adapter_state_t *ha)
{
	int		rval;
	uint32_t	count;
	uint32_t	start_addr;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	rval = ql_lock_nvram(ha, &start_addr, LNF_NVRAM_DATA);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, ql_lock_nvram=%xh\n", rval);
		return (EIO);
	}
	rval = 0;

	if (CFG_IST(ha, CFG_CTRL_24258081)) {
		nvram_24xx_t	*nv;
		uint32_t	*longptr;
		uint32_t	csum = 0;

		nv = kmem_zalloc(sizeof (*nv), KM_SLEEP);
		if (nv == NULL) {
			EL(ha, "failed, kmem_zalloc\n");
			return (ENOMEM);
		}

		nv->nvram_version[0] = LSB(ICB_24XX_VERSION);
		nv->nvram_version[1] = MSB(ICB_24XX_VERSION);

		nv->version[0] = 1;
		nv->max_frame_length[1] = 8;
		nv->execution_throttle[0] = 16;
		nv->login_retry_count[0] = 8;

		nv->firmware_options_1[0] = BIT_2 | BIT_1;
		nv->firmware_options_1[1] = BIT_5;
		nv->firmware_options_2[0] = BIT_5;
		nv->firmware_options_2[1] = BIT_4;
		nv->firmware_options_3[1] = BIT_6;

		/*
		 * Set default host adapter parameters
		 */
		nv->host_p[0] = BIT_4 | BIT_1;
		nv->host_p[1] = BIT_3 | BIT_2;
		nv->reset_delay = 5;
		nv->max_luns_per_target[0] = 128;
		nv->port_down_retry_count[0] = 30;
		nv->link_down_timeout[0] = 30;

		/*
		 * compute the chesksum now
		 */
		longptr = (uint32_t *)nv;
		csum = 0;
		for (count = 0; count < (sizeof (nvram_24xx_t)/4)-1; count++) {
			csum += *longptr;
			longptr++;
		}
		csum = (uint32_t)(~csum + 1);
		LITTLE_ENDIAN_32((long)csum);
		*longptr = csum;

		/*
		 * Now load the NVRAM
		 */
		longptr = (uint32_t *)nv;
		for (count = 0; count < sizeof (nvram_24xx_t) / 4; count++) {
			(void) ql_24xx_load_nvram(ha,
			    (uint32_t)(count + start_addr), *longptr++);
		}

		/*
		 * Read NVRAM and verify the contents
		 */
		csum = 0;
		longptr = (uint32_t *)nv;
		for (count = 0; count < sizeof (nvram_24xx_t) / 4; count++) {
			rval = ql_24xx_read_flash(ha, count + start_addr,
			    longptr);
			if (rval != QL_SUCCESS) {
				EL(ha, "24xx_read_flash failed=%xh\n", rval);
				break;
			}
			csum += *longptr;
		}

		if (csum) {
			rval = EINVAL;
		}
		kmem_free(nv, sizeof (nvram_24xx_t));
	} else {
		nvram_t		*nv;
		uint16_t	*wptr;
		uint8_t		*bptr;
		uint8_t		csum;

		nv = kmem_zalloc(sizeof (*nv), KM_SLEEP);
		if (nv == NULL) {
			EL(ha, "failed, kmem_zalloc\n");
			return (ENOMEM);
		}
		/*
		 * Set default initialization control block.
		 */
		nv->parameter_block_version = ICB_VERSION;
		nv->firmware_options[0] = BIT_4 | BIT_3 | BIT_2 | BIT_1;
		nv->firmware_options[1] = BIT_7 | BIT_5 | BIT_2;

		nv->max_frame_length[1] = 4;
		nv->max_iocb_allocation[1] = 1;
		nv->execution_throttle[0] = 16;
		nv->login_retry_count = 8;
		nv->port_name[0] = 33;
		nv->port_name[3] = 224;
		nv->port_name[4] = 139;
		nv->login_timeout = 4;

		/*
		 * Set default host adapter parameters
		 */
		nv->host_p[0] = BIT_1;
		nv->host_p[1] = BIT_2;
		nv->reset_delay = 5;
		nv->port_down_retry_count = 8;
		nv->maximum_luns_per_target[0] = 8;

		/*
		 * compute the chesksum now
		 */
		bptr = (uint8_t *)nv;
		csum = 0;
		for (count = 0; count < sizeof (nvram_t) - 1; count++) {
			csum = (uint8_t)(csum + *bptr++);
		}
		csum = (uint8_t)(~csum + 1);
		nv->checksum = csum;

		/*
		 * Now load the NVRAM
		 */
		wptr = (uint16_t *)nv;
		for (count = 0; count < sizeof (nvram_t) / 2; count++) {
			ql_load_nvram(ha, (uint8_t)(count + start_addr),
			    *wptr++);
		}

		/*
		 * Read NVRAM and verify the contents
		 */
		wptr = (uint16_t *)nv;
		csum = 0;
		for (count = 0; count < sizeof (nvram_t) / 2; count++) {
			if (ql_get_nvram_word(ha, count + start_addr) !=
			    *wptr) {
				rval = EIO;
				break;
			}
			csum = (uint8_t)(csum + (uint8_t)*wptr);
			csum = (uint8_t)(csum + (uint8_t)(*wptr >> 8));
			wptr++;
		}
		if (csum) {
			rval = EINVAL;
		}
		kmem_free(nv, sizeof (*nv));
	}
	ql_release_nvram(ha);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

static void
ql_load_nvram(ql_adapter_state_t *ha, uint8_t addr, uint16_t value)
{
	int			count;
	volatile uint16_t	word;
	volatile uint32_t	nv_cmd;

	ql_nv_write(ha, NV_DATA_OUT);
	ql_nv_write(ha, 0);
	ql_nv_write(ha, 0);

	for (word = 0; word < 8; word++) {
		ql_nv_write(ha, NV_DATA_OUT);
	}

	/*
	 * Deselect the chip
	 */
	WRT16_IO_REG(ha, nvram, NV_DESELECT);
	ql_nv_delay();

	/*
	 * Erase Location
	 */
	nv_cmd = (addr << 16) | NV_ERASE_OP;
	nv_cmd <<= 5;
	for (count = 0; count < 11; count++) {
		if (nv_cmd & BIT_31) {
			ql_nv_write(ha, NV_DATA_OUT);
		} else {
			ql_nv_write(ha, 0);
		}
		nv_cmd <<= 1;
	}

	/*
	 * Wait for Erase to Finish
	 */
	WRT16_IO_REG(ha, nvram, NV_DESELECT);
	ql_nv_delay();
	WRT16_IO_REG(ha, nvram, NV_SELECT);
	word = 0;
	while ((word & NV_DATA_IN) == 0) {
		ql_nv_delay();
		word = RD16_IO_REG(ha, nvram);
	}
	WRT16_IO_REG(ha, nvram, NV_DESELECT);
	ql_nv_delay();

	/*
	 * Write data now
	 */
	nv_cmd = (addr << 16) | NV_WRITE_OP;
	nv_cmd |= value;
	nv_cmd <<= 5;
	for (count = 0; count < 27; count++) {
		if (nv_cmd & BIT_31) {
			ql_nv_write(ha, NV_DATA_OUT);
		} else {
			ql_nv_write(ha, 0);
		}
		nv_cmd <<= 1;
	}

	/*
	 * Wait for NVRAM to become ready
	 */
	WRT16_IO_REG(ha, nvram, NV_DESELECT);
	ql_nv_delay();
	WRT16_IO_REG(ha, nvram, NV_SELECT);
	word = 0;
	while ((word & NV_DATA_IN) == 0) {
		ql_nv_delay();
		word = RD16_IO_REG(ha, nvram);
	}
	WRT16_IO_REG(ha, nvram, NV_DESELECT);
	ql_nv_delay();

	/*
	 * Disable writes
	 */
	ql_nv_write(ha, NV_DATA_OUT);
	for (count = 0; count < 10; count++) {
		ql_nv_write(ha, 0);
	}

	/*
	 * Deselect the chip now
	 */
	WRT16_IO_REG(ha, nvram, NV_DESELECT);
}

/*
 * ql_24xx_load_nvram
 *	Enable NVRAM and writes a 32bit word to ISP24xx NVRAM.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	addr:	NVRAM address.
 *	value:	data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_24xx_load_nvram(ql_adapter_state_t *ha, uint32_t addr, uint32_t value)
{
	int	rval;

	/* Enable flash write. */
	if (!(CFG_IST(ha, CFG_CTRL_8081))) {
		WRT32_IO_REG(ha, ctrl_status,
		    RD32_IO_REG(ha, ctrl_status) | ISP_FLASH_ENABLE);
		RD32_IO_REG(ha, ctrl_status);	/* PCI Posting. */
	}

	/* Disable NVRAM write-protection. */
	if (CFG_IST(ha, CFG_CTRL_2422)) {
		(void) ql_24xx_write_flash(ha, NVRAM_CONF_ADDR | 0x101, 0);
	} else {
		if ((rval = ql_24xx_unprotect_flash(ha)) != QL_SUCCESS) {
			EL(ha, "unprotect_flash failed, rval=%xh\n", rval);
			return (rval);
		}
	}

	/* Write to flash. */
	rval = ql_24xx_write_flash(ha, addr, value);

	/* Enable NVRAM write-protection. */
	if (CFG_IST(ha, CFG_CTRL_2422)) {
		/* TODO: Check if 0x8c is correct -- sb: 0x9c ? */
		(void) ql_24xx_write_flash(ha, NVRAM_CONF_ADDR | 0x101, 0x8c);
	} else {
		ql_24xx_protect_flash(ha);
	}

	/* Disable flash write. */
	if (!(CFG_IST(ha, CFG_CTRL_81XX))) {
		WRT32_IO_REG(ha, ctrl_status,
		    RD32_IO_REG(ha, ctrl_status) & ~ISP_FLASH_ENABLE);
		RD32_IO_REG(ha, ctrl_status);	/* PCI Posting. */
	}

	return (rval);
}

/*
 * ql_nv_util_load
 *	Loads NVRAM from application.
 *
 * Input:
 *	ha = adapter state pointer.
 *	bp = user buffer address.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
int
ql_nv_util_load(ql_adapter_state_t *ha, void *bp, int mode)
{
	uint8_t		cnt;
	void		*nv;
	uint16_t	*wptr;
	uint16_t	data;
	uint32_t	start_addr, *lptr, data32;
	nvram_t		*nptr;
	int		rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if ((nv = kmem_zalloc(ha->nvram_cache->size, KM_SLEEP)) == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (ENOMEM);
	}

	if (ddi_copyin(bp, nv, ha->nvram_cache->size, mode) != 0) {
		EL(ha, "Buffer copy failed\n");
		kmem_free(nv, ha->nvram_cache->size);
		return (EFAULT);
	}

	/* See if the buffer passed to us looks sane */
	nptr = (nvram_t *)nv;
	if (nptr->id[0] != 'I' || nptr->id[1] != 'S' || nptr->id[2] != 'P' ||
	    nptr->id[3] != ' ') {
		EL(ha, "failed, buffer sanity check\n");
		kmem_free(nv, ha->nvram_cache->size);
		return (EINVAL);
	}

	/* Quiesce I/O */
	if (ql_stall_driver(ha, 0) != QL_SUCCESS) {
		EL(ha, "ql_stall_driver failed\n");
		kmem_free(nv, ha->nvram_cache->size);
		return (EBUSY);
	}

	rval = ql_lock_nvram(ha, &start_addr, LNF_NVRAM_DATA);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, ql_lock_nvram=%xh\n", rval);
		kmem_free(nv, ha->nvram_cache->size);
		ql_restart_driver(ha);
		return (EIO);
	}

	/* Load NVRAM. */
	if (CFG_IST(ha, CFG_CTRL_258081)) {
		GLOBAL_HW_UNLOCK();
		start_addr &= ~ha->flash_data_addr;
		start_addr <<= 2;
		if ((rval = ql_r_m_w_flash(ha, bp, ha->nvram_cache->size,
		    start_addr, mode)) != QL_SUCCESS) {
			EL(ha, "nvram load failed, rval = %0xh\n", rval);
		}
		GLOBAL_HW_LOCK();
	} else if (CFG_IST(ha, CFG_CTRL_2422)) {
		lptr = (uint32_t *)nv;
		for (cnt = 0; cnt < ha->nvram_cache->size / 4; cnt++) {
			data32 = *lptr++;
			LITTLE_ENDIAN_32(&data32);
			rval = ql_24xx_load_nvram(ha, cnt + start_addr,
			    data32);
			if (rval != QL_SUCCESS) {
				EL(ha, "failed, 24xx_load_nvram=%xh\n", rval);
				break;
			}
		}
	} else {
		wptr = (uint16_t *)nv;
		for (cnt = 0; cnt < ha->nvram_cache->size / 2; cnt++) {
			data = *wptr++;
			LITTLE_ENDIAN_16(&data);
			ql_load_nvram(ha, (uint8_t)(cnt + start_addr), data);
		}
	}
	/* switch to the new one */
	NVRAM_CACHE_LOCK(ha);

	kmem_free(ha->nvram_cache->cache, ha->nvram_cache->size);
	ha->nvram_cache->cache = (void *)nptr;

	NVRAM_CACHE_UNLOCK(ha);

	ql_release_nvram(ha);
	ql_restart_driver(ha);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	if (rval == QL_SUCCESS) {
		return (0);
	}

	return (EFAULT);
}

/*
 * ql_nv_util_dump
 *	Dumps NVRAM to application.
 *
 * Input:
 *	ha = adapter state pointer.
 *	bp = user buffer address.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
int
ql_nv_util_dump(ql_adapter_state_t *ha, void *bp, int mode)
{
	uint32_t	start_addr;
	int		rval2, rval = 0;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (ha->nvram_cache == NULL ||
	    ha->nvram_cache->size == 0 ||
	    ha->nvram_cache->cache == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (ENOMEM);
	} else if (ha->nvram_cache->valid != 1) {

		/* Quiesce I/O */
		if (ql_stall_driver(ha, 0) != QL_SUCCESS) {
			EL(ha, "ql_stall_driver failed\n");
			return (EBUSY);
		}

		rval2 = ql_lock_nvram(ha, &start_addr, LNF_NVRAM_DATA);
		if (rval2 != QL_SUCCESS) {
			EL(ha, "failed, ql_lock_nvram=%xh\n", rval2);
			ql_restart_driver(ha);
			return (EIO);
		}
		NVRAM_CACHE_LOCK(ha);

		rval2 = ql_get_nvram(ha, ha->nvram_cache->cache,
		    start_addr, ha->nvram_cache->size);
		if (rval2 != QL_SUCCESS) {
			rval = rval2;
		} else {
			ha->nvram_cache->valid = 1;
			EL(ha, "nvram cache now valid.");
		}

		NVRAM_CACHE_UNLOCK(ha);

		ql_release_nvram(ha);
		ql_restart_driver(ha);

		if (rval != 0) {
			EL(ha, "failed to dump nvram, rval=%x\n", rval);
			return (rval);
		}
	}

	if (ddi_copyout(ha->nvram_cache->cache, bp,
	    ha->nvram_cache->size, mode) != 0) {
		EL(ha, "Buffer copy failed\n");
		return (EFAULT);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

int
ql_get_nvram(ql_adapter_state_t *ha, void *dest_addr, uint32_t src_addr,
    uint32_t size)
{
	int rval = QL_SUCCESS;
	int cnt;
	/* Dump NVRAM. */
	if (CFG_IST(ha, CFG_CTRL_24258081)) {
		uint32_t	*lptr = (uint32_t *)dest_addr;

		for (cnt = 0; cnt < size / 4; cnt++) {
			rval = ql_24xx_read_flash(ha, src_addr++, lptr);
			if (rval != QL_SUCCESS) {
				EL(ha, "read_flash failed=%xh\n", rval);
				rval = EAGAIN;
				break;
			}
			LITTLE_ENDIAN_32(lptr);
			lptr++;
		}
	} else {
		uint16_t	data;
		uint16_t	*wptr = (uint16_t *)dest_addr;

		for (cnt = 0; cnt < size / 2; cnt++) {
			data = (uint16_t)ql_get_nvram_word(ha, cnt +
			    src_addr);
			LITTLE_ENDIAN_16(&data);
			*wptr++ = data;
		}
	}
	return (rval);
}

/*
 * ql_vpd_load
 *	Loads VPD from application.
 *
 * Input:
 *	ha = adapter state pointer.
 *	bp = user buffer address.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
int
ql_vpd_load(ql_adapter_state_t *ha, void *bp, int mode)
{
	uint8_t		cnt;
	uint8_t		*vpd, *vpdptr, *vbuf;
	uint32_t	start_addr, vpd_size, *lptr, data32;
	int		rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if ((CFG_IST(ha, CFG_CTRL_24258081)) == 0) {
		EL(ha, "unsupported adapter feature\n");
		return (ENOTSUP);
	}

	vpd_size = QL_24XX_VPD_SIZE;

	if ((vpd = kmem_zalloc(vpd_size, KM_SLEEP)) == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (ENOMEM);
	}

	if (ddi_copyin(bp, vpd, vpd_size, mode) != 0) {
		EL(ha, "Buffer copy failed\n");
		kmem_free(vpd, vpd_size);
		return (EFAULT);
	}

	/* Sanity check the user supplied data via checksum */
	if ((vpdptr = ql_vpd_findtag(ha, vpd, "RV")) == NULL) {
		EL(ha, "vpd RV tag missing\n");
		kmem_free(vpd, vpd_size);
		return (EINVAL);
	}

	vpdptr += 3;
	cnt = 0;
	vbuf = vpd;
	while (vbuf <= vpdptr) {
		cnt += *vbuf++;
	}
	if (cnt != 0) {
		EL(ha, "mismatched checksum, cal=%xh, passed=%xh\n",
		    (uint8_t)cnt, (uintptr_t)vpdptr);
		kmem_free(vpd, vpd_size);
		return (EINVAL);
	}

	/* Quiesce I/O */
	if (ql_stall_driver(ha, 0) != QL_SUCCESS) {
		EL(ha, "ql_stall_driver failed\n");
		kmem_free(vpd, vpd_size);
		return (EBUSY);
	}

	rval = ql_lock_nvram(ha, &start_addr, LNF_VPD_DATA);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, ql_lock_nvram=%xh\n", rval);
		kmem_free(vpd, vpd_size);
		ql_restart_driver(ha);
		return (EIO);
	}

	/* Load VPD. */
	if (CFG_IST(ha, CFG_CTRL_258081)) {
		GLOBAL_HW_UNLOCK();
		start_addr &= ~ha->flash_data_addr;
		start_addr <<= 2;
		if ((rval = ql_r_m_w_flash(ha, bp, vpd_size, start_addr,
		    mode)) != QL_SUCCESS) {
			EL(ha, "vpd load error: %xh\n", rval);
		}
		GLOBAL_HW_LOCK();
	} else {
		lptr = (uint32_t *)vpd;
		for (cnt = 0; cnt < vpd_size / 4; cnt++) {
			data32 = *lptr++;
			LITTLE_ENDIAN_32(&data32);
			rval = ql_24xx_load_nvram(ha, cnt + start_addr,
			    data32);
			if (rval != QL_SUCCESS) {
				EL(ha, "failed, 24xx_load_nvram=%xh\n", rval);
				break;
			}
		}
	}

	kmem_free(vpd, vpd_size);

	/* Update the vcache */
	CACHE_LOCK(ha);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, load\n");
	} else if ((ha->vcache == NULL) && ((ha->vcache =
	    kmem_zalloc(vpd_size, KM_SLEEP)) == NULL)) {
		EL(ha, "failed, kmem_zalloc2\n");
	} else if (ddi_copyin(bp, ha->vcache, vpd_size, mode) != 0) {
		EL(ha, "Buffer copy2 failed\n");
		kmem_free(ha->vcache, vpd_size);
		ha->vcache = NULL;
	}

	CACHE_UNLOCK(ha);

	ql_release_nvram(ha);
	ql_restart_driver(ha);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	if (rval == QL_SUCCESS) {
		return (0);
	}

	return (EFAULT);
}

/*
 * ql_vpd_dump
 *	Dumps VPD to application buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *	bp = user buffer address.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
int
ql_vpd_dump(ql_adapter_state_t *ha, void *bp, int mode)
{
	uint8_t		cnt;
	void		*vpd;
	uint32_t	start_addr, vpd_size, *lptr;
	int		rval = 0;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if ((CFG_IST(ha, CFG_CTRL_24258081)) == 0) {
		EL(ha, "unsupported adapter feature\n");
		return (EACCES);
	}

	vpd_size = QL_24XX_VPD_SIZE;

	CACHE_LOCK(ha);

	if (ha->vcache != NULL) {
		/* copy back the vpd cache data */
		if (ddi_copyout(ha->vcache, bp, vpd_size, mode) != 0) {
			EL(ha, "Buffer copy failed\n");
			rval = EFAULT;
		}
		CACHE_UNLOCK(ha);
		return (rval);
	}

	if ((vpd = kmem_zalloc(vpd_size, KM_SLEEP)) == NULL) {
		CACHE_UNLOCK(ha);
		EL(ha, "failed, kmem_zalloc\n");
		return (ENOMEM);
	}

	/* Quiesce I/O */
	if (ql_stall_driver(ha, 0) != QL_SUCCESS) {
		CACHE_UNLOCK(ha);
		EL(ha, "ql_stall_driver failed\n");
		kmem_free(vpd, vpd_size);
		return (EBUSY);
	}

	rval = ql_lock_nvram(ha, &start_addr, LNF_VPD_DATA);
	if (rval != QL_SUCCESS) {
		CACHE_UNLOCK(ha);
		EL(ha, "failed, ql_lock_nvram=%xh\n", rval);
		kmem_free(vpd, vpd_size);
		ql_restart_driver(ha);
		return (EIO);
	}

	/* Dump VPD. */
	lptr = (uint32_t *)vpd;

	for (cnt = 0; cnt < vpd_size / 4; cnt++) {
		rval = ql_24xx_read_flash(ha, start_addr++, lptr);
		if (rval != QL_SUCCESS) {
			EL(ha, "read_flash failed=%xh\n", rval);
			rval = EAGAIN;
			break;
		}
		LITTLE_ENDIAN_32(lptr);
		lptr++;
	}

	ql_release_nvram(ha);
	ql_restart_driver(ha);

	if (ddi_copyout(vpd, bp, vpd_size, mode) != 0) {
		CACHE_UNLOCK(ha);
		EL(ha, "Buffer copy failed\n");
		kmem_free(vpd, vpd_size);
		return (EFAULT);
	}

	ha->vcache = vpd;

	CACHE_UNLOCK(ha);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	if (rval != QL_SUCCESS) {
		return (EFAULT);
	} else {
		return (0);
	}
}

/*
 * ql_vpd_findtag
 *	Search the passed vpd buffer for the requested VPD tag type.
 *
 * Input:
 *	ha	= adapter state pointer.
 *	vpdbuf	= Pointer to start of the buffer to search
 *	op	= VPD opcode to find (must be NULL terminated).
 *
 * Returns:
 *	Pointer to the opcode in the buffer if opcode found.
 *	NULL if opcode is not found.
 *
 * Context:
 *	Kernel context.
 */
static uint8_t *
ql_vpd_findtag(ql_adapter_state_t *ha, uint8_t *vpdbuf, int8_t *opcode)
{
	uint8_t		*vpd = vpdbuf;
	uint8_t		*end = vpdbuf + QL_24XX_VPD_SIZE;
	uint32_t	found = 0;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (vpdbuf == NULL || opcode == NULL) {
		EL(ha, "null parameter passed!\n");
		return (NULL);
	}

	while (vpd < end) {

		/* check for end of vpd */
		if (vpd[0] == VPD_TAG_END) {
			if (opcode[0] == VPD_TAG_END) {
				found = 1;
			} else {
				found = 0;
			}
			break;
		}

		/* check opcode */
		if (bcmp(opcode, vpd, strlen(opcode)) == 0) {
			/* found opcode requested */
			found = 1;
			break;
		}

		/*
		 * Didn't find the opcode, so calculate start of
		 * next tag. Depending on the current tag type,
		 * the length field can be 1 or 2 bytes
		 */
		if (!(strncmp((char *)vpd, (char *)VPD_TAG_PRODID, 1))) {
			vpd += (vpd[2] << 8) + vpd[1] + 3;
		} else if (*vpd == VPD_TAG_LRT || *vpd == VPD_TAG_LRTC) {
			vpd += 3;
		} else {
			vpd += vpd[2] +3;
		}
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (found == 1 ? vpd : NULL);
}

/*
 * ql_vpd_lookup
 *	Return the VPD data for the request VPD tag
 *
 * Input:
 *	ha	= adapter state pointer.
 *	opcode	= VPD opcode to find (must be NULL terminated).
 *	bp	= Pointer to returned data buffer.
 *	bplen	= Length of returned data buffer.
 *
 * Returns:
 *	Length of data copied into returned data buffer.
 *		>0 = VPD data field (NULL terminated)
 *		 0 = no data.
 *		-1 = Could not find opcode in vpd buffer / error.
 *
 * Context:
 *	Kernel context.
 *
 * NB: The opcode buffer and the bp buffer *could* be the same buffer!
 *
 */
int32_t
ql_vpd_lookup(ql_adapter_state_t *ha, uint8_t *opcode, uint8_t *bp,
    int32_t bplen)
{
	uint8_t		*vpd;
	uint8_t		*vpdbuf;
	int32_t		len = -1;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (opcode == NULL || bp == NULL || bplen < 1) {
		EL(ha, "invalid parameter passed: opcode=%ph, "
		    "bp=%ph, bplen=%xh\n", opcode, bp, bplen);
		return (len);
	}

	if ((CFG_IST(ha, CFG_CTRL_24258081)) == 0) {
		return (len);
	}

	if ((vpdbuf = (uint8_t *)kmem_zalloc(QL_24XX_VPD_SIZE,
	    KM_SLEEP)) == NULL) {
		EL(ha, "unable to allocate vpd memory\n");
		return (len);
	}

	if ((ql_vpd_dump(ha, vpdbuf, (int)FKIOCTL)) != 0) {
		kmem_free(vpdbuf, QL_24XX_VPD_SIZE);
		EL(ha, "unable to retrieve VPD data\n");
		return (len);
	}

	if ((vpd = ql_vpd_findtag(ha, vpdbuf, (int8_t *)opcode)) != NULL) {
		/*
		 * Found the tag
		 */
		if (*opcode == VPD_TAG_END || *opcode == VPD_TAG_LRT ||
		    *opcode == VPD_TAG_LRTC) {
			/*
			 * we found it, but the tag doesn't have a data
			 * field.
			 */
			len = 0;
		} else if (!(strncmp((char *)vpd, (char *)
		    VPD_TAG_PRODID, 1))) {
			len = vpd[2] << 8;
			len += vpd[1];
		} else {
			len = vpd[2];
		}

		/*
		 * make sure that the vpd len doesn't exceed the
		 * vpd end
		 */
		if (vpd+len > vpdbuf + QL_24XX_VPD_SIZE) {
			EL(ha, "vpd tag len (%xh) exceeds vpd buffer "
			    "length\n", len);
			len = -1;
		}
	}

	if (len >= 0) {
		/*
		 * make sure we don't exceed callers buffer space len
		 */
		if (len > bplen) {
			len = bplen-1;
		}

		/* copy the data back */
		(void) strncpy((int8_t *)bp, (int8_t *)(vpd+3), (int64_t)len);
		bp[len] = 0;
	} else {
		/* error -- couldn't find tag */
		bp[0] = 0;
		if (opcode[1] != 0) {
			EL(ha, "unable to find tag '%s'\n", opcode);
		} else {
			EL(ha, "unable to find tag '%xh'\n", opcode[0]);
		}
	}

	kmem_free(vpdbuf, QL_24XX_VPD_SIZE);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (len);
}

/*
 * ql_r_m_w_flash
 *	Read modify write from user space to flash.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dp:	source byte pointer.
 *	bc:	byte count.
 *	faddr:	flash byte address.
 *	mode:	flags.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_r_m_w_flash(ql_adapter_state_t *ha, caddr_t dp, uint32_t bc, uint32_t faddr,
    int mode)
{
	uint8_t		*bp;
	uint32_t	xfer, bsize, saddr, ofst;
	int		rval = 0;

	QL_PRINT_9(CE_CONT, "(%d): started, dp=%ph, faddr=%xh, bc=%xh\n",
	    ha->instance, (void *)dp, faddr, bc);

	bsize = ha->xioctl->fdesc.block_size;
	saddr = faddr & ~(bsize - 1);
	ofst = faddr & (bsize - 1);

	if ((bp = kmem_zalloc(bsize, KM_SLEEP)) == NULL) {
		EL(ha, "kmem_zalloc=null\n");
		return (QL_MEMORY_ALLOC_FAILED);
	}

	while (bc) {
		xfer = bc > bsize ? bsize : bc;
		if (ofst + xfer > bsize) {
			xfer = bsize - ofst;
		}
		QL_PRINT_9(CE_CONT, "(%d): dp=%ph, saddr=%xh, bc=%xh, "
		    "ofst=%xh, xfer=%xh\n", ha->instance, (void *)dp, saddr,
		    bc, ofst, xfer);

		if (ofst || xfer < bsize) {
			/* Dump Flash sector. */
			if ((rval = ql_dump_fcode(ha, bp, bsize, saddr)) !=
			    QL_SUCCESS) {
				EL(ha, "dump_flash status=%x\n", rval);
				break;
			}
		}

		/* Set new data. */
		if ((rval = ddi_copyin(dp, (caddr_t)(bp + ofst), xfer,
		    mode)) != 0) {
			EL(ha, "ddi_copyin status=%xh, dp=%ph, ofst=%xh, "
			    "xfer=%xh\n", rval, (void *)dp, ofst, xfer);
			rval = QL_FUNCTION_FAILED;
			break;
		}

		/* Write to flash. */
		if ((rval = ql_load_fcode(ha, bp, bsize, saddr)) !=
		    QL_SUCCESS) {
			EL(ha, "load_flash status=%x\n", rval);
			break;
		}
		bc -= xfer;
		dp += xfer;
		saddr += bsize;
		ofst = 0;
	}

	kmem_free(bp, bsize);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_adm_op
 *	Performs qladm utility operations
 *
 * Input:
 *	ha:	adapter state pointer.
 *	arg:	driver_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_op(ql_adapter_state_t *ha, void *arg, int mode)
{
	ql_adm_op_t		dop;
	int			rval = 0;

	if (ddi_copyin(arg, &dop, sizeof (ql_adm_op_t), mode) != 0) {
		EL(ha, "failed, driver_op_t ddi_copyin\n");
		return (EFAULT);
	}

	QL_PRINT_9(CE_CONT, "(%d): started, cmd=%xh, buffer=%llx,"
	    " length=%xh, option=%xh\n", ha->instance, dop.cmd, dop.buffer,
	    dop.length, dop.option);

	switch (dop.cmd) {
	case QL_ADAPTER_INFO:
		rval = ql_adm_adapter_info(ha, &dop, mode);
		break;

	case QL_EXTENDED_LOGGING:
		rval = ql_adm_extended_logging(ha, &dop);
		break;

	case QL_LOOP_RESET:
		rval = ql_adm_loop_reset(ha);
		break;

	case QL_DEVICE_LIST:
		rval = ql_adm_device_list(ha, &dop, mode);
		break;

	case QL_PROP_UPDATE_INT:
		rval = ql_adm_prop_update_int(ha, &dop, mode);
		break;

	case QL_UPDATE_PROPERTIES:
		rval = ql_adm_update_properties(ha);
		break;

	case QL_FW_DUMP:
		rval = ql_adm_fw_dump(ha, &dop, arg, mode);
		break;

	case QL_NVRAM_LOAD:
		rval = ql_adm_nvram_load(ha, &dop, mode);
		break;

	case QL_NVRAM_DUMP:
		rval = ql_adm_nvram_dump(ha, &dop, mode);
		break;

	case QL_FLASH_LOAD:
		rval = ql_adm_flash_load(ha, &dop, mode);
		break;

	case QL_VPD_LOAD:
		rval = ql_adm_vpd_load(ha, &dop, mode);
		break;

	case QL_VPD_DUMP:
		rval = ql_adm_vpd_dump(ha, &dop, mode);
		break;

	case QL_VPD_GETTAG:
		rval = ql_adm_vpd_gettag(ha, &dop, mode);
		break;

	case QL_UPD_FWMODULE:
		rval = ql_adm_updfwmodule(ha, &dop, mode);
		break;

	default:
		EL(ha, "unsupported driver op cmd: %x\n", dop.cmd);
		return (EINVAL);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_adm_adapter_info
 *	Performs qladm QL_ADAPTER_INFO command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_adapter_info(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	ql_adapter_info_t	hba;
	uint8_t			*dp;
	uint32_t		length;
	int			rval, i;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	hba.device_id = ha->device_id;

	dp = CFG_IST(ha, CFG_CTRL_24258081) ?
	    &ha->init_ctrl_blk.cb24.port_name[0] :
	    &ha->init_ctrl_blk.cb.port_name[0];
	bcopy(dp, hba.wwpn, 8);

	hba.d_id = ha->d_id.b24;

	if (ha->xioctl->fdesc.flash_size == 0 &&
	    !(CFG_IST(ha, CFG_CTRL_2200) && !ha->subven_id)) {
		if (ql_stall_driver(ha, 0) != QL_SUCCESS) {
			EL(ha, "ql_stall_driver failed\n");
			return (EBUSY);
		}

		if ((rval = ql_setup_fcache(ha)) != QL_SUCCESS) {
			EL(ha, "ql_setup_flash failed=%xh\n", rval);
			if (rval == QL_FUNCTION_TIMEOUT) {
				return (EBUSY);
			}
			return (EIO);
		}

		/* Resume I/O */
		if (CFG_IST(ha, CFG_CTRL_24258081)) {
			ql_restart_driver(ha);
		} else {
			EL(ha, "isp_abort_needed for restart\n");
			ql_awaken_task_daemon(ha, NULL, ISP_ABORT_NEEDED,
			    DRIVER_STALL);
		}
	}
	hba.flash_size = ha->xioctl->fdesc.flash_size;

	(void) strcpy(hba.driver_ver, QL_VERSION);

	(void) sprintf(hba.fw_ver, "%d.%d.%d", ha->fw_major_version,
	    ha->fw_minor_version, ha->fw_subminor_version);

	bzero(hba.fcode_ver, sizeof (hba.fcode_ver));

	/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
	rval = ddi_getlongprop(DDI_DEV_T_ANY, ha->dip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "version", (caddr_t)&dp, &i);
	length = i;
	if (rval != DDI_PROP_SUCCESS) {
		EL(ha, "failed, ddi_getlongprop=%xh\n", rval);
	} else {
		if (length > (uint32_t)sizeof (hba.fcode_ver)) {
			length = sizeof (hba.fcode_ver) - 1;
		}
		bcopy((void *)dp, (void *)hba.fcode_ver, length);
		kmem_free(dp, length);
	}

	if (ddi_copyout((void *)&hba, (void *)(uintptr_t)dop->buffer,
	    dop->length, mode) != 0) {
		EL(ha, "failed, ddi_copyout\n");
		return (EFAULT);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

/*
 * ql_adm_extended_logging
 *	Performs qladm QL_EXTENDED_LOGGING command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_extended_logging(ql_adapter_state_t *ha, ql_adm_op_t *dop)
{
	char	prop_name[MAX_PROP_LENGTH];
	int	rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	(void) sprintf(prop_name, "hba%d-extended-logging", ha->instance);

	/*LINTED [Solaris DDI_DEV_T_NONE Lint warning]*/
	rval = ddi_prop_update_int(DDI_DEV_T_NONE, ha->dip, prop_name,
	    (int)dop->option);
	if (rval != DDI_PROP_SUCCESS) {
		EL(ha, "failed, prop_update = %xh\n", rval);
		return (EINVAL);
	} else {
		dop->option ?
		    (ha->cfg_flags |= CFG_ENABLE_EXTENDED_LOGGING) :
		    (ha->cfg_flags &= ~CFG_ENABLE_EXTENDED_LOGGING);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

/*
 * ql_adm_loop_reset
 *	Performs qladm QL_LOOP_RESET command
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_loop_reset(ql_adapter_state_t *ha)
{
	int	rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (ha->task_daemon_flags & LOOP_DOWN) {
		(void) ql_full_login_lip(ha);
	} else if ((rval = ql_full_login_lip(ha)) != QL_SUCCESS) {
		EL(ha, "failed, ql_initiate_lip=%xh\n", rval);
		return (EIO);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

/*
 * ql_adm_device_list
 *	Performs qladm QL_DEVICE_LIST command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_device_list(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	ql_device_info_t	dev;
	ql_link_t		*link;
	ql_tgt_t		*tq;
	uint32_t		index, cnt;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	cnt = 0;
	dev.address = 0xffffffff;

	/* Scan port list for requested target and fill in the values */
	for (link = NULL, index = 0;
	    index < DEVICE_HEAD_LIST_SIZE && link == NULL; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;

			if (!VALID_TARGET_ID(ha, tq->loop_id)) {
				continue;
			}
			if (cnt != dop->option) {
				cnt++;
				continue;
			}
			/* fill in the values */
			bcopy(tq->port_name, dev.wwpn, 8);
			dev.address = tq->d_id.b24;
			dev.loop_id = tq->loop_id;
			if (tq->flags & TQF_TAPE_DEVICE) {
				dev.type = FCT_TAPE;
			} else if (tq->flags & TQF_INITIATOR_DEVICE) {
				dev.type = FCT_INITIATOR;
			} else {
				dev.type = FCT_TARGET;
			}
			break;
		}
	}

	if (ddi_copyout((void *)&dev, (void *)(uintptr_t)dop->buffer,
	    dop->length, mode) != 0) {
		EL(ha, "failed, ddi_copyout\n");
		return (EFAULT);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

/*
 * ql_adm_update_properties
 *	Performs qladm QL_UPDATE_PROPERTIES command
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_update_properties(ql_adapter_state_t *ha)
{
	ql_comb_init_cb_t	init_ctrl_blk;
	ql_comb_ip_init_cb_t	ip_init_ctrl_blk;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	/* Stall driver instance. */
	(void) ql_stall_driver(ha, 0);

	/* Save init control blocks. */
	bcopy(&ha->init_ctrl_blk, &init_ctrl_blk, sizeof (ql_comb_init_cb_t));
	bcopy(&ha->ip_init_ctrl_blk, &ip_init_ctrl_blk,
	    sizeof (ql_comb_ip_init_cb_t));

	/* Update PCI configration. */
	(void) ql_pci_sbus_config(ha);

	/* Get configuration properties. */
	(void) ql_nvram_config(ha);

	/* Check for init firmware required. */
	if (bcmp(&ha->init_ctrl_blk, &init_ctrl_blk,
	    sizeof (ql_comb_init_cb_t)) != 0 ||
	    bcmp(&ha->ip_init_ctrl_blk, &ip_init_ctrl_blk,
	    sizeof (ql_comb_ip_init_cb_t)) != 0) {

		EL(ha, "isp_abort_needed\n");
		ha->loop_down_timer = LOOP_DOWN_TIMER_START;
		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags |= LOOP_DOWN | ISP_ABORT_NEEDED;
		TASK_DAEMON_UNLOCK(ha);
	}

	/* Update AEN queue. */
	if (ha->xioctl->flags & QL_AEN_TRACKING_ENABLE) {
		ql_enqueue_aen(ha, MBA_PORT_UPDATE, NULL);
	}

	/* Restart driver instance. */
	ql_restart_driver(ha);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

/*
 * ql_adm_prop_update_int
 *	Performs qladm QL_PROP_UPDATE_INT command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_prop_update_int(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	char	*prop_name;
	int	rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	prop_name = kmem_zalloc(dop->length, KM_SLEEP);
	if (prop_name == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (ENOMEM);
	}

	if (ddi_copyin((void *)(uintptr_t)dop->buffer, prop_name, dop->length,
	    mode) != 0) {
		EL(ha, "failed, prop_name ddi_copyin\n");
		kmem_free(prop_name, dop->length);
		return (EFAULT);
	}

	/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
	if ((rval = ddi_prop_update_int(DDI_DEV_T_NONE, ha->dip, prop_name,
	    (int)dop->option)) != DDI_PROP_SUCCESS) {
		EL(ha, "failed, prop_update=%xh\n", rval);
		kmem_free(prop_name, dop->length);
		return (EINVAL);
	}

	kmem_free(prop_name, dop->length);

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

/*
 * ql_adm_fw_dump
 *	Performs qladm QL_FW_DUMP command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	udop:	user space ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_fw_dump(ql_adapter_state_t *ha, ql_adm_op_t *dop, void *udop, int mode)
{
	caddr_t	dmp;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (dop->length < ha->risc_dump_size) {
		EL(ha, "failed, incorrect length=%xh, size=%xh\n",
		    dop->length, ha->risc_dump_size);
		return (EINVAL);
	}

	if (ha->ql_dump_state & QL_DUMP_VALID) {
		dmp = kmem_zalloc(ha->risc_dump_size, KM_SLEEP);
		if (dmp == NULL) {
			EL(ha, "failed, kmem_zalloc\n");
			return (ENOMEM);
		}

		dop->length = (uint32_t)ql_ascii_fw_dump(ha, dmp);
		if (ddi_copyout((void *)dmp, (void *)(uintptr_t)dop->buffer,
		    dop->length, mode) != 0) {
			EL(ha, "failed, ddi_copyout\n");
			kmem_free(dmp, ha->risc_dump_size);
			return (EFAULT);
		}

		kmem_free(dmp, ha->risc_dump_size);
		ha->ql_dump_state |= QL_DUMP_UPLOADED;

	} else {
		EL(ha, "failed, no dump file\n");
		dop->length = 0;
	}

	if (ddi_copyout(dop, udop, sizeof (ql_adm_op_t), mode) != 0) {
		EL(ha, "failed, driver_op_t ddi_copyout\n");
		return (EFAULT);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

/*
 * ql_adm_nvram_dump
 *	Performs qladm QL_NVRAM_DUMP command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_nvram_dump(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	int		rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (dop->length < ha->nvram_cache->size) {
		EL(ha, "failed, length=%xh, size=%xh\n", dop->length,
		    ha->nvram_cache->size);
		return (EINVAL);
	}

	if ((rval = ql_nv_util_dump(ha, (void *)(uintptr_t)dop->buffer,
	    mode)) != 0) {
		EL(ha, "failed, ql_nv_util_dump\n");
	} else {
		/*EMPTY*/
		QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_adm_nvram_load
 *	Performs qladm QL_NVRAM_LOAD command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_nvram_load(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	int		rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if (dop->length < ha->nvram_cache->size) {
		EL(ha, "failed, length=%xh, size=%xh\n", dop->length,
		    ha->nvram_cache->size);
		return (EINVAL);
	}

	if ((rval = ql_nv_util_load(ha, (void *)(uintptr_t)dop->buffer,
	    mode)) != 0) {
		EL(ha, "failed, ql_nv_util_dump\n");
	} else {
		/*EMPTY*/
		QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_adm_flash_load
 *	Performs qladm QL_FLASH_LOAD command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_flash_load(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	uint8_t	*dp;
	int	rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if ((dp = kmem_zalloc(dop->length, KM_SLEEP)) == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (ENOMEM);
	}

	if (ddi_copyin((void *)(uintptr_t)dop->buffer, dp, dop->length,
	    mode) != 0) {
		EL(ha, "ddi_copyin failed\n");
		kmem_free(dp, dop->length);
		return (EFAULT);
	}

	if (ql_stall_driver(ha, 0) != QL_SUCCESS) {
		EL(ha, "ql_stall_driver failed\n");
		kmem_free(dp, dop->length);
		return (EBUSY);
	}

	rval = (CFG_IST(ha, CFG_CTRL_24258081) ?
	    ql_24xx_load_flash(ha, dp, dop->length, dop->option) :
	    ql_load_flash(ha, dp, dop->length));

	ql_restart_driver(ha);

	kmem_free(dp, dop->length);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed\n");
		return (EIO);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (0);
}

/*
 * ql_adm_vpd_dump
 *	Performs qladm QL_VPD_DUMP command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_vpd_dump(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	int		rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if ((CFG_IST(ha, CFG_CTRL_24258081)) == 0) {
		EL(ha, "hba does not support VPD\n");
		return (EINVAL);
	}

	if (dop->length < QL_24XX_VPD_SIZE) {
		EL(ha, "failed, length=%xh, size=%xh\n", dop->length,
		    QL_24XX_VPD_SIZE);
		return (EINVAL);
	}

	if ((rval = ql_vpd_dump(ha, (void *)(uintptr_t)dop->buffer, mode))
	    != 0) {
		EL(ha, "failed, ql_vpd_dump\n");
	} else {
		/*EMPTY*/
		QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_adm_vpd_load
 *	Performs qladm QL_VPD_LOAD command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_vpd_load(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	int		rval;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if ((CFG_IST(ha, CFG_CTRL_24258081)) == 0) {
		EL(ha, "hba does not support VPD\n");
		return (EINVAL);
	}

	if (dop->length < QL_24XX_VPD_SIZE) {
		EL(ha, "failed, length=%xh, size=%xh\n", dop->length,
		    QL_24XX_VPD_SIZE);
		return (EINVAL);
	}

	if ((rval = ql_vpd_load(ha, (void *)(uintptr_t)dop->buffer, mode))
	    != 0) {
		EL(ha, "failed, ql_vpd_dump\n");
	} else {
		/*EMPTY*/
		QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_adm_vpd_gettag
 *	Performs qladm QL_VPD_GETTAG command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_adm_vpd_gettag(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	int		rval = 0;
	uint8_t		*lbuf;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	if ((CFG_IST(ha, CFG_CTRL_24258081)) == 0) {
		EL(ha, "hba does not support VPD\n");
		return (EINVAL);
	}

	if ((lbuf = (uint8_t *)kmem_zalloc(dop->length, KM_SLEEP)) == NULL) {
		EL(ha, "mem alloc failure of %xh bytes\n", dop->length);
		rval = EFAULT;
	} else {
		if (ddi_copyin((void *)(uintptr_t)dop->buffer, lbuf,
		    dop->length, mode) != 0) {
			EL(ha, "ddi_copyin failed\n");
			kmem_free(lbuf, dop->length);
			return (EFAULT);
		}

		if ((rval = ql_vpd_lookup(ha, lbuf, lbuf, (int32_t)
		    dop->length)) < 0) {
			EL(ha, "failed vpd_lookup\n");
		} else {
			if (ddi_copyout(lbuf, (void *)(uintptr_t)dop->buffer,
			    strlen((int8_t *)lbuf)+1, mode) != 0) {
				EL(ha, "failed, ddi_copyout\n");
				rval = EFAULT;
			} else {
				rval = 0;
			}
		}
		kmem_free(lbuf, dop->length);
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_adm_updfwmodule
 *	Performs qladm QL_UPD_FWMODULE command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dop:	ql_adm_op_t structure pointer.
 *	mode:	flags.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
ql_adm_updfwmodule(ql_adapter_state_t *ha, ql_adm_op_t *dop, int mode)
{
	int			rval = DDI_SUCCESS;
	ql_link_t		*link;
	ql_adapter_state_t	*ha2 = NULL;
	uint16_t		fw_class = (uint16_t)dop->option;

	QL_PRINT_9(CE_CONT, "(%d): started\n", ha->instance);

	/* zero the firmware module reference count */
	for (link = ql_hba.first; link != NULL; link = link->next) {
		ha2 = link->base_address;
		if (fw_class == ha2->fw_class) {
			if ((rval = ddi_modclose(ha2->fw_module)) !=
			    DDI_SUCCESS) {
				EL(ha2, "modclose rval=%xh\n", rval);
				break;
			}
			ha2->fw_module = NULL;
		}
	}

	/* reload the f/w modules */
	for (link = ql_hba.first; link != NULL; link = link->next) {
		ha2 = link->base_address;

		if ((fw_class == ha2->fw_class) && (ha2->fw_class == 0)) {
			if ((rval = (int32_t)ql_fwmodule_resolve(ha2)) !=
			    QL_SUCCESS) {
				EL(ha2, "unable to load f/w module: '%x' "
				    "(rval=%xh)\n", ha2->fw_class, rval);
				rval = EFAULT;
			} else {
				EL(ha2, "f/w module updated: '%x'\n",
				    ha2->fw_class);
			}

			EL(ha2, "isp abort needed (%d)\n", ha->instance);

			ql_awaken_task_daemon(ha2, NULL, ISP_ABORT_NEEDED, 0);

			rval = 0;
		}
	}

	QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}
