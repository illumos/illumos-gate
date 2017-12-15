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

/*
 * tavor_ioctl.c
 *    Tavor IOCTL Routines
 *
 *    Implements all ioctl access into the driver.  This includes all routines
 *    necessary for updating firmware, accessing the tavor flash device, and
 *    providing interfaces for VTS.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/file.h>

#include <sys/ib/adapters/tavor/tavor.h>

/* Tavor HCA state pointer (extern) */
extern void	*tavor_statep;

/*
 * The ioctl declarations (for firmware flash burning, register read/write
 * (DEBUG-only), and VTS interfaces)
 */
static int tavor_ioctl_flash_read(tavor_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int tavor_ioctl_flash_write(tavor_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int tavor_ioctl_flash_erase(tavor_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int tavor_ioctl_flash_init(tavor_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int tavor_ioctl_flash_fini(tavor_state_t *state, dev_t dev);
static void tavor_ioctl_flash_cleanup(tavor_state_t *state);
static void tavor_ioctl_flash_cleanup_nolock(tavor_state_t *state);
#ifdef	DEBUG
static int tavor_ioctl_reg_write(tavor_state_t *state, intptr_t arg,
    int mode);
static int tavor_ioctl_reg_read(tavor_state_t *state, intptr_t arg,
    int mode);
#endif	/* DEBUG */
static int tavor_ioctl_info(tavor_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int tavor_ioctl_ports(tavor_state_t *state, intptr_t arg,
    int mode);
static int tavor_ioctl_loopback(tavor_state_t *state, intptr_t arg,
    int mode);
static int tavor_ioctl_ddr_read(tavor_state_t *state, intptr_t arg,
    int mode);

/* Tavor Flash Functions */
static void tavor_flash_read_sector(tavor_state_t *state, uint32_t sector_num);
static void tavor_flash_read_quadlet(tavor_state_t *state, uint32_t *data,
    uint32_t addr);
static int  tavor_flash_write_sector(tavor_state_t *state, uint32_t sector_num);
static int  tavor_flash_write_byte(tavor_state_t *state, uint32_t addr,
    uchar_t data);
static int  tavor_flash_erase_sector(tavor_state_t *state, uint32_t sector_num);
static int  tavor_flash_erase_chip(tavor_state_t *state);
static void tavor_flash_bank(tavor_state_t *state, uint32_t addr);
static uint32_t tavor_flash_read(tavor_state_t *state, uint32_t addr);
static void tavor_flash_write(tavor_state_t *state, uint32_t addr,
    uchar_t data);
static void tavor_flash_init(tavor_state_t *state);
static void tavor_flash_cfi_init(tavor_state_t *state, uint32_t *cfi_info,
    int *intel_xcmd);
static void tavor_flash_fini(tavor_state_t *state);
static void tavor_flash_reset(tavor_state_t *state);
static uint32_t tavor_flash_read_cfg(ddi_acc_handle_t pci_config_hdl,
    uint32_t addr);
static void tavor_flash_write_cfg(ddi_acc_handle_t pci_config_hdl,
    uint32_t addr, uint32_t data);
static void tavor_flash_cfi_byte(uint8_t *ch, uint32_t dword, int i);
static void tavor_flash_cfi_dword(uint32_t *dword, uint8_t *ch, int i);

/* Tavor loopback test functions */
static void tavor_loopback_free_qps(tavor_loopback_state_t *lstate);
static void tavor_loopback_free_state(tavor_loopback_state_t *lstate);
static int tavor_loopback_init(tavor_state_t *state,
    tavor_loopback_state_t *lstate);
static void tavor_loopback_init_qp_info(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm);
static int tavor_loopback_alloc_mem(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm, int sz);
static int tavor_loopback_alloc_qps(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm);
static int tavor_loopback_modify_qp(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm, uint_t qp_num);
static int tavor_loopback_copyout(tavor_loopback_ioctl_t *lb,
    intptr_t arg, int mode);
static int tavor_loopback_post_send(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *tx, tavor_loopback_comm_t *rx);
static int tavor_loopback_poll_cq(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm);

/* Patchable timeout values for flash operations */
int tavor_hw_flash_timeout_gpio_sema = TAVOR_HW_FLASH_TIMEOUT_GPIO_SEMA;
int tavor_hw_flash_timeout_config = TAVOR_HW_FLASH_TIMEOUT_CONFIG;
int tavor_hw_flash_timeout_write = TAVOR_HW_FLASH_TIMEOUT_WRITE;
int tavor_hw_flash_timeout_erase = TAVOR_HW_FLASH_TIMEOUT_ERASE;

/*
 * tavor_ioctl()
 */
/* ARGSUSED */
int
tavor_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	tavor_state_t	*state;
	minor_t		instance;
	int		status;

	TAVOR_TNF_ENTER(tavor_ioctl);

	if (drv_priv(credp) != 0) {
		TNF_PROBE_0(tavor_ioctl_priv_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl);
		return (EPERM);
	}

	instance = TAVOR_DEV_INSTANCE(dev);
	if (instance == -1) {
		TNF_PROBE_0(tavor_ioctl_inst_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl);
		return (EBADF);
	}

	state = ddi_get_soft_state(tavor_statep, instance);
	if (state == NULL) {
		TNF_PROBE_0(tavor_ioctl_gss_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl);
		return (EBADF);
	}

	status = 0;

	switch (cmd) {
	case TAVOR_IOCTL_FLASH_READ:
		status = tavor_ioctl_flash_read(state, dev, arg, mode);
		break;

	case TAVOR_IOCTL_FLASH_WRITE:
		status = tavor_ioctl_flash_write(state, dev, arg, mode);
		break;

	case TAVOR_IOCTL_FLASH_ERASE:
		status = tavor_ioctl_flash_erase(state, dev, arg, mode);
		break;

	case TAVOR_IOCTL_FLASH_INIT:
		status = tavor_ioctl_flash_init(state, dev, arg, mode);
		break;

	case TAVOR_IOCTL_FLASH_FINI:
		status = tavor_ioctl_flash_fini(state, dev);
		break;

	case TAVOR_IOCTL_INFO:
		status = tavor_ioctl_info(state, dev, arg, mode);
		break;

	case TAVOR_IOCTL_PORTS:
		status = tavor_ioctl_ports(state, arg, mode);
		break;

	case TAVOR_IOCTL_DDR_READ:
		status = tavor_ioctl_ddr_read(state, arg, mode);
		break;

	case TAVOR_IOCTL_LOOPBACK:
		status = tavor_ioctl_loopback(state, arg, mode);
		break;

#ifdef	DEBUG
	case TAVOR_IOCTL_REG_WRITE:
		status = tavor_ioctl_reg_write(state, arg, mode);
		break;

	case TAVOR_IOCTL_REG_READ:
		status = tavor_ioctl_reg_read(state, arg, mode);
		break;
#endif	/* DEBUG */

	default:
		status = ENOTTY;
		TNF_PROBE_0(tavor_ioctl_default_fail, TAVOR_TNF_ERROR, "");
		break;
	}
	*rvalp = status;

	TAVOR_TNF_EXIT(tavor_ioctl);
	return (status);
}

/*
 * tavor_ioctl_flash_read()
 */
static int
tavor_ioctl_flash_read(tavor_state_t *state, dev_t dev, intptr_t arg, int mode)
{
	tavor_flash_ioctl_t ioctl_info;
	int status = 0;

	TAVOR_TNF_ENTER(tavor_ioctl_flash_read);

	/*
	 * Check that flash init ioctl has been called first.  And check
	 * that the same dev_t that called init is the one calling read now.
	 */
	mutex_enter(&state->ts_fw_flashlock);
	if ((state->ts_fw_flashdev != dev) ||
	    (state->ts_fw_flashstarted == 0)) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_flash_bad_state, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_read);
		return (EIO);
	}

	/* copy user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		tavor_flash_ioctl32_t info32;

		if (ddi_copyin((void *)arg, &info32,
		    sizeof (tavor_flash_ioctl32_t), mode) != 0) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_ioctl_flash_read_copyin_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_read);
			return (EFAULT);
		}
		ioctl_info.tf_type = info32.tf_type;
		ioctl_info.tf_sector = (caddr_t)(uintptr_t)info32.tf_sector;
		ioctl_info.tf_sector_num = info32.tf_sector_num;
		ioctl_info.tf_addr = info32.tf_addr;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &ioctl_info, sizeof (tavor_flash_ioctl_t),
	    mode) != 0) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_ioctl_flash_read_copyin_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_read);
		return (EFAULT);
	}

	/*
	 * Determine type of READ ioctl
	 */
	switch (ioctl_info.tf_type) {
	case TAVOR_FLASH_READ_SECTOR:
		/* Check if sector num is too large for flash device */
		if (ioctl_info.tf_sector_num >=
		    (state->ts_fw_device_sz >> state->ts_fw_log_sector_sz)) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_flash_read_sector_num_too_large,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_read);
			return (EFAULT);
		}

		/* Perform the Sector Read */
		tavor_flash_reset(state);
		tavor_flash_read_sector(state, ioctl_info.tf_sector_num);

		/* copyout the firmware sector image data */
		if (ddi_copyout(&state->ts_fw_sector[0],
		    &ioctl_info.tf_sector[0], 1 << state->ts_fw_log_sector_sz,
		    mode) != 0) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_flash_read_copyout_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_read);
			return (EFAULT);
		}
		break;

	case TAVOR_FLASH_READ_QUADLET:
		/* Check if addr is too large for flash device */
		if (ioctl_info.tf_addr >= state->ts_fw_device_sz) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_flash_read_quad_addr_too_large,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_read);
			return (EFAULT);
		}

		/* Perform the Quadlet Read */
		tavor_flash_reset(state);
		tavor_flash_read_quadlet(state, &ioctl_info.tf_quadlet,
		    ioctl_info.tf_addr);
		break;

	default:
		TNF_PROBE_0(tavor_ioctl_flash_read_invalid_type,
		    TAVOR_TNF_ERROR, "");
		status = EIO;
		break;
	}

	/* copy results back to userland */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		tavor_flash_ioctl32_t info32;

		info32.tf_quadlet = ioctl_info.tf_quadlet;
		info32.tf_type = ioctl_info.tf_type;
		info32.tf_sector_num = ioctl_info.tf_sector_num;
		info32.tf_sector = (caddr32_t)(uintptr_t)ioctl_info.tf_sector;
		info32.tf_addr = ioctl_info.tf_addr;

		if (ddi_copyout(&info32, (void *)arg,
		    sizeof (tavor_flash_ioctl32_t), mode) != 0) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_flash_read_copyout_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_read);
			return (EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout(&ioctl_info, (void *)arg,
	    sizeof (tavor_flash_ioctl_t), mode) != 0) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_flash_read_copyout_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_read);
		return (EFAULT);
	}

	mutex_exit(&state->ts_fw_flashlock);
	TAVOR_TNF_EXIT(tavor_ioctl_flash_read);
	return (status);
}

/*
 * tavor_ioctl_flash_write()
 */
static int
tavor_ioctl_flash_write(tavor_state_t *state, dev_t dev, intptr_t arg, int mode)
{
	tavor_flash_ioctl_t	ioctl_info;
	int status = 0;

	TAVOR_TNF_ENTER(tavor_ioctl_flash_write);

	/*
	 * Check that flash init ioctl has been called first.  And check
	 * that the same dev_t that called init is the one calling write now.
	 */
	mutex_enter(&state->ts_fw_flashlock);
	if ((state->ts_fw_flashdev != dev) ||
	    (state->ts_fw_flashstarted == 0)) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_flash_bad_state, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_write);
		return (EIO);
	}

	/* copy user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		tavor_flash_ioctl32_t info32;

		if (ddi_copyin((void *)arg, &info32,
		    sizeof (tavor_flash_ioctl32_t), mode) != 0) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_ioctl_flash_write_copyin_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_write);
			return (EFAULT);
		}
		ioctl_info.tf_type = info32.tf_type;
		ioctl_info.tf_sector = (caddr_t)(uintptr_t)info32.tf_sector;
		ioctl_info.tf_sector_num = info32.tf_sector_num;
		ioctl_info.tf_addr = info32.tf_addr;
		ioctl_info.tf_byte = info32.tf_byte;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &ioctl_info,
	    sizeof (tavor_flash_ioctl_t), mode) != 0) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_ioctl_flash_write_ci_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_write);
		return (EFAULT);
	}

	/*
	 * Determine type of WRITE ioctl
	 */
	switch (ioctl_info.tf_type) {
	case TAVOR_FLASH_WRITE_SECTOR:
		/* Check if sector num is too large for flash device */
		if (ioctl_info.tf_sector_num >=
		    (state->ts_fw_device_sz >> state->ts_fw_log_sector_sz)) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_flash_write_sector_num_too_large,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_write);
			return (EFAULT);
		}

		/* copy in fw sector image data */
		if (ddi_copyin(&ioctl_info.tf_sector[0],
		    &state->ts_fw_sector[0], 1 << state->ts_fw_log_sector_sz,
		    mode) != 0) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_ioctl_flash_write_fw_sector_ci_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_write);
			return (EFAULT);
		}

		/* Perform Write Sector */
		status = tavor_flash_write_sector(state,
		    ioctl_info.tf_sector_num);
		break;

	case TAVOR_FLASH_WRITE_BYTE:
		/* Check if addr is too large for flash device */
		if (ioctl_info.tf_addr >= state->ts_fw_device_sz) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_flash_write_byte_addr_too_large,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_write);
			return (EFAULT);
		}

		/* Perform Write Byte */
		tavor_flash_bank(state, ioctl_info.tf_addr);
		tavor_flash_reset(state);
		status = tavor_flash_write_byte(state, ioctl_info.tf_addr,
		    ioctl_info.tf_byte);
		tavor_flash_reset(state);
		break;

	default:
		TNF_PROBE_0(tavor_ioctl_flash_write_invalid_type,
		    TAVOR_TNF_ERROR, "");
		status = EIO;
		break;
	}

	mutex_exit(&state->ts_fw_flashlock);
	TAVOR_TNF_EXIT(tavor_ioctl_flash_write);
	return (status);
}

/*
 * tavor_ioctl_flash_erase()
 */
static int
tavor_ioctl_flash_erase(tavor_state_t *state, dev_t dev, intptr_t arg, int mode)
{
	tavor_flash_ioctl_t	ioctl_info;
	int status = 0;

	TAVOR_TNF_ENTER(tavor_ioctl_flash_erase);

	/*
	 * Check that flash init ioctl has been called first.  And check
	 * that the same dev_t that called init is the one calling erase now.
	 */
	mutex_enter(&state->ts_fw_flashlock);
	if ((state->ts_fw_flashdev != dev) ||
	    (state->ts_fw_flashstarted == 0)) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_flash_bad_state, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_erase);
		return (EIO);
	}

	/* copy user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		tavor_flash_ioctl32_t info32;

		if (ddi_copyin((void *)arg, &info32,
		    sizeof (tavor_flash_ioctl32_t), mode) != 0) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_ioctl_flash_read_copyin_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_erase);
			return (EFAULT);
		}
		ioctl_info.tf_type = info32.tf_type;
		ioctl_info.tf_sector_num = info32.tf_sector_num;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &ioctl_info, sizeof (tavor_flash_ioctl_t),
	    mode) != 0) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_ioctl_flash_erase_ci_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_erase);
		return (EFAULT);
	}

	/*
	 * Determine type of ERASE ioctl
	 */
	switch (ioctl_info.tf_type) {
	case TAVOR_FLASH_ERASE_SECTOR:
		/* Check if sector num is too large for flash device */
		if (ioctl_info.tf_sector_num >=
		    (state->ts_fw_device_sz >> state->ts_fw_log_sector_sz)) {
			mutex_exit(&state->ts_fw_flashlock);
			TNF_PROBE_0(tavor_flash_erase_sector_num_too_large,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_flash_write);
			return (EFAULT);
		}

		/* Perform Sector Erase */
		status = tavor_flash_erase_sector(state,
		    ioctl_info.tf_sector_num);
		break;

	case TAVOR_FLASH_ERASE_CHIP:
		/* Perform Chip Erase */
		status = tavor_flash_erase_chip(state);
		break;

	default:
		TNF_PROBE_0(tavor_ioctl_flash_erase_invalid_type,
		    TAVOR_TNF_ERROR, "");
		status = EIO;
		break;
	}

	mutex_exit(&state->ts_fw_flashlock);
	TAVOR_TNF_EXIT(tavor_ioctl_flash_erase);
	return (status);
}

/*
 * tavor_ioctl_flash_init()
 */
static int
tavor_ioctl_flash_init(tavor_state_t *state, dev_t dev, intptr_t arg, int mode)
{
	tavor_flash_init_ioctl_t init_info;
	int ret;
	int intel_xcmd = 0;

	TAVOR_TNF_ENTER(tavor_ioctl_flash_init);

	/*
	 * init cannot be called more than once.  If we have already init'd the
	 * flash, return directly.
	 */
	mutex_enter(&state->ts_fw_flashlock);
	if (state->ts_fw_flashstarted == 1) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_ioctl_flash_init_already_started,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_init);
		return (EIO);
	}

	/* copyin the user struct to kernel */
	if (ddi_copyin((void *)arg, &init_info,
	    sizeof (tavor_flash_init_ioctl_t), mode) != 0) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_flash_init_ioctl_copyin_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_init);
		return (EFAULT);
	}

	/* Init Flash */
	tavor_flash_init(state);

	/* Read CFI info */
	tavor_flash_cfi_init(state, &init_info.tf_cfi_info[0], &intel_xcmd);

	/*
	 * Return error if the command set is unknown.
	 */
	if (state->ts_fw_cmdset == TAVOR_FLASH_UNKNOWN_CMDSET) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_1(tavor_ioctl_flash_init_cmdset_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg,
		    "UNKNOWN flash command set");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_init);
		return (EFAULT);
	}

	/* Read HWREV - least significant 8 bits is revision ID */
	init_info.tf_hwrev = pci_config_get32(state->ts_pci_cfghdl,
	    TAVOR_HW_FLASH_CFG_HWREV) & 0xFF;

	/* Fill in the firmwate revision numbers */
	init_info.tf_fwrev.tfi_maj	= state->ts_fw.fw_rev_major;
	init_info.tf_fwrev.tfi_min	= state->ts_fw.fw_rev_minor;
	init_info.tf_fwrev.tfi_sub	= state->ts_fw.fw_rev_subminor;

	/* Alloc flash mem for one sector size */
	state->ts_fw_sector = (uint32_t *)kmem_zalloc(1 <<
	    state->ts_fw_log_sector_sz, KM_SLEEP);

	/* Set HW part number and length */
	init_info.tf_pn_len = state->ts_hca_pn_len;
	if (state->ts_hca_pn_len != 0) {
		(void) memcpy(init_info.tf_hwpn, state->ts_hca_pn,
		    state->ts_hca_pn_len);
	}

	/* Copy ioctl results back to userland */
	if (ddi_copyout(&init_info, (void *)arg,
	    sizeof (tavor_flash_init_ioctl_t), mode) != 0) {

		tavor_ioctl_flash_cleanup_nolock(state);

		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_ioctl_flash_init_copyout_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_init);
		return (EFAULT);
	}

	/* Set flash state to started */
	state->ts_fw_flashstarted = 1;
	state->ts_fw_flashdev	  = dev;

	mutex_exit(&state->ts_fw_flashlock);

	/*
	 * If "flash init" is successful, add an "on close" callback to the
	 * current dev node to ensure that "flash fini" gets called later
	 * even if the userland process prematurely exits.
	 */
	ret = tavor_umap_db_set_onclose_cb(dev,
	    TAVOR_ONCLOSE_FLASH_INPROGRESS,
	    (void (*)(void *))tavor_ioctl_flash_cleanup, state);
	if (ret != DDI_SUCCESS) {
		(void) tavor_ioctl_flash_fini(state, dev);

		TNF_PROBE_0(tavor_ioctl_flash_init_set_cb_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_init);
		return (EFAULT);
	}

	TAVOR_TNF_EXIT(tavor_ioctl_flash_init);
	return (0);
}

/*
 * tavor_ioctl_flash_fini()
 */
static int
tavor_ioctl_flash_fini(tavor_state_t *state, dev_t dev)
{
	int ret;

	TAVOR_TNF_ENTER(tavor_ioctl_flash_fini);

	/*
	 * Check that flash init ioctl has been called first.  And check
	 * that the same dev_t that called init is the one calling fini now.
	 */
	mutex_enter(&state->ts_fw_flashlock);
	if ((state->ts_fw_flashdev != dev) ||
	    (state->ts_fw_flashstarted == 0)) {
		mutex_exit(&state->ts_fw_flashlock);
		TNF_PROBE_0(tavor_flash_bad_state, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_fini);
		return (EIO);
	}

	tavor_ioctl_flash_cleanup_nolock(state);

	mutex_exit(&state->ts_fw_flashlock);

	/*
	 * If "flash fini" is successful, remove the "on close" callback
	 * that was setup during "flash init".
	 */
	ret = tavor_umap_db_clear_onclose_cb(dev,
	    TAVOR_ONCLOSE_FLASH_INPROGRESS);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_flash_fini_clear_cb_fail, TAVOR_TNF_ERROR,
		    "");
		TAVOR_TNF_EXIT(tavor_ioctl_flash_fini);
		return (EFAULT);
	}

	TAVOR_TNF_EXIT(tavor_ioctl_flash_fini);
	return (0);
}


/*
 * tavor_ioctl_flash_cleanup()
 */
static void
tavor_ioctl_flash_cleanup(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_ioctl_flash_cleanup);

	mutex_enter(&state->ts_fw_flashlock);
	tavor_ioctl_flash_cleanup_nolock(state);
	mutex_exit(&state->ts_fw_flashlock);

	TAVOR_TNF_EXIT(tavor_ioctl_flash_cleanup);
}


/*
 * tavor_ioctl_flash_cleanup_nolock()
 */
static void
tavor_ioctl_flash_cleanup_nolock(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_ioctl_flash_cleanup_nolock);

	ASSERT(MUTEX_HELD(&state->ts_fw_flashlock));

	/* free flash mem */
	kmem_free(state->ts_fw_sector, 1 << state->ts_fw_log_sector_sz);

	/* Fini the Flash */
	tavor_flash_fini(state);

	/* Set flash state to fini */
	state->ts_fw_flashstarted = 0;
	state->ts_fw_flashdev	  = 0;

	TAVOR_TNF_EXIT(tavor_ioctl_flash_cleanup_nolock);
}


/*
 * tavor_ioctl_info()
 */
static int
tavor_ioctl_info(tavor_state_t *state, dev_t dev, intptr_t arg, int mode)
{
	tavor_info_ioctl_t	 info;
	tavor_flash_init_ioctl_t init_info;

	TAVOR_TNF_ENTER(tavor_ioctl_info);

	/*
	 * Access to Tavor VTS ioctls is not allowed in "maintenance mode".
	 */
	if (state->ts_operational_mode == TAVOR_MAINTENANCE_MODE) {
		TNF_PROBE_0(tavor_ioctl_info_maintenance_mode_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_info);
		return (EFAULT);
	}

	/* copyin the user struct to kernel */
	if (ddi_copyin((void *)arg, &info, sizeof (tavor_info_ioctl_t),
	    mode) != 0) {
		TNF_PROBE_0(tavor_ioctl_info_copyin_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_info);
		return (EFAULT);
	}

	/*
	 * Check ioctl revision
	 */
	if (info.ti_revision != TAVOR_VTS_IOCTL_REVISION) {
		TNF_PROBE_0(tavor_ioctl_info_bad_rev, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_info);
		return (EINVAL);
	}

	/*
	 * If the 'fw_device_sz' has not been initialized yet, we initialize it
	 * here.  This is done by leveraging the
	 * tavor_ioctl_flash_init()/fini() calls.  We also hold our own mutex
	 * around this operation in case we have multiple VTS threads in
	 * process at the same time.
	 */
	mutex_enter(&state->ts_info_lock);
	if (state->ts_fw_device_sz == 0) {
		if (tavor_ioctl_flash_init(state, dev, (intptr_t)&init_info,
		    (FKIOCTL | mode)) != 0) {
			mutex_exit(&state->ts_info_lock);
			TNF_PROBE_0(tavor_ioctl_info_flash_init_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_info);
			return (EFAULT);
		}
		(void) tavor_ioctl_flash_fini(state, dev);
	}
	mutex_exit(&state->ts_info_lock);

	info.ti_hw_rev		 = state->ts_adapter.rev_id;
	info.ti_flash_sz	 = state->ts_fw_device_sz;
	info.ti_fw_rev.tfi_maj	 = state->ts_fw.fw_rev_major;
	info.ti_fw_rev.tfi_min	 = state->ts_fw.fw_rev_minor;
	info.ti_fw_rev.tfi_sub	 = state->ts_fw.fw_rev_subminor;
	info.ti_mem_start_offset = 0;
	info.ti_mem_end_offset	 = state->ts_ddr.ddr_endaddr -
	    state->ts_ddr.ddr_baseaddr;

	/* Copy ioctl results back to user struct */
	if (ddi_copyout(&info, (void *)arg, sizeof (tavor_info_ioctl_t),
	    mode) != 0) {
		TNF_PROBE_0(tavor_ioctl_info_copyout_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_info);
		return (EFAULT);
	}

	TAVOR_TNF_EXIT(tavor_ioctl_info);
	return (0);
}

/*
 * tavor_ioctl_ports()
 */
static int
tavor_ioctl_ports(tavor_state_t *state, intptr_t arg, int mode)
{
	tavor_ports_ioctl_t	info;
	tavor_stat_port_ioctl_t	portstat;
	ibt_hca_portinfo_t	pi;
	uint_t			tbl_size;
	ib_gid_t		*sgid_tbl;
	ib_pkey_t		*pkey_tbl;
	int			i;

	TAVOR_TNF_ENTER(tavor_ioctl_ports);

	/*
	 * Access to Tavor VTS ioctls is not allowed in "maintenance mode".
	 */
	if (state->ts_operational_mode == TAVOR_MAINTENANCE_MODE) {
		TNF_PROBE_0(tavor_ioctl_ports_maintenance_mode_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_ports);
		return (EFAULT);
	}

	/* copyin the user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		tavor_ports_ioctl32_t info32;

		if (ddi_copyin((void *)arg, &info32,
		    sizeof (tavor_ports_ioctl32_t), mode) != 0) {
			TNF_PROBE_0(tavor_ioctl_ports_copyin_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_ports);
			return (EFAULT);
		}
		info.tp_revision  = info32.tp_revision;
		info.tp_ports	  =
		    (tavor_stat_port_ioctl_t *)(uintptr_t)info32.tp_ports;
		info.tp_num_ports = info32.tp_num_ports;

	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &info, sizeof (tavor_ports_ioctl_t),
	    mode) != 0) {
		TNF_PROBE_0(tavor_ioctl_ports_copyin_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_ports);
		return (EFAULT);
	}

	/*
	 * Check ioctl revision
	 */
	if (info.tp_revision != TAVOR_VTS_IOCTL_REVISION) {
		TNF_PROBE_0(tavor_ioctl_ports_bad_rev, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_ports);
		return (EINVAL);
	}

	/* Allocate space for temporary GID table/PKey table */
	tbl_size = (1 << state->ts_cfg_profile->cp_log_max_gidtbl);
	sgid_tbl = (ib_gid_t *)kmem_zalloc(tbl_size * sizeof (ib_gid_t),
	    KM_SLEEP);
	tbl_size = (1 << state->ts_cfg_profile->cp_log_max_pkeytbl);
	pkey_tbl = (ib_pkey_t *)kmem_zalloc(tbl_size * sizeof (ib_pkey_t),
	    KM_SLEEP);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sgid_tbl, *pkey_tbl))

	/*
	 * Setup the number of ports, then loop through all ports and
	 * query properties of each.
	 */
	info.tp_num_ports = (uint8_t)state->ts_cfg_profile->cp_num_ports;
	for (i = 0; i < info.tp_num_ports; i++) {
		/*
		 * Get portstate information from the device.  If
		 * tavor_port_query() fails, leave zeroes in user
		 * struct port entry and continue.
		 */
		bzero(&pi, sizeof (ibt_hca_portinfo_t));
		pi.p_sgid_tbl = sgid_tbl;
		pi.p_pkey_tbl = pkey_tbl;
		if (tavor_port_query(state, i + 1, &pi) != 0) {
			TNF_PROBE_0(tavor_ioctl_ports_query_failed,
			    TAVOR_TNF_ERROR, "");
		}

		portstat.tsp_port_num	= pi.p_port_num;
		portstat.tsp_state	= pi.p_linkstate;
		portstat.tsp_guid	= pi.p_sgid_tbl[0].gid_guid;

		/*
		 * Copy queried port results back to user struct.  If
		 * this fails, then break out of loop, attempt to copy
		 * out remaining info to user struct, and return (without
		 * error).
		 */
		if (ddi_copyout(&portstat,
		    &(((tavor_stat_port_ioctl_t *)info.tp_ports)[i]),
		    sizeof (tavor_stat_port_ioctl_t), mode) != 0) {
			break;
		}
	}

	/* Free the temporary space used for GID table/PKey table */
	tbl_size = (1 << state->ts_cfg_profile->cp_log_max_gidtbl);
	kmem_free(sgid_tbl, tbl_size * sizeof (ib_gid_t));
	tbl_size = (1 << state->ts_cfg_profile->cp_log_max_pkeytbl);
	kmem_free(pkey_tbl, tbl_size * sizeof (ib_pkey_t));

	/* Copy ioctl results back to user struct */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		tavor_ports_ioctl32_t info32;

		info32.tp_revision  = info.tp_revision;
		info32.tp_ports	    = (caddr32_t)(uintptr_t)info.tp_ports;
		info32.tp_num_ports = info.tp_num_ports;

		if (ddi_copyout(&info32, (void *)arg,
		    sizeof (tavor_ports_ioctl32_t), mode) != 0) {
			TNF_PROBE_0(tavor_ioctl_ports_copyout_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_ports);
			return (EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout(&info, (void *)arg, sizeof (tavor_ports_ioctl_t),
	    mode) != 0) {
		TNF_PROBE_0(tavor_ioctl_ports_copyout_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_ports);
		return (EFAULT);
	}

	TAVOR_TNF_EXIT(tavor_ioctl_ports);
	return (0);
}

/*
 * tavor_ioctl_loopback()
 */
static int
tavor_ioctl_loopback(tavor_state_t *state, intptr_t arg, int mode)
{
	tavor_loopback_ioctl_t	lb;
	tavor_loopback_state_t	lstate;
	ibt_hca_portinfo_t 	pi;
	uint_t			tbl_size, loopmax, max_usec;
	ib_gid_t		*sgid_tbl;
	ib_pkey_t		*pkey_tbl;
	int			j, iter, ret;

	TAVOR_TNF_ENTER(tavor_ioctl_loopback);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(lstate))

	/*
	 * Access to Tavor VTS ioctls is not allowed in "maintenance mode".
	 */
	if (state->ts_operational_mode == TAVOR_MAINTENANCE_MODE) {
		TNF_PROBE_0(tavor_ioctl_loopback_maintenance_mode_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* copyin the user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		tavor_loopback_ioctl32_t lb32;

		if (ddi_copyin((void *)arg, &lb32,
		    sizeof (tavor_loopback_ioctl32_t), mode) != 0) {
			TNF_PROBE_0(tavor_ioctl_loopback_copyin_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_loopback);
			return (EFAULT);
		}
		lb.tlb_revision	    = lb32.tlb_revision;
		lb.tlb_send_buf	    = (caddr_t)(uintptr_t)lb32.tlb_send_buf;
		lb.tlb_fail_buf	    = (caddr_t)(uintptr_t)lb32.tlb_fail_buf;
		lb.tlb_buf_sz	    = lb32.tlb_buf_sz;
		lb.tlb_num_iter	    = lb32.tlb_num_iter;
		lb.tlb_pass_done    = lb32.tlb_pass_done;
		lb.tlb_timeout	    = lb32.tlb_timeout;
		lb.tlb_error_type   = lb32.tlb_error_type;
		lb.tlb_port_num	    = lb32.tlb_port_num;
		lb.tlb_num_retry    = lb32.tlb_num_retry;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &lb, sizeof (tavor_loopback_ioctl_t),
	    mode) != 0) {
		TNF_PROBE_0(tavor_ioctl_loopback_copyin_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* Initialize the internal loopback test state structure */
	bzero(&lstate, sizeof (tavor_loopback_state_t));

	/*
	 * Check ioctl revision
	 */
	if (lb.tlb_revision != TAVOR_VTS_IOCTL_REVISION) {
		lb.tlb_error_type = TAVOR_LOOPBACK_INVALID_REVISION;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		TNF_PROBE_0(tavor_ioctl_loopback_bad_rev,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EINVAL);
	}

	/* Validate that specified port number is legal */
	if (!tavor_portnum_is_valid(state, lb.tlb_port_num)) {
		lb.tlb_error_type = TAVOR_LOOPBACK_INVALID_PORT;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		TNF_PROBE_0(tavor_ioctl_loopback_inv_port,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EINVAL);
	}

	/* Allocate space for temporary GID table/PKey table */
	tbl_size = (1 << state->ts_cfg_profile->cp_log_max_gidtbl);
	sgid_tbl = (ib_gid_t *)kmem_zalloc(tbl_size * sizeof (ib_gid_t),
	    KM_SLEEP);
	tbl_size = (1 << state->ts_cfg_profile->cp_log_max_pkeytbl);
	pkey_tbl = (ib_pkey_t *)kmem_zalloc(tbl_size * sizeof (ib_pkey_t),
	    KM_SLEEP);

	/*
	 * Get portstate information from specific port on device
	 */
	bzero(&pi, sizeof (ibt_hca_portinfo_t));
	pi.p_sgid_tbl = sgid_tbl;
	pi.p_pkey_tbl = pkey_tbl;
	if (tavor_port_query(state, lb.tlb_port_num, &pi) != 0) {
		/* Free the temporary space used for GID table/PKey table */
		tbl_size = (1 << state->ts_cfg_profile->cp_log_max_gidtbl);
		kmem_free(sgid_tbl, tbl_size * sizeof (ib_gid_t));
		tbl_size = (1 << state->ts_cfg_profile->cp_log_max_pkeytbl);
		kmem_free(pkey_tbl, tbl_size * sizeof (ib_pkey_t));

		lb.tlb_error_type = TAVOR_LOOPBACK_INVALID_PORT;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TNF_PROBE_0(tavor_ioctl_loopback_bad_port,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EINVAL);
	}

	lstate.tls_port	   = pi.p_port_num;
	lstate.tls_lid	   = pi.p_base_lid;
	lstate.tls_pkey_ix = (pi.p_linkstate == TAVOR_PORT_LINK_ACTIVE) ? 1 : 0;
	lstate.tls_state   = state;
	lstate.tls_retry   = lb.tlb_num_retry;

	/* Free the temporary space used for GID table/PKey table */
	tbl_size = (1 << state->ts_cfg_profile->cp_log_max_gidtbl);
	kmem_free(sgid_tbl, tbl_size * sizeof (ib_gid_t));
	tbl_size = (1 << state->ts_cfg_profile->cp_log_max_pkeytbl);
	kmem_free(pkey_tbl, tbl_size * sizeof (ib_pkey_t));

	/*
	 * Compute the timeout duration in usec per the formula:
	 *    to_usec_per_retry = 4.096us * (2 ^ supplied_timeout)
	 * (plus we add a little fudge-factor here too)
	 */
	lstate.tls_timeout = lb.tlb_timeout;
	max_usec = (4096 * (1 << lstate.tls_timeout)) / 1000;
	max_usec = max_usec * (lstate.tls_retry + 1);
	max_usec = max_usec + 10000;

	/*
	 * Determine how many times we should loop before declaring a
	 * timeout failure.
	 */
	loopmax	 = max_usec/TAVOR_VTS_LOOPBACK_MIN_WAIT_DUR;
	if ((max_usec % TAVOR_VTS_LOOPBACK_MIN_WAIT_DUR) != 0) {
		loopmax++;
	}

	if (lb.tlb_send_buf == NULL || lb.tlb_buf_sz == 0) {
		lb.tlb_error_type = TAVOR_LOOPBACK_SEND_BUF_INVALID;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TNF_PROBE_0(tavor_ioctl_loopback_buf_null,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EINVAL);
	}

	/* Allocate protection domain (PD) */
	if (tavor_loopback_init(state, &lstate) != 0) {
		lb.tlb_error_type = lstate.tls_err;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* Allocate and register a TX buffer */
	if (tavor_loopback_alloc_mem(&lstate, &lstate.tls_tx,
	    lb.tlb_buf_sz) != 0) {
		lb.tlb_error_type =
		    TAVOR_LOOPBACK_SEND_BUF_MEM_REGION_ALLOC_FAIL;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TNF_PROBE_0(tavor_ioctl_loopback_txbuf_alloc_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* Allocate and register an RX buffer */
	if (tavor_loopback_alloc_mem(&lstate, &lstate.tls_rx,
	    lb.tlb_buf_sz) != 0) {
		lb.tlb_error_type =
		    TAVOR_LOOPBACK_RECV_BUF_MEM_REGION_ALLOC_FAIL;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TNF_PROBE_0(tavor_ioctl_loopback_rxbuf_alloc_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* Copy in the transmit buffer data */
	if (ddi_copyin((void *)lb.tlb_send_buf, lstate.tls_tx.tlc_buf,
	    lb.tlb_buf_sz, mode) != 0) {
		lb.tlb_error_type = TAVOR_LOOPBACK_SEND_BUF_COPY_FAIL;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TNF_PROBE_0(tavor_ioctl_loopback_tx_copyin_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* Allocate the transmit QP and CQs */
	lstate.tls_err = TAVOR_LOOPBACK_XMIT_SEND_CQ_ALLOC_FAIL;
	if (tavor_loopback_alloc_qps(&lstate, &lstate.tls_tx) != 0) {
		lb.tlb_error_type = lstate.tls_err;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TNF_PROBE_0(tavor_ioctl_loopback_txqp_alloc_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* Allocate the receive QP and CQs */
	lstate.tls_err = TAVOR_LOOPBACK_RECV_SEND_CQ_ALLOC_FAIL;
	if (tavor_loopback_alloc_qps(&lstate, &lstate.tls_rx) != 0) {
		lb.tlb_error_type = lstate.tls_err;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TNF_PROBE_0(tavor_ioctl_loopback_rxqp_alloc_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* Activate the TX QP (connect to RX QP) */
	lstate.tls_err = TAVOR_LOOPBACK_XMIT_QP_INIT_FAIL;
	if (tavor_loopback_modify_qp(&lstate, &lstate.tls_tx,
	    lstate.tls_rx.tlc_qp_num) != 0) {
		lb.tlb_error_type = lstate.tls_err;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TNF_PROBE_0(tavor_ioctl_loopback_txqp_init_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* Activate the RX QP (connect to TX QP) */
	lstate.tls_err = TAVOR_LOOPBACK_RECV_QP_INIT_FAIL;
	if (tavor_loopback_modify_qp(&lstate, &lstate.tls_rx,
	    lstate.tls_tx.tlc_qp_num) != 0) {
		lb.tlb_error_type = lstate.tls_err;
		(void) tavor_loopback_copyout(&lb, arg, mode);
		tavor_loopback_free_state(&lstate);
		TNF_PROBE_0(tavor_ioctl_loopback_rxqp_init_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_loopback);
		return (EFAULT);
	}

	/* Run the loopback test (for specified number of iterations) */
	lb.tlb_pass_done = 0;
	for (iter = 0; iter < lb.tlb_num_iter; iter++) {
		lstate.tls_err = 0;
		bzero(lstate.tls_rx.tlc_buf, lb.tlb_buf_sz);

		/* Post RDMA Write work request */
		if (tavor_loopback_post_send(&lstate, &lstate.tls_tx,
		    &lstate.tls_rx) != IBT_SUCCESS) {
			lb.tlb_error_type = TAVOR_LOOPBACK_WQE_POST_FAIL;
			(void) tavor_loopback_copyout(&lb, arg, mode);
			tavor_loopback_free_state(&lstate);
			TNF_PROBE_0(tavor_ioctl_loopback_wqe_post_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_ioctl_loopback);
			return (EFAULT);
		}

		/* Poll the TX CQ for a completion every few ticks */
		for (j = 0; j < loopmax; j++) {
			delay(drv_usectohz(TAVOR_VTS_LOOPBACK_MIN_WAIT_DUR));

			ret = tavor_loopback_poll_cq(&lstate, &lstate.tls_tx);
			if (((ret != IBT_SUCCESS) && (ret != IBT_CQ_EMPTY)) ||
			    ((ret == IBT_CQ_EMPTY) && (j == loopmax - 1))) {
				lb.tlb_error_type = TAVOR_LOOPBACK_CQ_POLL_FAIL;
				if (ddi_copyout(lstate.tls_rx.tlc_buf,
				    lb.tlb_fail_buf, lstate.tls_tx.tlc_buf_sz,
				    mode) != 0) {
					TNF_PROBE_0(
					    tavor_ioctl_loopback_xfer_co_fail,
					    TAVOR_TNF_ERROR, "");
					TAVOR_TNF_EXIT(tavor_ioctl_loopback);
					return (EFAULT);
				}
				(void) tavor_loopback_copyout(&lb, arg, mode);
				tavor_loopback_free_state(&lstate);
				TNF_PROBE_0(tavor_ioctl_loopback_xfer_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_ioctl_loopback);
				return (EFAULT);
			} else if (ret == IBT_CQ_EMPTY) {
				continue;
			}

			/* Compare the data buffers */
			if (bcmp(lstate.tls_tx.tlc_buf, lstate.tls_rx.tlc_buf,
			    lb.tlb_buf_sz) == 0) {
				break;
			} else {
				lb.tlb_error_type =
				    TAVOR_LOOPBACK_SEND_RECV_COMPARE_FAIL;
				if (ddi_copyout(lstate.tls_rx.tlc_buf,
				    lb.tlb_fail_buf, lstate.tls_tx.tlc_buf_sz,
				    mode) != 0) {
					TNF_PROBE_0(
					    tavor_ioctl_loopback_bcmp_co_fail,
					    TAVOR_TNF_ERROR, "");
					TAVOR_TNF_EXIT(tavor_ioctl_loopback);
					return (EFAULT);
				}
				(void) tavor_loopback_copyout(&lb, arg, mode);
				tavor_loopback_free_state(&lstate);
				TNF_PROBE_0(tavor_ioctl_loopback_bcmp_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_ioctl_loopback);
				return (EFAULT);
			}
		}

		lstate.tls_err	 = TAVOR_LOOPBACK_SUCCESS;
		lb.tlb_pass_done = iter + 1;
	}

	lb.tlb_error_type = TAVOR_LOOPBACK_SUCCESS;

	/* Copy ioctl results back to user struct */
	ret = tavor_loopback_copyout(&lb, arg, mode);

	/* Free up everything and release all consumed resources */
	tavor_loopback_free_state(&lstate);

	TAVOR_TNF_EXIT(tavor_ioctl_loopback);
	return (ret);
}

/*
 * tavor_ioctl_ddr_read()
 */
static int
tavor_ioctl_ddr_read(tavor_state_t *state, intptr_t arg, int mode)
{
	tavor_ddr_read_ioctl_t	rdreg;
	uint32_t		*addr;
	uintptr_t		baseaddr;
	uint64_t		ddr_size;

	TAVOR_TNF_ENTER(tavor_ioctl_ddr_read);

	/*
	 * Access to Tavor VTS ioctls is not allowed in "maintenance mode".
	 */
	if (state->ts_operational_mode == TAVOR_MAINTENANCE_MODE) {
		TNF_PROBE_0(tavor_ioctl_ddr_read_maintenance_mode_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_ddr_read);
		return (EFAULT);
	}

	/* copyin the user struct to kernel */
	if (ddi_copyin((void *)arg, &rdreg, sizeof (tavor_ddr_read_ioctl_t),
	    mode) != 0) {
		TNF_PROBE_0(tavor_ioctl_ddr_read_copyin_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_ddr_read);
		return (EFAULT);
	}

	/*
	 * Check ioctl revision
	 */
	if (rdreg.tdr_revision != TAVOR_VTS_IOCTL_REVISION) {
		TNF_PROBE_0(tavor_ioctl_ddr_read_bad_rev, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_ddr_read);
		return (EINVAL);
	}

	/*
	 * Check for valid offset
	 */
	ddr_size = (state->ts_ddr.ddr_endaddr - state->ts_ddr.ddr_baseaddr + 1);
	if ((uint64_t)rdreg.tdr_offset >= ddr_size) {
		TNF_PROBE_0(tavor_ioctl_ddr_read_bad_offset,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_ddr_read);
		return (EINVAL);
	}

	/* Determine base address for requested register read */
	baseaddr = (uintptr_t)state->ts_reg_ddr_baseaddr;

	/* Ensure that address is properly-aligned */
	addr = (uint32_t *)((baseaddr + rdreg.tdr_offset) & ~0x3);

	/* Read the register pointed to by addr */
	rdreg.tdr_data = ddi_get32(state->ts_reg_cmdhdl, addr);

	/* Copy ioctl results back to user struct */
	if (ddi_copyout(&rdreg, (void *)arg, sizeof (tavor_ddr_read_ioctl_t),
	    mode) != 0) {
		TNF_PROBE_0(tavor_ioctl_ddr_read_copyout_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_ddr_read);
		return (EFAULT);
	}

	TAVOR_TNF_EXIT(tavor_ioctl_ddr_read);
	return (0);
}


#ifdef	DEBUG
/*
 * tavor_ioctl_reg_read()
 */
static int
tavor_ioctl_reg_read(tavor_state_t *state, intptr_t arg, int mode)
{
	tavor_reg_ioctl_t	rdreg;
	uint32_t		*addr;
	uintptr_t		baseaddr;
	int			status;

	TAVOR_TNF_ENTER(tavor_ioctl_reg_read);

	/*
	 * Access to Tavor registers is not allowed in "maintenance mode".
	 * This is primarily because the device may not have BARs to access
	 */
	if (state->ts_operational_mode == TAVOR_MAINTENANCE_MODE) {
		TNF_PROBE_0(tavor_ioctl_reg_read_maintence_mode_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_reg_read);
		return (EFAULT);
	}

	/* Copy in the tavor_reg_ioctl_t structure */
	status = ddi_copyin((void *)arg, &rdreg, sizeof (tavor_reg_ioctl_t),
	    mode);
	if (status != 0) {
		TNF_PROBE_0(tavor_ioctl_reg_read_copyin_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_reg_read);
		return (EFAULT);
	}

	/* Determine base address for requested register set */
	switch (rdreg.trg_reg_set) {
	case TAVOR_CMD_BAR:
		baseaddr = (uintptr_t)state->ts_reg_cmd_baseaddr;
		break;

	case TAVOR_UAR_BAR:
		baseaddr = (uintptr_t)state->ts_reg_uar_baseaddr;
		break;

	case TAVOR_DDR_BAR:
		baseaddr = (uintptr_t)state->ts_reg_ddr_baseaddr;
		break;

	default:
		TNF_PROBE_0(tavor_ioctl_reg_read_invregset_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_reg_read);
		return (EFAULT);
	}

	/* Ensure that address is properly-aligned */
	addr = (uint32_t *)((baseaddr + rdreg.trg_offset) & ~0x3);

	/* Read the register pointed to by addr */
	rdreg.trg_data = ddi_get32(state->ts_reg_cmdhdl, addr);

	/* Copy in the result into the tavor_reg_ioctl_t structure */
	status = ddi_copyout(&rdreg, (void *)arg, sizeof (tavor_reg_ioctl_t),
	    mode);
	if (status != 0) {
		TNF_PROBE_0(tavor_ioctl_reg_read_copyout_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_reg_read);
		return (EFAULT);
	}

	TAVOR_TNF_EXIT(tavor_ioctl_reg_read);
	return (0);
}


/*
 * tavor_ioctl_reg_write()
 */
static int
tavor_ioctl_reg_write(tavor_state_t *state, intptr_t arg, int mode)
{
	tavor_reg_ioctl_t	wrreg;
	uint32_t		*addr;
	uintptr_t		baseaddr;
	int			status;

	TAVOR_TNF_ENTER(tavor_ioctl_reg_write);

	/*
	 * Access to Tavor registers is not allowed in "maintenance mode".
	 * This is primarily because the device may not have BARs to access
	 */
	if (state->ts_operational_mode == TAVOR_MAINTENANCE_MODE) {
		TNF_PROBE_0(tavor_ioctl_reg_write_maintence_mode_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_reg_write);
		return (EFAULT);
	}

	/* Copy in the tavor_reg_ioctl_t structure */
	status = ddi_copyin((void *)arg, &wrreg, sizeof (tavor_reg_ioctl_t),
	    mode);
	if (status != 0) {
		TNF_PROBE_0(tavor_ioctl_reg_write_copyin_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_reg_write);
		return (EFAULT);
	}

	/* Determine base address for requested register set */
	switch (wrreg.trg_reg_set) {
	case TAVOR_CMD_BAR:
		baseaddr = (uintptr_t)state->ts_reg_cmd_baseaddr;
		break;

	case TAVOR_UAR_BAR:
		baseaddr = (uintptr_t)state->ts_reg_uar_baseaddr;
		break;

	case TAVOR_DDR_BAR:
		baseaddr = (uintptr_t)state->ts_reg_ddr_baseaddr;
		break;

	default:
		TNF_PROBE_0(tavor_ioctl_reg_write_invregset_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ioctl_reg_write);
		return (EFAULT);
	}

	/* Ensure that address is properly-aligned */
	addr = (uint32_t *)((baseaddr + wrreg.trg_offset) & ~0x3);

	/* Write the data to the register pointed to by addr */
	ddi_put32(state->ts_reg_cmdhdl, addr, wrreg.trg_data);

	TAVOR_TNF_EXIT(tavor_ioctl_reg_write);
	return (0);
}
#endif	/* DEBUG */

/*
 * tavor_flash_reset()
 */
static void
tavor_flash_reset(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_flash_reset);

	/*
	 * Performs a reset to the flash device.  After a reset the flash will
	 * be operating in normal mode (capable of read/write, etc.).
	 */
	switch (state->ts_fw_cmdset) {
	case TAVOR_FLASH_AMD_CMDSET:
		tavor_flash_write(state, 0x555, TAVOR_HW_FLASH_RESET_AMD);
		break;

	case TAVOR_FLASH_INTEL_CMDSET:
		tavor_flash_write(state, 0x555, TAVOR_HW_FLASH_RESET_INTEL);
		break;

	default:
		break;
	}

	TAVOR_TNF_EXIT(tavor_flash_reset);
}

/*
 * tavor_flash_read_sector()
 */
static void
tavor_flash_read_sector(tavor_state_t *state, uint32_t sector_num)
{
	uint32_t addr;
	uint32_t end_addr;
	uint32_t *image;
	int i;

	TAVOR_TNF_ENTER(tavor_flash_read_sector);

	image = (uint32_t *)&state->ts_fw_sector[0];

	/*
	 * Calculate the start and end address of the sector, based on the
	 * sector number passed in.
	 */
	addr = sector_num << state->ts_fw_log_sector_sz;
	end_addr = addr + (1 << state->ts_fw_log_sector_sz);

	/* Set the flash bank correctly for the given address */
	tavor_flash_bank(state, addr);

	/* Read the entire sector, one quadlet at a time */
	for (i = 0; addr < end_addr; i++, addr += 4) {
		image[i] = tavor_flash_read(state, addr);
	}

	TAVOR_TNF_EXIT(tavor_flash_read_sector);
}

/*
 * tavor_flash_read_quadlet()
 */
static void
tavor_flash_read_quadlet(tavor_state_t *state, uint32_t *data,
    uint32_t addr)
{
	TAVOR_TNF_ENTER(tavor_flash_read_quadlet);

	/* Set the flash bank correctly for the given address */
	tavor_flash_bank(state, addr);

	/* Read one quadlet of data */
	*data = tavor_flash_read(state, addr);

	TAVOR_TNF_EXIT(tavor_flash_read_quadlet);
}

/*
 * tavor_flash_write_sector()
 */
static int
tavor_flash_write_sector(tavor_state_t *state, uint32_t sector_num)
{
	uint32_t addr;
	uint32_t end_addr;
	uchar_t *sector;
	int	status = 0;
	int	i;

	TAVOR_TNF_ENTER(tavor_flash_write_sector);

	sector = (uchar_t *)&state->ts_fw_sector[0];

	/*
	 * Calculate the start and end address of the sector, based on the
	 * sector number passed in.
	 */
	addr = sector_num << state->ts_fw_log_sector_sz;
	end_addr = addr + (1 << state->ts_fw_log_sector_sz);

	/* Set the flash bank correctly for the given address */
	tavor_flash_bank(state, addr);

	/* Erase the sector before writing */
	tavor_flash_reset(state);
	status = tavor_flash_erase_sector(state, sector_num);
	if (status != 0) {
		TAVOR_TNF_EXIT(tavor_flash_write_sector);
		return (status);
	}

	/* Write the entire sector, one byte at a time */
	for (i = 0; addr < end_addr; i++, addr++) {
		status = tavor_flash_write_byte(state, addr, sector[i]);
		if (status != 0) {
			break;
		}
	}

	tavor_flash_reset(state);
	TAVOR_TNF_EXIT(tavor_flash_write_sector);
	return (status);
}

/*
 * tavor_flash_write_byte()
 */
static int
tavor_flash_write_byte(tavor_state_t *state, uint32_t addr, uchar_t data)
{
	uint32_t stat;
	int status = 0;
	int i;

	TAVOR_TNF_ENTER(tavor_flash_write_byte);

	switch (state->ts_fw_cmdset) {
	case TAVOR_FLASH_AMD_CMDSET:
		/* Issue Flash Byte program command */
		tavor_flash_write(state, addr, 0xAA);
		tavor_flash_write(state, addr, 0x55);
		tavor_flash_write(state, addr, 0xA0);
		tavor_flash_write(state, addr, data);

		/*
		 * Wait for Write Byte to Complete:
		 *   1) Wait 1usec
		 *   2) Read status of the write operation
		 *   3) Determine if we have timed out the write operation
		 *   4) Compare correct data value to the status value that
		 *	was read from the same address.
		 */
		i = 0;
		do {
			drv_usecwait(1);
			stat = tavor_flash_read(state, addr & ~3);

			if (i == tavor_hw_flash_timeout_write) {
				cmn_err(CE_WARN,
				    "tavor_flash_write_byte: ACS write "
				    "timeout: addr: 0x%x, data: 0x%x\n",
				    addr, data);
				status = EIO;
				break;
			}

			i++;
		} while (data != ((stat >> ((3 - (addr & 3)) << 3)) & 0xFF));
		break;

	case TAVOR_FLASH_INTEL_CMDSET:
		/* Issue Flash Byte program command */
		tavor_flash_write(state, addr, TAVOR_HW_FLASH_ICS_WRITE);
		tavor_flash_write(state, addr, data);

		/* wait for completion */
		i = 0;
		do {
			drv_usecwait(1);
			stat = tavor_flash_read(state, addr & ~3);

			if (i == tavor_hw_flash_timeout_write) {
				cmn_err(CE_WARN,
				    "tavor_flash_write_byte: ICS write "
				    "timeout: addr: %x, data: %x\n",
				    addr, data);
				status = EIO;
				break;
			}

			i++;
		} while ((stat & TAVOR_HW_FLASH_ICS_READY) == 0);

		if (stat & TAVOR_HW_FLASH_ICS_ERROR) {
			cmn_err(CE_WARN,
			    "tavor_flash_write_byte: ICS write cmd error: "
			    "addr: %x, data: %x\n",
			    addr, data);
			status = EIO;
		}
		break;

	default:
		cmn_err(CE_WARN,
		    "tavor_flash_write_byte: unknown cmd set: 0x%x\n",
		    state->ts_fw_cmdset);
		status = EIO;
		break;
	}

	TAVOR_TNF_EXIT(tavor_flash_write_byte);
	return (status);
}

/*
 * tavor_flash_erase_sector()
 */
static int
tavor_flash_erase_sector(tavor_state_t *state, uint32_t sector_num)
{
	uint32_t addr;
	uint32_t stat;
	int status = 0;
	int i;

	TAVOR_TNF_ENTER(tavor_flash_erase_sector);

	/* Get address from sector num */
	addr = sector_num << state->ts_fw_log_sector_sz;

	switch (state->ts_fw_cmdset) {
	case TAVOR_FLASH_AMD_CMDSET:
		/* Issue Flash Sector Erase Command */
		tavor_flash_write(state, addr, 0xAA);
		tavor_flash_write(state, addr, 0x55);
		tavor_flash_write(state, addr, 0x80);
		tavor_flash_write(state, addr, 0xAA);
		tavor_flash_write(state, addr, 0x55);
		tavor_flash_write(state, addr, 0x30);

		/*
		 * Wait for Sector Erase to Complete
		 *   1) Wait 1usec
		 *   2) read the status at the base addr of the sector
		 *   3) Determine if we have timed out
		 *   4) Compare status of address with the value of a fully
		 *	erased quadlet. If these are equal, the sector
		 *	has been erased.
		 */
		i = 0;
		do {
			/* wait 1usec */
			drv_usecwait(1);
			stat = tavor_flash_read(state, addr);

			if (i == tavor_hw_flash_timeout_erase) {
				cmn_err(CE_WARN,
				    "tavor_flash_erase_sector: "
				    "ACS erase timeout\n");
				status = EIO;
				break;
			}

			i++;
		} while (stat != 0xFFFFFFFF);
		break;

	case TAVOR_FLASH_INTEL_CMDSET:
		/* Issue Erase Command */
		tavor_flash_write(state, addr, TAVOR_HW_FLASH_ICS_ERASE);
		tavor_flash_write(state, addr, TAVOR_HW_FLASH_ICS_CONFIRM);

		/* wait for completion */
		i = 0;
		do {
			drv_usecwait(1);
			stat = tavor_flash_read(state, addr & ~3);

			if (i == tavor_hw_flash_timeout_erase) {
				cmn_err(CE_WARN,
				    "tavor_flash_erase_sector: "
				    "ICS erase timeout\n");
				status = EIO;
				break;
			}

			i++;
		} while ((stat & TAVOR_HW_FLASH_ICS_READY) == 0);

		if (stat & TAVOR_HW_FLASH_ICS_ERROR) {
			cmn_err(CE_WARN,
			    "tavor_flash_erase_sector: "
			    "ICS erase cmd error\n");
			status = EIO;
		}
		break;

	default:
		cmn_err(CE_WARN,
		    "tavor_flash_erase_sector: unknown cmd set: 0x%x\n",
		    state->ts_fw_cmdset);
		status = EIO;
		break;
	}

	tavor_flash_reset(state);

	TAVOR_TNF_EXIT(tavor_flash_erase_sector);
	return (status);
}

/*
 * tavor_flash_erase_chip()
 */
static int
tavor_flash_erase_chip(tavor_state_t *state)
{
	uint_t size;
	uint32_t stat;
	int status = 0;
	int num_sect;
	int i;

	TAVOR_TNF_ENTER(tavor_flash_erase_chip);

	switch (state->ts_fw_cmdset) {
	case TAVOR_FLASH_AMD_CMDSET:
		/* Issue Flash Chip Erase Command */
		tavor_flash_write(state, 0, 0xAA);
		tavor_flash_write(state, 0, 0x55);
		tavor_flash_write(state, 0, 0x80);
		tavor_flash_write(state, 0, 0xAA);
		tavor_flash_write(state, 0, 0x55);
		tavor_flash_write(state, 0, 0x10);

		/*
		 * Wait for Chip Erase to Complete
		 *   1) Wait 1usec
		 *   2) read the status at the base addr of the sector
		 *   3) Determine if we have timed out
		 *   4) Compare status of address with the value of a
		 *	fully erased quadlet. If these are equal, the
		 *	chip has been erased.
		 */
		i = 0;
		do {
			/* wait 1usec */
			drv_usecwait(1);
			stat = tavor_flash_read(state, 0);

			if (i == tavor_hw_flash_timeout_erase) {
				cmn_err(CE_WARN,
				    "tavor_flash_erase_chip: erase timeout\n");
				status = EIO;
				break;
			}

			i++;
		} while (stat != 0xFFFFFFFF);
		break;

	case TAVOR_FLASH_INTEL_CMDSET:
		/*
		 * The Intel chip doesn't have a chip erase command, so erase
		 * all blocks one at a time.
		 */
		size = (0x1 << state->ts_fw_log_sector_sz);
		num_sect = state->ts_fw_device_sz / size;

		for (i = 0; i < num_sect; i++) {
			status = tavor_flash_erase_sector(state, i);
			if (status != 0) {
				cmn_err(CE_WARN,
				    "tavor_flash_erase_chip: "
				    "ICS sector %d erase error\n", i);
				status = EIO;
				break;
			}
		}
		break;

	default:
		cmn_err(CE_WARN, "tavor_flash_erase_chip: "
		    "unknown cmd set: 0x%x\n", state->ts_fw_cmdset);
		status = EIO;
		break;
	}

	TAVOR_TNF_EXIT(tavor_flash_erase_chip);
	return (status);
}

/*
 * tavor_flash_bank()
 */
static void
tavor_flash_bank(tavor_state_t *state, uint32_t addr)
{
	ddi_acc_handle_t	hdl;
	uint32_t		bank;

	TAVOR_TNF_ENTER(tavor_flash_bank);

	/* Set handle */
	hdl = state->ts_pci_cfghdl;

	/* Determine the bank setting from the address */
	bank = addr & TAVOR_HW_FLASH_BANK_MASK;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(state->ts_fw_flashbank))

	/*
	 * If the bank is different from the currently set bank, we need to
	 * change it.  Also, if an 'addr' of 0 is given, this allows the
	 * capability to force the flash bank to 0.  This is useful at init
	 * time to initially set the bank value
	 */
	if (state->ts_fw_flashbank != bank || addr == 0) {
		/* Set bank using the GPIO settings */
		tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_DATACLEAR, 0x70);
		tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_DATASET,
		    (bank >> 15) & 0x70);

		/* Save the bank state */
		state->ts_fw_flashbank = bank;
	}

	TAVOR_TNF_EXIT(tavor_flash_bank);
}

/*
 * tavor_flash_read()
 */
static uint32_t
tavor_flash_read(tavor_state_t *state, uint32_t addr)
{
	ddi_acc_handle_t	hdl;
	uint32_t		data;
	int			timeout;

	TAVOR_TNF_ENTER(tavor_flash_read);

	/* Set handle */
	hdl = state->ts_pci_cfghdl;

	/*
	 * The Read operation does the following:
	 *   1) Write the masked address to the TAVOR_FLASH_ADDR register.
	 *	Only the least significant 19 bits are valid.
	 *   2) Read back the register until the command has completed.
	 *   3) Read the data retrieved from the address at the TAVOR_FLASH_DATA
	 *	register.
	 */
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_ADDR,
	    (addr & TAVOR_HW_FLASH_ADDR_MASK) | (1 << 29));

	timeout = 0;
	do {
		data = tavor_flash_read_cfg(hdl, TAVOR_HW_FLASH_ADDR);
		timeout++;
	} while ((data & TAVOR_HW_FLASH_CMD_MASK) &&
	    (timeout < tavor_hw_flash_timeout_config));

	if (timeout == tavor_hw_flash_timeout_config) {
		cmn_err(CE_WARN, "tavor_flash_read: config command timeout.\n");
	}

	data = tavor_flash_read_cfg(hdl, TAVOR_HW_FLASH_DATA);

	TAVOR_TNF_EXIT(tavor_flash_read);
	return (data);
}

/*
 * tavor_flash_write()
 */
static void
tavor_flash_write(tavor_state_t *state, uint32_t addr, uchar_t data)
{
	ddi_acc_handle_t	hdl;
	int			cmd;
	int			timeout;

	TAVOR_TNF_ENTER(tavor_flash_write);

	/* Set handle */
	hdl = state->ts_pci_cfghdl;

	/*
	 * The Write operation does the following:
	 *   1) Write the data to be written to the TAVOR_FLASH_DATA offset.
	 *   2) Write the address to write the data to to the TAVOR_FLASH_ADDR
	 *	offset.
	 *   3) Wait until the write completes.
	 */
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_DATA, data << 24);
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_ADDR,
	    (addr & 0x7FFFF) | (2 << 29));

	timeout = 0;
	do {
		cmd = tavor_flash_read_cfg(hdl, TAVOR_HW_FLASH_ADDR);
		timeout++;
	} while ((cmd & TAVOR_HW_FLASH_CMD_MASK) &&
	    (timeout < tavor_hw_flash_timeout_config));

	if (timeout == tavor_hw_flash_timeout_config) {
		cmn_err(CE_WARN, "tavor_flash_write: config cmd timeout.\n");
	}

	TAVOR_TNF_EXIT(tavor_flash_write);
}

/*
 * tavor_flash_init()
 */
static void
tavor_flash_init(tavor_state_t *state)
{
	uint32_t		word;
	ddi_acc_handle_t	hdl;
	int			sema_cnt;
	int			gpio;

	TAVOR_TNF_ENTER(tavor_flash_init);

	/* Set handle */
	hdl = state->ts_pci_cfghdl;

	/* Init the flash */

	/*
	 * Grab the GPIO semaphore.  This allows us exclusive access to the
	 * GPIO settings on the Tavor for the duration of the flash burning
	 * procedure.
	 */
	sema_cnt = 0;
	do {
		word = tavor_flash_read_cfg(hdl, TAVOR_HW_FLASH_GPIO_SEMA);
		if (word == 0) {
			break;
		}

		sema_cnt++;
		drv_usecwait(1);
	} while (sema_cnt < tavor_hw_flash_timeout_gpio_sema);

	/*
	 * Determine if we timed out trying to grab the GPIO semaphore
	 */
	if (sema_cnt == tavor_hw_flash_timeout_gpio_sema) {
		cmn_err(CE_WARN, "tavor_flash_init: GPIO SEMA timeout\n");
	}

	/* Save away original GPIO Values */
	state->ts_fw_gpio[0] = tavor_flash_read_cfg(hdl,
	    TAVOR_HW_FLASH_GPIO_DIR);
	state->ts_fw_gpio[1] = tavor_flash_read_cfg(hdl,
	    TAVOR_HW_FLASH_GPIO_POL);
	state->ts_fw_gpio[2] = tavor_flash_read_cfg(hdl,
	    TAVOR_HW_FLASH_GPIO_MOD);
	state->ts_fw_gpio[3] = tavor_flash_read_cfg(hdl,
	    TAVOR_HW_FLASH_GPIO_DAT);

	/* Set New GPIO Values */
	gpio = state->ts_fw_gpio[0] | 0x70;
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_DIR, gpio);

	gpio = state->ts_fw_gpio[1] & ~0x70;
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_POL, gpio);

	gpio = state->ts_fw_gpio[2] & ~0x70;
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_MOD, gpio);

	/* Set CPUMODE to enable tavor to access the flash device */
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_CPUMODE,
	    1 << TAVOR_HW_FLASH_CPU_SHIFT);

	/* Initialize to bank 0 */
	tavor_flash_bank(state, 0);

	TAVOR_TNF_EXIT(tavor_flash_init);
}

/*
 * tavor_flash_cfi_init
 *   Implements access to the CFI (Common Flash Interface) data
 */
static void
tavor_flash_cfi_init(tavor_state_t *state, uint32_t *cfi_info, int *intel_xcmd)
{
	uint32_t	data;
	uint32_t	sector_sz_bytes;
	uint32_t	bit_count;
	uint8_t		cfi_ch_info[TAVOR_CFI_INFO_SIZE];
	int		i;

	TAVOR_TNF_ENTER(tavor_flash_cfi_init);

	/*
	 * Determine if the user command supports the Intel Extended
	 * Command Set. The query string is contained in the fourth
	 * quad word.
	 */
	tavor_flash_cfi_byte(cfi_ch_info, cfi_info[0x04], 0x10);
	if (cfi_ch_info[0x10] == 'M' &&
	    cfi_ch_info[0x11] == 'X' &&
	    cfi_ch_info[0x12] == '2') {
		*intel_xcmd = 1; /* support is there */
	}

	/* CFI QUERY */
	tavor_flash_write(state, 0x55, TAVOR_FLASH_CFI_INIT);

	/* Read in CFI data */
	for (i = 0; i < TAVOR_CFI_INFO_SIZE; i += 4) {
		data = tavor_flash_read(state, i);
		tavor_flash_cfi_byte(cfi_ch_info, data, i);
	}

	/* Determine chip set */
	state->ts_fw_cmdset = TAVOR_FLASH_UNKNOWN_CMDSET;
	if (cfi_ch_info[0x20] == 'Q' &&
	    cfi_ch_info[0x22] == 'R' &&
	    cfi_ch_info[0x24] == 'Y') {
		/*
		 * Mode: x16 working in x8 mode (Intel).
		 * Pack data - skip spacing bytes.
		 */
		for (i = 0; i < TAVOR_CFI_INFO_SIZE; i += 2) {
			cfi_ch_info[i/2] = cfi_ch_info[i];
		}
	}
	state->ts_fw_cmdset = cfi_ch_info[0x13];
	if (state->ts_fw_cmdset != TAVOR_FLASH_INTEL_CMDSET &&
	    state->ts_fw_cmdset != TAVOR_FLASH_AMD_CMDSET) {
		cmn_err(CE_WARN,
		    "tavor_flash_cfi_init: UNKNOWN chip cmd set\n");
		state->ts_fw_cmdset = TAVOR_FLASH_UNKNOWN_CMDSET;
		goto out;
	}

	/* Determine total bytes in one sector size */
	sector_sz_bytes = ((cfi_ch_info[0x30] << 8) | cfi_ch_info[0x2F]) << 8;

	/* Calculate equivalent of log2 (n) */
	for (bit_count = 0; sector_sz_bytes > 1; bit_count++) {
		sector_sz_bytes >>= 1;
	}

	/* Set sector size */
	state->ts_fw_log_sector_sz = bit_count;

	/* Set flash size */
	state->ts_fw_device_sz = 0x1 << cfi_ch_info[0x27];

	/* Reset to turn off CFI mode */
	tavor_flash_reset(state);

	/*
	 * Pass CFI data back to user command.
	 */
	for (i = 0; i < TAVOR_FLASH_CFI_SIZE_QUADLET; i++) {
		tavor_flash_cfi_dword(&cfi_info[i], cfi_ch_info, i << 2);
	}

	if (*intel_xcmd == 1) {
		/*
		 * Inform the user cmd that this driver does support the
		 * Intel Extended Command Set.
		 */
		cfi_ch_info[0x10] = 'M';
		cfi_ch_info[0x11] = 'X';
		cfi_ch_info[0x12] = '2';
	} else {
		cfi_ch_info[0x10] = 'Q';
		cfi_ch_info[0x11] = 'R';
		cfi_ch_info[0x12] = 'Y';
	}
	cfi_ch_info[0x13] = state->ts_fw_cmdset;
	tavor_flash_cfi_dword(&cfi_info[0x4], cfi_ch_info, 0x10);
out:
	TAVOR_TNF_EXIT(tavor_flash_cfi_init);
}

/*
 * tavor_flash_fini()
 */
static void
tavor_flash_fini(tavor_state_t *state)
{
	ddi_acc_handle_t hdl;

	TAVOR_TNF_ENTER(tavor_flash_fini);

	/* Set handle */
	hdl = state->ts_pci_cfghdl;

	/* Restore original GPIO Values */
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_DIR,
	    state->ts_fw_gpio[0]);
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_POL,
	    state->ts_fw_gpio[1]);
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_MOD,
	    state->ts_fw_gpio[2]);
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_DAT,
	    state->ts_fw_gpio[3]);

	/* Give up semaphore */
	tavor_flash_write_cfg(hdl, TAVOR_HW_FLASH_GPIO_SEMA, 0);

	TAVOR_TNF_EXIT(tavor_flash_fini);
}

/*
 * tavor_flash_read_cfg
 */
static uint32_t
tavor_flash_read_cfg(ddi_acc_handle_t pci_config_hdl, uint32_t addr)
{
	uint32_t	read;

	TAVOR_TNF_ENTER(tavor_flash_read_cfg);

	/*
	 * Perform flash read operation:
	 *   1) Place addr to read from on the TAVOR_HW_FLASH_CFG_ADDR register
	 *   2) Read data at that addr from the TAVOR_HW_FLASH_CFG_DATA register
	 */
	pci_config_put32(pci_config_hdl, TAVOR_HW_FLASH_CFG_ADDR, addr);
	read = pci_config_get32(pci_config_hdl, TAVOR_HW_FLASH_CFG_DATA);

	TAVOR_TNF_EXIT(tavor_flash_read_cfg);

	return (read);
}

/*
 * tavor_flash_write_cfg
 */
static void
tavor_flash_write_cfg(ddi_acc_handle_t pci_config_hdl, uint32_t addr,
    uint32_t data)
{
	TAVOR_TNF_ENTER(tavor_flash_write_cfg);

	/*
	 * Perform flash write operation:
	 *   1) Place addr to write to on the TAVOR_HW_FLASH_CFG_ADDR register
	 *   2) Place data to write on to the TAVOR_HW_FLASH_CFG_DATA register
	 */
	pci_config_put32(pci_config_hdl, TAVOR_HW_FLASH_CFG_ADDR, addr);
	pci_config_put32(pci_config_hdl, TAVOR_HW_FLASH_CFG_DATA, data);

	TAVOR_TNF_EXIT(tavor_flash_write_cfg);
}

/*
 * Support routines to convert Common Flash Interface (CFI) data
 * from a 32  bit word to a char array, and from a char array to
 * a 32 bit word.
 */
static void
tavor_flash_cfi_byte(uint8_t *ch, uint32_t dword, int i)
{
	ch[i] = (uint8_t)((dword & 0xFF000000) >> 24);
	ch[i+1] = (uint8_t)((dword & 0x00FF0000) >> 16);
	ch[i+2] = (uint8_t)((dword & 0x0000FF00) >> 8);
	ch[i+3] = (uint8_t)((dword & 0x000000FF));
}

static void
tavor_flash_cfi_dword(uint32_t *dword, uint8_t *ch, int i)
{
	*dword = (uint32_t)
	    ((uint32_t)ch[i] << 24 |
	    (uint32_t)ch[i+1] << 16 |
	    (uint32_t)ch[i+2] << 8 |
	    (uint32_t)ch[i+3]);
}

/*
 * tavor_loopback_free_qps
 */
static void
tavor_loopback_free_qps(tavor_loopback_state_t *lstate)
{
	int i;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lstate))

	if (lstate->tls_tx.tlc_qp_hdl != NULL) {
		(void) tavor_qp_free(lstate->tls_state,
		    &lstate->tls_tx.tlc_qp_hdl, IBC_FREE_QP_AND_QPN, NULL,
		    TAVOR_NOSLEEP);
	}
	if (lstate->tls_rx.tlc_qp_hdl != NULL) {
		(void) tavor_qp_free(lstate->tls_state,
		    &lstate->tls_rx.tlc_qp_hdl, IBC_FREE_QP_AND_QPN, NULL,
		    TAVOR_NOSLEEP);
	}
	lstate->tls_tx.tlc_qp_hdl = NULL;
	lstate->tls_rx.tlc_qp_hdl = NULL;
	for (i = 0; i < 2; i++) {
		if (lstate->tls_tx.tlc_cqhdl[i] != NULL) {
			(void) tavor_cq_free(lstate->tls_state,
			    &lstate->tls_tx.tlc_cqhdl[i], TAVOR_NOSLEEP);
		}
		if (lstate->tls_rx.tlc_cqhdl[i] != NULL) {
			(void) tavor_cq_free(lstate->tls_state,
			    &lstate->tls_rx.tlc_cqhdl[i], TAVOR_NOSLEEP);
		}
		lstate->tls_tx.tlc_cqhdl[i] = NULL;
		lstate->tls_rx.tlc_cqhdl[i] = NULL;
	}
}

/*
 * tavor_loopback_free_state
 */
static void
tavor_loopback_free_state(tavor_loopback_state_t *lstate)
{
	tavor_loopback_free_qps(lstate);
	if (lstate->tls_tx.tlc_mrhdl != NULL) {
		(void) tavor_mr_deregister(lstate->tls_state,
		    &lstate->tls_tx.tlc_mrhdl, TAVOR_MR_DEREG_ALL,
		    TAVOR_NOSLEEP);
	}
	if (lstate->tls_rx.tlc_mrhdl !=  NULL) {
		(void) tavor_mr_deregister(lstate->tls_state,
		    &lstate->tls_rx.tlc_mrhdl, TAVOR_MR_DEREG_ALL,
		    TAVOR_NOSLEEP);
	}
	if (lstate->tls_pd_hdl != NULL) {
		(void) tavor_pd_free(lstate->tls_state, &lstate->tls_pd_hdl);
	}
	if (lstate->tls_tx.tlc_buf != NULL) {
		kmem_free(lstate->tls_tx.tlc_buf, lstate->tls_tx.tlc_buf_sz);
	}
	if (lstate->tls_rx.tlc_buf != NULL) {
		kmem_free(lstate->tls_rx.tlc_buf, lstate->tls_rx.tlc_buf_sz);
	}
	bzero(lstate, sizeof (tavor_loopback_state_t));
}

/*
 * tavor_loopback_init
 */
static int
tavor_loopback_init(tavor_state_t *state, tavor_loopback_state_t *lstate)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lstate))

	lstate->tls_hca_hdl = (ibc_hca_hdl_t)state;
	lstate->tls_status  = tavor_pd_alloc(lstate->tls_state,
	    &lstate->tls_pd_hdl, TAVOR_NOSLEEP);
	if (lstate->tls_status != IBT_SUCCESS) {
		lstate->tls_err = TAVOR_LOOPBACK_PROT_DOMAIN_ALLOC_FAIL;
		TNF_PROBE_0(tavor_ioctl_loopback_alloc_pd_fail,
		    TAVOR_TNF_ERROR, "");
		return (EFAULT);
	}

	return (0);
}

/*
 * tavor_loopback_init_qp_info
 */
static void
tavor_loopback_init_qp_info(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm)
{
	bzero(&comm->tlc_cq_attr, sizeof (ibt_cq_attr_t));
	bzero(&comm->tlc_qp_attr, sizeof (ibt_qp_alloc_attr_t));
	bzero(&comm->tlc_qp_info, sizeof (ibt_qp_info_t));

	comm->tlc_wrid = 1;
	comm->tlc_cq_attr.cq_size = 128;
	comm->tlc_qp_attr.qp_sizes.cs_sq_sgl = 3;
	comm->tlc_qp_attr.qp_sizes.cs_rq_sgl = 3;
	comm->tlc_qp_attr.qp_sizes.cs_sq = 16;
	comm->tlc_qp_attr.qp_sizes.cs_rq = 16;
	comm->tlc_qp_attr.qp_flags = IBT_WR_SIGNALED;

	comm->tlc_qp_info.qp_state = IBT_STATE_RESET;
	comm->tlc_qp_info.qp_trans = IBT_RC_SRV;
	comm->tlc_qp_info.qp_flags = IBT_CEP_RDMA_RD | IBT_CEP_RDMA_WR;
	comm->tlc_qp_info.qp_transport.rc.rc_path.cep_hca_port_num =
	    lstate->tls_port;
	comm->tlc_qp_info.qp_transport.rc.rc_path.cep_pkey_ix =
	    lstate->tls_pkey_ix;
	comm->tlc_qp_info.qp_transport.rc.rc_path.cep_timeout =
	    lstate->tls_timeout;
	comm->tlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_srvl = 0;
	comm->tlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_srate =
	    IBT_SRATE_4X;
	comm->tlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_send_grh = 0;
	comm->tlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_dlid =
	    lstate->tls_lid;
	comm->tlc_qp_info.qp_transport.rc.rc_retry_cnt = lstate->tls_retry;
	comm->tlc_qp_info.qp_transport.rc.rc_sq_psn = 0;
	comm->tlc_qp_info.qp_transport.rc.rc_rq_psn = 0;
	comm->tlc_qp_info.qp_transport.rc.rc_rdma_ra_in	 = 4;
	comm->tlc_qp_info.qp_transport.rc.rc_rdma_ra_out = 4;
	comm->tlc_qp_info.qp_transport.rc.rc_dst_qpn = 0;
	comm->tlc_qp_info.qp_transport.rc.rc_min_rnr_nak = IBT_RNR_NAK_655ms;
	comm->tlc_qp_info.qp_transport.rc.rc_path_mtu = IB_MTU_1K;
}

/*
 * tavor_loopback_alloc_mem
 */
static int
tavor_loopback_alloc_mem(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm, int sz)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm))

	/* Allocate buffer of specified size */
	comm->tlc_buf_sz = sz;
	comm->tlc_buf	 = kmem_zalloc(sz, KM_NOSLEEP);
	if (comm->tlc_buf == NULL) {
		return (EFAULT);
	}

	/* Register the buffer as a memory region */
	comm->tlc_memattr.mr_vaddr = (uint64_t)(uintptr_t)comm->tlc_buf;
	comm->tlc_memattr.mr_len   = (ib_msglen_t)sz;
	comm->tlc_memattr.mr_as	   = NULL;
	comm->tlc_memattr.mr_flags = IBT_MR_NOSLEEP |
	    IBT_MR_ENABLE_REMOTE_WRITE | IBT_MR_ENABLE_LOCAL_WRITE;

	comm->tlc_status = tavor_mr_register(lstate->tls_state,
	    lstate->tls_pd_hdl, &comm->tlc_memattr, &comm->tlc_mrhdl, NULL);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm->tlc_mrhdl))

	comm->tlc_mrdesc.md_vaddr  = comm->tlc_mrhdl->mr_bindinfo.bi_addr;
	comm->tlc_mrdesc.md_lkey   = comm->tlc_mrhdl->mr_lkey;
	comm->tlc_mrdesc.md_rkey   = comm->tlc_mrhdl->mr_rkey;
	if (comm->tlc_status != IBT_SUCCESS) {
		return (EFAULT);
	}
	return (0);
}

/*
 * tavor_loopback_alloc_qps
 */
static int
tavor_loopback_alloc_qps(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm)
{
	uint32_t		i, real_size;
	tavor_qp_info_t		qpinfo;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lstate))

	/* Allocate send and recv CQs */
	for (i = 0; i < 2; i++) {
		bzero(&comm->tlc_cq_attr, sizeof (ibt_cq_attr_t));
		comm->tlc_cq_attr.cq_size = 128;
		comm->tlc_status = tavor_cq_alloc(lstate->tls_state,
		    (ibt_cq_hdl_t)NULL, &comm->tlc_cq_attr, &real_size,
		    &comm->tlc_cqhdl[i], TAVOR_NOSLEEP);
		if (comm->tlc_status != IBT_SUCCESS) {
			lstate->tls_err += i;
			return (EFAULT);
		}
	}

	/* Allocate the QP */
	tavor_loopback_init_qp_info(lstate, comm);
	comm->tlc_qp_attr.qp_pd_hdl	 = (ibt_pd_hdl_t)lstate->tls_pd_hdl;
	comm->tlc_qp_attr.qp_scq_hdl	 = (ibt_cq_hdl_t)comm->tlc_cqhdl[0];
	comm->tlc_qp_attr.qp_rcq_hdl	 = (ibt_cq_hdl_t)comm->tlc_cqhdl[1];
	comm->tlc_qp_attr.qp_ibc_scq_hdl = (ibt_opaque1_t)comm->tlc_cqhdl[0];
	comm->tlc_qp_attr.qp_ibc_rcq_hdl = (ibt_opaque1_t)comm->tlc_cqhdl[1];
	qpinfo.qpi_attrp	= &comm->tlc_qp_attr;
	qpinfo.qpi_type		= IBT_RC_RQP;
	qpinfo.qpi_ibt_qphdl	= NULL;
	qpinfo.qpi_queueszp	= &comm->tlc_chan_sizes;
	qpinfo.qpi_qpn		= &comm->tlc_qp_num;
	comm->tlc_status = tavor_qp_alloc(lstate->tls_state, &qpinfo,
	    TAVOR_NOSLEEP, NULL);
	if (comm->tlc_status == DDI_SUCCESS) {
		comm->tlc_qp_hdl = qpinfo.qpi_qphdl;
	}

	if (comm->tlc_status != IBT_SUCCESS) {
		lstate->tls_err += 2;
		return (EFAULT);
	}
	return (0);
}

/*
 * tavor_loopback_modify_qp
 */
static int
tavor_loopback_modify_qp(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm, uint_t qp_num)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lstate))

	/* Modify QP to INIT */
	tavor_loopback_init_qp_info(lstate, comm);
	comm->tlc_qp_info.qp_state = IBT_STATE_INIT;
	comm->tlc_status = tavor_qp_modify(lstate->tls_state, comm->tlc_qp_hdl,
	    IBT_CEP_SET_STATE, &comm->tlc_qp_info, &comm->tlc_queue_sizes);
	if (comm->tlc_status != IBT_SUCCESS) {
		return (EFAULT);
	}

	/*
	 * Modify QP to RTR (set destination LID and QP number to local
	 * LID and QP number)
	 */
	comm->tlc_qp_info.qp_state = IBT_STATE_RTR;
	comm->tlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_dlid
	    = lstate->tls_lid;
	comm->tlc_qp_info.qp_transport.rc.rc_dst_qpn = qp_num;
	comm->tlc_status = tavor_qp_modify(lstate->tls_state, comm->tlc_qp_hdl,
	    IBT_CEP_SET_STATE, &comm->tlc_qp_info, &comm->tlc_queue_sizes);
	if (comm->tlc_status != IBT_SUCCESS) {
		lstate->tls_err += 1;
		return (EFAULT);
	}

	/* Modify QP to RTS */
	comm->tlc_qp_info.qp_current_state = IBT_STATE_RTR;
	comm->tlc_qp_info.qp_state = IBT_STATE_RTS;
	comm->tlc_status = tavor_qp_modify(lstate->tls_state, comm->tlc_qp_hdl,
	    IBT_CEP_SET_STATE, &comm->tlc_qp_info, &comm->tlc_queue_sizes);
	if (comm->tlc_status != IBT_SUCCESS) {
		lstate->tls_err += 2;
		return (EFAULT);
	}
	return (0);
}

/*
 * tavor_loopback_copyout
 */
static int
tavor_loopback_copyout(tavor_loopback_ioctl_t *lb, intptr_t arg, int mode)
{
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		tavor_loopback_ioctl32_t lb32;

		lb32.tlb_revision	= lb->tlb_revision;
		lb32.tlb_send_buf	=
		    (caddr32_t)(uintptr_t)lb->tlb_send_buf;
		lb32.tlb_fail_buf	=
		    (caddr32_t)(uintptr_t)lb->tlb_fail_buf;
		lb32.tlb_buf_sz		= lb->tlb_buf_sz;
		lb32.tlb_num_iter	= lb->tlb_num_iter;
		lb32.tlb_pass_done	= lb->tlb_pass_done;
		lb32.tlb_timeout	= lb->tlb_timeout;
		lb32.tlb_error_type	= lb->tlb_error_type;
		lb32.tlb_port_num	= lb->tlb_port_num;
		lb32.tlb_num_retry	= lb->tlb_num_retry;

		if (ddi_copyout(&lb32, (void *)arg,
		    sizeof (tavor_loopback_ioctl32_t), mode) != 0) {
			TNF_PROBE_0(tavor_ioctl_loopback_copyout_fail,
			    TAVOR_TNF_ERROR, "");
			return (EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout(lb, (void *)arg, sizeof (tavor_loopback_ioctl_t),
	    mode) != 0) {
		TNF_PROBE_0(tavor_ioctl_loopback_copyout_fail,
		    TAVOR_TNF_ERROR, "");
		return (EFAULT);
	}
	return (0);
}

/*
 * tavor_loopback_post_send
 */
static int
tavor_loopback_post_send(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *tx, tavor_loopback_comm_t *rx)
{
	int	 ret;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*tx))

	bzero(&tx->tlc_sgl, sizeof (ibt_wr_ds_t));
	bzero(&tx->tlc_wr, sizeof (ibt_send_wr_t));

	/* Initialize local address for TX buffer */
	tx->tlc_sgl.ds_va   = tx->tlc_mrdesc.md_vaddr;
	tx->tlc_sgl.ds_key  = tx->tlc_mrdesc.md_lkey;
	tx->tlc_sgl.ds_len  = tx->tlc_buf_sz;

	/* Initialize the remaining details of the work request */
	tx->tlc_wr.wr_id = tx->tlc_wrid++;
	tx->tlc_wr.wr_flags  = IBT_WR_SEND_SIGNAL;
	tx->tlc_wr.wr_nds    = 1;
	tx->tlc_wr.wr_sgl    = &tx->tlc_sgl;
	tx->tlc_wr.wr_opcode = IBT_WRC_RDMAW;
	tx->tlc_wr.wr_trans  = IBT_RC_SRV;

	/* Initialize the remote address for RX buffer */
	tx->tlc_wr.wr.rc.rcwr.rdma.rdma_raddr = rx->tlc_mrdesc.md_vaddr;
	tx->tlc_wr.wr.rc.rcwr.rdma.rdma_rkey  = rx->tlc_mrdesc.md_rkey;
	tx->tlc_complete = 0;
	ret = tavor_post_send(lstate->tls_state, tx->tlc_qp_hdl, &tx->tlc_wr,
	    1, NULL);
	if (ret != IBT_SUCCESS) {
		return (EFAULT);
	}
	return (0);
}

/*
 * tavor_loopback_poll_cq
 */
static int
tavor_loopback_poll_cq(tavor_loopback_state_t *lstate,
    tavor_loopback_comm_t *comm)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm))

	comm->tlc_wc.wc_status	= 0;
	comm->tlc_num_polled	= 0;
	comm->tlc_status = tavor_cq_poll(lstate->tls_state,
	    comm->tlc_cqhdl[0], &comm->tlc_wc, 1, &comm->tlc_num_polled);
	if ((comm->tlc_status == IBT_SUCCESS) &&
	    (comm->tlc_wc.wc_status != IBT_WC_SUCCESS)) {
		comm->tlc_status = ibc_get_ci_failure(0);
	}
	return (comm->tlc_status);
}
