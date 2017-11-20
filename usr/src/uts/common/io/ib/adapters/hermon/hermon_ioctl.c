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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * hermon_ioctl.c
 *    Hemron IOCTL Routines
 *
 *    Implements all ioctl access into the driver.  This includes all routines
 *    necessary for updating firmware, accessing the hermon flash device, and
 *    providing interfaces for VTS.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/file.h>

#include <sys/ib/adapters/hermon/hermon.h>

/* Hemron HCA state pointer (extern) */
extern void	*hermon_statep;
extern int	hermon_verbose;

#define	DO_WRCONF	1
static int do_bar0 = 1;

/*
 * The ioctl declarations (for firmware flash burning, register read/write
 * (DEBUG-only), and VTS interfaces)
 */
static int hermon_ioctl_flash_read(hermon_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int hermon_ioctl_flash_write(hermon_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int hermon_ioctl_flash_erase(hermon_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int hermon_ioctl_flash_init(hermon_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int hermon_ioctl_flash_fini(hermon_state_t *state, dev_t dev);
static int hermon_ioctl_flash_cleanup(hermon_state_t *state);
static int hermon_ioctl_flash_cleanup_nolock(hermon_state_t *state);
#ifdef	DEBUG
static int hermon_ioctl_reg_write(hermon_state_t *state, intptr_t arg,
    int mode);
static int hermon_ioctl_reg_read(hermon_state_t *state, intptr_t arg,
    int mode);
#endif	/* DEBUG */
static int hermon_ioctl_write_boot_addr(hermon_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int hermon_ioctl_info(hermon_state_t *state, dev_t dev,
    intptr_t arg, int mode);
static int hermon_ioctl_ports(hermon_state_t *state, intptr_t arg,
    int mode);
static int hermon_ioctl_loopback(hermon_state_t *state, intptr_t arg,
    int mode);

/* Hemron Flash Functions */
static void hermon_flash_spi_exec_command(hermon_state_t *state,
    ddi_acc_handle_t hdl, uint32_t cmd);
static int hermon_flash_read_sector(hermon_state_t *state,
    uint32_t sector_num);
static int hermon_flash_read_quadlet(hermon_state_t *state, uint32_t *data,
    uint32_t addr);
static int hermon_flash_write_sector(hermon_state_t *state,
    uint32_t sector_num);
static int hermon_flash_spi_write_dword(hermon_state_t *state,
    uint32_t addr, uint32_t data);
static int hermon_flash_write_byte(hermon_state_t *state, uint32_t addr,
    uchar_t data);
static int hermon_flash_erase_sector(hermon_state_t *state,
    uint32_t sector_num);
static int hermon_flash_erase_chip(hermon_state_t *state);
static int hermon_flash_bank(hermon_state_t *state, uint32_t addr);
static uint32_t hermon_flash_read(hermon_state_t *state, uint32_t addr,
    int *err);
static void hermon_flash_write(hermon_state_t *state, uint32_t addr,
    uchar_t data, int *err);
static int hermon_flash_spi_wait_wip(hermon_state_t *state);
static void hermon_flash_spi_write_enable(hermon_state_t *state);
static int hermon_flash_init(hermon_state_t *state);
static int hermon_flash_cfi_init(hermon_state_t *state, uint32_t *cfi_info,
    int *intel_xcmd);
static int hermon_flash_fini(hermon_state_t *state);
static int hermon_flash_reset(hermon_state_t *state);
static uint32_t hermon_flash_read_cfg(hermon_state_t *state,
    ddi_acc_handle_t pci_config_hdl, uint32_t addr);
#ifdef DO_WRCONF
static void hermon_flash_write_cfg(hermon_state_t *state,
    ddi_acc_handle_t pci_config_hdl, uint32_t addr, uint32_t data);
static void hermon_flash_write_cfg_helper(hermon_state_t *state,
    ddi_acc_handle_t pci_config_hdl, uint32_t addr, uint32_t data);
static void hermon_flash_write_confirm(hermon_state_t *state,
    ddi_acc_handle_t pci_config_hdl);
#endif
static void hermon_flash_cfi_byte(uint8_t *ch, uint32_t dword, int i);
static void hermon_flash_cfi_dword(uint32_t *dword, uint8_t *ch, int i);

/* Hemron loopback test functions */
static void hermon_loopback_free_qps(hermon_loopback_state_t *lstate);
static void hermon_loopback_free_state(hermon_loopback_state_t *lstate);
static int hermon_loopback_init(hermon_state_t *state,
    hermon_loopback_state_t *lstate);
static void hermon_loopback_init_qp_info(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm);
static int hermon_loopback_alloc_mem(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm, int sz);
static int hermon_loopback_alloc_qps(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm);
static int hermon_loopback_modify_qp(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm, uint_t qp_num);
static int hermon_loopback_copyout(hermon_loopback_ioctl_t *lb,
    intptr_t arg, int mode);
static int hermon_loopback_post_send(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *tx, hermon_loopback_comm_t *rx);
static int hermon_loopback_poll_cq(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm);

/* Patchable timeout values for flash operations */
int hermon_hw_flash_timeout_gpio_sema = HERMON_HW_FLASH_TIMEOUT_GPIO_SEMA;
int hermon_hw_flash_timeout_config = HERMON_HW_FLASH_TIMEOUT_CONFIG;
int hermon_hw_flash_timeout_write = HERMON_HW_FLASH_TIMEOUT_WRITE;
int hermon_hw_flash_timeout_erase = HERMON_HW_FLASH_TIMEOUT_ERASE;

/*
 * hermon_ioctl()
 */
/* ARGSUSED */
int
hermon_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	hermon_state_t	*state;
	minor_t		instance;
	int		status;

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	instance = HERMON_DEV_INSTANCE(dev);
	if (instance == (minor_t)-1) {
		return (EBADF);
	}

	state = ddi_get_soft_state(hermon_statep, instance);
	if (state == NULL) {
		return (EBADF);
	}

	status = 0;

	switch (cmd) {
	case HERMON_IOCTL_FLASH_READ:
		status = hermon_ioctl_flash_read(state, dev, arg, mode);
		break;

	case HERMON_IOCTL_FLASH_WRITE:
		status = hermon_ioctl_flash_write(state, dev, arg, mode);
		break;

	case HERMON_IOCTL_FLASH_ERASE:
		status = hermon_ioctl_flash_erase(state, dev, arg, mode);
		break;

	case HERMON_IOCTL_FLASH_INIT:
		status = hermon_ioctl_flash_init(state, dev, arg, mode);
		break;

	case HERMON_IOCTL_FLASH_FINI:
		status = hermon_ioctl_flash_fini(state, dev);
		break;

	case HERMON_IOCTL_INFO:
		status = hermon_ioctl_info(state, dev, arg, mode);
		break;

	case HERMON_IOCTL_PORTS:
		status = hermon_ioctl_ports(state, arg, mode);
		break;

	case HERMON_IOCTL_LOOPBACK:
		status = hermon_ioctl_loopback(state, arg, mode);
		break;

#ifdef	DEBUG
	case HERMON_IOCTL_REG_WRITE:
		status = hermon_ioctl_reg_write(state, arg, mode);
		break;

	case HERMON_IOCTL_REG_READ:
		status = hermon_ioctl_reg_read(state, arg, mode);
		break;
#endif	/* DEBUG */

	case HERMON_IOCTL_DDR_READ:
		/* XXX guard until the ioctl header is cleaned up */
		status = ENODEV;
		break;

	case HERMON_IOCTL_WRITE_BOOT_ADDR:
		status = hermon_ioctl_write_boot_addr(state, dev, arg, mode);
		break;

	default:
		status = ENOTTY;
		break;
	}
	*rvalp = status;

	return (status);
}

/*
 * hermon_ioctl_flash_read()
 */
static int
hermon_ioctl_flash_read(hermon_state_t *state, dev_t dev, intptr_t arg,
    int mode)
{
	hermon_flash_ioctl_t ioctl_info;
	int status = 0;

	/*
	 * Check that flash init ioctl has been called first.  And check
	 * that the same dev_t that called init is the one calling read now.
	 */
	mutex_enter(&state->hs_fw_flashlock);
	if ((state->hs_fw_flashdev != dev) ||
	    (state->hs_fw_flashstarted == 0)) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EIO);
	}

	/* copy user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		hermon_flash_ioctl32_t info32;

		if (ddi_copyin((void *)arg, &info32,
		    sizeof (hermon_flash_ioctl32_t), mode) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}
		ioctl_info.af_type = info32.af_type;
		ioctl_info.af_sector = (caddr_t)(uintptr_t)info32.af_sector;
		ioctl_info.af_sector_num = info32.af_sector_num;
		ioctl_info.af_addr = info32.af_addr;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &ioctl_info, sizeof (hermon_flash_ioctl_t),
	    mode) != 0) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EFAULT);
	}

	/*
	 * Determine type of READ ioctl
	 */
	switch (ioctl_info.af_type) {
	case HERMON_FLASH_READ_SECTOR:
		/* Check if sector num is too large for flash device */
		if (ioctl_info.af_sector_num >=
		    (state->hs_fw_device_sz >> state->hs_fw_log_sector_sz)) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}

		/* Perform the Sector Read */
		if ((status = hermon_flash_reset(state)) != 0 ||
		    (status = hermon_flash_read_sector(state,
		    ioctl_info.af_sector_num)) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (status);
		}

		/* copyout the firmware sector image data */
		if (ddi_copyout(&state->hs_fw_sector[0],
		    &ioctl_info.af_sector[0], 1 << state->hs_fw_log_sector_sz,
		    mode) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}
		break;

	case HERMON_FLASH_READ_QUADLET:
		/* Check if addr is too large for flash device */
		if (ioctl_info.af_addr >= state->hs_fw_device_sz) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}

		/* Perform the Quadlet Read */
		if ((status = hermon_flash_reset(state)) != 0 ||
		    (status = hermon_flash_read_quadlet(state,
		    &ioctl_info.af_quadlet, ioctl_info.af_addr)) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (status);
		}
		break;

	default:
		mutex_exit(&state->hs_fw_flashlock);
		return (EINVAL);
	}

	/* copy results back to userland */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		hermon_flash_ioctl32_t info32;

		info32.af_quadlet = ioctl_info.af_quadlet;
		info32.af_type = ioctl_info.af_type;
		info32.af_sector_num = ioctl_info.af_sector_num;
		info32.af_sector = (caddr32_t)(uintptr_t)ioctl_info.af_sector;
		info32.af_addr = ioctl_info.af_addr;

		if (ddi_copyout(&info32, (void *)arg,
		    sizeof (hermon_flash_ioctl32_t), mode) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout(&ioctl_info, (void *)arg,
	    sizeof (hermon_flash_ioctl_t), mode) != 0) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EFAULT);
	}

	mutex_exit(&state->hs_fw_flashlock);
	return (status);
}

/*
 * hermon_ioctl_flash_write()
 */
static int
hermon_ioctl_flash_write(hermon_state_t *state, dev_t dev, intptr_t arg,
    int mode)
{
	hermon_flash_ioctl_t	ioctl_info;
	int status = 0;

	/*
	 * Check that flash init ioctl has been called first.  And check
	 * that the same dev_t that called init is the one calling write now.
	 */
	mutex_enter(&state->hs_fw_flashlock);
	if ((state->hs_fw_flashdev != dev) ||
	    (state->hs_fw_flashstarted == 0)) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EIO);
	}

	/* copy user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		hermon_flash_ioctl32_t info32;

		if (ddi_copyin((void *)arg, &info32,
		    sizeof (hermon_flash_ioctl32_t), mode) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}
		ioctl_info.af_type = info32.af_type;
		ioctl_info.af_sector = (caddr_t)(uintptr_t)info32.af_sector;
		ioctl_info.af_sector_num = info32.af_sector_num;
		ioctl_info.af_addr = info32.af_addr;
		ioctl_info.af_byte = info32.af_byte;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &ioctl_info,
	    sizeof (hermon_flash_ioctl_t), mode) != 0) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EFAULT);
	}

	/*
	 * Determine type of WRITE ioctl
	 */
	switch (ioctl_info.af_type) {
	case HERMON_FLASH_WRITE_SECTOR:
		/* Check if sector num is too large for flash device */
		if (ioctl_info.af_sector_num >=
		    (state->hs_fw_device_sz >> state->hs_fw_log_sector_sz)) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}

		/* copy in fw sector image data */
		if (ddi_copyin(&ioctl_info.af_sector[0],
		    &state->hs_fw_sector[0], 1 << state->hs_fw_log_sector_sz,
		    mode) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}

		/* Perform Write Sector */
		status = hermon_flash_write_sector(state,
		    ioctl_info.af_sector_num);
		break;

	case HERMON_FLASH_WRITE_BYTE:
		/* Check if addr is too large for flash device */
		if (ioctl_info.af_addr >= state->hs_fw_device_sz) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}

		/* Perform Write Byte */
		/*
		 * CMJ -- is a reset really needed before and after writing
		 * each byte?  This code came from arbel, but we should look
		 * into this.  Also, for SPI, no reset is actually performed.
		 */
		if ((status = hermon_flash_bank(state,
		    ioctl_info.af_addr)) != 0 ||
		    (status = hermon_flash_reset(state)) != 0 ||
		    (status = hermon_flash_write_byte(state,
		    ioctl_info.af_addr, ioctl_info.af_byte)) != 0 ||
		    (status = hermon_flash_reset(state)) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (status);
		}
		break;

	default:
		status = EINVAL;
		break;
	}

	mutex_exit(&state->hs_fw_flashlock);
	return (status);
}

/*
 * hermon_ioctl_flash_erase()
 */
static int
hermon_ioctl_flash_erase(hermon_state_t *state, dev_t dev, intptr_t arg,
    int mode)
{
	hermon_flash_ioctl_t	ioctl_info;
	int status = 0;

	/*
	 * Check that flash init ioctl has been called first.  And check
	 * that the same dev_t that called init is the one calling erase now.
	 */
	mutex_enter(&state->hs_fw_flashlock);
	if ((state->hs_fw_flashdev != dev) ||
	    (state->hs_fw_flashstarted == 0)) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EIO);
	}

	/* copy user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		hermon_flash_ioctl32_t info32;

		if (ddi_copyin((void *)arg, &info32,
		    sizeof (hermon_flash_ioctl32_t), mode) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}
		ioctl_info.af_type = info32.af_type;
		ioctl_info.af_sector_num = info32.af_sector_num;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &ioctl_info, sizeof (hermon_flash_ioctl_t),
	    mode) != 0) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EFAULT);
	}

	/*
	 * Determine type of ERASE ioctl
	 */
	switch (ioctl_info.af_type) {
	case HERMON_FLASH_ERASE_SECTOR:
		/* Check if sector num is too large for flash device */
		if (ioctl_info.af_sector_num >=
		    (state->hs_fw_device_sz >> state->hs_fw_log_sector_sz)) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}

		/* Perform Sector Erase */
		status = hermon_flash_erase_sector(state,
		    ioctl_info.af_sector_num);
		break;

	case HERMON_FLASH_ERASE_CHIP:
		/* Perform Chip Erase */
		status = hermon_flash_erase_chip(state);
		break;

	default:
		status = EINVAL;
		break;
	}

	mutex_exit(&state->hs_fw_flashlock);
	return (status);
}

/*
 * hermon_ioctl_flash_init()
 */
static int
hermon_ioctl_flash_init(hermon_state_t *state, dev_t dev, intptr_t arg,
    int mode)
{
	hermon_flash_init_ioctl_t init_info;
	int ret;
	int intel_xcmd = 0;
	ddi_acc_handle_t pci_hdl = hermon_get_pcihdl(state);

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	state->hs_fw_sector = NULL;

	/*
	 * init cannot be called more than once.  If we have already init'd the
	 * flash, return directly.
	 */
	mutex_enter(&state->hs_fw_flashlock);
	if (state->hs_fw_flashstarted == 1) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EINVAL);
	}

	/* copyin the user struct to kernel */
	if (ddi_copyin((void *)arg, &init_info,
	    sizeof (hermon_flash_init_ioctl_t), mode) != 0) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EFAULT);
	}

	/* Init Flash */
	if ((ret = hermon_flash_init(state)) != 0) {
		if (ret == EIO) {
			goto pio_error;
		}
		mutex_exit(&state->hs_fw_flashlock);
		return (ret);
	}

	/* Read CFI info */
	if ((ret = hermon_flash_cfi_init(state, &init_info.af_cfi_info[0],
	    &intel_xcmd)) != 0) {
		if (ret == EIO) {
			goto pio_error;
		}
		mutex_exit(&state->hs_fw_flashlock);
		return (ret);
	}

	/*
	 * Return error if the command set is unknown.
	 */
	if (state->hs_fw_cmdset == HERMON_FLASH_UNKNOWN_CMDSET) {
		if ((ret = hermon_ioctl_flash_cleanup_nolock(state)) != 0) {
			if (ret == EIO) {
				goto pio_error;
			}
			mutex_exit(&state->hs_fw_flashlock);
			return (ret);
		}
		mutex_exit(&state->hs_fw_flashlock);
		return (EFAULT);
	}

	/* the FMA retry loop starts. */
	hermon_pio_start(state, pci_hdl, pio_error,
	    fm_loop_cnt, fm_status, fm_test);

	/* Read HWREV - least significant 8 bits is revision ID */
	init_info.af_hwrev = pci_config_get32(pci_hdl,
	    HERMON_HW_FLASH_CFG_HWREV) & 0xFF;

	/* the FMA retry loop ends. */
	hermon_pio_end(state, pci_hdl, pio_error, fm_loop_cnt,
	    fm_status, fm_test);

	/* Fill in the firmwate revision numbers */
	init_info.af_fwrev.afi_maj	= state->hs_fw.fw_rev_major;
	init_info.af_fwrev.afi_min	= state->hs_fw.fw_rev_minor;
	init_info.af_fwrev.afi_sub	= state->hs_fw.fw_rev_subminor;

	/* Alloc flash mem for one sector size */
	state->hs_fw_sector = (uint32_t *)kmem_zalloc(1 <<
	    state->hs_fw_log_sector_sz, KM_SLEEP);

	/* Set HW part number and length */
	init_info.af_pn_len = state->hs_hca_pn_len;
	if (state->hs_hca_pn_len != 0) {
		(void) memcpy(init_info.af_hwpn, state->hs_hca_pn,
		    state->hs_hca_pn_len);
	}

	/* Copy ioctl results back to userland */
	if (ddi_copyout(&init_info, (void *)arg,
	    sizeof (hermon_flash_init_ioctl_t), mode) != 0) {
		if ((ret = hermon_ioctl_flash_cleanup_nolock(state)) != 0) {
			if (ret == EIO) {
				goto pio_error;
			}
			mutex_exit(&state->hs_fw_flashlock);
			return (ret);
		}
		mutex_exit(&state->hs_fw_flashlock);
		return (EFAULT);
	}

	/* Set flash state to started */
	state->hs_fw_flashstarted = 1;
	state->hs_fw_flashdev	  = dev;

	mutex_exit(&state->hs_fw_flashlock);

	/*
	 * If "flash init" is successful, add an "on close" callback to the
	 * current dev node to ensure that "flash fini" gets called later
	 * even if the userland process prematurely exits.
	 */
	ret = hermon_umap_db_set_onclose_cb(dev,
	    HERMON_ONCLOSE_FLASH_INPROGRESS,
	    (int (*)(void *))hermon_ioctl_flash_cleanup, state);
	if (ret != DDI_SUCCESS) {
		int status = hermon_ioctl_flash_fini(state, dev);
		if (status != 0) {
			if (status == EIO) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_IOCTL);
				return (EIO);
			}
			return (status);
		}
	}
	return (0);

pio_error:
	mutex_exit(&state->hs_fw_flashlock);
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}

/*
 * hermon_ioctl_flash_fini()
 */
static int
hermon_ioctl_flash_fini(hermon_state_t *state, dev_t dev)
{
	int ret;

	/*
	 * Check that flash init ioctl has been called first.  And check
	 * that the same dev_t that called init is the one calling fini now.
	 */
	mutex_enter(&state->hs_fw_flashlock);
	if ((state->hs_fw_flashdev != dev) ||
	    (state->hs_fw_flashstarted == 0)) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EINVAL);
	}

	if ((ret = hermon_ioctl_flash_cleanup_nolock(state)) != 0) {
		mutex_exit(&state->hs_fw_flashlock);
		if (ret == EIO) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
		}
		return (ret);
	}
	mutex_exit(&state->hs_fw_flashlock);

	/*
	 * If "flash fini" is successful, remove the "on close" callback
	 * that was setup during "flash init".
	 */
	ret = hermon_umap_db_clear_onclose_cb(dev,
	    HERMON_ONCLOSE_FLASH_INPROGRESS);
	if (ret != DDI_SUCCESS) {
		return (EFAULT);
	}
	return (0);
}


/*
 * hermon_ioctl_flash_cleanup()
 */
static int
hermon_ioctl_flash_cleanup(hermon_state_t *state)
{
	int status;

	mutex_enter(&state->hs_fw_flashlock);
	status = hermon_ioctl_flash_cleanup_nolock(state);
	mutex_exit(&state->hs_fw_flashlock);

	return (status);
}


/*
 * hermon_ioctl_flash_cleanup_nolock()
 */
static int
hermon_ioctl_flash_cleanup_nolock(hermon_state_t *state)
{
	int status;
	ASSERT(MUTEX_HELD(&state->hs_fw_flashlock));

	/* free flash mem */
	if (state->hs_fw_sector) {
		kmem_free(state->hs_fw_sector, 1 << state->hs_fw_log_sector_sz);
	}

	/* Fini the Flash */
	if ((status = hermon_flash_fini(state)) != 0)
		return (status);

	/* Set flash state to fini */
	state->hs_fw_flashstarted = 0;
	state->hs_fw_flashdev	  = 0;
	return (0);
}


/*
 * hermon_ioctl_info()
 */
static int
hermon_ioctl_info(hermon_state_t *state, dev_t dev, intptr_t arg, int mode)
{
	hermon_info_ioctl_t	 info;
	hermon_flash_init_ioctl_t init_info;

	/*
	 * Access to Hemron VTS ioctls is not allowed in "maintenance mode".
	 */
	if (state->hs_operational_mode == HERMON_MAINTENANCE_MODE) {
		return (EFAULT);
	}

	/* copyin the user struct to kernel */
	if (ddi_copyin((void *)arg, &info, sizeof (hermon_info_ioctl_t),
	    mode) != 0) {
		return (EFAULT);
	}

	/*
	 * Check ioctl revision
	 */
	if (info.ai_revision != HERMON_VTS_IOCTL_REVISION) {
		return (EINVAL);
	}

	/*
	 * If the 'fw_device_sz' has not been initialized yet, we initialize it
	 * here.  This is done by leveraging the
	 * hermon_ioctl_flash_init()/fini() calls.  We also hold our own mutex
	 * around this operation in case we have multiple VTS threads in
	 * process at the same time.
	 */
	mutex_enter(&state->hs_info_lock);
	if (state->hs_fw_device_sz == 0) {
		if (hermon_ioctl_flash_init(state, dev, (intptr_t)&init_info,
		    (FKIOCTL | mode)) != 0) {
			mutex_exit(&state->hs_info_lock);
			return (EFAULT);
		}
		(void) hermon_ioctl_flash_fini(state, dev);
	}
	mutex_exit(&state->hs_info_lock);

	info.ai_hw_rev		 = state->hs_revision_id;
	info.ai_flash_sz	 = state->hs_fw_device_sz;
	info.ai_fw_rev.afi_maj	 = state->hs_fw.fw_rev_major;
	info.ai_fw_rev.afi_min	 = state->hs_fw.fw_rev_minor;
	info.ai_fw_rev.afi_sub	 = state->hs_fw.fw_rev_subminor;

	/* Copy ioctl results back to user struct */
	if (ddi_copyout(&info, (void *)arg, sizeof (hermon_info_ioctl_t),
	    mode) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * hermon_ioctl_ports()
 */
static int
hermon_ioctl_ports(hermon_state_t *state, intptr_t arg, int mode)
{
	hermon_ports_ioctl_t	info;
	hermon_stat_port_ioctl_t	portstat;
	ibt_hca_portinfo_t	pi;
	uint_t			tbl_size;
	ib_gid_t		*sgid_tbl;
	ib_pkey_t		*pkey_tbl;
	int			i;

	/*
	 * Access to Hemron VTS ioctls is not allowed in "maintenance mode".
	 */
	if (state->hs_operational_mode == HERMON_MAINTENANCE_MODE) {
		return (EFAULT);
	}

	/* copyin the user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		hermon_ports_ioctl32_t info32;

		if (ddi_copyin((void *)arg, &info32,
		    sizeof (hermon_ports_ioctl32_t), mode) != 0) {
			return (EFAULT);
		}
		info.ap_revision  = info32.ap_revision;
		info.ap_ports	  =
		    (hermon_stat_port_ioctl_t *)(uintptr_t)info32.ap_ports;
		info.ap_num_ports = info32.ap_num_ports;

	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &info, sizeof (hermon_ports_ioctl_t),
	    mode) != 0) {
		return (EFAULT);
	}

	/*
	 * Check ioctl revision
	 */
	if (info.ap_revision != HERMON_VTS_IOCTL_REVISION) {
		return (EINVAL);
	}

	/* Allocate space for temporary GID table/PKey table */
	tbl_size = (1 << state->hs_cfg_profile->cp_log_max_gidtbl);
	sgid_tbl = (ib_gid_t *)kmem_zalloc(tbl_size * sizeof (ib_gid_t),
	    KM_SLEEP);
	tbl_size = (1 << state->hs_cfg_profile->cp_log_max_pkeytbl);
	pkey_tbl = (ib_pkey_t *)kmem_zalloc(tbl_size * sizeof (ib_pkey_t),
	    KM_SLEEP);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sgid_tbl, *pkey_tbl))

	/*
	 * Setup the number of ports, then loop through all ports and
	 * query properties of each.
	 */
	info.ap_num_ports = (uint8_t)state->hs_cfg_profile->cp_num_ports;
	for (i = 0; i < info.ap_num_ports; i++) {
		/*
		 * Get portstate information from the device.  If
		 * hermon_port_query() fails, leave zeroes in user
		 * struct port entry and continue.
		 */
		bzero(&pi, sizeof (ibt_hca_portinfo_t));
		pi.p_sgid_tbl = sgid_tbl;
		pi.p_pkey_tbl = pkey_tbl;
		(void) hermon_port_query(state, i + 1, &pi);

		portstat.asp_port_num	= pi.p_port_num;
		portstat.asp_state	= pi.p_linkstate;
		portstat.asp_guid	= pi.p_sgid_tbl[0].gid_guid;

		/*
		 * Copy queried port results back to user struct.  If
		 * this fails, then break out of loop, attempt to copy
		 * out remaining info to user struct, and return (without
		 * error).
		 */
		if (ddi_copyout(&portstat,
		    &(((hermon_stat_port_ioctl_t *)info.ap_ports)[i]),
		    sizeof (hermon_stat_port_ioctl_t), mode) != 0) {
			break;
		}
	}

	/* Free the temporary space used for GID table/PKey table */
	tbl_size = (1 << state->hs_cfg_profile->cp_log_max_gidtbl);
	kmem_free(sgid_tbl, tbl_size * sizeof (ib_gid_t));
	tbl_size = (1 << state->hs_cfg_profile->cp_log_max_pkeytbl);
	kmem_free(pkey_tbl, tbl_size * sizeof (ib_pkey_t));

	/* Copy ioctl results back to user struct */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		hermon_ports_ioctl32_t info32;

		info32.ap_revision  = info.ap_revision;
		info32.ap_ports	    = (caddr32_t)(uintptr_t)info.ap_ports;
		info32.ap_num_ports = info.ap_num_ports;

		if (ddi_copyout(&info32, (void *)arg,
		    sizeof (hermon_ports_ioctl32_t), mode) != 0) {
			return (EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout(&info, (void *)arg, sizeof (hermon_ports_ioctl_t),
	    mode) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * hermon_ioctl_loopback()
 */
static int
hermon_ioctl_loopback(hermon_state_t *state, intptr_t arg, int mode)
{
	hermon_loopback_ioctl_t	lb;
	hermon_loopback_state_t	lstate;
	ibt_hca_portinfo_t 	pi;
	uint_t			tbl_size, loopmax, max_usec;
	ib_gid_t		*sgid_tbl;
	ib_pkey_t		*pkey_tbl;
	int			j, iter, ret;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(lstate))

	/*
	 * Access to Hemron VTS ioctls is not allowed in "maintenance mode".
	 */
	if (state->hs_operational_mode == HERMON_MAINTENANCE_MODE) {
		return (EFAULT);
	}

	/* copyin the user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		hermon_loopback_ioctl32_t lb32;

		if (ddi_copyin((void *)arg, &lb32,
		    sizeof (hermon_loopback_ioctl32_t), mode) != 0) {
			return (EFAULT);
		}
		lb.alb_revision	    = lb32.alb_revision;
		lb.alb_send_buf	    = (caddr_t)(uintptr_t)lb32.alb_send_buf;
		lb.alb_fail_buf	    = (caddr_t)(uintptr_t)lb32.alb_fail_buf;
		lb.alb_buf_sz	    = lb32.alb_buf_sz;
		lb.alb_num_iter	    = lb32.alb_num_iter;
		lb.alb_pass_done    = lb32.alb_pass_done;
		lb.alb_timeout	    = lb32.alb_timeout;
		lb.alb_error_type   = lb32.alb_error_type;
		lb.alb_port_num	    = lb32.alb_port_num;
		lb.alb_num_retry    = lb32.alb_num_retry;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &lb, sizeof (hermon_loopback_ioctl_t),
	    mode) != 0) {
		return (EFAULT);
	}

	/* Initialize the internal loopback test state structure */
	bzero(&lstate, sizeof (hermon_loopback_state_t));

	/*
	 * Check ioctl revision
	 */
	if (lb.alb_revision != HERMON_VTS_IOCTL_REVISION) {
		lb.alb_error_type = HERMON_LOOPBACK_INVALID_REVISION;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		return (EINVAL);
	}

	/* Validate that specified port number is legal */
	if (!hermon_portnum_is_valid(state, lb.alb_port_num)) {
		lb.alb_error_type = HERMON_LOOPBACK_INVALID_PORT;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		return (EINVAL);
	}

	/* Allocate space for temporary GID table/PKey table */
	tbl_size = (1 << state->hs_cfg_profile->cp_log_max_gidtbl);
	sgid_tbl = (ib_gid_t *)kmem_zalloc(tbl_size * sizeof (ib_gid_t),
	    KM_SLEEP);
	tbl_size = (1 << state->hs_cfg_profile->cp_log_max_pkeytbl);
	pkey_tbl = (ib_pkey_t *)kmem_zalloc(tbl_size * sizeof (ib_pkey_t),
	    KM_SLEEP);

	/*
	 * Get portstate information from specific port on device
	 */
	bzero(&pi, sizeof (ibt_hca_portinfo_t));
	pi.p_sgid_tbl = sgid_tbl;
	pi.p_pkey_tbl = pkey_tbl;
	if (hermon_port_query(state, lb.alb_port_num, &pi) != 0) {
		/* Free the temporary space used for GID table/PKey table */
		tbl_size = (1 << state->hs_cfg_profile->cp_log_max_gidtbl);
		kmem_free(sgid_tbl, tbl_size * sizeof (ib_gid_t));
		tbl_size = (1 << state->hs_cfg_profile->cp_log_max_pkeytbl);
		kmem_free(pkey_tbl, tbl_size * sizeof (ib_pkey_t));

		lb.alb_error_type = HERMON_LOOPBACK_INVALID_PORT;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EINVAL);
	}

	lstate.hls_port	   = pi.p_port_num;
	lstate.hls_lid	   = pi.p_base_lid;
	lstate.hls_pkey_ix = (pi.p_linkstate == HERMON_PORT_LINK_ACTIVE) ?
	    1 : 0;	/* XXX bogus assumption of a SUN subnet manager */
	lstate.hls_state   = state;
	lstate.hls_retry   = lb.alb_num_retry;

	/* Free the temporary space used for GID table/PKey table */
	tbl_size = (1 << state->hs_cfg_profile->cp_log_max_gidtbl);
	kmem_free(sgid_tbl, tbl_size * sizeof (ib_gid_t));
	tbl_size = (1 << state->hs_cfg_profile->cp_log_max_pkeytbl);
	kmem_free(pkey_tbl, tbl_size * sizeof (ib_pkey_t));

	/*
	 * Compute the timeout duration in usec per the formula:
	 *    to_usec_per_retry = 4.096us * (2 ^ supplied_timeout)
	 * (plus we add a little fudge-factor here too)
	 */
	lstate.hls_timeout = lb.alb_timeout;
	max_usec = (4096 * (1 << lstate.hls_timeout)) / 1000;
	max_usec = max_usec * (lstate.hls_retry + 1);
	max_usec = max_usec + 10000;

	/*
	 * Determine how many times we should loop before declaring a
	 * timeout failure.
	 */
	loopmax	 = max_usec/HERMON_VTS_LOOPBACK_MIN_WAIT_DUR;
	if ((max_usec % HERMON_VTS_LOOPBACK_MIN_WAIT_DUR) != 0) {
		loopmax++;
	}

	if (lb.alb_send_buf == NULL || lb.alb_buf_sz == 0) {
		lb.alb_error_type = HERMON_LOOPBACK_SEND_BUF_INVALID;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EINVAL);
	}

	/* Allocate protection domain (PD) */
	if (hermon_loopback_init(state, &lstate) != 0) {
		lb.alb_error_type = lstate.hls_err;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EFAULT);
	}

	/* Allocate and register a TX buffer */
	if (hermon_loopback_alloc_mem(&lstate, &lstate.hls_tx,
	    lb.alb_buf_sz) != 0) {
		lb.alb_error_type =
		    HERMON_LOOPBACK_SEND_BUF_MEM_REGION_ALLOC_FAIL;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EFAULT);
	}

	/* Allocate and register an RX buffer */
	if (hermon_loopback_alloc_mem(&lstate, &lstate.hls_rx,
	    lb.alb_buf_sz) != 0) {
		lb.alb_error_type =
		    HERMON_LOOPBACK_RECV_BUF_MEM_REGION_ALLOC_FAIL;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EFAULT);
	}

	/* Copy in the transmit buffer data */
	if (ddi_copyin((void *)lb.alb_send_buf, lstate.hls_tx.hlc_buf,
	    lb.alb_buf_sz, mode) != 0) {
		lb.alb_error_type = HERMON_LOOPBACK_SEND_BUF_COPY_FAIL;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EFAULT);
	}

	/* Allocate the transmit QP and CQs */
	lstate.hls_err = HERMON_LOOPBACK_XMIT_SEND_CQ_ALLOC_FAIL;
	if (hermon_loopback_alloc_qps(&lstate, &lstate.hls_tx) != 0) {
		lb.alb_error_type = lstate.hls_err;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EFAULT);
	}

	/* Allocate the receive QP and CQs */
	lstate.hls_err = HERMON_LOOPBACK_RECV_SEND_CQ_ALLOC_FAIL;
	if (hermon_loopback_alloc_qps(&lstate, &lstate.hls_rx) != 0) {
		lb.alb_error_type = lstate.hls_err;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EFAULT);
	}

	/* Activate the TX QP (connect to RX QP) */
	lstate.hls_err = HERMON_LOOPBACK_XMIT_QP_INIT_FAIL;
	if (hermon_loopback_modify_qp(&lstate, &lstate.hls_tx,
	    lstate.hls_rx.hlc_qp_num) != 0) {
		lb.alb_error_type = lstate.hls_err;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EFAULT);
	}

	/* Activate the RX QP (connect to TX QP) */
	lstate.hls_err = HERMON_LOOPBACK_RECV_QP_INIT_FAIL;
	if (hermon_loopback_modify_qp(&lstate, &lstate.hls_rx,
	    lstate.hls_tx.hlc_qp_num) != 0) {
		lb.alb_error_type = lstate.hls_err;
		(void) hermon_loopback_copyout(&lb, arg, mode);
		hermon_loopback_free_state(&lstate);
		return (EFAULT);
	}

	/* Run the loopback test (for specified number of iterations) */
	lb.alb_pass_done = 0;
	for (iter = 0; iter < lb.alb_num_iter; iter++) {
		lstate.hls_err = 0;
		bzero(lstate.hls_rx.hlc_buf, lb.alb_buf_sz);

		/* Post RDMA Write work request */
		if (hermon_loopback_post_send(&lstate, &lstate.hls_tx,
		    &lstate.hls_rx) != IBT_SUCCESS) {
			lb.alb_error_type = HERMON_LOOPBACK_WQE_POST_FAIL;
			(void) hermon_loopback_copyout(&lb, arg, mode);
			hermon_loopback_free_state(&lstate);
			return (EFAULT);
		}

		/* Poll the TX CQ for a completion every few ticks */
		for (j = 0; j < loopmax; j++) {
			delay(drv_usectohz(HERMON_VTS_LOOPBACK_MIN_WAIT_DUR));

			ret = hermon_loopback_poll_cq(&lstate, &lstate.hls_tx);
			if (((ret != IBT_SUCCESS) && (ret != IBT_CQ_EMPTY)) ||
			    ((ret == IBT_CQ_EMPTY) && (j == loopmax - 1))) {
				lb.alb_error_type =
				    HERMON_LOOPBACK_CQ_POLL_FAIL;
				if (ddi_copyout(lstate.hls_rx.hlc_buf,
				    lb.alb_fail_buf, lstate.hls_tx.hlc_buf_sz,
				    mode) != 0) {
					return (EFAULT);
				}
				(void) hermon_loopback_copyout(&lb, arg, mode);
				hermon_loopback_free_state(&lstate);
				return (EFAULT);
			} else if (ret == IBT_CQ_EMPTY) {
				continue;
			}

			/* Compare the data buffers */
			if (bcmp(lstate.hls_tx.hlc_buf, lstate.hls_rx.hlc_buf,
			    lb.alb_buf_sz) == 0) {
				break;
			} else {
				lb.alb_error_type =
				    HERMON_LOOPBACK_SEND_RECV_COMPARE_FAIL;
				if (ddi_copyout(lstate.hls_rx.hlc_buf,
				    lb.alb_fail_buf, lstate.hls_tx.hlc_buf_sz,
				    mode) != 0) {
					return (EFAULT);
				}
				(void) hermon_loopback_copyout(&lb, arg, mode);
				hermon_loopback_free_state(&lstate);
				return (EFAULT);
			}
		}

		lstate.hls_err	 = HERMON_LOOPBACK_SUCCESS;
		lb.alb_pass_done = iter + 1;
	}

	lb.alb_error_type = HERMON_LOOPBACK_SUCCESS;

	/* Copy ioctl results back to user struct */
	ret = hermon_loopback_copyout(&lb, arg, mode);

	/* Free up everything and release all consumed resources */
	hermon_loopback_free_state(&lstate);

	return (ret);
}

#ifdef	DEBUG
/*
 * hermon_ioctl_reg_read()
 */
static int
hermon_ioctl_reg_read(hermon_state_t *state, intptr_t arg, int mode)
{
	hermon_reg_ioctl_t	rdreg;
	uint32_t		*addr;
	uintptr_t		baseaddr;
	int			status;
	ddi_acc_handle_t	handle;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	/*
	 * Access to Hemron registers is not allowed in "maintenance mode".
	 * This is primarily because the device may not have BARs to access
	 */
	if (state->hs_operational_mode == HERMON_MAINTENANCE_MODE) {
		return (EFAULT);
	}

	/* Copy in the hermon_reg_ioctl_t structure */
	status = ddi_copyin((void *)arg, &rdreg, sizeof (hermon_reg_ioctl_t),
	    mode);
	if (status != 0) {
		return (EFAULT);
	}

	/* Determine base address for requested register set */
	switch (rdreg.arg_reg_set) {
	case HERMON_CMD_BAR:
		baseaddr = (uintptr_t)state->hs_reg_cmd_baseaddr;
		handle = hermon_get_cmdhdl(state);
		break;

	case HERMON_UAR_BAR:
		baseaddr = (uintptr_t)state->hs_reg_uar_baseaddr;
		handle = hermon_get_uarhdl(state);
		break;


	default:
		return (EINVAL);
	}

	/* Ensure that address is properly-aligned */
	addr = (uint32_t *)((baseaddr + rdreg.arg_offset) & ~0x3);

	/* the FMA retry loop starts. */
	hermon_pio_start(state, handle, pio_error, fm_loop_cnt,
	    fm_status, fm_test);

	/* Read the register pointed to by addr */
	rdreg.arg_data = ddi_get32(handle, addr);

	/* the FMA retry loop ends. */
	hermon_pio_end(state, handle, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	/* Copy in the result into the hermon_reg_ioctl_t structure */
	status = ddi_copyout(&rdreg, (void *)arg, sizeof (hermon_reg_ioctl_t),
	    mode);
	if (status != 0) {
		return (EFAULT);
	}
	return (0);

pio_error:
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}


/*
 * hermon_ioctl_reg_write()
 */
static int
hermon_ioctl_reg_write(hermon_state_t *state, intptr_t arg, int mode)
{
	hermon_reg_ioctl_t	wrreg;
	uint32_t		*addr;
	uintptr_t		baseaddr;
	int			status;
	ddi_acc_handle_t	handle;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	/*
	 * Access to Hermon registers is not allowed in "maintenance mode".
	 * This is primarily because the device may not have BARs to access
	 */
	if (state->hs_operational_mode == HERMON_MAINTENANCE_MODE) {
		return (EFAULT);
	}

	/* Copy in the hermon_reg_ioctl_t structure */
	status = ddi_copyin((void *)arg, &wrreg, sizeof (hermon_reg_ioctl_t),
	    mode);
	if (status != 0) {
		return (EFAULT);
	}

	/* Determine base address for requested register set */
	switch (wrreg.arg_reg_set) {
	case HERMON_CMD_BAR:
		baseaddr = (uintptr_t)state->hs_reg_cmd_baseaddr;
		handle = hermon_get_cmdhdl(state);
		break;

	case HERMON_UAR_BAR:
		baseaddr = (uintptr_t)state->hs_reg_uar_baseaddr;
		handle = hermon_get_uarhdl(state);
		break;

	default:
		return (EINVAL);
	}

	/* Ensure that address is properly-aligned */
	addr = (uint32_t *)((baseaddr + wrreg.arg_offset) & ~0x3);

	/* the FMA retry loop starts. */
	hermon_pio_start(state, handle, pio_error, fm_loop_cnt,
	    fm_status, fm_test);

	/* Write the data to the register pointed to by addr */
	ddi_put32(handle, addr, wrreg.arg_data);

	/* the FMA retry loop ends. */
	hermon_pio_end(state, handle, pio_error, fm_loop_cnt, fm_status,
	    fm_test);
	return (0);

pio_error:
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}
#endif	/* DEBUG */

static int
hermon_ioctl_write_boot_addr(hermon_state_t *state, dev_t dev, intptr_t arg,
    int mode)
{
	hermon_flash_ioctl_t	ioctl_info;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	/*
	 * Check that flash init ioctl has been called first.  And check
	 * that the same dev_t that called init is the one calling write now.
	 */
	mutex_enter(&state->hs_fw_flashlock);
	if ((state->hs_fw_flashdev != dev) ||
	    (state->hs_fw_flashstarted == 0)) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EIO);
	}

	/* copy user struct to kernel */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		hermon_flash_ioctl32_t info32;

		if (ddi_copyin((void *)arg, &info32,
		    sizeof (hermon_flash_ioctl32_t), mode) != 0) {
			mutex_exit(&state->hs_fw_flashlock);
			return (EFAULT);
		}
		ioctl_info.af_type = info32.af_type;
		ioctl_info.af_sector = (caddr_t)(uintptr_t)info32.af_sector;
		ioctl_info.af_sector_num = info32.af_sector_num;
		ioctl_info.af_addr = info32.af_addr;
		ioctl_info.af_byte = info32.af_byte;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &ioctl_info,
	    sizeof (hermon_flash_ioctl_t), mode) != 0) {
		mutex_exit(&state->hs_fw_flashlock);
		return (EFAULT);
	}

	switch (state->hs_fw_cmdset) {
	case HERMON_FLASH_AMD_CMDSET:
	case HERMON_FLASH_INTEL_CMDSET:
		break;

	case HERMON_FLASH_SPI_CMDSET:
	{
		ddi_acc_handle_t pci_hdl = hermon_get_pcihdl(state);

		/* the FMA retry loop starts. */
		hermon_pio_start(state, pci_hdl, pio_error,
		    fm_loop_cnt, fm_status, fm_test);

		hermon_flash_write_cfg(state, pci_hdl,
		    HERMON_HW_FLASH_SPI_BOOT_ADDR_REG,
		    (ioctl_info.af_addr << 8) | 0x06);

		/* the FMA retry loop ends. */
		hermon_pio_end(state, pci_hdl, pio_error,
		    fm_loop_cnt, fm_status, fm_test);
		break;
	}

	case HERMON_FLASH_UNKNOWN_CMDSET:
	default:
		mutex_exit(&state->hs_fw_flashlock);
		return (EINVAL);
	}
	mutex_exit(&state->hs_fw_flashlock);
	return (0);

pio_error:
	mutex_exit(&state->hs_fw_flashlock);
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}

/*
 * hermon_flash_reset()
 */
static int
hermon_flash_reset(hermon_state_t *state)
{
	int status;

	/*
	 * Performs a reset to the flash device.  After a reset the flash will
	 * be operating in normal mode (capable of read/write, etc.).
	 */
	switch (state->hs_fw_cmdset) {
	case HERMON_FLASH_AMD_CMDSET:
		hermon_flash_write(state, 0x555, HERMON_HW_FLASH_RESET_AMD,
		    &status);
		if (status != 0) {
			return (status);
		}
		break;

	case HERMON_FLASH_INTEL_CMDSET:
		hermon_flash_write(state, 0x555, HERMON_HW_FLASH_RESET_INTEL,
		    &status);
		if (status != 0) {
			return (status);
		}
		break;

	/* It appears no reset is needed for SPI */
	case HERMON_FLASH_SPI_CMDSET:
		status = 0;
		break;

	case HERMON_FLASH_UNKNOWN_CMDSET:
	default:
		status = EINVAL;
		break;
	}
	return (status);
}

/*
 * hermon_flash_read_sector()
 */
static int
hermon_flash_read_sector(hermon_state_t *state, uint32_t sector_num)
{
	uint32_t addr;
	uint32_t end_addr;
	uint32_t *image;
	int i, status;

	image = (uint32_t *)&state->hs_fw_sector[0];

	/*
	 * Calculate the start and end address of the sector, based on the
	 * sector number passed in.
	 */
	addr = sector_num << state->hs_fw_log_sector_sz;
	end_addr = addr + (1 << state->hs_fw_log_sector_sz);

	/* Set the flash bank correctly for the given address */
	if ((status = hermon_flash_bank(state, addr)) != 0)
		return (status);

	/* Read the entire sector, one quadlet at a time */
	for (i = 0; addr < end_addr; i++, addr += 4) {
		image[i] = hermon_flash_read(state, addr, &status);
		if (status != 0) {
			return (status);
		}
	}
	return (0);
}

/*
 * hermon_flash_read_quadlet()
 */
static int
hermon_flash_read_quadlet(hermon_state_t *state, uint32_t *data,
    uint32_t addr)
{
	int status;

	/* Set the flash bank correctly for the given address */
	if ((status = hermon_flash_bank(state, addr)) != 0) {
		return (status);
	}

	/* Read one quadlet of data */
	*data = hermon_flash_read(state, addr, &status);
	if (status != 0) {
		return (EIO);
	}

	return (0);
}

/*
 * hermon_flash_write_sector()
 */
static int
hermon_flash_write_sector(hermon_state_t *state, uint32_t sector_num)
{
	uint32_t	addr;
	uint32_t	end_addr;
	uint32_t	*databuf;
	uchar_t		*sector;
	int		status = 0;
	int		i;

	sector = (uchar_t *)&state->hs_fw_sector[0];

	/*
	 * Calculate the start and end address of the sector, based on the
	 * sector number passed in.
	 */
	addr = sector_num << state->hs_fw_log_sector_sz;
	end_addr = addr + (1 << state->hs_fw_log_sector_sz);

	/* Set the flash bank correctly for the given address */
	if ((status = hermon_flash_bank(state, addr)) != 0 ||
	    (status = hermon_flash_reset(state)) != 0) {
		return (status);
	}

	/* Erase the sector before writing */
	status = hermon_flash_erase_sector(state, sector_num);
	if (status != 0) {
		return (status);
	}

	switch (state->hs_fw_cmdset) {
	case HERMON_FLASH_SPI_CMDSET:
		databuf = (uint32_t *)(void *)sector;
		/* Write the sector, one dword at a time */
		for (i = 0; addr < end_addr; i++, addr += 4) {
			if ((status = hermon_flash_spi_write_dword(state, addr,
			    htonl(databuf[i]))) != 0) {
				return (status);
			}
		}
		status = hermon_flash_reset(state);
		break;

	case HERMON_FLASH_INTEL_CMDSET:
	case HERMON_FLASH_AMD_CMDSET:
		/* Write the sector, one byte at a time */
		for (i = 0; addr < end_addr; i++, addr++) {
			status = hermon_flash_write_byte(state, addr,
			    sector[i]);
			if (status != 0) {
				break;
			}
		}
		status = hermon_flash_reset(state);
		break;

	case HERMON_FLASH_UNKNOWN_CMDSET:
	default:
		status = EINVAL;
		break;
	}

	return (status);
}

/*
 * hermon_flash_spi_write_dword()
 *
 * NOTE: This function assumes that "data" is in network byte order.
 *
 */
static int
hermon_flash_spi_write_dword(hermon_state_t *state, uint32_t addr,
    uint32_t data)
{
	int status;
	ddi_acc_handle_t	hdl;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	hdl = hermon_get_pcihdl(state);

	/* the FMA retry loop starts. */
	hermon_pio_start(state, hdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	/* Issue Write Enable */
	hermon_flash_spi_write_enable(state);

	/* Set the Address */
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_SPI_ADDR,
	    addr & HERMON_HW_FLASH_SPI_ADDR_MASK);

	/* Set the Data */
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_SPI_DATA, data);

	/* Set the Page Program and execute */
	hermon_flash_spi_exec_command(state, hdl,
	    HERMON_HW_FLASH_SPI_INSTR_PHASE_OFF |
	    HERMON_HW_FLASH_SPI_ADDR_PHASE_OFF |
	    HERMON_HW_FLASH_SPI_DATA_PHASE_OFF |
	    HERMON_HW_FLASH_SPI_TRANS_SZ_4B |
	    (HERMON_HW_FLASH_SPI_PAGE_PROGRAM <<
	    HERMON_HW_FLASH_SPI_INSTR_SHIFT));

	/* Wait for write to complete */
	if ((status = hermon_flash_spi_wait_wip(state)) != 0) {
		return (status);
	}

	/* the FMA retry loop ends. */
	hermon_pio_end(state, hdl, pio_error, fm_loop_cnt, fm_status, fm_test);
	return (0);

pio_error:
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}

/*
 * hermon_flash_write_byte()
 */
static int
hermon_flash_write_byte(hermon_state_t *state, uint32_t addr, uchar_t data)
{
	uint32_t stat;
	int status = 0;
	int dword_addr;
	int byte_offset;
	int i;
	union {
		uint8_t		bytes[4];
		uint32_t	dword;
	} dword;

	switch (state->hs_fw_cmdset) {
	case HERMON_FLASH_AMD_CMDSET:
		/* Issue Flash Byte program command */
		hermon_flash_write(state, addr, 0xAA, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, addr, 0x55, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, addr, 0xA0, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, addr, data, &status);
		if (status != 0) {
			return (status);
		}

		/* Wait for Write Byte to Complete */
		i = 0;
		do {
			drv_usecwait(1);
			stat = hermon_flash_read(state, addr & ~3, &status);
			if (status != 0) {
				return (status);
			}

			if (i == hermon_hw_flash_timeout_write) {
				cmn_err(CE_WARN,
				    "hermon_flash_write_byte: ACS write "
				    "timeout: addr: 0x%x, data: 0x%x\n",
				    addr, data);
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_IOCTL);
				return (EIO);
			}
			i++;
		} while (data != ((stat >> ((3 - (addr & 3)) << 3)) & 0xFF));

		break;

	case HERMON_FLASH_INTEL_CMDSET:
		/* Issue Flash Byte program command */
		hermon_flash_write(state, addr, HERMON_HW_FLASH_ICS_WRITE,
		    &status);
		if (status != 0) {
			return (status);
		}
		hermon_flash_write(state, addr, data, &status);
		if (status != 0) {
			return (status);
		}

		/* Wait for Write Byte to Complete */
		i = 0;
		do {
			drv_usecwait(1);
			stat = hermon_flash_read(state, addr & ~3, &status);
			if (status != 0) {
				return (status);
			}

			if (i == hermon_hw_flash_timeout_write) {
				cmn_err(CE_WARN,
				    "hermon_flash_write_byte: ICS write "
				    "timeout: addr: %x, data: %x\n",
				    addr, data);
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_IOCTL);
				return (EIO);
			}
			i++;
		} while ((stat & HERMON_HW_FLASH_ICS_READY) == 0);

		if (stat & HERMON_HW_FLASH_ICS_ERROR) {
			cmn_err(CE_WARN,
			    "hermon_flash_write_byte: ICS write cmd error: "
			    "addr: %x, data: %x\n",
			    addr, data);
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
			return (EIO);
		}
		break;

	case HERMON_FLASH_SPI_CMDSET:
		/*
		 * Our lowest write granularity on SPI is a dword.
		 * To support this ioctl option, we can read in the
		 * dword that contains this byte, modify this byte,
		 * and write the dword back out.
		 */

		/* Determine dword offset and byte offset within the dword */
		byte_offset = addr & 3;
		dword_addr = addr - byte_offset;
#ifdef _LITTLE_ENDIAN
		byte_offset = 3 - byte_offset;
#endif

		/* Read in dword */
		if ((status = hermon_flash_read_quadlet(state, &dword.dword,
		    dword_addr)) != 0)
			break;

		/* Set "data" to the appopriate byte */
		dword.bytes[byte_offset] = data;

		/* Write modified dword back out */
		status = hermon_flash_spi_write_dword(state, dword_addr,
		    dword.dword);

		break;

	case HERMON_FLASH_UNKNOWN_CMDSET:
	default:
		cmn_err(CE_WARN,
		    "hermon_flash_write_byte: unknown cmd set: 0x%x\n",
		    state->hs_fw_cmdset);
		status = EINVAL;
		break;
	}

	return (status);
}

/*
 * hermon_flash_erase_sector()
 */
static int
hermon_flash_erase_sector(hermon_state_t *state, uint32_t sector_num)
{
	ddi_acc_handle_t	hdl;
	uint32_t addr;
	uint32_t stat;
	int status = 0;
	int i;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	/* Get address from sector num */
	addr = sector_num << state->hs_fw_log_sector_sz;

	switch (state->hs_fw_cmdset) {
	case HERMON_FLASH_AMD_CMDSET:
		/* Issue Flash Sector Erase Command */
		hermon_flash_write(state, addr, 0xAA, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, addr, 0x55, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, addr, 0x80, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, addr, 0xAA, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, addr, 0x55, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, addr, 0x30, &status);
		if (status != 0) {
			return (status);
		}

		/* Wait for Sector Erase to complete */
		i = 0;
		do {
			drv_usecwait(1);
			stat = hermon_flash_read(state, addr, &status);
			if (status != 0) {
				return (status);
			}

			if (i == hermon_hw_flash_timeout_erase) {
				cmn_err(CE_WARN,
				    "hermon_flash_erase_sector: "
				    "ACS erase timeout\n");
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_IOCTL);
				return (EIO);
			}
			i++;
		} while (stat != 0xFFFFFFFF);
		break;

	case HERMON_FLASH_INTEL_CMDSET:
		/* Issue Flash Sector Erase Command */
		hermon_flash_write(state, addr, HERMON_HW_FLASH_ICS_ERASE,
		    &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, addr, HERMON_HW_FLASH_ICS_CONFIRM,
		    &status);
		if (status != 0) {
			return (status);
		}

		/* Wait for Sector Erase to complete */
		i = 0;
		do {
			drv_usecwait(1);
			stat = hermon_flash_read(state, addr & ~3, &status);
			if (status != 0) {
				return (status);
			}

			if (i == hermon_hw_flash_timeout_erase) {
				cmn_err(CE_WARN,
				    "hermon_flash_erase_sector: "
				    "ICS erase timeout\n");
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_IOCTL);
				return (EIO);
			}
			i++;
		} while ((stat & HERMON_HW_FLASH_ICS_READY) == 0);

		if (stat & HERMON_HW_FLASH_ICS_ERROR) {
			cmn_err(CE_WARN,
			    "hermon_flash_erase_sector: "
			    "ICS erase cmd error\n");
			hermon_fm_ereport(state, HCA_SYS_ERR,
			    HCA_ERR_IOCTL);
			return (EIO);
		}
		break;

	case HERMON_FLASH_SPI_CMDSET:
		hdl = hermon_get_pcihdl(state);

		/* the FMA retry loop starts. */
		hermon_pio_start(state, hdl, pio_error, fm_loop_cnt, fm_status,
		    fm_test);

		/* Issue Write Enable */
		hermon_flash_spi_write_enable(state);

		/* Set the Address */
		hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_SPI_ADDR,
		    addr & HERMON_HW_FLASH_SPI_ADDR_MASK);

		/* Issue Flash Sector Erase */
		hermon_flash_spi_exec_command(state, hdl,
		    HERMON_HW_FLASH_SPI_INSTR_PHASE_OFF |
		    HERMON_HW_FLASH_SPI_ADDR_PHASE_OFF |
		    ((uint32_t)(HERMON_HW_FLASH_SPI_SECTOR_ERASE) <<
		    HERMON_HW_FLASH_SPI_INSTR_SHIFT));

		/* the FMA retry loop ends. */
		hermon_pio_end(state, hdl, pio_error, fm_loop_cnt, fm_status,
		    fm_test);

		/* Wait for Sector Erase to complete */
		status = hermon_flash_spi_wait_wip(state);
		break;

	case HERMON_FLASH_UNKNOWN_CMDSET:
	default:
		cmn_err(CE_WARN,
		    "hermon_flash_erase_sector: unknown cmd set: 0x%x\n",
		    state->hs_fw_cmdset);
		status = EINVAL;
		break;
	}

	/* Reset the flash device */
	if (status == 0) {
		status = hermon_flash_reset(state);
	}
	return (status);

pio_error:
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}

/*
 * hermon_flash_erase_chip()
 */
static int
hermon_flash_erase_chip(hermon_state_t *state)
{
	uint32_t stat;
	uint_t size;
	int status = 0;
	int i;
	int num_sect;

	switch (state->hs_fw_cmdset) {
	case HERMON_FLASH_AMD_CMDSET:
		/* Issue Flash Chip Erase Command */
		hermon_flash_write(state, 0, 0xAA, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, 0, 0x55, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, 0, 0x80, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, 0, 0xAA, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, 0, 0x55, &status);
		if (status != 0) {
			return (status);
		}

		hermon_flash_write(state, 0, 0x10, &status);
		if (status != 0) {
			return (status);
		}

		/* Wait for Chip Erase to Complete */
		i = 0;
		do {
			drv_usecwait(1);
			stat = hermon_flash_read(state, 0, &status);
			if (status != 0) {
				return (status);
			}

			if (i == hermon_hw_flash_timeout_erase) {
				cmn_err(CE_WARN,
				    "hermon_flash_erase_chip: erase timeout\n");
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_IOCTL);
				return (EIO);
			}
			i++;
		} while (stat != 0xFFFFFFFF);
		break;

	case HERMON_FLASH_INTEL_CMDSET:
	case HERMON_FLASH_SPI_CMDSET:
		/*
		 * These chips don't have a chip erase command, so erase
		 * all blocks one at a time.
		 */
		size = (0x1 << state->hs_fw_log_sector_sz);
		num_sect = state->hs_fw_device_sz / size;

		for (i = 0; i < num_sect; i++) {
			status = hermon_flash_erase_sector(state, i);
			if (status != 0) {
				cmn_err(CE_WARN,
				    "hermon_flash_erase_chip: "
				    "sector %d erase error\n", i);
				return (status);
			}
		}
		break;

	case HERMON_FLASH_UNKNOWN_CMDSET:
	default:
		cmn_err(CE_WARN, "hermon_flash_erase_chip: "
		    "unknown cmd set: 0x%x\n", state->hs_fw_cmdset);
		status = EINVAL;
		break;
	}

	return (status);
}

/*
 * hermon_flash_spi_write_enable()
 */
static void
hermon_flash_spi_write_enable(hermon_state_t *state)
{
	ddi_acc_handle_t	hdl;

	hdl = hermon_get_pcihdl(state);

	hermon_flash_spi_exec_command(state, hdl,
	    HERMON_HW_FLASH_SPI_INSTR_PHASE_OFF |
	    (HERMON_HW_FLASH_SPI_WRITE_ENABLE <<
	    HERMON_HW_FLASH_SPI_INSTR_SHIFT));
}

/*
 * hermon_flash_spi_wait_wip()
 */
static int
hermon_flash_spi_wait_wip(hermon_state_t *state)
{
	ddi_acc_handle_t	hdl;
	uint32_t		status;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	hdl = hermon_get_pcihdl(state);

	/* the FMA retry loop starts. */
	hermon_pio_start(state, hdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	/* wait on the gateway to clear busy */
	do {
		status = hermon_flash_read_cfg(state, hdl,
		    HERMON_HW_FLASH_SPI_GW);
	} while (status & HERMON_HW_FLASH_SPI_BUSY);

	/* now, get the status and check for WIP to clear */
	do {
		hermon_flash_spi_exec_command(state, hdl,
		    HERMON_HW_FLASH_SPI_READ_OP |
		    HERMON_HW_FLASH_SPI_INSTR_PHASE_OFF |
		    HERMON_HW_FLASH_SPI_DATA_PHASE_OFF |
		    HERMON_HW_FLASH_SPI_TRANS_SZ_4B |
		    (HERMON_HW_FLASH_SPI_READ_STATUS_REG <<
		    HERMON_HW_FLASH_SPI_INSTR_SHIFT));

		status = hermon_flash_read_cfg(state, hdl,
		    HERMON_HW_FLASH_SPI_DATA);
	} while (status & HERMON_HW_FLASH_SPI_WIP);

	/* the FMA retry loop ends. */
	hermon_pio_end(state, hdl, pio_error, fm_loop_cnt, fm_status, fm_test);
	return (0);

pio_error:
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}

/*
 * hermon_flash_bank()
 */
static int
hermon_flash_bank(hermon_state_t *state, uint32_t addr)
{
	ddi_acc_handle_t	hdl;
	uint32_t		bank;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	/* Set handle */
	hdl = hermon_get_pcihdl(state);

	/* Determine the bank setting from the address */
	bank = addr & HERMON_HW_FLASH_BANK_MASK;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(state->hs_fw_flashbank))

	/*
	 * If the bank is different from the currently set bank, we need to
	 * change it.  Also, if an 'addr' of 0 is given, this allows the
	 * capability to force the flash bank to 0.  This is useful at init
	 * time to initially set the bank value
	 */
	if (state->hs_fw_flashbank != bank || addr == 0) {
		switch (state->hs_fw_cmdset) {
		case HERMON_FLASH_SPI_CMDSET:
			/* CMJ: not needed for hermon */
			break;

		case HERMON_FLASH_INTEL_CMDSET:
		case HERMON_FLASH_AMD_CMDSET:
			/* the FMA retry loop starts. */
			hermon_pio_start(state, hdl, pio_error, fm_loop_cnt,
			    fm_status, fm_test);

			hermon_flash_write_cfg(state, hdl,
			    HERMON_HW_FLASH_GPIO_DATACLEAR, 0x70);
			hermon_flash_write_cfg(state, hdl,
			    HERMON_HW_FLASH_GPIO_DATASET, (bank >> 15) & 0x70);

			/* the FMA retry loop ends. */
			hermon_pio_end(state, hdl, pio_error, fm_loop_cnt,
			    fm_status, fm_test);
			break;

		case HERMON_FLASH_UNKNOWN_CMDSET:
		default:
			return (EINVAL);
		}

		state->hs_fw_flashbank = bank;
	}
	return (0);

pio_error:
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}

/*
 * hermon_flash_spi_exec_command()
 */
static void
hermon_flash_spi_exec_command(hermon_state_t *state, ddi_acc_handle_t hdl,
    uint32_t cmd)
{
	uint32_t data;
	int timeout = 0;

	cmd |= HERMON_HW_FLASH_SPI_BUSY | HERMON_HW_FLASH_SPI_ENABLE_OFF;

	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_SPI_GW, cmd);

	do {
		data = hermon_flash_read_cfg(state, hdl,
		    HERMON_HW_FLASH_SPI_GW);
		timeout++;
	} while ((data & HERMON_HW_FLASH_SPI_BUSY) &&
	    (timeout < hermon_hw_flash_timeout_config));
}

/*
 * hermon_flash_read()
 */
static uint32_t
hermon_flash_read(hermon_state_t *state, uint32_t addr, int *err)
{
	ddi_acc_handle_t	hdl;
	uint32_t		data = 0;
	int			timeout, status = 0;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	hdl = hermon_get_pcihdl(state);

	/* the FMA retry loop starts. */
	hermon_pio_start(state, hdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	switch (state->hs_fw_cmdset) {
	case HERMON_FLASH_SPI_CMDSET:
		/* Set the transaction address */
		hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_SPI_ADDR,
		    (addr & HERMON_HW_FLASH_SPI_ADDR_MASK));

		hermon_flash_spi_exec_command(state, hdl,
		    HERMON_HW_FLASH_SPI_READ_OP |
		    HERMON_HW_FLASH_SPI_INSTR_PHASE_OFF |
		    HERMON_HW_FLASH_SPI_ADDR_PHASE_OFF |
		    HERMON_HW_FLASH_SPI_DATA_PHASE_OFF |
		    HERMON_HW_FLASH_SPI_TRANS_SZ_4B |
		    (HERMON_HW_FLASH_SPI_READ <<
		    HERMON_HW_FLASH_SPI_INSTR_SHIFT));

		data = hermon_flash_read_cfg(state, hdl,
		    HERMON_HW_FLASH_SPI_DATA);
		break;

	case HERMON_FLASH_INTEL_CMDSET:
	case HERMON_FLASH_AMD_CMDSET:
		/*
		 * The Read operation does the following:
		 *   1) Write the masked address to the HERMON_FLASH_ADDR
		 *	register. Only the least significant 19 bits are valid.
		 *   2) Read back the register until the command has completed.
		 *   3) Read the data retrieved from the address at the
		 *	HERMON_FLASH_DATA register.
		 */
		hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_ADDR,
		    (addr & HERMON_HW_FLASH_ADDR_MASK) | (1 << 29));

		timeout = 0;
		do {
			data = hermon_flash_read_cfg(state, hdl,
			    HERMON_HW_FLASH_ADDR);
			timeout++;
		} while ((data & HERMON_HW_FLASH_CMD_MASK) &&
		    (timeout < hermon_hw_flash_timeout_config));

		if (timeout == hermon_hw_flash_timeout_config) {
			cmn_err(CE_WARN, "hermon_flash_read: command timed "
			    "out.\n");
			*err = EIO;
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
			return (data);
		}

		data = hermon_flash_read_cfg(state, hdl, HERMON_HW_FLASH_DATA);
		break;

	case HERMON_FLASH_UNKNOWN_CMDSET:
	default:
		cmn_err(CE_CONT, "hermon_flash_read: unknown cmdset: 0x%x\n",
		    state->hs_fw_cmdset);
		status = EINVAL;
		break;
	}


	/* the FMA retry loop ends. */
	hermon_pio_end(state, hdl, pio_error, fm_loop_cnt, fm_status, fm_test);
	*err = status;
	return (data);

pio_error:
	*err = EIO;
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (data);
}

/*
 * hermon_flash_write()
 */
static void
hermon_flash_write(hermon_state_t *state, uint32_t addr, uchar_t data, int *err)
{
	ddi_acc_handle_t	hdl;
	int			cmd;
	int			timeout;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	hdl = hermon_get_pcihdl(state);

	/* the FMA retry loop starts. */
	hermon_pio_start(state, hdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	/*
	 * The Write operation does the following:
	 *   1) Write the data to be written to the HERMON_FLASH_DATA offset.
	 *   2) Write the address to write the data to to the HERMON_FLASH_ADDR
	 *	offset.
	 *   3) Wait until the write completes.
	 */

	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_DATA, data << 24);
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_ADDR,
	    (addr & 0x7FFFF) | (2 << 29));

	timeout = 0;
	do {
		cmd = hermon_flash_read_cfg(state, hdl, HERMON_HW_FLASH_ADDR);
		timeout++;
	} while ((cmd & HERMON_HW_FLASH_CMD_MASK) &&
	    (timeout < hermon_hw_flash_timeout_config));

	if (timeout == hermon_hw_flash_timeout_config) {
		cmn_err(CE_WARN, "hermon_flash_write: config cmd timeout.\n");
		*err = EIO;
		hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
		return;
	}

	/* the FMA retry loop ends. */
	hermon_pio_end(state, hdl, pio_error, fm_loop_cnt, fm_status, fm_test);
	*err = 0;
	return;

pio_error:
	*err = EIO;
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
}

/*
 * hermon_flash_init()
 */
static int
hermon_flash_init(hermon_state_t *state)
{
	uint32_t		word;
	ddi_acc_handle_t	hdl;
	int			sema_cnt;
	int			gpio;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	/* Set handle */
	hdl = hermon_get_pcihdl(state);

	/* the FMA retry loop starts. */
	hermon_pio_start(state, hdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	/* Init the flash */

#ifdef DO_WRCONF
	/*
	 * Grab the WRCONF semaphore.
	 */
	word = hermon_flash_read_cfg(state, hdl, HERMON_HW_FLASH_WRCONF_SEMA);
#endif

	/*
	 * Grab the GPIO semaphore.  This allows us exclusive access to the
	 * GPIO settings on the Hermon for the duration of the flash burning
	 * procedure.
	 */
	sema_cnt = 0;
	do {
		word = hermon_flash_read_cfg(state, hdl,
		    HERMON_HW_FLASH_GPIO_SEMA);
		if (word == 0) {
			break;
		}

		sema_cnt++;
		drv_usecwait(1);

	} while (sema_cnt < hermon_hw_flash_timeout_gpio_sema);

	/*
	 * Determine if we timed out trying to grab the GPIO semaphore
	 */
	if (sema_cnt == hermon_hw_flash_timeout_gpio_sema) {
		cmn_err(CE_WARN, "hermon_flash_init: GPIO SEMA timeout\n");
		cmn_err(CE_WARN, "GPIO_SEMA value: 0x%x\n", word);
		hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
		return (EIO);
	}

	/* Save away original GPIO Values */
	state->hs_fw_gpio[0] = hermon_flash_read_cfg(state, hdl,
	    HERMON_HW_FLASH_GPIO_DATA);

	/* Set new GPIO value */
	gpio = state->hs_fw_gpio[0] | HERMON_HW_FLASH_GPIO_PIN_ENABLE;
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_DATA, gpio);

	/* Save away original GPIO Values */
	state->hs_fw_gpio[1] = hermon_flash_read_cfg(state, hdl,
	    HERMON_HW_FLASH_GPIO_MOD0);
	state->hs_fw_gpio[2] = hermon_flash_read_cfg(state, hdl,
	    HERMON_HW_FLASH_GPIO_MOD1);

	/* unlock GPIO */
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_LOCK,
	    HERMON_HW_FLASH_GPIO_UNLOCK_VAL);

	/*
	 * Set new GPIO values
	 */
	gpio = state->hs_fw_gpio[1] | HERMON_HW_FLASH_GPIO_PIN_ENABLE;
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_MOD0, gpio);

	gpio = state->hs_fw_gpio[2] & ~HERMON_HW_FLASH_GPIO_PIN_ENABLE;
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_MOD1, gpio);

	/* re-lock GPIO */
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_LOCK, 0);

	/* Set CPUMODE to enable hermon to access the flash device */
	/* CMJ This code came from arbel.  Hermon doesn't seem to need it. */
	/*
	 *	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_CPUMODE,
	 *	    1 << HERMON_HW_FLASH_CPU_SHIFT);
	 */

	/* the FMA retry loop ends. */
	hermon_pio_end(state, hdl, pio_error, fm_loop_cnt, fm_status, fm_test);
	return (0);

pio_error:
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}

/*
 * hermon_flash_cfi_init
 *   Implements access to the CFI (Common Flash Interface) data
 */
static int
hermon_flash_cfi_init(hermon_state_t *state, uint32_t *cfi_info,
    int *intel_xcmd)
{
	uint32_t	data;
	uint32_t	sector_sz_bytes;
	uint32_t	bit_count;
	uint8_t		cfi_ch_info[HERMON_CFI_INFO_SIZE];
	int		i;
	int		status;

	/* Right now, all hermon cards use SPI. */
	if (hermon_device_mode(state)) {
		/*
		 * Don't use CFI for SPI part. Just fill in what we need
		 * and return.
		 */
		state->hs_fw_cmdset = HERMON_FLASH_SPI_CMDSET;
		state->hs_fw_log_sector_sz = HERMON_FLASH_SPI_LOG_SECTOR_SIZE;
		state->hs_fw_device_sz = HERMON_FLASH_SPI_DEVICE_SIZE;

		/*
		 * set this to inform caller of cmdset type.
		 */
		cfi_ch_info[0x13] = HERMON_FLASH_SPI_CMDSET;
		hermon_flash_cfi_dword(&cfi_info[4], cfi_ch_info, 0x10);
		return (0);
	}

	/*
	 * Determine if the user command supports the Intel Extended
	 * Command Set. The query string is contained in the fourth
	 * quad word.
	 */
	hermon_flash_cfi_byte(cfi_ch_info, cfi_info[0x04], 0x10);
	if (cfi_ch_info[0x10] == 'M' &&
	    cfi_ch_info[0x11] == 'X' &&
	    cfi_ch_info[0x12] == '2') {
		*intel_xcmd = 1; /* support is there */
		if (hermon_verbose) {
			IBTF_DPRINTF_L2("hermon",
			    "Support for Intel X is present\n");
		}
	}

	/* CFI QUERY */
	hermon_flash_write(state, 0x55, HERMON_FLASH_CFI_INIT, &status);
	if (status != 0) {
		return (status);
	}

	/* temporarily set the cmdset in order to do the initial read */
	state->hs_fw_cmdset = HERMON_FLASH_INTEL_CMDSET;

	/* Read in CFI data */
	for (i = 0; i < HERMON_CFI_INFO_SIZE; i += 4) {
		data = hermon_flash_read(state, i, &status);
		if (status != 0) {
			return (status);
		}
		hermon_flash_cfi_byte(cfi_ch_info, data, i);
	}

	/* Determine chip set */
	state->hs_fw_cmdset = HERMON_FLASH_UNKNOWN_CMDSET;
	if (cfi_ch_info[0x20] == 'Q' &&
	    cfi_ch_info[0x22] == 'R' &&
	    cfi_ch_info[0x24] == 'Y') {
		/*
		 * Mode: x16 working in x8 mode (Intel).
		 * Pack data - skip spacing bytes.
		 */
		if (hermon_verbose) {
			IBTF_DPRINTF_L2("hermon",
			    "x16 working in x8 mode (Intel)\n");
		}
		for (i = 0; i < HERMON_CFI_INFO_SIZE; i += 2) {
			cfi_ch_info[i/2] = cfi_ch_info[i];
		}
	}
	state->hs_fw_cmdset = cfi_ch_info[0x13];

	if (state->hs_fw_cmdset != HERMON_FLASH_INTEL_CMDSET &&
	    state->hs_fw_cmdset != HERMON_FLASH_AMD_CMDSET) {
		cmn_err(CE_WARN,
		    "hermon_flash_cfi_init: UNKNOWN chip cmd set 0x%04x\n",
		    state->hs_fw_cmdset);
		state->hs_fw_cmdset = HERMON_FLASH_UNKNOWN_CMDSET;
		return (0);
	}

	/* Determine total bytes in one sector size */
	sector_sz_bytes = ((cfi_ch_info[0x30] << 8) | cfi_ch_info[0x2F]) << 8;

	/* Calculate equivalent of log2 (n) */
	for (bit_count = 0; sector_sz_bytes > 1; bit_count++) {
		sector_sz_bytes >>= 1;
	}

	/* Set sector size */
	state->hs_fw_log_sector_sz = bit_count;

	/* Set flash size */
	state->hs_fw_device_sz = 0x1 << cfi_ch_info[0x27];

	/* Reset to turn off CFI mode */
	if ((status = hermon_flash_reset(state)) != 0)
		goto out;

	/* Pass CFI data back to user command. */
	for (i = 0; i < HERMON_FLASH_CFI_SIZE_QUADLET; i++) {
		hermon_flash_cfi_dword(&cfi_info[i], cfi_ch_info, i << 2);
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
	cfi_ch_info[0x13] = state->hs_fw_cmdset;
	hermon_flash_cfi_dword(&cfi_info[0x4], cfi_ch_info, 0x10);
out:
	return (status);
}

/*
 * hermon_flash_fini()
 */
static int
hermon_flash_fini(hermon_state_t *state)
{
	int status;
	ddi_acc_handle_t hdl;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	/* Set handle */
	hdl = hermon_get_pcihdl(state);

	if ((status = hermon_flash_bank(state, 0)) != 0)
		return (status);

	/* the FMA retry loop starts. */
	hermon_pio_start(state, hdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	/*
	 * Restore original GPIO Values
	 */
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_DATA,
	    state->hs_fw_gpio[0]);

	/* unlock GPIOs */
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_LOCK,
	    HERMON_HW_FLASH_GPIO_UNLOCK_VAL);

	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_MOD0,
	    state->hs_fw_gpio[1]);
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_MOD1,
	    state->hs_fw_gpio[2]);

	/* re-lock GPIOs */
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_LOCK, 0);

	/* Give up gpio semaphore */
	hermon_flash_write_cfg(state, hdl, HERMON_HW_FLASH_GPIO_SEMA, 0);

	/* the FMA retry loop ends. */
	hermon_pio_end(state, hdl, pio_error, fm_loop_cnt, fm_status, fm_test);
	return (0);

pio_error:
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_IOCTL);
	return (EIO);
}

/*
 * hermon_flash_read_cfg
 */
static uint32_t
hermon_flash_read_cfg(hermon_state_t *state, ddi_acc_handle_t pci_config_hdl,
    uint32_t addr)
{
	uint32_t	read;

	if (do_bar0) {
		read = ddi_get32(hermon_get_cmdhdl(state), (uint32_t *)(void *)
		    (state->hs_reg_cmd_baseaddr + addr));
	} else {
		/*
		 * Perform flash read operation:
		 *   1) Place addr to read from on the HERMON_HW_FLASH_CFG_ADDR
		 *	register
		 *   2) Read data at that addr from the HERMON_HW_FLASH_CFG_DATA
		 *	 register
		 */
		pci_config_put32(pci_config_hdl, HERMON_HW_FLASH_CFG_ADDR,
		    addr);
		read = pci_config_get32(pci_config_hdl,
		    HERMON_HW_FLASH_CFG_DATA);
	}

	return (read);
}

#ifdef DO_WRCONF
static void
hermon_flash_write_cfg(hermon_state_t *state,
    ddi_acc_handle_t pci_config_hdl, uint32_t addr, uint32_t data)
{
	hermon_flash_write_cfg_helper(state, pci_config_hdl, addr, data);
	hermon_flash_write_confirm(state, pci_config_hdl);
}

static void
hermon_flash_write_confirm(hermon_state_t *state,
    ddi_acc_handle_t pci_config_hdl)
{
	uint32_t	sem_value = 1;

	hermon_flash_write_cfg_helper(state, pci_config_hdl,
	    HERMON_HW_FLASH_WRCONF_SEMA, 0);
	while (sem_value) {
		sem_value = hermon_flash_read_cfg(state, pci_config_hdl,
		    HERMON_HW_FLASH_WRCONF_SEMA);
	}
}
#endif

/*
 * hermon_flash_write_cfg
 */
static void
#ifdef DO_WRCONF
hermon_flash_write_cfg_helper(hermon_state_t *state,
    ddi_acc_handle_t pci_config_hdl, uint32_t addr, uint32_t data)
#else
hermon_flash_write_cfg(hermon_state_t *state,
    ddi_acc_handle_t pci_config_hdl, uint32_t addr, uint32_t data)
#endif
{
	if (do_bar0) {
		ddi_put32(hermon_get_cmdhdl(state), (uint32_t *)(void *)
		    (state->hs_reg_cmd_baseaddr + addr), data);

	} else {

		/*
		 * Perform flash write operation:
		 *   1) Place addr to write to on the HERMON_HW_FLASH_CFG_ADDR
		 *	register
		 *   2) Place data to write on to the HERMON_HW_FLASH_CFG_DATA
		 *	register
		 */
		pci_config_put32(pci_config_hdl, HERMON_HW_FLASH_CFG_ADDR,
		    addr);
		pci_config_put32(pci_config_hdl, HERMON_HW_FLASH_CFG_DATA,
		    data);
	}
}

/*
 * Support routines to convert Common Flash Interface (CFI) data
 * from a 32  bit word to a char array, and from a char array to
 * a 32 bit word.
 */
static void
hermon_flash_cfi_byte(uint8_t *ch, uint32_t dword, int i)
{
	ch[i] = (uint8_t)((dword & 0xFF000000) >> 24);
	ch[i+1] = (uint8_t)((dword & 0x00FF0000) >> 16);
	ch[i+2] = (uint8_t)((dword & 0x0000FF00) >> 8);
	ch[i+3] = (uint8_t)((dword & 0x000000FF));
}

static void
hermon_flash_cfi_dword(uint32_t *dword, uint8_t *ch, int i)
{
	*dword = (uint32_t)
	    ((uint32_t)ch[i] << 24 |
	    (uint32_t)ch[i+1] << 16 |
	    (uint32_t)ch[i+2] << 8 |
	    (uint32_t)ch[i+3]);
}

/*
 * hermon_loopback_free_qps
 */
static void
hermon_loopback_free_qps(hermon_loopback_state_t *lstate)
{
	int i;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lstate))

	if (lstate->hls_tx.hlc_qp_hdl != NULL) {
		(void) hermon_qp_free(lstate->hls_state,
		    &lstate->hls_tx.hlc_qp_hdl, IBC_FREE_QP_AND_QPN, NULL,
		    HERMON_NOSLEEP);
	}
	if (lstate->hls_rx.hlc_qp_hdl != NULL) {
		(void) hermon_qp_free(lstate->hls_state,
		    &lstate->hls_rx.hlc_qp_hdl, IBC_FREE_QP_AND_QPN, NULL,
		    HERMON_NOSLEEP);
	}
	lstate->hls_tx.hlc_qp_hdl = NULL;
	lstate->hls_rx.hlc_qp_hdl = NULL;
	for (i = 0; i < 2; i++) {
		if (lstate->hls_tx.hlc_cqhdl[i] != NULL) {
			(void) hermon_cq_free(lstate->hls_state,
			    &lstate->hls_tx.hlc_cqhdl[i], HERMON_NOSLEEP);
		}
		if (lstate->hls_rx.hlc_cqhdl[i] != NULL) {
			(void) hermon_cq_free(lstate->hls_state,
			    &lstate->hls_rx.hlc_cqhdl[i], HERMON_NOSLEEP);
		}
		lstate->hls_tx.hlc_cqhdl[i] = NULL;
		lstate->hls_rx.hlc_cqhdl[i] = NULL;
	}
}

/*
 * hermon_loopback_free_state
 */
static void
hermon_loopback_free_state(hermon_loopback_state_t *lstate)
{
	hermon_loopback_free_qps(lstate);
	if (lstate->hls_tx.hlc_mrhdl != NULL) {
		(void) hermon_mr_deregister(lstate->hls_state,
		    &lstate->hls_tx.hlc_mrhdl, HERMON_MR_DEREG_ALL,
		    HERMON_NOSLEEP);
	}
	if (lstate->hls_rx.hlc_mrhdl !=  NULL) {
		(void) hermon_mr_deregister(lstate->hls_state,
		    &lstate->hls_rx.hlc_mrhdl, HERMON_MR_DEREG_ALL,
		    HERMON_NOSLEEP);
	}
	if (lstate->hls_pd_hdl != NULL) {
		(void) hermon_pd_free(lstate->hls_state, &lstate->hls_pd_hdl);
	}
	if (lstate->hls_tx.hlc_buf != NULL) {
		kmem_free(lstate->hls_tx.hlc_buf, lstate->hls_tx.hlc_buf_sz);
	}
	if (lstate->hls_rx.hlc_buf != NULL) {
		kmem_free(lstate->hls_rx.hlc_buf, lstate->hls_rx.hlc_buf_sz);
	}
	bzero(lstate, sizeof (hermon_loopback_state_t));
}

/*
 * hermon_loopback_init
 */
static int
hermon_loopback_init(hermon_state_t *state, hermon_loopback_state_t *lstate)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lstate))

	lstate->hls_hca_hdl = (ibc_hca_hdl_t)state;
	lstate->hls_status  = hermon_pd_alloc(lstate->hls_state,
	    &lstate->hls_pd_hdl, HERMON_NOSLEEP);
	if (lstate->hls_status != IBT_SUCCESS) {
		lstate->hls_err = HERMON_LOOPBACK_PROT_DOMAIN_ALLOC_FAIL;
		return (EFAULT);
	}

	return (0);
}

/*
 * hermon_loopback_init_qp_info
 */
static void
hermon_loopback_init_qp_info(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm)
{
	bzero(&comm->hlc_cq_attr, sizeof (ibt_cq_attr_t));
	bzero(&comm->hlc_qp_attr, sizeof (ibt_qp_alloc_attr_t));
	bzero(&comm->hlc_qp_info, sizeof (ibt_qp_info_t));

	comm->hlc_wrid = 1;
	comm->hlc_cq_attr.cq_size = 128;
	comm->hlc_qp_attr.qp_sizes.cs_sq_sgl = 3;
	comm->hlc_qp_attr.qp_sizes.cs_rq_sgl = 3;
	comm->hlc_qp_attr.qp_sizes.cs_sq = 16;
	comm->hlc_qp_attr.qp_sizes.cs_rq = 16;
	comm->hlc_qp_attr.qp_flags = IBT_WR_SIGNALED;

	comm->hlc_qp_info.qp_state = IBT_STATE_RESET;
	comm->hlc_qp_info.qp_trans = IBT_RC_SRV;
	comm->hlc_qp_info.qp_flags = IBT_CEP_RDMA_RD | IBT_CEP_RDMA_WR;
	comm->hlc_qp_info.qp_transport.rc.rc_path.cep_hca_port_num =
	    lstate->hls_port;
	comm->hlc_qp_info.qp_transport.rc.rc_path.cep_pkey_ix =
	    lstate->hls_pkey_ix;
	comm->hlc_qp_info.qp_transport.rc.rc_path.cep_timeout =
	    lstate->hls_timeout;
	comm->hlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_srvl = 0;
	comm->hlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_srate =
	    IBT_SRATE_4X;
	comm->hlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_send_grh = 0;
	comm->hlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_dlid =
	    lstate->hls_lid;
	comm->hlc_qp_info.qp_transport.rc.rc_retry_cnt = lstate->hls_retry;
	comm->hlc_qp_info.qp_transport.rc.rc_sq_psn = 0;
	comm->hlc_qp_info.qp_transport.rc.rc_rq_psn = 0;
	comm->hlc_qp_info.qp_transport.rc.rc_rdma_ra_in	 = 4;
	comm->hlc_qp_info.qp_transport.rc.rc_rdma_ra_out = 4;
	comm->hlc_qp_info.qp_transport.rc.rc_dst_qpn = 0;
	comm->hlc_qp_info.qp_transport.rc.rc_min_rnr_nak = IBT_RNR_NAK_655ms;
	comm->hlc_qp_info.qp_transport.rc.rc_path_mtu = IB_MTU_1K;
}

/*
 * hermon_loopback_alloc_mem
 */
static int
hermon_loopback_alloc_mem(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm, int sz)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm))

	/* Allocate buffer of specified size */
	comm->hlc_buf_sz = sz;
	comm->hlc_buf	 = kmem_zalloc(sz, KM_NOSLEEP);
	if (comm->hlc_buf == NULL) {
		return (EFAULT);
	}

	/* Register the buffer as a memory region */
	comm->hlc_memattr.mr_vaddr = (uint64_t)(uintptr_t)comm->hlc_buf;
	comm->hlc_memattr.mr_len   = (ib_msglen_t)sz;
	comm->hlc_memattr.mr_as	   = NULL;
	comm->hlc_memattr.mr_flags = IBT_MR_NOSLEEP |
	    IBT_MR_ENABLE_REMOTE_WRITE | IBT_MR_ENABLE_LOCAL_WRITE;

	comm->hlc_status = hermon_mr_register(lstate->hls_state,
	    lstate->hls_pd_hdl, &comm->hlc_memattr, &comm->hlc_mrhdl,
	    NULL, HERMON_MPT_DMPT);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm->hlc_mrhdl))

	comm->hlc_mrdesc.md_vaddr  = comm->hlc_mrhdl->mr_bindinfo.bi_addr;
	comm->hlc_mrdesc.md_lkey   = comm->hlc_mrhdl->mr_lkey;
	comm->hlc_mrdesc.md_rkey   = comm->hlc_mrhdl->mr_rkey;
	if (comm->hlc_status != IBT_SUCCESS) {
		return (EFAULT);
	}
	return (0);
}

/*
 * hermon_loopback_alloc_qps
 */
static int
hermon_loopback_alloc_qps(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm)
{
	uint32_t		i, real_size;
	hermon_qp_info_t		qpinfo;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lstate))

	/* Allocate send and recv CQs */
	for (i = 0; i < 2; i++) {
		bzero(&comm->hlc_cq_attr, sizeof (ibt_cq_attr_t));
		comm->hlc_cq_attr.cq_size = 128;
		comm->hlc_status = hermon_cq_alloc(lstate->hls_state,
		    (ibt_cq_hdl_t)NULL, &comm->hlc_cq_attr, &real_size,
		    &comm->hlc_cqhdl[i], HERMON_NOSLEEP);
		if (comm->hlc_status != IBT_SUCCESS) {
			lstate->hls_err += i;
			return (EFAULT);
		}
	}

	/* Allocate the QP */
	hermon_loopback_init_qp_info(lstate, comm);
	comm->hlc_qp_attr.qp_pd_hdl	 = (ibt_pd_hdl_t)lstate->hls_pd_hdl;
	comm->hlc_qp_attr.qp_scq_hdl	 = (ibt_cq_hdl_t)comm->hlc_cqhdl[0];
	comm->hlc_qp_attr.qp_rcq_hdl	 = (ibt_cq_hdl_t)comm->hlc_cqhdl[1];
	comm->hlc_qp_attr.qp_ibc_scq_hdl = (ibt_opaque1_t)comm->hlc_cqhdl[0];
	comm->hlc_qp_attr.qp_ibc_rcq_hdl = (ibt_opaque1_t)comm->hlc_cqhdl[1];
	qpinfo.qpi_attrp	= &comm->hlc_qp_attr;
	qpinfo.qpi_type		= IBT_RC_RQP;
	qpinfo.qpi_ibt_qphdl	= NULL;
	qpinfo.qpi_queueszp	= &comm->hlc_chan_sizes;
	qpinfo.qpi_qpn		= &comm->hlc_qp_num;
	comm->hlc_status = hermon_qp_alloc(lstate->hls_state, &qpinfo,
	    HERMON_NOSLEEP);
	if (comm->hlc_status == DDI_SUCCESS) {
		comm->hlc_qp_hdl = qpinfo.qpi_qphdl;
	}

	if (comm->hlc_status != IBT_SUCCESS) {
		lstate->hls_err += 2;
		return (EFAULT);
	}
	return (0);
}

/*
 * hermon_loopback_modify_qp
 */
static int
hermon_loopback_modify_qp(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm, uint_t qp_num)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lstate))

	/* Modify QP to INIT */
	hermon_loopback_init_qp_info(lstate, comm);
	comm->hlc_qp_info.qp_state = IBT_STATE_INIT;
	comm->hlc_status = hermon_qp_modify(lstate->hls_state, comm->hlc_qp_hdl,
	    IBT_CEP_SET_STATE, &comm->hlc_qp_info, &comm->hlc_queue_sizes);
	if (comm->hlc_status != IBT_SUCCESS) {
		return (EFAULT);
	}

	/*
	 * Modify QP to RTR (set destination LID and QP number to local
	 * LID and QP number)
	 */
	comm->hlc_qp_info.qp_state = IBT_STATE_RTR;
	comm->hlc_qp_info.qp_transport.rc.rc_path.cep_adds_vect.av_dlid
	    = lstate->hls_lid;
	comm->hlc_qp_info.qp_transport.rc.rc_dst_qpn = qp_num;
	comm->hlc_status = hermon_qp_modify(lstate->hls_state, comm->hlc_qp_hdl,
	    IBT_CEP_SET_STATE, &comm->hlc_qp_info, &comm->hlc_queue_sizes);
	if (comm->hlc_status != IBT_SUCCESS) {
		lstate->hls_err += 1;
		return (EFAULT);
	}

	/* Modify QP to RTS */
	comm->hlc_qp_info.qp_current_state = IBT_STATE_RTR;
	comm->hlc_qp_info.qp_state = IBT_STATE_RTS;
	comm->hlc_status = hermon_qp_modify(lstate->hls_state, comm->hlc_qp_hdl,
	    IBT_CEP_SET_STATE, &comm->hlc_qp_info, &comm->hlc_queue_sizes);
	if (comm->hlc_status != IBT_SUCCESS) {
		lstate->hls_err += 2;
		return (EFAULT);
	}
	return (0);
}

/*
 * hermon_loopback_copyout
 */
static int
hermon_loopback_copyout(hermon_loopback_ioctl_t *lb, intptr_t arg, int mode)
{
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		hermon_loopback_ioctl32_t lb32;

		lb32.alb_revision	= lb->alb_revision;
		lb32.alb_send_buf	=
		    (caddr32_t)(uintptr_t)lb->alb_send_buf;
		lb32.alb_fail_buf	=
		    (caddr32_t)(uintptr_t)lb->alb_fail_buf;
		lb32.alb_buf_sz		= lb->alb_buf_sz;
		lb32.alb_num_iter	= lb->alb_num_iter;
		lb32.alb_pass_done	= lb->alb_pass_done;
		lb32.alb_timeout	= lb->alb_timeout;
		lb32.alb_error_type	= lb->alb_error_type;
		lb32.alb_port_num	= lb->alb_port_num;
		lb32.alb_num_retry	= lb->alb_num_retry;

		if (ddi_copyout(&lb32, (void *)arg,
		    sizeof (hermon_loopback_ioctl32_t), mode) != 0) {
			return (EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout(lb, (void *)arg, sizeof (hermon_loopback_ioctl_t),
	    mode) != 0) {
		return (EFAULT);
	}
	return (0);
}

/*
 * hermon_loopback_post_send
 */
static int
hermon_loopback_post_send(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *tx, hermon_loopback_comm_t *rx)
{
	int	 ret;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*tx))

	bzero(&tx->hlc_sgl, sizeof (ibt_wr_ds_t));
	bzero(&tx->hlc_wr, sizeof (ibt_send_wr_t));

	/* Initialize local address for TX buffer */
	tx->hlc_sgl.ds_va   = tx->hlc_mrdesc.md_vaddr;
	tx->hlc_sgl.ds_key  = tx->hlc_mrdesc.md_lkey;
	tx->hlc_sgl.ds_len  = tx->hlc_buf_sz;

	/* Initialize the remaining details of the work request */
	tx->hlc_wr.wr_id = tx->hlc_wrid++;
	tx->hlc_wr.wr_flags  = IBT_WR_SEND_SIGNAL;
	tx->hlc_wr.wr_nds    = 1;
	tx->hlc_wr.wr_sgl    = &tx->hlc_sgl;
	tx->hlc_wr.wr_opcode = IBT_WRC_RDMAW;
	tx->hlc_wr.wr_trans  = IBT_RC_SRV;

	/* Initialize the remote address for RX buffer */
	tx->hlc_wr.wr.rc.rcwr.rdma.rdma_raddr = rx->hlc_mrdesc.md_vaddr;
	tx->hlc_wr.wr.rc.rcwr.rdma.rdma_rkey  = rx->hlc_mrdesc.md_rkey;
	tx->hlc_complete = 0;
	ret = hermon_post_send(lstate->hls_state, tx->hlc_qp_hdl, &tx->hlc_wr,
	    1, NULL);
	if (ret != IBT_SUCCESS) {
		return (EFAULT);
	}
	return (0);
}

/*
 * hermon_loopback_poll_cq
 */
static int
hermon_loopback_poll_cq(hermon_loopback_state_t *lstate,
    hermon_loopback_comm_t *comm)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*comm))

	comm->hlc_wc.wc_status	= 0;
	comm->hlc_num_polled	= 0;
	comm->hlc_status = hermon_cq_poll(lstate->hls_state,
	    comm->hlc_cqhdl[0], &comm->hlc_wc, 1, &comm->hlc_num_polled);
	if ((comm->hlc_status == IBT_SUCCESS) &&
	    (comm->hlc_wc.wc_status != IBT_WC_SUCCESS)) {
		comm->hlc_status = ibc_get_ci_failure(0);
	}
	return (comm->hlc_status);
}
