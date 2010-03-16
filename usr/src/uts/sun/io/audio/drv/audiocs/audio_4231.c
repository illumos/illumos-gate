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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * audiocs Audio Driver
 *
 * This Audio Driver controls the Crystal CS4231 Codec used on many SPARC
 * platforms. It does not support the CS4231 on Power PCs or x86 PCs. It
 * does support two different DMA engines, the APC and EB2. The code for
 * those DMA engines is split out and a well defined, but private, interface
 * is used to control those DMA engines.
 *
 * For some reason setting the CS4231's registers doesn't always
 * succeed.  Therefore every time we set a register we always read it
 * back to make sure it was set. If not we wait a little while and
 * then try again. This is all taken care of in the routines
 * audiocs_put_index() and audiocs_sel_index() and the macros ORIDX()
 * and ANDIDX(). We don't worry about the status register because it
 * is cleared by writing anything to it.  So it doesn't matter what
 * the value written is.
 *
 * This driver supports suspending and resuming. A suspend just stops playing
 * and recording. The play DMA buffers end up getting thrown away, but when
 * you shut down the machine there is a break in the audio anyway, so they
 * won't be missed and it isn't worth the effort to save them. When we resume
 * we always start playing and recording. If they aren't needed they get
 * shut off by the mixer.
 *
 * Power management is supported by this driver.
 *
 *	NOTE: This module depends on drv/audio being loaded first.
 */

#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/audio/audio_driver.h>
#include "audio_4231.h"

/*
 * Module linkage routines for the kernel
 */
static int audiocs_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int audiocs_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int audiocs_ddi_power(dev_info_t *, int, int);

/*
 * Entry point routine prototypes
 */
static int audiocs_open(void *, int, unsigned *, caddr_t *);
static void audiocs_close(void *);
static int audiocs_start(void *);
static void audiocs_stop(void *);
static int audiocs_format(void *);
static int audiocs_channels(void *);
static int audiocs_rate(void *);
static uint64_t audiocs_count(void *);
static void audiocs_sync(void *, unsigned);

/*
 * Control callbacks.
 */
static int audiocs_get_value(void *, uint64_t *);
static int audiocs_set_ogain(void *, uint64_t);
static int audiocs_set_igain(void *, uint64_t);
static int audiocs_set_mgain(void *, uint64_t);
static int audiocs_set_inputs(void *, uint64_t);
static int audiocs_set_outputs(void *, uint64_t);
static int audiocs_set_micboost(void *, uint64_t);

/* Local Routines */
static int audiocs_resume(dev_info_t *);
static int audiocs_attach(dev_info_t *);
static int audiocs_detach(dev_info_t *);
static int audiocs_suspend(dev_info_t *);

static void audiocs_destroy(CS_state_t *);
static int audiocs_init_state(CS_state_t *);
static int audiocs_chip_init(CS_state_t *);
static int audiocs_alloc_engine(CS_state_t *, int);
static void audiocs_free_engine(CS_engine_t *);
static void audiocs_get_ports(CS_state_t *);
static void audiocs_configure_input(CS_state_t *);
static void audiocs_configure_output(CS_state_t *);
static CS_ctrl_t *audiocs_alloc_ctrl(CS_state_t *, uint32_t, uint64_t);
static void audiocs_free_ctrl(CS_ctrl_t *);
static int audiocs_add_controls(CS_state_t *);
static void audiocs_del_controls(CS_state_t *);
static void audiocs_power_up(CS_state_t *);
static void audiocs_power_down(CS_state_t *);
static int audiocs_poll_ready(CS_state_t *);
#ifdef	DEBUG
static void audiocs_put_index(CS_state_t *,  uint8_t, uint8_t, int);
static void audiocs_sel_index(CS_state_t *, uint8_t, int);
#define	SELIDX(s, idx)		audiocs_sel_index(s, idx, __LINE__)
#define	PUTIDX(s, val, mask)	audiocs_put_index(s, val, mask, __LINE__)
#else
static void audiocs_put_index(CS_state_t *,  uint8_t, uint8_t);
static void audiocs_sel_index(CS_state_t *, uint8_t);
#define	SELIDX(s, idx)		audiocs_sel_index(s, idx)
#define	PUTIDX(s, val, mask)	audiocs_put_index(s, val, mask)
#endif
#define	GETIDX(s)		ddi_get8((handle), &CS4231_IDR)

#define	ORIDX(s, val, mask)						\
	PUTIDX(s,							\
	    (ddi_get8((handle), &CS4231_IDR) | (uint8_t)(val)),		\
	    (uint8_t)(mask))

#define	ANDIDX(s, val, mask)						\
	PUTIDX(s, (ddi_get8((handle), &CS4231_IDR) & (uint8_t)(val)),	\
	    (uint8_t)(mask))

static audio_engine_ops_t audiocs_engine_ops = {
	AUDIO_ENGINE_VERSION,
	audiocs_open,
	audiocs_close,
	audiocs_start,
	audiocs_stop,
	audiocs_count,
	audiocs_format,
	audiocs_channels,
	audiocs_rate,
	audiocs_sync,
	NULL,
	NULL,
	NULL,
};

#define	OUTPUT_SPEAKER		0
#define	OUTPUT_HEADPHONES	1
#define	OUTPUT_LINEOUT		2

static const char *audiocs_outputs[] = {
	AUDIO_PORT_SPEAKER,
	AUDIO_PORT_HEADPHONES,
	AUDIO_PORT_LINEOUT,
	NULL
};

#define	INPUT_MIC		0
#define	INPUT_LINEIN		1
#define	INPUT_STEREOMIX		2
#define	INPUT_CD		3

static const char *audiocs_inputs[] = {
	AUDIO_PORT_MIC,
	AUDIO_PORT_LINEIN,
	AUDIO_PORT_STEREOMIX,
	AUDIO_PORT_CD,
	NULL
};

/*
 * Global variables, but viewable only by this file.
 */

/* play gain array, converts linear gain to 64 steps of log10 gain */
static uint8_t cs4231_atten[] = {
	0x3f,	0x3e,	0x3d,	0x3c,	0x3b,	/* [000] -> [004] */
	0x3a,	0x39,	0x38,	0x37,	0x36,	/* [005] -> [009] */
	0x35,	0x34,	0x33,	0x32,	0x31,	/* [010] -> [014] */
	0x30,	0x2f,	0x2e,	0x2d,	0x2c,	/* [015] -> [019] */
	0x2b,	0x2a,	0x29,	0x29,	0x28,	/* [020] -> [024] */
	0x28,	0x27,	0x27,	0x26,	0x26,	/* [025] -> [029] */
	0x25,	0x25,	0x24,	0x24,	0x23,	/* [030] -> [034] */
	0x23,	0x22,	0x22,	0x21,	0x21,	/* [035] -> [039] */
	0x20,	0x20,	0x1f,	0x1f,	0x1f,	/* [040] -> [044] */
	0x1e,	0x1e,	0x1e,	0x1d,	0x1d,	/* [045] -> [049] */
	0x1d,	0x1c,	0x1c,	0x1c,	0x1b,	/* [050] -> [054] */
	0x1b,	0x1b,	0x1a,	0x1a,	0x1a,	/* [055] -> [059] */
	0x1a,	0x19,	0x19,	0x19,	0x19,	/* [060] -> [064] */
	0x18,	0x18,	0x18,	0x18,	0x17,	/* [065] -> [069] */
	0x17,	0x17,	0x17,	0x16,	0x16,	/* [070] -> [074] */
	0x16,	0x16,	0x16,	0x15,	0x15,	/* [075] -> [079] */
	0x15,	0x15,	0x15,	0x14,	0x14,	/* [080] -> [084] */
	0x14,	0x14,	0x14,	0x13,	0x13,	/* [085] -> [089] */
	0x13,	0x13,	0x13,	0x12,	0x12,	/* [090] -> [094] */
	0x12,	0x12,	0x12,	0x12,	0x11,	/* [095] -> [099] */
	0x11,	0x11,	0x11,	0x11,	0x11,	/* [100] -> [104] */
	0x10,	0x10,	0x10,	0x10,	0x10,	/* [105] -> [109] */
	0x10,	0x0f,	0x0f,	0x0f,	0x0f,	/* [110] -> [114] */
	0x0f,	0x0f,	0x0e,	0x0e,	0x0e,	/* [114] -> [119] */
	0x0e,	0x0e,	0x0e,	0x0e,	0x0d,	/* [120] -> [124] */
	0x0d,	0x0d,	0x0d,	0x0d,	0x0d,	/* [125] -> [129] */
	0x0d,	0x0c,	0x0c,	0x0c,	0x0c,	/* [130] -> [134] */
	0x0c,	0x0c,	0x0c,	0x0b,	0x0b,	/* [135] -> [139] */
	0x0b,	0x0b,	0x0b,	0x0b,	0x0b,	/* [140] -> [144] */
	0x0b,	0x0a,	0x0a,	0x0a,	0x0a,	/* [145] -> [149] */
	0x0a,	0x0a,	0x0a,	0x0a,	0x09,	/* [150] -> [154] */
	0x09,	0x09,	0x09,	0x09,	0x09,	/* [155] -> [159] */
	0x09,	0x09,	0x08,	0x08,	0x08,	/* [160] -> [164] */
	0x08,	0x08,	0x08,	0x08,	0x08,	/* [165] -> [169] */
	0x08,	0x07,	0x07,	0x07,	0x07,	/* [170] -> [174] */
	0x07,	0x07,	0x07,	0x07,	0x07,	/* [175] -> [179] */
	0x06,	0x06,	0x06,	0x06,	0x06,	/* [180] -> [184] */
	0x06,	0x06,	0x06,	0x06,	0x05,	/* [185] -> [189] */
	0x05,	0x05,	0x05,	0x05,	0x05,	/* [190] -> [194] */
	0x05,	0x05,	0x05,	0x05,	0x04,	/* [195] -> [199] */
	0x04,	0x04,	0x04,	0x04,	0x04,	/* [200] -> [204] */
	0x04,	0x04,	0x04,	0x04,	0x03,	/* [205] -> [209] */
	0x03,	0x03,	0x03,	0x03,	0x03,	/* [210] -> [214] */
	0x03,	0x03,	0x03,	0x03,	0x03,	/* [215] -> [219] */
	0x02,	0x02,	0x02,	0x02,	0x02,	/* [220] -> [224] */
	0x02,	0x02,	0x02,	0x02,	0x02,	/* [225] -> [229] */
	0x02,	0x01,	0x01,	0x01,	0x01,	/* [230] -> [234] */
	0x01,	0x01,	0x01,	0x01,	0x01,	/* [235] -> [239] */
	0x01,	0x01,	0x01,	0x00,	0x00,	/* [240] -> [244] */
	0x00,	0x00,	0x00,	0x00,	0x00,	/* [245] -> [249] */
	0x00,	0x00,	0x00,	0x00,	0x00,	/* [250] -> [254] */
	0x00					/* [255] */
};

/*
 * STREAMS Structures
 */

/*
 * DDI Structures
 */

/* Device operations structure */
static struct dev_ops audiocs_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	NULL,				/* devo_getinfo */
	nulldev,			/* devo_identify - obsolete */
	nulldev,			/* devo_probe - not needed */
	audiocs_ddi_attach,		/* devo_attach */
	audiocs_ddi_detach,		/* devo_detach */
	nodev,				/* devo_reset */
	NULL,				/* devi_cb_ops */
	NULL,				/* devo_bus_ops */
	audiocs_ddi_power,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/* Linkage structure for loadable drivers */
static struct modldrv audiocs_modldrv = {
	&mod_driverops,		/* drv_modops */
	CS4231_MOD_NAME,	/* drv_linkinfo */
	&audiocs_dev_ops	/* drv_dev_ops */
};

/* Module linkage structure */
static struct modlinkage audiocs_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&audiocs_modldrv,	/* ml_linkage */
	NULL				/* NULL terminates the list */
};


/* *******  Loadable Module Configuration Entry Points  ********************* */

/*
 * _init()
 *
 * Description:
 *	Implements _init(9E).
 *
 * Returns:
 *	mod_install() status, see mod_install(9f)
 */
int
_init(void)
{
	int	rv;

	audio_init_ops(&audiocs_dev_ops, CS4231_NAME);

	if ((rv = mod_install(&audiocs_modlinkage)) != 0) {
		audio_fini_ops(&audiocs_dev_ops);
	}

	return (rv);
}

/*
 * _fini()
 *
 * Description:
 *	Implements _fini(9E).
 *
 * Returns:
 *	mod_remove() status, see mod_remove(9f)
 */
int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&audiocs_modlinkage)) == 0) {
		audio_fini_ops(&audiocs_dev_ops);
	}

	return (rv);
}

/*
 * _info()
 *
 * Description:
 *	Implements _info(9E).
 *
 * Arguments:
 *	modinfo *modinfop	Pointer to the opaque modinfo structure
 *
 * Returns:
 *	mod_info() status, see mod_info(9f)
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&audiocs_modlinkage, modinfop));
}


/* *******  Driver Entry Points  ******************************************** */

/*
 * audiocs_ddi_attach()
 *
 * Description:
 *	Implement attach(9e).
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *	ddi_attach_cmd_t cmd	Attach command
 *
 * Returns:
 *	DDI_SUCCESS		The driver was initialized properly
 *	DDI_FAILURE		The driver couldn't be initialized properly
 */
static int
audiocs_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (audiocs_attach(dip));

	case DDI_RESUME:
		return (audiocs_resume(dip));

	default:
		return (DDI_FAILURE);
	}
}

/*
 * audiocs_ddi_detach()
 *
 * Description:
 *	Implement detach(9e).
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *	ddi_detach_cmd_t cmd	Detach command
 *
 * Returns:
 *	DDI_SUCCESS		Success.
 *	DDI_FAILURE		Failure.
 */
static int
audiocs_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (audiocs_detach(dip));

	case DDI_SUSPEND:
		return (audiocs_suspend(dip));

	default:
		return (DDI_FAILURE);
	}
}

/*
 * audiocs_ddi_power()
 *
 * Description:
 *	Implements power(9E).
 *
 * Arguments:
 *	def_info_t	*dip		Ptr to the device's dev_info structure
 *	int		component	Which component to power up/down
 *	int		level		The power level for the component
 *
 * Returns:
 *	DDI_SUCCESS		Power level changed, we always succeed
 */
static int
audiocs_ddi_power(dev_info_t *dip, int component, int level)
{
	CS_state_t		*state;

	if (component != CS4231_COMPONENT)
		return (DDI_FAILURE);

	/* get the state structure */
	state = ddi_get_driver_private(dip);

	ASSERT(!mutex_owned(&state->cs_lock));

	/* make sure we have some work to do */
	mutex_enter(&state->cs_lock);

	/*
	 * We don't do anything if we're suspended.  Suspend/resume diddles
	 * with power anyway.
	 */
	if (!state->cs_suspended) {

		/* check the level change to see what we need to do */
		if (level == CS4231_PWR_OFF && state->cs_powered) {

			/* power down and save the state */
			audiocs_power_down(state);
			state->cs_powered = B_FALSE;

		} else if (level == CS4231_PWR_ON && !state->cs_powered) {

			/* power up */
			audiocs_power_up(state);
			state->cs_powered = B_TRUE;
		}
	}

	mutex_exit(&state->cs_lock);

	ASSERT(!mutex_owned(&state->cs_lock));

	return (DDI_SUCCESS);
}

/* ******* Local Routines *************************************************** */

static void
audiocs_destroy(CS_state_t *state)
{
	if (state == NULL)
		return;

	for (int i = CS4231_PLAY; i <= CS4231_REC; i++) {
		audiocs_free_engine(state->cs_engines[i]);
	}
	audiocs_del_controls(state);

	if (state->cs_adev) {
		audio_dev_free(state->cs_adev);
	}

	/* unmap the registers */
	CS4231_DMA_UNMAP_REGS(state);

	/* destroy the state mutex */
	mutex_destroy(&state->cs_lock);
	kmem_free(state, sizeof (*state));
}

/*
 * audiocs_attach()
 *
 * Description:
 *	Attach an instance of the CS4231 driver. This routine does the device
 *	dependent attach tasks.  When it is complete it calls
 *	audio_dev_register() to register with the framework.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS		The driver was initialized properly
 *	DDI_FAILURE		The driver couldn't be initialized properly
 */
static int
audiocs_attach(dev_info_t *dip)
{
	CS_state_t		*state;
	audio_dev_t		*adev;

	/* allocate the state structure */
	state = kmem_zalloc(sizeof (*state), KM_SLEEP);
	state->cs_dip = dip;
	ddi_set_driver_private(dip, state);

	/* now fill it in, initialize the state mutexs first */
	mutex_init(&state->cs_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * audio state initialization... should always succeed,
	 * framework will message failure.
	 */
	if ((state->cs_adev = audio_dev_alloc(dip, 0)) == NULL) {
		goto error;
	}
	adev = state->cs_adev;
	audio_dev_set_description(adev, CS_DEV_CONFIG_ONBRD1);
	audio_dev_add_info(adev, "Legacy codec: Crystal Semiconductor CS4231");

	/* initialize the audio state structures */
	if ((audiocs_init_state(state)) == DDI_FAILURE) {
		audio_dev_warn(adev, "init_state() failed");
		goto error;
	}

	mutex_enter(&state->cs_lock);

	/* initialize the audio chip */
	if ((audiocs_chip_init(state)) == DDI_FAILURE) {
		mutex_exit(&state->cs_lock);
		audio_dev_warn(adev, "chip_init() failed");
		goto error;
	}
	/* chip init will have powered us up */
	state->cs_powered = B_TRUE;

	mutex_exit(&state->cs_lock);

	/* finally register with framework to kick everything off */
	if (audio_dev_register(state->cs_adev) != DDI_SUCCESS) {
		audio_dev_warn(state->cs_adev, "unable to register audio dev");
	}

	/* everything worked out, so report the device */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error:
	audiocs_destroy(state);
	return (DDI_FAILURE);
}

/*
 * audiocs_resume()
 *
 * Description:
 *	Resume a suspended device instance.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS		The driver was initialized properly
 *	DDI_FAILURE		The driver couldn't be initialized properly
 */
static int
audiocs_resume(dev_info_t *dip)
{
	CS_state_t		*state;
	audio_dev_t		*adev;

	/* we've already allocated the state structure so get ptr */
	state = ddi_get_driver_private(dip);
	adev = state->cs_adev;

	ASSERT(dip == state->cs_dip);
	ASSERT(!mutex_owned(&state->cs_lock));

	/* mark the Codec busy -- this should keep power(9e) away */
	(void) pm_busy_component(state->cs_dip, CS4231_COMPONENT);

	/* power it up */
	audiocs_power_up(state);
	state->cs_powered = B_TRUE;

	mutex_enter(&state->cs_lock);

	/* initialize the audio chip */
	if ((audiocs_chip_init(state)) == DDI_FAILURE) {
		mutex_exit(&state->cs_lock);
		audio_dev_warn(adev, "chip_init() failed");
		(void) pm_idle_component(state->cs_dip, CS4231_COMPONENT);
		return (DDI_FAILURE);
	}

	state->cs_suspended = B_FALSE;

	mutex_exit(&state->cs_lock);

	/*
	 * We have already powered up the chip, but this alerts the
	 * framework to the fact.
	 */
	(void) pm_raise_power(dip, CS4231_COMPONENT, CS4231_PWR_ON);
	(void) pm_idle_component(state->cs_dip, CS4231_COMPONENT);

	audio_dev_resume(state->cs_adev);

	return (DDI_SUCCESS);
}

/*
 * audiocs_detach()
 *
 * Description:
 *	Detach an instance of the CS4231 driver.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS		The driver was detached
 *	DDI_FAILURE		The driver couldn't be detached (busy)
 */
static int
audiocs_detach(dev_info_t *dip)
{
	CS_state_t		*state;
	audio_dev_t		*adev;
	ddi_acc_handle_t	handle;

	/* get the state structure */
	state = ddi_get_driver_private(dip);
	handle = CODEC_HANDLE;
	adev = state->cs_adev;

	/* don't detach if still in use */
	if (audio_dev_unregister(adev) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (state->cs_powered) {
		/*
		 * Make sure the Codec and DMA engine are off.
		 */
		SELIDX(state, INTC_REG);
		ANDIDX(state, ~(INTC_PEN|INTC_CEN), INTC_VALID_MASK);

		/* make sure the DMA engine isn't going to do anything */
		CS4231_DMA_RESET(state);

		/*
		 * power down the device, no reason to waste power without
		 * a driver
		 */
		(void) pm_lower_power(dip, CS4231_COMPONENT, CS4231_PWR_OFF);
	}

	audiocs_destroy(state);

	return (DDI_SUCCESS);
}

/*
 * audiocs_suspend()
 *
 * Description:
 *	Suspend an instance of the CS4231 driver.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS		The driver was detached
 *	DDI_FAILURE		The driver couldn't be detached
 */
static int
audiocs_suspend(dev_info_t *dip)
{
	CS_state_t		*state;

	/* get the state structure */
	state = ddi_get_driver_private(dip);

	mutex_enter(&state->cs_lock);

	ASSERT(!state->cs_suspended);

	audio_dev_suspend(state->cs_adev);

	if (state->cs_powered) {
		/* now we can power down the Codec */
		audiocs_power_down(state);
		state->cs_powered = B_FALSE;
	}
	state->cs_suspended = B_TRUE;	/* stop new ops */
	mutex_exit(&state->cs_lock);

	return (DDI_SUCCESS);
}

#define	PLAYCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_PLAY)
#define	RECCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_REC)
#define	MONCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_MONITOR)
#define	PCMVOL	(PLAYCTL | AUDIO_CTRL_FLAG_PCMVOL)
#define	MAINVOL	(PLAYCTL | AUDIO_CTRL_FLAG_MAINVOL)
#define	RECVOL	(RECCTL | AUDIO_CTRL_FLAG_RECVOL)
#define	MONVOL	(MONCTL | AUDIO_CTRL_FLAG_MONVOL)

/*
 * audiocs_alloc_ctrl
 *
 * Description:
 *	Allocates a control structure for the audio mixer.
 *
 * Arguments:
 *	CS_state_t	*state		Device soft state.
 *	uint32_t	num		Control number to allocate.
 *	uint64_t	val		Initial value.
 *
 * Returns:
 *	Pointer to newly allocated CS_ctrl_t structure.
 */
static CS_ctrl_t *
audiocs_alloc_ctrl(CS_state_t *state, uint32_t num, uint64_t val)
{
	audio_ctrl_desc_t	desc;
	audio_ctrl_wr_t		fn;
	CS_ctrl_t		*cc;

	cc = kmem_zalloc(sizeof (*cc), KM_SLEEP);
	cc->cc_state = state;
	cc->cc_num = num;

	bzero(&desc, sizeof (desc));

	switch (num) {
	case CTL_VOLUME:
		desc.acd_name = AUDIO_CTRL_ID_VOLUME;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		fn = audiocs_set_ogain;
		break;

	case CTL_IGAIN:
		desc.acd_name = AUDIO_CTRL_ID_RECGAIN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = audiocs_set_igain;
		break;

	case CTL_MGAIN:
		desc.acd_name = AUDIO_CTRL_ID_MONGAIN;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MONVOL;
		fn = audiocs_set_mgain;
		break;

	case CTL_INPUTS:
		desc.acd_name = AUDIO_CTRL_ID_RECSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_minvalue = state->cs_imask;
		desc.acd_maxvalue = state->cs_imask;
		desc.acd_flags = RECCTL;
		for (int i = 0; audiocs_inputs[i]; i++) {
			desc.acd_enum[i] = audiocs_inputs[i];
		}
		fn = audiocs_set_inputs;

		break;

	case CTL_OUTPUTS:
		desc.acd_name = AUDIO_CTRL_ID_OUTPUTS;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_minvalue = state->cs_omod;
		desc.acd_maxvalue = state->cs_omask;
		desc.acd_flags = PLAYCTL | AUDIO_CTRL_FLAG_MULTI;
		for (int i = 0; audiocs_outputs[i]; i++) {
			desc.acd_enum[i] = audiocs_outputs[i];
		}
		fn = audiocs_set_outputs;
		break;

	case CTL_MICBOOST:
		desc.acd_name = AUDIO_CTRL_ID_MICBOOST;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 1;
		desc.acd_flags = RECCTL;
		fn = audiocs_set_micboost;
		break;
	}

	cc->cc_val = val;
	cc->cc_ctrl = audio_dev_add_control(state->cs_adev, &desc,
	    audiocs_get_value, fn, cc);

	return (cc);
}

/*
 * audiocs_free_ctrl
 *
 * Description:
 *	Frees a control and all resources associated with it.
 *
 * Arguments:
 *	CS_ctrl_t	*cc	Pointer to control structure.
 */
static void
audiocs_free_ctrl(CS_ctrl_t *cc)
{
	if (cc == NULL)
		return;
	if (cc->cc_ctrl)
		audio_dev_del_control(cc->cc_ctrl);
	kmem_free(cc, sizeof (*cc));
}

/*
 * audiocs_add_controls
 *
 * Description:
 *	Allocates and registers all controls for this device.
 *
 * Arguments:
 *	CS_state_t	*state		Device soft state.
 *
 * Returns:
 *	DDI_SUCCESS	All controls added and registered
 *	DDI_FAILURE	At least one control was not added or registered.
 */
static int
audiocs_add_controls(CS_state_t *state)
{
#define	ADD_CTRL(CTL, ID, VAL)						\
	state->cs_##CTL = audiocs_alloc_ctrl(state, ID, VAL);		\
	if (state->cs_##CTL == NULL) {					\
		audio_dev_warn(state->cs_adev,				\
		    "unable to allocate %s control", #ID);		\
		return (DDI_FAILURE);					\
	}

	ADD_CTRL(ogain, CTL_VOLUME, 0x4b4b);
	ADD_CTRL(igain, CTL_IGAIN, 0x3232);
	ADD_CTRL(mgain, CTL_MGAIN, 0);
	ADD_CTRL(micboost, CTL_MICBOOST, 0);
	ADD_CTRL(outputs, CTL_OUTPUTS, (state->cs_omask & ~state->cs_omod) |
	    (1U << OUTPUT_SPEAKER));
	ADD_CTRL(inputs, CTL_INPUTS, (1U << INPUT_MIC));

	return (DDI_SUCCESS);
}

/*
 * audiocs_del_controls
 *
 * Description:
 *	Unregisters and frees all controls for this device.
 *
 * Arguments:
 *	CS_state_t	*state		Device soft state.
 */
void
audiocs_del_controls(CS_state_t *state)
{
	audiocs_free_ctrl(state->cs_ogain);
	audiocs_free_ctrl(state->cs_igain);
	audiocs_free_ctrl(state->cs_mgain);
	audiocs_free_ctrl(state->cs_micboost);
	audiocs_free_ctrl(state->cs_inputs);
	audiocs_free_ctrl(state->cs_outputs);
}


/*
 * audiocs_chip_init()
 *
 * Description:
 *	Power up the audio core, initialize the audio Codec, prepare the chip
 *	for use.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *
 * Returns:
 *	DDI_SUCCESS			Chip initialized and ready to use
 *	DDI_FAILURE			Chip not initialized and not ready
 */
static int
audiocs_chip_init(CS_state_t *state)
{
	ddi_acc_handle_t	handle = CODEC_HANDLE;

	/* make sure we are powered up */
	CS4231_DMA_POWER(state, CS4231_PWR_ON);

	CS4231_DMA_RESET(state);

	/* wait for the Codec before we continue */
	if (audiocs_poll_ready(state) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	/* activate registers 16 -> 31 */
	SELIDX(state, MID_REG);
	ddi_put8(handle, &CS4231_IDR, MID_MODE2);

	/* now figure out what version we have */
	SELIDX(state, VID_REG);
	if (ddi_get8(handle, &CS4231_IDR) & VID_A) {
		state->cs_revA = B_TRUE;
	} else {
		state->cs_revA = B_FALSE;
	}

	/* get rid of annoying popping by muting the output channels */
	SELIDX(state, LDACO_REG);
	PUTIDX(state, LDACO_LDM | LDACO_MID_GAIN, LDAC0_VALID_MASK);
	SELIDX(state, RDACO_REG);
	PUTIDX(state, RDACO_RDM | RDACO_MID_GAIN, RDAC0_VALID_MASK);

	/* initialize aux input channels to known gain values & muted */
	SELIDX(state, LAUX1_REG);
	PUTIDX(state, LAUX1_LX1M | LAUX1_UNITY_GAIN, LAUX1_VALID_MASK);
	SELIDX(state, RAUX1_REG);
	PUTIDX(state, RAUX1_RX1M | RAUX1_UNITY_GAIN, RAUX1_VALID_MASK);
	SELIDX(state, LAUX2_REG);
	PUTIDX(state, LAUX2_LX2M | LAUX2_UNITY_GAIN, LAUX2_VALID_MASK);
	SELIDX(state, RAUX2_REG);
	PUTIDX(state, RAUX2_RX2M | RAUX2_UNITY_GAIN, RAUX2_VALID_MASK);

	/* initialize aux input channels to known gain values & muted */
	SELIDX(state, LLIC_REG);
	PUTIDX(state, LLIC_LLM | LLIC_UNITY_GAIN, LLIC_VALID_MASK);
	SELIDX(state, RLIC_REG);
	PUTIDX(state, RLIC_RLM | RLIC_UNITY_GAIN, RLIC_VALID_MASK);

	/* program the sample rate, play and capture must be the same */
	SELIDX(state, FSDF_REG | IAR_MCE);
	PUTIDX(state, FS_48000 | PDF_LINEAR16NE | PDF_STEREO, FSDF_VALID_MASK);
	if (audiocs_poll_ready(state) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	SELIDX(state, CDF_REG | IAR_MCE);
	PUTIDX(state, CDF_LINEAR16NE | CDF_STEREO, CDF_VALID_MASK);
	if (audiocs_poll_ready(state) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	/*
	 * Set up the Codec for playback and capture disabled, dual DMA, and
	 * playback and capture DMA.
	 */
	SELIDX(state, (INTC_REG | IAR_MCE));
	PUTIDX(state, INTC_DDC | INTC_PDMA | INTC_CDMA, INTC_VALID_MASK);
	if (audiocs_poll_ready(state) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	/*
	 * Turn on the output level bit to be 2.8 Vpp. Also, don't go to 0 on
	 * underflow.
	 */
	SELIDX(state, AFE1_REG);
	PUTIDX(state, AFE1_OLB, AFE1_VALID_MASK);

	/* turn on the high pass filter if Rev A */
	SELIDX(state, AFE2_REG);
	if (state->cs_revA) {
		PUTIDX(state, AFE2_HPF, AFE2_VALID_MASK);
	} else {
		PUTIDX(state, 0, AFE2_VALID_MASK);
	}


	/* clear the play and capture interrupt flags */
	SELIDX(state, AFS_REG);
	ddi_put8(handle, &CS4231_STATUS, (AFS_RESET_STATUS));

	/* the play and record gains will be set by the audio mixer */

	/* unmute the output */
	SELIDX(state, LDACO_REG);
	ANDIDX(state, ~LDACO_LDM, LDAC0_VALID_MASK);
	SELIDX(state, RDACO_REG);
	ANDIDX(state, ~RDACO_RDM, RDAC0_VALID_MASK);

	/* unmute the mono speaker and mute mono in */
	SELIDX(state, MIOC_REG);
	PUTIDX(state, MIOC_MIM, MIOC_VALID_MASK);

	audiocs_configure_output(state);
	audiocs_configure_input(state);

	return (DDI_SUCCESS);
}

/*
 * audiocs_init_state()
 *
 * Description:
 *	This routine initializes the audio driver's state structure and
 *	maps in the registers. This also includes reading the properties.
 *
 *	CAUTION: This routine maps the registers and initializes a mutex.
 *		 Failure cleanup is handled by cs4231_attach(). It is not
 *		 handled locally by this routine.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *
 * Returns:
 *	DDI_SUCCESS			State structure initialized
 *	DDI_FAILURE			State structure not initialized
 */
static int
audiocs_init_state(CS_state_t *state)
{
	audio_dev_t	*adev = state->cs_adev;
	dev_info_t	*dip = state->cs_dip;
	char		*prop_str;
	char		*pm_comp[] = {
				"NAME=audiocs audio device",
				"0=off",
				"1=on" };

	/* set up the pm-components */
	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "pm-components", pm_comp, 3) != DDI_PROP_SUCCESS) {
		audio_dev_warn(adev, "couldn't create pm-components property");
		return (DDI_FAILURE);
	}

	/* figure out which DMA engine hardware we have */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "dma-model", &prop_str) == DDI_PROP_SUCCESS) {
		if (strcmp(prop_str, "eb2dma") == 0) {
			state->cs_dma_engine = EB2_DMA;
			state->cs_dma_ops = &cs4231_eb2dma_ops;
		} else {
			state->cs_dma_engine = APC_DMA;
			state->cs_dma_ops = &cs4231_apcdma_ops;
		}
		ddi_prop_free(prop_str);
	} else {
		state->cs_dma_engine = APC_DMA;
		state->cs_dma_ops = &cs4231_apcdma_ops;
	}

	/* cs_regs, cs_eb2_regs and cs_handles filled in later */

	/* most of what's left is filled in when the registers are mapped */

	audiocs_get_ports(state);

	/* Allocate engines, must be done before register mapping called  */
	if ((audiocs_alloc_engine(state, CS4231_PLAY) != DDI_SUCCESS) ||
	    (audiocs_alloc_engine(state, CS4231_REC) != DDI_SUCCESS)) {
		return (DDI_FAILURE);
	}

	/* Map in the registers */
	if (CS4231_DMA_MAP_REGS(state) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}


	/* Allocate and add controls, must be done *after* registers mapped */
	if (audiocs_add_controls(state) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	state->cs_suspended = B_FALSE;
	state->cs_powered = B_FALSE;

	return (DDI_SUCCESS);
}

/*
 * audiocs_get_ports()
 *
 * Description:
 *	Get which audiocs h/w version we have and use this to
 *	determine the input and output ports as well whether or not
 *	the hardware has internal loopbacks or not. We also have three
 *	different ways for the properties to be specified, which we
 *	also need to worry about.
 *
 * Vers	Platform(s)	DMA eng.	audio-module**	loopback
 * a    SS-4+/SS-5+	apcdma		no		no
 * b	Ultra-1&2	apcdma		no		yes
 * c	positron	apcdma		no		yes
 * d	PPC - retired
 * e	x86 - retired
 * f	tazmo		eb2dma		Perigee		no
 * g	tazmo		eb2dma		Quark		yes
 * h	darwin+		eb2dma		no		N/A
 *
 * Vers	model~		aux1*		aux2*
 * a	N/A		N/A		N/A
 * b	N/A		N/A		N/A
 * c	N/A		N/A		N/A
 * d	retired
 * e	retired
 * f	SUNW,CS4231f	N/A		N/A
 * g	SUNW,CS4231g	N/A		N/A
 * h	SUNW,CS4231h	cdrom		none
 *
 * *   = Replaces internal-loopback for latest property type, can be
 *	 set to "cdrom", "loopback", or "none".
 *
 * **  = For plugin audio modules only. Starting with darwin, this
 *	 property is replaces by the model property.
 *
 * ~   = Replaces audio-module.
 *
 * +   = Has the capability of having a cable run from the internal
 *	 CD-ROM to the audio device.
 *
 * N/A = Not applicable, the property wasn't created for early
 *	 platforms, or the property has been retired.
 *
 * NOTE: Older tazmo and quark machines don't have the model property.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 */
static void
audiocs_get_ports(CS_state_t *state)
{
	dev_info_t	*dip = state->cs_dip;
	audio_dev_t	*adev = state->cs_adev;
	char		*prop_str;

	/* First we set the common ports, etc. */
	state->cs_omask = state->cs_omod =
	    (1U << OUTPUT_SPEAKER) |
	    (1U << OUTPUT_HEADPHONES) |
	    (1U << OUTPUT_LINEOUT);
	state->cs_imask =
	    (1U << INPUT_MIC) |
	    (1U << INPUT_LINEIN) |
	    (1U << INPUT_STEREOMIX);

	/* now we try the new "model" property */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "model", &prop_str) == DDI_PROP_SUCCESS) {
		if (strcmp(prop_str, "SUNW,CS4231h") == 0) {
			/* darwin */
			audio_dev_set_version(adev, CS_DEV_VERSION_H);
			state->cs_imask |= (1U << INPUT_CD);
			state->cs_omod = (1U << OUTPUT_SPEAKER);
		} else if (strcmp(prop_str, "SUNW,CS4231g") == 0) {
			/* quark audio module */
			audio_dev_set_version(adev, CS_DEV_VERSION_G);
			/*
			 * NB: This could do SUNVTS LOOPBACK, but we
			 * don't support it for now... owing to no
			 * support in framework.
			 */
		} else if (strcmp(prop_str, "SUNW,CS4231f") == 0) {
			/* tazmo */
			audio_dev_set_version(adev, CS_DEV_VERSION_F);
		} else {
			audio_dev_set_version(adev, prop_str);
			audio_dev_warn(adev,
			    "unknown audio model: %s, some parts of "
			    "audio may not work correctly", prop_str);
		}
		ddi_prop_free(prop_str);	/* done with the property */
	} else {	/* now try the older "audio-module" property */
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "audio-module", &prop_str) ==
		    DDI_PROP_SUCCESS) {
			switch (*prop_str) {
			case 'Q':	/* quark audio module */
				audio_dev_set_version(adev, CS_DEV_VERSION_G);
				/* See quark comment above about SunVTS */
				break;
			case 'P':	/* tazmo */
				audio_dev_set_version(adev, CS_DEV_VERSION_F);
				break;
			default:
				audio_dev_set_version(adev, prop_str);
				audio_dev_warn(adev,
				    "unknown audio module: %s, some "
				    "parts of audio may not work correctly",
				    prop_str);
				break;
			}
			ddi_prop_free(prop_str);	/* done with the prop */
		} else {	/* now try heuristics, ;-( */
			if (ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "internal-loopback", B_FALSE)) {
				if (state->cs_dma_engine == EB2_DMA) {
					audio_dev_set_version(adev,
					    CS_DEV_VERSION_C);
				} else {
					audio_dev_set_version(adev,
					    CS_DEV_VERSION_B);
				}
				/*
				 * Again, we don't support SunVTS for these
				 * boards, although we potentially could.
				 */
			} else {
				audio_dev_set_version(adev, CS_DEV_VERSION_A);
				state->cs_imask |= (1U << INPUT_CD);
			}
		}
	}
}

/*
 * audiocs_power_up()
 *
 * Description:
 *	Power up the Codec and restore the codec's registers.
 *
 *	NOTE: We don't worry about locking since the only routines
 *		that may call us are attach() and power() Both of
 *		which should be the only threads in the driver.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 */
static void
audiocs_power_up(CS_state_t *state)
{
	ddi_acc_handle_t	handle = CODEC_HANDLE;
	int			i;

	/* turn on the Codec */
	CS4231_DMA_POWER(state, CS4231_PWR_ON);

	/* reset the DMA engine(s) */
	CS4231_DMA_RESET(state);

	(void) audiocs_poll_ready(state);

	/*
	 * Reload the Codec's registers, the DMA engines will be
	 * taken care of when play and record start up again. But
	 * first enable registers 16 -> 31.
	 */
	SELIDX(state, MID_REG);
	PUTIDX(state, state->cs_save[MID_REG], MID_VALID_MASK);

	for (i = 0; i < CS4231_REGS; i++) {
		/* restore Codec registers */
		SELIDX(state, (i | IAR_MCE));
		ddi_put8(handle, &CS4231_IDR, state->cs_save[i]);
		(void) audiocs_poll_ready(state);
	}
	/* clear MCE bit */
	SELIDX(state, 0);
}

/*
 * audiocs_power_down()
 *
 * Description:
 *	Power down the Codec and save the codec's registers.
 *
 *	NOTE: See the note in cs4231_power_up() about locking.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 */
static void
audiocs_power_down(CS_state_t *state)
{
	ddi_acc_handle_t	handle;
	int			i;

	handle = state->cs_handles.cs_codec_hndl;

	/*
	 * We are powering down, so we don't need to do a thing with
	 * the DMA engines. However, we do need to save the Codec
	 * registers.
	 */

	for (i = 0; i < CS4231_REGS; i++) {
		/* save Codec regs */
		SELIDX(state, i);
		state->cs_save[i] = ddi_get8(handle, &CS4231_IDR);
	}

	/* turn off the Codec */
	CS4231_DMA_POWER(state, CS4231_PWR_OFF);

}	/* cs4231_power_down() */

/*
 * audiocs_configure_input()
 *
 * Description:
 *	Configure input properties of the mixer (e.g. igain, ports).
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 */
static void
audiocs_configure_input(CS_state_t *state)
{
	uint8_t		l, r;
	uint64_t	inputs;
	uint64_t	micboost;

	ASSERT(mutex_owned(&state->cs_lock));

	inputs = state->cs_inputs->cc_val;
	micboost = state->cs_micboost->cc_val;
	r = (state->cs_igain->cc_val & 0xff);
	l = ((state->cs_igain->cc_val & 0xff00) >> 8);

	/* rescale these for our atten array */
	l = (((uint32_t)l * 255) / 100) & 0xff;
	r = (((uint32_t)r * 255) / 100) & 0xff;

	/* we downshift by 4 bits -- igain only has 16 possible values */
	/* NB: that we do not scale here!  The SADA driver didn't do so. */
	l = l >> 4;
	r = r >> 4;

	if (inputs & (1U << INPUT_MIC)) {
		l |= LADCI_LMIC;
		r |= RADCI_RMIC;
	}
	if (inputs & (1U << INPUT_LINEIN)) {
		l |= LADCI_LLINE;
		r |= RADCI_RLINE;
	}
	if (inputs & (1U << INPUT_CD)) {
		/* note that SunVTS also uses this */
		l |= LADCI_LAUX1;
		r |= RADCI_RAUX1;
	}
	if (inputs & (1U << INPUT_STEREOMIX)) {
		l |= LADCI_LLOOP;
		r |= RADCI_RLOOP;
	}
	if (micboost) {
		l |= LADCI_LMGE;
		r |= RADCI_RMGE;
	}

	SELIDX(state, LADCI_REG);
	PUTIDX(state, l, LADCI_VALID_MASK);

	SELIDX(state, RADCI_REG);
	PUTIDX(state, r, RADCI_VALID_MASK);
}

/*
 * audiocs_configure_output()
 *
 * Description:
 *	Configure output properties of the mixer (e.g. ogain, mgain).
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 */
static void
audiocs_configure_output(CS_state_t *state)
{
	uint64_t		outputs;
	uint8_t			l, r;
	uint8_t			rmute, lmute;
	uint8_t			mgain;
	ddi_acc_handle_t	handle = CODEC_HANDLE;

	rmute = lmute = 0;

	ASSERT(mutex_owned(&state->cs_lock));

	outputs = state->cs_outputs->cc_val;

	/* port selection */
	SELIDX(state, MIOC_REG);
	if (outputs & (1U << OUTPUT_SPEAKER)) {
		ANDIDX(state, ~MIOC_MONO_SPKR_MUTE, MIOC_VALID_MASK);
	} else {
		ORIDX(state, MIOC_MONO_SPKR_MUTE, MIOC_VALID_MASK);
	}
	SELIDX(state, PC_REG);
	if (outputs & (1U << OUTPUT_HEADPHONES)) {
		ANDIDX(state, ~PC_HEADPHONE_MUTE, PC_VALID_MASK);
	} else {
		ORIDX(state, PC_HEADPHONE_MUTE, PC_VALID_MASK);
	}
	SELIDX(state, PC_REG);
	if (outputs & (1U << OUTPUT_LINEOUT)) {
		ANDIDX(state, ~PC_LINE_OUT_MUTE, PC_VALID_MASK);
	} else {
		ORIDX(state, PC_LINE_OUT_MUTE, PC_VALID_MASK);
	}

	/* monitor gain */
	mgain = cs4231_atten[((state->cs_mgain->cc_val * 255) / 100) & 0xff];
	SELIDX(state, LC_REG);
	if (mgain == 0) {
		/* disable loopbacks when gain == 0 */
		PUTIDX(state, LC_OFF, LC_VALID_MASK);
	} else {
		/* we use cs4231_atten[] to linearize attenuation */
		PUTIDX(state, (mgain << 2) | LC_LBE, LC_VALID_MASK);
	}

	/* output gain */
	l = ((state->cs_ogain->cc_val >> 8) & 0xff);
	r = (state->cs_ogain->cc_val & 0xff);
	if (l == 0) {
		lmute = LDACO_LDM;
	}
	if (r == 0) {
		rmute = RDACO_RDM;
	}

	/* rescale these for our atten array */
	l = cs4231_atten[(((uint32_t)l * 255) / 100) & 0xff] | lmute;
	r = cs4231_atten[(((uint32_t)r * 255) / 100) & 0xff] | rmute;

	SELIDX(state, LDACO_REG);
	PUTIDX(state, l, LDAC0_VALID_MASK);
	SELIDX(state, RDACO_REG);
	PUTIDX(state, r, RDAC0_VALID_MASK);
}

/*
 * audiocs_get_value()
 *
 * Description:
 *	Get a control value
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint64_t	*valp		Pointer to store value.
 *
 * Returns:
 *	0		The Codec parameter has been retrieved.
 */
static int
audiocs_get_value(void *arg, uint64_t *valp)
{
	CS_ctrl_t		*cc = arg;
	CS_state_t		*state = cc->cc_state;

	mutex_enter(&state->cs_lock);
	*valp = cc->cc_val;
	mutex_exit(&state->cs_lock);
	return (0);
}


/*
 * audiocs_set_ogain()
 *
 * Description:
 *	Set the play gain.
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint64_t	val		The gain to set (both left and right)
 *
 * Returns:
 *	0		The Codec parameter has been set
 */
static int
audiocs_set_ogain(void *arg, uint64_t val)
{
	CS_ctrl_t		*cc = arg;
	CS_state_t		*state = cc->cc_state;

	if ((val & ~0xffff) ||
	    ((val & 0xff) > 100) ||
	    (((val & 0xff00) >> 8) > 100))
		return (EINVAL);

	mutex_enter(&state->cs_lock);
	cc->cc_val = val;
	audiocs_configure_output(state);
	mutex_exit(&state->cs_lock);
	return (0);
}

/*
 * audiocs_set_micboost()
 *
 * Description:
 *	Set the 20 dB microphone boost.
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint64_t	val		The 1 to enable, 0 to disable.
 *
 * Returns:
 *	0		The Codec parameter has been set
 */
static int
audiocs_set_micboost(void *arg, uint64_t val)
{
	CS_ctrl_t	*cc = arg;
	CS_state_t	*state = cc->cc_state;

	mutex_enter(&state->cs_lock);
	cc->cc_val = val ? B_TRUE : B_FALSE;
	audiocs_configure_input(state);
	mutex_exit(&state->cs_lock);
	return (0);
}

/*
 * audiocs_set_igain()
 *
 * Description:
 *	Set the record gain.
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint64_t	val		The gain to set (both left and right)
 *
 * Returns:
 *	0		The Codec parameter has been set
 */
static int
audiocs_set_igain(void *arg, uint64_t val)
{
	CS_ctrl_t	*cc = arg;
	CS_state_t	*state = cc->cc_state;

	if ((val & ~0xffff) ||
	    ((val & 0xff) > 100) ||
	    (((val & 0xff00) >> 8) > 100))
		return (EINVAL);

	mutex_enter(&state->cs_lock);
	cc->cc_val = val;
	audiocs_configure_input(state);
	mutex_exit(&state->cs_lock);

	return (0);
}

/*
 * audiocs_set_inputs()
 *
 * Description:
 *	Set the input ports.
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint64_t	val		The mask of output ports.
 *
 * Returns:
 *	0		The Codec parameter has been set
 */
static int
audiocs_set_inputs(void *arg, uint64_t val)
{
	CS_ctrl_t	*cc = arg;
	CS_state_t	*state = cc->cc_state;

	if (val & ~(state->cs_imask))
		return (EINVAL);

	mutex_enter(&state->cs_lock);
	cc->cc_val = val;
	audiocs_configure_input(state);
	mutex_exit(&state->cs_lock);

	return (0);
}

/*
 * audiocs_set_outputs()
 *
 * Description:
 *	Set the output ports.
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint64_t	val		The mask of input ports.
 *
 * Returns:
 *	0		The Codec parameter has been set
 */
static int
audiocs_set_outputs(void *arg, uint64_t val)
{
	CS_ctrl_t	*cc = arg;
	CS_state_t	*state = cc->cc_state;

	if ((val & ~(state->cs_omod)) !=
	    (state->cs_omask & ~state->cs_omod))
		return (EINVAL);

	mutex_enter(&state->cs_lock);
	cc->cc_val = val;
	audiocs_configure_output(state);
	mutex_exit(&state->cs_lock);

	return (0);
}

/*
 * audiocs_set_mgain()
 *
 * Description:
 *	Set the monitor gain.
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint64_t	val		The gain to set (monoaural).)
 *
 * Returns:
 *	0		The Codec parameter has been set
 */
static int
audiocs_set_mgain(void *arg, uint64_t gain)
{
	CS_ctrl_t	*cc = arg;
	CS_state_t	*state = cc->cc_state;

	if (gain > 100)
		return (EINVAL);

	mutex_enter(&state->cs_lock);
	cc->cc_val = gain;
	audiocs_configure_output(state);
	mutex_exit(&state->cs_lock);

	return (0);
}

/*
 * audiocs_open()
 *
 * Description:
 *	Opens a DMA engine for use.
 *
 * Arguments:
 *	void		*arg		The DMA engine to set up
 *	int		flag		Open flags
 *	unsigned	*nframesp	Receives number of frames
 *	caddr_t		*bufp		Receives kernel data buffer
 *
 * Returns:
 *	0	on success
 *	errno	on failure
 */
static int
audiocs_open(void *arg, int flag, unsigned *nframesp, caddr_t *bufp)
{
	CS_engine_t	*eng = arg;
	CS_state_t	*state = eng->ce_state;
	dev_info_t	*dip = state->cs_dip;

	_NOTE(ARGUNUSED(flag));

	(void) pm_busy_component(dip, CS4231_COMPONENT);
	if (pm_raise_power(dip, CS4231_COMPONENT, CS4231_PWR_ON) ==
	    DDI_FAILURE) {

		/* match the busy call above */
		(void) pm_idle_component(dip, CS4231_COMPONENT);

		audio_dev_warn(state->cs_adev, "power up failed");
	}

	eng->ce_count = 0;
	*nframesp = CS4231_NFRAMES;
	*bufp = eng->ce_kaddr;

	return (0);
}

/*
 * audiocs_close()
 *
 * Description:
 *	Closes an audio DMA engine that was previously opened.  Since
 *	nobody is using it, we take this opportunity to possibly power
 *	down the entire device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to shut down
 */
static void
audiocs_close(void *arg)
{
	CS_engine_t	*eng = arg;
	CS_state_t	*state = eng->ce_state;

	(void) pm_idle_component(state->cs_dip, CS4231_COMPONENT);
}

/*
 * audiocs_stop()
 *
 * Description:
 *	This is called by the framework to stop an engine that is
 *	transferring data.
 *
 * Arguments:
 *	void	*arg		The DMA engine to stop
 */
static void
audiocs_stop(void *arg)
{
	CS_engine_t		*eng = arg;
	CS_state_t		*state = eng->ce_state;
	ddi_acc_handle_t	handle = CODEC_HANDLE;

	mutex_enter(&state->cs_lock);
	/*
	 * Stop the DMA engine.
	 */
	CS4231_DMA_STOP(state, eng);

	/*
	 * Stop the codec.
	 */
	SELIDX(state, INTC_REG);
	ANDIDX(state, ~(eng->ce_codec_en), INTC_VALID_MASK);
	mutex_exit(&state->cs_lock);
}

/*
 * audiocs_start()
 *
 * Description:
 *	This is called by the framework to start an engine transferring data.
 *
 * Arguments:
 *	void	*arg		The DMA engine to start
 *
 * Returns:
 *	0 	on success, an errno otherwise
 */
static int
audiocs_start(void *arg)
{
	CS_engine_t		*eng = arg;
	CS_state_t		*state = eng->ce_state;
	ddi_acc_handle_t	handle = CODEC_HANDLE;
	uint8_t			mask;
	uint8_t			value;
	uint8_t			reg;
	int			rv;

	mutex_enter(&state->cs_lock);

	if (eng->ce_num == CS4231_PLAY) {
		/* sample rate only set on play side */
		value = FS_48000 | PDF_STEREO | PDF_LINEAR16NE;
		reg = FSDF_REG;
		mask = FSDF_VALID_MASK;
	} else {
		value = CDF_STEREO | CDF_LINEAR16NE;
		reg = CDF_REG;
		mask = CDF_VALID_MASK;
	}
	eng->ce_curoff = 0;
	eng->ce_curidx = 0;

	SELIDX(state, reg | IAR_MCE);
	PUTIDX(state, value, mask);

	if (audiocs_poll_ready(state) != DDI_SUCCESS) {
		rv = EIO;
	} else if (CS4231_DMA_START(state, eng) != DDI_SUCCESS) {
		rv = EIO;
	} else {
		/*
		 * Start the codec.
		 */
		SELIDX(state, INTC_REG);
		ORIDX(state, eng->ce_codec_en, INTC_VALID_MASK);
		rv = 0;
	}

	mutex_exit(&state->cs_lock);
	return (rv);
}

/*
 * audiocs_format()
 *
 * Description:
 *	Called by the framework to query the format of the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	AUDIO_FORMAT_S16_NE
 */
static int
audiocs_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_NE);
}

/*
 * audiocs_channels()
 *
 * Description:
 *	Called by the framework to query the channels of the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	2 (stereo)
 */
static int
audiocs_channels(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (2);
}

/*
 * audiocs_rates()
 *
 * Description:
 *	Called by the framework to query the sample rate of the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	48000
 */
static int
audiocs_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (48000);
}

/*
 * audiocs_count()
 *
 * Description:
 *	This is called by the framework to get the engine's frame counter
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	frame count for current engine
 */
static uint64_t
audiocs_count(void *arg)
{
	CS_engine_t		*eng = arg;
	CS_state_t		*state = eng->ce_state;
	uint64_t		val;
	uint32_t		off;

	mutex_enter(&state->cs_lock);

	off = CS4231_DMA_ADDR(state, eng);
	ASSERT(off >= eng->ce_paddr);
	off -= eng->ce_paddr;

	/*
	 * Every now and then, we get a value that is just a wee bit
	 * too large.  This seems to be a small value related to
	 * prefetch.  Rather than believe it, we just assume the last
	 * offset in the buffer.  This should allow us to handle
	 * wraps, but without inserting bogus sample counts.
	 */
	if (off >= CS4231_BUFSZ) {
		off = CS4231_BUFSZ - 4;
	}

	off /= 4;

	val = (off >= eng->ce_curoff) ?
	    off - eng->ce_curoff :
	    off + CS4231_NFRAMES - eng->ce_curoff;

	eng->ce_count += val;
	eng->ce_curoff = off;
	val = eng->ce_count;

	/* while here, possibly reload the next address */
	CS4231_DMA_RELOAD(state, eng);
	mutex_exit(&state->cs_lock);

	return (val);
}

/*
 * audiocs_sync()
 *
 * Description:
 *	This is called by the framework to synchronize DMA caches.
 *
 * Arguments:
 *	void	*arg		The DMA engine to sync
 */
static void
audiocs_sync(void *arg, unsigned nframes)
{
	CS_engine_t *eng = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(eng->ce_dmah, 0, 0, eng->ce_syncdir);
}

/*
 * audiocs_alloc_engine()
 *
 * Description:
 *	Allocates the DMA handles and the memory for the DMA engine.
 *
 * Arguments:
 *	CS_state_t	*dip	Pointer to the device's soft state
 *	int		num	Engine number, CS4231_PLAY or CS4231_REC.
 *
 * Returns:
 *	DDI_SUCCESS		Engine initialized.
 *	DDI_FAILURE		Engine not initialized.
 */
int
audiocs_alloc_engine(CS_state_t *state, int num)
{
	unsigned		caps;
	int			dir;
	int			rc;
	audio_dev_t		*adev;
	dev_info_t		*dip;
	CS_engine_t		*eng;
	uint_t			ccnt;
	ddi_dma_cookie_t	dmac;
	size_t			bufsz;

	static ddi_device_acc_attr_t buf_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC
	};

	adev = state->cs_adev;
	dip = state->cs_dip;

	eng = kmem_zalloc(sizeof (*eng), KM_SLEEP);
	eng->ce_state = state;
	eng->ce_started = B_FALSE;
	eng->ce_num = num;

	switch (num) {
	case CS4231_REC:
		dir = DDI_DMA_READ;
		caps = ENGINE_INPUT_CAP;
		eng->ce_syncdir = DDI_DMA_SYNC_FORKERNEL;
		eng->ce_codec_en = INTC_CEN;
		break;
	case CS4231_PLAY:
		dir = DDI_DMA_WRITE;
		caps = ENGINE_OUTPUT_CAP;
		eng->ce_syncdir = DDI_DMA_SYNC_FORDEV;
		eng->ce_codec_en = INTC_PEN;
		break;
	default:
		kmem_free(eng, sizeof (*eng));
		audio_dev_warn(adev, "bad engine number (%d)!", num);
		return (DDI_FAILURE);
	}
	state->cs_engines[num] = eng;

	/* allocate dma handle */
	rc = ddi_dma_alloc_handle(dip, CS4231_DMA_ATTR(state), DDI_DMA_SLEEP,
	    NULL, &eng->ce_dmah);
	if (rc != DDI_SUCCESS) {
		audio_dev_warn(adev, "ddi_dma_alloc_handle failed: %d", rc);
		return (DDI_FAILURE);
	}
	/* allocate DMA buffer */
	rc = ddi_dma_mem_alloc(eng->ce_dmah, CS4231_BUFSZ, &buf_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &eng->ce_kaddr,
	    &bufsz, &eng->ce_acch);
	if (rc == DDI_FAILURE) {
		audio_dev_warn(adev, "dma_mem_alloc failed");
		return (DDI_FAILURE);
	}

	/* bind DMA buffer */
	rc = ddi_dma_addr_bind_handle(eng->ce_dmah, NULL,
	    eng->ce_kaddr, CS4231_BUFSZ, dir | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &dmac, &ccnt);
	if ((rc != DDI_DMA_MAPPED) || (ccnt != 1)) {
		audio_dev_warn(adev,
		    "ddi_dma_addr_bind_handle failed: %d", rc);
		return (DDI_FAILURE);
	}

	eng->ce_paddr = dmac.dmac_address;

	eng->ce_engine = audio_engine_alloc(&audiocs_engine_ops, caps);
	if (eng->ce_engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(eng->ce_engine, eng);
	audio_dev_add_engine(adev, eng->ce_engine);
	return (DDI_SUCCESS);
}

/*
 * audiocs_free_engine()
 *
 * Description:
 *	This routine fress the engine and all associated resources.
 *
 * Arguments:
 *	CS_engine_t	*eng	Engine to free.
 */
void
audiocs_free_engine(CS_engine_t *eng)
{
	CS_state_t	*state = eng->ce_state;
	audio_dev_t	*adev = state->cs_adev;

	if (eng == NULL)
		return;
	if (eng->ce_engine) {
		audio_dev_remove_engine(adev, eng->ce_engine);
		audio_engine_free(eng->ce_engine);
	}
	if (eng->ce_paddr) {
		(void) ddi_dma_unbind_handle(eng->ce_dmah);
	}
	if (eng->ce_acch) {
		ddi_dma_mem_free(&eng->ce_acch);
	}
	if (eng->ce_dmah) {
		ddi_dma_free_handle(&eng->ce_dmah);
	}
	kmem_free(eng, sizeof (*eng));
}

/*
 * audiocs_poll_ready()
 *
 * Description:
 *	This routine waits for the Codec to complete its initialization
 *	sequence and is done with its autocalibration.
 *
 *	Early versions of the Codec have a bug that can take as long as
 *	15 seconds to complete its initialization. For these cases we
 *	use a timeout mechanism so we don't keep the machine locked up.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	DDI_SUCCESS		The Codec is ready to continue
 *	DDI_FAILURE		The Codec isn't ready to continue
 */
int
audiocs_poll_ready(CS_state_t *state)
{
	ddi_acc_handle_t	handle = CODEC_HANDLE;
	int			x = 0;
	uint8_t			iar;
	uint8_t			idr;

	ASSERT(state->cs_regs != NULL);
	ASSERT(handle != NULL);

	/* wait for the chip to initialize itself */
	iar = ddi_get8(handle, &CS4231_IAR);

	while ((iar & IAR_INIT) && x++ < CS4231_TIMEOUT) {
		drv_usecwait(50);
		iar = ddi_get8(handle, &CS4231_IAR);
	}

	if (x >= CS4231_TIMEOUT) {
		return (DDI_FAILURE);
	}

	x = 0;

	/*
	 * Now wait for the chip to complete its autocalibration.
	 * Set the test register.
	 */
	SELIDX(state, ESI_REG);

	idr = ddi_get8(handle, &CS4231_IDR);

	while ((idr & ESI_ACI) && x++ < CS4231_TIMEOUT) {
		drv_usecwait(50);
		idr = ddi_get8(handle, &CS4231_IDR);
	}

	if (x >= CS4231_TIMEOUT) {
		return (DDI_FAILURE);
	}


	return (DDI_SUCCESS);

}

/*
 * audiocs_sel_index()
 *
 * Description:
 *	Select a cs4231 register. The cs4231 has a hardware bug where a
 *	register is not always selected the first time. We try and try
 *	again until the proper register is selected or we time out and
 *	print an error message.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	ddi_acc_handle_t handle		A handle to the device's registers
 *	uint8_t		addr		The register address to program
 *	int		reg		The register to select
 */
void
#ifdef	DEBUG
audiocs_sel_index(CS_state_t *state, uint8_t reg, int n)
#else
audiocs_sel_index(CS_state_t *state, uint8_t reg)
#endif
{
	int			x;
	uint8_t			T;
	ddi_acc_handle_t	handle = CODEC_HANDLE;
	uint8_t			*addr = &CS4231_IAR;

	for (x = 0; x < CS4231_RETRIES; x++) {
		ddi_put8(handle, addr, reg);
		T = ddi_get8(handle, addr);
		if (T == reg) {
			break;
		}
		drv_usecwait(1000);
	}

	if (x == CS4231_RETRIES) {
		audio_dev_warn(state->cs_adev,
#ifdef	DEBUG
		    "line %d: Couldn't select index (0x%02x 0x%02x)", n,
#else
		    "Couldn't select index (0x%02x 0x%02x)",
#endif
		    T, reg);
		audio_dev_warn(state->cs_adev,
		    "audio may not work correctly until it is stopped and "
		    "restarted");
	}
}

/*
 * audiocs_put_index()
 *
 * Description:
 *	Program a cs4231 register. The cs4231 has a hardware bug where a
 *	register is not programmed properly the first time. We program a value,
 *	then immediately read back the value and reprogram if nescessary.
 *	We do this until the register is properly programmed or we time out and
 *	print an error message.
 *
 * Arguments:
 *	CS_state_t	state		Handle to this device
 *	uint8_t		mask		Mask to not set reserved register bits
 *	int		val		The value to program
 */
void
#ifdef DEBUG
audiocs_put_index(CS_state_t *state, uint8_t val, uint8_t mask, int n)
#else
audiocs_put_index(CS_state_t *state, uint8_t val, uint8_t mask)
#endif
{
	int			x;
	uint8_t			T;
	ddi_acc_handle_t	handle = CODEC_HANDLE;
	uint8_t			*addr = &CS4231_IDR;

	val &= mask;

	for (x = 0; x < CS4231_RETRIES; x++) {
		ddi_put8(handle, addr, val);
		T = ddi_get8(handle, addr);
		if (T == val) {
			break;
		}
		drv_usecwait(1000);
	}

	if (x == CS4231_RETRIES) {
#ifdef DEBUG
		audio_dev_warn(state->cs_adev,
		    "line %d: Couldn't set value (0x%02x 0x%02x)", n, T, val);
#else
		audio_dev_warn(state->cs_adev,
		    "Couldn't set value (0x%02x 0x%02x)", T, val);
#endif
		audio_dev_warn(state->cs_adev,
		    "audio may not work correctly until it is stopped and "
		    "restarted");
	}
}
