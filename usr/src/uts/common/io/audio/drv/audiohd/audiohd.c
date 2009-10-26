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

#include <sys/audio/audio_driver.h>
#include <sys/note.h>
#include <sys/beep.h>
#include <sys/pci.h>
#include "audiohd.h"

#define	DEFINTS			175
#define	DRVNAME			"audiohd"
/*
 * Module linkage routines for the kernel
 */

static int audiohd_attach(dev_info_t *, ddi_attach_cmd_t);
static int audiohd_detach(dev_info_t *, ddi_detach_cmd_t);
static int audiohd_quiesce(dev_info_t *);
static int audiohd_resume(audiohd_state_t *);
static int audiohd_suspend(audiohd_state_t *);

/* interrupt handler */
static uint_t audiohd_intr(caddr_t, caddr_t);

/*
 * Local routines
 */
static int audiohd_init_state(audiohd_state_t *, dev_info_t *);
static int audiohd_init_pci(audiohd_state_t *, ddi_device_acc_attr_t *);
static void audiohd_fini_pci(audiohd_state_t *);
static int audiohd_reset_controller(audiohd_state_t *);
static int audiohd_init_controller(audiohd_state_t *);
static void audiohd_fini_controller(audiohd_state_t *);
static void audiohd_stop_dma(audiohd_state_t *);
static void audiohd_disable_intr(audiohd_state_t *);
static int audiohd_create_codec(audiohd_state_t *);
static void audiohd_build_path(audiohd_state_t *);
static void audiohd_destroy_codec(audiohd_state_t *);
static int audiohd_alloc_dma_mem(audiohd_state_t *, audiohd_dma_t *,
    size_t, ddi_dma_attr_t *, uint_t);
static void audiohd_finish_output_path(hda_codec_t *codec);
static uint32_t audioha_codec_verb_get(void *, uint8_t,
    uint8_t, uint16_t, uint8_t);
static uint32_t audioha_codec_4bit_verb_get(void *, uint8_t,
    uint8_t, uint16_t, uint16_t);
static int audiohd_reinit_hda(audiohd_state_t *);
static int audiohd_response_from_codec(audiohd_state_t *statep,
    uint32_t *resp, uint32_t *respex);
static void audiohd_restore_codec_gpio(audiohd_state_t *statep);
static void audiohd_change_speaker_state(audiohd_state_t *statep, int on);
static int audiohd_allocate_port(audiohd_state_t *statep);
static void audiohd_free_port(audiohd_state_t *statep);
static void audiohd_restore_path(audiohd_state_t *statep);
static int audiohd_add_controls(audiohd_state_t *statep);
static void audiohd_get_channels(audiohd_state_t *statep);
static void audiohd_init_path(audiohd_state_t *statep);
static void audiohd_del_controls(audiohd_state_t *statep);
static void audiohd_destroy(audiohd_state_t *statep);
static void audiohd_beep_on(void *arg);
static void audiohd_beep_off(void *arg);
static void audiohd_beep_freq(void *arg, int freq);
static wid_t audiohd_find_beep(hda_codec_t *codec, wid_t wid, int depth);
static void audiohd_build_beep_path(hda_codec_t *codec);
static void audiohd_build_beep_amp(hda_codec_t *codec);
static void  audiohd_finish_beep_path(hda_codec_t *codec);
static void audiohd_do_set_beep_volume(audiohd_state_t *statep,
    audiohd_path_t *path, uint64_t val);
static void audiohd_set_beep_volume(audiohd_state_t *statep);
static int audiohd_set_beep(void *arg, uint64_t val);

static	int	audiohd_beep;
static	int	audiohd_beep_divider;
static	int	audiohd_beep_vol = 1;

static ddi_device_acc_attr_t hda_dev_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static const char *audiohd_dtypes[] = {
	AUDIO_PORT_LINEOUT,
	AUDIO_PORT_SPEAKER,
	AUDIO_PORT_HEADPHONES,
	AUDIO_PORT_CD,
	AUDIO_PORT_SPDIFOUT,
	AUDIO_PORT_DIGOUT,
	AUDIO_PORT_MODEM,
	AUDIO_PORT_HANDSET,
	AUDIO_PORT_LINEIN,
	AUDIO_PORT_AUX1IN,
	AUDIO_PORT_MIC,
	AUDIO_PORT_PHONE,
	AUDIO_PORT_SPDIFIN,
	AUDIO_PORT_DIGIN,
	AUDIO_PORT_NONE,	/* reserved port, don't use */
	AUDIO_PORT_OTHER,
	NULL,
};

enum {
	CTL_VOLUME = 0,
	CTL_FRONT,
	CTL_SPEAKER,
	CTL_HEADPHONE,
	CTL_REAR,
	CTL_CENTER,
	CTL_SURROUND,
	CTL_LFE,
	CTL_IGAIN,
	CTL_LINEIN,
	CTL_MIC,
	CTL_CD,
	CTL_MONGAIN,
	CTL_MONSRC,
	CTL_RECSRC,
	CTL_BEEP
};

static void
audiohd_set_chipset_info(audiohd_state_t *statep)
{
	uint32_t		devid;
	const char		*name;
	const char		*vers;

	devid = pci_config_get16(statep->hda_pci_handle, PCI_CONF_VENID);
	devid <<= 16;
	devid |= pci_config_get16(statep->hda_pci_handle, PCI_CONF_DEVID);
	statep->devid = devid;

	name = AUDIOHD_DEV_CONFIG;
	vers = AUDIOHD_DEV_VERSION;

	switch (devid) {
	case 0x80862668:
		name = "Intel HD Audio";
		vers = "ICH6";
		break;
	case 0x808627d8:
		name = "Intel HD Audio";
		vers = "ICH7";
		break;
	case 0x8086284b:
		name = "Intel HD Audio";
		vers = "ICH8";
		break;
	case 0x8086293e:
		name = "Intel HD Audio";
		vers = "ICH9";
		break;
	case 0x10de0371:
		name = "NVIDIA HD Audio";
		vers = "MCP55";
		break;
	case 0x10de03f0:
		name = "NVIDIA HD Audio";
		vers = "MCP61A";
		break;
	case 0x10de026c:
		name = "NVIDIA HD Audio";
		vers = "MCP51";
		break;
	case 0x10de03e4:
		name = "NVIDIA HD Audio";
		vers = "MCP61";
		break;
	case 0x10de044a:
		name = "NVIDIA HD Audio";
		vers = "MCP65";
		break;
	case 0x10de055c:
		name = "NVIDIA HD Audio";
		vers = "MCP67";
		break;
	case 0x10de0ac0:
		name = "NVIDIA HD Audio";
		vers = "MCP79";
		break;
	case 0x1002437b:
		name = "ATI HD Audio";
		vers = "SB450";
		break;
	case 0x10024383:
		name = "ATI HD Audio";
		vers = "SB600";
		break;
	case 0x11063288:
		name = "VIA HD Audio";
		vers = "HDA";
		break;
	}
	/* set device information */
	audio_dev_set_description(statep->adev, name);
	audio_dev_set_version(statep->adev, vers);
}


/*
 * audiohd_add_intrs:
 *
 * Register FIXED or MSI interrupts.
 */
static int
audiohd_add_intrs(audiohd_state_t *statep, int intr_type)
{
	dev_info_t 		*dip = statep->hda_dip;
	ddi_intr_handle_t	ihandle;
	int 			avail;
	int 			actual;
	int 			intr_size;
	int 			count;
	int 			i, j;
	int 			ret, flag;

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		audio_dev_warn(statep->adev,
		    "ddi_intr_get_nintrs() failure, ret: %d, count: %d",
		    ret, count);
		return (DDI_FAILURE);
	}

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		audio_dev_warn(statep->adev, "ddi_intr_get_navail() failure, "
		    "ret: %d, avail: %d", ret, avail);
		return (DDI_FAILURE);
	}

	if (avail < 1) {
		audio_dev_warn(statep->adev,
		    "Interrupts count: %d, available: %d",
		    count, avail);
	}

	/* Allocate an array of interrupt handles */
	intr_size = count * sizeof (ddi_intr_handle_t);
	statep->htable = kmem_alloc(intr_size, KM_SLEEP);
	statep->intr_rqst = count;

	flag = (intr_type == DDI_INTR_TYPE_MSI) ?
	    DDI_INTR_ALLOC_STRICT:DDI_INTR_ALLOC_NORMAL;

	/* Call ddi_intr_alloc() */
	ret = ddi_intr_alloc(dip, statep->htable, intr_type, 0,
	    count, &actual, flag);
	if (ret != DDI_SUCCESS || actual == 0) {
		/* ddi_intr_alloc() failed  */
		kmem_free(statep->htable, intr_size);
		return (DDI_FAILURE);
	}

	if (actual < 1) {
		audio_dev_warn(statep->adev,
		    "Interrupts requested: %d, received: %d",
		    count, actual);
	}

	statep->intr_cnt = actual;

	/*
	 * Get priority for first msi, assume remaining are all the same
	 */
	if ((ret = ddi_intr_get_pri(statep->htable[0], &statep->intr_pri)) !=
	    DDI_SUCCESS) {
		audio_dev_warn(statep->adev, "ddi_intr_get_pri() failed %d",
		    ret);
		/* Free already allocated intr */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(statep->htable[i]);
		}
		kmem_free(statep->htable, intr_size);
		return (DDI_FAILURE);
	}

	/* Test for high level mutex */
	if (statep->intr_pri >= ddi_intr_get_hilevel_pri()) {
		audio_dev_warn(statep->adev,
		    "Hi level interrupt not supported");
		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(statep->htable[i]);
		kmem_free(statep->htable, intr_size);
		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(statep->htable[i], audiohd_intr,
		    (caddr_t)statep, (caddr_t)(uintptr_t)i)) != DDI_SUCCESS) {
			audio_dev_warn(statep->adev, "ddi_intr_add_handler() "
			    "failed %d", ret);
			/* Remove already added intr */
			for (j = 0; j < i; j++) {
				ihandle = statep->htable[j];
				(void) ddi_intr_remove_handler(ihandle);
			}
			/* Free already allocated intr */
			for (i = 0; i < actual; i++) {
				(void) ddi_intr_free(statep->htable[i]);
			}
			kmem_free(statep->htable, intr_size);
			return (DDI_FAILURE);
		}
	}

	if ((ret = ddi_intr_get_cap(statep->htable[0], &statep->intr_cap))
	    != DDI_SUCCESS) {
		audio_dev_warn(statep->adev,
		    "ddi_intr_get_cap() failed %d", ret);
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_remove_handler(statep->htable[i]);
			(void) ddi_intr_free(statep->htable[i]);
		}
		kmem_free(statep->htable, intr_size);
		return (DDI_FAILURE);
	}

	for (i = 0; i < actual; i++) {
		(void) ddi_intr_clr_mask(statep->htable[i]);
	}

	return (DDI_SUCCESS);
}

/*
 * audiohd_rem_intrs:
 *
 * Unregister FIXED or MSI interrupts
 */
static void
audiohd_rem_intrs(audiohd_state_t *statep)
{

	int i;

	/* Disable all interrupts */
	if (statep->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_disable() */
		(void) ddi_intr_block_disable(statep->htable, statep->intr_cnt);
	} else {
		for (i = 0; i < statep->intr_cnt; i++) {
			(void) ddi_intr_disable(statep->htable[i]);
		}
	}

	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < statep->intr_cnt; i++) {
		(void) ddi_intr_remove_handler(statep->htable[i]);
		(void) ddi_intr_free(statep->htable[i]);
	}

	kmem_free(statep->htable,
	    statep->intr_rqst * sizeof (ddi_intr_handle_t));
}

static int
audiohd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	audiohd_state_t		*statep;
	int			instance;
	int 			intr_types;
	int			i, rc = 0;

	instance = ddi_get_instance(dip);
	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		statep = ddi_get_driver_private(dip);
		ASSERT(statep != NULL);
		return (audiohd_resume(statep));

	default:
		return (DDI_FAILURE);
	}

	/* High-level interrupt isn't supported by this driver */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		cmn_err(CE_WARN,
		    "unsupported high level interrupt");
		return (DDI_FAILURE);
	}

	/* allocate the soft state structure */
	statep = kmem_zalloc(sizeof (*statep), KM_SLEEP);
	ddi_set_driver_private(dip, statep);

	/* interrupt cookie and initialize mutex */
	if (audiohd_init_state(statep, dip) != DDI_SUCCESS) {
		cmn_err(CE_NOTE,
		    "audiohd_init_state failed");
		goto error;
	}

	/* Set PCI command register to enable bus master and memeory I/O */
	if (audiohd_init_pci(statep, &hda_dev_accattr) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev,
		    "couldn't init pci regs");
		goto error;
	}

	audiohd_set_chipset_info(statep);

	if (audiohd_init_controller(statep) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev,
		    "couldn't init controller");
		goto error;
	}

	if (audiohd_create_codec(statep) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev,
		    "couldn't create codec");
		goto error;
	}

	audiohd_build_path(statep);

	audiohd_get_channels(statep);
	if (audiohd_allocate_port(statep) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev, "allocate port failure");
		goto error;
	}
	audiohd_init_path(statep);
	/* set up kernel statistics */
	if ((statep->hda_ksp = kstat_create(DRVNAME, instance,
	    DRVNAME, "controller", KSTAT_TYPE_INTR, 1,
	    KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(statep->hda_ksp);
	}

	/* disable interrupts and clear interrupt status */
	audiohd_disable_intr(statep);

	/*
	 * Get supported interrupt types
	 */
	if (ddi_intr_get_supported_types(dip, &intr_types) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev,
		    "ddi_intr_get_supported_types failed");
		goto error;
	}

	/*
	 * Add the h/w interrupt handler and initialise mutexes
	 */

	if ((intr_types & DDI_INTR_TYPE_MSI) && statep->msi_enable) {
		if (audiohd_add_intrs(statep, DDI_INTR_TYPE_MSI) ==
		    DDI_SUCCESS) {
			statep->intr_type = DDI_INTR_TYPE_MSI;
			statep->intr_added = B_TRUE;
		}
	}
	if (!(statep->intr_added) &&
	    (intr_types & DDI_INTR_TYPE_FIXED)) {
		/* MSI registration failed, trying FIXED interrupt type */
		if (audiohd_add_intrs(statep, DDI_INTR_TYPE_FIXED) !=
		    DDI_SUCCESS) {
			audio_dev_warn(statep->adev, "FIXED interrupt "
			    "registration failed");
			goto error;
		}
		/* FIXED interrupt type is supported */
		statep->intr_type = DDI_INTR_TYPE_FIXED;
		statep->intr_added = B_TRUE;
	}
	if (!(statep->intr_added)) {
		audio_dev_warn(statep->adev, "No interrupts registered");
		goto error;
	}
	mutex_init(&statep->hda_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(statep->intr_pri));

	/*
	 * Now that mutex lock is initialized, enable interrupts.
	 */
	if (statep->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI interrupts */
		rc = ddi_intr_block_enable(statep->htable, statep->intr_cnt);
		if (rc != DDI_SUCCESS) {
			audio_dev_warn(statep->adev,
			    "Enable block intr failed: %d\n", rc);
			return (DDI_FAILURE);
		}
	} else {
		/* Call ddi_intr_enable for MSI or FIXED interrupts */
		for (i = 0; i < statep->intr_cnt; i++) {
			rc = ddi_intr_enable(statep->htable[i]);
			if (rc != DDI_SUCCESS) {
				audio_dev_warn(statep->adev,
				    "Enable intr failed: %d\n", rc);
				return (DDI_FAILURE);
			}
		}
	}

	/*
	 * Register audio controls.
	 */
	if (audiohd_add_controls(statep) == DDI_FAILURE) {
		audio_dev_warn(statep->adev,
		    "unable to allocate controls");
		goto error;
	}
	if (audio_dev_register(statep->adev) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev,
		    "unable to register with framework");
		goto error;
	}
	ddi_report_dev(dip);

	/* enable interrupt */
	AUDIOHD_REG_SET32(AUDIOHD_REG_INTCTL,
	    AUDIOHD_INTCTL_BIT_GIE |
	    AUDIOHD_INTCTL_BIT_SIE);
	return (DDI_SUCCESS);
error:
	audiohd_destroy(statep);
	return (DDI_FAILURE);
}

static int
audiohd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audiohd_state_t		*statep;

	statep = ddi_get_driver_private(dip);
	ASSERT(statep != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (audiohd_suspend(statep));

	default:
		return (DDI_FAILURE);
	}
	if (audio_dev_unregister(statep->adev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (audiohd_beep)
		(void) beep_fini();
	audiohd_destroy(statep);
	return (DDI_SUCCESS);
}

static struct dev_ops audiohd_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	audiohd_attach,		/* attach */
	audiohd_detach,		/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	audiohd_quiesce,	/* quiesce */
};

static struct modldrv audiohd_modldrv = {
	&mod_driverops,			/* drv_modops */
	"AudioHD",			/* linkinfo */
	&audiohd_dev_ops,		/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &audiohd_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&audiohd_dev_ops, DRVNAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&audiohd_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&audiohd_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Audio routines
 */

static int
audiohd_engine_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}

static int
audiohd_engine_channels(void *arg)
{
	audiohd_port_t *port = arg;

	return (port->nchan);
}

static int
audiohd_engine_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (48000);
}
static void
audiohd_free_path(audiohd_state_t *statep)
{
	audiohd_path_t		*path;
	int			i;

	for (i = 0; i < statep->pathnum; i++) {
		if (statep->path[i]) {
			path = statep->path[i];
			kmem_free(path, sizeof (audiohd_path_t));
		}
	}
}
static void
audiohd_destroy(audiohd_state_t *statep)
{
	mutex_enter(&statep->hda_mutex);
	audiohd_stop_dma(statep);
	audiohd_disable_intr(statep);
	mutex_exit(&statep->hda_mutex);
	if (statep->intr_added) {
		audiohd_rem_intrs(statep);
	}
	if (statep->hda_ksp)
		kstat_delete(statep->hda_ksp);
	audiohd_free_port(statep);
	audiohd_free_path(statep);
	audiohd_destroy_codec(statep);
	audiohd_del_controls(statep);
	audiohd_fini_controller(statep);
	audiohd_fini_pci(statep);
	mutex_destroy(&statep->hda_mutex);
	if (statep->adev)
		audio_dev_free(statep->adev);
	kmem_free(statep, sizeof (*statep));
}
/*
 * get the max channels the hardware supported
 */
static void
audiohd_get_channels(audiohd_state_t *statep)
{
	int		i;
	uint8_t		maxp, assoc;

	maxp = 2;
	for (i = 0; i < AUDIOHD_MAX_ASSOC; i++) {
		if (maxp < statep->chann[i]) {
			maxp = statep->chann[i];
			assoc = i;
		}
	}
	statep->pchan = maxp;
	statep->assoc = assoc;
	/* for record, support stereo so far */
	statep->rchan = 2;
}
static void
audiohd_init_play_path(audiohd_path_t *path)
{
	int				i;
	uint32_t			ctrl;
	uint8_t				ctrl8;
	uint8_t				nchann;
	audiohd_widget_t		*widget;
	audiohd_pin_t			*pin;
	wid_t				wid;
	audiohd_pin_color_t		color;

	audiohd_state_t		*statep = path->statep;
	hda_codec_t		*codec = path->codec;

	/* enable SPDIF output */
	for (i = 0; i < path->pin_nums; i++) {
		wid = path->pin_wid[i];
		widget = codec->widget[wid];
		pin = (audiohd_pin_t *)widget->priv;
		if (pin->device == DTYPE_SPDIF_OUT) {
			ctrl = audioha_codec_verb_get(
			    statep,
			    codec->index,
			    path->adda_wid,
			    AUDIOHDC_VERB_GET_SPDIF_CTL,
			    0);
			ctrl |= AUDIOHD_SPDIF_ON;
			ctrl8 = ctrl &
			    AUDIOHD_SPDIF_MASK;
			(void) audioha_codec_verb_get(
			    statep,
			    codec->index,
			    path->adda_wid,
			    AUDIOHDC_VERB_SET_SPDIF_LCL,
			    ctrl8);
			/*
			 * We find that on intel ICH10 chipset with codec
			 * ALC888, audio is scratchy if we set the tag on the
			 * SPDIF path. So we just return here without setting
			 * the tag for the path as a workaround.
			 */
			if (codec->vid == AUDIOHD_CODECID_ALC888) {
				return;
			}
		}
	}
	wid = path->pin_wid[0];
	widget = codec->widget[wid];
	pin = (audiohd_pin_t *)widget->priv;

	/* two channels supported */
	if (pin->device == DTYPE_SPEAKER ||
	    pin->device == DTYPE_HP_OUT ||
	    pin->assoc != statep->assoc) {
		(void) audioha_codec_verb_get(
		    statep,
		    codec->index,
		    path->adda_wid,
		    AUDIOHDC_VERB_SET_STREAM_CHANN,
		    statep->port[PORT_DAC]->index <<
		    AUDIOHD_PLAY_TAG_OFF);
		(void) audioha_codec_4bit_verb_get(
		    statep,
		    codec->index,
		    path->adda_wid,
		    AUDIOHDC_VERB_SET_CONV_FMT,
		    AUDIOHD_FMT_PCM << 4 |
		    statep->pchan - 1);
	/* multichannel supported */
	} else {
		color = (pin->config >> AUDIOHD_PIN_CLR_OFF) &
		    AUDIOHD_PIN_CLR_MASK;
		switch (color) {
		case AUDIOHD_PIN_BLACK:
			nchann = statep->pchan - 2;
			break;
		case AUDIOHD_PIN_ORANGE:
			nchann = 2;
			break;
		case AUDIOHD_PIN_GREY:
			nchann = 4;
			break;
		case AUDIOHD_PIN_GREEN:
			nchann = 0;
			break;
		default:
			nchann = 0;
			break;
		}
		(void) audioha_codec_verb_get(statep,
		    codec->index,
		    path->adda_wid,
		    AUDIOHDC_VERB_SET_STREAM_CHANN,
		    statep->port[PORT_DAC]->index <<
		    AUDIOHD_PLAY_TAG_OFF |
		    nchann);
		(void) audioha_codec_4bit_verb_get(
		    statep,
		    codec->index,
		    path->adda_wid,
		    AUDIOHDC_VERB_SET_CONV_FMT,
		    AUDIOHD_FMT_PCM << 4 |
		    statep->pchan - 1);
	}
}
static void
audiohd_init_record_path(audiohd_path_t *path)
{
	audiohd_state_t		*statep = path->statep;
	hda_codec_t		*codec = path->codec;
	int			i;
	wid_t			wid;
	audiohd_pin_t		*pin;
	audiohd_widget_t	*widget;

	for (i = 0; i < path->pin_nums; i++) {
		wid = path->pin_wid[i];
		widget = codec->widget[wid];
		pin = (audiohd_pin_t *)widget->priv;
	/*
	 * Since there is no SPDIF input device available for test,
	 * we will use this code in the future to support SPDIF input
	 */
#if 0
		if (pin->device == DTYPE_SPDIF_IN) {
			ctrl = audioha_codec_verb_get(
			    statep,
			    codec->index,
			    path->adda_wid,
			    AUDIOHDC_VERB_GET_SPDIF_CTL,
			    0);
			ctrl |= AUDIOHD_SPDIF_ON;
			ctrl8 = ctrl &
			    AUDIOHD_SPDIF_MASK;
			(void) audioha_codec_verb_get(
			    statep,
			    codec->index,
			    path->adda_wid,
			    AUDIOHDC_VERB_SET_SPDIF_LCL,
			    ctrl8);
			statep->inmask |= (1U << DTYPE_SPDIF_IN);
		}
#endif
		if (pin->device == DTYPE_MIC_IN) {
			if (((pin->config >>
			    AUDIOHD_PIN_CONTP_OFF) &
			    AUDIOHD_PIN_CONTP_MASK) ==
			    AUDIOHD_PIN_CON_FIXED)
				statep->port[PORT_ADC]->index = path->tag;
		}
		if ((pin->device == DTYPE_LINE_IN) ||
		    (pin->device == DTYPE_CD) ||
		    (pin->device == DTYPE_MIC_IN)) {
			statep->inmask |= (1U << pin->device);
		}
	}
	(void) audioha_codec_verb_get(statep,
	    codec->index,
	    path->adda_wid,
	    AUDIOHDC_VERB_SET_STREAM_CHANN,
	    path->tag <<
	    AUDIOHD_REC_TAG_OFF);
	(void) audioha_codec_4bit_verb_get(statep,
	    codec->index,
	    path->adda_wid,
	    AUDIOHDC_VERB_SET_CONV_FMT,
	    AUDIOHD_FMT_PCM << 4 | statep->rchan - 1);

}
static void
audiohd_init_path(audiohd_state_t *statep)
{
	int				i;
	audiohd_path_t			*path;

	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path)
			continue;
		switch (path->path_type) {
			case PLAY:
				audiohd_init_play_path(path);
				break;
			case RECORD:
				audiohd_init_record_path(path);
				break;
			default:
				break;
		}
	}
	statep->in_port = 0;
}

static int
audiohd_reset_port(audiohd_port_t *port)
{
	uint16_t		regbase;
	audiohd_state_t		*statep;
	uint8_t			bTmp;
	int			i;

	regbase = port->regoff;
	statep = port->statep;

	bTmp = AUDIOHD_REG_GET8(regbase + AUDIOHD_SDREG_OFFSET_CTL);
	/* stop stream */
	bTmp &= ~AUDIOHD_REG_RIRBSIZE;
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, bTmp);

	/* wait 40us for stream to stop as HD spec */
	drv_usecwait(40);

	/* reset stream */
	bTmp |= AUDIOHDR_SD_CTL_SRST;
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, bTmp);

	for (i = 0; i < AUDIOHD_RETRY_TIMES; i++) {
		/* Empirical testing time, which works well */
		drv_usecwait(50);
		bTmp = AUDIOHD_REG_GET8(regbase + AUDIOHD_SDREG_OFFSET_CTL);
		bTmp &= AUDIOHDR_SD_CTL_SRST;
		if (bTmp)
			break;
	}

	if (!bTmp) {
		audio_dev_warn(statep->adev, "Failed to reset stream %d",
		    port->index);
		return (DDI_FAILURE);
	}

	/* Empirical testing time, which works well */
	drv_usecwait(300);

	/* exit reset stream */
	bTmp &= ~AUDIOHDR_SD_CTL_SRST;
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, bTmp);

	for (i = 0; i < AUDIOHD_RETRY_TIMES; i++) {
		/* Empircal testing time */
		drv_usecwait(50);
		bTmp = AUDIOHD_REG_GET8(regbase + AUDIOHD_SDREG_OFFSET_CTL);
		bTmp &= AUDIOHDR_SD_CTL_SRST;
		if (!bTmp)
			break;
	}

	if (bTmp) {
		audio_dev_warn(statep->adev,
		    "Failed to exit reset state for"
		    " stream %d, bTmp=0x%02x", port->index, bTmp);
		return (DDI_FAILURE);
	}

	AUDIOHD_REG_SET32(regbase + AUDIOHD_SDREG_OFFSET_BDLPL,
	    (uint32_t)port->bdl_paddr);
	AUDIOHD_REG_SET32(regbase + AUDIOHD_SDREG_OFFSET_BDLPU,
	    (uint32_t)(port->bdl_paddr >> 32));
	AUDIOHD_REG_SET16(regbase + AUDIOHD_SDREG_OFFSET_LVI,
	    AUDIOHD_BDLE_NUMS - 1);
	AUDIOHD_REG_SET32(regbase + AUDIOHD_SDREG_OFFSET_CBL,
	    port->samp_size * AUDIOHD_BDLE_NUMS);

	AUDIOHD_REG_SET16(regbase + AUDIOHD_SDREG_OFFSET_FORMAT,
	    port->format << 4 | port->nchan - 1);

	/* clear status */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_STS,
	    AUDIOHDR_SD_STS_BCIS | AUDIOHDR_SD_STS_FIFOE |
	    AUDIOHDR_SD_STS_DESE);

	/* set stream tag */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL +
	    AUDIOHD_PLAY_CTL_OFF,
	    (port->index) << AUDIOHD_PLAY_TAG_OFF);

	return (DDI_SUCCESS);
}

static int
audiohd_engine_open(void *arg, int flag,
    unsigned *fragfrp, unsigned *nfragsp, caddr_t *bufp)
{
	audiohd_port_t	*port = arg;
	audiohd_state_t	*statep = port->statep;

	_NOTE(ARGUNUSED(flag));

	mutex_enter(&statep->hda_mutex);
	(void) audiohd_reset_port(port);
	mutex_exit(&statep->hda_mutex);

	port->started = B_FALSE;
	port->count = 0;
	port->curpos = 0;
	*fragfrp = port->fragfr;
	*nfragsp = AUDIOHD_BDLE_NUMS;
	*bufp = port->samp_kaddr;

	return (0);
}

static void
audiohd_start_port(audiohd_port_t *port)
{
	audiohd_state_t	*statep = port->statep;

	ASSERT(mutex_owned(&statep->hda_mutex));

	/* if suspended, then do nothing else */
	if (statep->suspended) {
		return;
	}

	/* Enable interrupt and start DMA */
	AUDIOHD_REG_SET8(port->regoff + AUDIOHD_SDREG_OFFSET_CTL,
	    AUDIOHDR_SD_CTL_INTS | AUDIOHDR_SD_CTL_SRUN);
}

static void
audiohd_stop_port(audiohd_port_t *port)
{
	audiohd_state_t	*statep = port->statep;

	ASSERT(mutex_owned(&statep->hda_mutex));
	/* if suspended, then do nothing else */
	if (statep->suspended) {
		return;
	}
	AUDIOHD_REG_SET8(port->regoff + AUDIOHD_SDREG_OFFSET_CTL, 0);
}

static int
audiohd_engine_start(void *arg)
{
	audiohd_port_t		*port = arg;
	audiohd_state_t		*statep = port->statep;

	mutex_enter(&statep->hda_mutex);
	if (!port->started) {
		audiohd_start_port(port);
		port->started = B_TRUE;
		port->triggered = B_TRUE;
	}
	mutex_exit(&statep->hda_mutex);
	return (0);
}

static void
audiohd_engine_stop(void *arg)
{
	audiohd_port_t		*port = arg;
	audiohd_state_t		*statep = port->statep;

	mutex_enter(&statep->hda_mutex);
	if (port->started) {
		audiohd_stop_port(port);
	}
	port->started = B_FALSE;
	mutex_exit(&statep->hda_mutex);
}

static void
audiohd_update_port(audiohd_port_t *port)
{
	int			pos;
	uint32_t		len;
	audiohd_state_t		*statep = port->statep;

	pos = AUDIOHD_REG_GET32(port->regoff + AUDIOHD_SDREG_OFFSET_LPIB);
	pos &= AUDIOHD_POS_MASK;
	if (pos > port->curpos)
		len = (pos - port->curpos) & AUDIOHD_POS_MASK;
	else {
		len = pos + port->samp_size * AUDIOHD_BDLE_NUMS - port->curpos;
		len &= AUDIOHD_POS_MASK;
	}
	port->curpos += len;
	if (port->curpos >= port->samp_size * AUDIOHD_BDLE_NUMS)
		port->curpos -= port->samp_size * AUDIOHD_BDLE_NUMS;

	port->count += len / (port->nchan * 2);


}

static uint64_t
audiohd_engine_count(void *arg)
{
	audiohd_port_t	*port = arg;
	audiohd_state_t	*statep = port->statep;
	uint64_t	val;

	mutex_enter(&statep->hda_mutex);
	audiohd_update_port(port);
	val = port->count;
	mutex_exit(&statep->hda_mutex);
	return (val);
}

static void
audiohd_engine_close(void *arg)
{
	audiohd_port_t		*port = arg;
	audiohd_state_t		*statep = port->statep;

	mutex_enter(&statep->hda_mutex);
	audiohd_stop_port(port);
	port->started = B_FALSE;
	port->triggered = B_FALSE;
	mutex_exit(&statep->hda_mutex);
}

static void
audiohd_engine_sync(void *arg, unsigned nframes)
{
	audiohd_port_t *port = arg;

	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(port->samp_dmah, 0,
	    0, port->sync_dir);

}

static size_t
audiohd_engine_qlen(void *arg)
{
	audiohd_port_t *port = arg;

	return (port->fragfr);
}

audio_engine_ops_t audiohd_engine_ops = {
	AUDIO_ENGINE_VERSION,		/* version number */
	audiohd_engine_open,
	audiohd_engine_close,
	audiohd_engine_start,
	audiohd_engine_stop,
	audiohd_engine_count,
	audiohd_engine_format,
	audiohd_engine_channels,
	audiohd_engine_rate,
	audiohd_engine_sync,
	audiohd_engine_qlen,
};

static int
audiohd_get_value(void *arg, uint64_t *val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;

	mutex_enter(&statep->hda_mutex);
	*val = pc->val;
	mutex_exit(&statep->hda_mutex);
	return (0);
}

static void
audiohd_set_output_gain(audiohd_state_t *statep)
{
	int			i;
	audiohd_path_t		*path;
	uint_t			tmp;
	wid_t			wid;
	audiohd_widget_t	*w;
	uint8_t			gain;
	uint32_t		maxgain;

	if (statep->soft_volume)
		return;
	gain = (uint8_t)statep->controls[CTL_VOLUME]->val;
	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path || path->path_type != PLAY)
			continue;
		/* use the DACs to adjust the volume */
		wid = path->adda_wid;
		w = path->codec->widget[wid];
		maxgain = w->outamp_cap &
		    AUDIOHDC_AMP_CAP_STEP_NUMS;
		maxgain >>= AUDIOHD_GAIN_OFF;
		if (w->outamp_cap) {
			tmp = gain * maxgain / 100;
			(void) audioha_codec_4bit_verb_get(statep,
			    path->codec->index,
			    wid,
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_LEFT |
			    AUDIOHDC_AMP_SET_OUTPUT | tmp);
			(void) audioha_codec_4bit_verb_get(statep,
			    path->codec->index,
			    wid,
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_RIGHT |
			    AUDIOHDC_AMP_SET_OUTPUT | tmp);
		}
	}
}

static void
audiohd_do_set_pin_volume(audiohd_state_t *statep, audiohd_path_t *path,
    uint64_t val)
{
	uint8_t				l, r;
	uint_t				tmp;
	int				gain;

	if (path->mute_wid && val == 0) {
		(void) audioha_codec_4bit_verb_get(
		    statep,
		    path->codec->index,
		    path->mute_wid,
		    AUDIOHDC_VERB_SET_AMP_MUTE,
		    path->mute_dir |
		    AUDIOHDC_AMP_SET_LNR |
		    AUDIOHDC_AMP_SET_MUTE);
		return;
	}

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);

	tmp = l * path->gain_bits / 100;
	(void) audioha_codec_4bit_verb_get(statep,
	    path->codec->index,
	    path->gain_wid,
	    AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LEFT | path->gain_dir |
	    tmp);
	tmp = r * path->gain_bits / 100;
	(void) audioha_codec_4bit_verb_get(statep,
	    path->codec->index,
	    path->gain_wid,
	    AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_RIGHT | path->gain_dir |
	    tmp);
	if (path->mute_wid && path->mute_wid != path->gain_wid) {
		gain = AUDIOHDC_GAIN_MAX;
		(void) audioha_codec_4bit_verb_get(
		    statep,
		    path->codec->index,
		    path->mute_wid,
		    AUDIOHDC_VERB_SET_AMP_MUTE,
		    path->mute_dir |
		    AUDIOHDC_AMP_SET_LEFT |
		    gain);
		(void) audioha_codec_4bit_verb_get(
		    statep,
		    path->codec->index,
		    path->mute_wid,
		    AUDIOHDC_VERB_SET_AMP_MUTE,
		    path->mute_dir |
		    AUDIOHDC_AMP_SET_RIGHT |
		    gain);
	}
}

static void
audiohd_set_pin_volume(audiohd_state_t *statep, audiohda_device_type_t type)
{
	int				i, j;
	audiohd_path_t			*path;
	audiohd_widget_t		*widget;
	wid_t				wid;
	audiohd_pin_t			*pin;
	hda_codec_t			*codec;
	uint64_t			val;
	audiohd_ctrl_t			*control;

	switch (type) {
		case DTYPE_SPEAKER:
			control = statep->controls[CTL_SPEAKER];
			if (control == NULL)
				return;
			val = control->val;
			break;
		case DTYPE_HP_OUT:
			control = statep->controls[CTL_HEADPHONE];
			if (control == NULL)
				return;
			val = control->val;
			break;
		case DTYPE_LINEOUT:
			control = statep->controls[CTL_FRONT];
			if (control == NULL)
				return;
			val = control->val;
			break;

		case DTYPE_CD:
			control = statep->controls[CTL_CD];
			if (control == NULL)
				return;
			val = control->val;
			break;
		case DTYPE_LINE_IN:
			control = statep->controls[CTL_LINEIN];
			if (control == NULL)
				return;
			val = control->val;
			break;
		case DTYPE_MIC_IN:
			control = statep->controls[CTL_MIC];
			if (control == NULL)
				return;
			val = control->val;
			break;
	}

	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path)
			continue;
		codec = path->codec;
		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			widget = codec->widget[wid];
			pin = (audiohd_pin_t *)widget->priv;
			if ((pin->device == type) && path->gain_wid) {
				audiohd_do_set_pin_volume(statep, path, val);
			}
		}
	}
}


static void
audiohd_set_pin_volume_by_color(audiohd_state_t *statep,
    audiohd_pin_color_t color)
{
	int			i, j;
	audiohd_path_t		*path;
	audiohd_widget_t	*widget;
	wid_t			wid;
	audiohd_pin_t		*pin;
	hda_codec_t		*codec;
	uint8_t			l, r;
	uint64_t		val;
	audiohd_pin_color_t	clr;
	audiohd_ctrl_t		*control;

	switch (color) {
		case AUDIOHD_PIN_GREEN:
			control = statep->controls[CTL_FRONT];
			if (control == NULL)
				return;
			val = control->val;
			break;
		case AUDIOHD_PIN_BLACK:
			control = statep->controls[CTL_REAR];
			if (control == NULL)
				return;
			val = control->val;
			break;
		case AUDIOHD_PIN_ORANGE:
			control = statep->controls[CTL_CENTER];
			if (control == NULL)
				return;
			l = control->val;
			control = statep->controls[CTL_LFE];
			if (control == NULL)
				return;
			r = control->val;
			val = (l << 8) | r;
			break;
		case AUDIOHD_PIN_GREY:
			control = statep->controls[CTL_SURROUND];
			if (control == NULL)
				return;
			val = control->val;
			break;
	}

	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path)
			continue;
		codec = path->codec;
		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			widget = codec->widget[wid];
			pin = (audiohd_pin_t *)widget->priv;
			clr = (pin->config >> AUDIOHD_PIN_CLR_OFF) &
			    AUDIOHD_PIN_CLR_MASK;
			if ((clr == color) && path->gain_wid) {
				audiohd_do_set_pin_volume(statep, path, val);
			}
		}
	}
}

static int
audiohd_set_input_pin(audiohd_state_t *statep)
{
	uint64_t		val;
	hda_codec_t		*codec;
	audiohd_pin_t		*pin;
	audiohd_path_t		*path;
	audiohd_widget_t	*widget, *w;
	int			i, j;
	wid_t			wid, pin_wid = 0;

	val = statep->controls[CTL_RECSRC]->val;
	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path || path->path_type != RECORD)
			continue;
		switch ((ddi_ffs(val & 0xffff)) - 1) {
		case DTYPE_LINE_IN:
		case DTYPE_MIC_IN:
		case DTYPE_CD:
			for (j = 0; j < path->pin_nums; j++) {
				wid = path->pin_wid[j];
				widget = path->codec->widget[wid];
				pin = (audiohd_pin_t *)widget->priv;
				if ((1U << pin->device) == val) {
					AUDIOHD_ENABLE_PIN_IN(statep,
					    path->codec->index,
					    pin->wid);
					pin_wid = pin->wid;
					codec = path->codec;
					statep->in_port = pin->device;
				} else if (statep->in_port == pin->device) {
					AUDIOHD_DISABLE_PIN_IN(statep,
					    path->codec->index,
					    pin->wid);
				}
			}
			break;
		default:
			break;
		}
		break;
	}
	if (pin_wid == 0)
		return (DDI_SUCCESS);
	w = codec->widget[pin_wid];
	pin = (audiohd_pin_t *)w->priv;
	w = codec->widget[pin->adc_dac_wid];
	path = (audiohd_path_t *)w->priv;
	/*
	 * If there is a real selector in this input path,
	 * we select the right one input for the selector.
	 */
	if (path->sum_wid) {
		w = codec->widget[path->sum_wid];
		if (w->type == WTYPE_AUDIO_SEL) {
			for (i = 0; i < path->pin_nums; i++)
				if (path->pin_wid[i] == pin_wid)
					break;
			(void) audioha_codec_verb_get(
			    statep, codec->index, path->sum_wid,
			    AUDIOHDC_VERB_SET_CONN_SEL,
			    path->sum_selconn[i]);
		}
	}
	return (DDI_SUCCESS);
}

static void
audiohd_set_pin_monitor_gain(hda_codec_t *codec, audiohd_state_t *statep,
    uint_t caddr, audiohd_pin_t *pin, uint64_t gain)
{
	int 			i, k;
	uint_t			ltmp, rtmp;
	audiohd_widget_t	*widget;
	uint8_t		l, r;

	l = (gain & 0xff00) >> 8;
	r = (gain & 0xff);

	for (k = 0; k < pin->num; k++) {
		ltmp = l * pin->mg_gain[k] / 100;
		rtmp = r * pin->mg_gain[k] / 100;
		widget = codec->widget[pin->mg_wid[k]];
		if (pin->mg_dir[k] == AUDIOHDC_AMP_SET_OUTPUT) {
			(void) audioha_codec_4bit_verb_get(
			    statep,
			    caddr,
			    pin->mg_wid[k],
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_LEFT|
			    pin->mg_dir[k] | ltmp);
			(void) audioha_codec_4bit_verb_get(
			    statep,
			    caddr,
			    pin->mg_wid[k],
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_RIGHT|
			    pin->mg_dir[k] | rtmp);
		} else if (pin->mg_dir[k] == AUDIOHDC_AMP_SET_INPUT) {
			for (i = 0; i < widget->used; i++) {
				(void) audioha_codec_4bit_verb_get(
				    statep,
				    caddr,
				    pin->mg_wid[k],
				    AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_RIGHT|
				    widget->selmon[i]<<
				    AUDIOHDC_AMP_SET_INDEX_OFFSET |
				    pin->mg_dir[k] | rtmp);
				(void) audioha_codec_4bit_verb_get(
				    statep,
				    caddr,
				    pin->mg_wid[k],
				    AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_LEFT|
				    widget->selmon[i]<<
				    AUDIOHDC_AMP_SET_INDEX_OFFSET |
				    pin->mg_dir[k] | ltmp);
			}
		}
	}
}

static void
audiohd_set_monitor_gain(audiohd_state_t *statep)
{
	int			i, j;
	audiohd_path_t		*path;
	uint_t			caddr;
	audiohd_widget_t	*w;
	wid_t			wid;
	audiohd_pin_t		*pin;
	audiohd_ctrl_t		*ctrl;
	uint64_t		val;

	ctrl = statep->controls[CTL_MONGAIN];
	if (ctrl == NULL)
		return;
	val = ctrl->val;

	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (path == NULL || path->path_type != PLAY)
			continue;
		caddr = path->codec->index;
		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			w = path->codec->widget[wid];
			pin = (audiohd_pin_t *)w->priv;
			audiohd_set_pin_monitor_gain(path->codec, statep,
			    caddr, pin, val);
		}
	}

}

static void
audiohd_set_beep_volume(audiohd_state_t *statep)
{
	int			i;
	audiohd_path_t		*path;
	hda_codec_t		*codec;
	uint64_t		val;
	uint_t			tmp;
	audiohd_ctrl_t		*control;
	uint32_t		vid;

	control = statep->controls[CTL_BEEP];
	if (control == NULL)
		return;
	val = control->val;
	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path || path->path_type != BEEP)
			continue;
		codec = path->codec;
		vid = codec->vid;
		vid = vid >> 16;

		switch (vid) {
		case  AUDIOHD_VID_SIGMATEL:
			/*
			 * Sigmatel HD codec specific operation.
			 * There is a workaround,
			 * Due to Sigmatel HD codec hardware problem,
			 * which it can't mute beep when volume is 0.
			 * So add global value audiohd_beep_vol,
			 * Set freq to 0 when volume is 0.
			 */
			tmp = val * path->gain_bits / 100;
			if (tmp == 0) {
				audiohd_beep_vol = 0;
			} else {
				audiohd_beep_vol = tmp;
				(void) audioha_codec_verb_get(
				    statep,
				    codec->index,
				    path->beep_wid,
				    AUDIOHDC_VERB_SET_BEEP_VOL,
				    tmp);
			}
			break;

		default:
			/* Common operation based on audiohd spec */
			audiohd_do_set_beep_volume(statep, path, val);
			break;
		}
	}
}

static void
audiohd_do_set_beep_volume(audiohd_state_t *statep, audiohd_path_t *path,
    uint64_t val)
{
	uint8_t		l, r;
	uint_t		tmp;
	int		gain;

	if (val == 0) {
		(void) audioha_codec_4bit_verb_get(
		    statep,
		    path->codec->index,
		    path->mute_wid,
		    AUDIOHDC_VERB_SET_AMP_MUTE,
		    path->mute_dir |
		    AUDIOHDC_AMP_SET_LNR |
		    AUDIOHDC_AMP_SET_MUTE);
		return;
	}

	r = (val & 0xff);
	l = r;

	tmp = l * path->gain_bits / 100;
	(void) audioha_codec_4bit_verb_get(statep,
	    path->codec->index,
	    path->gain_wid,
	    AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LEFT | path->gain_dir |
	    tmp);
	tmp = r * path->gain_bits / 100;
	(void) audioha_codec_4bit_verb_get(statep,
	    path->codec->index,
	    path->gain_wid,
	    AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_RIGHT | path->gain_dir |
	    tmp);
	if (path->mute_wid != path->gain_wid) {
		gain = AUDIOHDC_GAIN_MAX;
		(void) audioha_codec_4bit_verb_get(
		    statep,
		    path->codec->index,
		    path->mute_wid,
		    AUDIOHDC_VERB_SET_AMP_MUTE,
		    path->mute_dir |
		    AUDIOHDC_AMP_SET_LEFT |
		    gain);
		(void) audioha_codec_4bit_verb_get(
		    statep,
		    path->codec->index,
		    path->mute_wid,
		    AUDIOHDC_VERB_SET_AMP_MUTE,
		    path->mute_dir |
		    AUDIOHDC_AMP_SET_RIGHT |
		    gain);
	}
}

static void
audiohd_configure_output(audiohd_state_t *statep)
{
	audiohd_set_pin_volume(statep, DTYPE_LINEOUT);
	audiohd_set_pin_volume(statep, DTYPE_SPEAKER);
	audiohd_set_pin_volume(statep, DTYPE_HP_OUT);

	audiohd_set_pin_volume_by_color(statep, AUDIOHD_PIN_GREEN);
	audiohd_set_pin_volume_by_color(statep, AUDIOHD_PIN_BLACK);
	audiohd_set_pin_volume_by_color(statep, AUDIOHD_PIN_GREY);
	audiohd_set_pin_volume_by_color(statep, AUDIOHD_PIN_ORANGE);

	audiohd_set_output_gain(statep);
}
static void
audiohd_configure_input(audiohd_state_t *statep)
{
	(void) audiohd_set_input_pin(statep);
	audiohd_set_monitor_gain(statep);
	audiohd_set_pin_volume(statep, DTYPE_LINE_IN);
	audiohd_set_pin_volume(statep, DTYPE_CD);
	audiohd_set_pin_volume(statep, DTYPE_MIC_IN);
}
static int
audiohd_set_volume(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;

	val &= 0xff;
	if (val > 100)
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_configure_output(statep);
	mutex_exit(&statep->hda_mutex);

	return (0);
}

static int
audiohd_set_recsrc(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t *statep = pc->statep;

	if (val & ~(statep->inmask))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_configure_input(statep);
	mutex_exit(&statep->hda_mutex);
	return (0);
}

static int
audiohd_set_rear(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;
	uint8_t		l, r;

	if (val & ~0xffff)
		return (EINVAL);

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);
	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume_by_color(statep, AUDIOHD_PIN_BLACK);
	mutex_exit(&statep->hda_mutex);

	return (0);
}

static int
audiohd_set_center(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;

	val &= 0xff;

	if (val > 100)
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume_by_color(statep, AUDIOHD_PIN_ORANGE);
	mutex_exit(&statep->hda_mutex);

	return (0);
}

static int
audiohd_set_surround(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;
	uint8_t		l, r;

	if (val & ~0xffff)
		return (EINVAL);

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);
	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume_by_color(statep, AUDIOHD_PIN_GREY);
	mutex_exit(&statep->hda_mutex);

	return (0);
}

static int
audiohd_set_lfe(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;

	val &= 0xff;

	if (val > 100)
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume_by_color(statep, AUDIOHD_PIN_ORANGE);
	mutex_exit(&statep->hda_mutex);

	return (0);
}
static int
audiohd_set_speaker(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;
	uint8_t		l, r;

	if (val & ~0xffff)
		return (EINVAL);

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);
	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume(statep, DTYPE_SPEAKER);
	mutex_exit(&statep->hda_mutex);

	return (0);
}
static int
audiohd_set_front(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;
	uint8_t		l, r;

	if (val & ~0xffff)
		return (EINVAL);

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);
	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume_by_color(statep, AUDIOHD_PIN_GREEN);
	mutex_exit(&statep->hda_mutex);

	return (0);
}
static int
audiohd_set_headphone(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;
	uint8_t		l, r;

	if (val & ~0xffff)
		return (EINVAL);

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);
	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume(statep, DTYPE_HP_OUT);
	mutex_exit(&statep->hda_mutex);

	return (0);
}
static int
audiohd_set_linein(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;
	uint8_t		l, r;

	if (val & ~0xffff)
		return (EINVAL);

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);
	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume(statep, DTYPE_LINE_IN);
	mutex_exit(&statep->hda_mutex);

	return (0);
}

static int
audiohd_set_mic(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;
	uint8_t		l, r;

	if (val & ~0xffff)
		return (EINVAL);

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);
	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume(statep, DTYPE_MIC_IN);
	mutex_exit(&statep->hda_mutex);

	return (0);
}

static int
audiohd_set_cd(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;
	uint8_t		l, r;

	if (val & ~0xffff)
		return (EINVAL);

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);
	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_pin_volume(statep, DTYPE_CD);
	mutex_exit(&statep->hda_mutex);

	return (0);
}

static int
audiohd_set_mongain(void *arg, uint64_t val)
{
	audiohd_ctrl_t	*pc = arg;
	audiohd_state_t	*statep = pc->statep;
	uint8_t		l, r;

	if (val & ~0xffff)
		return (EINVAL);

	l = (val & 0xff00) >> 8;
	r = (val & 0xff);
	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_configure_input(statep);
	mutex_exit(&statep->hda_mutex);

	return (0);
}

static int
audiohd_set_beep(void *arg, uint64_t val)
{
	audiohd_ctrl_t  *pc = arg;
	audiohd_state_t *statep = pc->statep;

	val &= 0xff;

	if (val > 100)
		return (EINVAL);

	mutex_enter(&statep->hda_mutex);
	pc->val = val;
	audiohd_set_beep_volume(statep);
	mutex_exit(&statep->hda_mutex);

	return (0);
}

#define	PLAYCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_PLAY)
#define	RECCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_REC)
#define	MONCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_MONITOR)
#define	PCMVOL	(PLAYCTL | AUDIO_CTRL_FLAG_PCMVOL)
#define	MONVOL	(MONCTL | AUDIO_CTRL_FLAG_MONVOL)
#define	MAINVOL	(PLAYCTL | AUDIO_CTRL_FLAG_MAINVOL)
#define	RECVOL	(RECCTL | AUDIO_CTRL_FLAG_RECVOL)
#define	RWCTL	AUDIO_CTRL_FLAG_RW

static audiohd_ctrl_t *
audiohd_alloc_ctrl(audiohd_state_t *statep, uint32_t num, uint64_t val)
{
	audio_ctrl_desc_t	desc;
	audio_ctrl_wr_t		fn;
	audiohd_ctrl_t		*pc;

	pc = kmem_zalloc(sizeof (*pc), KM_SLEEP);
	pc->statep = statep;
	pc->num = num;

	bzero(&desc, sizeof (desc));

	switch (num) {
	case CTL_VOLUME:
		desc.acd_name = AUDIO_CTRL_ID_VOLUME;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		fn = audiohd_set_volume;
		break;

	case CTL_FRONT:
		desc.acd_name = AUDIO_CTRL_ID_FRONT;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = audiohd_set_front;
		break;

	case CTL_SPEAKER:
		desc.acd_name = AUDIO_CTRL_ID_SPEAKER;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = audiohd_set_speaker;
		break;

	case CTL_HEADPHONE:
		desc.acd_name = AUDIO_CTRL_ID_HEADPHONE;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = audiohd_set_headphone;
		break;

	case CTL_REAR:
		desc.acd_name = AUDIO_CTRL_ID_REAR;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = audiohd_set_rear;
		break;

	case CTL_CENTER:
		desc.acd_name = AUDIO_CTRL_ID_CENTER;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = audiohd_set_center;
		break;

	case CTL_SURROUND:
		desc.acd_name = AUDIO_CTRL_ID_SURROUND;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = audiohd_set_surround;
		break;

	case CTL_LFE:
		desc.acd_name = AUDIO_CTRL_ID_LFE;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = audiohd_set_lfe;
		break;

	case CTL_LINEIN:
		desc.acd_name = AUDIO_CTRL_ID_LINEIN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = audiohd_set_linein;
		break;

	case CTL_MIC:
		desc.acd_name = AUDIO_CTRL_ID_MIC;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = audiohd_set_mic;
		break;

	case CTL_CD:
		desc.acd_name = AUDIO_CTRL_ID_CD;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = audiohd_set_cd;
		break;

	case CTL_MONGAIN:
		desc.acd_name = AUDIO_CTRL_ID_MONGAIN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MONVOL;
		fn = audiohd_set_mongain;
		break;

	case CTL_RECSRC:
		desc.acd_name = AUDIO_CTRL_ID_RECSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_minvalue = statep->inmask;
		desc.acd_maxvalue = statep->inmask;
		desc.acd_flags = RECCTL;
		for (int i = 0; audiohd_dtypes[i]; i++) {
			desc.acd_enum[i] = audiohd_dtypes[i];
		}
		fn = audiohd_set_recsrc;
		break;

	case CTL_BEEP:
		desc.acd_name = AUDIO_CTRL_ID_BEEP;
		desc.acd_type =	AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RWCTL;
		fn = audiohd_set_beep;
		break;
	}

	pc->val = val;
	pc->ctrl = audio_dev_add_control(statep->adev, &desc,
	    audiohd_get_value, fn, pc);

	return (pc);
}

static void
audiohd_free_ctrl(audiohd_ctrl_t *pc)
{
	if (pc == NULL)
		return;
	if (pc->ctrl)
		audio_dev_del_control(pc->ctrl);
	kmem_free(pc, sizeof (*pc));
}

static void
audiohd_del_controls(audiohd_state_t *statep)
{
	int		i;
	for (i = 0; i < CTRL_NUM; i++) {
		if (statep->controls[i])
			audiohd_free_ctrl(statep->controls[i]);
	}
}

static int
audiohd_add_controls(audiohd_state_t *statep)
{
	int			i, j;
	audiohd_path_t		*path;
	wid_t			wid;
	audiohd_pin_t		*pin;
	audiohd_widget_t	*widget, *w;
	hda_codec_t		*codec;
	audiohd_pin_color_t	clr;

#define	ADD_CTRL(ID, VAL)	\
	if (statep->controls[ID] == NULL) \
		statep->controls[ID] = audiohd_alloc_ctrl(statep, ID, VAL);\
	if (statep->controls[ID] == NULL) {				\
		audio_dev_warn(statep->adev,				\
		    "Unable to allocate %s control", #ID);		\
		return (DDI_FAILURE);					\
	}

	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path || path->path_type != PLAY)
			continue;
		/*
		 * Firstly we check if all the DACs on the play paths
		 * have amplifiers. If any of them doesn't have, we just use
		 * the soft volume control to adjust the PCM volume.
		 */
		wid = path->adda_wid;
		w = path->codec->widget[wid];
		if (!w->outamp_cap) {
			(void) audio_dev_add_soft_volume(statep->adev);
			statep->soft_volume = B_TRUE;
			break;
		}
	}
	/*
	 * if all the DACs on the play paths have the amplifiers, we use DACs'
	 * amplifiers to adjust volume.
	 */
	if (!statep->soft_volume) {
		ADD_CTRL(CTL_VOLUME, 0x4b);
	}
	/* allocate other controls */
	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path)
			continue;
		codec = path->codec;
		if (path->path_type == BEEP) {
			widget = codec->widget[path->beep_wid];
			if (widget->type == WTYPE_BEEP &&
			    path->gain_wid != 0) {
				ADD_CTRL(CTL_BEEP, 0x4b4b);
				break;
			}
		}

		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			widget = codec->widget[wid];
			pin = (audiohd_pin_t *)widget->priv;
			if (pin->device == DTYPE_SPEAKER) {
				ADD_CTRL(CTL_SPEAKER, 0x4b4b);
			} else if (pin->device == DTYPE_HP_OUT) {
				ADD_CTRL(CTL_HEADPHONE, 0x4b4b);
			} else if (pin->device == DTYPE_LINE_IN) {
				ADD_CTRL(CTL_LINEIN, 0x3232);
			} else if (pin->device == DTYPE_MIC_IN) {
				ADD_CTRL(CTL_MIC, 0x3232);
			} else if (pin->device == DTYPE_CD) {
				ADD_CTRL(CTL_CD, 0x3232);
			}
			clr = (pin->config >> AUDIOHD_PIN_CLR_OFF) &
			    AUDIOHD_PIN_CLR_MASK;
			if (clr == AUDIOHD_PIN_GREEN) {
				ADD_CTRL(CTL_FRONT, 0x4b4b);
			} else if (clr == AUDIOHD_PIN_BLACK &&
			    pin->device != DTYPE_HP_OUT &&
			    pin->device != DTYPE_MIC_IN) {
				ADD_CTRL(CTL_REAR, 0x4b4b);
			} else if (clr == AUDIOHD_PIN_ORANGE) {
				ADD_CTRL(CTL_CENTER, 0x4b);
				ADD_CTRL(CTL_LFE, 0x4b);
			} else if (clr == AUDIOHD_PIN_GREY) {
				ADD_CTRL(CTL_SURROUND, 0x4b4b);
			}
		}
	}

	if (!statep->monitor_unsupported) {
		ADD_CTRL(CTL_MONGAIN, 0);
	}

	ADD_CTRL(CTL_RECSRC, (1U << DTYPE_MIC_IN));

	audiohd_configure_output(statep);
	audiohd_configure_input(statep);

	return (DDI_SUCCESS);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
audiohd_quiesce(dev_info_t *dip)
{
	audiohd_state_t		*statep;

	statep = ddi_get_driver_private(dip);

	audiohd_stop_dma(statep);
	audiohd_disable_intr(statep);

	return (DDI_SUCCESS);
}

static void
audiohd_beep_on(void *arg)
{
	hda_codec_t *codec = ((audiohd_widget_t *)arg)->codec;
	audiohd_state_t *statep = codec->soft_statep;
	int caddr = codec->index;
	wid_t wid = ((audiohd_widget_t *)arg)->wid_wid;

	(void) audioha_codec_verb_get(statep, caddr, wid,
	    AUDIOHDC_VERB_SET_BEEP_GEN, audiohd_beep_divider);
}

static void
audiohd_beep_off(void *arg)
{
	hda_codec_t *codec = ((audiohd_widget_t *)arg)->codec;
	audiohd_state_t *statep = codec->soft_statep;
	int caddr = codec->index;
	wid_t wid = ((audiohd_widget_t *)arg)->wid_wid;

	(void) audioha_codec_verb_get(statep, caddr, wid,
	    AUDIOHDC_VERB_SET_BEEP_GEN, AUDIOHDC_MUTE_BEEP_GEN);
}

static void
audiohd_beep_freq(void *arg, int freq)
{
	_NOTE(ARGUNUSED(arg));
	if (freq == 0) {
		audiohd_beep_divider = 0;
	} else {
		if (freq > AUDIOHDC_MAX_BEEP_GEN)
			freq = AUDIOHDC_MAX_BEEP_GEN;
		else if (freq < AUDIOHDC_MIX_BEEP_GEN)
			freq = AUDIOHDC_MIX_BEEP_GEN;
		audiohd_beep_divider = AUDIOHDC_SAMPR48000 / freq;
	}

	if (audiohd_beep_vol == 0)
		audiohd_beep_divider = 0;
}

/*
 * audiohd_init_state()
 *
 * Description
 *	This routine initailizes soft state of driver instance,
 *	also, it requests an interrupt cookie and initializes
 *	mutex for soft state.
 */
/*ARGSUSED*/
static int
audiohd_init_state(audiohd_state_t *statep, dev_info_t *dip)
{
	audio_dev_t			*adev;

	statep->hda_dip = dip;

	if ((adev = audio_dev_alloc(dip, 0)) == NULL) {
		cmn_err(CE_WARN, "unable to allocate audio dev");
		return (DDI_FAILURE);
	}
	statep->adev = adev;
	statep->intr_added = B_FALSE;
	statep->msi_enable = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "msi_enable", B_TRUE);

	/* set device information */
	audio_dev_set_description(adev, AUDIOHD_DEV_CONFIG);
	audio_dev_set_version(adev, AUDIOHD_DEV_VERSION);

	statep->hda_rirb_rp = 0;

	return (DDI_SUCCESS);
}	/* audiohd_init_state() */

/*
 * audiohd_init_pci()
 *
 * Description
 *	enable driver to access PCI configure space and memory
 *	I/O space.
 */
static int
audiohd_init_pci(audiohd_state_t *statep, ddi_device_acc_attr_t *acc_attr)
{
	uint16_t	cmdreg;
	uint16_t	vid;
	uint8_t		cTmp;
	dev_info_t	*dip = statep->hda_dip;
	audio_dev_t	*ahandle = statep->adev;

	if (pci_config_setup(dip, &statep->hda_pci_handle) == DDI_FAILURE) {
		audio_dev_warn(ahandle,
		    "pci config mapping failed");
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(dip, 1, &statep->hda_reg_base, 0,
	    0, acc_attr, &statep->hda_reg_handle) != DDI_SUCCESS) {
		audio_dev_warn(ahandle,
		    "memory I/O mapping failed");
		return (DDI_FAILURE);
	}

	/*
	 * HD audio control uses memory I/O only, enable it here.
	 */
	cmdreg = pci_config_get16(statep->hda_pci_handle, PCI_CONF_COMM);
	pci_config_put16(statep->hda_pci_handle, PCI_CONF_COMM,
	    cmdreg | PCI_COMM_MAE | PCI_COMM_ME);

	vid = pci_config_get16(statep->hda_pci_handle, PCI_CONF_VENID);
	switch (vid) {

	case AUDIOHD_VID_INTEL:
		/*
		 * Currently, Intel (G)MCH and ICHx chipsets support PCI
		 * Express QoS. It implemenets two VCs(virtual channels)
		 * and allows OS software to map 8 traffic classes to the
		 * two VCs. Some BIOSes initialize HD audio hardware to
		 * use TC7 (traffic class 7) and to map TC7 to VC1 as Intel
		 * recommended. However, solaris doesn't support PCI express
		 * QoS yet. As a result, this driver can not work for those
		 * hardware without touching PCI express control registers.
		 * Here, we set TCSEL to 0 so as to use TC0/VC0 (VC0 is
		 * always enabled and TC0 is always mapped to VC0) for all
		 * Intel HD audio controllers.
		 */
		cTmp = pci_config_get8(statep->hda_pci_handle,
		    AUDIOHD_INTEL_PCI_TCSEL);
		pci_config_put8(statep->hda_pci_handle,
		    AUDIOHD_INTEL_PCI_TCSEL, (cTmp & AUDIOHD_INTEL_TCS_MASK));
		break;

	case AUDIOHD_VID_ATI:
		/*
		 * Refer to ATI SB450 datesheet. We set snoop for SB450
		 * like hardware.
		 */
		cTmp = pci_config_get8(statep->hda_pci_handle,
		    AUDIOHD_ATI_PCI_MISC2);
		pci_config_put8(statep->hda_pci_handle, AUDIOHD_ATI_PCI_MISC2,
		    (cTmp & AUDIOHD_ATI_MISC2_MASK) | AUDIOHD_ATI_MISC2_SNOOP);
		break;
		/*
		 * Refer to the datasheet, we set snoop for NVIDIA
		 * like hardware
		 */
	case AUDIOHD_VID_NVIDIA:
		cTmp = pci_config_get8(statep->hda_pci_handle,
		    AUDIOHD_CORB_SIZE_OFF);
		pci_config_put8(statep->hda_pci_handle, AUDIOHD_CORB_SIZE_OFF,
		    cTmp | AUDIOHD_NVIDIA_SNOOP);
		break;

	default:
		break;
	}

	return (DDI_SUCCESS);
}	/* audiohd_init_pci() */


/*
 * audiohd_fini_pci()
 *
 * Description
 *	Release mapping for PCI configure space.
 */
static void
audiohd_fini_pci(audiohd_state_t *statep)
{
	if (statep->hda_reg_handle != NULL) {
		ddi_regs_map_free(&statep->hda_reg_handle);
		statep->hda_reg_handle = NULL;
	}

	if (statep->hda_pci_handle != NULL) {
		pci_config_teardown(&statep->hda_pci_handle);
		statep->hda_pci_handle = NULL;
	}

}	/* audiohd_fini_pci() */

/*
 * audiohd_stop_dma()
 *
 * Description
 *	Stop all DMA behaviors of controllers, for command I/O
 *	and each audio stream.
 */
static void
audiohd_stop_dma(audiohd_state_t *statep)
{
	int	i;
	uint_t	base;
	uint8_t	bTmp;

	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBCTL, 0);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBCTL, 0);

	base = AUDIOHD_REG_SD_BASE;
	for (i = 0; i < statep->hda_streams_nums; i++) {
		bTmp = AUDIOHD_REG_GET8(base + AUDIOHD_SDREG_OFFSET_CTL);

		/* for input/output stream, it is the same */
		bTmp &= ~AUDIOHDR_RIRBCTL_DMARUN;

		AUDIOHD_REG_SET8(base + AUDIOHD_SDREG_OFFSET_CTL, bTmp);
		base += AUDIOHD_REG_SD_LEN;
	}

	/* wait 40us for stream DMA to stop */
	drv_usecwait(40);

}	/* audiohd_stop_dma() */

/*
 * audiohd_reset_controller()
 *
 * Description:
 *	This routine is just used to reset controller and
 *	CODEC as well by HW reset bit in global control
 *	register of HD controller.
 */
static int
audiohd_reset_controller(audiohd_state_t *statep)
{
	int		i;
	uint16_t	sTmp;
	uint32_t	gctl;

	/* Reset Status register but preserve the first bit */
	sTmp = AUDIOHD_REG_GET16(AUDIOHD_REG_STATESTS);
	AUDIOHD_REG_SET16(AUDIOHD_REG_STATESTS, sTmp & 0x8000);

	/* reset controller */
	gctl = AUDIOHD_REG_GET32(AUDIOHD_REG_GCTL);
	gctl &= ~AUDIOHDR_GCTL_CRST;
	AUDIOHD_REG_SET32(AUDIOHD_REG_GCTL, gctl);  /* entering reset state */
	for (i = 0; i < AUDIOHD_RETRY_TIMES; i++) {
		/* Empirical testing time: 150 */
		drv_usecwait(150);
		gctl = AUDIOHD_REG_GET32(AUDIOHD_REG_GCTL);
		if ((gctl & AUDIOHDR_GCTL_CRST) == 0)
			break;
	}

	if ((gctl & AUDIOHDR_GCTL_CRST) != 0) {
		audio_dev_warn(statep->adev,
		    "failed to enter reset state");
		return (DDI_FAILURE);
	}

	/* Empirical testing time:300 */
	drv_usecwait(300);

	/* exit reset state */
	AUDIOHD_REG_SET32(AUDIOHD_REG_GCTL, gctl | AUDIOHDR_GCTL_CRST);

	for (i = 0; i < AUDIOHD_RETRY_TIMES; i++) {
		/* Empirical testing time: 150, which works well */
		drv_usecwait(150);
		gctl = AUDIOHD_REG_GET32(AUDIOHD_REG_GCTL);
		if (gctl & AUDIOHDR_GCTL_CRST)
			break;
	}

	if ((gctl & AUDIOHDR_GCTL_CRST) == 0) {
		audio_dev_warn(statep->adev,
		    "failed to exit reset state");
		return (DDI_FAILURE);
	}

	/* HD spec requires to wait 250us at least. we use 500us */
	drv_usecwait(500);

	/* enable unsolicited response */
	AUDIOHD_REG_SET32(AUDIOHD_REG_GCTL,
	    gctl |  AUDIOHDR_GCTL_URESPE);

	return (DDI_SUCCESS);

}	/* audiohd_reset_controller() */

/*
 * audiohd_alloc_dma_mem()
 *
 * Description:
 *	This is an utility routine. It is used to allocate DMA
 *	memory.
 */
static int
audiohd_alloc_dma_mem(audiohd_state_t *statep, audiohd_dma_t *pdma,
    size_t memsize, ddi_dma_attr_t *dma_attr_p, uint_t dma_flags)
{
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	dev_info_t		*dip = statep->hda_dip;
	audio_dev_t		*ahandle = statep->adev;

	if (ddi_dma_alloc_handle(dip, dma_attr_p, DDI_DMA_SLEEP,
	    NULL, &pdma->ad_dmahdl) != DDI_SUCCESS) {
		audio_dev_warn(ahandle,
		    "ddi_dma_alloc_handle failed");
		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(pdma->ad_dmahdl, memsize, &hda_dev_accattr,
	    dma_flags & (DDI_DMA_CONSISTENT | DDI_DMA_STREAMING),
	    DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&pdma->ad_vaddr, &pdma->ad_real_sz,
	    &pdma->ad_acchdl) != DDI_SUCCESS) {
		audio_dev_warn(ahandle,
		    "ddi_dma_mem_alloc failed");
		return (DDI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(pdma->ad_dmahdl, NULL,
	    (caddr_t)pdma->ad_vaddr, pdma->ad_real_sz, dma_flags,
	    DDI_DMA_SLEEP, NULL, &cookie, &count) != DDI_DMA_MAPPED) {
		audio_dev_warn(ahandle,
		    "ddi_dma_addr_bind_handle failed");
		return (DDI_FAILURE);
	}

	pdma->ad_paddr = (uint64_t)(cookie.dmac_laddress);
	pdma->ad_req_sz = memsize;

	return (DDI_SUCCESS);
}	/* audiohd_alloc_dma_mem() */

/*
 * audiohd_release_dma_mem()
 *
 * Description:
 *	Release DMA memory.
 */

static void
audiohd_release_dma_mem(audiohd_dma_t *pdma)
{
	if (pdma->ad_dmahdl != NULL) {
		(void) ddi_dma_unbind_handle(pdma->ad_dmahdl);
	}

	if (pdma->ad_acchdl != NULL) {
		ddi_dma_mem_free(&pdma->ad_acchdl);
		pdma->ad_acchdl = NULL;
	}

	if (pdma->ad_dmahdl != NULL) {
		ddi_dma_free_handle(&pdma->ad_dmahdl);
		pdma->ad_dmahdl = NULL;
	}

}	/* audiohd_release_dma_mem() */

/*
 * audiohd_reinit_hda()
 *
 * Description:
 *	This routine is used to re-initialize HD controller and codec.
 */
static int
audiohd_reinit_hda(audiohd_state_t *statep)
{
	uint64_t	addr;

	/* set PCI configure space in case it's not restored OK */
	(void) audiohd_init_pci(statep, &hda_dev_accattr);

	/* reset controller */
	if (audiohd_reset_controller(statep) != DDI_SUCCESS)
		return (DDI_FAILURE);
	AUDIOHD_REG_SET32(AUDIOHD_REG_SYNC, 0); /* needn't sync stream */

	/* Initialize controller RIRB */
	addr = statep->hda_dma_rirb.ad_paddr;
	AUDIOHD_REG_SET32(AUDIOHD_REG_RIRBLBASE, (uint32_t)addr);
	AUDIOHD_REG_SET32(AUDIOHD_REG_RIRBUBASE,
	    (uint32_t)(addr >> 32));
	AUDIOHD_REG_SET16(AUDIOHD_REG_RIRBWP, AUDIOHDR_RIRBWP_RESET);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBSIZE, AUDIOHDR_RIRBSZ_256);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBCTL, AUDIOHDR_RIRBCTL_DMARUN |
	    AUDIOHDR_RIRBCTL_RINTCTL);

	/* Initialize controller CORB */
	addr = statep->hda_dma_corb.ad_paddr;
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBRP, AUDIOHDR_CORBRP_RESET);
	AUDIOHD_REG_SET32(AUDIOHD_REG_CORBLBASE, (uint32_t)addr);
	AUDIOHD_REG_SET32(AUDIOHD_REG_CORBUBASE,
	    (uint32_t)(addr >> 32));
	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBSIZE, AUDIOHDR_CORBSZ_256);
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBWP, 0);
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBRP, 0);
	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBCTL, AUDIOHDR_CORBCTL_DMARUN);

	audiohd_restore_codec_gpio(statep);
	audiohd_restore_path(statep);
	audiohd_init_path(statep);

	return (DDI_SUCCESS);
}	/* audiohd_reinit_hda */

/*
 * audiohd_init_controller()
 *
 * Description:
 *	This routine is used to initialize HD controller. It
 *	allocates DMA memory for CORB/RIRB, buffer descriptor
 *	list and cylic data buffer for both play and record
 *	stream.
 */
static int
audiohd_init_controller(audiohd_state_t *statep)
{
	uint64_t	addr;
	uint16_t	gcap;
	int		retval;

	ddi_dma_attr_t	dma_attr = {
		DMA_ATTR_V0,		/* version */
		0,			/* addr_lo */
		0xffffffffffffffffULL,	/* addr_hi */
		0x00000000ffffffffULL,	/* count_max */
		128,			/* 128-byte alignment as HD spec */
		0xfff,			/* burstsize */
		1,			/* minxfer */
		0xffffffff,		/* maxxfer */
		0xffffffff,		/* seg */
		1,			/* sgllen */
		1,			/* granular */
		0			/* flags */
	};

	gcap = AUDIOHD_REG_GET16(AUDIOHD_REG_GCAP);

	/*
	 * If the device doesn't support 64-bit DMA, we should not
	 * allocate DMA memory from 4G above
	 */
	if ((gcap & AUDIOHDR_GCAP_64OK) == 0)
		dma_attr.dma_attr_addr_hi = 0xffffffffUL;

	statep->hda_input_streams = (gcap & AUDIOHDR_GCAP_INSTREAMS) >>
	    AUDIOHD_INSTR_NUM_OFF;
	statep->hda_output_streams = (gcap & AUDIOHDR_GCAP_OUTSTREAMS) >>
	    AUDIOHD_OUTSTR_NUM_OFF;
	statep->hda_streams_nums = statep->hda_input_streams +
	    statep->hda_output_streams;


	statep->hda_record_regbase = AUDIOHD_REG_SD_BASE;
	statep->hda_play_regbase = AUDIOHD_REG_SD_BASE + AUDIOHD_REG_SD_LEN *
	    statep->hda_input_streams;


	/* stop all dma before starting to reset controller */
	audiohd_stop_dma(statep);

	if (audiohd_reset_controller(statep) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* check codec */
	statep->hda_codec_mask = AUDIOHD_REG_GET16(AUDIOHD_REG_STATESTS);
	if (!statep->hda_codec_mask) {
		audio_dev_warn(statep->adev,
		    "no codec exists");
		return (DDI_FAILURE);
	}

	/* allocate DMA for CORB */
	retval = audiohd_alloc_dma_mem(statep, &statep->hda_dma_corb,
	    AUDIOHD_CDBIO_CORB_LEN, &dma_attr,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING);
	if (retval != DDI_SUCCESS) {
		audio_dev_warn(statep->adev,
		    "failed to alloc DMA for CORB");
		return (DDI_FAILURE);
	}

	/* allocate DMA for RIRB */
	retval = audiohd_alloc_dma_mem(statep, &statep->hda_dma_rirb,
	    AUDIOHD_CDBIO_RIRB_LEN, &dma_attr,
	    DDI_DMA_READ | DDI_DMA_STREAMING);
	if (retval != DDI_SUCCESS) {
		audio_dev_warn(statep->adev,
		    "failed to alloc DMA for RIRB");
		return (DDI_FAILURE);
	}


	AUDIOHD_REG_SET32(AUDIOHD_REG_SYNC, 0); /* needn't sync stream */

	/* Initialize RIRB */
	addr = statep->hda_dma_rirb.ad_paddr;
	AUDIOHD_REG_SET32(AUDIOHD_REG_RIRBLBASE, (uint32_t)addr);
	AUDIOHD_REG_SET32(AUDIOHD_REG_RIRBUBASE,
	    (uint32_t)(addr >> 32));
	AUDIOHD_REG_SET16(AUDIOHD_REG_RIRBWP, AUDIOHDR_RIRBWP_RESET);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBSIZE, AUDIOHDR_RIRBSZ_256);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBCTL, AUDIOHDR_RIRBCTL_DMARUN |
	    AUDIOHDR_RIRBCTL_RINTCTL);

	/* initialize CORB */
	addr = statep->hda_dma_corb.ad_paddr;
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBRP, AUDIOHDR_CORBRP_RESET);
	AUDIOHD_REG_SET32(AUDIOHD_REG_CORBLBASE, (uint32_t)addr);
	AUDIOHD_REG_SET32(AUDIOHD_REG_CORBUBASE,
	    (uint32_t)(addr >> 32));
	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBSIZE, AUDIOHDR_CORBSZ_256);
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBWP, 0);
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBRP, 0);
	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBCTL, AUDIOHDR_CORBCTL_DMARUN);

	/* work around for some chipsets which could not enable MSI */
	switch (statep->devid) {
	case AUDIOHD_CONTROLLER_MCP51:
		statep->msi_enable = B_FALSE;
		break;
	default:
		break;
	}

	return (DDI_SUCCESS);
}	/* audiohd_init_controller() */

/*
 * audiohd_fini_controller()
 *
 * Description:
 *	Releases DMA memory allocated in audiohd_init_controller()
 */
static void
audiohd_fini_controller(audiohd_state_t *statep)
{
	audiohd_stop_dma(statep);
	audiohd_release_dma_mem(&statep->hda_dma_rirb);
	audiohd_release_dma_mem(&statep->hda_dma_corb);

}	/* audiohd_fini_controller() */

/*
 * audiohd_get_conns_from_entry()
 *
 * Description:
 *	Get connection list from every entry for a widget
 */
static void
audiohd_get_conns_from_entry(hda_codec_t *codec, audiohd_widget_t *widget,
    uint32_t entry, audiohd_entry_prop_t *prop)
{
	int	i, k, num;
	wid_t	input_wid;

	for (i = 0; i < prop->conns_per_entry &&
	    widget->nconns < prop->conn_len;
	    i++, entry >>= prop->bits_per_conn) {
		ASSERT(widget->nconns < AUDIOHD_MAX_CONN);
		input_wid = entry & prop->mask_wid;
		if (entry & prop->mask_range) {
			if (widget->nconns == 0) {
				if (input_wid < codec->first_wid ||
				    (input_wid > codec->last_wid)) {
					break;
				}
				widget->avail_conn[widget->nconns++] =
				    input_wid;
			} else {
				for (k = widget->avail_conn[widget->nconns-1] +
				    1; k <= input_wid; k++) {
					ASSERT(widget->nconns <
					    AUDIOHD_MAX_CONN);
					if (k < codec->first_wid ||
					    (k > codec->last_wid)) {
						break;
					} else {
						num = widget->nconns;
						widget->avail_conn[num] = k;
						widget->nconns++;
					}
				}
			}
		} else {
			if ((codec->first_wid <= input_wid) && (input_wid <=
			    codec->last_wid))
				widget->avail_conn[widget->nconns++] =
				    input_wid;
		}
	}
}

/*
 * audiohd_get_conns()
 *
 * Description:
 *	Get all connection list for a widget. The connection list is used for
 *	build output path, input path, and monitor path
 */
static void
audiohd_get_conns(hda_codec_t *codec, wid_t wid)
{
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_widget_t	*widget = codec->widget[wid];
	uint8_t	caddr = codec->index;
	uint32_t	entry;
	audiohd_entry_prop_t	prop;
	wid_t	input_wid;
	int	i;

	prop.conn_len = audioha_codec_verb_get(statep, caddr, wid,
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_CONNLIST_LEN);

	if (prop.conn_len & AUDIOHD_FORM_MASK) {
		prop.conns_per_entry = 2;
		prop.bits_per_conn = 16;
		prop.mask_range = 0x00008000;
		prop.mask_wid = 0x00007fff;
	} else {
		prop.conns_per_entry = 4;
		prop.bits_per_conn = 8;
		prop.mask_range = 0x00000080;
		prop.mask_wid = 0x0000007f;
	}
	prop.conn_len &= AUDIOHD_LEN_MASK;

	/*
	 * This should not happen since the ConnectionList bit of
	 * widget capabilities already told us that this widget
	 * has a connection list
	 */
	if (prop.conn_len == 0) {
		widget->nconns = 0;
		cmn_err(CE_WARN, "node %d has 0 connections\n", wid);
		return;
	}

	if (prop.conn_len == 1) {
		entry = audioha_codec_verb_get(statep, caddr,
		    wid, AUDIOHDC_VERB_GET_CONN_LIST_ENT, 0);
		input_wid = entry & prop.mask_wid;
		if ((input_wid < codec->first_wid) ||
		    (input_wid > codec->last_wid)) {
			return;
		}
		widget->avail_conn[0] = input_wid;
		widget->nconns = 1;
		return;
	}
	widget->nconns = 0;
	for (i = 0; i < prop.conn_len; i += prop.conns_per_entry) {
		entry = audioha_codec_verb_get(statep, caddr, wid,
		    AUDIOHDC_VERB_GET_CONN_LIST_ENT, i);
		audiohd_get_conns_from_entry(codec, widget, entry, &prop);
	}
}

/*
 * Read PinCapabilities & default configuration
 */
static void
audiohd_get_pin_config(audiohd_widget_t *widget)
{
	hda_codec_t		*codec = widget->codec;
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_pin_t		*pin, *prev, *p;

	int		caddr = codec->index;
	wid_t		wid = widget->wid_wid;
	uint32_t	cap, config, pinctrl;
	uint8_t		urctrl, vrefbits;

	cap = audioha_codec_verb_get(statep, caddr, wid,
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_PIN_CAP);
	config = audioha_codec_verb_get(statep, caddr,
	    wid, AUDIOHDC_VERB_GET_DEFAULT_CONF, 0);
	pinctrl = audioha_codec_verb_get(statep, caddr,
	    wid, AUDIOHDC_VERB_GET_PIN_CTRL, 0);

	pin = (audiohd_pin_t *)kmem_zalloc(sizeof (audiohd_pin_t), KM_SLEEP);
	widget->priv = pin;

	/*
	 * If the pin has no physical connection for port,
	 * we won't link it to pin linkage list ???
	 */
	if (((config >> AUDIOHD_PIN_CON_STEP) & AUDIOHD_PIN_CON_MASK) == 0x1) {
		pin->no_phys_conn = 1;
	}

	/* bit 4:3 are reserved, read-modify-write is needed */
	pin->ctrl = pinctrl & AUDIOHD_PIN_IO_MASK;
	pin->wid = wid;
	pin->cap = cap;
	pin->config = config;
	pin->num = 0;
	pin->finish = 0;

	vrefbits = (cap >> AUDIOHD_PIN_VREF_OFF) & AUDIOHD_PIN_VREF_MASK;
	if (vrefbits & AUDIOHD_PIN_VREF_L1)
		pin->vrefvalue = 0x5;
	else if (vrefbits & AUDIOHD_PIN_VREF_L2)
		pin->vrefvalue = 0x4;
	else if (vrefbits & AUDIOHD_PIN_VREF_L3)
		pin->vrefvalue = 0x2;
	else
		pin->vrefvalue = 0x1;

	pin->seq = config & AUDIOHD_PIN_SEQ_MASK;
	pin->assoc = (config & AUDIOHD_PIN_ASO_MASK) >> AUDIOHD_PIN_ASO_OFF;
	pin->device = (config & AUDIOHD_PIN_DEV_MASK) >> AUDIOHD_PIN_DEV_OFF;

	/* enable the unsolicited response of the pin */
	if ((widget->widget_cap & AUDIOHD_URCAP_MASK) &&
	    (pin->cap & AUDIOHD_DTCCAP_MASK) &&
	    ((pin->device == DTYPE_LINEOUT) ||
	    (pin->device == DTYPE_SPDIF_OUT) ||
	    (pin->device == DTYPE_HP_OUT) ||
	    (pin->device == DTYPE_MIC_IN))) {
			urctrl = (uint8_t)(1 << (AUDIOHD_UR_ENABLE_OFF - 1));
			urctrl |= (wid & AUDIOHD_UR_TAG_MASK);
			(void) audioha_codec_verb_get(statep, caddr,
			    wid, AUDIOHDC_VERB_SET_URCTRL, urctrl);
	}
	/* accommodate all the pins in a link list sorted by assoc and seq */
	if (codec->first_pin == NULL) {
		codec->first_pin = pin;
	} else {
		prev = NULL;
		p = codec->first_pin;
		while (p) {
			if (p->assoc > pin->assoc)
				break;
			if ((p->assoc == pin->assoc) &&
			    (p->seq > pin->seq))
				break;
			prev = p;
			p = p->next;
		}
		if (prev) {
			pin->next = prev->next;
			prev->next = pin;
		} else {
			pin->next = codec->first_pin;
			codec->first_pin = pin;
		}
	}

}	/* audiohd_get_pin_config() */

/*
 * audiohd_create_widgets()
 *
 * Description:
 *	All widgets are created and stored in an array of codec
 */
static int
audiohd_create_widgets(hda_codec_t *codec)
{
	audiohd_widget_t	*widget;
	audiohd_state_t		*statep = codec->soft_statep;
	wid_t	wid;
	uint32_t	type, widcap;
	int		caddr = codec->index;

	for (wid = codec->first_wid;
	    wid <= codec->last_wid; wid++) {
		widget = (audiohd_widget_t *)
		    kmem_zalloc(sizeof (audiohd_widget_t), KM_SLEEP);
		codec->widget[wid] = widget;
		widget->codec = codec;
		widget->selconn = AUDIOHD_NULL_CONN;

		widcap = audioha_codec_verb_get(statep, caddr, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AUDIO_WID_CAP);
		type = AUDIOHD_WIDCAP_TO_WIDTYPE(widcap);
		widget->wid_wid = wid;
		widget->type = type;
		widget->widget_cap = widcap;
		widget->finish = 0;
		widget->used = 0;

		/* if there's connection list */
		if (widcap & AUDIOHD_WIDCAP_CONNLIST) {
			audiohd_get_conns(codec, wid);
		}

		/* if power control, power it up to D0 state */
		if (widcap & AUDIOHD_WIDCAP_PWRCTRL) {
			(void) audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_SET_POWER_STATE, 0);
		}

		/*
		 * if this widget has format override, we read it.
		 * Otherwise, it uses the format of audio function.
		 */
		if (widcap & AUDIOHD_WIDCAP_FMT_OVRIDE) {
			widget->pcm_format =
			    audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_PCM);
		} else {
			widget->pcm_format = codec->pcm_format;
		}

		/*
		 * Input amplifier. Has the widget input amplifier ?
		 */
		if (widcap & AUDIOHD_WIDCAP_INAMP) {
			/*
			 * if overrided bit is 0, use the default
			 * amplifier of audio function as HD spec.
			 * Otherwise, we read it.
			 */
			if ((widcap & AUDIOHD_WIDCAP_AMP_OVRIDE) == 0)
				widget->inamp_cap = codec->inamp_cap;
			else
				widget->inamp_cap =
				    audioha_codec_verb_get(statep, caddr, wid,
				    AUDIOHDC_VERB_GET_PARAM,
				    AUDIOHDC_PAR_INAMP_CAP);
		} else {
			widget->inamp_cap = 0;
		}

		/*
		 * output amplifier. Has this widget output amplifier ?
		 */
		if (widcap & AUDIOHD_WIDCAP_OUTAMP) {
			if ((widcap & AUDIOHD_WIDCAP_AMP_OVRIDE) == 0)
				widget->outamp_cap = codec->outamp_cap;
			else
				widget->outamp_cap =
				    audioha_codec_verb_get(statep, caddr, wid,
				    AUDIOHDC_VERB_GET_PARAM,
				    AUDIOHDC_PAR_OUTAMP_CAP);
		} else {
			widget->outamp_cap = 0;
		}

		switch (type) {
		case WTYPE_AUDIO_OUT:
		case WTYPE_AUDIO_IN:
		case WTYPE_AUDIO_MIX:
		case WTYPE_AUDIO_SEL:
		case WTYPE_VENDOR:
		case WTYPE_POWER:
		case WTYPE_VOL_KNOB:
			break;
		case WTYPE_PIN:
			audiohd_get_pin_config(widget);
			break;
		case WTYPE_BEEP:
			/*
			 * Get the audiohd_beep_switch value from audiohd.conf,
			 * which is for turning on/off widget beep.
			 */
			audiohd_beep = ddi_prop_get_int(DDI_DEV_T_ANY,
			    statep->hda_dip,
			    DDI_PROP_DONTPASS, "audiohd_beep", 1);

			if (audiohd_beep) {
				(void) beep_fini();
				(void) beep_init((void *) widget,
				    audiohd_beep_on,
				    audiohd_beep_off,
				    audiohd_beep_freq);
			}
			break;
		default:
			break;
		}
	}

	return (DDI_SUCCESS);

}	/* audiohd_create_widgets() */

/*
 * audiohd_destroy_widgets()
 */
static void
audiohd_destroy_widgets(hda_codec_t *codec)
{
	for (int i = 0; i < AUDIOHD_MAX_WIDGET; i++) {
		if (codec->widget[i]) {
			kmem_free(codec->widget[i], sizeof (audiohd_widget_t));
			codec->widget[i] = NULL;
		}
	}

}	/* audiohd_destroy_widgets() */

static void
audiohd_set_codec_info(hda_codec_t *codec)
{
	char buf[256];

	switch (codec->vid) {
	case 0x10ec0260:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC260");
		break;
	case 0x10ec0262:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC262");
		break;
	case 0x10ec0268:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC268");
		break;
	case 0x10ec0662:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC662");
		break;
	case 0x10ec0663:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC663");
		break;
	case 0x10ec861:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC861");
		break;
	case 0x10ec0862:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC862");
		break;
	case 0x10ec0880:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC880");
		break;
	case 0x10ec0882:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC882");
		break;
	case 0x10ec0883:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC883");
		break;
	case 0x10ec0885:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC885");
		break;
	case 0x10ec0888:
		(void) snprintf(buf, sizeof (buf), "Realtek HD codec: ALC888");
		break;
	case 0x10de0007:
		(void) snprintf(buf, sizeof (buf),
		    "nVidia HD codec: MCP7A HDMI");
		break;
	case 0x13f69880:
		(void) snprintf(buf, sizeof (buf), "CMedia HD codec: CMI19880");
		break;
	case 0x434d4980:
		(void) snprintf(buf, sizeof (buf), "CMedia HD codec: CMI19880");
		break;
	case 0x11d41981:
		(void) snprintf(buf, sizeof (buf),
		    "Analog Devices HD codec: AD1981");
		break;
	case 0x11d41983:
		(void) snprintf(buf, sizeof (buf),
		    "Analog Devices HD codec: AD1983");
		break;
	case 0x11d41984:
		(void) snprintf(buf, sizeof (buf),
		    "Analog Devices HD codec: AD1984");
		break;
	case 0x11d41986:
		(void) snprintf(buf, sizeof (buf),
		    "Analog Devices HD codec: AD1986A");
		break;
	case 0x11d41988:
		(void) snprintf(buf, sizeof (buf),
		    "Analog Devices HD codec: AD1988A");
		break;
	case 0x11d4198b:
		(void) snprintf(buf, sizeof (buf),
		    "Analog Devices HD codec: AD1988B");
		break;
	case 0x83847690:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9200");
		break;
	case 0x838476a0:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9205");
		break;
	case 0x838476a1:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9205D");
		break;
	case 0x838476a2:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9204");
		break;
	case 0x838476a3:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9204D");
		break;
	case 0x83847880:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9220 A1");
		break;
	case 0x83847882:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9220 A2");
		break;
	case 0x83847680:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9221 A1");
		break;
	case 0x83847681:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9220 D");
		break;
	case 0x83847682:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9221");
		break;
	case 0x83847683:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9221D");
		break;
	case 0x83847610:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9230XN");
		break;
	case 0x83847611:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9230DN");
		break;
	case 0x83847612:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9230XT");
		break;
	case 0x83847613:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9230DT");
		break;
	case 0x83847614:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9229X");
		break;
	case 0x83847615:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9229D");
		break;
	case 0x83847616:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9228X");
		break;
	case 0x83847617:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9228D");
		break;
	case 0x83847618:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9227X");
		break;
	case 0x83847619:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9227D");
		break;
	case 0x838476a4:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9255");
		break;
	case 0x838476a5:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9255D");
		break;
	case 0x838476a6:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9254");
		break;
	case 0x838476a7:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9254D");
		break;
	case 0x83847620:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9274");
		break;
	case 0x83847621:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9274D");
		break;
	case 0x83847622:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9273X");
		break;
	case 0x83847623:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9273D");
		break;
	case 0x83847624:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9272X");
		break;
	case 0x83847625:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9272D");
		break;
	case 0x83847626:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9271X");
		break;
	case 0x83847627:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9271D");
		break;
	case 0x83847628:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9274X5NH");
		break;
	case 0x83847629:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9274D5NH");
		break;
	case 0x83847662:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9872AK");
		break;
	case 0x83847664:
		(void) snprintf(buf, sizeof (buf),
		    "Sigmatel HD codec: STAC9872K");
		break;
	default:
		(void) snprintf(buf, sizeof (buf),
		    "Unknown HD codec: 0x%x", codec->vid);
		break;

	}
	audio_dev_add_info(codec->soft_statep->adev, buf);
}
/*
 * audiohd_create_codec()
 *
 * Description:
 *	Searching for supported CODEC. If find, allocate memory
 *	to hold codec structure.
 */
static int
audiohd_create_codec(audiohd_state_t *statep)
{
	hda_codec_t	*codec;
	uint32_t	mask, type;
	uint32_t	nums;
	uint32_t	i, j;
	wid_t		wid;

	mask = statep->hda_codec_mask;
	ASSERT(mask != 0);

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if ((mask & (1 << i)) == 0)
			continue;
		codec = (hda_codec_t *)kmem_zalloc(
		    sizeof (hda_codec_t), KM_SLEEP);
		codec->index = i;
		codec->vid = audioha_codec_verb_get(statep, i,
		    AUDIOHDC_NODE_ROOT, AUDIOHDC_VERB_GET_PARAM,
		    AUDIOHDC_PAR_VENDOR_ID);
		codec->revid =
		    audioha_codec_verb_get(statep, i,
		    AUDIOHDC_NODE_ROOT, AUDIOHDC_VERB_GET_PARAM,
		    AUDIOHDC_PAR_REV_ID);

		nums = audioha_codec_verb_get(statep,
		    i, AUDIOHDC_NODE_ROOT,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_NODE_COUNT);
		if (nums == (uint32_t)(-1)) {
			kmem_free(codec, sizeof (hda_codec_t));
			continue;
		}
		wid = (nums >> AUDIOHD_CODEC_STR_OFF) & AUDIOHD_CODEC_STR_MASK;
		nums = nums & AUDIOHD_CODEC_NUM_MASK;

		/*
		 * Assume that each codec has just one audio function group
		 */
		for (j = 0; j < nums; j++, wid++) {
			type = audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_GET_PARAM,
			    AUDIOHDC_PAR_FUNCTION_TYPE);
			if ((type & AUDIOHD_CODEC_TYPE_MASK) ==
			    AUDIOHDC_AUDIO_FUNC_GROUP) {
				codec->wid_afg = wid;
				break;
			}
		}

		if (codec->wid_afg == 0) {
			kmem_free(codec, sizeof (hda_codec_t));
			continue;
		}

		ASSERT(codec->wid_afg == wid);

		/* work around for Sony VAIO laptop with specific codec */
		if ((codec->vid != AUDIOHD_CODECID_SONY1) &&
		    (codec->vid != AUDIOHD_CODECID_SONY2)) {
			/*
			 * GPIO controls which are laptop specific workarounds
			 * and might be changed. Some laptops use GPIO,
			 * so we need to enable and set the GPIO correctly.
			 */
			(void) audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_SET_GPIO_MASK, AUDIOHDC_GPIO_ENABLE);
			(void) audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_SET_GPIO_DIREC, AUDIOHDC_GPIO_DIRECT);
			(void) audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_SET_GPIO_STCK,
			    AUDIOHDC_GPIO_DATA_CTRL);
			(void) audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_SET_GPIO_DATA,
			    AUDIOHDC_GPIO_STCK_CTRL);
		}

		/* power-up audio function group */
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_POWER_STATE, 0);

		/* subsystem id is attached to funtion group */
		codec->outamp_cap = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_OUTAMP_CAP);
		codec->inamp_cap = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_INAMP_CAP);
		codec->stream_format = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_STREAM);
		codec->pcm_format = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_PCM);

		nums = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM,
		    AUDIOHDC_PAR_NODE_COUNT);
		wid = (nums >> AUDIOHD_CODEC_STR_OFF) & AUDIOHD_CODEC_STR_MASK;
		nums = nums & AUDIOHD_CODEC_NUM_MASK;
		codec->first_wid = wid;
		codec->last_wid = wid + nums;
		codec->nnodes = nums;

		/*
		 * We output the codec information to syslog
		 */
		statep->codec[i] = codec;
		codec->soft_statep = statep;
		audiohd_set_codec_info(codec);
		(void) audiohd_create_widgets(codec);
	}

	return (DDI_SUCCESS);

}	/* audiohd_create_codec() */

/*
 * audiohd_destroy_codec()
 *
 * Description:
 *	destroy codec structure, and release its memory
 */
static void
audiohd_destroy_codec(audiohd_state_t *statep)
{
	int			i;
	audiohd_pin_t		*pin, *npin;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if (statep->codec[i]) {
			audiohd_destroy_widgets(statep->codec[i]);
			/*
			 * free pins
			 */
			pin = statep->codec[i]->first_pin;
			while (pin) {
				npin = pin;
				pin = pin->next;
				kmem_free(npin, sizeof (audiohd_pin_t));
			}

			kmem_free(statep->codec[i], sizeof (hda_codec_t));
			statep->codec[i] = NULL;
		}
	}
}	/* audiohd_destroy_codec() */

/*
 * audiohd_find_dac()
 * Description:
 *	Find a dac for a output path. Then the play data can be sent to the out
 *	put pin through the output path.
 *
 * Arguments:
 *	hda_codec_t	*codec		where the dac widget exists
 *	wid_t		wid		the no. of a widget
 *	int		mixer		whether the path need mixer or not
 *	int		*mixernum	the total of mixer in the output path
 *	int		exclusive	an exclusive path or share path
 *	int		depth		the depth of search
 *
 * Return:
 *	1) wid of the first shared widget in the path from
 *	   pin to DAC if exclusive is 0;
 *	2) wid of DAC widget;
 *	3) 0 if no path
 */
static wid_t
audiohd_find_dac(hda_codec_t *codec, wid_t wid,
    int mixer, int *mixernum,
    int exclusive, int depth)
{
	audiohd_widget_t	*widget = codec->widget[wid];
	wid_t	wdac = (uint32_t)(DDI_FAILURE);
	wid_t	retval;

	if (depth > AUDIOHD_MAX_DEPTH)
		return (uint32_t)(DDI_FAILURE);

	if (widget == NULL)
		return (uint32_t)(DDI_FAILURE);

	/*
	 * If exclusive is true, we try to find a path which doesn't
	 * share any widget with other paths.
	 */
	if (exclusive) {
		if (widget->path_flags & AUDIOHD_PATH_DAC)
			return (uint32_t)(DDI_FAILURE);
	} else {
		if (widget->path_flags & AUDIOHD_PATH_DAC)
			return (wid);
	}

	switch (widget->type) {
	case WTYPE_AUDIO_OUT:
		/* We need mixer widget, but the the mixer num is 0, failed  */
		if (mixer && !*mixernum)
			return (uint32_t)(DDI_FAILURE);
		widget->path_flags |= AUDIOHD_PATH_DAC;
		widget->out_weight++;
		wdac = widget->wid_wid;
		break;

	case WTYPE_AUDIO_MIX:
	case WTYPE_AUDIO_SEL:
		if (widget->type == WTYPE_AUDIO_MIX)
			(*mixernum)++;
		for (int i = 0; i < widget->nconns; i++) {
			retval = audiohd_find_dac(codec,
			    widget->avail_conn[i],
			    mixer, mixernum,
			    exclusive, depth + 1);
			if (retval != (uint32_t)DDI_FAILURE) {
				if (widget->selconn == AUDIOHD_NULL_CONN) {
					widget->selconn = i;
					wdac = retval;
				}
				widget->path_flags |= AUDIOHD_PATH_DAC;
				widget->out_weight++;

				/* return when found a path */
				return (wdac);
			}
		}
	default:
		break;
	}

	return (wdac);
}	/* audiohd_find_dac() */

/*
 * audiohd_do_build_output_path()
 *
 * Description:
 *	Search an output path for each pin in the codec.
 * Arguments:
 *	hda_codec_t	*codec		where the output path exists
 *	int		mixer		wheter the path needs mixer widget
 *	int		*mnum		total of mixer widget in the path
 *	int		exclusive	an exclusive path or shared path
 *	int		depth		search depth
 */
static void
audiohd_do_build_output_path(hda_codec_t *codec, int mixer, int *mnum,
    int exclusive, int depth)
{
	audiohd_pin_t		*pin;
	audiohd_widget_t	*widget, *wdac;
	audiohd_path_t	*path;
	wid_t			wid;
	audiohd_state_t	*statep;
	int			i;

	statep = codec->soft_statep;

	for (pin = codec->first_pin; pin; pin = pin->next) {
		if ((pin->cap & AUDIOHD_PIN_CAP_MASK) == 0)
			continue;
		if ((pin->config & AUDIOHD_PIN_CONF_MASK) ==
		    AUDIOHD_PIN_NO_CONN)
			continue;
		if ((pin->device != DTYPE_LINEOUT) &&
		    (pin->device != DTYPE_SPEAKER) &&
		    (pin->device != DTYPE_SPDIF_OUT) &&
		    (pin->device != DTYPE_HP_OUT))
			continue;
		if (pin->finish)
			continue;
		widget = codec->widget[pin->wid];

		widget->inamp_cap = 0;
		for (i = 0; i < widget->nconns; i++) {
			/*
			 * If a dac found, the return value is the wid of the
			 * widget on the path, or the return value is
			 * DDI_FAILURE
			 */
			wid = audiohd_find_dac(codec,
			    widget->avail_conn[i], mixer, mnum, exclusive,
			    depth);
			/*
			 * A dac was not found
			 */
			if (wid == (wid_t)DDI_FAILURE)
				continue;
			if (pin->device != DTYPE_SPEAKER &&
			    pin->device != DTYPE_HP_OUT)
				statep->chann[pin->assoc] += 2;
			path = (audiohd_path_t *)
			    kmem_zalloc(sizeof (audiohd_path_t),
			    KM_SLEEP);
			path->adda_wid = wid;
			path->pin_wid[0] = widget->wid_wid;
			path->pin_nums = 1;
			path->path_type = PLAY;
			path->codec = codec;
			path->statep = statep;
			wdac = codec->widget[wid];
			wdac->priv = path;
			pin->adc_dac_wid = wid;
			pin->finish = 1;
			widget->path_flags |= AUDIOHD_PATH_DAC;
			widget->out_weight++;
			widget->selconn = i;
			statep->path[statep->pathnum++] = path;
			break;
		}
	}

}	/* audiohd_do_build_output_path() */

/*
 * audiohd_build_output_path()
 *
 * Description:
 *	Build the output path in the codec for every pin.
 *	First we try to search output path with mixer widget exclusively
 *	Then we try to search shared output path with mixer widget.
 *	Then we try to search output path without mixer widget exclusively.
 *	At last we try to search shared ouput path for the remained pins
 */
static void
audiohd_build_output_path(hda_codec_t *codec)
{
	int 			mnum = 0;
	uint8_t			mixer_allow = 1;

	/*
	 * Work around for laptops which have IDT or AD audio chipset, such as
	 * HP mini 1000 laptop, Dell Lattitude 6400, Lenovo T60. We don't
	 * allow mixer widget on such path, which leads to speaker
	 * loud hiss noise.
	 */
	if (codec->vid == AUDIOHD_CODEC_IDT7608 ||
	    codec->vid == AUDIOHD_CODEC_IDT76B2 ||
	    codec->vid == AUDIOHD_CODEC_AD1981)
		mixer_allow = 0;
	/* search an exclusive mixer widget path. This is preferred */
	audiohd_do_build_output_path(codec, mixer_allow, &mnum, 1, 0);

	/* search a shared mixer widget path for the remained pins */
	audiohd_do_build_output_path(codec, mixer_allow, &mnum, 0, 0);

	/* search an exclusive widget path without mixer for the remained pin */
	audiohd_do_build_output_path(codec, 0, &mnum, 1, 0);

	/* search a shared widget path without mixer for the remained pin */
	audiohd_do_build_output_path(codec, 0, &mnum, 0, 0);

}	/* audiohd_build_output_path */

/*
 * audiohd_build_output_amp
 *
 * Description:
 *	Find the gain control and mute control widget
 */
static void
audiohd_build_output_amp(hda_codec_t *codec)
{
	audiohd_path_t		*path;
	audiohd_widget_t	*w, *widget, *wpin, *wdac;
	audiohd_pin_t		*pin;
	wid_t		wid;
	int		weight;
	int		i, j;
	uint32_t	gain;

	for (i = 0; i < codec->soft_statep->pathnum; i++) {
		path = codec->soft_statep->path[i];
		if (path == NULL || path->path_type == RECORD ||
		    path->codec != codec)
			continue;
		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			wpin = codec->widget[wid];
			pin = (audiohd_pin_t *)wpin->priv;
			weight = wpin->out_weight;

			/*
			 * search a node which can mute this pin while
			 * the mute functionality doesn't effect other
			 * pins.
			 */
			widget = wpin;
			while (widget) {
				if (widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_MUTE_CAP) {
					pin->mute_wid = widget->wid_wid;
					pin->mute_dir = AUDIOHDC_AMP_SET_OUTPUT;
					break;
				}
				if (widget->inamp_cap &
				    AUDIOHDC_AMP_CAP_MUTE_CAP) {
					pin->mute_wid = widget->wid_wid;
					pin->mute_dir = AUDIOHDC_AMP_SET_INPUT;
					break;
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
				if (widget && widget->out_weight != weight)
					break;
			}

			/*
			 * We select the wid which has maxium gain range in
			 * the output path. Meanwhile, the gain controlling
			 * of this node doesn't effect other pins if this
			 * output stream has multiple pins.
			 */
			gain = 0;
			widget = wpin;
			while (widget) {
				gain = (widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS);
				if (gain && gain > pin->gain_bits) {
					pin->gain_dir = AUDIOHDC_AMP_SET_OUTPUT;
					pin->gain_bits = gain;
					pin->gain_wid = widget->wid_wid;
				}
				gain = widget->inamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS;
				if (gain && gain > pin->gain_bits) {
					pin->gain_dir = AUDIOHDC_AMP_SET_INPUT;
					pin->gain_bits = gain;
					pin->gain_wid = widget->wid_wid;
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
				if (widget && widget->out_weight != weight)
					break;
			}
			pin->gain_bits >>= AUDIOHD_GAIN_OFF;
		}

		/*
		 * if this stream has multiple pins, we try to find
		 * a mute & gain-controlling nodes which can effect
		 * all output pins of this stream to be used for the
		 * whole stream
		 */
		if (path->pin_nums == 1) {
			path->mute_wid = pin->mute_wid;
			path->mute_dir = pin->mute_dir;
			path->gain_wid = pin->gain_wid;
			path->gain_dir = pin->gain_dir;
			path->gain_bits = pin->gain_bits;
		} else {
			wdac = codec->widget[path->adda_wid];
			weight = wdac->out_weight;
			wid = path->pin_wid[0];
			w = codec->widget[wid];
			while (w && w->out_weight != weight) {
				wid = w->avail_conn[w->selconn];
				w = codec->widget[wid];
			}

			/* find mute controlling node for this stream */
			widget = w;
			while (widget) {
				if (widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_MUTE_CAP) {
					path->mute_wid = widget->wid_wid;
					path->mute_dir =
					    AUDIOHDC_AMP_SET_OUTPUT;
					break;
				}
				if (widget->inamp_cap &
				    AUDIOHDC_AMP_CAP_MUTE_CAP) {
					path->mute_wid = widget->wid_wid;
					path->mute_dir =
					    AUDIOHDC_AMP_SET_INPUT;
					break;
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}

			/* find volume controlling node for this stream */
			gain = 0;
			widget = w;
			while (widget) {
				gain = (widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS);
				if (gain && gain > pin->gain_bits) {
					path->gain_dir =
					    AUDIOHDC_AMP_SET_OUTPUT;
					path->gain_bits = gain;
					path->gain_wid = widget->wid_wid;
				}
				gain = widget->inamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS;
				if (gain && (gain > pin->gain_bits) &&
				    (widget->type != WTYPE_AUDIO_MIX)) {
					path->gain_dir =
					    AUDIOHDC_AMP_SET_INPUT;
					path->gain_bits = gain;
					path->gain_wid = widget->wid_wid;
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}
			path->gain_bits >>= AUDIOHD_GAIN_OFF;
		}

	}

}	/* audiohd_build_output_amp */

/*
 * audiohd_finish_output_path()
 *
 * Description:
 *	Enable the widgets on the output path
 */
static void
audiohd_finish_output_path(hda_codec_t *codec)
{
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_path_t		*path;
	audiohd_widget_t	*widget;
	audiohd_pin_t		*pin;
	uint_t			caddr = codec->index;
	wid_t			wid;
	int			i, j;

	for (i = 0; i < codec->soft_statep->pathnum; i++) {
		path = codec->soft_statep->path[i];
		if (!path || path->path_type != PLAY || path->codec != codec)
			continue;
		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			widget = codec->widget[wid];
			pin = (audiohd_pin_t *)widget->priv;
			{
			uint32_t    lTmp;

			lTmp = audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_GET_PIN_CTRL, 0);
			(void) audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_SET_PIN_CTRL, (lTmp |
			    pin->vrefvalue |
			    AUDIOHDC_PIN_CONTROL_OUT_ENABLE |
			    AUDIOHDC_PIN_CONTROL_HP_ENABLE) &
			    ~ AUDIOHDC_PIN_CONTROL_IN_ENABLE);
			}
			/* If this pin has external amplifier, enable it */
			if (pin->cap & AUDIOHD_EXT_AMP_MASK)
				(void) audioha_codec_verb_get(statep, caddr,
				    wid, AUDIOHDC_VERB_SET_EAPD,
				    AUDIOHD_EXT_AMP_ENABLE);

			if (widget->outamp_cap) {
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr, wid, AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_LR_OUTPUT |
				    AUDIOHDC_GAIN_MAX);
			}

			(void) audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_SET_CONN_SEL, widget->selconn);

			wid = widget->avail_conn[widget->selconn];
			widget = codec->widget[wid];

			while (widget) {
				/*
				 * Set all amplifiers in this path to
				 * the maximum
				 * volume and unmute them.
				 */
				if (widget->outamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    wid, AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_OUTPUT |
					    AUDIOHDC_GAIN_MAX);
				}
				if (widget->inamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    wid, AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_INPUT |
					    AUDIOHDC_GAIN_MAX |
					    (widget->selconn <<
					    AUDIOHDC_AMP_SET_INDEX_OFFSET));
				}

				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				/*
				 * Accoding to HD spec, mixer doesn't support
				 * "select connection"
				 */
				if ((widget->type != WTYPE_AUDIO_MIX) &&
				    (widget->nconns > 1))
					(void) audioha_codec_verb_get(statep,
					    caddr,
					    wid,
					    AUDIOHDC_VERB_SET_CONN_SEL,
					    widget->selconn);

				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}
		}
	}
}	/* audiohd_finish_output_path() */

/*
 * audiohd_find_input_pins()
 *
 * Description:
 * 	Here we consider a mixer/selector with multi-input as a real sum
 * 	widget. Only the first real mixer/selector widget is permitted in
 * 	an input path(recording path). If there are more mixers/selectors
 * 	execept the first one, only the first input/connection of those
 * 	widgets will be used by our driver, that means, we ignore other
 * 	inputs of those mixers/selectors.
 */
static int
audiohd_find_input_pins(hda_codec_t *codec, wid_t wid, int allowmixer,
    int depth, audiohd_path_t *path)
{
	audiohd_widget_t	*widget = codec->widget[wid];
	audiohd_pin_t		*pin;
	audiohd_state_t		*statep = codec->soft_statep;
	uint_t			caddr = codec->index;
	int			retval = -1;
	int			num, i;
	uint32_t		pinctrl;

	if (depth > AUDIOHD_MAX_DEPTH)
		return (uint32_t)(DDI_FAILURE);
	if (widget == NULL)
		return (uint32_t)(DDI_FAILURE);

	/* we don't share widgets */
	if (widget->path_flags & AUDIOHD_PATH_ADC ||
	    widget->path_flags & AUDIOHD_PATH_DAC)
		return (uint32_t)(DDI_FAILURE);

	switch (widget->type) {
	case WTYPE_PIN:
		pin = (audiohd_pin_t *)widget->priv;
		if (pin->no_phys_conn)
			return (uint32_t)(DDI_FAILURE);
		/* enable the pins' input capability */
		pinctrl = audioha_codec_verb_get(statep, caddr, wid,
		    AUDIOHDC_VERB_GET_PIN_CTRL, 0);
		(void) audioha_codec_verb_get(statep, caddr, wid,
		    AUDIOHDC_VERB_SET_PIN_CTRL,
		    pinctrl | AUDIOHD_PIN_IN_ENABLE);
		if (pin->cap & AUDIOHD_EXT_AMP_MASK) {
			(void) audioha_codec_verb_get(statep, caddr,
			    wid, AUDIOHDC_VERB_SET_EAPD,
			    AUDIOHD_EXT_AMP_ENABLE);
		}
		switch (pin->device) {
		case DTYPE_CD:
		case DTYPE_LINE_IN:
		case DTYPE_MIC_IN:
		case DTYPE_AUX:
			widget->path_flags |= AUDIOHD_PATH_ADC;
			widget->in_weight++;
			path->pin_wid[path->pin_nums++] = wid;
			pin->adc_dac_wid = path->adda_wid;
			return (DDI_SUCCESS);
		}
		break;
	case WTYPE_AUDIO_MIX:
	case WTYPE_AUDIO_SEL:
		/*
		 * If the sum widget has only one input, we don't
		 * consider it as a real sum widget.
		 */
		if (widget->nconns == 1) {
			widget->selconn = 0;
			retval = audiohd_find_input_pins(codec,
			    widget->avail_conn[0],
			    allowmixer, depth + 1, path);
			if (retval != DDI_FAILURE) {
				widget->path_flags |= AUDIOHD_PATH_ADC;
				widget->in_weight++;
			}
			break;
		}

		if (allowmixer) {
			/*
			 * This is a real sum widget, we will reject
			 * other real sum widget when we find more in
			 * the following path-searching.
			 */
			for (int i = 0; i < widget->nconns; i++) {
				retval = audiohd_find_input_pins(codec,
				    widget->avail_conn[i], 0, depth + 1,
				    path);
				if (retval != DDI_FAILURE) {
					widget->in_weight++;
					num = path->pin_nums - 1;
					path->sum_selconn[num] = i;
					path->sum_wid = wid;
					widget->path_flags |=
					    AUDIOHD_PATH_ADC;
					if (widget->selconn ==
					    AUDIOHD_NULL_CONN) {
						widget->selconn = i;
					}
				}
			}

			/* return SUCCESS if we found at least one input path */
			if (path->pin_nums > 0)
				retval = DDI_SUCCESS;
		} else {
			/*
			 * We had already found a real sum before this one since
			 * allowmixer is 0.
			 */
			for (i = 0; i < widget->nconns; i++) {
				retval = audiohd_find_input_pins(codec,
				    widget->avail_conn[i], 0, depth + 1,
				    path);
				if (retval != DDI_FAILURE) {
					widget->selconn = i;
					widget->path_flags |= AUDIOHD_PATH_ADC;
					widget->in_weight++;
					break;
				}
			}
		}
		break;
	default:
		break;
	}

	return (retval);
}	/* audiohd_find_input_pins */

/*
 * audiohd_build_input_path()
 *
 * Description:
 *	Find input path for the codec
 */
static void
audiohd_build_input_path(hda_codec_t *codec)
{
	audiohd_widget_t	*widget;
	audiohd_path_t		*path = NULL;
	wid_t			wid;
	int			i;
	int			retval;
	uint8_t			rtag = 0;
	audiohd_state_t		*statep = codec->soft_statep;

	for (wid = codec->first_wid; wid <= codec->last_wid; wid++) {

		widget = codec->widget[wid];

		/* check if it is an ADC widget */
		if (!widget || widget->type != WTYPE_AUDIO_IN)
			continue;

		if (path == NULL)
			path = kmem_zalloc(sizeof (audiohd_path_t),
			    KM_SLEEP);
		else
			bzero(path, sizeof (audiohd_port_t));

		path->adda_wid = wid;

		/*
		 * Is there any ADC widget which has more than one input ??
		 * I don't believe. Anyway, we carefully deal with this. But
		 * if hardware vendors embed a selector in a ADC, we just use
		 * the first available input, which has connection to input pin
		 * widget. Because selector cannot perform mixer functionality,
		 * and we just permit one selector or mixer in a recording path,
		 * if we use the selector embedded in ADC,we cannot use possible
		 * mixer during path searching.
		 */
		for (i = 0; i < widget->nconns; i++) {
			retval = audiohd_find_input_pins(codec,
			    widget->avail_conn[i], 1, 0, path);
			if (retval == DDI_SUCCESS) {
				path->codec = codec;
				path->statep = statep;
				path->path_type = RECORD;
				path->tag = ++rtag;
				codec->nistream++;
				statep->path[statep->pathnum++] = path;
				widget->selconn = i;
				widget->priv = path;
				path = NULL;
				break;
			}
		}
	}
	if (path)
		kmem_free(path, sizeof (audiohd_path_t));
}	/* audiohd_build_input_path */

/*
 * audiohd_build_input_amp()
 *
 * Description:
 *	Find gain and mute control widgets on the input path
 */
static void
audiohd_build_input_amp(hda_codec_t *codec)
{
	audiohd_path_t		*path;
	audiohd_widget_t	*wsum, *wadc, *w;
	audiohd_pin_t		*pin;
	uint_t			gain;
	wid_t			wid;
	int			i, j;
	int			weight;

	for (i = 0; i < codec->soft_statep->pathnum; i++) {
		path = codec->soft_statep->path[i];
		if (path == NULL || path->path_type != RECORD ||
		    path->codec != codec)
			continue;

		wid = path->adda_wid;
		wadc = path->codec->widget[wid];
		weight = wadc->in_weight;

		/*
		 * Search node which has mute functionality for
		 * the whole input path
		 */
		w = wadc;
		while (w) {
			if (w->outamp_cap & AUDIOHDC_AMP_CAP_MUTE_CAP) {
				path->mute_wid = w->wid_wid;
				path->mute_dir = AUDIOHDC_AMP_SET_OUTPUT;
				break;
			}
			if ((w->inamp_cap & AUDIOHDC_AMP_CAP_MUTE_CAP) &&
			    (w->wid_wid != path->sum_wid)) {
				path->mute_wid = w->wid_wid;
				path->mute_dir = AUDIOHDC_AMP_SET_INPUT;
				break;
			}

			if (w->selconn == AUDIOHD_NULL_CONN)
				break;
			wid = w->avail_conn[w->selconn];
			w = path->codec->widget[wid];
			if (w && w->in_weight != weight)
				break;
		}

		/*
		 * Search a node for amplifier adjusting for the whole
		 * input path
		 */
		w = wadc;
		gain = 0;
		while (w) {
			gain = (w->outamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS);
			if (gain && gain > path->gain_bits) {
				path->gain_dir = AUDIOHDC_AMP_SET_OUTPUT;
				path->gain_bits = gain;
				path->gain_wid = w->wid_wid;
			}
			gain = w->inamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS;
			if (gain && (gain > path->gain_bits) &&
			    (w->wid_wid != path->sum_wid)) {
				path->gain_dir = AUDIOHDC_AMP_SET_INPUT;
				path->gain_bits = gain;
				path->gain_wid = w->wid_wid;
			}
			if (w->selconn == AUDIOHD_NULL_CONN)
				break;
			wid = w->avail_conn[w->selconn];
			w = path->codec->widget[wid];
		}
		path->gain_bits >>= AUDIOHD_GAIN_OFF;

		/*
		 * If the input path has one pin only, the mute/amp
		 * controlling is shared by the whole path and pin
		 */
		if (path->pin_nums == 1) {
			wid = path->pin_wid[0];
			w = path->codec->widget[wid];
			pin = (audiohd_pin_t *)w->priv;
			pin->gain_dir = path->gain_dir;
			pin->gain_bits = path->gain_bits;
			pin->gain_wid = path->gain_wid;
			pin->mute_wid = path->mute_wid;
			pin->mute_dir = path->mute_dir;
			continue;
		}

		/*
		 * For multi-pin device, there must be a selector
		 * or mixer along the input path, and the sum_wid
		 * is the widget's node id.
		 */
		wid = path->sum_wid;
		wsum = path->codec->widget[wid]; /* sum widget */

		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			w = path->codec->widget[wid];
			pin = (audiohd_pin_t *)w->priv;

			/* find node for mute */
			if (wsum->inamp_cap & AUDIOHDC_AMP_CAP_MUTE_CAP) {
				pin->mute_wid = wsum->wid_wid;
				pin->mute_dir = AUDIOHDC_AMP_SET_INPUT;
			} else {
				wid = wsum->avail_conn[path->sum_selconn[i]];
				w = path->codec->widget[wid];
				while (w) {
					if (w->outamp_cap &
					    AUDIOHDC_AMP_CAP_MUTE_CAP) {
						pin->mute_wid = w->wid_wid;
						pin->mute_dir =
						    AUDIOHDC_AMP_SET_OUTPUT;
						break;
					}
					if (w->inamp_cap &
					    AUDIOHDC_AMP_CAP_MUTE_CAP) {
						pin->mute_wid = w->wid_wid;
						pin->mute_dir =
						    AUDIOHDC_AMP_SET_INPUT;
						break;
					}

					if (w->selconn == AUDIOHD_NULL_CONN)
						break;
					wid = w->avail_conn[w->selconn];
					w = path->codec->widget[wid];
				}
			}

			/* find node for amp controlling */
			gain = (wsum->inamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS);
			wid = wsum->avail_conn[path->sum_selconn[i]];
			w = path->codec->widget[wid];
			while (w) {
				gain = (w->outamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS);
				if (gain && gain > pin->gain_bits) {
					pin->gain_dir = AUDIOHDC_AMP_SET_OUTPUT;
					pin->gain_bits = gain;
					pin->gain_wid = w->wid_wid;
				}
				gain = w->inamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS;
				if (gain && (gain > pin->gain_bits)) {
					pin->gain_dir = AUDIOHDC_AMP_SET_INPUT;
					pin->gain_bits = gain;
					pin->gain_wid = w->wid_wid;
				}
				if (w->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = w->avail_conn[w->selconn];
				w = path->codec->widget[wid];
			}
			pin->gain_bits >>= AUDIOHD_GAIN_OFF;
		}
	}
}	/* audiohd_build_input_amp() */

/*
 * audiohd_finish_input_path()
 *
 * Description:
 *	Enable the widgets on the input path
 */
static void
audiohd_finish_input_path(hda_codec_t *codec)
{
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_path_t		*path;
	audiohd_widget_t	*w, *wsum;
	uint_t			caddr = codec->index;
	wid_t			wid;
	int			i, j;

	for (i = 0; i < codec->soft_statep->pathnum; i++) {
		path = codec->soft_statep->path[i];
		if (path == NULL || path->path_type != RECORD ||
		    path->codec != codec)
			continue;
		wid = path->adda_wid;
		w = path->codec->widget[wid];
		while (w && (w->wid_wid != path->sum_wid) &&
		    (w->type != WTYPE_PIN)) {
			if ((w->type == WTYPE_AUDIO_SEL) && (w->nconns > 1))
				(void) audioha_codec_verb_get(statep, caddr,
				    w->wid_wid,
				    AUDIOHDC_VERB_SET_CONN_SEL, w->selconn);

			if (w->outamp_cap) {
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr,
				    w->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_LR_OUTPUT |
				    AUDIOHDC_GAIN_MAX);
			}

			if (w->inamp_cap) {
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr,
				    w->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_LR_INPUT |
				    AUDIOHDC_GAIN_MAX |
				    (w->selconn <<
				    AUDIOHDC_AMP_SET_INDEX_OFFSET));
			}

			wid = w->avail_conn[w->selconn];
			w = path->codec->widget[wid];
		}

		/*
		 * After exiting from the above loop, the widget pointed
		 * by w can be a pin widget or select/mixer widget. If it
		 * is a pin widget, we already finish "select connection"
		 * operation for the whole path.
		 */
		if (w && w->type == WTYPE_PIN)
			continue;

		/*
		 * deal with multi-pin input devices.
		 */
		wid = path->sum_wid;
		wsum = path->codec->widget[wid];
		if (wsum == NULL)
			continue;
		if (wsum->outamp_cap) {
			(void) audioha_codec_4bit_verb_get(statep,
			    caddr,
			    wsum->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_LR_OUTPUT |
			    AUDIOHDC_GAIN_MAX);
		}

		for (j = 0; j < path->pin_nums; j++) {
			if (wsum->inamp_cap) {
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr,
				    wsum->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_LR_INPUT |
				    AUDIOHDC_GAIN_MAX |
				    (path->sum_selconn[j] <<
				    AUDIOHDC_AMP_SET_INDEX_OFFSET));
			}
			if (wsum->type == WTYPE_AUDIO_SEL) {
				(void) audioha_codec_verb_get(statep, caddr,
				    wsum->wid_wid,
				    AUDIOHDC_VERB_SET_CONN_SEL,
				    path->sum_selconn[j]);
			}

			wid = wsum->avail_conn[path->sum_selconn[j]];
			w = path->codec->widget[wid];
			while (w && w->type != WTYPE_PIN) {
				if ((w->type != WTYPE_AUDIO_MIX) &&
				    (w->nconns > 1))
					(void) audioha_codec_verb_get(statep,
					    caddr, w->wid_wid,
					    AUDIOHDC_VERB_SET_CONN_SEL,
					    w->selconn);

				if (w->outamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    w->wid_wid,
					    AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_OUTPUT |
					    AUDIOHDC_GAIN_MAX);
				}

				if (w->inamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    w->wid_wid,
					    AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_INPUT |
					    AUDIOHDC_GAIN_MAX |
					    (w->selconn <<
					    AUDIOHDC_AMP_SET_INDEX_OFFSET));
				}
				wid = w->avail_conn[w->selconn];
				w = path->codec->widget[wid];
			}
		}
	}	/* end of istream loop */
}	/* audiohd_finish_input_path */

/*
 * audiohd_find_inpin_for_monitor()
 *
 * Description:
 *	Find input pin for monitor path.
 *
 * Arguments:
 *	hda_codec_t		*codec		where the monitor path exists
 *	audiohd_ostream_t	*ostream	output ostream
 *	wid_t			id		no. of widget being searched
 *	int			mixer		share or not
 */
static int
audiohd_find_inpin_for_monitor(hda_codec_t *codec,
    audiohd_path_t *path, wid_t id, int mixer)
{
	wid_t 			wid;
	audiohd_widget_t	*widget;
	audiohd_pin_t		*pin;
	int 			i, find = 0;

	wid = id;
	widget = codec->widget[wid];
	if (widget == NULL)
		return (uint32_t)(DDI_FAILURE);

	if (widget->type == WTYPE_PIN) {
		pin = (audiohd_pin_t *)widget->priv;
		if (pin->no_phys_conn)
			return (uint32_t)(DDI_FAILURE);
		switch (pin->device) {
			case DTYPE_SPDIF_IN:
				widget->path_flags |= AUDIOHD_PATH_MON;
				return (DDI_SUCCESS);
			case DTYPE_CD:
				widget->path_flags |= AUDIOHD_PATH_MON;
				return (DDI_SUCCESS);
			case DTYPE_LINE_IN:
				widget->path_flags |= AUDIOHD_PATH_MON;
				return (DDI_SUCCESS);
			case DTYPE_MIC_IN:
				widget->path_flags |= AUDIOHD_PATH_MON;
				return (DDI_SUCCESS);
			case DTYPE_AUX:
				widget->path_flags |= AUDIOHD_PATH_MON;
				return (DDI_SUCCESS);
			default:
				return (uint32_t)(DDI_FAILURE);
		}
	}
	/* the widget has been visited and can't be directed to input pin */
	if (widget->path_flags & AUDIOHD_PATH_NOMON) {
		return (uint32_t)(DDI_FAILURE);
	}
	/* the widget has been used by the monitor path, and we can share it */
	if (widget->path_flags & AUDIOHD_PATH_MON) {
		if (mixer)
			return (DDI_SUCCESS);
		else
			return (uint32_t)(DDI_FAILURE);
	}
	switch (widget->type) {
		case WTYPE_AUDIO_MIX:
			for (i = 0; i < widget->nconns; i++) {
				if (widget->selconn == i && widget->path_flags &
				    AUDIOHD_PATH_DAC)
					continue;
				if (audiohd_find_inpin_for_monitor(codec,
				    path,
				    widget->avail_conn[i], mixer) ==
				    DDI_SUCCESS) {
					widget->selmon[widget->used++] = i;
					widget->path_flags |= AUDIOHD_PATH_MON;
					find = 1;
				}
			}
			break;
		case WTYPE_AUDIO_SEL:
			for (i = 0; i < widget->nconns; i++) {
				if (widget->selconn == i && widget->path_flags &
				    AUDIOHD_PATH_DAC)
					continue;
				if (audiohd_find_inpin_for_monitor(codec,
				    path,
				    widget->avail_conn[i],
				    mixer) ==
				    DDI_SUCCESS) {
					widget->selmon[0] = i;
					widget->path_flags |= AUDIOHD_PATH_MON;
					return (DDI_SUCCESS);
				}
			}
		default:
			break;
	}
	if (!find) {
		widget->path_flags |= AUDIOHD_PATH_NOMON;
		return (uint32_t)(DDI_FAILURE);
	}
	else
		return (DDI_SUCCESS);
}	/* audiohd_find_inpin_for_monitor */

/*
 * audiohd_build_monitor_path()
 *
 * Description:
 * 	The functionality of mixer is to mix inputs, such as CD-IN, MIC,
 * 	Line-in, etc, with DAC outputs, so as to minitor what is being
 * 	recorded and implement "What you hear is what you get". However,
 * 	this functionality are really hardware-dependent: the inputs
 * 	must be directed to MIXER if they can be directed to ADC as
 * 	recording sources.
 */
static void
audiohd_build_monitor_path(hda_codec_t *codec)
{
	audiohd_path_t		*path;
	audiohd_widget_t	*widget;
	audiohd_state_t		*statep = codec->soft_statep;
	wid_t			wid;
	int			i, j, k, l, find;
	int			mixernum = 0;

	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path || path->codec != codec ||path->path_type != PLAY)
			continue;
		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			widget = codec->widget[wid];
			l = 0;
			while (widget) {
				while (widget &&
				    ((widget->type != WTYPE_AUDIO_MIX) ||
				    (widget->nconns < 2))) {
					if (widget->selconn ==
					    AUDIOHD_NULL_CONN)
						break;
					wid =
					    widget->avail_conn[widget->selconn];
					widget = codec->widget[wid];
				}

				/*
				 * No mixer in this output path, we cannot build
				 * mixer path for this path, skip it,
				 * and continue
				 * for next output path.
				 */
				if (widget == NULL || widget->selconn ==
				    AUDIOHD_NULL_CONN) {
					break;
				}
				mixernum++;
				for (k = 0; k < widget->nconns; k++) {

					/*
					 * this connection must be routined
					 * to DAC instead of an input pin
					 * widget, we needn't waste time for
					 * it
					 */
					if (widget->selconn == k)
						continue;
					find = 0;
					if (audiohd_find_inpin_for_monitor(
					    codec,
					    path,
					    widget->avail_conn[k], 0) ==
					    DDI_SUCCESS) {
						path->mon_wid[j][l] = wid;
						widget->selmon[widget->used++] =
						    k;
						widget->path_flags |=
						    AUDIOHD_PATH_MON;
						find = 1;
					} else if (
					    audiohd_find_inpin_for_monitor(
					    codec,
					    path,
					    widget->avail_conn[k], 1) ==
					    DDI_SUCCESS) {
						path->mon_wid[j][l] = wid;
						widget->selmon[widget->used++] =
						    k;
						widget->path_flags |=
						    AUDIOHD_PATH_MON;
						find = 1;

					}

				}

				/*
				 * we needn't check widget->selconn here
				 * since this
				 * widget is a selector or mixer, it cannot
				 * be NULL connection.
				 */
				if (!find) {
					path->mon_wid[i][l] = 0;
					widget->path_flags |=
					    AUDIOHD_PATH_NOMON;
				}
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
				l++;
			}
			path->maxmixer[j] = l;
		}

	}
	if (mixernum == 0)
		statep->monitor_unsupported = B_TRUE;
	else
		statep->monitor_unsupported = B_FALSE;
}	/* audiohd_build_monitor_path */

/*
 * audiohd_do_finish_monitor_path
 *
 * Description:
 *	Enable the widgets on the monitor path
 */
static void
audiohd_do_finish_monitor_path(hda_codec_t *codec, audiohd_widget_t *wgt)
{
	uint_t			caddr = codec->index;
	audiohd_widget_t 	*widget = wgt;
	audiohd_widget_t	*w;
	audiohd_state_t		*statep = codec->soft_statep;
	wid_t			wid;
	int			i;
	int			share = 0;

	if (!widget || widget->finish)
		return;
	if (widget->path_flags & AUDIOHD_PATH_ADC)
		share = 1;
	if ((widget->outamp_cap)&&!share)
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    widget->wid_wid,
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_LR_OUTPUT
			    | AUDIOHDC_GAIN_MAX);
	if ((widget->inamp_cap)&&!share) {
		for (i = 0; i < widget->used; i++) {
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    widget->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
		    AUDIOHDC_AMP_SET_LR_INPUT |
		    AUDIOHDC_GAIN_MAX |
		    (widget->selmon[i] <<
		    AUDIOHDC_AMP_SET_INDEX_OFFSET));
		}
	}
	if ((widget->type == WTYPE_AUDIO_SEL) && (widget->nconns > 1) &&
	    !share) {
		(void) audioha_codec_verb_get(statep, caddr,
		    widget->wid_wid,
		    AUDIOHDC_VERB_SET_CONN_SEL, widget->selmon[0]);
	}
	widget->finish = 1;
	if (widget->used == 0)
		return;
	if (widget->used > 0) {
		for (i = 0; i < widget->used; i++) {
			wid = widget->avail_conn[widget->selmon[i]];
			w = codec->widget[wid];
			audiohd_do_finish_monitor_path(codec, w);
		}
	}
}	/* audiohd_do_finish_monitor_path */

/*
 * audiohd_finish_monitor_path
 *
 * Description:
 *	Enable the monitor path for every ostream path
 */
static void
audiohd_finish_monitor_path(hda_codec_t *codec)
{
	audiohd_path_t		*path;
	audiohd_widget_t	*widget;
	audiohd_state_t		*statep = codec->soft_statep;
	wid_t			wid;
	int 			i, j, k;

	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path || path->codec != codec || path->path_type != PLAY)
			continue;
		for (j = 0; j < path->pin_nums; j++) {
			for (k = 0; k < path->maxmixer[j]; k++) {
				wid = path->mon_wid[j][k];
				if (wid == 0) {
					continue;
				}
				widget = codec->widget[wid];
				audiohd_do_finish_monitor_path(codec, widget);
			}
		}
	}
}	/* audiohd_finish_monitor_path */

/*
 * audiohd_do_build_monit_amp()
 *
 * Description:
 *	Search for the gain control widget for the monitor path
 */
static void
audiohd_do_build_monitor_amp(hda_codec_t *codec, audiohd_pin_t *pin,
    audiohd_widget_t *widget)
{
	audiohd_widget_t	*w = widget;
	uint32_t		gain;
	int			i;
	wid_t			wid;

	if (!w ||
	    (w->type == WTYPE_PIN) ||
	    !w->used ||
	    (pin->num == AUDIOHD_MAX_CONN) ||
	    (w->path_flags & AUDIOHD_PATH_ADC))
		return;
	if (!(w->path_flags & AUDIOHD_PATH_DAC)) {
		gain = w->outamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS;
		if (gain) {
			pin->mg_dir[pin->num] = AUDIOHDC_AMP_SET_OUTPUT;
			pin->mg_gain[pin->num] = gain;
			pin->mg_wid[pin->num] = w->wid_wid;
			pin->mg_gain[pin->num] >>= AUDIOHD_GAIN_OFF;
			pin->num++;
			return;
		}
		gain = w->inamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS;
		if (gain) {
			pin->mg_dir[pin->num] = AUDIOHDC_AMP_SET_INPUT;
			pin->mg_gain[pin->num] = gain;
			pin->mg_wid[pin->num] = w->wid_wid;
			pin->mg_gain[pin->num] >>= AUDIOHD_GAIN_OFF;
			pin->num++;
			return;
		}
	}
	for (i = 0; i < w->used; i++) {
		wid = w->avail_conn[w->selmon[i]];
		audiohd_do_build_monitor_amp(codec, pin, codec->widget[wid]);
	}


}	/* audiohd_do_build_monitor_amp() */

/*
 * audiohd_build_monitor_amp()
 *
 * Description:
 *	Search gain control widget for every ostream monitor
 */
static void
audiohd_build_monitor_amp(hda_codec_t *codec)
{
	audiohd_path_t		*path;
	audiohd_widget_t	*widget, *w;
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_pin_t		*pin;
	wid_t			wid, id;
	int			i, j, k;

	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path || path->codec != codec || path->path_type != PLAY)
			continue;
		for (j = 0; j < path->pin_nums; j++) {
			id = path->pin_wid[j];
			w = codec->widget[id];
			pin = (audiohd_pin_t *)(w->priv);
			for (k = 0; k < path->maxmixer[j]; k++) {
				wid = path->mon_wid[j][k];
				if (!wid)
					continue;
				widget = codec->widget[wid];
				audiohd_do_build_monitor_amp(codec, pin,
				    widget);
			}
		}
	}
}

/*
 * audiohd_find_beep()
 * Description:
 *      Find a beep for a beep path. Then the play data can be sent to the out
 *      put pin through the beep path.
 *
 * Arguments:
 *      hda_codec_t     *codec          where the beep widget exists
 *      wid_t           wid             the no. of a widget
 *      int             depth           the depth of search
 *
 * Return:
 *      1) wid of Beep widget;
 *      2) 0 if no path
 */
static wid_t
audiohd_find_beep(hda_codec_t *codec, wid_t wid, int depth)
{
	audiohd_widget_t	*widget = codec->widget[wid];
	wid_t   		wbeep = (uint32_t)(DDI_FAILURE);
	wid_t   		retval;

	if (depth > AUDIOHD_MAX_DEPTH)
		return (uint32_t)(DDI_FAILURE);

	if (widget == NULL)
		return (uint32_t)(DDI_FAILURE);

	switch (widget->type) {
	case WTYPE_BEEP:
		widget->path_flags |= AUDIOHD_PATH_BEEP;
		wbeep = widget->wid_wid;
		break;

	case WTYPE_AUDIO_MIX:
	case WTYPE_AUDIO_SEL:
		for (int i = 0; i < widget->nconns; i++) {
			retval = audiohd_find_beep(codec,
			    widget->avail_conn[i], depth + 1);
			if (retval != (uint32_t)DDI_FAILURE) {
				if (widget->selconn != AUDIOHD_NULL_CONN)
					continue;
				widget->selconn = i;
				wbeep = retval;
				widget->path_flags |= AUDIOHD_PATH_BEEP;
				return (wbeep);
			}
		}
	default:
		break;
	}

	return (wbeep);
}       /* audiohd_find_beep() */

/*
 * audiohd_build_beep_path()
 *
 * Description:
 *      Search an beep path for each pin in the codec.
 * Arguments:
 *      hda_codec_t     *codec          where the beep path exists
 */
static void
audiohd_build_beep_path(hda_codec_t *codec)
{
	audiohd_pin_t		*pin;
	audiohd_widget_t	*widget;
	audiohd_path_t		*path;
	wid_t			wid;
	audiohd_state_t		*statep;
	int			i;
	boolean_t		beeppath = B_FALSE;

	statep = codec->soft_statep;

	for (pin = codec->first_pin; pin; pin = pin->next) {
		if ((pin->cap & AUDIOHD_PIN_CAP_MASK) == 0)
			continue;
		if ((pin->config & AUDIOHD_PIN_CONF_MASK) ==
		    AUDIOHD_PIN_NO_CONN)
			continue;
		if ((pin->device != DTYPE_LINEOUT) &&
		    (pin->device != DTYPE_SPEAKER) &&
		    (pin->device != DTYPE_SPDIF_OUT) &&
		    (pin->device != DTYPE_HP_OUT))
			continue;
		widget = codec->widget[pin->wid];

		widget->inamp_cap = 0;
		for (i = 0; i < widget->nconns; i++) {
			/*
			 * If a beep found, the return value is the wid of the
			 * widget on the path, or the return value is
			 * DDI_FAILURE
			 */
			wid = audiohd_find_beep(codec,
			    widget->avail_conn[i], 0);
			/*
			 * A beep was not found
			 */
			if (wid == (wid_t)DDI_FAILURE)
				continue;
			if (widget->selconn != AUDIOHD_NULL_CONN)
				continue;
			path = (audiohd_path_t *)
			    kmem_zalloc(sizeof (audiohd_path_t),
			    KM_SLEEP);
			path->beep_wid = wid;
			path->pin_wid[0] = widget->wid_wid;
			path->pin_nums = 1;
			path->path_type = BEEP;
			beeppath = 1;
			path->codec = codec;
			path->statep = statep;
			widget->path_flags |= AUDIOHD_PATH_BEEP;
			widget->selconn = i;
			statep->path[statep->pathnum++] = path;

			break;
		}
	}

	if (!beeppath) {
		for (int i = 0; i < AUDIOHD_CODEC_MAX; i++) {
			codec = statep->codec[i];
			if (!codec)
				continue;
			for (wid = codec->first_wid; wid <= codec->last_wid;
			    wid++) {
				widget = codec->widget[wid];
				if (widget->type == WTYPE_BEEP) {
					path = (audiohd_path_t *)
					    kmem_zalloc(sizeof (audiohd_path_t),
					    KM_SLEEP);
					path->beep_wid = wid;
					path->pin_nums = 0;
					path->path_type = BEEP;
					beeppath = 1;
					path->codec = codec;
					path->statep = statep;
					widget->path_flags |= AUDIOHD_PATH_BEEP;
					statep->path[statep->pathnum++] = path;
					break;
				}
			}
		}
	}
}       /* audiohd_build_beep_path() */

/*
 * audiohd_build_beep_amp
 *
 * Description:
 *      Find the gain control and mute control widget
 */
static void
audiohd_build_beep_amp(hda_codec_t *codec)
{
	audiohd_path_t		*path;
	audiohd_widget_t	*widget, *wpin, *wbeep;
	wid_t			wid;
	int			i, j;
	uint32_t		gain;

	for (i = 0; i < codec->soft_statep->pathnum; i++) {
		path = codec->soft_statep->path[i];
		if (path == NULL || path->path_type != BEEP ||
		    path->codec != codec)
			continue;
		if (path->pin_nums == 0) {
			path->mute_wid = path->beep_wid;
			path->mute_dir = AUDIOHDC_AMP_SET_OUTPUT;
			wbeep = codec->widget[path->beep_wid];
			gain = (wbeep->outamp_cap &
			    AUDIOHDC_AMP_CAP_STEP_NUMS);
			if (gain) {
				path->gain_dir = AUDIOHDC_AMP_SET_OUTPUT;
				path->gain_bits = gain;
				path->gain_wid = path->beep_wid;
			}
			path->gain_bits >>= AUDIOHD_GAIN_OFF;
			break;
		}
		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			wpin = codec->widget[wid];
			wbeep = codec->widget[path->beep_wid];

			widget = wpin;
			while (widget) {
				if (widget->out_weight == 0 &&
				    widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_MUTE_CAP) {
					path->mute_wid = widget->wid_wid;
					path->mute_dir =
					    AUDIOHDC_AMP_SET_OUTPUT;
					break;
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}

			gain = 0;
			widget = wpin;
			while (widget) {
				if (widget->out_weight == 0 &&
				    widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS) {
					gain = (widget->outamp_cap &
					    AUDIOHDC_AMP_CAP_STEP_NUMS);
					if (gain && gain > path->gain_bits) {
						path->gain_dir =
						    AUDIOHDC_AMP_SET_OUTPUT;
						path->gain_bits = gain;
						path->gain_wid =
						    widget->wid_wid;
					}
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}
			path->gain_bits >>= AUDIOHD_GAIN_OFF;
		}
	}
}       /* audiohd_build_beep_amp */

/*
 * audiohd_finish_beep_path()
 *
 * Description:
 *      Enable the widgets on the beep path
 */
static void
audiohd_finish_beep_path(hda_codec_t *codec)
{
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_path_t		*path;
	audiohd_widget_t	*widget;
	uint_t			caddr = codec->index;
	wid_t			wid;
	int			i, j;

	for (i = 0; i < codec->soft_statep->pathnum; i++) {
		path = codec->soft_statep->path[i];
		if (!path || path->path_type != BEEP || path->codec != codec)
			continue;
		for (j = 0; j < path->pin_nums; j++) {
			wid = path->pin_wid[j];
			widget = codec->widget[wid];

			(void) audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_SET_CONN_SEL, widget->selconn);

			wid = widget->avail_conn[widget->selconn];
			widget = codec->widget[wid];

			while (widget) {
				/*
				 * Set all amplifiers in this path to
				 * the maximum
				 * volume and unmute them.
				 */
				if (widget->out_weight != 0)
					continue;
				if (widget->outamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    wid, AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_OUTPUT |
					    AUDIOHDC_GAIN_MAX);
					}
				if (widget->inamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    wid, AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_INPUT |
					    AUDIOHDC_GAIN_MAX |
					    (widget->selconn <<
					    AUDIOHDC_AMP_SET_INDEX_OFFSET));
				}

				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				/*
				 * Accoding to HD spec, mixer doesn't support
				 * "select connection"
				 */
				if ((widget->type != WTYPE_AUDIO_MIX) &&
				    (widget->nconns > 1))
					(void) audioha_codec_verb_get(statep,
					    caddr,
					    wid,
					    AUDIOHDC_VERB_SET_CONN_SEL,
					    widget->selconn);

				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}
		}
	}
}       /* audiohd_finish_beep_path */

/*
 * audiohd_build_path()
 *
 * Description:
 *	Here we build the output, input, monitor path.
 *	And also enable the path in default.
 *	Search for the gain and mute control for the path
 */
static void
audiohd_build_path(audiohd_state_t *statep)
{
	int		i;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if (statep->codec[i]) {
			audiohd_build_output_path(statep->codec[i]);
			audiohd_build_output_amp(statep->codec[i]);
			audiohd_finish_output_path(statep->codec[i]);

			audiohd_build_input_path(statep->codec[i]);
			audiohd_build_input_amp(statep->codec[i]);
			audiohd_finish_input_path(statep->codec[i]);

			audiohd_build_monitor_path(statep->codec[i]);
			audiohd_build_monitor_amp(statep->codec[i]);
			audiohd_finish_monitor_path(statep->codec[i]);

			audiohd_build_beep_path(statep->codec[i]);
			audiohd_build_beep_amp(statep->codec[i]);
			audiohd_finish_beep_path(statep->codec[i]);
		}
	}
}	/* audiohd_build_path */

/*
 * audiohd_allocate_port()
 */
static int
audiohd_allocate_port(audiohd_state_t *statep)
{
	int			i, j;
	audiohd_port_t		*port;
	int			dir;
	unsigned		caps;
	char			*prop;
	int			rc;
	audio_dev_t		*adev;
	dev_info_t		*dip;
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	uint64_t		buf_phys_addr;
	sd_bdle_t		*entry;
	uint16_t		gcap;
	size_t			real_size;

	adev = statep->adev;
	dip = statep->hda_dip;

	ddi_dma_attr_t	dma_attr = {
		DMA_ATTR_V0,		/* version */
		0,			/* addr_lo */
		0xffffffffffffffffULL,	/* addr_hi */
		0x00000000ffffffffULL,	/* count_max */
		128,			/* 128-byte alignment as HD spec */
		0xfff,			/* burstsize */
		1,			/* minxfer */
		0xffffffff,		/* maxxfer */
		0xffffffff,		/* seg */
		1,			/* sgllen */
		1,			/* granular */
		0			/* flags */
	};

	gcap = AUDIOHD_REG_GET16(AUDIOHD_REG_GCAP);
	if ((gcap & AUDIOHDR_GCAP_64OK) == 0)
		dma_attr.dma_attr_addr_hi = 0xffffffffUL;

	for (i = 0; i < PORT_MAX; i++) {
		port = kmem_zalloc(sizeof (*port), KM_SLEEP);
		port->started = B_FALSE;
		port->triggered = B_FALSE;
		statep->port[i] = port;
		port->statep = statep;
		switch (i) {
		case PORT_ADC:
			prop = "record-interrupts";
			dir = DDI_DMA_READ | DDI_DMA_CONSISTENT;
			caps = ENGINE_INPUT_CAP;
			port->sync_dir = DDI_DMA_SYNC_FORKERNEL;
			port->nchan = statep->rchan;
			port->index = 1;
			port->regoff = AUDIOHD_REG_SD_BASE;
			break;
		case PORT_DAC:
			prop = "play-interrupts";
			dir = DDI_DMA_WRITE | DDI_DMA_CONSISTENT;
			caps = ENGINE_OUTPUT_CAP;
			port->sync_dir = DDI_DMA_SYNC_FORDEV;
			port->nchan = statep->pchan;
			port->index = statep->hda_input_streams + 1;
			port->regoff = AUDIOHD_REG_SD_BASE +
			    AUDIOHD_REG_SD_LEN *
			    statep->hda_input_streams;
			break;
		default:
			return (DDI_FAILURE);
		}

		port->intrs = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, prop, AUDIOHD_INTS);

		/* make sure the values are good */
		if (port->intrs < AUDIOHD_MIN_INTS) {
			audio_dev_warn(adev, "%s too low, %d, resetting to %d",
			    prop, port->intrs, AUDIOHD_INTS);
			port->intrs = AUDIOHD_INTS;
		} else if (port->intrs > AUDIOHD_MAX_INTS) {
			audio_dev_warn(adev, "%s too high, %d, resetting to %d",
			    prop, port->intrs, AUDIOHD_INTS);
			port->intrs = AUDIOHD_INTS;
		}

		port->format = AUDIOHD_FMT_PCM;
		port->fragfr = 48000 / port->intrs;
		port->fragfr = (port->fragfr + AUDIOHD_FRAGFR_ALIGN - 1) & ~
		    (AUDIOHD_FRAGFR_ALIGN - 1);
		port->samp_size = port->fragfr * port->nchan * 2;
		port->samp_size = (port->samp_size +
		    AUDIOHD_BDLE_BUF_ALIGN - 1) & ~
		    (AUDIOHD_BDLE_BUF_ALIGN - 1);

		/* allocate dma handle */
		rc = ddi_dma_alloc_handle(dip, &dma_attr, DDI_DMA_SLEEP,
		    NULL, &port->samp_dmah);
		if (rc != DDI_SUCCESS) {
			audio_dev_warn(adev, "ddi_dma_alloc_handle failed: %d",
			    rc);
			return (DDI_FAILURE);
		}
		/*
		 * Warning: please be noted that allocating the dma memory
		 * with the flag IOMEM_DATA_UNCACHED is a hack due
		 * to an incorrect cache synchronization on NVidia MCP79
		 * chipset which causes the audio distortion problem,
		 * and that it should be fixed later. There should be
		 * no reason you have to allocate UNCACHED memory. In
		 * complex architectures with nested IO caches,
		 * reliance on this flag might lead to failure.
		 */
		rc = ddi_dma_mem_alloc(port->samp_dmah, port->samp_size *
		    AUDIOHD_BDLE_NUMS,
		    &hda_dev_accattr,
		    DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
		    DDI_DMA_SLEEP, NULL, &port->samp_kaddr,
		    &real_size, &port->samp_acch);
		if (rc == DDI_FAILURE) {
			if (ddi_dma_mem_alloc(port->samp_dmah,
			    port->samp_size * AUDIOHD_BDLE_NUMS,
			    &hda_dev_accattr,
			    DDI_DMA_CONSISTENT,
			    DDI_DMA_SLEEP, NULL,
			    &port->samp_kaddr, &real_size,
			    &port->samp_acch) != DDI_SUCCESS) {
				audio_dev_warn(adev,
				    "ddi_dma_mem_alloc failed");
				return (DDI_FAILURE);
			}
		}

		/* bind DMA buffer */
		rc = ddi_dma_addr_bind_handle(port->samp_dmah, NULL,
		    port->samp_kaddr, real_size, dir,
		    DDI_DMA_SLEEP, NULL, &cookie, &count);
		if ((rc != DDI_DMA_MAPPED) || (count != 1)) {
			audio_dev_warn(adev,
			    "ddi_dma_addr_bind_handle failed: %d", rc);
			return (DDI_FAILURE);
		}
		port->samp_paddr = (uint64_t)cookie.dmac_laddress;

		/*
		 * now, from here we allocate DMA
		 * memory for buffer descriptor list.
		 * we allocate adjacent DMA memory for all DMA engines.
		 */
		rc = ddi_dma_alloc_handle(dip, &dma_attr, DDI_DMA_SLEEP,
		    NULL, &port->bdl_dmah);
		if (rc != DDI_SUCCESS) {
			audio_dev_warn(adev,
			    "ddi_dma_alloc_handle(bdlist) failed");
			return (DDI_FAILURE);
		}

		/*
		 * we allocate all buffer descriptors lists in continuous
		 * dma memory.
		 */
		port->bdl_size = sizeof (sd_bdle_t) * AUDIOHD_BDLE_NUMS;
		rc = ddi_dma_mem_alloc(port->bdl_dmah, port->bdl_size,
		    &hda_dev_accattr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
		    &port->bdl_kaddr, &real_size, &port->bdl_acch);
		if (rc != DDI_SUCCESS) {
			audio_dev_warn(adev,
			    "ddi_dma_mem_alloc(bdlist) failed");
			return (DDI_FAILURE);
		}

		rc = ddi_dma_addr_bind_handle(port->bdl_dmah, NULL,
		    port->bdl_kaddr,
		    real_size, DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP,
		    NULL, &cookie, &count);
		if ((rc != DDI_DMA_MAPPED) || (count != 1)) {
			audio_dev_warn(adev, "addr_bind_handle failed");
			return (DDI_FAILURE);
		}
		port->bdl_paddr = (uint64_t)cookie.dmac_laddress;

		entry = (sd_bdle_t *)port->bdl_kaddr;
		buf_phys_addr = port->samp_paddr;

		for (j = 0; j < AUDIOHD_BDLE_NUMS; j++) {
			entry->sbde_addr = buf_phys_addr;
			entry->sbde_len = port->samp_size;
			entry->sbde_ioc = 1;
			buf_phys_addr += port->samp_size;
			entry++;
		}
		(void) ddi_dma_sync(port->bdl_dmah, 0, sizeof (sd_bdle_t) *
		    AUDIOHD_BDLE_NUMS, DDI_DMA_SYNC_FORDEV);
		port->curpos = 0;

		port->engine = audio_engine_alloc(&audiohd_engine_ops, caps);
		if (port->engine == NULL) {
			return (DDI_FAILURE);
		}

		audio_engine_set_private(port->engine, port);
		audio_dev_add_engine(adev, port->engine);
	}

	return (DDI_SUCCESS);
}

static void
audiohd_free_port(audiohd_state_t *statep)
{
	int			i;
	audiohd_port_t		*port;

	if (statep == NULL) {
		return;
	}
	for (i = 0; i < PORT_MAX; i++) {
		port = statep->port[i];
		if (port == NULL)
			continue;
		if (port->engine) {
			audio_dev_remove_engine(statep->adev,
			    port->engine);
			audio_engine_free(port->engine);
		}
		if (port->samp_dmah) {
			(void) ddi_dma_unbind_handle(port->samp_dmah);
		}
		if (port->samp_acch) {
			ddi_dma_mem_free(&port->samp_acch);
		}
		if (port->samp_dmah) {
			ddi_dma_free_handle(&port->samp_dmah);
		}
		if (port->bdl_dmah) {
			(void) ddi_dma_unbind_handle(port->bdl_dmah);
		}
		if (port->bdl_acch) {
			ddi_dma_mem_free(&port->bdl_acch);
		}
		if (port->bdl_dmah) {
			ddi_dma_free_handle(&port->bdl_dmah);
		}

		kmem_free(port, sizeof (audiohd_port_t));
	}
}

/*
 * audiohd_change_widget_power_state(audiohd_state_t *statep, int off)
 * Description:
 * 	This routine is used to change the widget power betwen D0 and D2.
 * 	D0 is fully on; D2 allows the lowest possible power consuming state
 * 	from which it can return to the fully on state: D0.
 */
static void
audiohd_change_widget_power_state(audiohd_state_t *statep, int off)
{
	int			i;
	wid_t			wid;
	hda_codec_t		*codec;
	audiohd_widget_t	*widget;

	/* Change power to D2 */
	if (off) {
		for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
			codec = statep->codec[i];
			if (!codec)
				continue;
			for (wid = codec->first_wid; wid <= codec->last_wid;
			    wid++) {
				widget = codec->widget[wid];
				if (widget->widget_cap &
				    AUDIOHD_WIDCAP_PWRCTRL) {
					(void) audioha_codec_verb_get(statep,
					    codec->index, wid,
					    AUDIOHDC_VERB_SET_POWER_STATE,
					    AUDIOHD_PW_D2);
				}
			}
		}
	/* Change power to D0 */
	} else {
		for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
			codec = statep->codec[i];
			if (!codec)
				continue;
			for (wid = codec->first_wid; wid <= codec->last_wid;
			    wid++) {
				widget = codec->widget[wid];
				if (widget->widget_cap &
				    AUDIOHD_WIDCAP_PWRCTRL) {
					(void) audioha_codec_verb_get(statep,
					    codec->index, wid,
					    AUDIOHDC_VERB_SET_POWER_STATE,
					    AUDIOHD_PW_D0);
				}
			}
		}
	}
}
/*
 * audiohd_restore_path()
 * Description:
 * 	This routine is used to restore the path on the codec.
 */
static void
audiohd_restore_path(audiohd_state_t *statep)
{
	int			i;
	hda_codec_t		*codec;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		codec = statep->codec[i];
		if (!codec)
			continue;
		audiohd_finish_output_path(statep->codec[i]);
		audiohd_finish_input_path(statep->codec[i]);
		audiohd_finish_monitor_path(statep->codec[i]);
	}
}

/*
 * restore_play_and_record()
 */
static void
audiohd_restore_play_and_record(audiohd_state_t *statep)
{
	int		i;
	audiohd_port_t	*port;

	mutex_enter(&statep->hda_mutex);
	for (i = 0; i < PORT_MAX; i++) {
		port = statep->port[i];
		if (port == NULL)
			continue;
		if (port != NULL)
			audio_engine_reset(port->engine);
		if (port->triggered) {
			(void) audiohd_reset_port(port);
			audiohd_start_port(port);
		} else {
			audiohd_stop_port(port);

		}
	}
	mutex_exit(&statep->hda_mutex);
}
/*
 * audiohd_reset_pins_ur_cap()
 * Description:
 * 	Enable the unsolicited response of the pins which have the unsolicited
 * 	response capability
 */
static void
audiohd_reset_pins_ur_cap(audiohd_state_t *statep)
{
	hda_codec_t		*codec;
	audiohd_pin_t		*pin;
	audiohd_widget_t	*widget;
	uint32_t		urctrl;
	int			i;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		codec = statep->codec[i];
		if (!codec)
			continue;
		pin = codec->first_pin;
		while (pin) {
			/* enable the unsolicited response of the pin */
			widget = codec->widget[pin->wid];
			if ((widget->widget_cap &
			    (AUDIOHD_URCAP_MASK) &&
			    (pin->cap & AUDIOHD_DTCCAP_MASK)) &&
			    ((pin->device == DTYPE_LINEOUT) ||
			    (pin->device == DTYPE_SPDIF_OUT) ||
			    (pin->device == DTYPE_HP_OUT) ||
			    (pin->device == DTYPE_MIC_IN))) {
				urctrl = (uint8_t)(1 <<
				    (AUDIOHD_UR_ENABLE_OFF - 1));
				urctrl |= (pin->wid & AUDIOHD_UR_TAG_MASK);
				(void) audioha_codec_verb_get(statep,
				    codec->index,
				    pin->wid,
				    AUDIOHDC_VERB_SET_URCTRL, urctrl);
			}
			pin = pin->next;
		}
	}
}
static void
audiohd_restore_codec_gpio(audiohd_state_t *statep)
{
	int		i;
	wid_t		wid;
	hda_codec_t	*codec;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		codec = statep->codec[i];
		if (codec == NULL)
			continue;
		wid = codec->wid_afg;

		/* power-up audio function group */
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_POWER_STATE, 0);
		/* work around for Sony VAIO laptop with specific codec */
		if ((codec->vid != AUDIOHD_CODECID_SONY1) &&
		    (codec->vid != AUDIOHD_CODECID_SONY2)) {
			/*
			 * GPIO controls which are laptop specific workarounds
			 * and might be changed. Some laptops use GPIO,
			 * so we need to enable and set the GPIO correctly.
			 */
			(void) audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_SET_GPIO_MASK, AUDIOHDC_GPIO_ENABLE);
			(void) audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_SET_GPIO_DIREC, AUDIOHDC_GPIO_DIRECT);
			(void) audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_SET_GPIO_STCK,
			    AUDIOHDC_GPIO_DATA_CTRL);
			(void) audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_SET_GPIO_DATA,
			    AUDIOHDC_GPIO_STCK_CTRL);
		}
	}
}
/*
 * audiohd_resume()
 */
static int
audiohd_resume(audiohd_state_t *statep)
{
	uint8_t		rirbsts;

	mutex_enter(&statep->hda_mutex);
	statep->suspended = B_FALSE;
	/* Restore the hda state */
	if (audiohd_reinit_hda(statep) == DDI_FAILURE) {
		audio_dev_warn(statep->adev,
		    "hda reinit failed");
		mutex_exit(&statep->hda_mutex);
		return (DDI_SUCCESS);
	}
	/* reset to enable the capability of unsolicited response for pin */
	audiohd_reset_pins_ur_cap(statep);
	/* Enable interrupt */
	AUDIOHD_REG_SET32(AUDIOHD_REG_INTCTL,
	    AUDIOHD_INTCTL_BIT_GIE |
	    AUDIOHD_INTCTL_BIT_SIE);
	/* clear the unsolicited response interrupt */
	rirbsts = AUDIOHD_REG_GET8(AUDIOHD_REG_RIRBSTS);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBSTS, rirbsts);
	mutex_exit(&statep->hda_mutex);

	audiohd_restore_play_and_record(statep);
	audiohd_configure_output(statep);
	audiohd_configure_input(statep);

	/* set widget power to D0 */
	audiohd_change_widget_power_state(statep, AUDIOHD_PW_ON);

	return (DDI_SUCCESS);
}	/* audiohd_resume */

/*
 * audiohd_suspend()
 */
static int
audiohd_suspend(audiohd_state_t *statep)
{
	mutex_enter(&statep->hda_mutex);
	statep->suspended = B_TRUE;

	/* set widget power to D2 */
	audiohd_change_widget_power_state(statep, AUDIOHD_PW_OFF);
	/* Disable h/w */
	audiohd_disable_intr(statep);
	audiohd_stop_dma(statep);
	audiohd_fini_pci(statep);
	mutex_exit(&statep->hda_mutex);

	return (DDI_SUCCESS);
}	/* audiohd_suspend */

/*
 * audiohd_disable_pin()
 */
static int
audiohd_disable_pin(audiohd_state_t *statep, int caddr, wid_t wid)
{
	AUDIOHD_DISABLE_PIN_OUT(statep, caddr, wid);
	return (DDI_SUCCESS);
}

/*
 * audiohd_enable_pin()
 */
static int
audiohd_enable_pin(audiohd_state_t *statep, int caddr, wid_t wid)
{
	AUDIOHD_ENABLE_PIN_OUT(statep, caddr, wid);
	return (DDI_SUCCESS);
}
/*
 * audiohd_change_speaker_state()
 */
static void
audiohd_change_speaker_state(audiohd_state_t *statep, int on)
{
	audiohd_path_t		*path;
	audiohd_widget_t	*widget;
	audiohd_pin_t		*pin;
	int			i, j;
	wid_t			wid;

	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (!path || path->path_type != PLAY)
			continue;
		if (on) {
			for (j = 0; j < path->pin_nums; j++) {
				wid = path->pin_wid[j];
				widget = path->codec->widget[wid];
				pin = (audiohd_pin_t *)widget->priv;
				if (pin->device == DTYPE_SPEAKER) {
					(void) audiohd_enable_pin(
					    statep,
					    path->codec->index,
					    pin->wid);
				}
			}

		} else {
			for (j = 0; j < path->pin_nums; j++) {
				wid = path->pin_wid[j];
				widget = path->codec->widget[wid];
				pin = (audiohd_pin_t *)widget->priv;
				if (pin->device == DTYPE_SPEAKER) {
					(void) audiohd_disable_pin(
					    statep,
					    path->codec->index,
					    pin->wid);
				}
			}
		}
	}
}
/*
 * audiohd_select_mic()
 *
 * Description:
 *	This function is used for the recording path which has a selector
 *	as the sumwidget. We select the external MIC if it is plugged into the
 *	MIC jack, otherwise the internal integrated MIC is selected.
 */
static void
audiohd_select_mic(audiohd_state_t *statep, uint8_t index,
uint8_t id, int select)
{
	hda_codec_t		*codec;
	audiohd_path_t		*path;
	audiohd_widget_t	*widget, *sumwgt;
	audiohd_pin_t		*pin;
	int			i, j;
	wid_t			wid;

	codec = statep->codec[index];
	if (codec == NULL)
		return;
	for (i = 0; i < statep->pathnum; i++) {
		path = statep->path[i];
		if (path->codec != codec || path->path_type != RECORD)
			continue;
		sumwgt = codec->widget[path->sum_wid];
		if (path && sumwgt &&
		    (sumwgt->type == WTYPE_AUDIO_SEL)) {
			for (j = 0; j < path->pin_nums; j++) {
				wid = path->pin_wid[j];
				widget = codec->widget[wid];
				if (widget == NULL)
					return;
				pin = (audiohd_pin_t *)widget->priv;
				if (select &&
				    pin->device == DTYPE_MIC_IN &&
				    pin->wid == id &&
				    (((pin->config >>
				    AUDIOHD_PIN_CONTP_OFF) &
				    AUDIOHD_PIN_CONTP_MASK) ==
				    AUDIOHD_PIN_CON_JACK)) {
					(void) audioha_codec_verb_get(
					    statep,
					    index,
					    path->sum_wid,
					    AUDIOHDC_VERB_SET_CONN_SEL,
					    path->sum_selconn[j]);
					statep->port[PORT_ADC]->index =
					    path->tag;
					return;
				} else if (!select &&
				    pin->device == DTYPE_MIC_IN &&
				    pin->wid == id &&
				    (((pin->config >>
				    AUDIOHD_PIN_CONTP_OFF) &
				    AUDIOHD_PIN_CONTP_MASK) ==
				    AUDIOHD_PIN_CON_JACK)) {
					(void) audioha_codec_verb_get(
					    statep,
					    index,
					    path->sum_wid,
					    AUDIOHDC_VERB_SET_CONN_SEL,
					    path->sum_selconn[j]);
					statep->port[PORT_ADC]->index =
					    path->tag;
					return;
				}
			}
			if (path == NULL)
				break;
			sumwgt = codec->widget[path->sum_wid];
		}
	}
	/*
	 * If the input istream > 1, we should set the record stream tag
	 * respectively. All the input streams sharing one tag may make the
	 * record sound distorted.
	 */
	if (codec->nistream > 1) {
		for (i = 0; i < statep->pathnum; i++) {
			path = statep->path[i];
			if (!path || path->path_type != RECORD)
				continue;
			for (j = 0; j < path->pin_nums; j++) {
				wid = path->pin_wid[j];
				widget = codec->widget[wid];
				if (widget == NULL)
					return;
				pin = (audiohd_pin_t *)widget->priv;
				if (select &&
				    pin->device == DTYPE_MIC_IN &&
				    pin->wid == id &&
				    (((pin->config >>
				    AUDIOHD_PIN_CONTP_OFF) &
				    AUDIOHD_PIN_CONTP_MASK) ==
				    AUDIOHD_PIN_CON_JACK)) {
					statep->port[PORT_ADC]->index =
					    path->tag;
					return;
				} else if (!select &&
				    pin->device == DTYPE_MIC_IN &&
				    (((pin->config >>
				    AUDIOHD_PIN_CONTP_OFF) &
				    AUDIOHD_PIN_CONTP_MASK) ==
				    AUDIOHD_PIN_CON_FIXED)) {
					statep->port[PORT_ADC]->index =
					    path->tag;
					return;
				}
			}
		}
	}
}
/*
 * audiohd_pin_sense()
 *
 * Description
 *
 * 	When the earphone is plugged into the jack associtated with the pin
 * 	complex, we disable the built in speaker. When the earphone is plugged
 * 	out of the jack, we enable the built in speaker.
 */
static void
audiohd_pin_sense(audiohd_state_t *statep, uint32_t resp, uint32_t respex)
{
	uint8_t			index;
	uint8_t			id;
	uint32_t		rs;
	audiohd_widget_t	*widget;
	audiohd_pin_t		*pin;
	hda_codec_t		*codec;

	index = respex & AUDIOHD_RIRB_CODEC_MASK;
	id = resp >> (AUDIOHD_RIRB_WID_OFF - 1);

	codec = statep->codec[index];
	if (codec == NULL)
		return;
	widget = codec->widget[id];
	if (widget == NULL)
		return;

	rs = audioha_codec_verb_get(statep, index, id,
	    AUDIOHDC_VERB_GET_PIN_SENSE, 0);
	if (rs >> (AUDIOHD_PIN_PRES_OFF - 1) & 1) {
		/* A MIC is plugged in, we select the MIC as input */
		if ((widget->type == WTYPE_PIN) &&
		    (pin = (audiohd_pin_t *)widget->priv) &&
		    (pin->device == DTYPE_MIC_IN)) {
			audiohd_select_mic(statep, index, id, 1);
			return;
		}
		/* output pin is plugged */
		audiohd_change_speaker_state(statep, AUDIOHD_SP_OFF);
	} else {
		/*
		 * A MIC is unplugged, we select the built in MIC
		 * as input.
		 */
		if ((widget->type == WTYPE_PIN) &&
		    (pin = (audiohd_pin_t *)widget->priv) &&
		    (pin->device == DTYPE_MIC_IN)) {
			audiohd_select_mic(statep, index, id, 0);
			return;
		}
		/* output pin is unplugged */
		audiohd_change_speaker_state(statep, AUDIOHD_SP_ON);
	}

}
/*
 * audiohd_intr()
 *
 * Description
 *
 *
 * Arguments:
 *	caddr_t     arg Pointer to the interrupting device's state
 *	            structure
 *
 * Returns:
 *	DDI_INTR_CLAIMED    Interrupt claimed and processed
 *	DDI_INTR_UNCLAIMED  Interrupt not claimed, and thus ignored
 */
static uint_t
audiohd_intr(caddr_t arg1, caddr_t arg2)
{
	audiohd_state_t	*statep = (void *)arg1;
	uint32_t	status;
	uint32_t	regbase;
	uint32_t	resp, respex;
	uint8_t		sdstatus, rirbsts;
	int		i, ret;

	_NOTE(ARGUNUSED(arg2))
	audio_engine_t	*do_adc = NULL;
	audio_engine_t	*do_dac = NULL;


	mutex_enter(&statep->hda_mutex);
	if (statep->suspended) {
		mutex_exit(&statep->hda_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	status = AUDIOHD_REG_GET32(AUDIOHD_REG_INTSTS);
	if (status == 0) {
		mutex_exit(&statep->hda_mutex);
		return (DDI_INTR_UNCLAIMED);
	}
	AUDIOHD_REG_SET32(AUDIOHD_REG_INTSTS, status);

	/*
	 * unsolicited response from pins, maybe something plugged in or out
	 * of the jack.
	 */
	if (status & AUDIOHD_CIS_MASK) {
		/* clear the unsolicited response interrupt */
		rirbsts = AUDIOHD_REG_GET8(AUDIOHD_REG_RIRBSTS);
		AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBSTS, rirbsts);
		/*
		 * We have to wait and try several times to make sure the
		 * unsolicited response is generated by our pins.
		 * we need to make it work for audiohd spec 0.9, which is
		 * just a draft version and requires more time to wait.
		 */
		for (i = 0; i < AUDIOHD_TEST_TIMES; i++) {
			ret = audiohd_response_from_codec(statep, &resp,
			    &respex);
			if ((ret == DDI_SUCCESS) &&
			    (respex & AUDIOHD_RIRB_UR_MASK)) {
				/*
				 * A pin may generate more than one ur rirb,
				 * we only need handle one of them, and clear
				 * the other ones
				 */
				statep->hda_rirb_rp =
				    AUDIOHD_REG_GET16(AUDIOHD_REG_RIRBWP) &
				    AUDIOHD_RIRB_WPMASK;
				break;
			}
		}
		if ((ret == DDI_SUCCESS) &&
		    (respex & AUDIOHD_RIRB_UR_MASK)) {
			audiohd_pin_sense(statep, resp, respex);
		}
	}

	/* stream intr */
	for (i = 0; i < statep->hda_streams_nums; i++) {
		if ((status & (1<<i)) == 0)
			continue;

		regbase = AUDIOHD_REG_SD_BASE + AUDIOHD_REG_SD_LEN * i;
		sdstatus = AUDIOHD_REG_GET8(regbase + AUDIOHD_SDREG_OFFSET_STS);

		/* clear intrs */
		AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_STS, sdstatus);
		if (i < statep->hda_input_streams)
			do_adc = statep->port[PORT_ADC]->engine;
		else
			do_dac = statep->port[PORT_DAC]->engine;
	}

	/* update the kernel interrupt statistics */
	if (statep->hda_ksp) {
		((kstat_intr_t *)
		    (statep->hda_ksp->ks_data))->intrs[KSTAT_INTR_HARD]++;
	}

	mutex_exit(&statep->hda_mutex);

	if (do_adc)
		audio_engine_produce(do_adc);
	if (do_dac)
		audio_engine_consume(do_dac);
	return (DDI_INTR_CLAIMED);
}	/* audiohd_intr() */

/*
 * audiohd_disable_intr()
 *
 * Description:
 *	Disable all possible interrupts.
 */
static void
audiohd_disable_intr(audiohd_state_t *statep)
{
	int		i;
	uint32_t	base;

	AUDIOHD_REG_SET32(AUDIOHD_REG_INTCTL, 0);
	base = AUDIOHD_REG_SD_BASE;
	for (i = 0; i < statep->hda_streams_nums; i++) {
		AUDIOHD_REG_SET8(base + AUDIOHD_SDREG_OFFSET_STS,
		    AUDIOHDR_SD_STS_INTRS);
		base += AUDIOHD_REG_SD_LEN;
	}
	AUDIOHD_REG_SET32(AUDIOHD_REG_INTSTS, (uint32_t)(-1));

}	/* audiohd_disable_intr() */


/*
 * audiohd_12bit_verb_to_codec()
 *
 * Description:
 *
 */
static int
audiohd_12bit_verb_to_codec(audiohd_state_t *statep, uint8_t caddr,
    uint8_t wid,
    uint16_t cmd, uint8_t param)
{
	uint32_t	verb;
	uint16_t	wptr;
	uint16_t	rptr;

	ASSERT((cmd & AUDIOHDC_12BIT_VERB_MASK) == 0);

	wptr = AUDIOHD_REG_GET16(AUDIOHD_REG_CORBWP) & AUDIOHD_CMDIO_ENT_MASK;
	rptr = AUDIOHD_REG_GET16(AUDIOHD_REG_CORBRP) & AUDIOHD_CMDIO_ENT_MASK;

	wptr++;
	wptr &= AUDIOHD_CMDIO_ENT_MASK;

	/* overflow */
	if (wptr == rptr) {
		return (DDI_FAILURE);
	}

	verb = (caddr & 0x0f) << AUDIOHD_VERB_ADDR_OFF;
	verb |= wid << AUDIOHD_VERB_NID_OFF;
	verb |= cmd << AUDIOHD_VERB_CMD_OFF;
	verb |= param;

	*((uint32_t *)(statep->hda_dma_corb.ad_vaddr) + wptr) = verb;
	(void) ddi_dma_sync(statep->hda_dma_corb.ad_dmahdl, 0,
	    sizeof (sd_bdle_t) * AUDIOHD_BDLE_NUMS, DDI_DMA_SYNC_FORDEV);
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBWP, wptr);

	return (DDI_SUCCESS);

}	/* audiohd_12bit_verb_to_codec() */

/*
 * audiohd_4bit_verb_to_codec()
 *
 * Description:
 *
 */
static int
audiohd_4bit_verb_to_codec(audiohd_state_t *statep, uint8_t caddr,
    uint8_t wid,
    uint32_t cmd, uint16_t param)
{
	uint32_t	verb;
	uint16_t	wptr;
	uint16_t	rptr;

	ASSERT((cmd & AUDIOHDC_4BIT_VERB_MASK) == 0);

	wptr = AUDIOHD_REG_GET16(AUDIOHD_REG_CORBWP) & AUDIOHD_CMDIO_ENT_MASK;
	rptr = AUDIOHD_REG_GET16(AUDIOHD_REG_CORBRP) & AUDIOHD_CMDIO_ENT_MASK;

	wptr++;
	wptr &= AUDIOHD_CMDIO_ENT_MASK;

	/* overflow */
	if (wptr == rptr) {
		return (DDI_FAILURE);
	}

	verb = (caddr & 0x0f) << AUDIOHD_VERB_ADDR_OFF;
	verb |= wid << AUDIOHD_VERB_NID_OFF;
	verb |= cmd << AUDIOHD_VERB_CMD16_OFF;
	verb |= param;

	*((uint32_t *)(statep->hda_dma_corb.ad_vaddr) + wptr) = verb;
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBWP, wptr);

	return (DDI_SUCCESS);

}	/* audiohd_4bit_verb_to_codec() */

/*
 * audiohd_response_from_codec()
 *
 * Description:
 *
 */
static int
audiohd_response_from_codec(audiohd_state_t *statep, uint32_t *resp,
    uint32_t *respex)
{
	uint16_t	wptr;
	uint16_t	rptr;
	uint32_t	*lp;

	wptr = AUDIOHD_REG_GET16(AUDIOHD_REG_RIRBWP) & 0x00ff;
	rptr = statep->hda_rirb_rp;

	if (rptr == wptr) {
		return (DDI_FAILURE);
	}

	rptr++;
	rptr &= AUDIOHD_RING_MAX_SIZE;

	lp = (uint32_t *)(statep->hda_dma_rirb.ad_vaddr) + (rptr << 1);
	*resp = *(lp);
	*respex = *(lp + 1);

	statep->hda_rirb_rp = rptr;

	return (DDI_SUCCESS);

}	/* audiohd_response_from_codec() */


/*
 * audioha_codec_verb_get()
 */
static uint32_t
audioha_codec_verb_get(void *arg, uint8_t caddr, uint8_t wid,
    uint16_t verb,
    uint8_t param)
{
	audiohd_state_t	*statep = (audiohd_state_t *)arg;
	uint32_t	resp;
	uint32_t	respex;
	int		ret;
	int		i;

	ret = audiohd_12bit_verb_to_codec(statep, caddr, wid, verb, param);
	if (ret != DDI_SUCCESS) {
		return (uint32_t)(-1);
	}

	/*
	 * Empirical testing times. 50 times is enough for audiohd spec 1.0.
	 * But we need to make it work for audiohd spec 0.9, which is just a
	 * draft version and requires more time to wait.
	 */
	for (i = 0; i < 500; i++) {
		ret = audiohd_response_from_codec(statep, &resp, &respex);
		if (((respex & AUDIOHD_BDLE_RIRB_SDI) == caddr) &&
		    ((respex & AUDIOHD_BDLE_RIRB_UNSOLICIT) == 0) &&
		    (ret == DDI_SUCCESS))
			break;
		/* Empirical testing time, which works well */
		drv_usecwait(30);
	}

	if (ret == DDI_SUCCESS) {
		return (resp);
	}

	audio_dev_warn(statep->adev, "timeout when get "
	    "response from codec: wid=%d, verb=0x%04x, param=0x%04x",
	    wid, verb, param);

	return ((uint32_t)(-1));

}	/* audioha_codec_verb_get() */


/*
 * audioha_codec_4bit_verb_get()
 */
static uint32_t
audioha_codec_4bit_verb_get(void *arg, uint8_t caddr, uint8_t wid,
    uint16_t verb, uint16_t param)
{
	audiohd_state_t	*statep = (audiohd_state_t *)arg;
	uint32_t	resp;
	uint32_t	respex;
	int		ret;
	int		i;

	ret = audiohd_4bit_verb_to_codec(statep, caddr, wid, verb, param);
	if (ret != DDI_SUCCESS) {
		return (uint32_t)(-1);
	}

	for (i = 0; i < 500; i++) {
		ret = audiohd_response_from_codec(statep, &resp, &respex);
		if (((respex & AUDIOHD_BDLE_RIRB_SDI) == caddr) &&
		    ((respex & AUDIOHD_BDLE_RIRB_UNSOLICIT) == 0) &&
		    (ret == DDI_SUCCESS))
			break;
		/* Empirical testing time, which works well */
		drv_usecwait(30);
	}

	if (ret == DDI_SUCCESS) {
		return (resp);
	}

	audio_dev_warn(statep->adev,  "timeout when get "
	    " response from codec: wid=%d, verb=0x%04x, param=0x%04x",
	    wid, verb, param);

	return ((uint32_t)(-1));

}	/* audioha_codec_4bit_verb_get() */
