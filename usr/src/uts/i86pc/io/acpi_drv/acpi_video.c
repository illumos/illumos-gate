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
 *  Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2015 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

/*
 * Solaris x86 Generic ACPI Video Extensions Hotkey driver
 */
#include <sys/hotkey_drv.h>
#include <sys/smbios.h>

/*
 * Vendor specific hotkey support list
 * 	1. Toshiba: acpi_toshiba
 */
struct vendor_hotkey_drv vendor_hotkey_drv_list[] = {
/* vendor,	module name,		enable? */
{"Toshiba",	"acpi_toshiba",		B_TRUE},
/* Terminator */
{NULL,		NULL,			B_FALSE}
};

enum vga_output_type {
	OUTPUT_OTHER,
	OUTPUT_CRT,
	OUTPUT_TV,
	OUTPUT_DVI,
	OUTPUT_LCD
};

struct acpi_video_output {
	struct acpi_drv_dev dev;
	uint32_t			adr;
	enum vga_output_type		type;
	struct acpi_video_output	*next;
};

struct acpi_video_brightness {
	struct acpi_drv_dev dev;
	uint32_t			adr;
	uint32_t			nlevel;
	int				*levels;
	int				cur_level;
	uint32_t			cur_level_index;
	uint32_t			output_index;
	struct acpi_video_brightness	*next;
};

struct acpi_video_switch {
	struct acpi_drv_dev		dev;
	struct acpi_video_switch	*next;
};

/* ACPI video extension hotkey for video switch and brightness control */
static struct acpi_video {
	struct acpi_video_output	*vid_outputs;
	uint32_t			total_outputs;
	struct acpi_video_brightness	*vid_brightness;
	uint32_t			total_brightness;
	struct acpi_video_switch	*vid_switch;
	uint32_t			total_switch;
} acpi_video_hotkey;

int hotkey_drv_debug = 0;

static struct acpi_video_smbios_info {
	char *manufacturer;
	char *product;
} acpi_brightness_get_blacklist[] = {
	{ /* Dell AdamoXPS laptop */
		"Dell Inc.",
		"Adamo XPS"
	},
	{ /* termination entry */
		NULL,
		NULL
	}
};
/*
 * -1 = check acpi_brightness_get_blacklist[].
 * 0 = enable brightness get.
 * 1 = disable brightness get.
 */
int acpi_brightness_get_disable = -1;


#define	ACPI_METHOD_DOS			"_DOS"
#define	ACPI_METHOD_DOD			"_DOD"

#define	ACPI_DEVNAME_CRT		"CRT"
#define	ACPI_DEVNAME_LCD		"LCD"
#define	ACPI_DEVNAME_TV			"TV"
#define	ACPI_METHOD_ADR			"_ADR"
#define	ACPI_METHOD_DDC			"_DDC"
#define	ACPI_METHOD_DCS			"_DCS"
#define	ACPI_METHOD_DGS			"_DGS"
#define	ACPI_METHOD_DSS			"_DSS"

#define	VIDEO_NOTIFY_SWITCH		0x80
#define	VIDEO_NOTIFY_SWITCH_STATUS	0x81
#define	VIDEO_NOTIFY_SWITCH_CYCLE	0x82
#define	VIDEO_NOTIFY_SWITCH_NEXT	0x83
#define	VIDEO_NOTIFY_SWITCH_PREV	0x84

#define	VIDEO_NOTIFY_BRIGHTNESS_CYCLE	0x85
#define	VIDEO_NOTIFY_BRIGHTNESS_INC	0x86
#define	VIDEO_NOTIFY_BRIGHTNESS_DEC	0x87
#define	VIDEO_NOTIFY_BRIGHTNESS_ZERO	0x88

/* Output device status */
#define	ACPI_DRV_DCS_CONNECTOR_EXIST	(1 << 0)
#define	ACPI_DRV_DCS_ACTIVE		(1 << 1)
#define	ACPI_DRV_DCS_READY		(1 << 2)
#define	ACPI_DRV_DCS_FUNCTIONAL		(1 << 3)
#define	ACPI_DRV_DCS_ATTACHED		(1 << 4)

/* _DOS default value is 1 */
/* _DOS bit 1:0 */
#define	VIDEO_POLICY_SWITCH_OS		0x0
#define	VIDEO_POLICY_SWITCH_BIOS	0x1
#define	VIDEO_POLICY_SWITCH_LOCKED	0x2
#define	VIDEO_POLICY_SWITCH_OS_EVENT	0x3

/* _DOS bit 2 */
#define	VIDEO_POLICY_BRIGHTNESS_OS	0x4
#define	VIDEO_POLICY_BRIGHTNESS_BIOS	0x0

/* Set _DOS for video control policy */
static void
acpi_video_set_dos(struct acpi_video *vidp, uint32_t policy)
{
	struct acpi_video_switch *vidsp;
	ACPI_STATUS status;
	ACPI_OBJECT obj;
	ACPI_OBJECT_LIST objlist;

	obj.Type = ACPI_TYPE_INTEGER;
	obj.Integer.Value = policy;
	objlist.Count = 1;
	objlist.Pointer = &obj;

	vidsp = vidp->vid_switch;
	while (vidsp != NULL) {
		status = AcpiEvaluateObject(vidsp->dev.hdl, ACPI_METHOD_DOS,
		    &objlist, NULL);
		if (ACPI_FAILURE(status))
			cmn_err(CE_WARN, "!acpi_video_set_dos failed.");
		vidsp = vidsp->next;
	}
}

/*
 * Get the current brightness level and index.
 */
static int
acpi_video_brightness_get(struct acpi_video_brightness *vidbp)
{
	int i;

	if (acpi_brightness_get_disable) {
		/* simply initialize current brightness to the highest level */
		vidbp->cur_level_index = vidbp->nlevel - 1;
		vidbp->cur_level = vidbp->levels[vidbp->cur_level_index];
		return (ACPI_DRV_OK);
	}

	if (acpica_eval_int(vidbp->dev.hdl, "_BQC", &vidbp->cur_level)
	    != AE_OK) {
		vidbp->cur_level = 0;
		return (ACPI_DRV_ERR);
	}

	for (i = 0; i < vidbp->nlevel; i++) {
		if (vidbp->levels[i] == vidbp->cur_level) {
			vidbp->cur_level_index = i;
			if (hotkey_drv_debug & HOTKEY_DBG_NOTICE) {
				cmn_err(CE_NOTE, "!acpi_video_brightness_get():"
				    " cur_level = %d, cur_level_index = %d\n",
				    vidbp->cur_level, i);
			}
			break;
		}
	}

	return (ACPI_DRV_OK);
}

static int
acpi_video_brightness_set(struct acpi_video_brightness *vidbp, uint32_t level)
{
	if (acpi_drv_set_int(vidbp->dev.hdl, "_BCM", vidbp->levels[level])
	    != AE_OK) {
		return (ACPI_DRV_ERR);
	}

	vidbp->cur_level = vidbp->levels[level];
	vidbp->cur_level_index = level;

	return (ACPI_DRV_OK);
}

void
hotkey_drv_gen_sysevent(dev_info_t *dip, char *event)
{
	int err;

	/* Generate/log EC_ACPIEV sysevent */
	err = ddi_log_sysevent(dip, DDI_VENDOR_SUNW, EC_ACPIEV,
	    event, NULL, NULL, DDI_NOSLEEP);

	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "!failed to log hotkey sysevent, err code %x\n", err);
	}
}

/*ARGSUSED*/
static void
acpi_video_switch_notify(ACPI_HANDLE hdl, uint32_t notify, void *ctx)
{
	if (hotkey_drv_debug & HOTKEY_DBG_NOTICE) {
		cmn_err(CE_NOTE, "!acpi_video_switch_notify: got event 0x%x.\n",
		    notify);
	}

	mutex_enter(acpi_hotkey.hotkey_lock);
	switch (notify) {
	case VIDEO_NOTIFY_SWITCH:
	case VIDEO_NOTIFY_SWITCH_CYCLE:
	case VIDEO_NOTIFY_SWITCH_NEXT:
	case VIDEO_NOTIFY_SWITCH_PREV:
		hotkey_drv_gen_sysevent(acpi_hotkey.dip,
		    ESC_ACPIEV_DISPLAY_SWITCH);
		break;

	case VIDEO_NOTIFY_SWITCH_STATUS:
		break;

	default:
		if (hotkey_drv_debug) {
			cmn_err(CE_NOTE,
			    "!acpi_video_switch_notify: unknown event 0x%x.\n",
			    notify);
		}
	}
	mutex_exit(acpi_hotkey.hotkey_lock);
}

/*ARGSUSED*/
static void
acpi_video_brightness_notify(ACPI_HANDLE hdl, uint32_t notify, void *ctx)
{
	struct acpi_video_brightness *vidbp = ctx;

	if (hotkey_drv_debug & HOTKEY_DBG_NOTICE) {
		cmn_err(CE_NOTE,
		    "!acpi_video_brightness_notify: got event 0x%x.\n",
		    notify);
	}

	mutex_enter(acpi_hotkey.hotkey_lock);
	switch (notify) {
	case VIDEO_NOTIFY_BRIGHTNESS_CYCLE:
	case VIDEO_NOTIFY_BRIGHTNESS_INC:
		if (vidbp->cur_level_index < vidbp->nlevel - 1) {
			if (acpi_video_brightness_set(vidbp,
			    vidbp->cur_level_index + 1) != ACPI_DRV_OK) {
				break;
			}
		}
		acpi_drv_gen_sysevent(&vidbp->dev, ESC_PWRCTL_BRIGHTNESS_UP, 0);
		break;
	case VIDEO_NOTIFY_BRIGHTNESS_DEC:
		if (vidbp->cur_level_index > 0) {
			if (acpi_video_brightness_set(vidbp,
			    vidbp->cur_level_index - 1) != ACPI_DRV_OK) {
				break;
			}
		}
		acpi_drv_gen_sysevent(&vidbp->dev, ESC_PWRCTL_BRIGHTNESS_DOWN,
		    0);
		break;
	case VIDEO_NOTIFY_BRIGHTNESS_ZERO:
		if (acpi_video_brightness_set(vidbp, 0) != ACPI_DRV_OK) {
			break;
		}
		acpi_drv_gen_sysevent(&vidbp->dev, ESC_PWRCTL_BRIGHTNESS_DOWN,
		    0);
		break;

	default:
		if (hotkey_drv_debug) {
			cmn_err(CE_NOTE, "!acpi_video_brightness_notify: "
			    "unknown event 0x%x.\n", notify);
		}
	}
	mutex_exit(acpi_hotkey.hotkey_lock);
}

static int
acpi_video_notify_intall(struct acpi_video *vidp)
{
	ACPI_STATUS status;
	struct acpi_video_switch *vidsp;
	struct acpi_video_brightness *vidbp;
	int i;

	/* bind video switch notify */
	vidsp = vidp->vid_switch;
	for (i = 0; i < vidp->total_switch && vidsp != NULL; i++) {
		status = AcpiInstallNotifyHandler(vidsp->dev.hdl,
		    ACPI_DEVICE_NOTIFY, acpi_video_switch_notify, vidsp);
		if (ACPI_FAILURE(status)) {
			cmn_err(CE_WARN,
			    "!vids handler install failed = %d, vids = %p.",
			    status, (void *) vidsp);
		}
		vidsp = vidsp->next;
	}

	/* bind brightness control notify */
	vidbp = vidp->vid_brightness;
	for (i = 0; i < vidp->total_brightness && vidbp != NULL; i++) {
		status = AcpiInstallNotifyHandler(vidbp->dev.hdl,
		    ACPI_DEVICE_NOTIFY, acpi_video_brightness_notify, vidbp);
		if (ACPI_FAILURE(status)) {
			cmn_err(CE_WARN,
			    "!brightness handler install failed = %x, "
			    "brightness = %p.", status, (void *) vidbp);
		}
		vidbp = vidbp->next;
	}

	return (ACPI_DRV_OK);
}

static int
acpi_video_notify_unintall(struct acpi_video *vidp)
{
	struct acpi_video_switch *vidsp;
	struct acpi_video_brightness *vidbp;
	int i;

	/* unbind video switch notify */
	vidsp = vidp->vid_switch;
	for (i = 0; i < vidp->total_switch && vidsp != NULL; i++) {
		(void) AcpiRemoveNotifyHandler(vidsp->dev.hdl,
		    ACPI_DEVICE_NOTIFY, acpi_video_switch_notify);
		vidsp = vidsp->next;
	}

	/* unbind brightness control notify */
	vidbp = vidp->vid_brightness;
	for (i = 0; i < vidp->total_brightness && vidbp != NULL; i++) {
		(void) AcpiRemoveNotifyHandler(vidbp->dev.hdl,
		    ACPI_DEVICE_NOTIFY, acpi_video_brightness_notify);
		vidbp = vidbp->next;
	}

	return (ACPI_DRV_OK);
}

static int
acpi_video_free(struct acpi_video *vidp)
{
	struct acpi_video_switch *vidsp;
	struct acpi_video_switch *vidsp_next;
	struct acpi_video_brightness *vidbp;
	struct acpi_video_brightness *vidbp_next;
	struct acpi_video_output *vidop;
	struct acpi_video_output *vidop_next;

	/* free video switch objects */
	vidsp = vidp->vid_switch;
	while (vidsp != NULL) {
		vidsp_next = vidsp->next;
		kmem_free(vidsp, sizeof (struct acpi_video_switch));
		vidsp = vidsp_next;
	}

	/* free video brightness control objects */
	vidbp = vidp->vid_brightness;
	while (vidbp != NULL) {
		vidbp_next = vidbp->next;
		kmem_free(vidbp, sizeof (struct acpi_video_brightness));
		vidbp = vidbp_next;
	}

	/* free video output objects */
	vidop = vidp->vid_outputs;
	while (vidop != NULL) {
		vidop_next = vidop->next;
		kmem_free(vidop, sizeof (struct acpi_video_output));
		vidop = vidop_next;
	}

	return (ACPI_DRV_OK);
}

static int
acpi_video_fini(struct acpi_video *vidp)
{
	(void) acpi_video_notify_unintall(vidp);

	return (acpi_video_free(vidp));
}

static int
acpi_video_enum_output(ACPI_HANDLE hdl, struct acpi_video *vidp)
{
	int adr;
	struct acpi_video_brightness *vidbp;
	struct acpi_video_output *vidop;
	ACPI_BUFFER buf = {ACPI_ALLOCATE_BUFFER, NULL};
	ACPI_OBJECT *objp;


	if (acpica_eval_int(hdl, "_ADR", &adr) != AE_OK)
		return (ACPI_DRV_ERR);

	/* Allocate object */
	vidop = kmem_zalloc(sizeof (struct acpi_video_output), KM_SLEEP);
	vidop->dev.hdl = hdl;
	(void) acpi_drv_dev_init(&vidop->dev);
	vidop->adr = adr;
	vidop->type = adr;
	vidop->next = vidp->vid_outputs;
	vidp->vid_outputs = vidop;

	if (ACPI_SUCCESS(AcpiEvaluateObjectTyped(hdl, "_BCL",
	    NULL, &buf, ACPI_TYPE_PACKAGE))) {
		int i, j, k, l, m, nlev, tmp;

		vidbp = kmem_zalloc(sizeof (struct acpi_video_brightness),
		    KM_SLEEP);
		vidbp->dev = vidop->dev;
		vidop->adr = adr;
		vidbp->output_index = vidp->total_outputs;
		objp = buf.Pointer;

		/*
		 * op->nlev will be needed to free op->levels.
		 */
		vidbp->nlevel = nlev = objp->Package.Count;
		vidbp->levels = kmem_zalloc(nlev * sizeof (uint32_t), KM_SLEEP);

		/*
		 * Get all the supported brightness levels.
		 */
		for (i = 0; i < nlev; i++) {
			ACPI_OBJECT *o = &objp->Package.Elements[i];
			int lev = o->Integer.Value;

			if (hotkey_drv_debug & HOTKEY_DBG_NOTICE) {
				cmn_err(CE_NOTE, "!acpi_video_enum_output() "
				    "brlev=%d i=%d nlev=%d\n", lev, i, nlev);
			}
			if (o->Type != ACPI_TYPE_INTEGER) {
				continue;
			}
			vidbp->levels[i] = lev;
		}

		/*
		 * Sort the brightness levels.
		 */
		for (j = 0; j < nlev; j++) {
			for (k = 0; k < nlev - 1; k++) {
				if (vidbp->levels[k] > vidbp->levels[k+1]) {
					tmp = vidbp->levels[k+1];
					vidbp->levels[k+1] = vidbp->levels[k];
					vidbp->levels[k] = tmp;
				}
			}
		}

		/*
		 * The first two levels could be duplicated, so remove
		 * any duplicates.
		 */
		for (l = 0; l < nlev - 1; l++) {
			if (vidbp->levels[l] == vidbp->levels[l+1]) {
				for (m = l + 1; m < nlev - 1; m++) {
					vidbp->levels[m] = vidbp->levels[m+1];
				}
				nlev--;
			}
		}

		vidbp->nlevel = nlev;
		(void) acpi_video_brightness_get(vidbp);
		vidbp->next = vidp->vid_brightness;
		vidp->vid_brightness = vidbp;
		vidp->total_brightness++;

		AcpiOsFree(objp);
	}

	vidp->total_outputs++;

	return (ACPI_DRV_OK);
}

/*ARGSUSED*/
static ACPI_STATUS
acpi_video_find_and_alloc(ACPI_HANDLE hdl, UINT32 nest, void *ctx,
    void **rv)
{
	ACPI_HANDLE tmphdl;
	ACPI_STATUS err;
	ACPI_BUFFER buf = {ACPI_ALLOCATE_BUFFER, NULL};
	struct acpi_video *vidp;
	struct acpi_video_switch *vidsp;

	err = AcpiGetHandle(hdl, ACPI_METHOD_DOS, &tmphdl);
	if (err != AE_OK)
		return (AE_OK);

	err = AcpiGetHandle(hdl, ACPI_METHOD_DOD, &tmphdl);
	if (err != AE_OK)
		return (AE_OK);

	vidp = (struct acpi_video *)ctx;
	vidsp = kmem_zalloc(sizeof (struct acpi_video_switch), KM_SLEEP);
	vidsp->dev.hdl = hdl;
	(void) acpi_drv_dev_init(&vidsp->dev);
	vidsp->next = vidp->vid_switch;
	vidp->vid_switch = vidsp;
	vidp->total_switch++;

	/*
	 * Enumerate the output devices.
	 */
	while (ACPI_SUCCESS(AcpiGetNextObject(ACPI_TYPE_DEVICE,
	    hdl, tmphdl, &tmphdl))) {
		(void) acpi_video_enum_output(tmphdl, vidp);
	}

	if (!ACPI_FAILURE(AcpiGetName(hdl, ACPI_FULL_PATHNAME, &buf))) {
		if (buf.Pointer) {
			if (hotkey_drv_debug & HOTKEY_DBG_NOTICE) {
				cmn_err(CE_NOTE,
				    "!acpi video switch hdl = 0x%p, path = %s.",
				    hdl, (char *)buf.Pointer);
			}
			AcpiOsFree(buf.Pointer);
		}
	}

	return (AE_OK);
}

int
hotkey_brightness_inc(hotkey_drv_t *htkp)
{
	struct acpi_video *vidp;
	struct acpi_video_brightness *vidbp;

	vidp = (struct acpi_video *)htkp->acpi_video;

	for (vidbp = vidp->vid_brightness; vidbp != NULL; vidbp = vidbp->next) {
		if (vidbp->cur_level_index < vidbp->nlevel - 1) {
			if (acpi_video_brightness_set(vidbp,
			    vidbp->cur_level_index + 1) != ACPI_DRV_OK) {
				return (ACPI_DRV_ERR);
			}
		}
	}
	return (ACPI_DRV_OK);
}

int
hotkey_brightness_dec(hotkey_drv_t *htkp)
{
	struct acpi_video *vidp;
	struct acpi_video_brightness *vidbp;

	vidp = (struct acpi_video *)htkp->acpi_video;

	for (vidbp = vidp->vid_brightness; vidbp != NULL; vidbp = vidbp->next) {
		if (vidbp->cur_level_index > 0) {
			if (acpi_video_brightness_set(vidbp,
			    vidbp->cur_level_index - 1) != ACPI_DRV_OK) {
				return (ACPI_DRV_ERR);
			}
		}
	}

	return (ACPI_DRV_OK);
}

/*ARGSUSED*/
int
acpi_video_ioctl(void *p, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval)
{
	struct acpi_video *vidp = p;
	struct acpi_video_brightness *vidbp;
	int res = 0;

	if (vidp == NULL)
		return (ENXIO);

	vidbp = vidp->vid_brightness;
	if (vidbp == NULL)
		return (ENXIO);

	if (hotkey_drv_debug & HOTKEY_DBG_NOTICE) {
		cmn_err(CE_NOTE, "!acpi_video_ioctl cmd %d\n", cmd);
	}

	switch (cmd) {
	case ACPI_DRV_IOC_INFO:
	{
		struct acpi_drv_output_info inf;

		inf.adr = vidbp->adr;
		inf.nlev = vidbp->nlevel;
		if (copyout(&inf, (void *)arg, sizeof (inf))) {
			res = EFAULT;
		}
		break;
	}

	case ACPI_DRV_IOC_LEVELS:
		if (copyout(vidbp->levels, (void *)arg,
		    sizeof (*vidbp->levels) * vidbp->nlevel)) {
			res = EFAULT;
		}
		break;

	case ACPI_DRV_IOC_STATUS:
	{
		/*
		 * Need to get the current levels through ACPI first
		 * then go through array of levels to find index.
		 */
		struct acpi_drv_output_status status;
		int i;

		status.state = 0;
		status.num_levels = vidbp->nlevel;
		status.cur_level = vidbp->cur_level;
		for (i = 0; i < vidbp->nlevel; i++) {
			if (vidbp->levels[i] == vidbp->cur_level) {
				status.cur_level_index = i;
				if (hotkey_drv_debug & HOTKEY_DBG_NOTICE) {
					cmn_err(CE_NOTE, "!ACPI_DRV_IOC_STATUS "
					    "cur_level_index %d\n", i);
				}
				break;
			}
		}
		if (copyout(&status, (void *)arg, sizeof (status))) {
			res = EFAULT;
		}
		break;
	}

	case ACPI_DRV_IOC_SET_BRIGHTNESS: {
		int level;

		if (drv_priv(cr)) {
			res = EPERM;
			break;
		}
		if (copyin((void *)arg, &level, sizeof (level))) {
			res = EFAULT;
			break;
		}
		if (hotkey_drv_debug & HOTKEY_DBG_NOTICE) {
			cmn_err(CE_NOTE,
			    "!acpi_video_ioctl: set BRIGHTNESS level=%d\n",
			    level);
		}
		if (acpi_video_brightness_set(vidbp, level) != ACPI_DRV_OK) {
			res = EFAULT;
		}
		break;
	}

	default:
		res = EINVAL;
		break;
	}

	return (res);
}

/*ARGSUSED*/
int
acpi_drv_hotkey_ioctl(int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval)
{
	hotkey_drv_t *htkp = &acpi_hotkey;

	switch (htkp->hotkey_method) {
	case HOTKEY_METHOD_ACPI_VIDEO:
		return (acpi_video_ioctl(htkp->acpi_video, cmd, arg, mode,
		    cr, rval));
	case HOTKEY_METHOD_MISC:
	case HOTKEY_METHOD_VENDOR:
		return (htkp->vendor_ioctl(htkp, cmd, arg, mode, cr, rval));
	case HOTKEY_METHOD_NONE:
	default:
		return (ENXIO);
	}
}

static void
acpi_video_check_blacklist(void)
{
	smbios_hdl_t *smhdl = NULL;
	id_t smid;
	smbios_system_t smsys;
	smbios_info_t sminfo;
	char *mfg, *product;
	struct acpi_video_smbios_info *pblacklist;

	acpi_brightness_get_disable = 0;
	smhdl = smbios_open(NULL, SMB_VERSION, ksmbios_flags, NULL);
	if (smhdl == NULL ||
	    ((smid = smbios_info_system(smhdl, &smsys)) == SMB_ERR) ||
	    (smbios_info_common(smhdl, smid, &sminfo) == SMB_ERR)) {
		goto done;
	}

	mfg = (char *)sminfo.smbi_manufacturer;
	product = (char *)sminfo.smbi_product;
	for (pblacklist = acpi_brightness_get_blacklist;
	    pblacklist->manufacturer != NULL; pblacklist++) {
		if ((strcmp(mfg, pblacklist->manufacturer) == 0) &&
		    (strcmp(product, pblacklist->product) == 0)) {
			acpi_brightness_get_disable = 1;
		}
	}
done:
	if (smhdl != NULL)
		smbios_close(smhdl);
}

static int
hotkey_acpi_video_check(hotkey_drv_t *htkp)
{
	struct acpi_video *vidp;

	vidp = &acpi_video_hotkey;
	bzero(vidp, sizeof (struct acpi_video));
	if (acpi_brightness_get_disable == -1)
		acpi_video_check_blacklist();
	/* Find ACPI Video device handle */
	if (ACPI_FAILURE(AcpiGetDevices(NULL, acpi_video_find_and_alloc,
	    vidp, NULL))) {
		return (ACPI_DRV_ERR);
	}

	htkp->acpi_video = vidp;
	if (htkp->hotkey_method == HOTKEY_METHOD_NONE) {
		if (acpi_video_notify_intall(vidp) != ACPI_DRV_OK) {
			(void) acpi_video_fini(vidp);
			htkp->acpi_video = NULL;
			return (ACPI_DRV_ERR);
		}
	}
	htkp->hotkey_method |= HOTKEY_METHOD_ACPI_VIDEO;

	acpi_video_set_dos(vidp, VIDEO_POLICY_BRIGHTNESS_OS |
	    VIDEO_POLICY_SWITCH_OS);

	return (ACPI_DRV_OK);
}

int
hotkey_init(hotkey_drv_t *htkp)
{
	int i;
	int modid;
	modctl_t *modp;

	htkp->modid = -1;
	/* Try to find vendor specific method */
	for (i = 0; vendor_hotkey_drv_list[i].module != NULL; i++) {
		if (!vendor_hotkey_drv_list[i].enable)
			continue;

		if ((modid = modload("drv", vendor_hotkey_drv_list[i].module))
		    == -1) {
			continue;
		}

		htkp->modid = modid;
		if (hotkey_drv_debug & HOTKEY_DBG_NOTICE) {
			cmn_err(CE_NOTE, "!loaded %s specific method.\n",
			    vendor_hotkey_drv_list[i].vid);
		}
	}

	/* Check availability of ACPI Video Extension method */
	if (htkp->hotkey_method == HOTKEY_METHOD_NONE ||
	    htkp->check_acpi_video) {
		if (hotkey_acpi_video_check(htkp) == ACPI_DRV_OK) {
			if (hotkey_drv_debug & HOTKEY_DBG_NOTICE)
				cmn_err(CE_NOTE, "!find ACPI video method.\n");
		} else
			goto fail;
	}

	if (htkp->modid != -1) {
		modp = mod_hold_by_id(htkp->modid);
		mutex_enter(&mod_lock);
		modp->mod_ref = 1;
		modp->mod_loadflags |= MOD_NOAUTOUNLOAD;
		mutex_exit(&mod_lock);
		mod_release_mod(modp);
	}

	/* Create minor node for hotkey device. */
	if (ddi_create_minor_node(htkp->dip, "hotkey", S_IFCHR,
	    MINOR_HOTKEY(0), DDI_PSEUDO, 0) == DDI_FAILURE) {
		if (hotkey_drv_debug & HOTKEY_DBG_WARN)
			cmn_err(CE_WARN, "hotkey: minor node create failed");
		goto fail;
	}

	return (ACPI_DRV_OK);

fail:
	if (htkp->vendor_fini != NULL)
		htkp->vendor_fini(htkp);
	if (htkp->modid != -1)
		(void) modunload(htkp->modid);

	return (ACPI_DRV_ERR);
}


int
hotkey_fini(hotkey_drv_t *htkp)
{
	modctl_t *modp;

	if (htkp->vendor_fini != NULL)
		htkp->vendor_fini(htkp);
	if (htkp->acpi_video != NULL)
		(void) acpi_video_fini(htkp->acpi_video);
	if (htkp->modid != -1) {
		modp = mod_hold_by_id(htkp->modid);
		mutex_enter(&mod_lock);
		modp->mod_ref = 0;
		modp->mod_loadflags &= ~MOD_NOAUTOUNLOAD;
		mutex_exit(&mod_lock);
		mod_release_mod(modp);
		(void) modunload(htkp->modid);
	}

	return (ACPI_DRV_OK);
}
