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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <devfsadm.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>

extern char *devfsadm_get_devices_dir();
static int usb_process(di_minor_t minor, di_node_t node);

static void ugen_create_link(char *p_path, char *node_name,
    di_node_t node, di_minor_t minor);


/* Rules for creating links */
static devfsadm_create_t usb_cbt[] = {
	{ "usb", NULL, "usb_ac",	DRV_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", NULL, "usb_as",	DRV_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", NULL, "ddivs_usbc",	DRV_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", NULL, "usbvc",		DRV_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", NULL, "hid",		DRV_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", NULL, "hwarc",	DRV_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", NULL, "wusb_ca",	DRV_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_NEXUS, "hubd",	DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_NEXUS, "ohci",	DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_NEXUS, "ehci",	DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_NEXUS, "xhci",	DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_SCSI_NEXUS, "scsa2usb",	DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_UGEN, "scsa2usb",	DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_NEXUS, "uhci",	DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_UGEN, "ugen",	DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_NEXUS, "usb_mid", DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_UGEN, "usb_mid", DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_PRINTER, "usbprn", DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_UGEN, "usbprn", DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
	{ "usb", DDI_NT_NEXUS, "hwahc", DRV_EXACT|TYPE_EXACT,
						ILEVEL_0, usb_process },
};

/* For debug printing (-V filter) */
static char *debug_mid = "usb_mid";

DEVFSADM_CREATE_INIT_V0(usb_cbt);

/* USB device links */
#define	USB_LINK_RE_AUDIO	"^usb/audio[0-9]+$"
#define	USB_LINK_RE_AUDIOMUX	"^usb/audio-mux[0-9]+$"
#define	USB_LINK_RE_AUDIOCTL	"^usb/audio-control[0-9]+$"
#define	USB_LINK_RE_AUDIOSTREAM	"^usb/audio-stream[0-9]+$"
#define	USB_LINK_RE_DDIVS_USBC	"^usb/ddivs_usbc[0-9]+$"
#define	USB_LINK_RE_VIDEO	"^usb/video[0-9]+$"
#define	USB_LINK_RE_VIDEO2	"^video[0-9]+$"
#define	USB_LINK_RE_DEVICE	"^usb/device[0-9]+$"
#define	USB_LINK_RE_HID		"^usb/hid[0-9]+$"
#define	USB_LINK_RE_HUB		"^usb/hub[0-9]+$"
#define	USB_LINK_RE_MASS_STORE	"^usb/mass-storage[0-9]+$"
#define	USB_LINK_RE_UGEN	"^usb/[0-9,a-f]+\\.[0-9,a-f]+/[0-9]+/.+$"
#define	USB_LINK_RE_USBPRN	"^usb/printer[0-9]+$"
#define	USB_LINK_RE_WHOST	"^usb/whost[0-9]+$"
#define	USB_LINK_RE_HWARC	"^usb/hwarc[0-9]+$"
#define	USB_LINK_RE_WUSB_CA	"^usb/wusb_ca[0-9]+$"

/* Rules for removing links */
static devfsadm_remove_t usb_remove_cbt[] = {
	{ "usb", USB_LINK_RE_AUDIO, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_AUDIOMUX, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_AUDIOCTL, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_AUDIOSTREAM, RM_POST | RM_HOT | RM_ALWAYS,
			ILEVEL_0, devfsadm_rm_all },
	{ "usb", USB_LINK_RE_DDIVS_USBC, RM_POST | RM_HOT | RM_ALWAYS,
			ILEVEL_0, devfsadm_rm_all },
	{ "usb", USB_LINK_RE_VIDEO2, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_VIDEO, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_DEVICE, RM_POST | RM_HOT, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_HID, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_HUB, RM_POST | RM_HOT, ILEVEL_0, devfsadm_rm_all },
	{ "usb", USB_LINK_RE_MASS_STORE, RM_POST | RM_HOT | RM_ALWAYS,
			ILEVEL_0, devfsadm_rm_all },
	{ "usb", USB_LINK_RE_UGEN, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_USBPRN, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_link },
	{ "usb", USB_LINK_RE_WHOST, RM_POST | RM_HOT, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_HWARC, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_all },
	{ "usb", USB_LINK_RE_WUSB_CA, RM_POST | RM_HOT | RM_ALWAYS, ILEVEL_0,
			devfsadm_rm_all }
};

/*
 * Rules for different USB devices except ugen which is dynamically
 * created
 */
static devfsadm_enumerate_t audio_rules[1] =
	{"^usb$/^audio([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t audio_mux_rules[1] =
	{"^usb$/^audio-mux([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t audio_control_rules[1] =
	{"^usb$/^audio-control([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t audio_stream_rules[1] =
	{"^usb$/^audio-stream([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t ddivs_usbc_rules[1] =
	{"^usb$/^ddivs_usbc([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t video_rules[1] =
	{"^usb$/^video([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t device_rules[1] =
	{"^usb$/^device([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t hid_rules[1] =
	{"^usb$/^hid([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t hub_rules[1] =
	{"^usb$/^hub([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t mass_storage_rules[1] =
	{"^usb$/^mass-storage([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t usbprn_rules[1] =
	{"^usb$/^printer([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t whost_rules[1] =
	{"^usb$/^whost([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t hwarc_rules[1] =
	{"^usb$/^hwarc([0-9]+)$", 1, MATCH_ALL};
static devfsadm_enumerate_t wusb_ca_rules[1] =
	{"^usb$/^wusb_ca([0-9]+)$", 1, MATCH_ALL};

DEVFSADM_REMOVE_INIT_V0(usb_remove_cbt);

int
minor_init(void)
{
	devfsadm_print(debug_mid, "usb_link: minor_init\n");
	return (DEVFSADM_SUCCESS);
}

int
minor_fini(void)
{
	devfsadm_print(debug_mid, "usb_link: minor_fini\n");
	return (DEVFSADM_SUCCESS);
}

typedef enum {
	DRIVER_HUBD,
	DRIVER_OHCI,
	DRIVER_EHCI,
	DRIVER_UHCI,
	DRIVER_XHCI,
	DRIVER_USB_AC,
	DRIVER_USB_AS,
	DRIVER_HID,
	DRIVER_USB_MID,
	DRIVER_DDIVS_USBC,
	DRIVER_SCSA2USB,
	DRIVER_USBPRN,
	DRIVER_UGEN,
	DRIVER_VIDEO,
	DRIVER_HWAHC,
	DRIVER_HWARC,
	DRIVER_WUSB_CA,
	DRIVER_UNKNOWN
} driver_defs_t;

typedef struct {
	char	*driver_name;
	driver_defs_t	index;
} driver_name_table_entry_t;

driver_name_table_entry_t driver_name_table[] = {
	{ "hubd",	DRIVER_HUBD },
	{ "ohci",	DRIVER_OHCI },
	{ "ehci",	DRIVER_EHCI },
	{ "uhci",	DRIVER_UHCI },
	{ "xhci",	DRIVER_XHCI },
	{ "usb_ac",	DRIVER_USB_AC },
	{ "usb_as",	DRIVER_USB_AS },
	{ "hid",	DRIVER_HID },
	{ "usb_mid",	DRIVER_USB_MID },
	{ "ddivs_usbc",	DRIVER_DDIVS_USBC },
	{ "scsa2usb",	DRIVER_SCSA2USB },
	{ "usbprn",	DRIVER_USBPRN },
	{ "ugen",	DRIVER_UGEN },
	{ "usbvc",	DRIVER_VIDEO },
	{ "hwahc",	DRIVER_HWAHC },
	{ "hwarc",	DRIVER_HWARC },
	{ "wusb_ca",	DRIVER_WUSB_CA },
	{ NULL,		DRIVER_UNKNOWN }
};

/*
 * This function is called for every usb minor node.
 * Calls enumerate to assign a logical usb id, and then
 * devfsadm_mklink to make the link.
 */
static int
usb_process(di_minor_t minor, di_node_t node)
{
	devfsadm_enumerate_t rules[1];
	char *l_path, *p_path, *buf, *devfspath;
	char *minor_nm, *drvr_nm, *name = (char *)NULL;
	int i;
	driver_defs_t index;
	int flags = 0;
	int create_secondary_link = 0;

	minor_nm = di_minor_name(minor);
	drvr_nm = di_driver_name(node);
	if ((minor_nm == NULL) || (drvr_nm == NULL)) {
		return (DEVFSADM_CONTINUE);
	}

	devfsadm_print(debug_mid, "usb_process: minor=%s node=%s type=%s\n",
	    minor_nm, di_node_name(node), di_minor_nodetype(minor));

	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		devfsadm_print(debug_mid,
		    "USB_process: devfspath is	NULL\n");
		return (DEVFSADM_CONTINUE);
	}

	l_path = (char *)malloc(PATH_MAX);
	if (l_path == NULL) {
		di_devfs_path_free(devfspath);
		devfsadm_print(debug_mid, "usb_process: malloc() failed\n");
		return (DEVFSADM_CONTINUE);
	}

	p_path = (char *)malloc(PATH_MAX);
	if (p_path == NULL) {
		devfsadm_print(debug_mid, "usb_process: malloc() failed\n");
		di_devfs_path_free(devfspath);
		free(l_path);
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(p_path, devfspath);
	(void) strcat(p_path, ":");
	(void) strcat(p_path, minor_nm);
	di_devfs_path_free(devfspath);

	devfsadm_print(debug_mid, "usb_process: path %s\n", p_path);

	for (i = 0; ; i++) {
		if ((driver_name_table[i].driver_name == NULL) ||
		    (strcmp(drvr_nm, driver_name_table[i].driver_name) == 0)) {
			index = driver_name_table[i].index;
			break;
		}
	}

	if (strcmp(di_minor_nodetype(minor), DDI_NT_UGEN) == 0) {
		ugen_create_link(p_path, minor_nm, node, minor);
		free(l_path);
		free(p_path);
		return (DEVFSADM_CONTINUE);
	}

	/* Figure out which rules to apply */
	switch (index) {
	case DRIVER_HUBD:
	case DRIVER_OHCI:
	case DRIVER_EHCI:
	case DRIVER_UHCI:
	case DRIVER_XHCI:
		rules[0] = hub_rules[0];	/* For HUBs */
		name = "hub";

		break;
	case DRIVER_USB_AC:
		if (strcmp(minor_nm, "sound,audio") == 0) {
			rules[0] = audio_rules[0];
			name = "audio";		/* For audio */
			create_secondary_link = 1;
		} else if (strcmp(minor_nm, "sound,audioctl") == 0) {
			rules[0] = audio_control_rules[0];
			name = "audio-control";		/* For audio */
			create_secondary_link = 1;
		} else if (strcmp(minor_nm, "mux") == 0) {
			rules[0] = audio_mux_rules[0];
			name = "audio-mux";		/* For audio */
		} else {
			free(l_path);
			free(p_path);
			return (DEVFSADM_CONTINUE);
		}
		break;
	case DRIVER_USB_AS:
		rules[0] = audio_stream_rules[0];
		name = "audio-stream";		/* For audio */
		break;
	case DRIVER_VIDEO:
		rules[0] = video_rules[0];
		name = "video";			/* For video */
		create_secondary_link = 1;
		break;
	case DRIVER_HID:
		rules[0] = hid_rules[0];
		name = "hid";			/* For HIDs */
		break;
	case DRIVER_USB_MID:
		rules[0] = device_rules[0];
		name = "device";		/* For other USB devices */
		break;
	case DRIVER_DDIVS_USBC:
		rules[0] = ddivs_usbc_rules[0];
		name = "device";		/* For other USB devices */
		break;
	case DRIVER_SCSA2USB:
		rules[0] = mass_storage_rules[0];
		name = "mass-storage";		/* For mass-storage devices */
		break;
	case DRIVER_USBPRN:
		rules[0] = usbprn_rules[0];
		name = "printer";
		break;
	case DRIVER_HWAHC:
		if (strcmp(minor_nm, "hwahc") == 0) {
			rules[0] = whost_rules[0];
			name = "whost";		/* For HWA HC */
		} else if (strcmp(minor_nm, "hubd") == 0) {
			rules[0] = hub_rules[0];
			name = "hub";		/* For HWA HC */
		} else {
			free(l_path);
			free(p_path);
			return (DEVFSADM_CONTINUE);
		}
		break;
	case DRIVER_HWARC:
		rules[0] = hwarc_rules[0];
		name = "hwarc";		/* For UWB HWA Radio Controllers */
		break;
	case DRIVER_WUSB_CA:
		rules[0] = wusb_ca_rules[0];
		name = "wusb_ca";	/* for wusb cable association */
		break;
	default:
		devfsadm_print(debug_mid, "usb_process: unknown driver=%s\n",
		    drvr_nm);
		free(l_path);
		free(p_path);
		return (DEVFSADM_CONTINUE);
	}

	/*
	 *  build the physical path from the components.
	 *  find the logical usb id, and stuff it in buf
	 */
	if (devfsadm_enumerate_int(p_path, 0, &buf, rules, 1)) {
		devfsadm_print(debug_mid, "usb_process: exit/continue\n");
		free(l_path);
		free(p_path);
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(l_path, PATH_MAX, "usb/%s%s", name, buf);

	devfsadm_print(debug_mid, "usb_process: p_path=%s buf=%s\n",
	    p_path, buf);

	free(buf);

	devfsadm_print(debug_mid, "mklink %s -> %s\n", l_path, p_path);

	(void) devfsadm_mklink(l_path, node, minor, flags);

	if (create_secondary_link) {
		/*
		 * Create secondary links to make newly hotplugged
		 * usb audio device the primary device.
		 */
		if (strcmp(name, "audio") == 0) {
			(void) devfsadm_secondary_link("audio", l_path, 0);
		} else if (strcmp(name, "audio-control") == 0) {
			(void) devfsadm_secondary_link("audioctl", l_path, 0);
		} else if (strcmp(name, "video") == 0) {
			(void) devfsadm_secondary_link(l_path + 4, l_path, 0);
		}
	}

	free(p_path);
	free(l_path);

	return (DEVFSADM_CONTINUE);
}

static void
ugen_create_link(char *p_path, char *node_name,
    di_node_t node, di_minor_t minor)
{
	char *buf, s[MAXPATHLEN];
	char *lasts = s;
	char *vid, *pid;
	char *minor_name;
	char ugen_RE[128];
	devfsadm_enumerate_t ugen_rules[1];
	char l_path[PATH_MAX];
	int flags = 0;

	devfsadm_print(debug_mid, "ugen_create_link: p_path=%s name=%s\n",
	    p_path, node_name);

	(void) strlcpy(s, node_name, sizeof (s));

	/* get vid, pid and minor name strings */
	vid = strtok_r(lasts, ".", &lasts);
	pid = strtok_r(NULL, ".", &lasts);
	minor_name = lasts;

	if ((vid == NULL) || (pid == NULL) || (minor_name == NULL)) {
		return;
	}

	/* create regular expression contain vid and pid */
	(void) snprintf(ugen_RE, sizeof (ugen_RE),
	    "^usb$/^%s\\.%s$/^([0-9]+)$", vid, pid);
	devfsadm_print(debug_mid,
	    "ugen_create_link: ugen_RE=%s minor_name=%s\n",
	    ugen_RE, minor_name);

	bzero(ugen_rules, sizeof (ugen_rules));

	ugen_rules[0].re = ugen_RE;
	ugen_rules[0].subexp = 1;
	ugen_rules[0].flags = MATCH_ADDR;

	/*
	 *  build the physical path from the components.
	 *  find the logical usb id, and stuff it in buf
	 */
	if (devfsadm_enumerate_int(p_path, 0, &buf, ugen_rules, 1)) {
		devfsadm_print(debug_mid, "ugen_create_link: exit/continue\n");
		return;
	}

	(void) snprintf(l_path, sizeof (l_path), "usb/%s.%s/%s/%s",
	    vid, pid, buf, minor_name);

	devfsadm_print(debug_mid, "mklink %s -> %s\n", l_path, p_path);

	(void) devfsadm_mklink(l_path, node, minor, flags);

	free(buf);
}
