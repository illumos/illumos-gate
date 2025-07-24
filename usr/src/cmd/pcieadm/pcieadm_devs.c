/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include <ofmt.h>
#include <strings.h>
#include <sys/pci.h>

#include "pcieadm.h"

typedef struct pcieadm_show_devs {
	pcieadm_t *psd_pia;
	ofmt_handle_t psd_ofmt;
	boolean_t psd_funcs;
	int psd_nfilts;
	char **psd_filts;
	boolean_t *psd_used;
	uint_t psd_nprint;
} pcieadm_show_devs_t;

typedef enum pcieadm_show_devs_otype {
	PCIEADM_SDO_VID,
	PCIEADM_SDO_DID,
	PCIEADM_SDO_REV,
	PCIEADM_SDO_SUBVID,
	PCIEADM_SDO_SUBSYS,
	PCIEADM_SDO_BDF,
	PCIEADM_SDO_BDF_BUS,
	PCIEADM_SDO_BDF_DEV,
	PCIEADM_SDO_BDF_FUNC,
	PCIEADM_SDO_DRIVER,
	PCIEADM_SDO_INSTANCE,
	PCIEADM_SDO_INSTNUM,
	PCIEADM_SDO_TYPE,
	PCIEADM_SDO_VENDOR,
	PCIEADM_SDO_DEVICE,
	PCIEADM_SDO_SUBVENDOR,
	PCIEADM_SDO_SUBSYSTEM,
	PCIEADM_SDO_PATH,
	PCIEADM_SDO_MAXSPEED,
	PCIEADM_SDO_MAXWIDTH,
	PCIEADM_SDO_CURSPEED,
	PCIEADM_SDO_CURWIDTH,
	PCIEADM_SDO_SUPSPEEDS
} pcieadm_show_devs_otype_t;

typedef struct pcieadm_show_devs_ofmt {
	int psdo_vid;
	int psdo_did;
	int psdo_rev;
	int psdo_subvid;
	int psdo_subsys;
	uint_t psdo_bus;
	uint_t psdo_dev;
	uint_t psdo_func;
	const char *psdo_path;
	const char *psdo_vendor;
	const char *psdo_device;
	const char *psdo_subvendor;
	const char *psdo_subsystem;
	const char *psdo_driver;
	int psdo_instance;
	int psdo_mwidth;
	int psdo_cwidth;
	int64_t psdo_mspeed;
	int64_t psdo_cspeed;
	int psdo_nspeeds;
	int64_t *psdo_sspeeds;
} pcieadm_show_devs_ofmt_t;

static uint_t
pcieadm_speed2gen(int64_t speed)
{
	if (speed == 2500000000LL) {
		return (1);
	} else if (speed == 5000000000LL) {
		return (2);
	} else if (speed == 8000000000LL) {
		return (3);
	} else if (speed == 16000000000LL) {
		return (4);
	} else if (speed == 32000000000LL) {
		return (5);
	} else {
		return (0);
	}
}

static const char *
pcieadm_speed2str(int64_t speed)
{
	if (speed == 2500000000LL) {
		return ("2.5");
	} else if (speed == 5000000000LL) {
		return ("5.0");
	} else if (speed == 8000000000LL) {
		return ("8.0");
	} else if (speed == 16000000000LL) {
		return ("16.0");
	} else if (speed == 32000000000LL) {
		return ("32.0");
	} else {
		return (NULL);
	}
}

static boolean_t
pcieadm_show_devs_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	const char *str;
	pcieadm_show_devs_ofmt_t *psdo = ofarg->ofmt_cbarg;
	boolean_t first = B_TRUE;

	switch (ofarg->ofmt_id) {
	case PCIEADM_SDO_BDF:
		if (snprintf(buf, buflen, "%x/%x/%x", psdo->psdo_bus,
		    psdo->psdo_dev, psdo->psdo_func) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_BDF_BUS:
		if (snprintf(buf, buflen, "%x", psdo->psdo_bus) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_BDF_DEV:
		if (snprintf(buf, buflen, "%x", psdo->psdo_dev) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_BDF_FUNC:
		if (snprintf(buf, buflen, "%x", psdo->psdo_func) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_INSTANCE:
		if (psdo->psdo_driver == NULL || psdo->psdo_instance == -1) {
			(void) snprintf(buf, buflen, "--");
		} else if (snprintf(buf, buflen, "%s%d", psdo->psdo_driver,
		    psdo->psdo_instance) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_DRIVER:
		if (psdo->psdo_driver == NULL) {
			(void) snprintf(buf, buflen, "--");
		} else if (strlcpy(buf, psdo->psdo_driver, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_INSTNUM:
		if (psdo->psdo_instance == -1) {
			(void) snprintf(buf, buflen, "--");
		} else if (snprintf(buf, buflen, "%d", psdo->psdo_instance) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_PATH:
		if (strlcat(buf, psdo->psdo_path, buflen) >= buflen) {
			return (B_TRUE);
		}
		break;
	case PCIEADM_SDO_VID:
		if (psdo->psdo_vid == -1) {
			(void) strlcat(buf, "--", buflen);
		} else if (snprintf(buf, buflen, "%x", psdo->psdo_vid) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_DID:
		if (psdo->psdo_did == -1) {
			(void) strlcat(buf, "--", buflen);
		} else if (snprintf(buf, buflen, "%x", psdo->psdo_did) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_REV:
		if (psdo->psdo_rev == -1) {
			(void) strlcat(buf, "--", buflen);
		} else if (snprintf(buf, buflen, "%x", psdo->psdo_rev) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_SUBVID:
		if (psdo->psdo_subvid == -1) {
			(void) strlcat(buf, "--", buflen);
		} else if (snprintf(buf, buflen, "%x", psdo->psdo_subvid) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_SUBSYS:
		if (psdo->psdo_subsys == -1) {
			(void) strlcat(buf, "--", buflen);
		} else if (snprintf(buf, buflen, "%x", psdo->psdo_subsys) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_VENDOR:
		if (strlcat(buf, psdo->psdo_vendor, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_DEVICE:
		if (strlcat(buf, psdo->psdo_device, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_SUBVENDOR:
		if (strlcat(buf, psdo->psdo_subvendor, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_SUBSYSTEM:
		if (strlcat(buf, psdo->psdo_subsystem, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_MAXWIDTH:
		if (psdo->psdo_mwidth <= 0) {
			(void) strlcat(buf, "--", buflen);
		} else if (snprintf(buf, buflen, "x%d", psdo->psdo_mwidth) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_CURWIDTH:
		if (psdo->psdo_cwidth <= 0) {
			(void) strlcat(buf, "--", buflen);
		} else if (snprintf(buf, buflen, "x%d", psdo->psdo_cwidth) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_MAXSPEED:
		str = pcieadm_speed2str(psdo->psdo_mspeed);
		if (str == NULL) {
			(void) strlcat(buf, "--", buflen);
		} else if (snprintf(buf, buflen, "%s GT/s", str) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_CURSPEED:
		str = pcieadm_speed2str(psdo->psdo_cspeed);
		if (str == NULL) {
			(void) strlcat(buf, "--", buflen);
		} else if (snprintf(buf, buflen, "%s GT/s", str) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_SDO_SUPSPEEDS:
		buf[0] = 0;
		for (int i = 0; i < psdo->psdo_nspeeds; i++) {
			const char *str;

			str = pcieadm_speed2str(psdo->psdo_sspeeds[i]);
			if (str == NULL) {
				continue;
			}

			if (!first) {
				if (strlcat(buf, ",", buflen) >= buflen) {
					return (B_FALSE);
				}
			}
			first = B_FALSE;

			if (strlcat(buf, str, buflen) >= buflen) {
				return (B_FALSE);
			}
		}
		break;
	case PCIEADM_SDO_TYPE:
		/*
		 * We need to distinguish three different groups of things here:
		 *
		 *  - Something is a PCI device.
		 *  - We have a PCIe device where the link is down and therefore
		 *    have no current width or speed.
		 *  - We have a PCIe device which is up.
		 *
		 * A PCIe device should always have a maximum width value. This
		 * is required and therefore should be a good proxy for whether
		 * or not we have a PCIe device.
		 */
		if (psdo->psdo_mwidth == -1) {
			if (strlcat(buf, "PCI", buflen) >= buflen) {
				return (B_FALSE);
			}
			break;
		}

		/*
		 * If we don't have a valid link up, indicate we don't know.
		 * While the link is probably down, we don't have that as a
		 * guarantee right now.
		 */
		if (psdo->psdo_cspeed == -1 || psdo->psdo_cwidth == -1) {
			if (strlcat(buf, "PCIe unknown", buflen) >= buflen) {
				return (B_FALSE);
			}
			break;
		}

		if (snprintf(buf, buflen, "PCIe Gen %ux%d",
		    pcieadm_speed2gen(psdo->psdo_cspeed),
		    psdo->psdo_cwidth) >= buflen) {
			return (B_FALSE);
		}
		break;
	default:
		abort();
	}
	return (B_TRUE);
}

static const char *pcieadm_show_dev_fields = "bdf,type,instance,device";
static const char *pcieadm_show_dev_speeds =
	"bdf,driver,maxspeed,curspeed,maxwidth,curwidth,supspeeds";
static const ofmt_field_t pcieadm_show_dev_ofmt[] = {
	{ "VID", 6, PCIEADM_SDO_VID, pcieadm_show_devs_ofmt_cb },
	{ "DID", 6, PCIEADM_SDO_DID, pcieadm_show_devs_ofmt_cb },
	{ "REV", 6, PCIEADM_SDO_REV, pcieadm_show_devs_ofmt_cb },
	{ "SUBVID", 6, PCIEADM_SDO_SUBVID, pcieadm_show_devs_ofmt_cb },
	{ "SUBSYS", 6, PCIEADM_SDO_SUBSYS, pcieadm_show_devs_ofmt_cb },
	{ "BDF", 8, PCIEADM_SDO_BDF, pcieadm_show_devs_ofmt_cb },
	{ "DRIVER", 15, PCIEADM_SDO_DRIVER, pcieadm_show_devs_ofmt_cb },
	{ "INSTANCE", 15, PCIEADM_SDO_INSTANCE, pcieadm_show_devs_ofmt_cb },
	{ "INSTNUM", 8, PCIEADM_SDO_INSTNUM, pcieadm_show_devs_ofmt_cb },
	{ "TYPE", 15, PCIEADM_SDO_TYPE, pcieadm_show_devs_ofmt_cb },
	{ "VENDOR", 30, PCIEADM_SDO_VENDOR, pcieadm_show_devs_ofmt_cb },
	{ "DEVICE", 30, PCIEADM_SDO_DEVICE, pcieadm_show_devs_ofmt_cb },
	{ "SUBVENDOR", 30, PCIEADM_SDO_SUBVENDOR, pcieadm_show_devs_ofmt_cb },
	{ "SUBSYSTEM", 30, PCIEADM_SDO_SUBSYSTEM, pcieadm_show_devs_ofmt_cb },
	{ "PATH", 30, PCIEADM_SDO_PATH, pcieadm_show_devs_ofmt_cb },
	{ "BUS", 4, PCIEADM_SDO_BDF_BUS, pcieadm_show_devs_ofmt_cb },
	{ "DEV", 4, PCIEADM_SDO_BDF_DEV, pcieadm_show_devs_ofmt_cb },
	{ "FUNC", 4, PCIEADM_SDO_BDF_FUNC, pcieadm_show_devs_ofmt_cb },
	{ "MAXSPEED", 10, PCIEADM_SDO_MAXSPEED, pcieadm_show_devs_ofmt_cb },
	{ "MAXWIDTH", 10, PCIEADM_SDO_MAXWIDTH, pcieadm_show_devs_ofmt_cb },
	{ "CURSPEED", 10, PCIEADM_SDO_CURSPEED, pcieadm_show_devs_ofmt_cb },
	{ "CURWIDTH", 10, PCIEADM_SDO_CURWIDTH, pcieadm_show_devs_ofmt_cb },
	{ "SUPSPEEDS", 20, PCIEADM_SDO_SUPSPEEDS, pcieadm_show_devs_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

static boolean_t
pcieadm_show_devs_match(pcieadm_show_devs_t *psd,
    pcieadm_show_devs_ofmt_t *psdo)
{
	char dinst[128], bdf[128];

	if (psd->psd_nfilts == 0) {
		return (B_TRUE);
	}

	if (psdo->psdo_driver != NULL && psdo->psdo_instance != -1) {
		(void) snprintf(dinst, sizeof (dinst), "%s%d",
		    psdo->psdo_driver, psdo->psdo_instance);
	}
	(void) snprintf(bdf, sizeof (bdf), "%x/%x/%x", psdo->psdo_bus,
	    psdo->psdo_dev, psdo->psdo_func);

	for (uint_t i = 0; i < psd->psd_nfilts; i++) {
		const char *filt = psd->psd_filts[i];

		if (strcmp(filt, psdo->psdo_path) == 0) {
			psd->psd_used[i] = B_TRUE;
			return (B_TRUE);
		}

		if (strcmp(filt, bdf) == 0) {
			psd->psd_used[i] = B_TRUE;
			return (B_TRUE);
		}

		if (psdo->psdo_driver != NULL &&
		    strcmp(filt, psdo->psdo_driver) == 0) {
			psd->psd_used[i] = B_TRUE;
			return (B_TRUE);
		}

		if (psdo->psdo_driver != NULL && psdo->psdo_instance != -1 &&
		    strcmp(filt, dinst) == 0) {
			psd->psd_used[i] = B_TRUE;
			return (B_TRUE);
		}

		if (strncmp("/devices", filt, strlen("/devices")) == 0) {
			filt += strlen("/devices");
		}

		if (strcmp(filt, psdo->psdo_path) == 0) {
			psd->psd_used[i] = B_TRUE;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static int
pcieadm_show_devs_walk_cb(di_node_t node, void *arg)
{
	int nprop, *regs = NULL, *did, *vid, *mwidth, *cwidth, *rev;
	int *subvid, *subsys;
	int64_t *mspeed, *cspeed, *sspeeds;
	char *path = NULL;
	pcieadm_show_devs_t *psd = arg;
	int ret = DI_WALK_CONTINUE;
	char venstr[64], devstr[64], subvenstr[64], subsysstr[64];
	pcieadm_show_devs_ofmt_t oarg;
	pcidb_hdl_t *pcidb = psd->psd_pia->pia_pcidb;

	bzero(&oarg, sizeof (oarg));

	path = di_devfs_path(node);
	if (path == NULL) {
		err(EXIT_FAILURE, "failed to construct devfs path for node: "
		    "%s", di_node_name(node));
	}

	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "reg", &regs);
	if (nprop <= 0) {
		errx(EXIT_FAILURE, "failed to lookup regs array for %s",
		    path);
	}

	oarg.psdo_path = path;
	oarg.psdo_bus = PCI_REG_BUS_G(regs[0]);
	oarg.psdo_dev = PCI_REG_DEV_G(regs[0]);
	oarg.psdo_func = PCI_REG_FUNC_G(regs[0]);

	if (oarg.psdo_func != 0 && !psd->psd_funcs) {
		goto done;
	}

	oarg.psdo_driver = di_driver_name(node);
	oarg.psdo_instance = di_instance(node);

	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "device-id", &did);
	if (nprop != 1) {
		oarg.psdo_did = -1;
	} else {
		oarg.psdo_did = (uint16_t)*did;
	}

	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "vendor-id", &vid);
	if (nprop != 1) {
		oarg.psdo_vid = -1;
	} else {
		oarg.psdo_vid = (uint16_t)*vid;
	}

	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "revision-id", &rev);
	if (nprop != 1) {
		oarg.psdo_rev = -1;
	} else {
		oarg.psdo_rev = (uint16_t)*rev;
	}

	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "subsystem-vendor-id",
	    &subvid);
	if (nprop != 1) {
		oarg.psdo_subvid = -1;
	} else {
		oarg.psdo_subvid = (uint16_t)*subvid;
	}

	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "subsystem-id",
	    &subsys);
	if (nprop != 1) {
		oarg.psdo_subsys = -1;
	} else {
		oarg.psdo_subsys = (uint16_t)*subsys;
	}

	oarg.psdo_vendor = "--";
	if (oarg.psdo_vid != -1) {
		pcidb_vendor_t *vend = pcidb_lookup_vendor(pcidb,
		    oarg.psdo_vid);
		if (vend != NULL) {
			oarg.psdo_vendor = pcidb_vendor_name(vend);
		} else {
			(void) snprintf(venstr, sizeof (venstr),
			    "Unknown vendor: 0x%x", oarg.psdo_vid);
			oarg.psdo_vendor = venstr;
		}
	}

	oarg.psdo_device = "--";
	if (oarg.psdo_vid != -1 && oarg.psdo_did != -1) {
		pcidb_device_t *dev = pcidb_lookup_device(pcidb,
		    oarg.psdo_vid, oarg.psdo_did);
		if (dev != NULL) {
			oarg.psdo_device = pcidb_device_name(dev);
		} else {
			(void) snprintf(devstr, sizeof (devstr),
			    "Unknown device: 0x%x", oarg.psdo_did);
			oarg.psdo_device = devstr;
		}
	}

	/*
	 * The pci.ids database organizes subsystems under devices. We look at
	 * the subsystem vendor separately because even if the device or other
	 * information is not known, we may still be able to figure out what it
	 * is.
	 */
	oarg.psdo_subvendor = "--";
	oarg.psdo_subsystem = "--";
	if (oarg.psdo_subvid != -1) {
		pcidb_vendor_t *vend = pcidb_lookup_vendor(pcidb,
		    oarg.psdo_subvid);
		if (vend != NULL) {
			oarg.psdo_subvendor = pcidb_vendor_name(vend);
		} else {
			(void) snprintf(subvenstr, sizeof (subvenstr),
			    "Unknown vendor: 0x%x", oarg.psdo_vid);
			oarg.psdo_subvendor = subvenstr;
		}
	}

	if (oarg.psdo_vid != -1 && oarg.psdo_did != -1 &&
	    oarg.psdo_subvid != -1 && oarg.psdo_subsys != -1) {
		pcidb_subvd_t *subvd = pcidb_lookup_subvd(pcidb, oarg.psdo_vid,
		    oarg.psdo_did, oarg.psdo_subvid, oarg.psdo_subsys);
		if (subvd != NULL) {
			oarg.psdo_subsystem = pcidb_subvd_name(subvd);
		} else {
			(void) snprintf(subsysstr, sizeof (subsysstr),
			    "Unknown subsystem: 0x%x", oarg.psdo_subsys);
			oarg.psdo_subsystem = subsysstr;
		}
	}


	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    "pcie-link-maximum-width", &mwidth);
	if (nprop != 1) {
		oarg.psdo_mwidth = -1;
	} else {
		oarg.psdo_mwidth = *mwidth;
	}

	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    "pcie-link-current-width", &cwidth);
	if (nprop != 1) {
		oarg.psdo_cwidth = -1;
	} else {
		oarg.psdo_cwidth = *cwidth;
	}

	nprop = di_prop_lookup_int64(DDI_DEV_T_ANY, node,
	    "pcie-link-maximum-speed", &mspeed);
	if (nprop != 1) {
		oarg.psdo_mspeed = -1;
	} else {
		oarg.psdo_mspeed = *mspeed;
	}

	nprop = di_prop_lookup_int64(DDI_DEV_T_ANY, node,
	    "pcie-link-current-speed", &cspeed);
	if (nprop != 1) {
		oarg.psdo_cspeed = -1;
	} else {
		oarg.psdo_cspeed = *cspeed;
	}

	nprop = di_prop_lookup_int64(DDI_DEV_T_ANY, node,
	    "pcie-link-supported-speeds", &sspeeds);
	if (nprop > 0) {
		oarg.psdo_nspeeds = nprop;
		oarg.psdo_sspeeds = sspeeds;
	} else {
		oarg.psdo_nspeeds = 0;
		oarg.psdo_sspeeds = NULL;
	}

	if (pcieadm_show_devs_match(psd, &oarg)) {
		ofmt_print(psd->psd_ofmt, &oarg);
		psd->psd_nprint++;
	}

done:
	if (path != NULL) {
		di_devfs_path_free(path);
	}

	return (ret);
}

void
pcieadm_show_devs_usage(FILE *f)
{
	(void) fprintf(f, "\tshow-devs\t[-F] [-H] [-s | -o field[,...] [-p]] "
	    "[filter...]\n");
}

static void
pcieadm_show_devs_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "Usage:  %s show-devs [-F] [-H] [-s | -o "
	    "field[,...] [-p]] [filter...]\n", pcieadm_progname);

	(void) fprintf(stderr, "\nList PCI devices and functions in the "
	    "system. Each <filter> selects a set\nof devices to show and "
	    "can be a driver name, instance, /devices path, or\nb/d/f.\n\n"
	    "\t-F\t\tdo not display PCI functions\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparsable output (requires -o)\n"
	    "\t-s\t\tlist speeds and widths\n\n"
	    "The following fields are supported:\n"
	    "\tvid\t\tthe PCI vendor ID in hex\n"
	    "\tdid\t\tthe PCI device ID in hex\n"
	    "\trev\t\tthe PCI device revision in hex\n"
	    "\tsubvid\t\tthe PCI subsystem vendor ID in hex\n"
	    "\tsubsys\t\tthe PCI subsystem ID in hex\n"
	    "\tvendor\t\tthe name of the PCI vendor\n"
	    "\tdevice\t\tthe name of the PCI device\n"
	    "\tsubvendor\t\tthe name of the PCI subsystem vendor\n"
	    "\tsubsystem\t\tthe name of the PCI subsystem\n"
	    "\tinstance\tthe name of this particular instance, e.g. igb0\n"
	    "\tdriver\t\tthe name of the driver attached to the device\n"
	    "\tinstnum\t\tthe instance number of a device, e.g. 2 for nvme2\n"
	    "\tpath\t\tthe /devices path of the device\n"
	    "\tbdf\t\tthe PCI bus/device/function, with values in hex\n"
	    "\tbus\t\tthe PCI bus number of the device in hex\n"
	    "\tdev\t\tthe PCI device number of the device in hex\n"
	    "\tfunc\t\tthe PCI function number of the device in hex\n"
	    "\ttype\t\ta string describing the PCIe generation and width\n"
	    "\tmaxspeed\tthe maximum supported PCIe speed of the device\n"
	    "\tcurspeed\tthe current PCIe speed of the device\n"
	    "\tmaxwidth\tthe maximum supported PCIe lane count of the device\n"
	    "\tcurwidth\tthe current lane count of the PCIe device\n"
	    "\tsupspeeds\tthe list of speeds the device supports\n");
}

int
pcieadm_show_devs(pcieadm_t *pcip, int argc, char *argv[])
{
	int c, ret;
	uint_t flags = 0;
	const char *fields = NULL;
	pcieadm_show_devs_t psd;
	pcieadm_di_walk_t walk;
	ofmt_status_t oferr;
	boolean_t parse = B_FALSE;
	boolean_t speeds = B_FALSE;

	/*
	 * show-devs relies solely on the devinfo snapshot we already took.
	 * Formalize our privs immediately.
	 */
	pcieadm_init_privs(pcip);

	bzero(&psd, sizeof (psd));
	psd.psd_pia = pcip;
	psd.psd_funcs = B_TRUE;

	while ((c = getopt(argc, argv, ":FHo:ps")) != -1) {
		switch (c) {
		case 'F':
			psd.psd_funcs = B_FALSE;
			break;
		case 'p':
			parse = B_TRUE;
			flags |= OFMT_PARSABLE;
			break;
		case 'H':
			flags |= OFMT_NOHEADER;
			break;
		case 's':
			speeds = B_TRUE;
			break;
		case 'o':
			fields = optarg;
			break;
		case ':':
			pcieadm_show_devs_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			pcieadm_show_devs_help("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	if (parse && fields == NULL) {
		errx(EXIT_USAGE, "-p requires fields specified with -o");
	}

	if (fields != NULL && speeds) {
		errx(EXIT_USAGE, "-s cannot be used with with -o");
	}

	if (fields == NULL) {
		if (speeds) {
			fields = pcieadm_show_dev_speeds;
		} else {
			fields = pcieadm_show_dev_fields;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0) {
		psd.psd_nfilts = argc;
		psd.psd_filts = argv;
		psd.psd_used = calloc(argc, sizeof (boolean_t));
		if (psd.psd_used == NULL) {
			err(EXIT_FAILURE, "failed to allocate filter tracking "
			    "memory");
		}
	}

	oferr = ofmt_open(fields, pcieadm_show_dev_ofmt, flags, 0,
	    &psd.psd_ofmt);
	ofmt_check(oferr, parse, psd.psd_ofmt, pcieadm_ofmt_errx, warnx);

	walk.pdw_arg = &psd;
	walk.pdw_func = pcieadm_show_devs_walk_cb;

	pcieadm_di_walk(pcip, &walk);

	ret = EXIT_SUCCESS;
	for (int i = 0; i < psd.psd_nfilts; i++) {
		if (!psd.psd_used[i]) {
			warnx("filter '%s' did not match any devices",
			    psd.psd_filts[i]);
			ret = EXIT_FAILURE;
		}
	}

	if (psd.psd_nprint == 0) {
		ret = EXIT_FAILURE;
	}

	return (ret);
}
