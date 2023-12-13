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

/* Copyright 2015 QLogic Corporation */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver source file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2015 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

/*
 * Determine HBA FRU card information for T11 FC-HBA
 */

#include <ql_apps.h>
#include <ql_api.h>
#include <ql_debug.h>
#include <ql_ioctl.h>
#include <ql_xioctl.h>

/*
 * Temporary define until LV headers are updated
 */
#ifndef	FC_HBA_PORTSPEED_8GBIT
#define	FC_HBA_PORTSPEED_8GBIT		16    /* 8 GBit/sec */
#endif

/* Local prototypes */
static uint32_t ql_get_basedev_len(ql_adapter_state_t *, uint32_t *,
    uint32_t *);
static ql_adapter_state_t *ql_search_basedev(ql_adapter_state_t *, uint32_t);

/* Local structures */
static struct ql_known_models {
	uint16_t    ssid;		/* Subsystem ID */
	uint16_t    ssvid;		/* Subsystem Vendor ID */
	char	    model[256];
	char	    model_description[256];

} models[] = {
	{
	    /* QLogic */
	    0x2, 0x1077, "QLA2200", "QLogic PCI to 1Gb FC, Single Channel"
	}, {
	    /* QLogic */
	    0x9, 0x1077, "QLA2300", "QLogic PCI to 2Gb FC, Single Channel"
	}, {
	    /* QLA2200, SUN2200 Amber */
	    0x4082, 0x1077, "375-3019-xx", "X6799A"
	}, {
	    /* QLA2212, SUN2212 Crystal+ */
	    0x4083, 0x1077, "375-3030-xx", "X6727A"
	}, {
	    /* QCP2202, SUNQCP2202 Diamond */
	    0x4084, 0x1077, "375-0118-xx", "X6748A"
	}, {
	    /* QLA2202FS, SUN2202FS Ivory */
	    0x4085, 0x1077, "375-3048-xx", "X6757A"
	}, {
	    /* QLogic */
	    0x100, 0x1077, "QLA2340",
	    "QLogic 133MHz PCI-X to 2Gb FC, Single Channel"
	}, {
	    /* QLogic */
	    0x101, 0x1077, "QLA2342",
	    "QLogic 133MHz PCI-X to 2Gb FC, Dual Channel"
	}, {
	    /* QLogic */
	    0x102, 0x1077, "QLA2344",
	    "QLogic 133MHz PCI-X to 2Gb FC, Quad Channel"
	}, {
	    /* QLogic */
	    0x103, 0x1077, "QCP2342", "QLogic cPCI to 2Gb FC, Dual Channel"
	}, {
	    /* QLogic */
	    0x104, 0x1077, "QSB2340", "QLogic SBUS to 2Gb FC, Single Channel"
	}, {
	    /* QLogic */
	    0x105, 0x1077, "QSB2342", "QLogic SBUS to 2Gb FC, Dual Channel"
	}, {
	    /* QLA2310, SUN-66MHz PCI-X to 2Gb FC, Single Channel, Amber 2 */
	    0x0106, 0x1077, "375-3102-xx", "SG-XPCI1FC-QF2 (X6767A)"
	}, {
	    /* QLogic */
	    0x109, 0x1077, "QCP2340", "QLogic cPCI to 2Gb FC, Single Channel"
	}, {
	    /* QLA2342, SUN-133MHz PCI-X to 2Gb FC, Dualchannel, Crystal 2A */
	    0x010A, 0x1077, "375-3108-xx", "SG-XPCI2FC-QF2 (X6768A)"
	}, {
	    /* QLogic */
	    0x115, 0x1077, "QLA2360",
	    "QLogic 133MHz PCI-X to 2Gb FC, Single Channel"
	}, {
	    /* QLogic */
	    0x116, 0x1077, "QLA2362",
	    "QLogic 133MHz PCI-X to 2Gb FC, Dual Channel"
	}, {
	    /* QLogic */
	    0x117, 0x1077, "QLE2360",
	    "QLogic PCI-Express to 2Gb FC, Single Channel"
	}, {
	    /* QLogic */
	    0x118, 0x1077, "QLE2362",
	    "QLogic PCI Express to 2Gb FC, Dual Channel"
	}, {
	    /* QLogic */
	    0x119, 0x1077, "QLA200",
	    "QLogic 133MHz PCI-X to 2Gb FC, Single Channel"
	}, {
	    /* QLogic */
	    0x11c, 0x1077, "QLA200P",
	    "QLogic 133MHz PCI-X to 2Gb FC, Single Channel"
	}, {
	    /* QLogic */
	    0x12f, 0x1077, "QLA210",
	    "QLogic 133MHz PCI-X to 2Gb FC, Single Channel"
	}, {
	    /* QLogic */
	    0x130, 0x1077, "EMC250-051-900",
	    "QLogic 133MHz PCI-X to 2Gb FC, Single Channel"
	}, {
	    /* QLA210, SUN-133MHz PCI-X to 2Gb FC, Single Channel, Prism */
	    0x132, 0x1077, "375-32X3-01", "SG-PCI1FC-QLC"
	}, {
	    /* QLogic */
	    0x13e, 0x1077, "QLE210",
	    "QLogic PCI Express 2Gb FC, Single Channel"
	}, {
	    /* Sun */
	    0x149, 0x1077, "QLA2340",
	    "SUN - 133MHz PCI-X to 2Gb FC, Single Channel"
	}, {
	    /* HP */
	    0x100, 0x0e11, "QLA2340-HP", "PCIX to 2Gb FC, Single Channel"
	}, {
	    /* HP */
	    0x101, 0x0e11, "QLA2342-HP", "PCIX to 2Gb FC, Dual Channel"
	}, {
	    /* HP */
	    0x103, 0x0e11, "QLA2312-HP",
	    "HP Bladed Server Balcony Card - HP BalcnL"
	}, {
	    /* HP */
	    0x104, 0x0e11, "QLA2312-HP", "HP Bladed Server - HP MezzF"
	}, {
	    /* HP */
	    0x105, 0x0e11, "QLA2312-HP", "HP Bladed Server - HP BalcnL"
	}, {
	    /* HP */
	    0x106, 0x0e11, "QLA2312-HP", "HP Bladed Server - HP BalcnF"
	}, {
	    /* HP */
	    0x107, 0x0e11, "QLA2312-HP", "HP Bladed Server"
	}, {
	    /* HP */
	    0x108, 0x0e11, "QLA2312-HP", "HP Bladed Server"
	}, {
	    /* IBM FCEC */
	    0x27d, 0x1014, "IBM-FCEC",
	    "IBM eServer Blade Center FC Expansion Card"
	}, {
	    /* IBM FCEC */
	    0x2fb, 0x1014, "IBM-FCEC",
	    "IBM eServer Blade Center FC SFF Expansion Card"
	}, {
	    /* Intel */
	    0x34ba, 0x8086, "Intel SBFCM",
	    "Intel Server FC Expansion Card SBFCM"
	}, {
	    /* Intel */
	    0x34a0, 0x8086, "Intel SBEFCM",
	    "Intel Server SFF FC Expansion Card SBFCM"
	}, {
	    /* FCI/O */
	    0x1051, 0x1734, "FCI/O-CARD2Gb/s",
	    "FSC-Quanta FC I/O-Card 2GBit/s"
	}, {
	    /* Dell */
	    0x18a, 0x1028, "FCI/O-CARD2Gb/s", "Dell Glacier Blade Server"
	}, {
	    /* end of list */
	    0, 0, 0, 0, 0, 0
	} };

/*
 * ql_populate_hba_fru_details
 *	Sets up HBA fru information for UL utilities
 *	(cfgadm, fcinfo, et. al.)
 *
 * Input:
 *	ha		= adapter state structure
 *	port_info	= ptr to LV port strcture.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
void
ql_populate_hba_fru_details(ql_adapter_state_t *ha,
    fc_fca_port_info_t *port_info)
{
	fca_port_attrs_t	*attrs = &port_info->pi_attrs;
	uint16_t		chip = ha->device_id;
	uint16_t		model = ha->subsys_id;
	uint16_t		ssdevid = ha->subven_id;
	size_t			vlen;
	int32_t			i;

	QL_PRINT_3(ha, "started\n");

	attrs = &port_info->pi_attrs;

	/* Constants */
	(void) snprintf(attrs->manufacturer, FCHBA_MANUFACTURER_LEN,
	    "QLogic Corp.");
	(void) snprintf(attrs->driver_name, FCHBA_DRIVER_NAME_LEN,
	    "%s", QL_NAME);
	(void) snprintf(attrs->driver_version, FCHBA_DRIVER_VERSION_LEN,
	    "%s", ha->adapter_stats->revlvl.qlddv);

	if ((i = ql_vpd_lookup(ha, (uint8_t *)VPD_TAG_SN, (uint8_t *)
	    attrs->serial_number, FCHBA_SERIAL_NUMBER_LEN)) == -1) {
		attrs->serial_number[0] = '\0';
	}
	attrs->hardware_version[0] = '\0';

	/* Dynamic data */
	(void) snprintf(attrs->firmware_version, FCHBA_FIRMWARE_VERSION_LEN,
	    "%02d.%02d.%02d", ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version);

	/* Report FCode / BIOS / EFI version(s). */
	if (ha->fcache != NULL) {
		uint32_t	types = FTYPE_BIOS|FTYPE_FCODE|FTYPE_EFI;
		ql_fcache_t	*fptr = ha->fcache;
		int8_t		*orv = &*attrs->option_rom_version;

		while ((fptr != NULL) && (types != 0)) {
			/* Get the next image */
			if ((fptr = ql_get_fbuf(ha->fcache, types)) != NULL) {

				switch (fptr->type) {
				case FTYPE_FCODE:
					(void) snprintf(orv,
					    FCHBA_OPTION_ROM_VERSION_LEN,
					    "%s fcode: %s;", orv, fptr->verstr);
					break;
				case FTYPE_BIOS:
					(void) snprintf(orv,
					    FCHBA_OPTION_ROM_VERSION_LEN,
					    "%s BIOS: %s;", orv, fptr->verstr);
					break;
				case FTYPE_EFI:
					(void) snprintf(orv,
					    FCHBA_OPTION_ROM_VERSION_LEN,
					    "%s EFI: %s;", orv, fptr->verstr);
					break;
				default:
					EL(ha, "ignoring ftype: %xh\n",
					    fptr->type);
					break;
				}
				types &= ~(fptr->type);
			}
		}
	}

	if (strlen(attrs->option_rom_version) == 0) {
		int		rval = -1;
		uint32_t	i = 0;
		caddr_t		fcode_ver_buf = NULL;

		if (CFG_IST(ha, CFG_CTRL_22XX)) {
			/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
			rval = ddi_getlongprop(DDI_DEV_T_ANY, ha->dip,
			    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "version",
			    (caddr_t)&fcode_ver_buf, (int32_t *)&i);
		}

		(void) snprintf(attrs->option_rom_version,
		    FCHBA_OPTION_ROM_VERSION_LEN, "%s",
		    (rval == DDI_PROP_SUCCESS ? fcode_ver_buf :
		    "No boot image detected"));

		if (fcode_ver_buf != NULL) {
			kmem_free(fcode_ver_buf, (size_t)i);
		}

	}

	attrs->vendor_specific_id = ha->adapter_features;
	attrs->max_frame_size = ha->loginparams.common_service.rx_bufsize;
	attrs->supported_cos = 0x10000000; /* Class 3 only */

	switch (chip & 0xFF00) {
	case 0x2000:
		attrs->supported_speed = chip == 0x2071 ?
		    FC_HBA_PORTSPEED_32GBIT : FC_HBA_PORTSPEED_16GBIT;
		break;
	case 0x2200:
		attrs->supported_speed = chip == 0x2261 ?
		    FC_HBA_PORTSPEED_16GBIT : FC_HBA_PORTSPEED_1GBIT;
		break;
	case 0x2300:
		attrs->supported_speed = FC_HBA_PORTSPEED_2GBIT |
		    FC_HBA_PORTSPEED_1GBIT;
		break;
	case 0x2400:
	case 0x8400:
		attrs->supported_speed = FC_HBA_PORTSPEED_4GBIT |
		    FC_HBA_PORTSPEED_2GBIT | FC_HBA_PORTSPEED_1GBIT;
		break;
	case 0x8000:
		attrs->supported_speed = FC_HBA_PORTSPEED_10GBIT;
		break;
	case 0x2500:
		attrs->supported_speed = FC_HBA_PORTSPEED_8GBIT |
		    FC_HBA_PORTSPEED_4GBIT | FC_HBA_PORTSPEED_2GBIT |
		    FC_HBA_PORTSPEED_1GBIT;

		/*
		 * Correct supported speeds based on type of
		 * sfp that is present
		 */
		switch (ha->sfp_stat) {
		case 2:
		case 4:
			/* 4GB sfp */
			attrs->supported_speed &= ~FC_HBA_PORTSPEED_8GBIT;
			break;
		case 3:
		case 5:
			/* 8GB sfp */
			attrs->supported_speed &= ~FC_HBA_PORTSPEED_1GBIT;
			break;
		default:
			EL(ha, "sfp_stat: %xh\n", ha->sfp_stat);
			break;

		}

		break;
	case 0x5400:
		if (model == 0x13e) {
			/* QLE210 */
			attrs->supported_speed = FC_HBA_PORTSPEED_2GBIT;
		} else {
			attrs->supported_speed = FC_HBA_PORTSPEED_4GBIT;
		}
		break;
	case 0x6300:
		attrs->supported_speed = FC_HBA_PORTSPEED_2GBIT;
		break;
	default:
		attrs->supported_speed = FC_HBA_PORTSPEED_UNKNOWN;
		break;
	}

	/* Use parent dip as adapter identifier */
	attrs->hba_fru_details.low = 0x514C6F6769630000; /* QLogic */

	if (ha->fru_hba_index == 0) {
		EL(ha, "unable to generate high_fru details from "
		    "device path: %s\n", ha->devpath);
		attrs->hba_fru_details.low = 0;
		attrs->hba_fru_details.high = 0;
		attrs->hba_fru_details.port_index = 0;
	} else {
		attrs->hba_fru_details.high = ha->fru_hba_index;
		attrs->hba_fru_details.port_index = ha->fru_port_index;
	}

	/*
	 * Populate the model info. Legacy (22xx, 23xx, 63xx) do not
	 * have vpd info, so use the hard coded table. Anything else
	 * has VPD (or is suppose to have VPD), so use that. For both
	 * cases, if the model isn't found, use defaults.
	 */

	switch (chip & 0xFF00) {
	case 0x2200:
	case 0x2300:
	case 0x6300:
		/* Table based data */
		for (i = 0; models[i].ssid; i++) {
			if ((model == models[i].ssid) &&
			    (ssdevid == models[i].ssvid)) {
				break;
			}
		}

		if (models[i].ssid) {
			(void) snprintf(attrs->model, FCHBA_MODEL_LEN, "%s",
			    models[i].model);
			(void) snprintf(attrs->model_description,
			    FCHBA_MODEL_DESCRIPTION_LEN, "%s",
			    models[i].model_description);
		} else {
			(void) snprintf(attrs->model, FCHBA_MODEL_LEN,
			    "%x", chip);
			(void) snprintf(attrs->model_description,
			    FCHBA_MODEL_DESCRIPTION_LEN, "%x", chip);
		}

		/* Special model handling for RoHS version of the HBA */
		if (models[i].ssid == 0x10a && ha->adapInfo[10] ==
		    (uint8_t)0x36) {
			(void) snprintf(attrs->model, FCHBA_MODEL_LEN, "%s",
			    "375-3363-xx");
			(void) snprintf(attrs->model_description,
			    FCHBA_MODEL_DESCRIPTION_LEN, "%s",
			    "SG-XPCI2FC-QF2-Z");
		}
		break;

	case 0x2400:
	case 0x2500:
	case 0x5400:
	case 0x8400:
	case 0x8000:
	default:
		if ((i = ql_vpd_lookup(ha, (uint8_t *)VPD_TAG_PN,
		    (uint8_t *)attrs->model, FCHBA_MODEL_LEN)) >= 0) {
			(void) ql_vpd_lookup(ha, (uint8_t *)VPD_TAG_PRODID,
			    (uint8_t *)attrs->model_description,
			    FCHBA_MODEL_DESCRIPTION_LEN);
		} else {
			(void) snprintf(attrs->model, FCHBA_MODEL_LEN,
			    "%x", chip);
			(void) snprintf(attrs->model_description,
			    FCHBA_MODEL_DESCRIPTION_LEN, "%x", chip);
		}
		break;
	}

	/*
	 * Populate the LV symbolic node and port name strings
	 *
	 * Symbolic node name format is:
	 *	<hostname>
	 *
	 * Symbolic port name format is:
	 *	<driver_name>(<instance>,<vp index>)
	 */
	vlen = (strlen(utsname.nodename) > FCHBA_SYMB_NAME_LEN ?
	    FCHBA_SYMB_NAME_LEN : strlen(utsname.nodename));
	(void) snprintf((int8_t *)attrs->sym_node_name, vlen, "%s",
	    utsname.nodename);

	vlen = (strlen(QL_NAME) + 9 > FCHBA_SYMB_NAME_LEN ?
	    FCHBA_SYMB_NAME_LEN : strlen(QL_NAME) + 9);
	(void) snprintf((int8_t *)attrs->sym_port_name, vlen,
	    "%s(%d,%d)", QL_NAME, ha->instance, ha->vp_index);

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_setup_fruinfo
 *	Generates common id's for instances on the same
 *	physical HBA.
 *
 * Input:
 *	ha =  adapter state structure
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
void
ql_setup_fruinfo(ql_adapter_state_t *ha)
{
	uint32_t		mybasedev_len;
	ql_adapter_state_t	*base_ha = NULL;

	QL_PRINT_3(ha, "started\n");

	/*
	 * To generate common id for instances residing on the
	 * the same HBA, the devpath for each instance is parsed
	 * and those instances which have matching base devpaths are
	 * given same hba_index, and each port on the same hba are
	 * then assigned unique port_indexs based on the devpath.
	 */

	/*
	 * Get this ha's basedev path and its port index
	 */
	if (ql_get_basedev_len(ha, &mybasedev_len, &ha->fru_port_index) == 0) {

		/*
		 * Search for this basedev against all of the
		 * ha in the ql_hba global list. If found one
		 * then we are part of other adapter in the
		 * ql_hba list and hence use that ha's hba_index.
		 * If not create a new one from the global hba index.
		 */
		base_ha = ql_search_basedev(ha, mybasedev_len);
		if (base_ha != NULL && base_ha->fru_hba_index != 0) {
			ha->fru_hba_index = base_ha->fru_hba_index;
			ha->fru_port_index = base_ha->fru_port_index + 1;
		} else {
			ha->fru_hba_index = ql_gfru_hba_index++;
			ha->fru_port_index = 0;
		}
	} else {
		ha->fru_hba_index = 0;
		ha->fru_port_index = 0;
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 *  ql_get_basedev_len
 *
 *	Gets the length of the base device name in the
 *	devpath of the current instance.
 *
 * Input:
 *	ha		- adapter state pointer.
 *	basedev_len	- pointer to the integer which
 *			  holds the calculated length.
 *	port_index	- pointer to the integer which
 *			  contains the port index of
 *			  for this device.
 * Returns:
 *	0 if successfully parsed, -1 otherwise.
 *
 * Context:
 *	Kernel context.
 */
static uint32_t
ql_get_basedev_len(ql_adapter_state_t *ha, uint32_t *basedev_len,
    uint32_t *port_index)
{
	int32_t		dev_off;
	int32_t		port_off;
	int8_t		*devstr;

	QL_PRINT_3(ha, "started\n");

	if (ha->devpath == NULL) {
		return ((uint32_t)-1);
	}

	dev_off = (int32_t)(strlen(ha->devpath) - 1);
	port_off = -1;

	/* Until we reach the first char or a '@' char in the path */
	while ((dev_off >= 0) && (ha->devpath[dev_off] != '@')) {

		if (ha->devpath[dev_off] == ',') {
			port_off = dev_off + 1;
		}

		dev_off--;
	}

	if (dev_off < 0) {
		EL(ha, "Invalid device path '%s'. Cannot get basedev\n",
		    ha->devpath);
		return ((uint32_t)-1);
	}

	if (port_off == -1) {
		*port_index = 0;
		*basedev_len = (uint32_t)strlen(ha->devpath);
	} else {
		/* Get the port index */
		devstr = ha->devpath + port_off;
		*port_index = stoi(&devstr);
		if (*port_index == 0) {
			EL(ha, "Invalid device path '%s'. Cannot get "
			    "port_index\n", ha->devpath);
			return ((uint32_t)-1);
		}

		*basedev_len = (uint32_t)(port_off - 1);
	}

	QL_PRINT_3(ha, "done\n");

	return (0);
}

/*
 * ql_search_basedev
 *	Searches the list of ha instances to find which
 *	ha instance has same base device path as input's.
 *
 * Input:
 *	myha 		= current adapter state pointer.
 *	mybasedev_len	= Length of the base device in the
 *			  device path name.
 *
 * Returns:
 *	If match	= ptr to matching ha structure.
 *	If no match	= NULL ptr.
 *
 * Context:
 *	Kernel context.
 */
static ql_adapter_state_t *
ql_search_basedev(ql_adapter_state_t *myha, uint32_t mybasedev_len)
{
	ql_link_t		*link;
	ql_adapter_state_t	*ha;
	uint32_t		basedev_len, port_index;

	QL_PRINT_3(myha, "started\n", myha->instance);

	for (link = ql_hba.first; link != NULL; link = link->next) {

		ha = link->base_address;

		if (ha == NULL) {
			EL(myha, "null ha link detected!\n");
			return (NULL);
		}

		if (ha == myha) {
			continue;
		}

		if (ql_get_basedev_len(ha, &basedev_len, &port_index) != 0) {
			if (ha->devpath == NULL) {
				EL(myha, "Device path NULL. Unable to get "
				    "the basedev\n");
			} else {
				EL(myha, "Invalid device path '%s'. Cannot "
				    "get the hba index and port index\n",
				    ha->devpath);
			}
			continue;
		}

		/*
		 * If both the basedev len do not match, then it
		 * is obvious that both are not pointing to the
		 * same base device.
		 */
		if ((basedev_len == mybasedev_len) && (strncmp(myha->devpath,
		    ha->devpath, basedev_len) == 0)) {

			/* We found the ha with same basedev */
			QL_PRINT_3(myha, "found, done\n",
			    myha->instance);
			return (ha);
		}
	}

	QL_PRINT_3(myha, "not found, done\n", myha->instance);

	return (NULL);
}
