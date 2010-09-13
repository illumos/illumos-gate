/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1995-1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains an array of structures, each of which refers to
 *	a tuple that we are prepared to handle.  The last structure
 *	in this array must have a type of CISTPL_END.
 *
 * If you want the generic tuple handler to be called for a tuple, use
 *	the cis_no_tuple_handler() entry point.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/autoconf.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/ddi_impldefs.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/callb.h>

#include <sys/pctypes.h>
#include <pcmcia/sys/cs_types.h>
#include <pcmcia/sys/cis.h>
#include <pcmcia/sys/cis_handlers.h>
#include <pcmcia/sys/cs.h>
#include <pcmcia/sys/cs_priv.h>
#include <pcmcia/sys/cis_protos.h>

/*
 * cistpl_std_callout - callout list for standard tuples
 */
cistpl_callout_t cistpl_std_callout[] = {
	{	CISTPL_DEVICE,			/* device information */
		0,
		0,
		cistpl_device_handler,
		"CISTPL_DEVICE"		},
	{	CISTPL_CHECKSUM,		/* checksum control */
		0,
		0,
		cis_no_tuple_handler,
		"CISTPL_CHECKSUM"	},
	{	CISTPL_LONGLINK_A,		/* long-link to AM */
		0,
		0,
		cistpl_longlink_ac_handler,
		"CISTPL_LONGLINK_A"	},
	{	CISTPL_LONGLINK_C,		/* long-link to CM */
		0,
		0,
		cistpl_longlink_ac_handler,
		"CISTPL_LONGLINK_C"	},
	{	CISTPL_LONGLINK_MFC,		/* long-link to MFC CIS */
		0,
		0,
		cistpl_longlink_mfc_handler,
		"CISTPL_LONGLINK_MFC"	},
	{	CISTPL_LINKTARGET,		/* link-target control */
		0,
		0,
		cistpl_linktarget_handler,
		"CISTPL_LINKTARGET"	},
	{	CISTPL_NO_LINK,			/* no-link control */
		0,
		0,
		cis_no_tuple_handler,
		"CISTPL_NO_LINK"	},
	{	CISTPL_VERS_1,			/* level 1 version info */
		0,
		0,
		cistpl_vers_1_handler,
		"CISTPL_VERS_1"		},
	{	CISTPL_ALTSTR,			/* alternate language string */
		0,
		0,
		cis_no_tuple_handler,
		"CISTPL_ALTSTR"		},
	{	CISTPL_DEVICE_A,		/* AM device information */
		0,
		0,
		cistpl_device_handler,
		"CISTPL_DEVICE_A"	},
	{	CISTPL_JEDEC_C,			/* JEDEC info for CM */
		0,
		0,
		cistpl_jedec_handler,
		"CISTPL_JEDEC_C"	},
	{	CISTPL_JEDEC_A,			/* JEDEC info for AM */
		0,
		0,
		cistpl_jedec_handler,
		"CISTPL_JEDEC_A"	},
	{	CISTPL_CONFIG,			/* configuration */
		0,
		0,
		cistpl_config_handler,
		"CISTPL_CONFIG"		},
	{	CISTPL_CFTABLE_ENTRY,		/* configuration-table-entry */
		0,
		0,
		cistpl_cftable_handler,
		"CISTPL_CFTABLE_ENTRY"	},
	{	CISTPL_DEVICE_OC,		/* other conditions for CM */
		0,
		0,
		cistpl_device_handler,
		"CISTPL_DEVICE_OC"	},
	{	CISTPL_DEVICE_OA,		/* other conditions for AM */
		0,
		0,
		cistpl_device_handler,
		"CISTPL_DEVICE_OA"	},
	{	CISTPL_VERS_2,			/* level 2 version info */
		0,
		0,
		cistpl_vers_2_handler,
		"CISTPL_VERS_2"		},
	{	CISTPL_FORMAT,			/* format type */
		0,
		0,
		cistpl_format_handler,
		"CISTPL_FORMAT"		},
	{	CISTPL_FORMAT_A,		/* Attribute Memory */
		0,				/* recording format */
		0,
		cistpl_format_handler,
		"CISTPL_FORMAT_A"	},
	{	CISTPL_GEOMETRY,		/* geometry */
		0,
		0,
		cistpl_geometry_handler,
		"CISTPL_GEOMETRY"	},
	{	CISTPL_BYTEORDER,		/* byte order */
		0,
		0,
		cistpl_byteorder_handler,
		"CISTPL_BYTEORDER"	},
	{	CISTPL_DATE,			/* card initialization date */
		0,
		0,
		cistpl_date_handler,
		"CISTPL_DATE"		},
	{	CISTPL_BATTERY,			/* battery replacement date */
		0,
		0,
		cistpl_battery_handler,
		"CISTPL_BATTERY"	},
	{	CISTPL_ORG,			/* organization */
		0,
		0,
		cistpl_org_handler,
		"CISTPL_ORG"		},
	{	CISTPL_FUNCID,			/* card function ID */
		0,
		0,
		cistpl_funcid_handler,
		"CISTPL_FUNCID"		},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_MULTI,		/* for multifunction cards */
		0,
		cis_no_tuple_handler,
		"CISTPL_FUNCE/MULTI"	},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_MEMORY,		/* for memory cards */
		0,
		cis_no_tuple_handler,
		"CISTPL_FUNCE/MEMORY"	},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_SERIAL,		/* for serial port cards */
		0,
		cistpl_funce_serial_handler,
		"CISTPL_FUNCE/SERIAL"	},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_PARALLEL,		/* for parallel port cards */
		0,
		cis_no_tuple_handler,
		"CISTPL_FUNCE/PARALLEL"	},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_FIXED,		/* for fixed disk cards */
		0,
		cis_no_tuple_handler,
		"CISTPL_FUNCE/FIXED"	},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_VIDEO,		/* for video cards */
		0,
		cis_no_tuple_handler,
		"CISTPL_FUNCE/VIDEO"	},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_LAN,		/* for LAN cards */
		0,
		cistpl_funce_lan_handler,
		"CISTPL_FUNCE/LAN"	},

	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_AIMS,		/* Auto Incrementing Mass Storage */
		0,
		cis_no_tuple_handler,
		"CISTPL_FUNCE/AIMS"	},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_SCSI,		/* SCSI bridge */
		0,
		cis_no_tuple_handler,
		"CISTPL_FUNCE/SCSI"	},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_VENDOR_SPECIFIC,	/* Vendor Specific */
		0,
		cis_no_tuple_handler,
		"CISTPL_FUNCE/VENDOR_SPECIFIC"	},
	{	CISTPL_FUNCE,			/* card function extension */
		TPLFUNC_UNKNOWN,	/* for unknown functions */
		0,
		cis_no_tuple_handler,
		"CISTPL_FUNCE/unknown"	},
	{	CISTPL_MANFID,			/* manufacturer ID */
		0,
		0,
		cistpl_manfid_handler,
		"CISTPL_MANFID"		},
	{	CISTPL_SPCL,			/* special-purpose tuple */
		0,
		0,
		cis_no_tuple_handler,
		"CISTPL_SPCL"		},
	{	CISTPL_LONGLINK_CB,		/* longlink to next */
		0,				/* tuple chain */
		0,
		cis_no_tuple_handler,
		"CISTPL_LONGLINK_CB"	},
	{	CISTPL_CONFIG_CB,		/* configuration tuple */
		0,
		0,
		cis_no_tuple_handler,
		"CISTPL_CONFIG_CB"	},
	{	CISTPL_CFTABLE_ENTRY_CB,	/* configuration table */
		0,				/* entry */
		0,
		cis_no_tuple_handler,
		"CISTPL_CFTABLE_ENTRY_CB"	},
	{	CISTPL_BAR,			/* Base Address Register */
		0,				/* definition */
		0,
		cis_no_tuple_handler,
		"CISTPL_BAR"		},
	{	CISTPL_DEVICEGEO,		/* Common Memory */
		0,				/* device geometry */
		0,
		cis_no_tuple_handler,
		"CISTPL_DEVICEGEO"	},
	{	CISTPL_DEVICEGEO_A,		/* Attribute Memory */
		0,				/* device geometry */
		0,
		cis_no_tuple_handler,
		"CISTPL_DEVICEGEO_A"	},
	{	CISTPL_SWIL,			/* software interleave */
		0,
		0,
		cis_no_tuple_handler,
		"CISTPL_SWIL"		},
	{	CISTPL_VEND_SPEC_80,		/* vendor-specific 0x80 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_80"	},
	{	CISTPL_VEND_SPEC_81,		/* vendor-specific 0x81 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_81"	},
	{	CISTPL_VEND_SPEC_82,		/* vendor-specific 0x82 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_82"	},
	{	CISTPL_VEND_SPEC_83,		/* vendor-specific 0x83 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_83"	},
	{	CISTPL_VEND_SPEC_84,		/* vendor-specific 0x84 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_84"	},
	{	CISTPL_VEND_SPEC_85,		/* vendor-specific 0x85 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_85"	},
	{	CISTPL_VEND_SPEC_86,		/* vendor-specific 0x86 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_86"	},
	{	CISTPL_VEND_SPEC_87,		/* vendor-specific 0x87 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_87"	},
	{	CISTPL_VEND_SPEC_88,		/* vendor-specific 0x88 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_88"	},
	{	CISTPL_VEND_SPEC_89,		/* vendor-specific 0x89 */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_89"	},
	{	CISTPL_VEND_SPEC_8a,		/* vendor-specific 0x8a */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_8a"	},
	{	CISTPL_VEND_SPEC_8b,		/* vendor-specific 0x8b */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_8b"	},
	{	CISTPL_VEND_SPEC_8c,		/* vendor-specific 0x8c */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_8c"	},
	{	CISTPL_VEND_SPEC_8d,		/* vendor-specific 0x8d */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_8d"	},
	{	CISTPL_VEND_SPEC_8e,		/* vendor-specific 0x8e */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_8e"	},
	{	CISTPL_VEND_SPEC_8f,		/* vendor-specific 0x8f */
		0,
		0,
		cis_unknown_tuple_handler,
		"CISTPL_VEND_SPEC_8f"	},
	{	CISTPL_END,			/* end-of-list tuple */
		0,
		0,
		cis_no_tuple_handler,
		"unknown tuple"		},
	};
