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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SESIO_H
#define	_SYS_SESIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Enclosure Services Interface Structures
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Data Structures and definitions for SES Applications
 */

typedef struct {
	unsigned int obj_id;		/* Object Identifier */
	unsigned int		:  16,	/* reserved */
		subencid	:  8,	/* SubEnclosure ID */
		elem_type	:  8;	/* Element Type */
} ses_object;

/* Known Enclosure Types */
#define	SESTYP_UNSPECIFIED	0x00
#define	SESTYP_DEVICE		0x01
#define	SESTYP_POWER		0x02
#define	SESTYP_FAN		0x03
#define	SESTYP_THERM		0x04
#define	SESTYP_DOORLOCK		0x05
#define	SESTYP_ALARM		0x06
#define	SESTYP_ESCC		0x07	/* Enclosure SCC */
#define	SESTYP_SCC		0x08	/* SCC */
#define	SESTYP_NVRAM		0x09
#define	SESTYP_UPS		0x0b
#define	SESTYP_DISPLAY		0x0c
#define	SESTYP_KEYPAD		0x0d
#define	SESTYP_SCSIXVR		0x0f
#define	SESTYP_LANGUAGE		0x10
#define	SESTYP_COMPORT		0x11
#define	SESTYP_VOM		0x12
#define	SESTYP_AMMETER		0x13
#define	SESTYP_SCSI_TGT		0x14
#define	SESTYP_SCSI_INI		0x15
#define	SESTYP_SUBENC		0x16
#define	SESTYP_ARRAY		0x17	/* SES2r19 #7.1 */
#define	SESTYP_SASEXPANDER	0x18	/* SES2r19 #7.1 */
#define	SESTYP_SASCONNECTOR	0x19	/* SES2r19 #7.1 */


/*
 * Overall Enclosure Status
 */
#define	ENCSTAT_UNRECOV		0x1
#define	ENCSTAT_CRITICAL	0x2
#define	ENCSTAT_NONCRITICAL	0x4
#define	ENCSTAT_INFO		0x8

typedef struct {
	uint_t obj_id;
	uchar_t cstat[4];
} ses_objarg;

/* Summary SES Status Defines, Common Status Codes */
#define	SESSTAT_UNSUPPORTED	0
#define	SESSTAT_OK		1
#define	SESSTAT_CRIT		2
#define	SESSTAT_NONCRIT		3
#define	SESSTAT_UNRECOV		4
#define	SESSTAT_NOTINSTALLED	5
#define	SESSTAT_UNKNOWN		6
#define	SESSTAT_NOTAVAIL	7

/*
 * For control pages, cstat[0] is the same for the
 * enclosure and is common across all device types.
 *
 * If SESCTL_CSEL is set, then PRDFAIL, DISABLE and RSTSWAP
 * are checked, otherwise bits that are specific to the device
 * type in the other 3 bytes of cstat or checked.
 */
#define	SESCTL_CSEL		0x80
#define	SESCTL_PRDFAIL		0x40
#define	SESCTL_DISABLE		0x20
#define	SESCTL_RSTSWAP		0x10


/* Control bits, Device Elements, byte 2 */
#define	SESCTL_DRVLCK	0x40	/* "DO NOT REMOVE" */
#define	SESCTL_RQSINS	0x08	/* RQST INSERT */
#define	SESCTL_RQSRMV	0x04	/* RQST REMOVE */
#define	SESCTL_RQSID	0x02	/* RQST IDENT */
/* Control bits, Device Elements, byte 3 */
#define	SESCTL_RQSFLT	0x20	/* RQST FAULT */
#define	SESCTL_DEVOFF	0x10	/* DEVICE OFF */

/* Control bits, Generic, byte 3 */
#define	SESCTL_RQSTFAIL	0x40
#define	SESCTL_RQSTON	0x20


/*
 * SES Driver ioctls
 */
#define	SESIOC			('e'<<8)
#define	SESIOC_IOCTL_GETSTATE	(SESIOC|1)	/* get esi status */
#define	SESIOC_IOCTL_SETSTATE	(SESIOC|2)	/* set esi state */
#define	SESIOC_IOCTL_INQUIRY	(SESIOC|3)	/* get SCSI Inquiry info */
#define	SESIOC_GETNOBJ		(SESIOC|10)
#define	SESIOC_GETOBJMAP	(SESIOC|11)
#define	SESIOC_INIT		(SESIOC|12)
#define	SESIOC_GETENCSTAT	(SESIOC|13)
#define	SESIOC_SETENCSTAT	(SESIOC|14)
#define	SESIOC_GETOBJSTAT	(SESIOC|15)
#define	SESIOC_SETOBJSTAT	(SESIOC|16)

/*
 * The following structure is used by the SES_IOCTL_GETSTATE
 * and the SES_IOCTL_SETSTATE ioctls
 */
struct ses_ioctl {
    uint32_t	page_size;	/* Size of page to be read/written */
    uint8_t	page_code;	/* Page to be read/written */
    caddr_t	page;		/* Address of page to be read/written */
};


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SESIO_H */
