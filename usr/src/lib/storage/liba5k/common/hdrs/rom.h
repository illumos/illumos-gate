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

/*
 * PHOTON CONFIGURATION MANAGER
 * Downloadable code definitions
 */

#ifndef	_ROM_H
#define	_ROM_H


/*
 * Include any headers you depend on.
 */

/*
 * I18N message number ranges
 *  This file: 17500 - 17999
 *  Shared common messages: 1 - 1999
 */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * The PLUTO controller has 4 proms (0-3).  Prom 1-3 are writeable and are
 * soldered to the board while prom 0 is not writeable but socketed. The
 * following items are placed in the PLUTO prom set:
 *	- POST0		-Power On Self Test code.  This code goes in
 *			 pluto_prom0 and may not be modified in the field.
 *			 It contains serial port downloading code.
 *	- FUNC		-Pluto Functional code (SPARC)
 *	- SOC		-SOC microcode
 *	- ISP		-ISP microcode
 *	- OBP		-Open Boot Prom code
 *	- Date Code	-date/time of prom creation.
 *	- WWN		- World Wide Name
 *
 *
 * This utility creates the writeable prom images for PLUTO.  Three prom images
 * are created: pluto_prom1, pluto_prom2, pluto_prom3.
 *
 * The following defines the layout of the 4 proms on the PLUTO controller:
 *
 * prom		offset		image
 * -----------------------------------
 * prom_0:
 *		0		POST
 * prom_1:
 *		0		FUNC
 * prom_2:
 *		0		FUNC cont'd
 * prom_3:
 *		PROM_MAGIC_OFF  PROM_MAGIC
 *		DATE_OFF	DATE_CODE
 *		WWN_OFF		WWN
 *		SOC_OFF 	SOC
 *		ISP_OFF		ISP
 *		OBP_OFF		OBP
 */
#define	PROM_MAGIC	0x2468
#define	PROMSIZE	0x00040000	/* 256K bytes each prom */
#define	EEPROM_SECTSIZ	0x100


#define	IBEEPROM	1
#define	MBEEPROM	2

#define	FW_DL_INFO	0x2d0
#define	FPM_DL_INFO	0x31000

struct dl_info {
	ushort_t	unused;
	ushort_t	magic;
	ulong_t		cksum;
	time_t		datecode;
};

#define	WWN_SIZE	8
#define	TEXT_SZ		64*1024
#define	IDATA_SZ	32*1024
#define	FPM_SZ		60*1024

/* offsets in prom */
#define	TEXT_OFFSET	0
#define	IDATA_OFFSET	0x10000
#define	FPM_OFFSET	0x31000


#ifdef	__cplusplus
}
#endif

#endif	/* _ROM_H */
