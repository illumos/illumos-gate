/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_FW_H
#define	_EMLXS_FW_H

#ifdef	__cplusplus
extern "C" {
#endif

#if 0
#define	EMLXS_FW_TABLE_DEF	/* Causes the firmware table to be */
				/* defined in local memory. */

#define	EMLXS_FW_IMAGE_DEF	/* Causes the firmware image to be */
				/* defined in the firmware table. */
#endif /* 0 */

#define	EMLXS_FW_MODULE		"misc/"DRIVER_NAME"/"DRIVER_NAME"_fw"

/* Unique id for each firmware image */
typedef enum emlxs_fwid
{
	FW_NOT_PROVIDED = 0,
	LP10000_FW,
	LP11000_FW,
	LP11002_FW,
	LPe11000_FW,
	LPe11002_FW,
	LPe12000_FW
} emlxs_fwid_t;

/* Firmware image descriptor */
typedef struct emlxs_firmware
{
	emlxs_fwid_t	id;
	uint32_t	size;
	uint8_t		*image;
	char		label[64];
	uint32_t	kern;
	uint32_t	stub;
	uint32_t	sli1;
	uint32_t	sli2;
	uint32_t	sli3;
	uint32_t	sli4;
} emlxs_firmware_t;


#ifdef EMLXS_FW_TABLE_DEF

#ifndef MODFW_SUPPORT
#define	EMLXS_FW_IMAGE_DEF
#endif /* MODFW_SUPPORT */

/* Provide firmware information for each adapter */
#include <fw_lp10000.h>
#include <fw_lp11000.h>
#include <fw_lp11002.h>
#include <fw_lpe11000.h>
#include <fw_lpe11002.h>
#include <fw_lpe12000.h>

/* Build the firmware table */
#define	EMLXS_FW_TABLE	\
{\
	{\
		LP10000_FW,\
		emlxs_lp10000_size,\
		emlxs_lp10000_image,\
		emlxs_lp10000_label,\
		emlxs_lp10000_kern,\
		emlxs_lp10000_stub,\
		emlxs_lp10000_sli1,\
		emlxs_lp10000_sli2,\
		emlxs_lp10000_sli3,\
		emlxs_lp10000_sli4\
	},\
	{\
		LP11000_FW,\
		emlxs_lp11000_size,\
		emlxs_lp11000_image,\
		emlxs_lp11000_label,\
		emlxs_lp11000_kern,\
		emlxs_lp11000_stub,\
		emlxs_lp11000_sli1,\
		emlxs_lp11000_sli2,\
		emlxs_lp11000_sli3,\
		emlxs_lp11000_sli4,\
	},\
	{\
		LP11002_FW,\
		emlxs_lp11002_size,\
		emlxs_lp11002_image,\
		emlxs_lp11002_label,\
		emlxs_lp11002_kern,\
		emlxs_lp11002_stub,\
		emlxs_lp11002_sli1,\
		emlxs_lp11002_sli2,\
		emlxs_lp11002_sli3,\
		emlxs_lp11002_sli4\
	},\
	{\
		LPe11000_FW,\
		emlxs_lpe11000_size,\
		emlxs_lpe11000_image,\
		emlxs_lpe11000_label,\
		emlxs_lpe11000_kern,\
		emlxs_lpe11000_stub,\
		emlxs_lpe11000_sli1,\
		emlxs_lpe11000_sli2,\
		emlxs_lpe11000_sli3,\
		emlxs_lpe11000_sli4\
	},\
	{\
		LPe11002_FW,\
		emlxs_lpe11002_size,\
		emlxs_lpe11002_image,\
		emlxs_lpe11002_label,\
		emlxs_lpe11002_kern,\
		emlxs_lpe11002_stub,\
		emlxs_lpe11002_sli1,\
		emlxs_lpe11002_sli2,\
		emlxs_lpe11002_sli3,\
		emlxs_lpe11002_sli4\
	},\
	{\
		LPe12000_FW,\
		emlxs_lpe12000_size,\
		emlxs_lpe12000_image,\
		emlxs_lpe12000_label,\
		emlxs_lpe12000_kern,\
		emlxs_lpe12000_stub,\
		emlxs_lpe12000_sli1,\
		emlxs_lpe12000_sli2,\
		emlxs_lpe12000_sli3,\
		emlxs_lpe12000_sli4\
	}\
}
#endif /* EMLXS_FW_TABLE_DEF */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_FW_H */
