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

#ifndef	_SYS_SDCARD_SDA_IOCTL_H
#define	_SYS_SDCARD_SDA_IOCTL_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These IOCTLs are private between the sdcard cfgadm plugin, and the sda
 * framework.
 */

typedef enum {
	SDA_CT_UNKNOWN,
	SDA_CT_MMC,
	SDA_CT_SDMEM,
	SDA_CT_SDHC,
	SDA_CT_SDCOMBO,
	SDA_CT_SDIO	/* expand on this later */
} sda_card_type_t;

typedef struct {

	sda_card_type_t	ci_type;

	/* these are only valid for memory cards */
	uint32_t	ci_mfg;
	char		ci_oem[16];	/* mfg id */
	char		ci_pid[16];	/* ASCIIZ product */
	uint32_t	ci_serial;
	uint8_t		ci_month;
	uint8_t		ci_year;
	uint8_t		ci_major;
	uint8_t		ci_minor;
} sda_card_info_t;

struct sda_ap_control {
	unsigned	cmd;
	size_t		size;
	void		*data;
};

#ifdef	_KERNEL
struct sda_ap_control32 {
	unsigned	cmd;
	size32_t	size;
	caddr32_t	data;
};
#endif

/* AP_CONTROL commands */
#define	SDA_CFGA_GET_CARD_INFO		1
#define	SDA_CFGA_GET_DEVICE_PATH	2
#define	SDA_CFGA_RESET_SLOT		3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SDCARD_SDA_IOCTL_H */
