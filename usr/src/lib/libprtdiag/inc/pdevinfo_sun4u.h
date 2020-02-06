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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright (c) 2020 Peter Tribble.
 */

#ifndef	_PDEVINFO_SUN4U_H
#define	_PDEVINFO_SUN4U_H

#include <sys/obpdefs.h>
#include <sys/envctrl_gen.h>
#include <sys/envctrl_ue250.h>
#include <sys/envctrl_ue450.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These were formerly defined in sys/ac.h, which was specific to sunfire,
 * but usage has leaked into generic code.
 */
#ifndef	TRUE
#define	TRUE (1)
#endif
#ifndef	FALSE
#define	FALSE (0)
#endif

/*
 * These were formerly defined as part of the board_type enum in sys/fhc.h,
 * which was specific to sunfire, but usage has leaked into generic code.
 */
#define UNKNOWN_BOARD 1
#define CPU_BOARD 2

/* Define names of nodes to search for */
#define	SBUS_NAME	"sbus"
#define	PCI_NAME	"pci"
#define	FFB_NAME	"SUNW,ffb"
#define	AFB_NAME	"SUNW,afb"

/* Environmental info for Tazmo */
struct envctrl_kstat_data {
	envctrl_ps_t ps_kstats[MAX_DEVS];  /* kstats for powersupplies */
	envctrl_fan_t fan_kstats[MAX_DEVS]; /* kstats for fans */
	envctrl_encl_t encl_kstats[MAX_DEVS]; /* kstats for enclosure */
};

/* Environmental info for Javelin */
struct envctrltwo_kstat_data {
	envctrl_ps2_t ps_kstats[MAX_DEVS];	/* kstats for powersupplies */
	int num_ps_kstats;
	envctrl_fan_t fan_kstats[MAX_DEVS]; /* kstats for fans */
	int num_fan_kstats;
	envctrl_encl_t encl_kstats[MAX_DEVS]; /* kstats for enclosure */
	int num_encl_kstats;
	envctrl_temp_t temp_kstats[MAX_DEVS]; /* kstats for temperatures */
	int num_temp_kstats;
	envctrl_disk_t disk_kstats[MAX_DEVS]; /* kstats for disks */
	int num_disk_kstats;
};

struct system_kstat_data {
	int	sys_kstats_ok;	/* successful kstat read occurred */
	struct envctrl_kstat_data env_data;  /* environment data for Tazmo */
	int	envctrl_kstat_ok;
	struct envctrltwo_kstat_data envc_data;  /* environ data for Javelin */
	int	envctrltwo_kstat_ok;
};

#define	MAXSTRLEN	256

/* FFB info structure */
struct ffbinfo {
	int board;
	int upa_id;
	char *dev;
	struct ffbinfo *next;
};

/* FFB strap reg union */
union strap_un {
	struct {
		uint_t	unused:24;
		uint_t	afb_flag:1;
		uint_t	major_rev:2;
		uint_t	board_rev:2;
		uint_t	board_mem:1;
		uint_t	cbuf:1;
		uint_t	bbuf:1;
	} fld;
	uint_t ffb_strap_bits;
};

/* known values for manufacturer's JED code */
#define	MANF_BROOKTREE	214
#define	MANF_MITSUBISHI	28

/* FFB mnufacturer union */
union manuf {
	struct {
		uint_t version:4;	/* version of part number */
		uint_t partno:16;	/* part number */
		uint_t manf:11;		/* manufacturer's JED code */
		uint_t one:1;		/* always set to '1' */
	} fld;
	uint_t encoded_id;
};

#define	FFBIOC		('F' << 8)
#define	FFB_SYS_INFO	(FFBIOC| 80)

struct ffb_sys_info {
	unsigned int	ffb_strap_bits;	/* ffb_strapping register	*/
#define	FFB_B_BUFF	0x01		/* B buffer present		*/
#define	FFB_C_BUFF	0x02		/* C buffer present		*/
#define	FB_TYPE_AFB	0x80		/* AFB or FFB			*/
	unsigned int	fbc_version;	/* revision of FBC chip		*/
	unsigned int	dac_version;	/* revision of DAC chip		*/
	unsigned int	fbram_version;	/* revision of FBRAMs chip	*/
	unsigned int	flags;		/* miscellaneous flags		*/
#define	FFB_KSIM	0x00000001	/* kernel simulator		*/
#define	FFB_PAGE_FILL_BUG 0x00000002	/* FBRAM has page fill bug	*/
	unsigned int	afb_nfloats;	/* no. of Float asics in AFB	*/
	unsigned int	pad[58];	/* padding for AFB chips & misc. */
};

int get_id(Prom_node *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PDEVINFO_SUN4U_H */
