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
 */

#ifndef	_PDEVINFO_SUN4U_H
#define	_PDEVINFO_SUN4U_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/obpdefs.h>
#include <sys/fhc.h>
#include <sys/sysctrl.h>
#include <sys/environ.h>
#include <sys/envctrl_gen.h>
#include <sys/envctrl_ue250.h>
#include <sys/envctrl_ue450.h>
#include <sys/simmstat.h>
#include <sys/ac.h>
#include <sys/sram.h>
#include <reset_info.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	UNIX	"unix"

/* Define names of nodes to search for */
#define	CPU_NAME	"SUNW,UltraSPARC"
#define	SBUS_NAME	"sbus"
#define	PCI_NAME	"pci"
#define	FFB_NAME	"SUNW,ffb"
#define	AFB_NAME	"SUNW,afb"

struct mem_stat_data {
	enum ac_bank_status status;	/* bank status values */
	enum ac_bank_condition condition;	/* bank conditions */
};

struct bd_kstat_data {
	u_longlong_t 	ac_memctl;	/* Memctl register contents */
	u_longlong_t 	ac_memdecode[2]; /* memory decode registers . */
	int	ac_kstats_ok;	/* successful kstat read occurred */
	uint_t	fhc_bsr;	/* FHC Board Status Register */
	uint_t	fhc_csr;	/* FHC Control Status Register */
	int	fhc_kstats_ok;	/* successful kstat read occurred */
	uchar_t	simm_status[SIMM_COUNT];	/* SIMM status */
	int	simmstat_kstats_ok;	/* successful read occurred */
	struct temp_stats tempstat;
	int	temp_kstat_ok;
	struct	mem_stat_data	mem_stat[2];	/* raw kstat bank information */
	int	ac_memstat_ok;	/* successful read of memory status */
};

/*
 * Hot plug info structure. If a hotplug kstat is found, the bd_info
 * structure from the kstat is filled in the the hp_info structure
 * is marked OK.
 */
struct hp_info {
	struct bd_info bd_info;
	int kstat_ok;
};

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
	uchar_t	sysctrl;	/* sysctrl register contents */
	uchar_t	sysstat1;	/* system status1 register contents. */
	uchar_t	sysstat2;	/* system status2 register contents. */
	uchar_t ps_shadow[SYS_PS_COUNT];	/* power supply shadow */
	int	psstat_kstat_ok;
	uchar_t	clk_freq2;	/* clock frequency register 2 contents */
	uchar_t	fan_status;	/* shadow fan status */
	uchar_t	keysw_status;	/* status of the key switch */
	enum power_state power_state;	/* redundant power state */
	uchar_t	clk_ver;	/* clock version register */
	int	sys_kstats_ok;	/* successful kstat read occurred */
	struct temp_stats tempstat;
	int	temp_kstat_ok;
	struct reset_info reset_info;
	int	reset_kstats_ok;	/* kstat read OK */
	struct bd_kstat_data bd_ksp_list[MAX_BOARDS];
	struct hp_info hp_info[MAX_BOARDS];
	struct ft_list *ft_array;	/* fault array */
	int	nfaults;		/* number of faults in fault array */
	int	ft_kstat_ok;		/* Fault kstats OK */
	struct envctrl_kstat_data env_data;  /* environment data for Tazmo */
	int	envctrl_kstat_ok;
	struct envctrltwo_kstat_data envc_data;  /* environ data for Javelin */
	int	envctrltwo_kstat_ok;
};

/* Description of a single memory group */
struct grp {
	int valid;			/* active memory group present */
	u_longlong_t  base;		/* Phyiscal base of group */
	uint_t size;			/* size in bytes */
	uint_t curr_size;		/* current size in bytes */
	int board;			/* board number */
	enum board_type type;		/* board type */
	int group;			/* group # on board (0 or 1) */
	int factor;			/* interleave factor (0,2,4,8,16) */
	int speed;			/* Memory speed (in ns) */
	char groupid;			/* Alpha tag for group ID */
	enum ac_bank_status status;	/* bank status values */
	enum ac_bank_condition condition;	/* bank conditions */
};

#define	MAX_GROUPS	32
#define	MAXSTRLEN	256

/* Array of all possible groups in the system. */
struct grp_info {
	struct grp grp[MAX_GROUPS];
};

/* A memory interleave structure */
struct inter_grp {
	u_longlong_t base;	/* Physical base of group */
	int valid;
	int count;
	char groupid;
};

/* Array of all possible memory interleave structures */
struct mem_inter {
	struct inter_grp i_grp[MAX_GROUPS];
};

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
