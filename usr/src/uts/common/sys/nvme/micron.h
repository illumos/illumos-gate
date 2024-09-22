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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_NVME_MICRON_H
#define	_SYS_NVME_MICRON_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This header contains all of the current vendor-specific entries for known
 * Micron devices as well as common structures and definitions that are shared
 * across multiple device families.
 */

#include <sys/nvme/micron_7300.h>
#include <sys/nvme/micron_74x0.h>
#include <sys/nvme/micron_x500.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MICRON_PCI_VID	0x1344

/*
 * All data structures must be packed to account for the layout from the various
 * programmer's manuals.
 */
#pragma pack(1)

/*
 * Micron has a common extended SMART log that is used between multiple device
 * families. Some fields have been added in newer device generations and they
 * are reserved otherwise. Starting in the 6500/7500+ generation, the structure
 * was extended in size and is defined in its device-specific section.
 */
typedef struct {
	uint8_t mes_rsvd0[12];
	uint32_t mes_gbb;
	uint32_t mes_max_erase;
	uint32_t mes_power_on;
	uint8_t mes_rsvd24[24];
	uint32_t mes_wp_reason;
	uint8_t mes_rsvd52[12];
	uint64_t mes_cap;
	uint8_t mes_rsvd72[8];
	uint64_t mes_erase_count;
	uint64_t mes_use_rate;
	/*
	 * Begin 7400+ specific fields.
	 */
	uint64_t mes_erase_fail;
	uint8_t mes_rsvd104[8];
	uint64_t mes_uecc;
	uint8_t mes_rsvd120[24];
	uint8_t mes_prog_fail[16];
	uint8_t mes_read_bytes[16];
	uint8_t mes_write_bytes[16];
	uint8_t mes_rsvd192[16];
	/*
	 * End 7400+ specific fields.
	 */
	uint32_t mes_trans_size;
	uint32_t mes_bs_total;
	uint32_t mes_bs_free;
	uint64_t mes_bs_cap;
	uint8_t mes_rsvd228[16];
	uint32_t mes_user_erase_min;
	uint32_t mes_user_erase_avg;
	uint32_t mes_user_erase_max;
} micron_vul_ext_smart_t;

typedef enum {
	MICRON_VUL_WP_R_DRAM_DOUBLE_BIT		= 1 << 0,
	MICRON_VUL_WP_R_LOW_SPARE_BLOCKS	= 1 << 1,
	MICRON_VUL_WP_R_CAP_FAILURE		= 1 << 2,
	MICRON_VUL_WP_R_NVRAM_CKSUM		= 1 << 3,
	MICRON_VUL_WP_R_DRAM_RANGE		= 1 << 4,
	MICRON_VUL_WP_R_OVERTEMP		= 1 << 5
} micron_vul_wp_reason_t;

/*
 * Smatch can't handle packed structure sizeof calculations correctly,
 * unfortunately.
 */
#ifndef __CHECKER__
CTASSERT(sizeof (micron_vul_ext_smart_t) == 0x100);
#endif

#pragma	pack()	/* pack(1) */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_MICRON_H */
