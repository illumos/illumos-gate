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
 * Copyright 2024 Oxide Computer company
 */

#ifndef _SYS_NVME_SOLIDIGM_H
#define	_SYS_NVME_SOLIDIGM_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This header contains all of the current vendor-specific entries for supported
 * Solidigm devices as well as common structures and definitions that are shared
 * across multiple device families. This also contains the Intel variants as
 * these devices have been rebranded over time and therefore works as a
 * reasonable consolidation point for the Intel branded devices too.
 */

#include <sys/nvme/solidigm_p5xxx.h>
#include <sys/nvme/solidigm_ps10x0.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	INTEL_PCI_VID		0x8086
#define	SOLIDIGM_PCI_VID	0x25e

/*
 * All data structures must be packed to account for the layout from the various
 * programmer's manuals.
 */
#pragma pack(1)

/*
 * This represents a single entry which is used as part of the device-specific
 * SMART log (generally opcode 0xca).
 */
typedef struct {
	uint8_t sse_type;
	uint8_t sse_rsvd2[2];
	uint8_t sse_norm;
	uint8_t sse_rsvd4;
	uint8_t sse_raw[6];
	uint8_t sse_rsvd11;
} solidigm_smart_ent_t;

/*
 * These are the different type keys that exist for the solidigm_smart_ent_t
 * above. These will show up in an arbitrary order in the device log.
 */
typedef enum {
	SOLIDIGM_SMART_TYPE_PROGRAM_FAIL	= 0xab,
	SOLIDIGM_SMART_TYPE_ERASE_FAIL		= 0xac,
	SOLIDIGM_SMART_TYPE_WEAR_LEVEL		= 0xad,
	SOLIDIGM_SMART_TYPE_E2E_ERROR_DET	= 0xb8,
	SOLIDIGM_SMART_TYPE_CRC_ERROR		= 0xc7,
	SOLIDIGM_SMART_TYPE_TIMED_MEDIA_WEAR	= 0xe2,
	SOLIDIGM_SMART_TYPE_TIMED_HOST_READ	= 0xe3,
	SOLIDIGM_SMART_TYPE_TIMED_TIMER		= 0xe4,
	SOLIDIGM_SMART_TYPE_IN_FLIGHT_READ	= 0xe5,
	SOLIDIGM_SMART_TYPE_IN_FLIGHT_WRITE	= 0xe6,
	SOLIDIGM_SMART_TYPE_THERM_THROTTLE	= 0xea,
	SOLIDIGM_SMART_TYPE_RESKU		= 0xee,
	SOLIDIGM_SMART_TYPE_RETRY_BUF_OVRFLW	= 0xf0,
	SOLIDIGM_SMART_TYPE_PLL_LOSS		= 0xf3,
	SOLIDIGM_SMART_TYPE_NAND_WRITE		= 0xf4,
	SOLIDIGM_SMART_TYPE_HOST_WRITE		= 0xf5,
	SOLIDIGM_SMART_TYPE_SYS_LIFE		= 0xf6,
	SOLIDIGM_SMART_TYPE_NAND_READ		= 0xf8,
	SOLIDIGM_SMART_TYPE_AVAIL_FW_DOWN	= 0xf9,
	SOLIDIGM_SMART_TYPE_READ_COLL		= 0xfa,
	SOLIDIGM_SMART_TYPE_WRITE_COLL		= 0xfb,
	SOLIDIGM_SMART_TYPE_XOR_PASS		= 0xfc,
	SOLIDIGM_SMART_TYPE_XOR_FAIL		= 0xfd,
	SOLIDIGM_SMART_TYPE_XOR_INVOKE		= 0xfe,
} solidigm_smart_type_t;

/*
 * We size this based on the number of items that'll fit into a single 512 byte
 * log page.
 */
typedef struct {
	solidigm_smart_ent_t vsl_data[512 / sizeof (solidigm_smart_ent_t)];
} solidigm_vul_smart_log_t;

/*
 * Common temperature structure across different device generations.
 * Temperatures are all measured in units of degrees C.
 */
typedef struct {
	uint64_t temp_cur;
	uint64_t temp_over_last;
	uint64_t temp_over_life;
	uint64_t temp_comp_life_high;
	uint64_t temp_comp_life_low;
	uint8_t temp_rsvd40[40];
	uint64_t temp_norm_max_warn;
	uint8_t temp_rsvd88[8];
	uint64_t temp_spec_min_op;
	uint64_t temp_est_off;
} solidigm_vul_temp_t;

#pragma	pack()	/* pack(1) */

/*
 * Our current version of smatch cannot handle packed structures.
 */
#ifndef __CHECKER__
CTASSERT(sizeof (solidigm_smart_ent_t) == 12);
CTASSERT(sizeof (solidigm_vul_smart_log_t) <= 512);
CTASSERT(sizeof (solidigm_vul_smart_log_t) > 500);
CTASSERT(sizeof (solidigm_vul_temp_t) == 112);
#endif	/* __CHECKER__ */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_SOLIDIGM_H */
