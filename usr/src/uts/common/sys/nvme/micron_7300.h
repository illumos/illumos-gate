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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _SYS_NVME_MICRON_7300_H
#define	_SYS_NVME_MICRON_7300_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This header contains all of the current vendor-specific entries for known
 * Micron devices as well as common structures and definitions that are shared
 * across multiple device families.
 */

#include <sys/debug.h>
#include <sys/stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MICRON_7300_PRO_DID	0x51a2
#define	MICRON_7300_MAX_DID	0x51a3

typedef enum {
	/*
	 * This log is supported by the [79]300, though when supported, the
	 * extended SMART log is preferred.
	 */
	MICRON_7300_LOG_SMART		= 0xca,
	/*
	 * This log is the micron_vul_ext_smart_t.
	 */
	MICRON_7300_LOG_EXT_SMART	= 0xd0
} micron_7300_vul_t;

/*
 * All data structures must be packed to account for the layout from the various
 * programmer's manuals.
 */
#pragma pack(1)

/*
 * The Micron vendor-unique SMART log (0xca) is formed in terms of these data
 * entities that all have a fixed size. The type value tells you what it is
 * supposed to be (though the log has a fixed layout). The data payload
 * interpretation varies based on the type.
 */
typedef struct {
	uint8_t vse_type;
	uint8_t vse_rsvd[4];
	uint8_t vse_data[7];
} micron_vul_smart_ent_t;

typedef struct {
	micron_vul_smart_ent_t ms_writes;
	micron_vul_smart_ent_t ms_reads;
	micron_vul_smart_ent_t ms_throttle;
	micron_vul_smart_ent_t ms_life_temp;
	micron_vul_smart_ent_t ms_power;
	micron_vul_smart_ent_t ms_poweron_temp;
} micron_vul_smart_t;

CTASSERT(sizeof (micron_vul_smart_t) == 0x48);

#pragma	pack()	/* pack(1) */


#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_MICRON_7300_H */
