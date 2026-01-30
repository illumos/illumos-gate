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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _SYS_NVME_SOLIDIGM_P5XXX_H
#define	_SYS_NVME_SOLIDIGM_P5XXX_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * Vendor-specific definitions for the Intel/Solidigm 5000 series devices
 * including the P5510, P5520, and P5620. Note, these device all share a PCI ID
 * and must be disambiguated by their subsystem IDs. Logs fall into three
 * buckets:
 *
 * 1) Those unique to the P5510. These are prefixed with INTEL_P5510.
 * 2) Those that are shared between the P5510 and the P5[56]20. These are
 *    prefixed with SOLIDIGM_P5XXX. All logs in this case use the same data
 *    structure. Some logs have data structures shared across all devices and
 *    are in the top-level <sys/nvme/solidigm.h> header.
 * 3) Logs which are only supported by the P5520/P5620. These are prefixed with
 *    SOLIDIGM_P5X20.
 */

#include <sys/stdint.h>
#include <sys/debug.h>
#include <sys/stddef.h>

#include <sys/nvme/ocp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The device ID isn't enough to distinguish these different devices and
 * therefore we need to use the subsystem IDs as well. The 5510 only shows up
 * with an Intel vendor ID; however, the 5520 and 5620 show up with both a
 * Solidigm and Intel device ID.
 */
#define	SOLIDIGM_P5XXX_DID	0xb60
#define	SOLIDIGM_P5510_U2_SDID	0x8008
#define	SOLIDIGM_P5520_U2_SDID	0x9008
#define	SOLIDIGM_P5520_E1S_9P5MM_SDID	0x900c
#define	SOLIDIGM_P5520_E1S_15MM_SDID	0x900d
#define	SOLIDIGM_P5520_E1L_SDID	0x901c
#define	SOLIDIGM_P5620_U2_SDID	0x9108

typedef enum {
	/*
	 * This is a log specific to the P5510 which contains a directory of the
	 * other log pages that are present. This is a 512 byte log page with a
	 * leading version and then information about vendor specific logs
	 * support at an offset of 2x log page. This is here for completeness
	 * sake.
	 */
	INTEL_P5510_LOG_DIR		= 0xc0,
	/*
	 * The P5520 and P5620 use 0xc0 as the OCP SMART log, which is different
	 * from the P5510.
	 */
	SOLIDIGM_P5X20_LOG_OCP_SMART	= OCP_LOG_DSSD_SMART,
	/*
	 * The next two logs are used to contain read and write command latency
	 * statistics. For these to have useful content, the device must be
	 * explicitly told to perform tracking with a vendor-specific feature.
	 * Uses the solidigm_vul_p5xxx_lat_t structure.
	 */
	SOLIDIGM_P5XXX_LOG_READ_LAT	= 0xc1,
	SOLIDIGM_P5XXX_LOG_WRITE_LAT	= 0xc2,
	/*
	 * Uses the solidigm_vul_temp_t.
	 */
	SOLIDIGM_P5XXX_LOG_TEMP		= 0xc5,
	/*
	 * Uses the solidigm_vul_smart_log_t. The maximum number of entires is
	 * always grabbed, but there may be holes.
	 */
	SOLIDIGM_P5XXX_LOG_SMART	= 0xca,
	/*
	 * Uses the solidigm_vul_p5xxx_ioq_t.
	 */
	SOLIDIGM_P5XXX_LOG_IO_QUEUE	= 0xcb,
	/*
	 * This should be treated as a 512 byte log with an ASCII string encoded
	 * in it. However, don't assume hardware only outputs ASCII.
	 */
	SOLIDIGM_P5XXX_LOG_MARK_DESC	= 0xdd,
	/*
	 * Uses the solidigm_vul_temp_t.
	 */
	SOLIDIGM_P5X20_LOG_POWER	= 0xf2,
	/*
	 * Uses solidigm_vul_p5xxx_gc_t.
	 */
	SOLIDIGM_P5XXX_LOG_GC		= 0xfd,
	/*
	 * Uses solidigm_vul_p5xxx_lat_outlier_t.
	 */
	SOLIDIGM_P5XXX_LOG_OUTLIER	= 0xfe,
} solidigm_p5xxx_vul_t;

/*
 * All data structures must be packed to account for the layout from the various
 * programmer's manuals.
 */
#pragma pack(1)

/*
 * This log page is used for the read and write latency commands. These are
 * organized into groups of 4 byte buckets. Each bucket has a range and a given
 * step. For example, lat_63_127us_1us is latency in the range [63us, 127us)
 * with the bucket width as the last parameter.
 */
typedef struct {
	uint16_t lat_maj;
	uint16_t lat_minor;
	uint32_t lat_0_63us_1us[64];
	uint32_t lat_63_127us_1us[64];
	uint32_t lat_127_255us_2us[64];
	uint32_t lat_255_510us_4us[64];
	uint32_t lat_510_1p02ms_8us[64];
	uint32_t lat_1p02_2p04ms_16us[64];
	uint32_t lat_2p04_4p08ms_32us[64];
	uint32_t lat_4p08_8p16ms_64us[64];
	uint32_t lat_8p16_16p32ms_128us[64];
	uint32_t lat_16p32_32p64ms_256us[64];
	uint32_t lat_32p64_65p28ms_512us[64];
	uint32_t lat_65p28_130p56ms_1p024ms[64];
	uint32_t lat_130p56_256p12ms_2p048ms[64];
	uint32_t lat_251p12_522p25ms_4p096ms[64];
	uint32_t lat_522p24ms_1p04s_8p192ms[64];
	uint32_t lat_1p04_2p09s_16p384ms[64];
	uint32_t lat_2p09_4p18s_32p768ms[64];
	uint32_t lat_4p18_8p36s_65p536ms[64];
	uint32_t lat_8p36_16p72s_131p072ms[64];
	uint8_t lat_avg[8];
} solidigm_vul_p5xxx_lat_t;

typedef struct {
	uint16_t	iosq_id;
	uint16_t	iosq_iocq_id;
	uint16_t	iosq_head;
	uint16_t	iosq_tail;
	uint16_t	iosq_out;
	uint16_t	iosq_max_qdepth;
} solidigm_vul_iosq_t;

typedef struct {
	uint16_t	iocq_id;
	uint16_t	iocq_head;
	uint8_t		iocq_rsvd4[6];
} solidigm_vul_iocq_t;

#define	SOLIDIGM_VUL_MAX_QUEUES	32

typedef struct {
	uint16_t		ioq_vers;
	uint16_t		ioq_niosq;
	uint16_t		ioq_niocq;
	solidigm_vul_iosq_t	ioq_iosq[SOLIDIGM_VUL_MAX_QUEUES];
	solidigm_vul_iocq_t	ioq_iocq[SOLIDIGM_VUL_MAX_QUEUES];
	uint8_t			ioq_rsvd710[314];
} solidigm_vul_p5xxx_ioq_t;

/*
 * All values are in in the power measurement log are in uW.
 */
typedef struct {
	uint32_t	pow_vin1;
	uint32_t	pow_vin2;
} solidigm_vul_p5x2x_power_t;

/*
 * This is the size we recommend one obtain while reading the marketing name log
 * page.
 */
#define	SOLIDIGM_VUC_MARK_NAME_LEN	512

typedef struct {
	uint32_t	gce_type;
	uint64_t	gce_ts;
} solidigm_vul_gc_ent_t;

#define	SOLIDIGM_VUC_MAX_GC	100

typedef struct {
	uint16_t	gc_major;
	uint16_t	gc_minor;
	solidigm_vul_gc_ent_t	gc_ents[SOLIDIGM_VUC_MAX_GC];
} solidigm_vul_p5xxx_gc_t;

typedef struct {
	uint64_t	le_ts;
	uint32_t	le_cmd;
	uint32_t	le_lat_us;
	uint64_t	le_lba;
} soligm_vul_lat_ent_t;

typedef struct {
	uint16_t		lao_major;
	uint16_t		lao_minor;
	uint8_t			lao_rsvd[4];
	uint64_t		lao_nents;
	soligm_vul_lat_ent_t	lao_ents[];
} solidigm_vul_p5xxx_lat_outlier_t;

#pragma	pack()	/* pack(1) */

/*
 * Our current version of smatch cannot handle packed structures.
 */
#ifndef __CHECKER__
CTASSERT(sizeof (solidigm_vul_p5xxx_lat_t) == 4876);
CTASSERT(offsetof(solidigm_vul_p5xxx_lat_t, lat_4p18_8p36s_65p536ms) == 4356);
CTASSERT(sizeof (solidigm_vul_iosq_t) == 12);
CTASSERT(sizeof (solidigm_vul_iocq_t) == 10);
CTASSERT(offsetof(solidigm_vul_p5xxx_ioq_t, ioq_iocq) == 390);
CTASSERT(offsetof(solidigm_vul_p5xxx_ioq_t, ioq_rsvd710) == 710);
CTASSERT(sizeof (solidigm_vul_p5xxx_ioq_t) == 1024);
CTASSERT(sizeof (solidigm_vul_p5x2x_power_t) == 8);
CTASSERT(sizeof (solidigm_vul_gc_ent_t) == 12);
CTASSERT(sizeof (solidigm_vul_p5xxx_gc_t) == 1204);
#endif	/* __CHECKER__ */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_SOLIDIGM_P5XXX_H */
