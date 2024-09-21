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

#ifndef _SYS_NVME_KIOXIA_CD8_H
#define	_SYS_NVME_KIOXIA_CD8_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * Vendor-specific definitions for the Kioxia CD8 and CD8P.
 */

#include <sys/debug.h>
#include <sys/nvme/ocp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	KIOXIA_CD8_DID	0x1f
#define	KIOXIA_CD8P_DID	0x2b

typedef enum {
	KIOXIA_CD8_LOG_OCP_SMART	= OCP_LOG_DSSD_SMART,
	KIOXIA_CD8_LOG_OCP_ERRREC	= OCP_LOG_DSSD_ERROR_REC,
	KIOXIA_CD8_LOG_OCP_FWACT	= OCP_LOG_DSSD_FWACT,
	KIOXIA_CD8_LOG_OCP_LATENCY	= OCP_LOG_DSSD_LATENCY,
	KIOXIA_CD8_LOG_OCP_DEV_CAP	= OCP_LOG_DSSD_DEV_CAP,
	KIOXIA_CD8_LOG_OCP_UNSUP	= OCP_LOG_DSSD_UNSUP_REQ,
	/*
	 * Uses the kioxia_vul_cd8_extsmart_t.
	 */
	KIOXIA_CD8_LOG_EXTSMART	= 0xca
} kioxia_cd8_vul_t;

/*
 * All data structures must be packed to account for the layout from the various
 * programmer's manuals.
 */
#pragma pack(1)
typedef struct {
	uint8_t kes_id;
	uint8_t kes_rsvd1[2];
	uint8_t kse_norm;
	uint8_t kes_rsvd4;
	uint8_t kse_raw[6];
	uint8_t kse_rsvd11;
} kioxia_extsmart_ent_t;

/*
 * These are the different type keys that exist for the kioxia_extsmart_ent_t
 * above. Note, entries in the latter part of the log just use zero keys.
 */
typedef enum {
	SOLIDIGM_SMART_TYPE_PROGRAM_FAIL	= 0xab,
	SOLIDIGM_SMART_TYPE_ERASE_FAIL		= 0xac,
	SOLIDIGM_SMART_TYPE_WEAR_LEVEL		= 0xad,
	SOLIDIGM_SMART_TYPE_E2E_ERROR_DET	= 0xb8,
	SOLIDIGM_SMART_TYPE_CRC_ERROR		= 0xc7,
	SOLIDIGM_SMART_TYPE_NAND_WRITE		= 0xf4,
	SOLIDIGM_SMART_TYPE_HOST_WRITE		= 0xf5
} solidigm_smart_type_t;


typedef struct {
	kioxia_extsmart_ent_t cds_prog_fail;
	kioxia_extsmart_ent_t cds_erase_fail;
	kioxia_extsmart_ent_t cds_wear_level;
	kioxia_extsmart_ent_t cds_e2e_det;
	kioxia_extsmart_ent_t cds_crc_error;
	uint8_t cds_rvsd60[132 - 60];
	kioxia_extsmart_ent_t cds_nand_write;
	kioxia_extsmart_ent_t cds_host_write;
	uint8_t cds_rsvd156[256 - 156];
	kioxia_extsmart_ent_t cds_crit_warn;
	kioxia_extsmart_ent_t cds_host_read;
	kioxia_extsmart_ent_t cds_comp_temp;
	kioxia_extsmart_ent_t cds_life_used;
	kioxia_extsmart_ent_t cds_power_cycles;
	kioxia_extsmart_ent_t cds_power_hours;
	kioxia_extsmart_ent_t cds_unsafe_shut;
	uint8_t cds_rsvd340[512 - 340];
} kioxia_vul_cd8_smart_t;
#pragma	pack()	/* pack(1) */
/*
 * Our current version of smatch cannot handle packed structures.
 */
#ifndef __CHECKER__
CTASSERT(sizeof (kioxia_extsmart_ent_t) == 12);
CTASSERT(sizeof (kioxia_vul_cd8_smart_t) == 512);
#endif	/* __CHECKER__ */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_KIOXIA_CD8_H */
