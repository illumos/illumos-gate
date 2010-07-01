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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/atomic.h>
#include <sys/conf.h>
#include <sys/byteorder.h>
#include <sys/scsi/scsi_types.h>
#include <sys/scsi/generic/persist.h>

#include <sys/lpif.h>
#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/stmf_sbd_ioctl.h>

#include "stmf_sbd.h"
#include "sbd_impl.h"

#define	MAX_PGR_PARAM_LIST_LENGTH	(256 * 1024)

int  sbd_pgr_reservation_conflict(scsi_task_t *);
void sbd_pgr_reset(sbd_lu_t *);
void sbd_pgr_initialize_it(scsi_task_t *, sbd_it_data_t *);
void sbd_handle_pgr_in_cmd(scsi_task_t *, stmf_data_buf_t *);
void sbd_handle_pgr_out_cmd(scsi_task_t *, stmf_data_buf_t *);
void sbd_handle_pgr_out_data(scsi_task_t *, stmf_data_buf_t *);
void sbd_pgr_keylist_dealloc(sbd_lu_t *);
char *sbd_get_devid_string(sbd_lu_t *);

sbd_status_t sbd_pgr_meta_init(sbd_lu_t *);
sbd_status_t sbd_pgr_meta_load(sbd_lu_t *);
sbd_status_t sbd_pgr_meta_write(sbd_lu_t *);
static void sbd_swap_pgr_info(sbd_pgr_info_t *);
static void sbd_swap_pgrkey_info(sbd_pgr_key_info_t *);
static void sbd_pgr_key_free(sbd_pgr_key_t *);
static void sbd_pgr_remove_key(sbd_lu_t *, sbd_pgr_key_t *);
static uint32_t sbd_pgr_remove_keys(sbd_lu_t *, sbd_it_data_t *,
	sbd_pgr_key_t *, uint64_t, boolean_t);
static boolean_t sbd_pgr_key_compare(sbd_pgr_key_t *, scsi_devid_desc_t *,
	stmf_remote_port_t *);
static sbd_pgr_key_t *sbd_pgr_key_alloc(scsi_devid_desc_t *,
	scsi_transport_id_t *, int16_t, int16_t);

static void sbd_pgr_set_pgr_check_flag(sbd_lu_t *, boolean_t);
static void sbd_pgr_set_ua_conditions(sbd_lu_t *, sbd_it_data_t *, uint8_t);
static void sbd_pgr_in_read_keys(scsi_task_t *, stmf_data_buf_t *);
static void sbd_pgr_in_report_capabilities(scsi_task_t *, stmf_data_buf_t *);
static void sbd_pgr_in_read_reservation(scsi_task_t *, stmf_data_buf_t *);
static void sbd_pgr_in_read_full_status(scsi_task_t *, stmf_data_buf_t *);
static void sbd_pgr_out_register(scsi_task_t *, stmf_data_buf_t *);
static void sbd_pgr_out_reserve(scsi_task_t *);
static void sbd_pgr_out_release(scsi_task_t *);
static void sbd_pgr_out_clear(scsi_task_t *);
static void sbd_pgr_out_preempt(scsi_task_t *, stmf_data_buf_t *);
static void sbd_pgr_out_register_and_move(scsi_task_t *, stmf_data_buf_t *);

static sbd_pgr_key_t *sbd_pgr_do_register(sbd_lu_t *, sbd_it_data_t *,
	scsi_devid_desc_t *, stmf_remote_port_t *, uint8_t, uint64_t);
static void sbd_pgr_do_unregister(sbd_lu_t *, sbd_it_data_t *, sbd_pgr_key_t *);
static void sbd_pgr_do_release(sbd_lu_t *, sbd_it_data_t *, uint8_t);
static void sbd_pgr_do_reserve(sbd_pgr_t *, sbd_pgr_key_t *, sbd_it_data_t *it,
	stmf_scsi_session_t *, scsi_cdb_prout_t *);

extern sbd_status_t sbd_write_meta_section(sbd_lu_t *, sm_section_hdr_t *);
extern sbd_status_t sbd_read_meta_section(sbd_lu_t *, sm_section_hdr_t **,
	uint16_t);
extern void sbd_swap_section_hdr(sm_section_hdr_t *);
extern void sbd_handle_short_write_transfers(scsi_task_t *task,
	stmf_data_buf_t *dbuf, uint32_t cdb_xfer_size);
extern void sbd_handle_short_read_transfers(scsi_task_t *task,
	stmf_data_buf_t *dbuf, uint8_t *p, uint32_t cdb_xfer_size,
	uint32_t cmd_xfer_size);
extern uint16_t stmf_scsilib_get_lport_rtid(scsi_devid_desc_t *devid);
extern scsi_devid_desc_t *stmf_scsilib_get_devid_desc(uint16_t rtpid);
extern char sbd_ctoi(char c);

/*
 *
 *
 *   +-----------+
 *   |           |sl_it_list
 *   |           |---------------------------------------+
 *   |           |                                       |
 *   |  sbd_lu_t |                                       |
 *   |           |                                       |
 *   |           |                                       |
 *   |           |                                       |
 *   +-----+-----+                                       V
 *         |                                          +-------+
 *         V                                          |       |
 *   +-----------+ pgr_key_list               +------>|       |
 *   |           |------------+  +-->(NULL)   | +- ---|sbd_it |
 *   |           |            |  |            | |     | _data |
 *   | sbd_pgr_t |            V  |            | |     |       |
 *   |           |          +-------+         | |     +-------+
 *   |           |---+      |       |         | |         |
 *   |           |   |      |sbd_pgr|---------+ |         v
 *   +-----------+   |      | _key_t|<----------+     +-------+
 *                   |      |       |                 |       |
 *                   |      |       |                 |       |
 *                   |      +-------+        +--------|       |
 *                   |         |^            |        |       |
 *                   |         ||            |        |       |
 *                   |         v|            |        +-------+
 *                   |      +-------+        |            |
 *                   |      |       |        |            v
 *                   |      |ALL_TG_|<-------+        +-------+
 *                   |      |PT = 1 |<---------+      |       |
 *                   |      |       |---+      |      |       |
 *                   |      |       |   |      +------|       |
 *          (pgr_rsvholder  +-------+   V             |       |
 *             pgr_flags&      |^     (NUll)          |       |
 *              RSVD_ONE)      ||                     +-------+
 *                   |         v|                         |
 *                   |      +-------+                     v
 *                   |      |       |                 +-------+
 *                   |      |  not  |                 |       |
 *                   |      |claimed|---+             |       |
 *                   |      |       |   |        +----| unreg |
 *                   |      |       |   V        |    |       |
 *                   |      +-------+ (NUll)     V    |       |
 *                   |         |^              (NUll) +-------+
 *                   |         ||                         |
 *                   |         v|                         v
 *                   |      +-------+                 +-------+
 *                   |      |       |                 |       |
 *                   |      |reserv-|<----------------|       |
 *                   +----->|  ation|---------------->|       |
 *                          |holder |                 |       |
 *                          |key    |                 |       |
 *                          +-------+                 +-------+
 *                              |^                        |
 *                              ||                        v
 *                              v|                    +-------+
 *                           +-------+                |       |
 *                           |       |                |       |
 *                           |  not  |---+       +----| unreg |
 *                           |claimed|   |       |    |       |
 *                           |       |   V       V    |       |
 *                           |       | (NUll)  (NUll) +-------+
 *                           +-------+                    |
 *                              |                         v
 *                              v                      (NULL)
 *                           (NULL)
 *
 *
 */

#define	PGR_CONFLICT_FREE_CMDS(cdb)	( \
	/* ----------------------- */                                      \
	/* SPC-3 (rev 23) Table 31 */                                      \
	/* ----------------------- */                                      \
	((cdb[0]) == SCMD_INQUIRY)					|| \
	((cdb[0]) == SCMD_LOG_SENSE_G1)					|| \
	((cdb[0]) == SCMD_PERSISTENT_RESERVE_IN)			|| \
	((cdb[0]) == SCMD_REPORT_LUNS)					|| \
	((cdb[0]) == SCMD_REQUEST_SENSE)				|| \
	((cdb[0]) == SCMD_TEST_UNIT_READY)				|| \
	/* PREVENT ALLOW MEDIUM REMOVAL with prevent == 0 */               \
	((((cdb[0]) == SCMD_DOORLOCK) && (((cdb[4]) & 0x3) == 0)))	|| \
	/* SERVICE ACTION IN with READ MEDIA SERIAL NUMBER (0x01) */       \
	(((cdb[0]) == SCMD_SVC_ACTION_IN_G5) && (                          \
	    ((cdb[1]) & 0x1F) == 0x01))					|| \
	/* MAINTENANCE IN with service actions REPORT ALIASES (0x0Bh) */   \
	/* REPORT DEVICE IDENTIFIER (0x05)  REPORT PRIORITY (0x0Eh) */     \
	/* REPORT TARGET PORT GROUPS (0x0A) REPORT TIMESTAMP (0x0F) */     \
	(((cdb[0]) == SCMD_MAINTENANCE_IN) && (                            \
	    (((cdb[1]) & 0x1F) == 0x0B) ||                                 \
	    (((cdb[1]) & 0x1F) == 0x05) ||                                 \
	    (((cdb[1]) & 0x1F) == 0x0E) ||                                 \
	    (((cdb[1]) & 0x1F) == 0x0A) ||                                 \
	    (((cdb[1]) & 0x1F) == 0x0F)))				|| \
	/* REGISTER and REGISTER_AND_IGNORE_EXISTING_KEY */                \
	/* actions for PERSISTENT RESERVE OUT command */                   \
	(((cdb[0]) == SCMD_PERSISTENT_RESERVE_OUT) && (                    \
	    (((cdb[1]) & 0x1F) == PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY) || \
	    (((cdb[1]) & 0x1F) == PR_OUT_REGISTER))) 			|| \
	/* ----------------------- */                                      \
	/* SBC-3 (rev 17) Table 3  */                                      \
	/* ----------------------- */                                      \
	/* READ CAPACITY(10) */                                            \
	((cdb[0]) == SCMD_READ_CAPACITY)				|| \
	/* READ CAPACITY(16) */                                            \
	(((cdb[0]) == SCMD_SVC_ACTION_IN_G4) && (                          \
	    ((cdb[1]) & 0x1F) == 0x10))					|| \
	/* START STOP UNIT with START bit 0 and POWER CONDITION 0  */      \
	(((cdb[0]) == SCMD_START_STOP) && (                                \
	    (((cdb[4]) & 0xF0) == 0) && (((cdb[4]) & 0x01) == 0))))
/* End of PGR_CONFLICT_FREE_CMDS */

/* Commands allowed for registered IT nexues but not reservation holder */
#define	PGR_REGISTERED_POSSIBLE_CMDS(cdb)	( \
	(((cdb[0]) == SCMD_PERSISTENT_RESERVE_OUT) && (                \
	    (((cdb[1]) & 0x1F) == PR_OUT_RELEASE)		||     \
	    (((cdb[1]) & 0x1F) == PR_OUT_CLEAR)			||     \
	    (((cdb[1]) & 0x1F) == PR_OUT_PREEMPT)		||     \
	    (((cdb[1]) & 0x1F) == PR_OUT_PREEMPT_ABORT))))

/* List of commands allowed when WR_EX type reservation held */
#define	PGR_READ_POSSIBLE_CMDS(c)	(  \
	((c) == SCMD_READ)		|| \
	((c) == SCMD_READ_G1)		|| \
	((c) == SCMD_READ_G4)		|| \
	((c) == SCMD_READ_G5)		|| \
	/* READ FETCH (10) (16) */         \
	((c) == SCMD_READ_POSITION)	|| \
	((c) == 0x90)			|| \
	/* READ DEFECT DATA */             \
	((c) == SCMD_READ_DEFECT_LIST)	|| \
	((c) == 0xB7)			|| \
	/* VERIFY (10) (16) (12) */        \
	((c) == SCMD_VERIFY)		|| \
	((c) == SCMD_VERIFY_G4)		|| \
	((c) == SCMD_VERIFY_G5)		|| \
	/* XDREAD (10) */                  \
	((c) == 0x52))

#define	PGR_RESERVATION_HOLDER(pgr, key, it)	( \
	((pgr)->pgr_flags & SBD_PGR_RSVD_ALL_REGISTRANTS) || ( \
	    ((pgr)->pgr_rsvholder) && ((pgr)->pgr_rsvholder == (key)) && \
	    ((key)->pgr_key_it) && ((key)->pgr_key_it == (it))))

#define	PGR_SET_FLAG(flg, val)		(atomic_or_8(&(flg), (val)))
#define	PGR_CLEAR_FLAG(flg, val)	(atomic_and_8(&(flg), ~(val)))
#define	PGR_CLEAR_RSV_FLAG(flg)		(atomic_and_8(&(flg), \
	(~(SBD_PGR_RSVD_ALL_REGISTRANTS | SBD_PGR_RSVD_ONE))))

#define	PGR_VALID_SCOPE(scope)	((scope) == PR_LU_SCOPE)
#define	PGR_VALID_TYPE(type)	( \
				((type) == PGR_TYPE_WR_EX)	|| \
				((type) == PGR_TYPE_EX_AC)	|| \
				((type) == PGR_TYPE_WR_EX_RO)	|| \
				((type) == PGR_TYPE_EX_AC_RO)	|| \
				((type) == PGR_TYPE_WR_EX_AR)	|| \
				((type) == PGR_TYPE_EX_AC_AR))

#define	ALIGNED_TO_8BYTE_BOUNDARY(i)	(((i) + 7) & ~7)

static void
sbd_swap_pgr_info(sbd_pgr_info_t *spi)
{
	sbd_swap_section_hdr(&spi->pgr_sms_header);
	if (spi->pgr_data_order == SMS_DATA_ORDER)
		return;
	spi->pgr_sms_header.sms_chksum += SMS_DATA_ORDER - spi->pgr_data_order;
	spi->pgr_rsvholder_indx		= BSWAP_32(spi->pgr_rsvholder_indx);
	spi->pgr_numkeys		= BSWAP_32(spi->pgr_numkeys);
}

static void
sbd_swap_pgrkey_info(sbd_pgr_key_info_t *key)
{
	key->pgr_key			= BSWAP_64(key->pgr_key);
	key->pgr_key_lpt_len		= BSWAP_16(key->pgr_key_lpt_len);
	key->pgr_key_rpt_len		= BSWAP_16(key->pgr_key_rpt_len);
}

sbd_status_t
sbd_pgr_meta_init(sbd_lu_t *slu)
{
	sbd_pgr_info_t	*spi = NULL;
	uint32_t 	sz;
	sbd_status_t	ret;

	sz = sizeof (sbd_pgr_info_t);
	spi = (sbd_pgr_info_t *)kmem_zalloc(sz, KM_SLEEP);
	spi->pgr_data_order = SMS_DATA_ORDER;
	spi->pgr_sms_header.sms_size = sz;
	spi->pgr_sms_header.sms_id = SMS_ID_PGR_INFO;
	spi->pgr_sms_header.sms_data_order = SMS_DATA_ORDER;

	ret = sbd_write_meta_section(slu, (sm_section_hdr_t *)spi);
	kmem_free(spi, sz);
	return (ret);
}

sbd_status_t
sbd_pgr_meta_load(sbd_lu_t *slu)
{
	sbd_pgr_t		*pgr = slu->sl_pgr;
	sbd_pgr_info_t		*spi = NULL;
	sbd_pgr_key_t		*key, *last_key = NULL;
	sbd_pgr_key_info_t	*spi_key;
	sbd_status_t		ret = SBD_SUCCESS;
	scsi_devid_desc_t	*lpt;
	uint8_t			*ptr, *keyoffset,  *endoffset;
	uint32_t		i, sz;

	ret = sbd_read_meta_section(slu, (sm_section_hdr_t **)&spi,
	    SMS_ID_PGR_INFO);
	if (ret != SBD_SUCCESS) {
		/* No PGR section found, means volume made before PGR support */
		if (ret == SBD_NOT_FOUND) {
			/* So just create a default PGR section */
			ret = sbd_pgr_meta_init(slu);
		}
		return (ret);
	}

	if (spi->pgr_data_order != SMS_DATA_ORDER) {
		sbd_swap_pgr_info(spi);
	}

	pgr->pgr_flags = spi->pgr_flags;
	if (pgr->pgr_flags & SBD_PGR_APTPL) {
		pgr->pgr_rsv_type = spi->pgr_rsv_type;
		pgr->pgr_rsv_scope = spi->pgr_rsv_scope;
	} else {
		PGR_CLEAR_RSV_FLAG(pgr->pgr_flags);
	}

	PGR_CLEAR_FLAG(slu->sl_pgr->pgr_flags, SBD_PGR_ALL_KEYS_HAS_IT);

	endoffset	= (uint8_t *)spi;
	endoffset	+= spi->pgr_sms_header.sms_size;
	keyoffset	= (uint8_t *)(spi + 1);
	for (i = 1; i <= spi->pgr_numkeys; i++) {

		spi_key = (sbd_pgr_key_info_t *)keyoffset;
		if (spi->pgr_data_order != SMS_DATA_ORDER) {
			sbd_swap_pgrkey_info(spi_key);
		}

		/* Calculate the size and next offset */
		sz = ALIGNED_TO_8BYTE_BOUNDARY(sizeof (sbd_pgr_key_info_t) - 1 +
		    spi_key->pgr_key_lpt_len + spi_key->pgr_key_rpt_len);
		keyoffset += sz;

		/* Validate the key fields */
		if (spi_key->pgr_key_rpt_len == 0 || endoffset < keyoffset ||
		    (spi_key->pgr_key_lpt_len == 0 &&
		    !(spi_key->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT))) {
			ret = SBD_META_CORRUPTED;
			goto sbd_pgr_meta_load_failed;
		}

		lpt = (scsi_devid_desc_t *)spi_key->pgr_key_it;
		ptr = (uint8_t *)spi_key->pgr_key_it + spi_key->pgr_key_lpt_len;

		if (spi_key->pgr_key_flags & SBD_PGR_KEY_TPT_ID_FLAG) {
			uint16_t tpd_len = 0;

			if (!stmf_scsilib_tptid_validate(
			    (scsi_transport_id_t *)ptr,
			    spi_key->pgr_key_rpt_len, &tpd_len)) {
				ret = SBD_META_CORRUPTED;
				goto sbd_pgr_meta_load_failed;
			}
			if (tpd_len != spi_key->pgr_key_rpt_len) {
				ret = SBD_META_CORRUPTED;
				goto sbd_pgr_meta_load_failed;
			}
			key = sbd_pgr_key_alloc(lpt, (scsi_transport_id_t *)ptr,
			    spi_key->pgr_key_lpt_len, spi_key->pgr_key_rpt_len);
		} else {
			stmf_remote_port_t	*rpt = NULL;

			/*
			 * This block is executed only if the metadata was
			 * stored before the implementation of Transport ID
			 * support.
			 */
			rpt = stmf_scsilib_devid_to_remote_port(
			    (scsi_devid_desc_t *)ptr);
			if (rpt == NULL) {
				ret = SBD_META_CORRUPTED;
				goto sbd_pgr_meta_load_failed;
			}
			key = sbd_pgr_key_alloc(lpt, rpt->rport_tptid,
			    spi_key->pgr_key_lpt_len, rpt->rport_tptid_sz);
			stmf_remote_port_free(rpt);
		}

		key->pgr_key		= spi_key->pgr_key;
		key->pgr_key_flags	= spi_key->pgr_key_flags;
		key->pgr_key_prev	= last_key;

		if (last_key) {
			last_key->pgr_key_next = key;
		} else {
			pgr->pgr_keylist = key;
		}
		last_key = key;

		if ((pgr->pgr_flags & SBD_PGR_RSVD_ONE) &&
		    (i == spi->pgr_rsvholder_indx)) {
			pgr->pgr_rsvholder = key;
		}
	}

	kmem_free(spi, spi->pgr_sms_header.sms_size);
	return (ret);

sbd_pgr_meta_load_failed:
	{
	char *lun_name = sbd_get_devid_string(slu);
	sbd_pgr_keylist_dealloc(slu);
	kmem_free(spi, spi->pgr_sms_header.sms_size);
	cmn_err(CE_WARN, "sbd_pgr_meta_load: Failed to load PGR meta data "
	    "for lun %s.", lun_name);
	kmem_free(lun_name, strlen(lun_name) + 1);
	return (ret);
	}
}

sbd_status_t
sbd_pgr_meta_write(sbd_lu_t *slu)
{
	sbd_pgr_key_t		*key;
	sbd_pgr_info_t		*spi;
	sbd_pgr_key_info_t	*spi_key;
	sbd_pgr_t		*pgr = slu->sl_pgr;
	sbd_status_t		ret = SBD_SUCCESS;
	uint32_t		sz, totalsz;

	/* Calculate total pgr meta section size needed */
	sz = sizeof (sbd_pgr_info_t);
	if (pgr->pgr_flags & SBD_PGR_APTPL) {
		key = pgr->pgr_keylist;
		while (key != NULL) {
			sz = ALIGNED_TO_8BYTE_BOUNDARY(sz +
			    sizeof (sbd_pgr_key_info_t) - 1 +
			    key->pgr_key_lpt_len + key->pgr_key_rpt_len);
			key = key->pgr_key_next;
		}
	}
	totalsz = sz;

	spi = (sbd_pgr_info_t *)kmem_zalloc(totalsz, KM_SLEEP);
	spi->pgr_flags		= pgr->pgr_flags;
	spi->pgr_rsv_type	= pgr->pgr_rsv_type;
	spi->pgr_rsv_scope	= pgr->pgr_rsv_scope;
	spi->pgr_data_order	= SMS_DATA_ORDER;
	spi->pgr_numkeys	= 0;

	spi->pgr_sms_header.sms_size = totalsz;
	spi->pgr_sms_header.sms_id = SMS_ID_PGR_INFO;
	spi->pgr_sms_header.sms_data_order = SMS_DATA_ORDER;

	if (pgr->pgr_flags & SBD_PGR_APTPL) {
		uint8_t *ptr;
		key = pgr->pgr_keylist;
		sz = sizeof (sbd_pgr_info_t);
		while (key != NULL) {
			spi_key = (sbd_pgr_key_info_t *)((uint8_t *)spi + sz);
			spi_key->pgr_key = key->pgr_key;
			spi_key->pgr_key_flags = key->pgr_key_flags;
			spi_key->pgr_key_lpt_len = key->pgr_key_lpt_len;
			spi_key->pgr_key_rpt_len = key->pgr_key_rpt_len;
			ptr = spi_key->pgr_key_it;
			bcopy(key->pgr_key_lpt_id, ptr, key->pgr_key_lpt_len);
			ptr += key->pgr_key_lpt_len;
			bcopy(key->pgr_key_rpt_id, ptr, key->pgr_key_rpt_len);

			spi->pgr_numkeys++;
			if (key == pgr->pgr_rsvholder) {
				spi->pgr_rsvholder_indx = spi->pgr_numkeys;
			}

			sz = ALIGNED_TO_8BYTE_BOUNDARY(sz +
			    sizeof (sbd_pgr_key_info_t) - 1 +
			    key->pgr_key_lpt_len + key->pgr_key_rpt_len);
			key = key->pgr_key_next;
		}
	}

	ret = sbd_write_meta_section(slu, (sm_section_hdr_t *)spi);
	kmem_free(spi, totalsz);
	if (ret != SBD_SUCCESS) {
		sbd_pgr_key_t	*tmp_list;
		tmp_list = pgr->pgr_keylist;
		pgr->pgr_keylist = NULL;
		if (sbd_pgr_meta_load(slu) != SBD_SUCCESS) {
			char *lun_name = sbd_get_devid_string(slu);
			cmn_err(CE_WARN, "sbd_pgr_meta_write: Failed to revert "
			    "back to existing PGR state after meta write "
			    "failure, may cause PGR inconsistancy for lun %s.",
			    lun_name);
			kmem_free(lun_name, strlen(lun_name) + 1);
			pgr->pgr_keylist = tmp_list;
		} else {
			key = pgr->pgr_keylist;
			pgr->pgr_keylist = tmp_list;
			sbd_pgr_set_pgr_check_flag(slu, B_TRUE);
			sbd_pgr_keylist_dealloc(slu);
			pgr->pgr_keylist = key;
		}

	}
	return (ret);
}

static sbd_pgr_key_t *
sbd_pgr_key_alloc(scsi_devid_desc_t *lptid, scsi_transport_id_t *rptid,
					int16_t lpt_len, int16_t rpt_len)
{
	sbd_pgr_key_t *key;

	key = (sbd_pgr_key_t *)kmem_zalloc(sizeof (sbd_pgr_key_t), KM_SLEEP);

	if (lptid && lpt_len >= sizeof (scsi_devid_desc_t)) {
		key->pgr_key_lpt_len = lpt_len;
		key->pgr_key_lpt_id  = (scsi_devid_desc_t *)kmem_zalloc(
		    lpt_len, KM_SLEEP);
		bcopy(lptid, key->pgr_key_lpt_id, lpt_len);
	}

	if (rptid && rpt_len >= sizeof (scsi_transport_id_t)) {
		key->pgr_key_flags |= SBD_PGR_KEY_TPT_ID_FLAG;
		key->pgr_key_rpt_len = rpt_len;
		key->pgr_key_rpt_id  = (scsi_transport_id_t *)kmem_zalloc(
		    rpt_len, KM_SLEEP);
		bcopy(rptid, key->pgr_key_rpt_id, rpt_len);
	}

	return (key);
}

static void
sbd_pgr_key_free(sbd_pgr_key_t *key)
{
	if (key->pgr_key_lpt_id) {
		kmem_free(key->pgr_key_lpt_id, key->pgr_key_lpt_len);
	}
	if (key->pgr_key_rpt_id) {
		kmem_free(key->pgr_key_rpt_id, key->pgr_key_rpt_len);
	}
	kmem_free(key, sizeof (sbd_pgr_key_t));
}

void
sbd_pgr_keylist_dealloc(sbd_lu_t *slu)
{
	sbd_pgr_t	*pgr  = slu->sl_pgr;
	sbd_it_data_t	*it;
	sbd_pgr_key_t	*key;

	mutex_enter(&slu->sl_lock);
	for (it = slu->sl_it_list; it != NULL; it = it->sbd_it_next) {
		it->pgr_key_ptr = NULL;
	}
	mutex_exit(&slu->sl_lock);

	while (pgr->pgr_keylist != NULL) {
		key = pgr->pgr_keylist;
		pgr->pgr_keylist = key->pgr_key_next;
		sbd_pgr_key_free(key);
	}
}

/*
 * Reset and clear the keys, Can be used in the case of Lun Reset
 */
void
sbd_pgr_reset(sbd_lu_t *slu)
{
	sbd_pgr_t	*pgr  = slu->sl_pgr;

	rw_enter(&pgr->pgr_lock, RW_WRITER);
	if (!(pgr->pgr_flags & SBD_PGR_APTPL)) {
		sbd_pgr_keylist_dealloc(slu);
		pgr->pgr_PRgeneration	= 0;
		pgr->pgr_rsvholder	= NULL;
		pgr->pgr_rsv_type	= 0;
		pgr->pgr_flags		= 0;
	}
	rw_exit(&pgr->pgr_lock);
}

static void
sbd_pgr_remove_key(sbd_lu_t *slu, sbd_pgr_key_t *key)
{
	sbd_pgr_t *pgr  = slu->sl_pgr;
	sbd_it_data_t *it;

	ASSERT(key);

	mutex_enter(&slu->sl_lock);
	if (key->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT) {
		for (it = slu->sl_it_list; it != NULL; it = it->sbd_it_next) {
			if (it->pgr_key_ptr == key)
				it->pgr_key_ptr = NULL;
		}
	} else {
		if (key->pgr_key_it) {
			key->pgr_key_it->pgr_key_ptr = NULL;
		}
	}
	mutex_exit(&slu->sl_lock);

	if (key->pgr_key_next) {
		key->pgr_key_next->pgr_key_prev = key->pgr_key_prev;
	}
	if (key->pgr_key_prev) {
		key->pgr_key_prev->pgr_key_next = key->pgr_key_next;
	} else {
		pgr->pgr_keylist =  key->pgr_key_next;
	}

	sbd_pgr_key_free(key);
}

/*
 * Remove keys depends on boolean variable "match"
 * match = B_TRUE  ==>	Remove all keys which matches the given svc_key,
 *			except for IT equal to given "my_it".
 * match = B_FALSE ==>	Remove all keys which does not matches the svc_key,
 *			except for IT equal to given "my_it"
 */
static uint32_t
sbd_pgr_remove_keys(sbd_lu_t *slu, sbd_it_data_t *my_it, sbd_pgr_key_t *my_key,
				uint64_t svc_key, boolean_t match)
{
	sbd_pgr_t	*pgr  = slu->sl_pgr;
	sbd_it_data_t	*it;
	sbd_pgr_key_t	*nextkey, *key = pgr->pgr_keylist;
	uint32_t	count = 0;

	while (key) {

		nextkey = key->pgr_key_next;
		if (match == B_TRUE && key->pgr_key == svc_key ||
		    match == B_FALSE && key->pgr_key != svc_key) {
			/*
			 * If the key is registered by current IT keep it,
			 * but just remove pgr pointers from other ITs
			 */
			if (key == my_key) {
				mutex_enter(&slu->sl_lock);
				for (it = slu->sl_it_list; it != NULL;
				    it = it->sbd_it_next) {
					if (it->pgr_key_ptr == key &&
					    it != my_it)
						it->pgr_key_ptr = NULL;
				}
				mutex_exit(&slu->sl_lock);
			} else {
				sbd_pgr_remove_key(slu, key);
			}
			count++;
		}
		key = nextkey;
	}
	return (count);
}

static void
sbd_pgr_set_ua_conditions(sbd_lu_t *slu, sbd_it_data_t *my_it, uint8_t ua)
{
	sbd_it_data_t *it;

	mutex_enter(&slu->sl_lock);
	for (it = slu->sl_it_list; it != NULL; it = it->sbd_it_next) {
		if (it == my_it)
			continue;
		it->sbd_it_ua_conditions |= ua;
	}
	mutex_exit(&slu->sl_lock);
}

/*
 * Set the SBD_IT_PGR_CHECK_FLAG  depends on variable "registered". See Below.
 *
 *   If
 *     registered is B_TRUE  => Set PGR_CHECK_FLAG on all registered IT nexus
 *     registered is B_FALSE => Set PGR_CHECK_FLAG on all unregistered IT nexus
 */
static void
sbd_pgr_set_pgr_check_flag(sbd_lu_t *slu, boolean_t registered)
{
	sbd_it_data_t *it;

	PGR_CLEAR_FLAG(slu->sl_pgr->pgr_flags, SBD_PGR_ALL_KEYS_HAS_IT);
	mutex_enter(&slu->sl_lock);
	for (it = slu->sl_it_list; it != NULL; it = it->sbd_it_next) {
		if (it->pgr_key_ptr) {
			if (registered == B_TRUE)  {
				it->sbd_it_flags |=  SBD_IT_PGR_CHECK_FLAG;
			}
		} else {
			if (registered == B_FALSE)
				it->sbd_it_flags |=  SBD_IT_PGR_CHECK_FLAG;
		}
	}
	mutex_exit(&slu->sl_lock);
}

static boolean_t
sbd_pgr_key_compare(sbd_pgr_key_t *key, scsi_devid_desc_t *lpt,
					stmf_remote_port_t *rpt)
{
	scsi_devid_desc_t *id;

	if (!stmf_scsilib_tptid_compare(rpt->rport_tptid, key->pgr_key_rpt_id))
			return (B_FALSE);

	/*
	 * You can skip target port name comparison if ALL_TG_PT flag
	 * is set for this key;
	 */
	if (!(key->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT) && lpt) {
		id = key->pgr_key_lpt_id;
		if ((lpt->ident_length != id->ident_length) ||
		    (memcmp(id->ident, lpt->ident, id->ident_length) != 0)) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}


sbd_pgr_key_t *
sbd_pgr_key_registered(sbd_pgr_t *pgr, scsi_devid_desc_t *lpt,
					stmf_remote_port_t *rpt)
{
	sbd_pgr_key_t *key;

	for (key = pgr->pgr_keylist; key != NULL; key = key->pgr_key_next) {
		if (sbd_pgr_key_compare(key, lpt, rpt) == B_TRUE) {
			return (key);
		}
	}
	return (NULL);
}

void
sbd_pgr_initialize_it(scsi_task_t *task, sbd_it_data_t *it)
{
	sbd_lu_t *slu = (sbd_lu_t *)task->task_lu->lu_provider_private;
	stmf_scsi_session_t	*ses = task->task_session;
	sbd_pgr_t		*pgr = slu->sl_pgr;
	sbd_pgr_key_t		*key;
	scsi_devid_desc_t	*lpt, *id;
	stmf_remote_port_t	*rpt;

	if (pgr->pgr_flags & SBD_PGR_ALL_KEYS_HAS_IT)
		return;

	rpt = ses->ss_rport;
	lpt = ses->ss_lport->lport_id;

	rw_enter(&pgr->pgr_lock, RW_WRITER);
	PGR_SET_FLAG(pgr->pgr_flags,  SBD_PGR_ALL_KEYS_HAS_IT);
	for (key = pgr->pgr_keylist; key != NULL; key = key->pgr_key_next) {

		if ((!(key->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT)) &&
		    key->pgr_key_it != NULL)
			continue;
		/*
		 * SBD_PGR_ALL_KEYS_HAS_IT is set only if no single key
		 * in the list has SBD_PGR_KEY_ALL_TG_PT flag set and
		 * pgr_key_it all keys points to some IT
		 */
		PGR_CLEAR_FLAG(pgr->pgr_flags, SBD_PGR_ALL_KEYS_HAS_IT);

		/* Check if key matches with given lpt rpt combination */
		if (sbd_pgr_key_compare(key, lpt, rpt) == B_FALSE)
			continue;

		/* IT nexus devid information matches with this key */
		if (key->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT) {
			/*
			 * If ALL_TG_PT is set, pgr_key_it will point to NULL,
			 * unless pgr->pgr_rsvholder pointing to this key.
			 * In that case, pgr_key_it should point to the IT
			 * which initiated that reservation.
			 */
			if (pgr->pgr_rsvholder == key) {
				id = key->pgr_key_lpt_id;
				if (lpt->ident_length == id->ident_length) {
					if (memcmp(id->ident, lpt->ident,
					    id->ident_length) == 0)
						key->pgr_key_it = it;
				}
			}

		} else {
			key->pgr_key_it = it;
		}

		mutex_enter(&slu->sl_lock);
		it->pgr_key_ptr = key;
		mutex_exit(&slu->sl_lock);
		rw_exit(&pgr->pgr_lock);
		return;
	}
	rw_exit(&pgr->pgr_lock);
}

/*
 * Check for any PGR Reservation conflict. return 0 if access allowed
 */
int
sbd_pgr_reservation_conflict(scsi_task_t *task)
{
	sbd_lu_t	*slu = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_pgr_t	*pgr = slu->sl_pgr;
	sbd_it_data_t	*it  = (sbd_it_data_t *)task->task_lu_itl_handle;

	/* If Registered */
	if (pgr->pgr_flags & SBD_PGR_RSVD_ALL_REGISTRANTS && it->pgr_key_ptr)
			return (0);

	/* If you are registered */
	if (pgr->pgr_flags & SBD_PGR_RSVD_ONE) {
		rw_enter(&pgr->pgr_lock, RW_READER);

		/*
		 * Note: it->pgr_key_ptr is protected by sl_lock. Also,
		 *    it is expected to change its value only with pgr_lock
		 *    held. Hence we are safe to read its value without
		 *    grabbing sl_lock. But make sure that the value used is
		 *    not from registers by using "volatile" keyword.
		 *    Since this funtion is in performance path, we may want
		 *    to avoid grabbing sl_lock.
		 */
		if ((volatile sbd_pgr_key_t *)it->pgr_key_ptr) {
			/* If you are the reservation holder */
			if (pgr->pgr_rsvholder == it->pgr_key_ptr &&
			    it->pgr_key_ptr->pgr_key_it == it) {
				rw_exit(&pgr->pgr_lock);
				return (0);
			}

			/* If reserve type is not EX_AC */
			if (pgr->pgr_rsv_type != PGR_TYPE_EX_AC) {
				/* If reserve type is WR_EX allow read */
				if (pgr->pgr_rsv_type == PGR_TYPE_WR_EX) {
					if (PGR_READ_POSSIBLE_CMDS(
					    task->task_cdb[0])) {
						rw_exit(&pgr->pgr_lock);
						return (0);
					}
				/* For all other reserve types allow access */
				} else {
					rw_exit(&pgr->pgr_lock);
					return (0);
				}
			}

			/* If registered, allow these commands */
			if (PGR_REGISTERED_POSSIBLE_CMDS(task->task_cdb)) {
				rw_exit(&pgr->pgr_lock);
				return (0);
			}
		}
		rw_exit(&pgr->pgr_lock);
	}

	/* For any case, allow these commands */
	if (PGR_CONFLICT_FREE_CMDS(task->task_cdb)) {
		return (0);
	}

	/* Give read access if reservation type WR_EX for registrants */
	if (pgr->pgr_rsv_type == PGR_TYPE_WR_EX_RO ||
	    pgr->pgr_rsv_type == PGR_TYPE_WR_EX_AR) {
		if (PGR_READ_POSSIBLE_CMDS(task->task_cdb[0]))
			return (0);
	}

	/* If  you reached here, No access for you */
	return (1);
}

void
sbd_handle_pgr_in_cmd(scsi_task_t *task, stmf_data_buf_t *initial_dbuf)
{

	sbd_lu_t	*slu = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_pgr_t	*pgr = slu->sl_pgr;
	scsi_cdb_prin_t *pr_in;

	ASSERT(task->task_cdb[0] == SCMD_PERSISTENT_RESERVE_IN);

	pr_in = (scsi_cdb_prin_t *)task->task_cdb;

	rw_enter(&pgr->pgr_lock, RW_READER);
	switch (pr_in->action) {
	case PR_IN_READ_KEYS:
		sbd_pgr_in_read_keys(task, initial_dbuf);
		break;
	case PR_IN_READ_RESERVATION:
		sbd_pgr_in_read_reservation(task, initial_dbuf);
		break;
	case PR_IN_REPORT_CAPABILITIES:
		sbd_pgr_in_report_capabilities(task, initial_dbuf);
		break;
	case PR_IN_READ_FULL_STATUS:
		sbd_pgr_in_read_full_status(task, initial_dbuf);
		break;
	default :
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		break;
	}
	rw_exit(&pgr->pgr_lock);
}

void
sbd_handle_pgr_out_cmd(scsi_task_t *task, stmf_data_buf_t *initial_dbuf)
{

	scsi_cdb_prout_t *pr_out = (scsi_cdb_prout_t *)task->task_cdb;
	uint32_t param_len;

	ASSERT(task->task_cdb[0] == SCMD_PERSISTENT_RESERVE_OUT);

	switch (pr_out->action) {
		case PR_OUT_REGISTER:
		case PR_OUT_RESERVE:
		case PR_OUT_RELEASE:
		case PR_OUT_CLEAR:
		case PR_OUT_PREEMPT:
		case PR_OUT_PREEMPT_ABORT:
		case PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY:
		case PR_OUT_REGISTER_MOVE:
			param_len = READ_SCSI32(pr_out->param_len, uint32_t);
			if (param_len < MAX_PGR_PARAM_LIST_LENGTH &&
			    param_len > 0) {
				sbd_handle_short_write_transfers(task,
				    initial_dbuf, param_len);
			} else {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_PARAM_LIST_LENGTH_ERROR);
			}
			break;
		default :
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			break;
	}
}

void
sbd_handle_pgr_out_data(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	sbd_lu_t	*slu = (sbd_lu_t *)task->task_lu->lu_provider_private;
	scsi_cdb_prout_t	*pr_out	= (scsi_cdb_prout_t *)task->task_cdb;
	sbd_it_data_t		*it	= task->task_lu_itl_handle;
	sbd_pgr_t		*pgr	= slu->sl_pgr;
	sbd_pgr_key_t		*key;
	scsi_prout_plist_t	*plist;
	uint64_t		rsv_key;
	uint32_t		buflen;
	uint8_t			*buf;

	ASSERT(task->task_cdb[0] == SCMD_PERSISTENT_RESERVE_OUT);

	if (dbuf == NULL || dbuf->db_data_size < 24) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_PARAM_LIST_LENGTH_ERROR);
		return;
	}

	buf = dbuf->db_sglist[0].seg_addr;
	buflen = dbuf->db_data_size;
	plist = (scsi_prout_plist_t *)buf;

	/* SPC3 - 6.12.1 */
	if (pr_out->action != PR_OUT_REGISTER_MOVE && buflen != 24) {
		if ((pr_out->action !=
		    PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY &&
		    pr_out->action != PR_OUT_REGISTER) ||
		    plist->spec_i_pt == 0) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_PARAM_LIST_LENGTH_ERROR);
			return;
		}
	}

	/*
	 * Common Reservation Conflict Checks
	 *
	 * It is okey to handle REGISTER_MOVE with same plist here,
	 * because we are only accessing reservation key feild.
	 */
	rw_enter(&pgr->pgr_lock, RW_WRITER);

	/*
	 * Currently it is not mandatory to have volatile keyword here,
	 * because, it->pgr_key_ptr is not accessed yet. But still
	 * keeping it to safe gaurd against any possible future changes.
	 */
	key = (sbd_pgr_key_t *)((volatile sbd_pgr_key_t *)it->pgr_key_ptr);
	if (pr_out->action != PR_OUT_REGISTER &&
	    pr_out->action != PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY) {
		/* if IT is not yet registered send conflict status */
		if (key == NULL) {
			if (pr_out->action == PR_OUT_REGISTER_MOVE &&
			    SBD_PGR_RSVD_NONE(pgr)) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_INVALID_FIELD_IN_CDB);

			} else {
				stmf_scsilib_send_status(task,
				    STATUS_RESERVATION_CONFLICT, 0);
			}
			rw_exit(&pgr->pgr_lock);
			return;
		}

		/* Given reservation key should matches with registered key */
		rsv_key = READ_SCSI64(plist->reservation_key, uint64_t);
		if (key->pgr_key != rsv_key) {
			stmf_scsilib_send_status(task,
			    STATUS_RESERVATION_CONFLICT, 0);
			rw_exit(&pgr->pgr_lock);
			return;
		}
	}

	switch (pr_out->action) {
	case PR_OUT_REGISTER:
	case PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY:
		sbd_pgr_out_register(task, dbuf);
		break;
	case PR_OUT_REGISTER_MOVE:
		sbd_pgr_out_register_and_move(task, dbuf);
		break;
	case PR_OUT_RESERVE:
		sbd_pgr_out_reserve(task);
		break;
	case PR_OUT_RELEASE:
		sbd_pgr_out_release(task);
		break;
	case PR_OUT_CLEAR:
		sbd_pgr_out_clear(task);
		break;
	case PR_OUT_PREEMPT:
	case PR_OUT_PREEMPT_ABORT:
		sbd_pgr_out_preempt(task, dbuf);
		break;
	default :
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		break;
	}
	rw_exit(&pgr->pgr_lock);
}

static void
sbd_pgr_in_read_keys(scsi_task_t *task, stmf_data_buf_t *initial_dbuf)
{
	sbd_lu_t	*slu   = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_pgr_t	*pgr   =  slu->sl_pgr;
	sbd_pgr_key_t	*key;
	scsi_prin_readrsrv_t *buf;
	uint32_t buf_size, cdb_len, numkeys = 0;
	uint64_t *reg_key;

	ASSERT(task->task_cdb[0] == SCMD_PERSISTENT_RESERVE_IN);

	cdb_len = READ_SCSI16(&task->task_cdb[7], uint16_t);
	for (key = pgr->pgr_keylist; key != NULL; key = key->pgr_key_next)
		++numkeys;
	buf_size = 8 + numkeys * 8; /* minimum 8 bytes */
	buf = kmem_zalloc(buf_size, KM_SLEEP);
	SCSI_WRITE32(buf->PRgeneration, pgr->pgr_PRgeneration);
	SCSI_WRITE32(buf->add_len, numkeys * 8);

	reg_key = (uint64_t *)&buf->key_list;
	for (key = pgr->pgr_keylist; key != NULL; key = key->pgr_key_next) {
		SCSI_WRITE64(reg_key, key->pgr_key);
		reg_key++;
	}
	sbd_handle_short_read_transfers(task, initial_dbuf, (uint8_t *)buf,
	    cdb_len, buf_size);
	kmem_free(buf, buf_size);
}

static void
sbd_pgr_in_read_reservation(scsi_task_t *task, stmf_data_buf_t *initial_dbuf)
{
	sbd_lu_t	*slu   = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_pgr_t	*pgr   =  slu->sl_pgr;
	scsi_prin_readrsrv_t *buf;
	uint32_t cdb_len, buf_len, buf_size = 24;

	ASSERT(task->task_cdb[0] == SCMD_PERSISTENT_RESERVE_IN);

	cdb_len = READ_SCSI16(&task->task_cdb[7], uint16_t);
	buf = kmem_zalloc(buf_size, KM_SLEEP); /* fixed size cdb, 24 bytes */
	SCSI_WRITE32(buf->PRgeneration, pgr->pgr_PRgeneration);

	if (SBD_PGR_RSVD_NONE(pgr)) {
		SCSI_WRITE32(buf->add_len, 0);
		buf_len = 8;
	} else {
		if (pgr->pgr_flags & SBD_PGR_RSVD_ALL_REGISTRANTS) {
			SCSI_WRITE64(
			    buf->key_list.res_key_list[0].reservation_key, 0);
		} else {
			SCSI_WRITE64(
			    buf->key_list.res_key_list[0].reservation_key,
			    pgr->pgr_rsvholder->pgr_key);
		}
		buf->key_list.res_key_list[0].type = pgr->pgr_rsv_type;
		buf->key_list.res_key_list[0].scope = pgr->pgr_rsv_scope;
		SCSI_WRITE32(buf->add_len, 16);
		buf_len = 24;
	}

	sbd_handle_short_read_transfers(task, initial_dbuf, (uint8_t *)buf,
	    cdb_len, buf_len);
	kmem_free(buf, buf_size);
}

static void
sbd_pgr_in_report_capabilities(scsi_task_t *task,
				stmf_data_buf_t *initial_dbuf)
{
	sbd_lu_t	*slu   = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_pgr_t	*pgr   =  slu->sl_pgr;
	scsi_prin_rpt_cap_t buf;
	uint32_t cdb_len;

	ASSERT(task->task_cdb[0] == SCMD_PERSISTENT_RESERVE_IN);
	ASSERT(pgr != NULL);

	bzero(&buf, sizeof (buf));
	buf.ptpl_c		= 1;   /* Persist Through Power Loss C */
	buf.atp_c		= 1;   /* All Target Ports Capable */
	buf.sip_c		= 1;   /* Specify Initiator Ports Capable */
	buf.crh			= 0;   /* Supports Reserve/Release exception */
	buf.tmv			= 1;   /* Type Mask Valid */
	buf.pr_type.wr_ex	= 1;   /* Write Exclusve */
	buf.pr_type.ex_ac	= 1;   /* Exclusive Access */
	buf.pr_type.wr_ex_ro	= 1;   /* Write Exclusive Registrants Only */
	buf.pr_type.ex_ac_ro	= 1;   /* Exclusive Access Registrants Only */
	buf.pr_type.wr_ex_ar	= 1;   /* Write Exclusive All Registrants */
	buf.pr_type.ex_ac_ar	= 1;   /* Exclusive Access All Registrants */

	/* Persist Though Power Loss Active */
	buf.ptpl_a = pgr->pgr_flags & SBD_PGR_APTPL;
	SCSI_WRITE16(&buf.length, 8);
	cdb_len = READ_SCSI16(&task->task_cdb[7], uint16_t);
	sbd_handle_short_read_transfers(task, initial_dbuf, (uint8_t *)&buf,
	    cdb_len, 8);
}

/* Minimum required size, SPC3 rev23 Table 110 */
#define	PGR_IN_READ_FULL_STATUS_MINBUFSZ	8
/* Full Satus Descriptor Fromat size, SPC3 rev23 Table 111 */
#define	PGR_IN_READ_FULL_STATUS_DESCFMTSZ	24

static void
sbd_pgr_in_read_full_status(scsi_task_t *task,
				stmf_data_buf_t *initial_dbuf)
{
	sbd_lu_t	*slu   = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_pgr_t	*pgr   = slu->sl_pgr;
	sbd_pgr_key_t	*key;
	scsi_prin_status_t 	*sts;
	scsi_prin_full_status_t	*buf;
	uint32_t 		i, buf_size, cdb_len;
	uint8_t			*offset;

	ASSERT(task->task_cdb[0] == SCMD_PERSISTENT_RESERVE_IN);
	ASSERT(pgr != NULL);

	/* 4 byte allocation length for CDB, SPC3 rev23, Table 101 */
	cdb_len = READ_SCSI16(&task->task_cdb[7], uint16_t);

	/* PRgeneration and additional length fields */
	buf_size = PGR_IN_READ_FULL_STATUS_MINBUFSZ;
	for (key = pgr->pgr_keylist; key != NULL; key = key->pgr_key_next) {
		buf_size  = buf_size + PGR_IN_READ_FULL_STATUS_DESCFMTSZ +
		    key->pgr_key_rpt_len;
	}

	buf = kmem_zalloc(buf_size, KM_SLEEP);
	SCSI_WRITE32(buf->PRgeneration, pgr->pgr_PRgeneration);
	SCSI_WRITE32(buf->add_len, buf_size - PGR_IN_READ_FULL_STATUS_MINBUFSZ);

	offset	= (uint8_t *)&buf->full_desc[0];
	key	= pgr->pgr_keylist;
	i	= 0;
	while (key) {
		sts = (scsi_prin_status_t *)offset;
		SCSI_WRITE64(sts->reservation_key, key->pgr_key);
		if ((pgr->pgr_flags & SBD_PGR_RSVD_ALL_REGISTRANTS) ||
		    (pgr->pgr_rsvholder && pgr->pgr_rsvholder == key)) {
				sts->r_holder	= 1;
				sts->type 	= pgr->pgr_rsv_type;
				sts->scope	= pgr->pgr_rsv_scope;
		}

		if (key->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT) {
			sts->all_tg_pt = 1;
		} else {
			SCSI_WRITE16(sts->rel_tgt_port_id,
			    stmf_scsilib_get_lport_rtid(key->pgr_key_lpt_id));
		}
		SCSI_WRITE32(sts->add_len, key->pgr_key_rpt_len);
		offset += PGR_IN_READ_FULL_STATUS_DESCFMTSZ;
		(void) memcpy(offset, key->pgr_key_rpt_id,
		    key->pgr_key_rpt_len);
		offset += key->pgr_key_rpt_len;
		key = key->pgr_key_next;
		++i;
	}
	ASSERT(offset <= (uint8_t *)buf + buf_size);

	sbd_handle_short_read_transfers(task, initial_dbuf, (uint8_t *)buf,
	    cdb_len, buf_size);
	kmem_free(buf, buf_size);
}

static void
sbd_pgr_out_register(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	sbd_lu_t	*slu = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_pgr_t		*pgr	= slu->sl_pgr;
	stmf_scsi_session_t	*ses	= task->task_session;
	sbd_it_data_t		*it	= task->task_lu_itl_handle;
	sbd_pgr_key_t		*key	= it->pgr_key_ptr;
	scsi_cdb_prout_t	*pr_out	= (scsi_cdb_prout_t *)task->task_cdb;
	scsi_devid_desc_t	*lpt	= ses->ss_lport->lport_id;
	scsi_prout_plist_t	*plist;
	stmf_remote_port_t	rport;
	uint8_t			*buf, keyflag;
	uint32_t		buflen;
	uint64_t		rsv_key, svc_key;

	buf = dbuf->db_sglist[0].seg_addr;
	plist = (scsi_prout_plist_t *)buf;
	buflen = dbuf->db_data_size;
	rsv_key = READ_SCSI64(plist->reservation_key, uint64_t);
	svc_key = READ_SCSI64(plist->service_key, uint64_t);

	/* Handling already registered IT session */
	if (key) {

		if (pr_out->action == PR_OUT_REGISTER &&
		    key->pgr_key != rsv_key) {
			stmf_scsilib_send_status(task,
			    STATUS_RESERVATION_CONFLICT, 0);
			return;
		}
		if (plist->spec_i_pt) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		if (plist->all_tg_pt !=
		    (key->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT)) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		if (svc_key == 0) {
			sbd_pgr_do_unregister(slu, it, key);
		} else {
			key->pgr_key = svc_key;
		}

		goto sbd_pgr_reg_done;
	}

	/* Handling unregistered IT session */
	if (pr_out->action == PR_OUT_REGISTER && rsv_key != 0) {
		stmf_scsilib_send_status(task, STATUS_RESERVATION_CONFLICT, 0);
		return;
	}

	if (svc_key == 0) {
		/* Do we need to consider aptpl here? I don't think so */
		pgr->pgr_PRgeneration++;
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	keyflag = SBD_PGR_KEY_TPT_ID_FLAG;
	if (plist->all_tg_pt) {
		keyflag |= SBD_PGR_KEY_ALL_TG_PT;
		lpt = NULL;
	}

	if (plist->spec_i_pt) {
		uint32_t max_tpdnum, tpdnum, i, adn_len = 0;
		uint16_t tpd_sz = 0;
		uint8_t *adn_dat;
		scsi_transport_id_t *tpd;
		stmf_remote_port_t *rpt_ary;

		if (pr_out->action == PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		/* Length validation SPC3 rev23 Section 6.12.3 and Table 115 */
		if (buflen >= sizeof (scsi_prout_plist_t) - 1 +
		    sizeof (uint32_t))
			adn_len = READ_SCSI32(plist->apd, uint32_t);
		/* SPC3 rev23, adn_len should be multiple of 4 */
		if (adn_len % 4 != 0 ||
		    adn_len < sizeof (scsi_transport_id_t) +
		    sizeof (uint32_t) ||
		    buflen < sizeof (scsi_prout_plist_t) - 1 + adn_len) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_PARAM_LIST_LENGTH_ERROR);
			return;
		}

		tpdnum = 0;
		adn_dat = plist->apd + sizeof (uint32_t);
		max_tpdnum = adn_len / sizeof (scsi_transport_id_t);
		rpt_ary = (stmf_remote_port_t *)kmem_zalloc(
		    sizeof (stmf_remote_port_t) * max_tpdnum, KM_SLEEP);

		/* Check the validity of given TransportIDs */
		while (adn_len != 0) {
			if (!stmf_scsilib_tptid_validate(
			    (scsi_transport_id_t *)adn_dat, adn_len, &tpd_sz))
				break;
			/* SPC3 rev23, tpd_sz should be multiple of 4 */
			if (tpd_sz == 0 || tpd_sz % 4 != 0)
				break;
			tpd = (scsi_transport_id_t *)adn_dat;

			/* make sure that there is no duplicates */
			for (i = 0; i < tpdnum; i++) {
				if (stmf_scsilib_tptid_compare(
				    rpt_ary[i].rport_tptid, tpd))
					break;
			}
			if (i < tpdnum)
				break;

			rpt_ary[tpdnum].rport_tptid = tpd;
			rpt_ary[tpdnum].rport_tptid_sz = tpd_sz;

			/* Check if the given IT nexus is already registered */
			if (sbd_pgr_key_registered(pgr, lpt, &rpt_ary[tpdnum]))
				break;

			adn_len -= tpd_sz;
			adn_dat += tpd_sz;
			tpdnum++;
		}

		if (adn_len != 0) {
			kmem_free(rpt_ary,
			    sizeof (stmf_remote_port_t) * max_tpdnum);
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		for (i = 0; i < tpdnum; i++) {
			(void) sbd_pgr_do_register(slu, NULL, lpt, &rpt_ary[i],
			    keyflag, svc_key);
		}
		kmem_free(rpt_ary, sizeof (stmf_remote_port_t) * max_tpdnum);
	}

	rport.rport_tptid = ses->ss_rport->rport_tptid;
	rport.rport_tptid_sz = ses->ss_rport->rport_tptid_sz;

	(void) sbd_pgr_do_register(slu, it, lpt, &rport, keyflag, svc_key);

sbd_pgr_reg_done:

	if (pgr->pgr_flags & SBD_PGR_APTPL || plist->aptpl) {
		if (plist->aptpl)
			PGR_SET_FLAG(pgr->pgr_flags, SBD_PGR_APTPL);
		else
			PGR_CLEAR_FLAG(pgr->pgr_flags, SBD_PGR_APTPL);

		if (sbd_pgr_meta_write(slu) != SBD_SUCCESS) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INSUFFICIENT_REG_RESOURCES);
			return;
		}
	}

	pgr->pgr_PRgeneration++;
	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

static sbd_pgr_key_t *
sbd_pgr_do_register(sbd_lu_t *slu, sbd_it_data_t *it, scsi_devid_desc_t *lpt,
		stmf_remote_port_t *rpt, uint8_t keyflag, uint64_t svc_key)
{
	sbd_pgr_t		*pgr = slu->sl_pgr;
	sbd_pgr_key_t		*key;
	uint16_t		lpt_len = 0;

	if (lpt)
		lpt_len	= sizeof (scsi_devid_desc_t) + lpt->ident_length;

	key = sbd_pgr_key_alloc(lpt, rpt->rport_tptid,
	    lpt_len, rpt->rport_tptid_sz);
	key->pgr_key = svc_key;
	key->pgr_key_flags |= keyflag;

	if (key->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT) {
		/* set PGR_CHECK flag for all unregistered IT nexus */
		sbd_pgr_set_pgr_check_flag(slu, B_FALSE);
	} else {
		key->pgr_key_it = it;
	}

	if (it) {
		mutex_enter(&slu->sl_lock);
		it->pgr_key_ptr = key;
		mutex_exit(&slu->sl_lock);
	} else {
		sbd_pgr_set_pgr_check_flag(slu, B_FALSE);
	}

	key->pgr_key_next = pgr->pgr_keylist;
	if (pgr->pgr_keylist) {
		pgr->pgr_keylist->pgr_key_prev = key;
	}
	pgr->pgr_keylist = key;

	return (key);
}

static void
sbd_pgr_do_unregister(sbd_lu_t *slu, sbd_it_data_t *it, sbd_pgr_key_t *key)
{
	if (slu->sl_pgr->pgr_rsvholder == key) {
		sbd_pgr_do_release(slu, it, SBD_UA_RESERVATIONS_RELEASED);
	}

	sbd_pgr_remove_key(slu, key);
	if (slu->sl_pgr->pgr_keylist == NULL) {
		PGR_CLEAR_RSV_FLAG(slu->sl_pgr->pgr_flags);
	}
}

static void
sbd_pgr_out_reserve(scsi_task_t *task)
{
	sbd_lu_t	*slu   = (sbd_lu_t *)task->task_lu->lu_provider_private;
	stmf_scsi_session_t	*ses	= task->task_session;
	scsi_cdb_prout_t	*pr_out	= (scsi_cdb_prout_t *)task->task_cdb;
	sbd_it_data_t		*it	= task->task_lu_itl_handle;
	sbd_pgr_t		*pgr	= slu->sl_pgr;
	sbd_pgr_key_t		*key	= it->pgr_key_ptr;

	ASSERT(key);

	if (!(PGR_VALID_SCOPE(pr_out->scope) && PGR_VALID_TYPE(pr_out->type))) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	if (SBD_PGR_RSVD(pgr)) {
		if (PGR_RESERVATION_HOLDER(pgr, key, it)) {
			if (pgr->pgr_rsv_type != pr_out->type ||
			    pgr->pgr_rsv_scope != pr_out->scope) {
				stmf_scsilib_send_status(task,
				    STATUS_RESERVATION_CONFLICT, 0);
				return;
			}
		} else {
			stmf_scsilib_send_status(task,
			    STATUS_RESERVATION_CONFLICT, 0);
			return;

		}
	/* In case there is no reservation exist */
	} else {
		sbd_pgr_do_reserve(pgr, key, it, ses, pr_out);
		if (pgr->pgr_flags & SBD_PGR_APTPL) {
			if (sbd_pgr_meta_write(slu) != SBD_SUCCESS) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_INSUFFICIENT_REG_RESOURCES);
				return;
			}
		}
	}

	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

static void
sbd_pgr_do_reserve(sbd_pgr_t *pgr, sbd_pgr_key_t *key, sbd_it_data_t *it,
			stmf_scsi_session_t *ses, scsi_cdb_prout_t *pr_out)
{
	scsi_devid_desc_t	*lpt;
	uint16_t		lpt_len;

	pgr->pgr_rsv_type = pr_out->type;
	pgr->pgr_rsv_scope = pr_out->scope;
	if (pr_out->type == PGR_TYPE_WR_EX_AR ||
	    pr_out->type == PGR_TYPE_EX_AC_AR) {
		PGR_SET_FLAG(pgr->pgr_flags, SBD_PGR_RSVD_ALL_REGISTRANTS);
	} else {
		if (key->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT) {
			lpt = key->pgr_key_lpt_id;
			lpt_len = key->pgr_key_lpt_len;
			if (lpt_len > 0 && lpt != NULL) {
				kmem_free(lpt, lpt_len);
			}
			lpt = ses->ss_lport->lport_id;
			lpt_len = sizeof (scsi_devid_desc_t) +
			    lpt->ident_length;
			key->pgr_key_lpt_len = lpt_len;
			key->pgr_key_lpt_id = (scsi_devid_desc_t *)
			    kmem_zalloc(lpt_len, KM_SLEEP);
			bcopy(lpt, key->pgr_key_lpt_id, lpt_len);
			key->pgr_key_it = it;
		}

		PGR_SET_FLAG(pgr->pgr_flags, SBD_PGR_RSVD_ONE);
		pgr->pgr_rsvholder = key;
	}
}

static void
sbd_pgr_out_release(scsi_task_t *task)
{
	sbd_lu_t	*slu   = (sbd_lu_t *)task->task_lu->lu_provider_private;
	scsi_cdb_prout_t	*pr_out	= (scsi_cdb_prout_t *)task->task_cdb;
	sbd_it_data_t		*it	= task->task_lu_itl_handle;
	sbd_pgr_t		*pgr	= slu->sl_pgr;
	sbd_pgr_key_t		*key	= it->pgr_key_ptr;

	ASSERT(key);

	if (SBD_PGR_RSVD(pgr)) {
		if (pgr->pgr_flags & SBD_PGR_RSVD_ALL_REGISTRANTS ||
		    pgr->pgr_rsvholder == key) {
			if (pgr->pgr_rsv_type != pr_out->type ||
			    pgr->pgr_rsv_scope != pr_out->scope) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_INVALID_RELEASE_OF_PR);
				return;
			}
			sbd_pgr_do_release(slu, it,
			    SBD_UA_RESERVATIONS_RELEASED);
		}
	}
	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

static void
sbd_pgr_do_release(sbd_lu_t *slu, sbd_it_data_t *it, uint8_t ua_condition)
{

	sbd_pgr_t *pgr    =  slu->sl_pgr;

	/* Reset pgr_flags */
	PGR_CLEAR_RSV_FLAG(pgr->pgr_flags);
	pgr->pgr_rsvholder = NULL;

	/* set unit attention condition if necessary */
	if (pgr->pgr_rsv_type != PGR_TYPE_WR_EX &&
	    pgr->pgr_rsv_type != PGR_TYPE_EX_AC) {
		sbd_pgr_set_ua_conditions(slu, it, ua_condition);
	}
	pgr->pgr_rsv_type = 0;
}

static void
sbd_pgr_out_clear(scsi_task_t *task)
{
	sbd_lu_t	*slu   = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_it_data_t		*it	= task->task_lu_itl_handle;
	sbd_pgr_t		*pgr	= slu->sl_pgr;

	ASSERT(it->pgr_key_ptr);

	PGR_CLEAR_RSV_FLAG(pgr->pgr_flags);
	pgr->pgr_rsvholder = NULL;
	pgr->pgr_rsv_type = 0;
	mutex_enter(&slu->sl_lock);
	/* Remove all pointers from IT to pgr keys */
	for (it = slu->sl_it_list; it != NULL; it = it->sbd_it_next) {
		it->pgr_key_ptr = NULL;
	}
	mutex_exit(&slu->sl_lock);
	sbd_pgr_keylist_dealloc(slu);
	sbd_pgr_set_ua_conditions(slu, it, SBD_UA_RESERVATIONS_PREEMPTED);
	if (pgr->pgr_flags & SBD_PGR_APTPL) {
		if (sbd_pgr_meta_write(slu) != SBD_SUCCESS) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INSUFFICIENT_REG_RESOURCES);
			return;
		}
	}
	pgr->pgr_PRgeneration++;
	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

static void
sbd_pgr_out_preempt(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	sbd_lu_t	*slu   = (sbd_lu_t *)task->task_lu->lu_provider_private;
	stmf_scsi_session_t	*ses	= task->task_session;
	scsi_cdb_prout_t	*pr_out	= (scsi_cdb_prout_t *)task->task_cdb;
	sbd_it_data_t		*it	= task->task_lu_itl_handle;
	sbd_pgr_t		*pgr	= slu->sl_pgr;
	sbd_pgr_key_t		*key	= it->pgr_key_ptr;
	scsi_prout_plist_t	*plist;
	uint8_t			*buf, change_rsv = 0;
	uint64_t		svc_key;

	ASSERT(key);

	buf = dbuf->db_sglist[0].seg_addr;
	plist = (scsi_prout_plist_t *)buf;
	svc_key = READ_SCSI64(plist->service_key, uint64_t);

	if (SBD_PGR_RSVD_NONE(pgr)) {
		if (svc_key == 0 ||
		    sbd_pgr_remove_keys(slu, it, key, svc_key, B_TRUE) == 0) {
			stmf_scsilib_send_status(task,
			    STATUS_RESERVATION_CONFLICT, 0);
			return;
		}

	} else if (pgr->pgr_flags & SBD_PGR_RSVD_ONE) {
		if (svc_key == 0) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		/* Validity check of scope and type */
		if (pgr->pgr_rsvholder->pgr_key == svc_key) {
			if (!(PGR_VALID_SCOPE(pr_out->scope) &&
			    PGR_VALID_TYPE(pr_out->type))) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_INVALID_FIELD_IN_CDB);
				return;
			}
		}

		if (pgr->pgr_rsvholder != key &&
		    pgr->pgr_rsvholder->pgr_key == svc_key) {
			sbd_pgr_do_release(slu, it,
			    SBD_UA_REGISTRATIONS_PREEMPTED);
			change_rsv = 1;
		}

		if (pgr->pgr_rsvholder == key &&
		    pgr->pgr_rsvholder->pgr_key == svc_key) {
			if (pr_out->scope != pgr->pgr_rsv_scope ||
			    pr_out->type != pgr->pgr_rsv_type) {
				sbd_pgr_do_release(slu, it,
				    SBD_UA_REGISTRATIONS_PREEMPTED);
				change_rsv = 1;
			}
		} else {
			/*
			 * Remove matched keys in all cases, except when the
			 * current IT nexus holds the reservation and the given
			 * svc_key matches with registered key.
			 * Note that, if the reservation is held by another
			 * IT nexus, and svc_key matches registered key for
			 * that IT nexus, sbd_pgr_remove_key() is not expected
			 * return 0. Hence, returning check condition after
			 * releasing the reservation does not arise.
			 */
			if (sbd_pgr_remove_keys(slu, it, key, svc_key, B_TRUE)
			    == 0) {
				stmf_scsilib_send_status(task,
				    STATUS_RESERVATION_CONFLICT, 0);
				return;
			}
		}

		if (change_rsv) {
			sbd_pgr_do_reserve(pgr, key, it, ses, pr_out);
		}

	} else if (pgr->pgr_flags & SBD_PGR_RSVD_ALL_REGISTRANTS) {
		if (svc_key == 0) {
			if (!(PGR_VALID_SCOPE(pr_out->scope) &&
			    PGR_VALID_TYPE(pr_out->type))) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_INVALID_FIELD_IN_CDB);
				return;
			}
			sbd_pgr_do_release(slu, it,
			    SBD_UA_REGISTRATIONS_PREEMPTED);
			(void) sbd_pgr_remove_keys(slu, it, key, 0, B_FALSE);
			sbd_pgr_do_reserve(pgr, key, it, ses, pr_out);
		} else {
			if (sbd_pgr_remove_keys(slu, it, key, svc_key, B_TRUE)
			    == 0) {
				stmf_scsilib_send_status(task,
				    STATUS_RESERVATION_CONFLICT, 0);
				return;
			}
		}
	}

	if (pgr->pgr_flags & SBD_PGR_APTPL) {
		if (sbd_pgr_meta_write(slu) != SBD_SUCCESS) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INSUFFICIENT_REG_RESOURCES);
			return;
		}
	}

	pgr->pgr_PRgeneration++;

	if (pr_out->action == PR_OUT_PREEMPT_ABORT) {
		stmf_abort(STMF_QUEUE_ABORT_LU, task, STMF_ABORTED,
		    (void *)slu->sl_lu);
	}
	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

static void
sbd_pgr_out_register_and_move(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	sbd_lu_t	*slu   = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_it_data_t		*it	= task->task_lu_itl_handle;
	sbd_pgr_t		*pgr	= slu->sl_pgr;
	sbd_pgr_key_t		*key	= it->pgr_key_ptr;
	scsi_devid_desc_t	*lpt;
	stmf_remote_port_t	rport;
	sbd_pgr_key_t		*newkey;
	scsi_prout_reg_move_plist_t *plist;
	uint8_t			*buf, lpt_len;
	uint16_t		tpd_len;
	uint32_t		adn_len;
	uint64_t		svc_key;

	/*
	 * Check whether the key holds the reservation or current reservation
	 * is of type all registrants.
	 */
	if (pgr->pgr_rsvholder != key) {
		stmf_scsilib_send_status(task, STATUS_RESERVATION_CONFLICT, 0);
		return;
	}

	buf = dbuf->db_sglist[0].seg_addr;
	plist = (scsi_prout_reg_move_plist_t *)buf;
	svc_key = READ_SCSI64(plist->service_key, uint64_t);
	if (svc_key == 0) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	lpt = stmf_scsilib_get_devid_desc(READ_SCSI16(plist->rel_tgt_port_id,
	    uint16_t));
	if (lpt == NULL) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	adn_len = READ_SCSI32(plist->tptid_len, uint32_t);
	if (!stmf_scsilib_tptid_validate(
	    (scsi_transport_id_t *)plist->tptid, adn_len, &tpd_len)) {
		kmem_free(lpt, sizeof (scsi_devid_desc_t) + lpt->ident_length);
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_PARAM_LIST);
		return;
	}

	rport.rport_tptid = (scsi_transport_id_t *)plist->tptid;
	rport.rport_tptid_sz = tpd_len;

	if (sbd_pgr_key_compare(key, lpt, &rport)) {
		kmem_free(lpt, sizeof (scsi_devid_desc_t) + lpt->ident_length);
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_PARAM_LIST);
		return;
	}

	newkey = sbd_pgr_key_registered(pgr, lpt, &rport);
	if (newkey) {
		/* Set the pgr_key, irrespective of what it currently holds */
		newkey->pgr_key = svc_key;

		/* all_tg_pt is set for found key, copy lpt info to the key */
		if (newkey->pgr_key_flags & SBD_PGR_KEY_ALL_TG_PT) {
			if (newkey->pgr_key_lpt_id &&
			    newkey->pgr_key_lpt_len > 0) {
				kmem_free(newkey->pgr_key_lpt_id,
				    newkey->pgr_key_lpt_len);
			}
			lpt_len = sizeof (scsi_devid_desc_t) +
			    lpt->ident_length;
			newkey->pgr_key_lpt_len = lpt_len;
			newkey->pgr_key_lpt_id = (scsi_devid_desc_t *)
			    kmem_zalloc(lpt_len, KM_SLEEP);
			bcopy(lpt, newkey->pgr_key_lpt_id, lpt_len);
		}
		/* No IT nexus information, hence set PGR_CHEK flag */
		sbd_pgr_set_pgr_check_flag(slu, B_TRUE);
	} else  {
		newkey = sbd_pgr_do_register(slu, NULL, lpt, &rport,
		    SBD_PGR_KEY_TPT_ID_FLAG, svc_key);
	}

	kmem_free(lpt, sizeof (scsi_devid_desc_t) + lpt->ident_length);

	/* Now reserve the key corresponding to the specified IT nexus */
	pgr->pgr_rsvholder = newkey;

	if (plist->unreg) {
		sbd_pgr_do_unregister(slu, it, key);
	}


	/* Write to disk if currenty aptpl is set or given task is setting it */
	if (pgr->pgr_flags & SBD_PGR_APTPL || plist->aptpl) {
		if (plist->aptpl)
			PGR_SET_FLAG(pgr->pgr_flags, SBD_PGR_APTPL);
		else
			PGR_CLEAR_FLAG(pgr->pgr_flags, SBD_PGR_APTPL);

		if (sbd_pgr_meta_write(slu) != SBD_SUCCESS) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INSUFFICIENT_REG_RESOURCES);
			return;
		}
	}

	pgr->pgr_PRgeneration++;
	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

void
sbd_pgr_remove_it_handle(sbd_lu_t *sl, sbd_it_data_t *my_it) {
	sbd_it_data_t *it;

	rw_enter(&sl->sl_pgr->pgr_lock, RW_WRITER);
	mutex_enter(&sl->sl_lock);
	for (it = sl->sl_it_list; it != NULL; it = it->sbd_it_next) {
		if (it == my_it) {
			if (it->pgr_key_ptr) {
				sbd_pgr_key_t *key = it->pgr_key_ptr;
				if (key->pgr_key_it == it) {
					key->pgr_key_it = NULL;
					sl->sl_pgr->pgr_flags &=
					    ~SBD_PGR_ALL_KEYS_HAS_IT;
				}
			}
			break;
		}
	}
	mutex_exit(&sl->sl_lock);
	rw_exit(&sl->sl_pgr->pgr_lock);

}

char *
sbd_get_devid_string(sbd_lu_t *sl)
{
	char *str = (char *)kmem_zalloc(33, KM_SLEEP);
	(void) snprintf(str, 33,
	    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	    sl->sl_device_id[4], sl->sl_device_id[5], sl->sl_device_id[6],
	    sl->sl_device_id[7], sl->sl_device_id[8], sl->sl_device_id[9],
	    sl->sl_device_id[10], sl->sl_device_id[11], sl->sl_device_id[12],
	    sl->sl_device_id[13], sl->sl_device_id[14], sl->sl_device_id[15],
	    sl->sl_device_id[16], sl->sl_device_id[17], sl->sl_device_id[18],
	    sl->sl_device_id[19]);
	return (str);
}
