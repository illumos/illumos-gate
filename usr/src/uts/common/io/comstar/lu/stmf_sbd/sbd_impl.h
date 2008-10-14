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

#ifndef	_SBD_IMPL_H
#define	_SBD_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

struct register_lu_cmd;
struct modify_lu_cmd;
struct sbd_lu_attr;
struct sbd_it_data;

/*
 * sms endianess
 */
#define	SMS_BIG_ENDIAN			0x00
#define	SMS_LITTLE_ENDIAN		0xFF

#ifdef	_BIG_ENDIAN
#define	SMS_DATA_ORDER	SMS_BIG_ENDIAN
#else
#define	SMS_DATA_ORDER	SMS_LITTLE_ENDIAN
#endif

#define	SBD_V0_MAGIC	0x53554e4d4943524f
#define	SBD_MAGIC	0x53554e5342444c55

typedef struct sbd_v0_meta_start {
	uint64_t		sm_magic;	/* SBD_MAGIC */
	uint64_t		sm_meta_size;	/* Includes everything */
} sbd_v0_meta_start_t;

typedef struct sbd_meta_start {
	uint64_t		sm_magic;
	uint64_t		sm_meta_size;
	uint64_t		sm_meta_size_used;
	uint64_t		sm_rsvd1;	/* Defaults to zero */
	uint64_t		sm_rsvd2;
	uint16_t		sm_ver_major;
	uint16_t		sm_ver_minor;
	uint16_t		sm_ver_subminor;
	uint8_t			sm_flags;	/* None at this moment */
	uint8_t			sm_chksum;
} sbd_meta_start_t;

typedef struct sm_v0_section_hdr {
	uint64_t	sms_offset;	/* Offset of this section */
	uint64_t	sms_size;	/* Includes the header and padding */
	uint16_t	sms_id;		/* Section identifier */
	uint16_t	sms_padding;	/* For alignment */
	uint32_t	sms_seqno;	/* For multiple sections with same ID */
	uint8_t		sms_hdr_data_order; /* 0x00 or 0xff */
	uint8_t		sms_payload_data_order;
	uint16_t	rsvd2;
	uint32_t	rsvd3;		/* 8 byte align */
} sm_v0_section_hdr_t;

typedef struct sm_section_hdr {
	uint64_t	sms_offset;	/* Offset of this section */
	uint32_t	sms_size;	/* Includes the header and padding */
	uint16_t	sms_id;		/* Section identifier */
	uint8_t		sms_data_order; /* 0x00 or 0xff */
	uint8_t		sms_chksum;
} sm_section_hdr_t;

/*
 * sbd meta section identifiers
 */
#define	SMS_ID_LU_INFO	0

typedef struct sbd_v0_lu_info {
	sm_v0_section_hdr_t	sli_sms_header;
	uint64_t		sli_total_store_size;
	uint64_t		sli_total_meta_size;
	uint64_t		rsvd0;
	uint64_t		sli_lu_data_offset;
	uint64_t		sli_lu_data_size;
	uint64_t		rsvd1;
	uint32_t		sli_flags;
	uint16_t		sli_blocksize;
	uint16_t		rsvd2;
	uint8_t			sli_lu_devid[20];
	uint32_t		rsvd3;
} sbd_v0_lu_info_t;

typedef struct sbd_lu_info {
	sm_section_hdr_t	sli_sms_header;
	uint64_t		sli_total_store_size;
	uint64_t		sli_total_meta_size;
	uint64_t		sli_lu_data_offset;
	uint64_t		sli_lu_data_size;
	uint32_t		sli_flags;
	uint16_t		sli_blocksize;
	uint8_t			sli_data_order;
	uint8_t			rsvd1;
	uint8_t			sli_lu_devid[20];
	uint32_t		rsvd2;
} sbd_lu_info_t;

typedef struct sbd_lu {
	sbd_store_t			*sl_sst;
	uint32_t			sl_total_allocation_size;
	uint8_t				sl_shift_count;
	uint8_t				sl_state:7,
					sl_state_not_acked:1;
	uint8_t				sl_flags;
	kmutex_t			sl_it_list_lock;
	struct sbd_it_data		*sl_it_list;
	uint64_t			sl_rs_owner_session_id;
	stmf_lu_t			*sl_lu;
	struct sbd_lu			*sl_next; /* for int. tracking */

	sbd_meta_start_t		sl_sm;
	sbd_lu_info_t			*sl_sli;
	uint64_t			sl_meta_offset;
} sbd_lu_t;

extern sbd_lu_t *sbd_lu_list;

/*
 * sl_flags
 */
#define	SBD_LU_HAS_SCSI2_RESERVATION	0x0001

typedef struct sbd_cmd {
	uint8_t		flags;
	uint8_t		nbufs;
	uint16_t	cmd_type;	/* Type of command */
	uint32_t	rsvd2;
	uint64_t	addr;		/* current */
	uint32_t	len;		/* len left */
	uint32_t	current_ro;	/* running relative offset */
} sbd_cmd_t;

/*
 * flags for sbd_cmd
 */
#define	SBD_SCSI_CMD_ACTIVE		0x01
#define	SBD_SCSI_CMD_ABORT_REQUESTED	0x02
#define	SBD_SCSI_CMD_XFER_FAIL		0x04

/*
 * cmd types
 */
#define	SBD_CMD_SCSI_READ	0x01
#define	SBD_CMD_SCSI_WRITE	0x02
#define	SBD_CMD_SMALL_READ	0x03
#define	SBD_CMD_SMALL_WRITE	0x04

typedef struct sbd_it_data {
	struct sbd_it_data	*sbd_it_next;
	uint64_t		sbd_it_session_id;
	uint8_t			sbd_it_lun[8];
	uint8_t			sbd_it_ua_conditions;
	uint8_t			sbd_it_flags;
} sbd_it_data_t;

/*
 * Different UA conditions
 */
#define	SBD_UA_POR			0x01
#define	SBD_UA_CAPACITY_CHANGED		0x02

/*
 * sbd_it_flags
 */
#define	SBD_IT_HAS_SCSI2_RESERVATION		0x0001

stmf_status_t sbd_task_alloc(struct scsi_task *task);
void sbd_new_task(struct scsi_task *task, struct stmf_data_buf *initial_dbuf);
void sbd_dbuf_xfer_done(struct scsi_task *task, struct stmf_data_buf *dbuf);
void sbd_send_status_done(struct scsi_task *task);
void sbd_task_free(struct scsi_task *task);
stmf_status_t sbd_abort(struct stmf_lu *lu, int abort_cmd, void *arg,
							uint32_t flags);
void sbd_ctl(struct stmf_lu *lu, int cmd, void *arg);
stmf_status_t sbd_info(uint32_t cmd, stmf_lu_t *lu, void *arg,
				uint8_t *buf, uint32_t *bufsizep);

stmf_status_t memdisk_register_lu(struct register_lu_cmd *rlc);
stmf_status_t memdisk_deregister_lu(sbd_store_t *sst);
stmf_status_t filedisk_register_lu(struct register_lu_cmd *rlc);
stmf_status_t filedisk_deregister_lu(sbd_store_t *sst);
stmf_status_t filedisk_modify_lu(sbd_store_t *sst, struct modify_lu_cmd *mlc);
void filedisk_fillout_attr(struct sbd_store *sst, struct sbd_lu_attr *sla);
void memdisk_fillout_attr(struct sbd_store *sst, struct sbd_lu_attr *sla);

#ifdef	__cplusplus
}
#endif

#endif /* _SBD_IMPL_H */
