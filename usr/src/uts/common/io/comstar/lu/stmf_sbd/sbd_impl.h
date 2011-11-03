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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
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

/* Test if one of the BitOrder definitions exists */
#ifdef _BIT_FIELDS_LTOH
#elif defined(_BIT_FIELDS_HTOL)
#else
#error  One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
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

/*
 * sbd_it_flags
 */
#define	SBD_IT_HAS_SCSI2_RESERVATION	0x0001
#define	SBD_IT_PGR_REGISTERED		0x0002
#define	SBD_IT_PGR_EXCLUSIVE_RSV_HOLDER	0x0004
#define	SBD_IT_PGR_CHECK_FLAG		0x0008

/*
 * PGR flags
 */
#define	SBD_PGR_APTPL			0x01
#define	SBD_PGR_RSVD_ONE		0x02
#define	SBD_PGR_RSVD_ALL_REGISTRANTS	0x04
#define	SBD_PGR_ALL_KEYS_HAS_IT		0x08

#define	SBD_PGR_RSVD(pgr)	(((pgr)->pgr_flags) & (SBD_PGR_RSVD_ONE | \
					SBD_PGR_RSVD_ALL_REGISTRANTS))
#define	SBD_PGR_RSVD_NONE(pgr)	(!(SBD_PGR_RSVD(pgr)))

/*
 * PGR key flags
 */
#define	SBD_PGR_KEY_ALL_TG_PT		0x01
#define	SBD_PGR_KEY_TPT_ID_FLAG		0x02

typedef struct sbd_pgr_key_info {
	uint64_t	pgr_key;
	uint16_t	pgr_key_lpt_len;
	uint16_t	pgr_key_rpt_len;
	uint8_t		pgr_key_flags;
	uint8_t		pgr_key_it[1];	/* order:- initiator info followed by */
					/* scsi_devid_desc of local port */
} sbd_pgr_key_info_t;

typedef struct sbd_pgr_info {
	sm_section_hdr_t	pgr_sms_header;
	uint32_t		pgr_rsvholder_indx;
	uint32_t		pgr_numkeys;
	uint8_t			pgr_flags;
	uint8_t			pgr_data_order;
#ifdef _BIT_FIELDS_LTOH
	uint8_t			pgr_rsv_type:4,
				pgr_rsv_scope:4;
#else
	uint8_t			pgr_rsv_scope:4,
				pgr_rsv_type:4;
#endif
	uint8_t			rsvd[5];	/* 8 byte boundary */

} sbd_pgr_info_t;

typedef struct sbd_pgr_key {
	uint64_t		pgr_key;
	uint16_t		pgr_key_lpt_len;
	uint16_t		pgr_key_rpt_len;
	uint8_t			pgr_key_flags;
	struct scsi_devid_desc	*pgr_key_lpt_id;
	struct scsi_transport_id *pgr_key_rpt_id;
	struct sbd_it_data	*pgr_key_it;
	struct sbd_pgr_key	*pgr_key_next;
	struct sbd_pgr_key	*pgr_key_prev;
} sbd_pgr_key_t;

typedef struct sbd_pgr {
	sbd_pgr_key_t		*pgr_keylist;
	sbd_pgr_key_t		*pgr_rsvholder;
	uint32_t		pgr_PRgeneration; /* PGR PRgeneration value */
	uint8_t			pgr_flags;	/* PGR flags (eg: APTPL)  */
	uint8_t			pgr_rsv_type:4,
				pgr_rsv_scope:4;
	krwlock_t		pgr_lock; /* Lock order pgr_lock, sl_lock */
} sbd_pgr_t;


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

/*
 * sl_flags
 */
#define	SBD_LU_HAS_SCSI2_RESERVATION	0x0001

typedef struct sbd_cmd {
	uint8_t		flags;
	uint8_t		nbufs;
	uint16_t	cmd_type;	/* Type of command */
	uint32_t	trans_data_len;	/* Length of transient data buf */
	uint64_t	addr;		/* current */
	uint32_t	len;		/* len left */
	uint32_t	current_ro;	/* running relative offset */
	uint8_t		*trans_data;	/* Any transient data */
} sbd_cmd_t;

/*
 * flags for sbd_cmd
 */
#define	SBD_SCSI_CMD_ACTIVE		0x01
#define	SBD_SCSI_CMD_ABORT_REQUESTED	0x02
#define	SBD_SCSI_CMD_XFER_FAIL		0x04
#define	SBD_SCSI_CMD_SYNC_WRITE		0x08
#define	SBD_SCSI_CMD_TRANS_DATA		0x10

/*
 * cmd types
 */
#define	SBD_CMD_SCSI_READ	0x01
#define	SBD_CMD_SCSI_WRITE	0x02
#define	SBD_CMD_SMALL_READ	0x03
#define	SBD_CMD_SMALL_WRITE	0x04
#define	SBD_CMD_SCSI_PR_OUT	0x05

typedef struct sbd_it_data {
	struct sbd_it_data	*sbd_it_next;
	uint64_t		sbd_it_session_id;
	uint8_t			sbd_it_lun[8];
	uint8_t			sbd_it_ua_conditions;
	uint8_t			sbd_it_flags;
	sbd_pgr_key_t		*pgr_key_ptr;
} sbd_it_data_t;

typedef struct sbd_create_standby_lu {
	uint32_t	stlu_meta_fname_size;
	uint32_t	stlu_rsvd;
	uint8_t		stlu_guid[16];
	char		stlu_meta_fname[8];
} sbd_create_standby_lu_t;

/*
 * Different UA conditions
 */
#define	SBD_UA_POR			    0x01
#define	SBD_UA_CAPACITY_CHANGED		    0x02
#define	SBD_UA_MODE_PARAMETERS_CHANGED	    0x04
#define	SBD_UA_ACCESS_STATE_TRANSITION	    0x08
#define	SBD_UA_REGISTRATIONS_PREEMPTED	    0x10
#define	SBD_UA_RESERVATIONS_PREEMPTED	    0x20
#define	SBD_UA_RESERVATIONS_RELEASED	    0x40
#define	SBD_UA_ASYMMETRIC_ACCESS_CHANGED    0x80

/*
 * sbd_it_flags
 */
#define	SBD_IT_HAS_SCSI2_RESERVATION	0x0001

/*
 * dbuf private data needed for direct zvol data transfers
 *
 * To further isolate the zvol knowledge, the object handles
 * needed to call into zfs are declared void * here.
 */

typedef struct sbd_zvol_io {
	uint64_t	zvio_offset;	/* offset into volume */
	int		zvio_flags;	/* flags */
	void 		*zvio_dbp;	/* array of dmu buffers */
	void		*zvio_abp;	/* array of arc buffers */
	uio_t		*zvio_uio;	/* for copy operations */
} sbd_zvol_io_t;

#define	ZVIO_DEFAULT	0
#define	ZVIO_COMMIT	1
#define	ZVIO_ABORT	2
#define	ZVIO_SYNC	4
#define	ZVIO_ASYNC	8

/*
 * zvol data path functions
 */
int sbd_zvol_get_volume_params(sbd_lu_t *sl);
uint32_t sbd_zvol_numsegs(sbd_lu_t *sl, uint64_t off, uint32_t len);
int sbd_zvol_alloc_read_bufs(sbd_lu_t *sl, stmf_data_buf_t *dbuf);
void sbd_zvol_rele_read_bufs(sbd_lu_t *sl, stmf_data_buf_t *dbuf);
int sbd_zvol_alloc_write_bufs(sbd_lu_t *sl, stmf_data_buf_t *dbuf);
void sbd_zvol_rele_write_bufs_abort(sbd_lu_t *sl, stmf_data_buf_t *dbuf);
int sbd_zvol_rele_write_bufs(sbd_lu_t *sl, stmf_data_buf_t *dbuf);
int sbd_zvol_copy_read(sbd_lu_t *sl, uio_t *uio);
int sbd_zvol_copy_write(sbd_lu_t *sl, uio_t *uio, int flags);

stmf_status_t sbd_task_alloc(struct scsi_task *task);
void sbd_new_task(struct scsi_task *task, struct stmf_data_buf *initial_dbuf);
void sbd_dbuf_xfer_done(struct scsi_task *task, struct stmf_data_buf *dbuf);
void sbd_send_status_done(struct scsi_task *task);
void sbd_task_free(struct scsi_task *task);
stmf_status_t sbd_abort(struct stmf_lu *lu, int abort_cmd, void *arg,
							uint32_t flags);
void sbd_dbuf_free(struct scsi_task *task, struct stmf_data_buf *dbuf);
void sbd_ctl(struct stmf_lu *lu, int cmd, void *arg);
stmf_status_t sbd_info(uint32_t cmd, stmf_lu_t *lu, void *arg,
				uint8_t *buf, uint32_t *bufsizep);

#ifdef	__cplusplus
}
#endif

#endif /* _SBD_IMPL_H */
