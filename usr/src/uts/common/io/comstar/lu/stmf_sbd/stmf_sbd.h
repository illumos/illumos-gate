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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_STMF_SBD_H
#define	_STMF_SBD_H

#include <sys/dkio.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef	stmf_status_t	sbd_status_t;
extern char sbd_vendor_id[];
extern char sbd_product_id[];
extern char sbd_revision[];
extern char *sbd_mgmt_url;
extern uint16_t sbd_mgmt_url_alloc_size;
extern krwlock_t sbd_global_prop_lock;

/*
 * Error codes
 */
#define	SBD_SUCCESS		STMF_SUCCESS
#define	SBD_FAILURE		STMF_LU_FAILURE

#define	SBD_ALREADY		(SBD_FAILURE | STMF_FSC(1))
#define	SBD_NOT_SUPPORTED	(SBD_FAILURE | STMF_FSC(2))
#define	SBD_META_CORRUPTED	(SBD_FAILURE | STMF_FSC(3))
#define	SBD_INVALID_ARG		(SBD_FAILURE | STMF_FSC(4))
#define	SBD_NOT_FOUND		(SBD_FAILURE | STMF_FSC(5))
#define	SBD_ALLOC_FAILURE	(SBD_FAILURE | STMF_FSC(6))
#define	SBD_FILEIO_FAILURE	(SBD_FAILURE | STMF_FSC(7))
#define	SBD_IO_PAST_EOF		(SBD_FAILURE | STMF_FSC(8))
#define	SBD_BUSY		(SBD_FAILURE | STMF_FSC(9))

#define	SHARED_META_DATA_SIZE	65536
#define	SBD_META_OFFSET		4096
#define	SBD_MIN_LU_SIZE		(1024 * 1024)

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

#define	SBD_MAGIC	0x53554e5342444c55

#define	SBD_VER_MAJOR		1
#define	SBD_VER_MINOR		1
#define	SBD_VER_SUBMINOR	0

#if 0
typedef struct sbd_meta_start {
	uint64_t		sm_magic;
	uint64_t		sm_meta_size;
	uint64_t		sm_meta_size_used;
	uint64_t		sm_rsvd1;	/* Defaults to zero */
	uint64_t		sm_rsvd2;
	uint16_t		sm_ver_major;
	uint16_t		sm_ver_minor;
	uint16_t		sm_ver_subminor;
	uint8_t			sm_flags;
	uint8_t			sm_chksum;
} sbd_meta_start_t;
#endif

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
#define	SMS_ID_LU_INFO_1_0	0
#define	SMS_ID_LU_INFO_1_1	1
#define	SMS_ID_PGR_INFO		2
#define	SMS_ID_UNUSED		0x1000

typedef struct sbd_lu_info_1_0 {
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
} sbd_lu_info_1_0_t;

typedef struct sbd_lu_info_1_1 {
	sm_section_hdr_t	sli_sms_header;
	uint32_t		sli_flags;
	char			sli_rev[4];
	char			sli_vid[8];
	char			sli_pid[16];
	uint64_t		sli_lu_size;	/* Read capacity size */

	/*
	 * Essetially zfs volume name for zvols to verify that the
	 * metadata is coming in from the correct zvol and not from a
	 * clone. Has no meaning in any other case.
	 */
	uint64_t		sli_meta_fname_offset;

	/*
	 * Data filename or the media filename when the metadata is in
	 * a separate file. Its not needed if the metadata is shared
	 * with data as the user supplied name is the data filename.
	 */
	uint64_t		sli_data_fname_offset;
	uint64_t		sli_serial_offset;
	uint64_t		sli_alias_offset;
	uint8_t			sli_data_blocksize_shift;
	uint8_t			sli_data_order;
	uint8_t			sli_serial_size;
	uint8_t			sli_rsvd1;
	uint8_t			sli_device_id[20];
	uint64_t		sli_mgmt_url_offset;
	uint8_t			sli_rsvd2[248];

	/*
	 * In case there is no separate meta, sli_meta_fname_offset wont
	 * be valid. The same is true for zfs based metadata. The data_fname
	 * is the zvol.
	 */
	uint8_t			sli_buf[8];
} sbd_lu_info_1_1_t;

/*
 * sli flags
 */
#define	SLI_SEPARATE_META			0x0001
#define	SLI_WRITE_PROTECTED			0x0002
#define	SLI_VID_VALID				0x0004
#define	SLI_PID_VALID				0x0008
#define	SLI_REV_VALID				0x0010
#define	SLI_META_FNAME_VALID			0x0020
#define	SLI_DATA_FNAME_VALID			0x0040
#define	SLI_SERIAL_VALID			0x0080
#define	SLI_ALIAS_VALID				0x0100
#define	SLI_WRITEBACK_CACHE_DISABLE		0x0200
#define	SLI_ZFS_META				0x0400
#define	SLI_MGMT_URL_VALID			0x0800

struct sbd_it_data;

typedef struct sbd_lu {
	struct sbd_lu	*sl_next;
	stmf_lu_t	*sl_lu;
	uint32_t	sl_alloc_size;

	/* Current LU state */
	kmutex_t	sl_lock;
	uint32_t	sl_flags;
	uint8_t		sl_trans_op;
	uint8_t		sl_state:7,
			sl_state_not_acked:1;

	char		*sl_name;		/* refers to meta or data */

	/* Metadata */
	kmutex_t	sl_metadata_lock;
	krwlock_t	sl_access_state_lock;
	char		*sl_alias;
	char		*sl_meta_filename;	/* If applicable */
	char		*sl_mgmt_url;
	vnode_t		*sl_meta_vp;
	vtype_t		sl_meta_vtype;
	uint8_t		sl_device_id[20];	/* 4(hdr) + 16(GUID) */
	uint8_t		sl_meta_blocksize_shift; /* Left shift multiplier */
	uint8_t		sl_data_blocksize_shift;
	uint8_t		sl_data_fs_nbits;
	uint8_t		sl_serial_no_size;
	uint64_t	sl_total_meta_size;
	uint64_t	sl_meta_size_used;
	uint8_t		*sl_serial_no;		/* optional */
	char		sl_vendor_id[8];
	char		sl_product_id[16];
	char		sl_revision[4];
	uint32_t	sl_data_fname_alloc_size; /* for an explicit alloc */
	uint16_t	sl_alias_alloc_size;
	uint16_t	sl_mgmt_url_alloc_size;
	uint8_t		sl_serial_no_alloc_size;
	uint8_t		sl_access_state;
	uint64_t	sl_meta_offset;

	/* zfs metadata */
	krwlock_t	sl_zfs_meta_lock;
	char		*sl_zfs_meta;
	minor_t		sl_zvol_minor;		/* for direct zvol calls */
	/* opaque handles for zvol direct calls */
	void		*sl_zvol_minor_hdl;
	void		*sl_zvol_objset_hdl;
	void		*sl_zvol_zil_hdl;
	void		*sl_zvol_rl_hdl;
	void		*sl_zvol_dn_hdl;

	/* Backing store */
	char		*sl_data_filename;
	vnode_t		*sl_data_vp;
	vtype_t		sl_data_vtype;
	uint64_t	sl_total_data_size;
	uint64_t	sl_data_readable_size;	/* read() fails after this */
	uint64_t	sl_data_offset;		/* After the metadata,if any */
	uint64_t	sl_lu_size;		/* READ CAPACITY size */
	uint64_t	sl_blksize;		/* used for zvols */
	uint64_t	sl_max_xfer_len;	/* used for zvols */

	struct sbd_it_data	*sl_it_list;
	struct sbd_pgr		*sl_pgr;
	uint64_t	sl_rs_owner_session_id;
} sbd_lu_t;

/*
 * sl_flags
 */
#define	SL_LINKED			    0x00000001
#define	SL_META_OPENED			    0x00000002
#define	SL_REGISTERED			    0x00000004
#define	SL_META_NEEDS_FLUSH		    0x00000008
#define	SL_DATA_NEEDS_FLUSH		    0x00000010
#define	SL_VID_VALID			    0x00000020
#define	SL_PID_VALID			    0x00000040
#define	SL_REV_VALID			    0x00000080
#define	SL_WRITE_PROTECTED		    0x00000100
#define	SL_MEDIA_LOADED			    0x00000200
#define	SL_LU_HAS_SCSI2_RESERVATION	    0x00000400
#define	SL_WRITEBACK_CACHE_DISABLE	    0x00000800
#define	SL_SAVED_WRITE_CACHE_DISABLE	    0x00001000
#define	SL_MEDIUM_REMOVAL_PREVENTED	    0x00002000
#define	SL_NO_DATA_DKIOFLUSH		    0x00004000
#define	SL_SHARED_META			    0x00008000
#define	SL_ZFS_META			    0x00010000
#define	SL_WRITEBACK_CACHE_SET_UNSUPPORTED  0x00020000
#define	SL_FLUSH_ON_DISABLED_WRITECACHE	    0x00040000
#define	SL_CALL_ZVOL			    0x00080000
#define	SL_UNMAP_ENABLED		    0x00100000

/*
 * sl_trans_op. LU is undergoing some transition and this field
 * tells what kind of transition that is.
 */
#define	SL_OP_NONE				0
#define	SL_OP_CREATE_REGISTER_LU		1
#define	SL_OP_IMPORT_LU				2
#define	SL_OP_DELETE_LU				3
#define	SL_OP_MODIFY_LU				4
#define	SL_OP_LU_PROPS				5

sbd_status_t sbd_data_read(sbd_lu_t *sl, scsi_task_t *task,
    uint64_t offset, uint64_t size, uint8_t *buf);
sbd_status_t sbd_data_write(sbd_lu_t *sl, scsi_task_t *task,
    uint64_t offset, uint64_t size, uint8_t *buf);
stmf_status_t sbd_task_alloc(struct scsi_task *task);
void sbd_new_task(struct scsi_task *task, struct stmf_data_buf *initial_dbuf);
void sbd_dbuf_xfer_done(struct scsi_task *task, struct stmf_data_buf *dbuf);
void sbd_send_status_done(struct scsi_task *task);
void sbd_task_free(struct scsi_task *task);
stmf_status_t sbd_abort(struct stmf_lu *lu, int abort_cmd, void *arg,
    uint32_t flags);
void sbd_ctl(struct stmf_lu *lu, int cmd, void *arg);
stmf_status_t sbd_info(uint32_t cmd, stmf_lu_t *lu, void *arg, uint8_t *buf,
    uint32_t *bufsizep);
sbd_status_t sbd_write_lu_info(sbd_lu_t *sl);
sbd_status_t sbd_flush_data_cache(sbd_lu_t *sl, int fsync_done);
sbd_status_t sbd_wcd_set(int wcd, sbd_lu_t *sl);
void sbd_wcd_get(int *wcd, sbd_lu_t *sl);
int sbd_unmap(sbd_lu_t *sl, dkioc_free_list_t *dfl);

#ifdef	__cplusplus
}
#endif

#endif /* _STMF_SBD_H */
