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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_ATS_COPY_MGR_H
#define	_ATS_COPY_MGR_H

#ifdef	__cplusplus
extern "C" {
#endif

/* ATS structures and functions. */

typedef struct ats_state_s {
	/*
	 * We actually dont allow I/O which conflicts with current ats.
	 * The conflicting_rw_count is for those I/Os which are currently
	 * running and are potentally conflicting.
	 */
	list_node_t	as_next;
	uint8_t		as_cmd;
	uint32_t	as_conflicting_rw_count;
	uint32_t	as_non_conflicting_rw_count;
	uint32_t	as_ats_gen_ndx;
	uint32_t	as_cur_ats_handle;
	uint64_t	as_cur_ats_lba;
	uint64_t	as_cur_ats_lba_end;
	uint64_t	as_cur_ats_len;		/* in nblks */
	struct scsi_task *as_cur_ats_task;
} ats_state_t;

/* Since we're technically part of stmf_sbd.h, use some defines here. */
#define	sl_conflicting_rw_count	sl_ats_state.as_conflicting_rw_count
#define	sl_non_conflicting_rw_count sl_ats_state.as_non_conflicting_rw_count
#define	sl_ats_gen_ndx sl_ats_state.as_ats_gen_ndx
#define	sl_cur_ats_handle sl_ats_state.as_cur_ats_handle
#define	sl_cur_ats_lba sl_ats_state.as_cur_ats_lba
#define	sl_cur_ats_len sl_ats_state.as_cur_ats_len
#define	sl_cur_ats_task sl_ats_state.as_cur_ats_task

struct sbd_cmd;
struct sbd_lu;

void sbd_handle_ats_xfer_completion(struct scsi_task *, struct sbd_cmd *,
    struct stmf_data_buf *, uint8_t);
void sbd_do_ats_xfer(struct scsi_task *, struct sbd_cmd *,
    struct stmf_data_buf *, uint8_t);
void sbd_handle_ats(scsi_task_t *, struct stmf_data_buf *);
void sbd_handle_recv_copy_results(struct scsi_task *, struct stmf_data_buf *);
void sbd_free_ats_handle(struct scsi_task *, struct sbd_cmd *);
void sbd_handle_ats(scsi_task_t *, struct stmf_data_buf *);
uint8_t sbd_ats_max_nblks(void);
void sbd_ats_remove_by_task(scsi_task_t *);
sbd_status_t sbd_ats_handling_before_io(scsi_task_t *task, struct sbd_lu *sl,
    uint64_t lba, uint64_t count);

/* Block-copy structures and functions. */

struct scsi_task;
typedef	void *cpmgr_handle_t;

#define	CPMGR_INVALID_HANDLE		((cpmgr_handle_t)NULL)

#define	CPMGR_DEFAULT_TIMEOUT		30

#define	CPMGR_PARAM_HDR_LEN		16
#define	CPMGR_IDENT_TARGET_DESCRIPTOR	0xE4
#define	CPMGR_MAX_TARGET_DESCRIPTORS	2
#define	CPMGR_TARGET_DESCRIPTOR_SIZE	32

#define	CPMGR_B2B_SEGMENT_DESCRIPTOR		2
#define	CPMGR_MAX_SEGMENT_DESCRIPTORS		1
#define	CPMGR_B2B_SEGMENT_DESCRIPTOR_SIZE	28

/*
 * SCSI errors before copy starts.
 */
#define	CPMGR_PARAM_LIST_LEN_ERROR		0x051A00
#define	CPMGR_INVALID_FIELD_IN_PARAM_LIST	0x052600
#define	CPMGR_TOO_MANY_TARGET_DESCRIPTORS	0x052606
#define	CPMGR_UNSUPPORTED_TARGET_DESCRIPTOR	0x052607
#define	CPMGR_TOO_MANY_SEGMENT_DESCRIPTORS	0x052608
#define	CPMGR_UNSUPPORTED_SEGMENT_DESCRIPTOR	0x052609
#define	CPMGR_COPY_TARGET_NOT_REACHABLE		0x050D02
#define	CPMGR_INSUFFICIENT_RESOURCES		0x0B5503

/*
 * SCSI errors after copy has started.
 */
#define	CPMGR_LBA_OUT_OF_RANGE			0x0A2100
#define	CPMGR_THIRD_PARTY_DEVICE_FAILURE	0x0A0D01

/*
 * SCSI errors which dont result in STATUS_CHECK.
 * Use and invalid sense key to mark these.
 */
#define	CPMGR_RESERVATION_CONFLICT		0xF00001

typedef enum cm_state {
	CM_STARTING = 0,
	CM_COPYING,
	CM_COMPLETE
} cm_state_t;

#define	CPMGR_XFER_BUF_SIZE		(128 * 1024)

typedef struct cm_target_desc {
	stmf_lu_t	*td_lu;
	uint32_t	td_disk_block_len;
	uint8_t		td_lbasize_shift;
} cm_target_desc_t;

/*
 * Current implementation supports 2 target descriptors (identification type)
 * for src and dst and one segment descriptor (block -> block).
 */
typedef struct cpmgr {
	cm_target_desc_t	cm_tds[CPMGR_MAX_TARGET_DESCRIPTORS];
	uint8_t			cm_td_count;
	uint16_t		cm_src_td_ndx;
	uint16_t		cm_dst_td_ndx;
	cm_state_t		cm_state;
	uint32_t		cm_status;
	uint64_t		cm_src_offset;
	uint64_t		cm_dst_offset;
	uint64_t		cm_copy_size;
	uint64_t		cm_size_done;
	void			*cm_xfer_buf;
	scsi_task_t		*cm_task;
} cpmgr_t;

#define	cpmgr_done(cm)	(((cpmgr_t *)(cm))->cm_state == CM_COMPLETE)
#define	cpmgr_status(cm) (((cpmgr_t *)(cm))->cm_status)

cpmgr_handle_t cpmgr_create(struct scsi_task *task, uint8_t *params);
void cpmgr_destroy(cpmgr_handle_t h);
void cpmgr_run(cpmgr_t *cm, clock_t preemption_point);
void cpmgr_abort(cpmgr_t *cm, uint32_t s);
void sbd_handle_xcopy_xfer(scsi_task_t *, uint8_t *);
void sbd_handle_xcopy(scsi_task_t *, stmf_data_buf_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _ATS_COPY_MGR_H */
