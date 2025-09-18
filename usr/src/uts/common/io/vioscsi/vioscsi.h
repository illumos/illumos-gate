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
 * Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 * Copyright 2026 Hans Rosenfeld
 */

#ifndef _VIOSCSI_H_
#define	_VIOSCSI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/stddef.h>

#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <virtio.h>

#define	VIRTIO_SCSI_CDB_SIZE	32
#define	VIRTIO_SCSI_SENSE_SIZE	96

/*
 * Feature bits:
 */
#define	VIRTIO_SCSI_F_INOUT		(0x1 << 0)
#define	VIRTIO_SCSI_F_HOTPLUG		(0x1 << 1)
#define	VIRTIO_SCSI_F_CHANGE		(0x1 << 2)
#define	VIRTIO_SCSI_F_T10_PI		(0x1 << 3)

#define	VIOSCSI_FEATURE_FORMAT					\
	"\020\001INOUT\002HOTPLUG\004CHANGE\010T10_PI"

/*
 * We want hotplug notification, but we can work without.
 */
#define	VIOSCSI_WANTED_FEATURES		(VIRTIO_SCSI_F_HOTPLUG)
#define	VIOSCSI_NEEDED_FEATURES		0
CTASSERT(((VIOSCSI_WANTED_FEATURES & VIOSCSI_NEEDED_FEATURES) ^
    VIOSCSI_NEEDED_FEATURES) == 0);

/*
 * Register offset in bytes:
 */
#define	VIRTIO_SCSI_CFG_NUM_QUEUES	0
#define	VIRTIO_SCSI_CFG_SEG_MAX		4
#define	VIRTIO_SCSI_CFG_MAX_SECTORS	8
#define	VIRTIO_SCSI_CFG_CMD_PER_LUN	12
#define	VIRTIO_SCSI_CFG_EVI_SIZE	16
#define	VIRTIO_SCSI_CFG_SENSE_SIZE	20
#define	VIRTIO_SCSI_CFG_CDB_SIZE	24
#define	VIRTIO_SCSI_CFG_MAX_CHANNEL	28
#define	VIRTIO_SCSI_CFG_MAX_TARGET	30
#define	VIRTIO_SCSI_CFG_MAX_LUN		32

/*
 * Response codes:
 */
#define	VIRTIO_SCSI_S_OK			0
#define	VIRTIO_SCSI_S_FUNCTION_COMPLETED	0
#define	VIRTIO_SCSI_S_OVERRUN			1
#define	VIRTIO_SCSI_S_ABORTED			2
#define	VIRTIO_SCSI_S_BAD_TARGET		3
#define	VIRTIO_SCSI_S_RESET			4
#define	VIRTIO_SCSI_S_BUSY			5
#define	VIRTIO_SCSI_S_TRANSPORT_FAILURE		6
#define	VIRTIO_SCSI_S_TARGET_FAILURE		7
#define	VIRTIO_SCSI_S_NEXUS_FAILURE		8
#define	VIRTIO_SCSI_S_FAILURE			9
#define	VIRTIO_SCSI_S_FUNCTION_SUCCEEDED	10
#define	VIRTIO_SCSI_S_FUNCTION_REJECTED		11
#define	VIRTIO_SCSI_S_INCORRECT_LUN		12

/*
 * Control queue type codes:
 */
#define	VIRTIO_SCSI_T_TMF			0
#define	VIRTIO_SCSI_T_AN_QUERY			1
#define	VIRTIO_SCSI_T_AN_SUBSCRIBE		2

/*
 * Task management codes:
 */
#define	VIRTIO_SCSI_T_TMF_ABORT_TASK		0
#define	VIRTIO_SCSI_T_TMF_ABORT_TASK_SET	1
#define	VIRTIO_SCSI_T_TMF_CLEAR_ACA		2
#define	VIRTIO_SCSI_T_TMF_CLEAR_ACA_TASK_SET	3
#define	VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET	4
#define	VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET	5
#define	VIRTIO_SCSI_T_TMF_QUERY_TASK		6
#define	VIRTIO_SCSI_T_TMF_QUERY_TASK_SET	7

/*
 * Events:
 */
#define	VIRTIO_SCSI_T_EVENTS_MISSED		0x80000000
#define	VIRTIO_SCSI_T_NO_EVENT			0
#define	VIRTIO_SCSI_T_TRANSPORT_RESET		1
#define	VIRTIO_SCSI_T_ASYNC_NOTIFY		2

/*
 * Task attributes:
 */
#define	VIRTIO_SCSI_S_SIMPLE			0
#define	VIRTIO_SCSI_S_ORDERED			1
#define	VIRTIO_SCSI_S_HEAD			2
#define	VIRTIO_SCSI_S_ACA			3

/*
 * Reasons of reset event:
 */
#define	VIRTIO_SCSI_EVT_RESET_HARD		0
#define	VIRTIO_SCSI_EVT_RESET_RESCAN		1
#define	VIRTIO_SCSI_EVT_RESET_REMOVED		2


#define	VIOSCSI_MAX_TARGET			256
#define	VIOSCSI_MAX_LUN				16384
#define	VIOSCSI_MIN_SEGS			3
#define	VIOSCSI_MAX_SEGS			128
#define	VIOSCSI_NUM_EVENTS			16

/*
 * Data structures:
 */

#pragma pack(1)

/*
 * virtio SCSI command request:
 */
struct virtio_scsi_cmd_req {
	uint8_t		lun[8];
	uint64_t	tag;
	uint8_t		task_attr;
	uint8_t		prio;
	uint8_t		crn;
	uint8_t		cdb[VIRTIO_SCSI_CDB_SIZE];
};

/*
 * Virtio SCSI response:
 */
struct virtio_scsi_cmd_resp {
	uint32_t	sense_len;
	uint32_t	res_id;
	uint16_t	status_qualifier;
	uint8_t		status;
	uint8_t		response;
	uint8_t		sense[VIRTIO_SCSI_SENSE_SIZE];
};

/*
 * Task management request:
 */
struct virtio_scsi_ctrl_tmf_req {
	uint32_t	type;
	uint32_t	subtype;
	uint8_t		lun[8];
	uint64_t	tag;
};

/*
 * Task management response:
 */
struct virtio_scsi_ctrl_tmf_resp {
	uint8_t		response;
};

/*
 * Asynchronous notification request:
 */
struct virtio_scsi_ctrl_an_req {
	uint32_t	type;
	uint8_t		lun[8];
	uint32_t	event_requested;
};

/*
 * Asynchronous notification response:
 */
struct virtio_scsi_ctrl_an_resp {
	uint32_t	event_actual;
	uint8_t		response;
};

/*
 * Events delivered on the event queue:
 */
struct virtio_scsi_event {
	uint32_t	event;
	uint8_t		lun[8];
	uint32_t	reason;
};

#pragma pack()

typedef union {
	struct virtio_scsi_cmd_req		cmd;
	struct virtio_scsi_ctrl_tmf_req		tmf;
	struct virtio_scsi_ctrl_an_req		anr;
} vioscsi_req_t;

typedef union {
	struct virtio_scsi_cmd_resp		cmd;
	struct virtio_scsi_ctrl_tmf_resp	tmf;
	struct virtio_scsi_ctrl_an_resp		anr;
} vioscsi_res_t;

struct virtio_scsi_op {
	vioscsi_req_t	req;
	vioscsi_res_t	res;
};

#define	VIOSCSI_REQ_OFFSET	offsetof(struct virtio_scsi_op, req)
#define	VIOSCSI_RES_OFFSET	offsetof(struct virtio_scsi_op, res)

typedef struct vioscsi_request vioscsi_request_t;
typedef	struct vioscsi_event vioscsi_event_t;
typedef struct vioscsi_softc vioscsi_softc_t;
typedef struct vioscsi_dev vioscsi_dev_t;
typedef struct virtio_scsi_event vioscsi_evt_t;
typedef struct virtio_scsi_ctrl_tmf_req vioscsi_tmf_req_t;
typedef struct virtio_scsi_ctrl_tmf_resp vioscsi_tmf_res_t;
typedef struct virtio_scsi_cmd_req vioscsi_cmd_req_t;
typedef struct virtio_scsi_cmd_resp vioscsi_cmd_res_t;
typedef struct virtio_scsi_op vioscsi_op_t;

struct vioscsi_request {
	list_node_t		vr_node;
	struct scsi_pkt		*vr_pkt;
	virtio_queue_t		*vr_vq;
	virtio_dma_t		*vr_dma;
	virtio_chain_t		*vr_vic;
	vioscsi_dev_t		*vr_dev;
	vioscsi_req_t		*vr_req;
	vioscsi_res_t		*vr_res;
	uint64_t		vr_req_pa;
	uint64_t		vr_res_pa;
	boolean_t		vr_poll;
	uint8_t			vr_expired;	/* access using atomics */
	uint8_t			vr_done;	/* access using atomics */
	uint8_t			vr_task_attr;
	uint8_t			vr_target;
	uint16_t		vr_lun;
	clock_t			vr_time;	/* seconds */
	clock_t			vr_start;	/* ticks */
	clock_t			vr_expire;	/* ticks */
};

struct vioscsi_dev {
	list_node_t		vd_node;
	uint8_t			vd_target;
	uint16_t		vd_lun;
	struct scsi_device	*vd_sd;
	vioscsi_softc_t		*vd_sc;
	int			vd_num_cmd;
	int			vd_max_cmd;
	boolean_t		vd_rescan;
	list_t			vd_reqs;
	timeout_id_t		vd_timeout;
	kmutex_t		vd_lock;
};

struct vioscsi_event {
	virtio_chain_t		*ve_vic;
	virtio_dma_t		*ve_dma;
	vioscsi_evt_t		*ve_evt;
};

struct vioscsi_softc {
	dev_info_t		*vs_dip;
	virtio_t		*vs_virtio;
	uint64_t		vs_features;

	virtio_queue_t		*vs_ctl_vq;
	virtio_queue_t		*vs_evt_vq;
	virtio_queue_t		*vs_cmd_vq;

	scsi_hba_tran_t		*vs_tran;
	scsi_hba_tgtmap_t	*vs_tgtmap;
	ddi_taskq_t		*vs_tq;

	uint32_t		vs_num_queues;
	uint32_t		vs_seg_max;
	uint32_t		vs_max_sectors;
	uint32_t		vs_cmd_per_lun;
	uint32_t		vs_evi_size;
	uint32_t		vs_sense_size;
	uint32_t		vs_cdb_size;
	uint16_t		vs_max_channel;
	uint16_t		vs_max_target;
	uint32_t		vs_max_lun;

	vioscsi_event_t		vs_events[VIOSCSI_NUM_EVENTS];

	void			*vs_intr_pri;
	kmutex_t		vs_lock;
	list_t			vs_devs;
};

#ifdef __cplusplus
}
#endif

#endif /* _VIOSCSI_H_ */
