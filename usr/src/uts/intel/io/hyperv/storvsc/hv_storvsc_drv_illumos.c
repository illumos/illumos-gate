/*
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*
 * StorVSC driver for Hyper-V.  This driver presents a SCSI HBA interface
 * by plugging into the SCSA transport layer.
 * scsi_pkts are converted into VSCSI protocol messages which are delivered
 * to the parent partition StorVSP driver over the Hyper-V VMBUS.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callo.h>
#include <sys/ksynch.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/pci.h>
#include <sys/scsi/scsi.h>
#include <sys/uio.h>
#include <sys/cpuvar.h>
#include <sys/reboot.h>
#include <sys/fs/dv_node.h>

#include <sys/hyperv.h>
#include <sys/vmbus.h>
#include <sys/dditypes.h>
#include <sys/ddidmareq.h>
#include "hv_vstorage.h"

/*
 * These values are defined by Microsoft and should not be changed unless
 * the FreeBSD drivers, which this code is derived from, have also changed them.
 */
#define	STORVSC_MAX_LUNS_PER_TARGET	(64)
#define	STORVSC_MAX_IO_REQUESTS		(STORVSC_MAX_LUNS_PER_TARGET * 2)
#define	BLKVSC_MAX_IDE_DISKS_PER_TARGET	(1)
#define	BLKVSC_MAX_IO_REQUESTS		STORVSC_MAX_IO_REQUESTS
#define	STORVSC_MAX_TARGETS		(2)
#define	VSTOR_PKT_SIZE	(sizeof (struct vstor_packet) - vmscsi_size_delta)

#define	MAXCPU				256

#define	STORVSC_IDENT			"Hyper-V SCSI Interface"
#define	STORVSC_TGT_PRIV_SIZE		2

#define	AP2PRIV(ap)	((ap)->a_hba_tran->tran_hba_private)
#define	PKT2REQ(pkt)	((struct hv_storvsc_request *)((pkt)->pkt_ha_private))
#define	PKT2CMD(pkt)	((storvsc_cmd_t *)&(PKT2REQ(pkt)->hvs_cmd))
#define	CMD2PKT(cmd)	((struct scsi_pkt *)((cmd)->cmd_pkt))
#define	SDEV2PRIV(sd)	((sd)->sd_address.a_hba_tran->tran_hba_private)

#define	STORVSC_FLAG_CDB_EXT	0x0001
#define	STORVSC_FLAG_SCB_EXT	0x0002
#define	STORVSC_FLAG_PRIV_EXT	0x0004
#define	STORVSC_FLAG_TAG	0x0008
#define	STORVSC_FLAG_IO_READ	0x0010
#define	STORVSC_FLAG_IO_WRITE	0x0020
#define	STORVSC_FLAG_IO_IOPB	0x0040
#define	STORVSC_FLAG_DONE	0x0080
#define	STORVSC_FLAG_DMA_VALID	0x0100
#define	STORVSC_FLAG_XARQ	0x0200
#define	STORVSC_FLAG_TIMED_OUT	0x0400
#define	STORVSC_FLAG_ABORTED	0x0800
#define	STORVSC_FLAG_RESET_BUS	0x1000
#define	STORVSC_FLAG_RESET_DEV	0x2000
#define	STORVSC_FLAG_SRB_ERROR	0x4000
#define	STORVSC_FLAG_TRANSPORT	0x8000
#define	STORVSC_FLAG_DEV_GONE	0x10000

#define	STORVSC_FLAG_IO_MASK	0x0030

#define	STORVSC_STATUS_MASK	(STATUS_MASK | STATUS_TASK_ABORT)

#define	STORVSC_FLAGS_RESET \
	(STORVSC_FLAG_RESET_BUS | STORVSC_FLAG_RESET_DEV)

#define	STORVSC_FLAGS_EXT \
	(STORVSC_FLAG_CDB_EXT | STORVSC_FLAG_SCB_EXT | STORVSC_FLAG_PRIV_EXT)

#define	STORVSC_DATA_SEGCNT_MAX		128
#define	STORVSC_DATA_SEGSZ_MAX		4096		/* PAGESIZE */
#define	STORVSC_DATA_SIZE_MAX		\
	(STORVSC_DATA_SEGCNT_MAX * STORVSC_DATA_SEGSZ_MAX)

#define	STORVSC_POLL_DELAY_USECS	1000
#define	STORVSC_POLL_CYCLES(wait_secs) \
	((wait_secs * MICROSEC) / STORVSC_POLL_DELAY_USECS)

enum storvsc_request_type {
	WRITE_TYPE,
	READ_TYPE,
	UNKNOWN_TYPE
};

extern int do_polled_io;
int hv_storvsc_chan_cnt = 0;
uint_t hv_storvsc_use_win8ext_flags = 1;
static uint_t hv_storvsc_ringbuffer_size;

#define	STORVSC_MAX_IO						\
    vmbus_chan_prplist_nelem(hv_storvsc_ringbuffer_size,	\
    STORVSC_DATA_SEGCNT_MAX, VSTOR_PKT_SIZE)

/*
 * The storvsc_cmd defines the internal state for each scsi_pkt. The
 * structure holds the appropriate state to convert between SCSA layers
 * and the underlying hypervisor.
 */
typedef struct storvsc_cmd {
	struct scsi_pkt		*cmd_pkt;
	uint8_t			cmd_cdb[SCSI_CDB_SIZE];
	struct scsi_arq_status	cmd_scb;
	uint64_t		cmd_tgt_priv[STORVSC_TGT_PRIV_SIZE];
	size_t			cmd_tgtlen;
	size_t			cmd_len;
	size_t			cmd_statuslen;
	int			cmd_flags;
	ddi_dma_handle_t	cmd_handle;
	ddi_dma_cookie_t	cmd_cookie;
	uint_t			cmd_cookiec;
	uint_t			cmd_winindex;
	uint_t			cmd_nwin;
	off_t			cmd_dma_offset;
	size_t			cmd_dma_len;
	uint_t			cmd_dma_count;
	uint_t			cmd_total_dma_count;
	int			cmd_target;
	int			cmd_lun;
	struct storvsc_softc	*cmd_sc;
	struct buf		*cmd_arq_buf;
	int			cmd_rqslen;
	struct scsi_pkt		cmd_cached_pkt;
	buf_t			*cmd_bp;
} storvsc_cmd_t;

struct storvsc_gpa_range {
	struct vmbus_gpa_range	gpa_range;
	uint64_t		gpa_page[STORVSC_DATA_SEGCNT_MAX];
} __packed;

struct hv_storvsc_request {
	struct vstor_packet		vstor_packet;
	int				prp_cnt;
	struct storvsc_gpa_range	prp_list;
	void				*sense_data;
	uint8_t				sense_info_len;
	struct scsi_pkt			*pkt;
	timeout_id_t			timeout_id;
	/* Synchronize the request/response if needed */
	ksema_t				synch_sema;
	storvsc_cmd_t			hvs_cmd;
};

/*
 * The size of the vmscsi_request has changed in win8. The
 * additional size is for the newly added elements in the
 * structure. These elements are valid only when we are talking
 * to a win8 host.
 * Track the correct size we need to apply.
 */
static int vmscsi_size_delta = sizeof (struct vmscsi_win8_extension);

typedef struct storvsc_device {
	list_node_t	list;
	int		target;
	int		lun;
	dev_info_t	*dip;
	dev_info_t	*pdip;
} storvsc_device_t;


typedef struct storvsc_softc {
	struct vmbus_channel		*hs_chan;
	kmutex_t			hs_lock;
	struct storvsc_driver_props	*hs_drv_props;
	struct hv_storvsc_request	hs_init_req;
	uint32_t			hs_nchan;
	struct vmbus_channel		*hs_sel_chan[MAXCPU];
	struct hv_storvsc_request	hs_reset_req;
	uint32_t			hs_num_out_reqs;
	boolean_t			hs_destroy;
	boolean_t			hs_drain_notify;
	ksema_t				hs_drain_sema;
	dev_info_t			*hs_dip;
	int				hs_instance;
	scsi_hba_tran_t			*hs_tran;
	int				hs_num_active_commands;
	struct kmem_cache		*hs_req_cache;
	int				hs_num_luns;
	list_t				hs_devnodes;
	kstat_t				*hs_stats;
} storvsc_softc_t;

/*
 * Bus/adapter reset functionality on the Hyper-V host is
 * buggy and it will be disabled until
 * it can be further tested.
 */
#define	HVS_HOST_RESET 0

struct storvsc_driver_props {
	char		*drv_name;
	char		*drv_desc;
	uint8_t		drv_max_luns_per_target;
	uint32_t	drv_max_ios_per_target;		/* Not used */
	uint32_t	drv_ringbuffer_size;
};

enum hv_storage_type {
	DRIVER_BLKVSC,
	DRIVER_STORVSC,
	DRIVER_UNKNOWN
};

#define	HS_MAX_ADAPTERS 10

/*
 * Used to check if the host supports mult-channel I/O. The host
 * will set the chan_prop.flag bit to indicate support.
 */
#define	HV_STORAGE_SUPPORTS_MULTI_CHANNEL 0x1

/* {ba6163d9-04a1-4d29-b605-72e2ffb1dc7f} */
static const struct hyperv_guid gStorVscDeviceType = {
	.hv_guid = {0xd9, 0x63, 0x61, 0xba, 0xa1, 0x04, 0x29, 0x4d,
	    0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f}
};

/* {32412632-86cb-44a2-9b5c-50d1417354f5} */
static const struct hyperv_guid gBlkVscDeviceType = {
	.hv_guid = {0x32, 0x26, 0x41, 0x32, 0xcb, 0x86, 0xa2, 0x44,
	    0x9b, 0x5c, 0x50, 0xd1, 0x41, 0x73, 0x54, 0xf5}
};

static struct storvsc_driver_props g_drv_props_table[] = {
	{"blkvsc", "Hyper-V IDE Storage Interface",
	    BLKVSC_MAX_IDE_DISKS_PER_TARGET, BLKVSC_MAX_IO_REQUESTS, 0},
	{"storvsc", "Hyper-V SCSI Storage Interface",
	    STORVSC_MAX_LUNS_PER_TARGET, STORVSC_MAX_IO_REQUESTS, 0}
};

/*
 * Sense buffer size changed in win8; have a run-time
 * variable to track the size we should use.
 */
static int sense_buffer_size = PRE_WIN8_STORVSC_SENSE_BUFFER_SIZE;

/*
 * The storage protocol version is determined during the
 * initial exchange with the host.  It will indicate which
 * storage functionality is available in the host.
 */
static int vmstor_proto_version;

struct vmstor_proto {
	int proto_version;
	int sense_buffer_size;
	int vmscsi_size_delta;
};

static const struct vmstor_proto vmstor_proto_list[] = {
	{
	    VMSTOR_PROTOCOL_VERSION_WIN10,
	    POST_WIN7_STORVSC_SENSE_BUFFER_SIZE,
	    0
	},
	{
	    VMSTOR_PROTOCOL_VERSION_WIN8_1,
	    POST_WIN7_STORVSC_SENSE_BUFFER_SIZE,
	    0
	},
	{
	    VMSTOR_PROTOCOL_VERSION_WIN8,
	    POST_WIN7_STORVSC_SENSE_BUFFER_SIZE,
	    0
	},
	{
	    VMSTOR_PROTOCOL_VERSION_WIN7,
	    PRE_WIN8_STORVSC_SENSE_BUFFER_SIZE,
	    sizeof (struct vmscsi_win8_extension),
	},
	{
	    VMSTOR_PROTOCOL_VERSION_WIN6,
	    PRE_WIN8_STORVSC_SENSE_BUFFER_SIZE,
	    sizeof (struct vmscsi_win8_extension),
	}
};

typedef struct storvsc_stats {
	kstat_named_t vscstat_reads;
	kstat_named_t vscstat_writes;
	kstat_named_t vscstat_non_rw;
	kstat_named_t vscstat_timeouts;
	kstat_named_t vscstat_pending;
	kstat_named_t vscstat_chansend[MAXCPU];
} storvsc_stats_t;

#define	VSC_INCR_STAT(sc, x)						\
	if ((sc)->hs_stats != NULL) {					\
		storvsc_stats_t *sp;					\
		sp = (storvsc_stats_t *)(sc)->hs_stats->ks_data;	\
		atomic_inc_64(&sp->x.value.ui64);			\
	}

#define	VSC_DECR_STAT(sc, x) \
	if ((sc)->hs_stats != NULL) {					\
		storvsc_stats_t *sp;					\
		sp = (storvsc_stats_t *)(sc)->hs_stats->ks_data;	\
		atomic_dec_64(&sp->x.value.ui64);			\
	}

#define	HS_WARN(dip, fmt...)	dev_err((dip), CE_WARN, fmt)
#define	HS_NOTE(dip, fmt...)	dev_err((dip), CE_NOTE, fmt)

int hs_debug = 0;

#define	HS_DEBUG(dip, level, fmt...) {		\
	if (level <= hs_debug) {		\
		dev_err((dip), CE_NOTE, fmt);	\
	}					\
}


/* static functions */
static int storvsc_attach(dev_info_t *, ddi_attach_cmd_t);
static int storvsc_detach(dev_info_t *, ddi_detach_cmd_t);
static int storvsc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static void hv_storvsc_on_channel_callback(struct vmbus_channel *chan,
    void *xsc);
static enum hv_storage_type storvsc_get_storage_type(dev_info_t *);
static int create_storvsc_request(storvsc_cmd_t *cmd);
static void storvsc_io_done(struct hv_storvsc_request *reqp);
static void storvsc_destroy_pkt(struct scsi_address *, struct scsi_pkt *);
static void storvsc_dmafree(struct scsi_address *, struct scsi_pkt *);
static void storvsc_timeout(void *arg);
static void storvsc_init_kstat(storvsc_softc_t *sc);
static void storvsc_poll(storvsc_cmd_t *cmd);

static struct cb_ops storvsc_cb_ops = {
	.cb_open = scsi_hba_open,
	.cb_close = scsi_hba_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = storvsc_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_str = NULL,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops storvsc_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = ddi_no_info,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = storvsc_attach,
	.devo_detach = storvsc_detach,
	.devo_reset = nodev,
	.devo_cb_ops = &storvsc_cb_ops,
	.devo_bus_ops = NULL,
	.devo_power = NULL,
	.devo_quiesce = ddi_quiesce_not_supported
};

static struct modldrv modldrv = {
	&mod_driverops,
	STORVSC_IDENT,
	&storvsc_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

static void *storvsc_sstate;

static ddi_dma_attr_t storvsc_io_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000ull,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0xFFF,
	.dma_attr_align =	0x0000000000001000ull,
	.dma_attr_burstsizes =	0x0000000000000FFFull,
	.dma_attr_minxfer =	0x00000001,
	.dma_attr_maxxfer =	STORVSC_DATA_SIZE_MAX,
	.dma_attr_seg =		STORVSC_DATA_SEGSZ_MAX - 1,
	.dma_attr_sgllen =	STORVSC_DATA_SEGCNT_MAX,
	.dma_attr_granular =	512,
	.dma_attr_flags =	DDI_DMA_FLAGERR
};

static void
storvsc_subchan_attach(struct storvsc_softc *sc,
    struct vmbus_channel *new_channel)
{
	struct vmstor_chan_props props;

	(void) memset(&props, 0, sizeof (props));

	vmbus_chan_cpu_rr(new_channel);
	VERIFY0(vmbus_chan_open(new_channel,
	    sc->hs_drv_props->drv_ringbuffer_size,
	    sc->hs_drv_props->drv_ringbuffer_size,
	    (void *)&props,
	    sizeof (struct vmstor_chan_props),
	    hv_storvsc_on_channel_callback, sc));
}

/*
 * @brief Send multi-channel creation request to host
 *
 * @param device  a Hyper-V device pointer
 * @param max_chans  the max channels supported by vmbus
 */
static void
storvsc_send_multichannel_request(struct storvsc_softc *sc, int max_subch)
{
	struct vmbus_channel **subchan;
	struct hv_storvsc_request *request;
	struct vstor_packet *vstor_packet;
	uint16_t request_subch;
	int i;

	/* get sub-channel count that need to create */
	request_subch = MIN(max_subch, max_ncpus - 1);

	request = &sc->hs_init_req;

	/* request the host to create multi-channel */
	(void) memset(request, 0, sizeof (struct hv_storvsc_request));

	sema_init(&request->synch_sema, 0, ("stor_synch_sema"),
	    SEMA_DRIVER, NULL);

	vstor_packet = &request->vstor_packet;

	vstor_packet->operation = VSTOR_OPERATION_CREATE_MULTI_CHANNELS;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;
	vstor_packet->u.multi_channels_cnt = request_subch;

	VERIFY0(vmbus_chan_send(sc->hs_chan,
	    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
	    vstor_packet, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)request));

	sema_p(&request->synch_sema);

	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETEIO ||
	    vstor_packet->status != 0) {
		HS_WARN(sc->hs_dip,
		    "Storvsc_error: create multi-channel invalid operation "
		    "(%d) or status (%u)",
		    vstor_packet->operation, vstor_packet->status);
		return;
	}

	/* Update channel count */
	sc->hs_nchan = request_subch + 1;

	/* Wait for sub-channels setup to complete. */
	subchan = vmbus_subchan_get(sc->hs_chan, request_subch);

	/* Attach the sub-channels. */
	for (i = 0; i < request_subch; ++i)
		storvsc_subchan_attach(sc, subchan[i]);

	/* Release the sub-channels. */
	vmbus_subchan_rel(subchan, request_subch);

	if (boothowto & RB_VERBOSE) {
		HS_DEBUG(sc->hs_dip, 1, "Storvsc create multi-channel success "
		    "(cnt = %d)!", request_subch + 1);
	}
}

#if TEST_CHANNEL
static int
hv_channel_test(struct storvsc_softc *sc)
{
	struct hv_storvsc_request *request;
	struct vstor_packet *vstor_packet;

	request = &sc->hs_init_req;
	(void) memset(request, 0, sizeof (struct hv_storvsc_request));
	vstor_packet = &request->vstor_packet;
	request->hvs_cmd.cmd_sc = sc;

	sema_init(&request->synch_sema, 0, ("stor_synch_sema"),
	    SEMA_DRIVER, NULL);

	/*
	 * Query channel properties
	 */
	(void) memset(vstor_packet, 0, sizeof (struct vstor_packet));
	vstor_packet->operation = VSTOR_OPERATION_QUERYPROPERTIES;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	int ret = vmbus_chan_send(sc->hs_chan,
	    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
	    vstor_packet, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)request);

	sema_p(&request->synch_sema);
	sema_destroy(&request->synch_sema);
	return (ret);
}
#endif

/*
 * @brief initialize channel connection to parent partition
 *
 * @param dev  a Hyper-V device pointer
 * @returns  0 on success, non-zero error on failure
 */
static int
hv_storvsc_channel_init(struct storvsc_softc *sc)
{
	int ret = 0, i;
	struct hv_storvsc_request *request = &sc->hs_init_req;
	struct vstor_packet *vstor_packet = &request->vstor_packet;
	uint16_t max_subch = 0;
	boolean_t support_multichannel = B_FALSE;
	uint32_t version;

	(void) memset(request, 0, sizeof (struct hv_storvsc_request));
	request->hvs_cmd.cmd_sc = sc;

	/*
	 * Initiate the vsc/vsp initialization protocol on the open channel
	 */
	sema_init(&request->synch_sema, 0, ("stor_synch_sema"),
	    SEMA_DRIVER, NULL);

	vstor_packet->operation = VSTOR_OPERATION_BEGININITIALIZATION;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	ret = vmbus_chan_send(sc->hs_chan,
	    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
	    vstor_packet, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)request);

	if (ret != 0)
		goto cleanup;

	HS_DEBUG(sc->hs_dip, 1, "channel_init: begin initialization sent...");

	sema_p(&request->synch_sema);

	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETEIO ||
	    vstor_packet->status != 0) {
		HS_WARN(sc->hs_dip,
		    "channel_init: begin initialization failed! "
		    "operation: 0x%x, status: 0x%x",
		    vstor_packet->operation, vstor_packet->status);
		/* TODO:  ret = -1 */
		ASSERT(0);
		goto cleanup;
	}

	HS_DEBUG(sc->hs_dip, 1, "channel_init: begin initialization done.");

	for (i = 0; i < sizeof (vmstor_proto_list) /
	    sizeof (vmstor_proto_list[0]); i++) {
		/* reuse the packet for version range supported */

		(void) memset(vstor_packet, 0, sizeof (struct vstor_packet));
		vstor_packet->operation = VSTOR_OPERATION_QUERYPROTOCOLVERSION;
		vstor_packet->flags = REQUEST_COMPLETION_FLAG;

		vstor_packet->u.version.major_minor =
		    vmstor_proto_list[i].proto_version;

		/* revision is only significant for Windows guests */
		vstor_packet->u.version.revision = 0;

		ret = vmbus_chan_send(sc->hs_chan,
		    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
		    vstor_packet, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)request);

		if (ret != 0)
			goto cleanup;

		sema_p(&request->synch_sema);

		if (vstor_packet->operation != VSTOR_OPERATION_COMPLETEIO) {
			ret = EINVAL;
			goto cleanup;
		}
		if (vstor_packet->status == 0) {
			vmstor_proto_version =
			    vmstor_proto_list[i].proto_version;
			sense_buffer_size =
			    vmstor_proto_list[i].sense_buffer_size;
			vmscsi_size_delta =
			    vmstor_proto_list[i].vmscsi_size_delta;
			break;
		}
	}

	if (sense_buffer_size < SENSE_LENGTH) {
		HS_WARN(sc->hs_dip,
		    "sense_buffer size < SENSE_LENGTH, %d < %d",
		    (int)sense_buffer_size, (int)SENSE_LENGTH);
	}

	if (vstor_packet->status != 0) {
		ret = EINVAL;
		goto cleanup;
	}

	/*
	 * Query channel properties
	 */
	(void) memset(vstor_packet, 0, sizeof (struct vstor_packet));
	vstor_packet->operation = VSTOR_OPERATION_QUERYPROPERTIES;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	ret = vmbus_chan_send(sc->hs_chan,
	    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
	    vstor_packet, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)request);

	if (ret != 0)
		goto cleanup;

	HS_DEBUG(sc->hs_dip, 1, "channel_init: query properties sent...");

	sema_p(&request->synch_sema);

	/* TODO: Check returned version */
	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETEIO ||
	    vstor_packet->status != 0) {
		goto cleanup;
	}

	HS_DEBUG(sc->hs_dip, 1, "channel_init: query properties done.");

	max_subch = vstor_packet->u.chan_props.max_channel_cnt;
	if (hv_storvsc_chan_cnt > 0 && hv_storvsc_chan_cnt < (max_subch + 1))
		max_subch = hv_storvsc_chan_cnt - 1;

	/* multi-channels feature is supported by WIN8 and above version */
	version = vmbus_get_version();
	if (version != VMBUS_VERSION_WIN7 && version != VMBUS_VERSION_WS2008 &&
	    (vstor_packet->u.chan_props.flags &
	    HV_STORAGE_SUPPORTS_MULTI_CHANNEL)) {
		support_multichannel = B_TRUE;
	}

	HS_DEBUG(sc->hs_dip, 1, "channel_init: channel properties:");
	HS_DEBUG(sc->hs_dip, 1, "max_chans: %d, version: 0x%x", max_subch + 1,
	    version);
	HS_DEBUG(sc->hs_dip, 1, "proto_ver: 0x%x, path_id: 0x%x, "
	    "target_id: 0x%x", vstor_packet->u.chan_props.proto_ver,
	    vstor_packet->u.chan_props.path_id,
	    vstor_packet->u.chan_props.target_id);
	HS_DEBUG(sc->hs_dip, 1, "unique_id: 0x%"PRIx64,
	    vstor_packet->u.chan_props.unique_id);

	dev_err(sc->hs_dip, CE_CONT, "?max chans %d%s\n", max_subch + 1,
	    support_multichannel ? ", multi-chan capable" : "");

	(void) memset(vstor_packet, 0, sizeof (struct vstor_packet));
	vstor_packet->operation = VSTOR_OPERATION_ENDINITIALIZATION;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	ret = vmbus_chan_send(sc->hs_chan,
	    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
	    vstor_packet, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)request);

	if (ret != 0) {
		goto cleanup;
	}

	HS_DEBUG(sc->hs_dip, 1, "channel_init: end initialization sent...");

	sema_p(&request->synch_sema);

	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETEIO ||
	    vstor_packet->status != 0)
		goto cleanup;

	HS_DEBUG(sc->hs_dip, 1, "channel_init: end initialization done.");

	/*
	 * If multi-channel is supported, send multichannel create
	 * request to host.
	 */
	if (support_multichannel && max_subch > 0)
		storvsc_send_multichannel_request(sc, max_subch);
cleanup:
	sema_destroy(&request->synch_sema);
	return (ret);
}

/*
 * @brief Open channel connection to parent partition StorVSP driver
 *
 * Open and initialize channel connection to parent partition StorVSP driver.
 *
 * @param pointer to a Hyper-V device
 * @returns 0 on success, non-zero error on failure
 */
static int
hv_storvsc_connect_vsp(struct storvsc_softc *sc)
{
	int ret = 0;
	struct vmstor_chan_props props;

	(void) memset(&props, 0, sizeof (struct vmstor_chan_props));

	/*
	 * Open the channel
	 */
	vmbus_chan_cpu_rr(sc->hs_chan);
	ret = vmbus_chan_open(
	    sc->hs_chan,
	    sc->hs_drv_props->drv_ringbuffer_size,
	    sc->hs_drv_props->drv_ringbuffer_size,
	    (void *)&props,
	    sizeof (struct vmstor_chan_props),
	    hv_storvsc_on_channel_callback, sc);

	if (ret != 0)
		return (ret);

	ret = hv_storvsc_channel_init(sc);
	return (ret);
}

#if HVS_HOST_RESET
static int
hv_storvsc_host_reset(struct storvsc_softc *sc)
{
	int ret = 0;

	struct hv_storvsc_request *request;
	struct vstor_packet *vstor_packet;

	request = &sc->hs_reset_req;
	request->hvs_cmd.cmd_sc = sc;
	vstor_packet = &request->vstor_packet;

	sema_init(&request->synch_sema, 0, ("stor_synch_sema"),
	    SEMA_DRIVER, NULL);

	vstor_packet->operation = VSTOR_OPERATION_RESETBUS;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	ret = vmbus_chan_send(dev->channel,
	    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
	    vstor_packet, VSTOR_PKT_SIZE,
	    (uint64_t)(uintptr_t)&sc->hs_reset_req);

	if (ret != 0) {
		goto cleanup;
	}

	sema_p(&request->synch_sema);

	/*
	 * At this point, all outstanding requests in the adapter
	 * should have been flushed out and return to us
	 */

cleanup:
	sema_destroy(&request->synch_sema);
	return (ret);
}
#endif /* HVS_HOST_RESET */

/*
 * @brief Function to initiate an I/O request
 *
 * @param device Hyper-V device pointer
 * @param request pointer to a request structure
 * @returns 0 on success, non-zero error on failure
 */
static int
hv_storvsc_io_request(struct storvsc_softc *sc,
    struct hv_storvsc_request *request)
{
	struct vstor_packet *vstor_packet = &request->vstor_packet;
	struct vmbus_channel *outgoing_channel = NULL;
	int ret = 0, ch_sel;

	vstor_packet->flags |= REQUEST_COMPLETION_FLAG;
	vstor_packet->u.vm_srb.length =
	    sizeof (struct vmscsi_req) - vmscsi_size_delta;
	vstor_packet->u.vm_srb.sense_info_len = sense_buffer_size;
	vstor_packet->u.vm_srb.transfer_len =
	    request->prp_list.gpa_range.gpa_len;
	vstor_packet->operation = VSTOR_OPERATION_EXECUTESRB;

	/*
	 * XXX - investigate to see if sending I/O to the same lun across
	 * different channels is problematic.
	 */
	ch_sel = (vstor_packet->u.vm_srb.lun + CPU->cpu_id) % sc->hs_nchan;
	outgoing_channel = sc->hs_sel_chan[ch_sel];

	if (request->prp_list.gpa_range.gpa_len) {
		ret = vmbus_chan_send_prplist(outgoing_channel,
		    &request->prp_list.gpa_range, request->prp_cnt,
		    vstor_packet, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)request);
		HS_DEBUG(sc->hs_dip, 4,
		    "vmbus_chan_send_prplist - packet: %p, req: %p, ret %d",
		    (void *)vstor_packet, (void *)request, ret);
	} else {
		ret = vmbus_chan_send(outgoing_channel,
		    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
		    vstor_packet, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)request);
		HS_DEBUG(sc->hs_dip, 4,
		    "vmbus_chan_send - packet: %p, req: %p, ret %d",
		    (void *)vstor_packet, (void *)request, ret);
	}

	/* statistic for successful request sending on each channel */
	if (!ret) {
		VSC_INCR_STAT(sc, vscstat_chansend[ch_sel]);
	}

	if (ret != 0) {
		HS_WARN(sc->hs_dip, "Unable to send packet %p ret %d",
		    (void *)vstor_packet, ret);
	} else {
		switch (vstor_packet->u.vm_srb.u.cdb[0]) {
		case SCMD_READ:
		case SCMD_READ_G1:
			VSC_INCR_STAT(sc, vscstat_reads);
			break;
		case SCMD_WRITE:
		case SCMD_WRITE_G1:
			VSC_INCR_STAT(sc, vscstat_writes);
			break;
		default:
			VSC_INCR_STAT(sc, vscstat_non_rw);
			break;
		}
	}
	/*
	 * Always increment the outstanding and pending counters
	 * even if there is an error. They will get decremented
	 * when we call storvsc_complete_command().
	 */
	atomic_inc_32(&sc->hs_num_out_reqs);
	VSC_INCR_STAT(sc, vscstat_pending);

	return (ret);
}

/*
 * Process IO_COMPLETION_OPERATION and ready
 * the result to be completed for upper layer
 * processing.
 */
static void
hv_storvsc_on_iocompletion(struct storvsc_softc *sc,
    struct vstor_packet *vstor_packet, struct hv_storvsc_request *request)
{
	struct vmscsi_req *vm_srb;
	storvsc_cmd_t *cmd = &request->hvs_cmd;

	vm_srb = &vstor_packet->u.vm_srb;

	HS_DEBUG(sc->hs_dip, 3,
	    "%s completed, cmd: 0x%x, request: 0x%p"
	    " status: 0x%x, target: %d, lun: %d", __func__,
	    vm_srb->u.cdb[0], (void *)request, vm_srb->scsi_status,
	    cmd->cmd_target, cmd->cmd_lun);

	/*
	 * Copy some fields of the host's response into the request structure,
	 * because the fields will be used later in storvsc_io_done().
	 */
	request->vstor_packet.u.vm_srb.scsi_status = vm_srb->scsi_status;
	request->vstor_packet.u.vm_srb.srb_status = vm_srb->srb_status;
	request->vstor_packet.u.vm_srb.transfer_len = vm_srb->transfer_len;

	if (((vm_srb->scsi_status & 0xFF) == STATUS_CHECK) &&
	    (vm_srb->srb_status & SRB_STATUS_AUTOSENSE_VALID)) {
		/* Autosense data available */

		ASSERT3U(vm_srb->sense_info_len, <=, request->sense_info_len);

		(void) memcpy(request->sense_data, vm_srb->u.sense_data,
		    vm_srb->sense_info_len);

		request->sense_info_len = vm_srb->sense_info_len;
	}

	/*
	 * The current SCSI handling on the host side does
	 * not correctly handle:
	 * INQUIRY command with page code parameter set to 0x80
	 * MODE_SENSE command with cmd[2] == 0x1c
	 *
	 * Setup srb and scsi status so this won't be fatal.
	 * We do this so we can distinguish truly fatal failues
	 * (srb status == 0x4) and off-line the device in that case.
	 */
	if ((vm_srb->srb_status & SRB_STATUS_ERROR) &&
	    (((vm_srb->u.cdb[0] == SCMD_INQUIRY) &&
	    (vm_srb->u.cdb[2] == 0x80)) ||
	    (vm_srb->u.cdb[0] == SCMD_MODE_SENSE))) {
		request->vstor_packet.u.vm_srb.scsi_status = STATUS_GOOD;
		request->vstor_packet.u.vm_srb.srb_status = SRB_STATUS_SUCCESS;
	}

	/* Complete request by passing to the SCSA layer */
	storvsc_io_done(request);
}

static void
hv_storvsc_on_channel_callback(struct vmbus_channel *channel, void *xsc)
{
	int ret = 0;
	struct storvsc_softc *sc = xsc;
	int bytes_recvd;
	uint64_t request_id = 0;
	uint8_t packet[roundup(sizeof (struct vstor_packet), 8)];
	struct hv_storvsc_request *request;
	struct vstor_packet *vstor_packet;

	bytes_recvd = roundup(VSTOR_PKT_SIZE, 8);
	ret = vmbus_chan_recv(channel, packet, &bytes_recvd, &request_id);
	ASSERT3S(ret, !=, ENOBUFS);
	/* XXX check bytes_recvd to make sure that it contains enough data */

	while ((ret == 0) && (bytes_recvd > 0)) {
		request = (struct hv_storvsc_request *)(uintptr_t)request_id;
		vstor_packet = (struct vstor_packet *)packet;

		if ((request == &sc->hs_init_req) ||
		    (request == &sc->hs_reset_req)) {
			ASSERT3U(vstor_packet->operation, ==,
			    VSTOR_OPERATION_COMPLETEIO);
			(void) memcpy(&request->vstor_packet, packet,
			    sizeof (struct vstor_packet));
			sema_v(&request->synch_sema);
		} else {
			switch (vstor_packet->operation) {
			case VSTOR_OPERATION_COMPLETEIO:
				if (request == NULL) {
					/* might not be spurious, so panic */
					panic("storvsc received a "
					    "packet with NULL request id in "
					    "COMPLETEIO operation.");
				}

				hv_storvsc_on_iocompletion(sc,
				    vstor_packet, request);
				break;
			case VSTOR_OPERATION_REMOVEDEVICE:
			case VSTOR_OPERATION_ENUMERATE_BUS:
			default:
				HS_NOTE(sc->hs_dip,
				    "operation: %d not yet implemented.",
				    vstor_packet->operation);
				break;
			}
		}

		bytes_recvd = roundup(VSTOR_PKT_SIZE, 8),
		    ret = vmbus_chan_recv(channel, packet, &bytes_recvd,
		    &request_id);
		ASSERT3S(ret, !=, ENOBUFS);
		/*
		 * XXX check bytes_recvd to make sure that it contains
		 * enough data
		 */
	}
}

static void
storvsc_create_chan_sel(struct storvsc_softc *sc)
{
	struct vmbus_channel **subch;
	int i, nsubch;

	sc->hs_sel_chan[0] = sc->hs_chan;
	nsubch = sc->hs_nchan - 1;
	if (nsubch == 0)
		return;

	subch = vmbus_subchan_get(sc->hs_chan, nsubch);
	for (i = 0; i < nsubch; i++)
		sc->hs_sel_chan[i + 1] = subch[i];
	vmbus_subchan_rel(subch, nsubch);
}

static int
req_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	storvsc_softc_t  *sc = cdrarg;
	struct hv_storvsc_request *reqp = (struct hv_storvsc_request *)buf;
	storvsc_cmd_t	*cmd = &(reqp->hvs_cmd);
	struct scsi_address ap;
	int		error;
	int (*callback)(caddr_t) = (kmflags == KM_SLEEP) ? SLEEP_FUNC :
	    NULL_FUNC;

	(void) memset(reqp, 0, sizeof (struct hv_storvsc_request));
	cmd->cmd_sc = sc;

	/*
	 * Allocate cmd_handle, per request initialization done
	 * in req_cache_constructor
	 */
	error = ddi_dma_alloc_handle(sc->hs_dip, &storvsc_io_dma_attr,
	    callback, NULL, &cmd->cmd_handle);
	if (error != DDI_SUCCESS) {
		HS_WARN(sc->hs_dip,
		    "failed to create storvsc dma handle, "
		    "error: 0x%x", error);
		return (-1);
	}

	ap.a_hba_tran = sc->hs_tran;
	ap.a_target = 0;
	ap.a_lun = 0;

	/* Setup ARQ buffer. */
	if ((cmd->cmd_arq_buf = scsi_alloc_consistent_buf(&ap,
	    (struct buf *)NULL, sense_buffer_size, B_READ,
	    callback, NULL)) == NULL) {
		HS_WARN(sc->hs_dip, "failed to allocate ARQ buffer");
		goto free_handle;
	}
	cmd->cmd_rqslen = sense_buffer_size;

	return (0);
free_handle:
	ddi_dma_free_handle(&cmd->cmd_handle);

	return (-1);
}

/* ARGSUSED cdrarg */
static void
req_cache_destructor(void *buf, void *cdrarg)
{
	struct hv_storvsc_request *reqp = (struct hv_storvsc_request *)buf;
	storvsc_cmd_t	*cmd = &(reqp->hvs_cmd);

	if (cmd->cmd_handle) {
		ddi_dma_free_handle(&cmd->cmd_handle);
		cmd->cmd_handle = NULL;
	}

	if (cmd->cmd_arq_buf) {
		scsi_free_consistent_buf(cmd->cmd_arq_buf);
		cmd->cmd_arq_buf = NULL;
	}
}


static int
storvsc_init_requests(struct storvsc_softc *sc)
{
	char		buf[32];

	(void) sprintf(buf, "storvsc%d_cache", sc->hs_instance);
	sc->hs_req_cache = kmem_cache_create(buf,
	    sizeof (struct hv_storvsc_request), 0,
	    req_cache_constructor, req_cache_destructor, NULL, (void *)sc,
	    NULL, 0);

	if (sc->hs_req_cache == NULL)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static void
storvsc_fini_requests(struct storvsc_softc *sc)
{
	kmem_cache_destroy(sc->hs_req_cache);
	sc->hs_req_cache = NULL;
}

static int
create_storvsc_request(storvsc_cmd_t *cmd)
{
	struct scsi_pkt *pkt = CMD2PKT(cmd);
	struct hv_storvsc_request *reqp = PKT2REQ(pkt);

	/* refer to struct vmscsi_req for meanings of these two fields */
	reqp->vstor_packet.u.vm_srb.port = cmd->cmd_sc->hs_instance;
	reqp->vstor_packet.u.vm_srb.path_id = 0;

	reqp->vstor_packet.u.vm_srb.target_id = cmd->cmd_target;
	reqp->vstor_packet.u.vm_srb.lun = cmd->cmd_lun;
	reqp->vstor_packet.u.vm_srb.cdb_len = cmd->cmd_len;

	bcopy(cmd->cmd_cdb, &reqp->vstor_packet.u.vm_srb.u.cdb,	cmd->cmd_len);

	if (hv_storvsc_use_win8ext_flags) {
		reqp->vstor_packet.u.vm_srb.win8_extension.time_out_value =
		    pkt->pkt_time;
		reqp->vstor_packet.u.vm_srb.win8_extension.srb_flags |=
		    SRB_FLAGS_DISABLE_SYNCH_TRANSFER;
	}

	switch (cmd->cmd_flags & STORVSC_FLAG_IO_MASK) {
	case STORVSC_FLAG_IO_WRITE:
		reqp->vstor_packet.u.vm_srb.data_in = WRITE_TYPE;
		if (hv_storvsc_use_win8ext_flags) {
			reqp->vstor_packet.u.vm_srb.win8_extension.srb_flags |=
			    SRB_FLAGS_DATA_OUT;
		}
		break;
	case STORVSC_FLAG_IO_READ:
		reqp->vstor_packet.u.vm_srb.data_in = READ_TYPE;
		if (hv_storvsc_use_win8ext_flags) {
			reqp->vstor_packet.u.vm_srb.win8_extension.srb_flags |=
			    SRB_FLAGS_DATA_IN;
		}
		break;
	case 0x00: /* no data transfer */
		reqp->vstor_packet.u.vm_srb.data_in = UNKNOWN_TYPE;
		if (hv_storvsc_use_win8ext_flags) {
			/* LINTED */
			reqp->vstor_packet.u.vm_srb.win8_extension.srb_flags |=
			    SRB_FLAGS_NO_DATA_TRANSFER;
		}
		break;
	default:
		HS_WARN(cmd->cmd_sc->hs_dip,
		    "Error: cmd %p - unexpected data direction: 0x%x",
		    (void *)cmd, (cmd->cmd_flags & STORVSC_FLAG_IO_MASK));
		return (EINVAL);
	}

	/*
	 * Since we always allocate arq_buf, we will need it to get sense data
	 */
	reqp->sense_data = (caddr_t)cmd->cmd_arq_buf->b_un.b_addr;
	reqp->sense_info_len = cmd->cmd_rqslen;

	if ((cmd->cmd_flags & STORVSC_FLAG_XARQ) != 0)
		bzero(reqp->sense_data, cmd->cmd_rqslen);

	reqp->pkt = pkt;
	return (0);
}


static void
storvsc_set_command_status(storvsc_cmd_t *cmd)
{
	int	stats;

	if (cmd->cmd_flags & STORVSC_FLAG_TIMED_OUT) {
		cmd->cmd_pkt->pkt_reason = CMD_TIMEOUT;
		cmd->cmd_pkt->pkt_statistics |= (STAT_TIMEOUT);
		cmd->cmd_pkt->pkt_state |= (STATE_GOT_BUS |
		    STATE_GOT_TARGET | STATE_SENT_CMD);
	} else if (cmd->cmd_flags & STORVSC_FLAG_ABORTED) {
		cmd->cmd_pkt->pkt_reason = CMD_ABORTED;
		cmd->cmd_pkt->pkt_statistics |= (STAT_TIMEOUT|STAT_ABORTED);
	} else if (cmd->cmd_flags & STORVSC_FLAGS_RESET) {
		cmd->cmd_pkt->pkt_reason = CMD_RESET;
		if (cmd->cmd_flags & STORVSC_FLAG_RESET_BUS)
			stats = STAT_BUS_RESET;
		else
			stats = STAT_DEV_RESET;
		cmd->cmd_pkt->pkt_statistics |= stats;
	} else if (cmd->cmd_flags & STORVSC_FLAG_SRB_ERROR) {
		cmd->cmd_pkt->pkt_reason = CMD_TRAN_ERR;
		cmd->cmd_pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
	} else if (cmd->cmd_flags & STORVSC_FLAG_DEV_GONE) {
		cmd->cmd_pkt->pkt_reason = CMD_DEV_GONE;
		cmd->cmd_pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
	}
}

static void
storvsc_complete_command(storvsc_cmd_t *cmd)
{
	struct scsi_pkt *pkt = CMD2PKT(cmd);
	storvsc_softc_t *sc = cmd->cmd_sc;

	atomic_dec_32(&sc->hs_num_out_reqs);
	VSC_DECR_STAT(sc, vscstat_pending);

	if (sc->hs_drain_notify && (sc->hs_num_out_reqs == 0)) {
		sema_v(&sc->hs_drain_sema);
	}

	if (pkt != NULL) {
		if ((cmd->cmd_flags & STORVSC_FLAG_IO_IOPB) &&
		    (cmd->cmd_flags & STORVSC_FLAG_IO_READ)) {
			(void) ddi_dma_sync(cmd->cmd_handle, 0, 0,
			    DDI_DMA_SYNC_FORCPU);
		}

		storvsc_set_command_status(cmd);
		cmd->cmd_flags |= STORVSC_FLAG_DONE;
		cmd->cmd_flags &= ~STORVSC_FLAG_TRANSPORT;
		membar_producer();

		if (((pkt->pkt_flags & FLAG_NOINTR) == 0) && pkt->pkt_comp) {
			(*pkt->pkt_comp)(pkt);
		}
	}
}

static void
prepare_pkt(storvsc_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);

	/*
	 * Reinitialize some fields because the packet may
	 * have been resubmitted.
	 */
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;

	/* Zero status byte */
	*(pkt->pkt_scbp) = 0;

	if (cmd->cmd_flags & STORVSC_FLAG_DMA_VALID) {
		ASSERT(cmd->cmd_dma_count != 0);
		pkt->pkt_resid = cmd->cmd_dma_count;

		/*
		 * Consistent packets need to be sync'ed first
		 * (only for data going out).
		 */
		if ((cmd->cmd_flags & STORVSC_FLAG_IO_IOPB) != 0) {
			(void) ddi_dma_sync(cmd->cmd_handle, 0, 0,
			    DDI_DMA_SYNC_FORDEV);
		}
	}
}

static int
storvsc_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	storvsc_softc_t  *sc = ap->a_hba_tran->tran_hba_private;
	storvsc_cmd_t    *cmd = PKT2CMD(pkt);
	struct hv_storvsc_request	*reqp = PKT2REQ(pkt);
	boolean_t poll = ((pkt->pkt_flags & FLAG_NOINTR) != 0);
	int rc;

	ASSERT3P(cmd->cmd_pkt, ==, pkt);
	ASSERT3P(cmd->cmd_sc, ==, sc);
	ASSERT3P(reqp, !=, NULL);

	prepare_pkt(cmd);

	cmd->cmd_target = ap->a_target;
	cmd->cmd_lun = ap->a_lun;
	cmd->cmd_flags |= STORVSC_FLAG_TRANSPORT;

	if ((rc = create_storvsc_request(cmd)) != 0) {
		HS_WARN(sc->hs_dip,
		    "failed to create storvsc request, err: %d", rc);
		return (TRAN_FATAL_ERROR);
	}

	/* Setup timeout before submitting actual I/O */
	if (!poll && pkt->pkt_time > 0) {
		reqp->timeout_id = timeout(storvsc_timeout, reqp,
		    SEC_TO_TICK(pkt->pkt_time));
	} else {
		reqp->timeout_id = NULL;
	}

	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET);

	if ((rc = hv_storvsc_io_request(sc, reqp)) != 0) {
		HS_WARN(sc->hs_dip,
		    "hv_storvsc_io_request failed with %d", rc);
		pkt->pkt_state |= STAT_ABORTED;
		pkt->pkt_reason = CMD_TRAN_ERR;
		storvsc_complete_command(cmd);
		return (TRAN_BADPKT);
	}

	pkt->pkt_state |= STATE_SENT_CMD;

	if (poll)
		storvsc_poll(cmd);

	HS_DEBUG(sc->hs_dip, 3,
	    "%s: submitted cmd: 0x%x, pkt: %p, "
	    "timeout: %d, target: %d, lun: %d", __func__,
	    cmd->cmd_cdb[0], (void *)pkt, pkt->pkt_time,
	    cmd->cmd_target, cmd->cmd_lun);
	return (TRAN_ACCEPT);
}

static int
storvsc_reset(struct scsi_address *ap, int level)
{
	storvsc_softc_t *sc = AP2PRIV(ap);

#if HVS_HOST_RESET
	int res;
	if ((res = hv_storvsc_host_reset(sc)) != 0) {
		HS_WARN(sc->hs_dip,
		    "hv_storvsc_host_reset failed with %d", res);
		return (0);
	}
	return (1);
#else
	HS_WARN(sc->hs_dip, "%s reset not supported.",
	    (level == RESET_TARGET) ? "dev" : "bus");

	/*
	 * In order to allow a storvsc dump device, return success
	 * when in the middle of a crash dump.
	 */
	if (do_polled_io || panicstr != NULL)
		return (1);
	return (0);
#endif	/* HVS_HOST_RESET */
}

/*
 * Hyper-V guarantees that every valid I/O will be returned so
 * there is no need to abort a command.
 */
/* ARGSUSED */
static int
storvsc_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	return (0);
}

/* ARGSUSED */
static int
storvsc_getcap(struct scsi_address *ap, char *cap, int tgtonly)
{
	if (cap == NULL)
		return (-1);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_CDB_LEN:
		return (CDB_GROUP4);
	/* enable tag queuing and disconnected mode */
	case SCSI_CAP_ARQ:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_DISCONNECT:
		return (1);
	case SCSI_CAP_SCSI_VERSION:
		return (SCSI_VERSION_2);
	default:
		return (-1);
	}
}

/* ARGSUSED */
static int
storvsc_setcap(struct scsi_address *ap, char *cap, int value, int tgtonly)
{
	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_TAGGED_QING:
		return (1);
	default:
		return (0);
	}
}

static void
storvsc_cmd_ext_free(storvsc_cmd_t *cmd)
{
	struct scsi_pkt *pkt = CMD2PKT(cmd);

	if (cmd->cmd_flags & STORVSC_FLAG_CDB_EXT) {
		kmem_free(pkt->pkt_cdbp, cmd->cmd_len);
		cmd->cmd_flags &= ~STORVSC_FLAG_CDB_EXT;
	}
	if (cmd->cmd_flags & STORVSC_FLAG_SCB_EXT) {
		kmem_free(pkt->pkt_scbp, cmd->cmd_statuslen);
		cmd->cmd_flags &= ~STORVSC_FLAG_SCB_EXT;
	}
	if (cmd->cmd_flags & STORVSC_FLAG_PRIV_EXT) {
		kmem_free(pkt->pkt_private, cmd->cmd_tgtlen);
		cmd->cmd_flags &= ~STORVSC_FLAG_PRIV_EXT;
	}
}

static int
storvsc_cmd_ext_alloc(storvsc_cmd_t *cmd, int kf)
{
	void		*buf;
	struct scsi_pkt *pkt = CMD2PKT(cmd);

	if (cmd->cmd_len > sizeof (cmd->cmd_cdb)) {
		if ((buf = kmem_zalloc(cmd->cmd_len, kf)) == NULL)
			goto out;
		pkt->pkt_cdbp = buf;
		cmd->cmd_flags |= STORVSC_FLAG_CDB_EXT;
	}

	if (cmd->cmd_statuslen > sizeof (cmd->cmd_scb)) {
		if ((buf = kmem_zalloc(cmd->cmd_statuslen, kf)) == NULL)
			goto out;
		pkt->pkt_scbp = buf;
		cmd->cmd_flags |= STORVSC_FLAG_SCB_EXT;
		cmd->cmd_rqslen = (cmd->cmd_statuslen - sizeof (cmd->cmd_scb));
		/* XXX - investigate */
		cmd->cmd_rqslen = MIN(SENSE_BUFFER_SIZE,
		    cmd->cmd_statuslen - sizeof (cmd->cmd_scb));
		ASSERT3U(cmd->cmd_rqslen, <=, SENSE_BUFFER_SIZE);
	}

	if (cmd->cmd_tgtlen > sizeof (cmd->cmd_tgt_priv)) {
		if ((buf = kmem_zalloc(cmd->cmd_tgtlen, kf)) == NULL)
			goto out;
		pkt->pkt_private = buf;
		cmd->cmd_flags |= STORVSC_FLAG_PRIV_EXT;
	}

	return (DDI_SUCCESS);
out:
	storvsc_cmd_ext_free(cmd);

	return (DDI_FAILURE);
}

static struct scsi_pkt *
storvsc_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt, struct buf *bp,
    int cmdlen, int statuslen, int tgtlen, int flags,
    int (*callback)(), caddr_t arg)
{
	struct hv_storvsc_request	*reqp = NULL;
	int		kf = (callback == SLEEP_FUNC) ? KM_SLEEP: KM_NOSLEEP;
	storvsc_softc_t	*sc;
	storvsc_cmd_t	*cmd = NULL;
	boolean_t	is_new;
	int		rc;
	int		i;

	sc = ap->a_hba_tran->tran_hba_private;
	ASSERT(sc != NULL);

	if (ap->a_lun >= sc->hs_num_luns) {
		HS_WARN(sc->hs_dip, "bad lun provided: %d (MAX: %d)",
		    ap->a_lun, sc->hs_num_luns);
		return (NULL);
	}

	/* Allocate a new SCSI packet */
	if (pkt == NULL) {
		ddi_dma_handle_t		saved_handle;
		struct buf			*saved_arqbuf;
		int				saved_rqslen;

		if ((reqp = kmem_cache_alloc(sc->hs_req_cache, kf)) == NULL)
			return (NULL);

		cmd = &reqp->hvs_cmd;
		saved_handle = cmd->cmd_handle;
		saved_arqbuf = cmd->cmd_arq_buf;
		saved_rqslen = cmd->cmd_rqslen;

		bzero(reqp, sizeof (struct hv_storvsc_request));

		cmd->cmd_sc = sc;
		cmd->cmd_handle = saved_handle;
		cmd->cmd_arq_buf = saved_arqbuf;
		cmd->cmd_rqslen = saved_rqslen;

		pkt = &cmd->cmd_cached_pkt;
		pkt->pkt_ha_private = (opaque_t)reqp;
		reqp->pkt = pkt;

		pkt->pkt_address = *ap;
		pkt->pkt_scbp = (uint8_t *)&cmd->cmd_scb;
		pkt->pkt_cdbp = (uint8_t *)&cmd->cmd_cdb;
		pkt->pkt_cdblen = cmdlen;
		pkt->pkt_private = (opaque_t)&cmd->cmd_tgt_priv;

		cmd->cmd_tgtlen = tgtlen;
		cmd->cmd_statuslen = statuslen;
		cmd->cmd_len = cmdlen;
		cmd->cmd_pkt = pkt;

		reqp->vstor_packet.u.vm_srb.cdb_len = cmdlen; /* XXX */

		is_new = B_TRUE;

		/* Allocate extended buffers */
		if ((cmdlen > sizeof (cmd->cmd_cdb)) ||
		    (statuslen > sizeof (cmd->cmd_scb)) ||
		    (tgtlen > sizeof (cmd->cmd_tgt_priv))) {
			if (storvsc_cmd_ext_alloc(cmd, kf) != DDI_SUCCESS) {
				HS_WARN(sc->hs_dip,
				    "extent allocation failed");
				goto out;
			}
		}
	} else {
		cmd = PKT2CMD(pkt);
		ASSERT(cmd->cmd_nwin > 0);
		ASSERT3P(pkt->pkt_cdbp, ==, &cmd->cmd_cdb);
		is_new = B_FALSE;
	}

	ASSERT0(cmd->cmd_flags & STORVSC_FLAG_TRANSPORT);

	/*
	 * upper layer (target) drivers will fill
	 * the cdb before calling "tran_start",
	 * make sure its initialized here.
	 */
	bzero(pkt->pkt_cdbp, sizeof (cmd->cmd_cdb));

	if (flags & PKT_XARQ)
		cmd->cmd_flags |= STORVSC_FLAG_XARQ;

	/* Handle partial DMA transfers */
	if (cmd->cmd_nwin > 0) {
		if (++cmd->cmd_winindex >= cmd->cmd_nwin)
			return (NULL);
		if (ddi_dma_getwin(cmd->cmd_handle, cmd->cmd_winindex,
		    &cmd->cmd_dma_offset, &cmd->cmd_dma_len,
		    &cmd->cmd_cookie, &cmd->cmd_cookiec) == DDI_FAILURE) {
			HS_WARN(sc->hs_dip, "failed activating dma window %d",
			    cmd->cmd_winindex);
			return (NULL);
		}
		goto handle_dma_cookies;
	}

	/* Setup data buffer. */
	if (bp != NULL && bp->b_bcount > 0 &&
	    (cmd->cmd_flags & STORVSC_FLAG_DMA_VALID) == 0) {
		int	dma_flags;

		if (bp->b_flags & B_READ) {
			cmd->cmd_flags |= STORVSC_FLAG_IO_READ;
			dma_flags = DDI_DMA_READ;
		} else {
			cmd->cmd_flags |= STORVSC_FLAG_IO_WRITE;
			dma_flags = DDI_DMA_WRITE;
		}

		if (flags & PKT_CONSISTENT) {
			cmd->cmd_flags |= STORVSC_FLAG_IO_IOPB;
			dma_flags |= DDI_DMA_CONSISTENT;
		}

		if (flags & PKT_DMA_PARTIAL)
			dma_flags |= DDI_DMA_PARTIAL;

		ASSERT(cmd->cmd_handle != NULL);

		rc = ddi_dma_buf_bind_handle(cmd->cmd_handle, bp,
		    dma_flags, callback, arg, &cmd->cmd_cookie,
		    &cmd->cmd_cookiec);

		if (rc == DDI_DMA_PARTIAL_MAP) {
			cmd->cmd_winindex = 0;
			(void) ddi_dma_numwin(cmd->cmd_handle, &cmd->cmd_nwin);
			(void) ddi_dma_getwin(cmd->cmd_handle,
			    cmd->cmd_winindex, &cmd->cmd_dma_offset,
			    &cmd->cmd_dma_len, &cmd->cmd_cookie,
			    &cmd->cmd_cookiec);
		} else if (rc && (rc != DDI_DMA_MAPPED)) {
			HS_WARN(sc->hs_dip,
			    "failed to bind storvsc data request dma, "
			    "error: 0x%x", rc);

			switch (rc) {
			case DDI_DMA_NORESOURCES:
				bioerror(bp, 0);
				break;
			case DDI_DMA_BADATTR:
			case DDI_DMA_NOMAPPING:
				bioerror(bp, EFAULT);
				break;
			case DDI_DMA_TOOBIG:
			default:
				bioerror(bp, EINVAL);
				break;
			}
			cmd->cmd_flags &= ~STORVSC_FLAG_DMA_VALID;
			goto out;
		}
handle_dma_cookies:
		cmd->cmd_flags |= STORVSC_FLAG_DMA_VALID;
		cmd->cmd_dma_count = 0;

		ASSERT(cmd->cmd_cookiec > 0);
		ASSERT3U(cmd->cmd_cookiec, <=, STORVSC_DATA_SEGCNT_MAX);

		HS_DEBUG(sc->hs_dip, 6, "dma_buf_bind, got: %d cookies",
		    cmd->cmd_cookiec);

		/* NOTE: gpa_ofs is from first cookie */
		reqp = PKT2REQ(pkt);
		reqp->prp_list.gpa_range.gpa_ofs =
		    cmd->cmd_cookie.dmac_laddress & PAGEOFFSET;

		/*
		 * Calculate total amount of bytes for this I/O and
		 * store cookies for further processing.
		 */
		for (i = 0; i < cmd->cmd_cookiec; i++) {
			reqp->prp_list.gpa_page[i] =
			    btop(cmd->cmd_cookie.dmac_laddress);

			ASSERT(!P2BOUNDARY(cmd->cmd_cookie.dmac_laddress,
			    cmd->cmd_cookie.dmac_size, PAGESIZE));

			IMPLY(i > 0,
			    (cmd->cmd_cookie.dmac_laddress & PAGEOFFSET) == 0);

			cmd->cmd_dma_count += cmd->cmd_cookie.dmac_size;
			cmd->cmd_total_dma_count += cmd->cmd_cookie.dmac_size;
			ddi_dma_nextcookie(cmd->cmd_handle, &cmd->cmd_cookie);
		}
		reqp->prp_list.gpa_range.gpa_len = cmd->cmd_dma_count;
		ASSERT3U(reqp->prp_list.gpa_range.gpa_len, <=,
		    STORVSC_DATA_SIZE_MAX);
		reqp->prp_cnt = cmd->cmd_cookiec;
		cmd->cmd_bp = bp;

		pkt->pkt_resid = (bp->b_bcount - cmd->cmd_total_dma_count);
	} else {
		reqp->prp_list.gpa_range.gpa_len = 0; /* don't use prp_list */
		cmd->cmd_bp = NULL;
	}
	return (pkt);
out:
	if (is_new) {
		storvsc_destroy_pkt(ap, pkt);
	}

	return (NULL);
}

static void
storvsc_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	storvsc_cmd_t *cmd = PKT2CMD(pkt);
	storvsc_softc_t *sc = AP2PRIV(ap);

	ASSERT3P(sc, ==, cmd->cmd_sc);
	storvsc_dmafree(ap, pkt);
	if ((cmd->cmd_flags & STORVSC_FLAGS_EXT) != 0)
		storvsc_cmd_ext_free(cmd);
	kmem_cache_free(sc->hs_req_cache, PKT2REQ(pkt));
}

/* ARGSUSED ap */
static void
storvsc_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	storvsc_cmd_t	*cmd = PKT2CMD(pkt);

	ASSERT(cmd != NULL);
	if ((cmd->cmd_flags & STORVSC_FLAG_DMA_VALID) != 0) {
		(void) ddi_dma_unbind_handle(cmd->cmd_handle);
		cmd->cmd_flags &= ~STORVSC_FLAG_DMA_VALID;
	}
}

/* ARGSUSED ap pkt */
static void
storvsc_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
}

/* ARGSUSED ap flag callback arg */
static int
storvsc_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg)
{
	return (DDI_FAILURE);
}

static int
storvsc_inquiry_target(storvsc_softc_t *sc, int target, int lun, uchar_t evpd,
    uchar_t page, int (*callback)(caddr_t), caddr_t callback_arg,
    caddr_t buf, int len)
{
	struct scsi_address ap;
	int ret = -1;
	struct buf *b;
	struct scsi_pkt *pkt = NULL;

	ap.a_target = (ushort_t)target;
	ap.a_lun = (uint8_t)lun;
	ap.a_hba_tran = sc->hs_tran;

	if ((b = scsi_alloc_consistent_buf(&ap, (struct buf *)NULL, len, B_READ,
	    callback, callback_arg)) == NULL)
		return (-1);

	if ((pkt = scsi_init_pkt(&ap, (struct scsi_pkt *)NULL, b,
	    CDB_GROUP0, sizeof (struct scsi_arq_status), 0, 0,
	    callback, callback_arg)) == NULL)
		goto free_buf;

	pkt->pkt_cdbp[0] = SCMD_INQUIRY;
	pkt->pkt_cdbp[1] = evpd;
	pkt->pkt_cdbp[2] = page;
	pkt->pkt_cdbp[3] = (len & 0xff00) >> 8;
	pkt->pkt_cdbp[4] = (len & 0x00ff);
	pkt->pkt_cdbp[5] = 0;

	if (buf != NULL)
		bzero(buf, len);
	/* bcopy(cdb, pkt->pkt_cdbp, CDB_GROUP0); */
	bzero((caddr_t)b->b_un.b_addr, len);

	if ((ret = scsi_poll(pkt)) == 0 && buf != NULL)
		bcopy((caddr_t)b->b_un.b_addr, buf, len);

	if (pkt->pkt_reason != CMD_CMPLT)
		ret = -1;

	scsi_free_consistent_buf(b);
	scsi_destroy_pkt(pkt);
	return (ret);
free_buf:
	scsi_free_consistent_buf(b);

	return (-1);
}

static int
storvsc_config_one(dev_info_t *pdip, storvsc_softc_t *sc, int target, int lun,
    dev_info_t **childp)
{
	dev_info_t *dip;
	char *nodename = NULL;
	int ncompatible = 0;
	char **compatible = NULL;
	struct scsi_inquiry inq;
	storvsc_device_t *devnode;
	int dtype;
	int err;
	int rv = 0;
	struct scsi_device *sd;

	HS_DEBUG(sc->hs_dip, 2, "target %d, lun %d, child %p, parent %p",
	    target, lun, (void *)childp, (void *)pdip);

	err = storvsc_inquiry_target(sc, target, lun, 0, 0, NULL_FUNC, 0,
	    (caddr_t)&inq, sizeof (struct scsi_inquiry));
	if (err != 0) {
		HS_DEBUG(sc->hs_dip, 2,
		    "!failed inquiry for target: %d, lun: %d",
		    target, lun);
	}

	/* Find devnode */
	for (devnode = list_head(&sc->hs_devnodes); devnode != NULL;
	    devnode = list_next(&sc->hs_devnodes, devnode)) {
		if (devnode->target == target && devnode->lun == lun)
			break;
	}

	if (devnode != NULL) {
		if (err != 0) {
			/* Target disappeared, drop devnode */
			if (i_ddi_devi_attached(devnode->dip)) {
				char    *devname;
				/* Get full devname */
				devname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

				(void) ddi_deviname(devnode->dip, devname);
				/* Clean cache and name */
				(void) devfs_clean(devnode->pdip, devname + 1,
				    DV_CLEAN_FORCE);
				kmem_free(devname, MAXPATHLEN);
			}
			(void) ndi_devi_offline(devnode->dip, NDI_DEVI_REMOVE);

			list_remove(&sc->hs_devnodes, devnode);
			kmem_free(devnode, sizeof (*devnode));
		} else if (childp != NULL) {
			/* Target exists */
			*childp = devnode->dip;
		}
		return (NDI_SUCCESS);
	} else if (err != 0) {
		/* Target doesn't exist */
		return (NDI_FAILURE);
	}

	dtype = inq.inq_dtype & DTYPE_MASK;
	if (dtype != DTYPE_DIRECT) {
		HS_DEBUG(sc->hs_dip, 2, "invalid dtype: 0x%x for target: %d, "
		    "lun: %d", dtype, target, lun);
		rv = NDI_FAILURE;
		goto out;
	}

	HS_DEBUG(sc->hs_dip, 2,
	    "Got inq status - dtype: 0x%x, vid: %s, pid: %s",
	    inq.inq_dtype, inq.inq_vid, inq.inq_pid);

	scsi_hba_nodename_compatible_get(&inq, NULL, dtype, NULL,
	    &nodename, &compatible, &ncompatible);
	if (nodename == NULL) {
		HS_WARN(sc->hs_dip,
		    "!failed hba_nodename_compatible for instance: %d", target);
		rv = NDI_FAILURE;
		goto out;
	}

	HS_DEBUG(sc->hs_dip, 2, "target %d, lun %d, found nodename: %s",
	    target, lun, nodename);

	if (ndi_devi_alloc(pdip, nodename, DEVI_SID_NODEID,
	    &dip) != NDI_SUCCESS) {
		HS_WARN(sc->hs_dip, "!failed to alloc device instance");
		rv = NDI_FAILURE;
		goto out;
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "device-type", "scsi") != DDI_PROP_SUCCESS ||
	    ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    SCSI_ADDR_PROP_TARGET, target) != DDI_PROP_SUCCESS ||
	    ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    SCSI_ADDR_PROP_LUN, lun) != DDI_PROP_SUCCESS ||
	    ndi_prop_update_int64(DDI_DEV_T_NONE, dip,
	    SCSI_ADDR_PROP_LUN64, (int64_t)lun) != DDI_PROP_SUCCESS ||
	    ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "compatible", compatible, ncompatible) != DDI_PROP_SUCCESS) {
		HS_WARN(sc->hs_dip,
		    "!failed to update props for target %d", target);
		(void) ndi_devi_free(dip);
		rv = NDI_FAILURE;
		goto out;
	}

	sd = kmem_zalloc(sizeof (struct scsi_device), KM_SLEEP);
	sd->sd_address.a_hba_tran = sc->hs_tran;
	sd->sd_address.a_target = (uint16_t)target;
	sd->sd_address.a_lun = (uint8_t)lun;
	sd->sd_dev = dip;
	/*
	 * This checks if pages 0x80 & 0x83 are supported and
	 * decorates the dip with any of those data available
	 */
	if (scsi_device_identity(sd, SLEEP_FUNC) == 0) {
		ddi_devid_t	devid;
		char		*guid = NULL;
		uchar_t		*inq83 = NULL;
		uint_t		inq83_len = 0xFF;
		uint64_t	*wwnp = NULL;
		uint64_t	wwn;

		inq83 = NULL;
		if (scsi_device_prop_lookup_byte_array(sd,
		    SCSI_DEVICE_PROP_PATH, "inquiry-page-83",
		    &inq83, &inq83_len) == DDI_PROP_SUCCESS) {

			/*
			 * Check the "Assoctiation" field (bits 5:4 in
			 * byte 5).
			 */
			if ((inq83[5] & 0x30) != 0) {
				HS_WARN(sc->hs_dip,
				    "guid is not associated with the "
				    "lun %d, target %d", lun, target);
			}

			wwnp = (uint64_t *)(void *)(&inq83[8]);
			wwn = BE_64(*wwnp);
			HS_DEBUG(sc->hs_dip, 2,
			    "target %d, lun %d, found wwn w%016"PRIx64,
			    target, lun, wwn);

			if ((rv = ddi_devid_scsi_encode(
			    DEVID_SCSI_ENCODE_VERSION_LATEST, NULL,
			    (uchar_t *)&inq, sizeof (struct scsi_inquiry),
			    NULL, 0, inq83, (size_t)inq83_len,
			    &devid)) == DDI_SUCCESS) {
				/* extract GUID from DEVID */
				guid = ddi_devid_to_guid(devid);
				if (guid != NULL) {
					HS_DEBUG(sc->hs_dip, 2,
					    "target %d, lun %d, found guid: %s",
					    target, lun, guid);
					ddi_devid_free_guid(guid);
				}
				ddi_devid_free(devid);
			}
		}

		if (inq83 != NULL) {
			scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, inq83);
		}
	} else {
		HS_DEBUG(sc->hs_dip, 2,
		    "device_identity failed - target %d, lun %d",
		    target, lun);
	}
	kmem_free(sd, sizeof (struct scsi_device));

	if ((devnode = kmem_zalloc(sizeof (*devnode), KM_SLEEP)) == NULL) {
		ndi_prop_remove_all(dip);
		(void) ndi_devi_free(dip);
		return (NDI_FAILURE);
	}

	if ((rv = ndi_devi_online(dip, NDI_ONLINE_ATTACH)) != NDI_SUCCESS) {
		HS_WARN(sc->hs_dip,
		    "!failed to online target:%d, lun %d, err: %d",
		    target, lun, rv);
		kmem_free(devnode, sizeof (*devnode));
		ndi_prop_remove_all(dip);
		(void) ndi_devi_free(dip);
		rv = NDI_FAILURE;
		goto out;
	}

	devnode->target = target;
	devnode->lun = lun;
	devnode->dip = dip;
	devnode->pdip = pdip;
	list_insert_tail(&sc->hs_devnodes, devnode);

	if (childp != NULL)
		*childp = dip;

	rv = NDI_SUCCESS;
out:
	if (nodename != NULL)
		scsi_hba_nodename_compatible_free(nodename, compatible);
	return (rv);
}

static int
storvsc_config_all(dev_info_t *pdip, storvsc_softc_t *sc)
{
	int target, lun;

	for (target = 0; target < STORVSC_MAX_TARGETS; target++) {
		for (lun = 0; lun < STORVSC_MAX_LUNS_PER_TARGET; lun++) {
			/* ndi_devi_enter is done in storvsc_bus_config */
			(void) storvsc_config_one(pdip, sc, target, lun, NULL);
		}
	}

	return (NDI_SUCCESS);
}

static int
storvsc_parse_devname(char *devname, int *target, int *lun)
{
	char cname[SCSI_MAXNAMELEN];
	char *ptr;
	char *tgtp = NULL;
	char *lunp = NULL;
	char *name, *addr;
	int ret = NDI_SUCCESS;
	long num;

	if (target == NULL || lun == NULL)
		return (NDI_FAILURE);

	(void) strlcpy(cname, devname, sizeof (cname));
	/* split name into "name@addr" */
	i_ddi_parse_name(cname, &name, &addr, NULL);

	tgtp = addr;
	if ((ptr = strchr(addr, ',')) != NULL) {
		lunp = ptr + 1;
		ptr = '\0';
	}

	if (tgtp != NULL) {
		(void) ddi_strtol(tgtp, NULL, 0x10, &num);
		*target = num;
	} else {
		ret = NDI_FAILURE;
	}

	if (lunp != NULL) {
		(void) ddi_strtol(lunp, NULL, 0x10, &num);
		*lun = num;
	} else {
		ret = NDI_FAILURE;
	}
	return (ret);
}

static int
storvsc_bus_config(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **childp)
{
	scsi_hba_tran_t *tran;
	storvsc_softc_t	*sc;
	int circ;
	int ret = NDI_FAILURE;
	int target = 0, lun = 0;

	tran = ddi_get_driver_private(pdip);
	sc = tran->tran_hba_private;

	ndi_devi_enter(pdip, &circ);
	switch (op) {
	case BUS_CONFIG_ONE:
		if (storvsc_parse_devname(arg, &target, &lun) != NDI_SUCCESS) {
			return (NDI_FAILURE);
		}
		ret = storvsc_config_one(pdip, sc, target, lun, childp);
		break;
	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL:
		ret = storvsc_config_all(pdip, sc);
		break;
	default:
		break;
	}

	if (ret == NDI_SUCCESS)
		ret = ndi_busop_bus_config(pdip, flags, op, arg, childp, 0);
	ndi_devi_exit(pdip, circ);
	return (ret);
}


/* ARGSUSED hba_dip tgt_dip hba_tran */
static int
storvsc_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	storvsc_softc_t *sc = SDEV2PRIV(sd);

	ASSERT3P(sc, !=, NULL);

	if (sd->sd_address.a_lun >= sc->hs_num_luns ||
	    sd->sd_address.a_target >= STORVSC_MAX_TARGETS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/* ARGSUSED hba_dip tgt_dip hba_tran sd */
static void
storvsc_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
}

static int
storvsc_hba_setup(storvsc_softc_t *sc)
{
	scsi_hba_tran_t *hba_tran;
	int		tran_flags;

	hba_tran = sc->hs_tran = scsi_hba_tran_alloc(sc->hs_dip,
	    SCSI_HBA_CANSLEEP);
	ASSERT(sc->hs_tran != NULL);

	hba_tran->tran_hba_private = sc;
	hba_tran->tran_tgt_private = NULL;

	hba_tran->tran_tgt_init = storvsc_tgt_init;
	hba_tran->tran_tgt_free = storvsc_tgt_free;
	hba_tran->tran_tgt_probe = scsi_hba_probe;

	hba_tran->tran_start = storvsc_start;
	hba_tran->tran_reset = storvsc_reset;
	hba_tran->tran_abort = storvsc_abort;
	hba_tran->tran_getcap = storvsc_getcap;
	hba_tran->tran_setcap = storvsc_setcap;
	hba_tran->tran_init_pkt = storvsc_init_pkt;
	hba_tran->tran_destroy_pkt = storvsc_destroy_pkt;

	hba_tran->tran_dmafree = storvsc_dmafree;
	hba_tran->tran_sync_pkt = storvsc_sync_pkt;
	hba_tran->tran_reset_notify = storvsc_reset_notify;

	hba_tran->tran_quiesce = NULL;
	hba_tran->tran_unquiesce = NULL;
	hba_tran->tran_bus_reset = NULL;

	hba_tran->tran_add_eventcall = NULL;
	hba_tran->tran_get_eventcookie = NULL;
	hba_tran->tran_post_event = NULL;
	hba_tran->tran_remove_eventcall = NULL;

	hba_tran->tran_bus_config = storvsc_bus_config;

	hba_tran->tran_interconnect_type = INTERCONNECT_SAS;

	tran_flags = (SCSI_HBA_TRAN_SCB | SCSI_HBA_TRAN_CDB |
	    SCSI_HBA_TRAN_CLONE);

	if (scsi_hba_attach_setup(sc->hs_dip, &storvsc_io_dma_attr,
	    hba_tran, tran_flags) != DDI_SUCCESS) {
		HS_WARN(sc->hs_dip, "failed to attach HBA");
		scsi_hba_tran_free(hba_tran);
		sc->hs_tran = NULL;
		return (-1);
	}

	return (DDI_SUCCESS);
}

static void
storvsc_init_kstat(storvsc_softc_t *sc)
{
	int	ndata;
	storvsc_stats_t *sp = NULL;
	char name[32] = { 0 };

	ndata = (sizeof (storvsc_stats_t) /
	    sizeof (kstat_named_t)) - MAXCPU;
	ndata += sc->hs_nchan;

	mutex_enter(&sc->hs_lock);
	sc->hs_stats = kstat_create("storvsc", ddi_get_instance(sc->hs_dip),
	    "vscstats", "misc", KSTAT_TYPE_NAMED, ndata, 0);

	if (sc->hs_stats == NULL) {
		HS_WARN(sc->hs_dip,
		    "%s: Failed to create kstats", __func__);
		mutex_exit(&sc->hs_lock);
		return;
	}

	sp = (storvsc_stats_t *)sc->hs_stats->ks_data;
	kstat_named_init(&sp->vscstat_reads, "reads", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->vscstat_writes, "writes", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->vscstat_non_rw, "other", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->vscstat_timeouts, "timeouts", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->vscstat_pending, "pending", KSTAT_DATA_UINT64);
	for (int i = 0; i < sc->hs_nchan; i++) {
		struct vmbus_channel *chanp = sc->hs_sel_chan[i];
		if (chanp != NULL) {
			(void) snprintf(name, sizeof (name), "%s.%d", "chan",
			    vmbus_chan_id(chanp));
			kstat_named_init(&sp->vscstat_chansend[i], name,
			    KSTAT_DATA_UINT64);
		}
	}
	sc->hs_stats->ks_private = sc;
	sc->hs_stats->ks_update = nulldev;

	kstat_install(sc->hs_stats);
	mutex_exit(&sc->hs_lock);
}

/*
 * @brief StorVSC attach function
 *
 * Function responsible for allocating per-device structures,
 * setting up SCSA interfaces and scanning for available LUNs to
 * be used for SCSI device peripherals.
 *
 * @param a device
 * @returns 0 on success or an error on failure
 */
static int
storvsc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance, ret;
	storvsc_softc_t	*sc;
	enum hv_storage_type stor_type;

	stor_type = storvsc_get_storage_type(dip);
	if (stor_type == DRIVER_UNKNOWN)
		return (ENODEV);

	/* Invoke iport attach if this is an iport node */
	if (scsi_hba_iport_unit_address(dip) != NULL)
		return (DDI_SUCCESS);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	/* Allocate softstate information */
	if (ddi_soft_state_zalloc(storvsc_sstate, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "ddi_soft_state_zalloc() failed for instance %d", instance);
		return (DDI_FAILURE);
	}

	if ((sc = ddi_get_soft_state(storvsc_sstate, instance)) == NULL) {
		cmn_err(CE_WARN, "failed to get soft state for instance %d",
		    instance);
		goto fail;
	}
	HS_DEBUG(dip, 1, "Attaching storvsc: Allocated softstate");

	/*
	 * Indicate that we are 'sizeof (scsi_*(9S))' clean, we use
	 * scsi_pkt_size() instead.
	 */
	scsi_size_clean(dip);

	/* Setup HBA instance */
	sc->hs_instance = instance;
	sc->hs_dip = dip;
	sc->hs_num_luns = STORVSC_MAX_LUNS_PER_TARGET;
	mutex_init(&sc->hs_lock, "storvsc instance mutex", MUTEX_DRIVER, NULL);
	list_create(&sc->hs_devnodes, sizeof (storvsc_device_t),
	    offsetof(storvsc_device_t, list));

	sc->hs_nchan = 1;
	sc->hs_chan = vmbus_get_channel(sc->hs_dip);
	ASSERT3P(sc->hs_chan, !=, NULL);

	/* fill in driver specific properties */
	sc->hs_drv_props = &g_drv_props_table[stor_type];
	hv_storvsc_ringbuffer_size = (64 * PAGESIZE);
	sc->hs_drv_props->drv_ringbuffer_size = hv_storvsc_ringbuffer_size;

	if ((storvsc_init_requests(sc)) != DDI_SUCCESS) {
		HS_WARN(sc->hs_dip, "failed to create request cache");
		goto fail;
	}

	sc->hs_destroy = B_FALSE;
	sc->hs_drain_notify = B_FALSE;
	sema_init(&sc->hs_drain_sema, 0, ("stor_synch_sema"),
	    SEMA_DRIVER, NULL);

	ret = hv_storvsc_connect_vsp(sc);
	if (ret != 0)
		goto free_cache;
	HS_DEBUG(sc->hs_dip, 1, "Attaching storvsc: connected to vsp");

	/* Construct cpu to channel mapping */
	storvsc_create_chan_sel(sc);

	/* OS specific scsi configuration */
	HS_DEBUG(sc->hs_dip, 1, "Attaching storvsc: setup io");

	if (storvsc_hba_setup(sc) != 0) {
		HS_WARN(sc->hs_dip, "failed to setup HBA");
		goto free_cache;
	}
	HS_DEBUG(sc->hs_dip, 1, "Attaching storvsc: hba setup done.");

	storvsc_init_kstat(sc);

	ddi_report_dev(sc->hs_dip);
	return (DDI_SUCCESS);

free_cache:
	storvsc_fini_requests(sc);
fail:
	ddi_soft_state_free(storvsc_sstate, instance);

	return (DDI_FAILURE);
}


static int
storvsc_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp,
    int *rval)
{
	int		ret;

	if (ddi_get_soft_state(storvsc_sstate, getminor(dev)) == NULL) {
		cmn_err(CE_WARN, "invalid device instance: %d", getminor(dev));
		return (ENXIO);
	}

	/* Try to handle command in a common way */
	if ((ret = scsi_hba_ioctl(dev, cmd, data, mode, credp, rval)) != ENOTTY)
		return (ret);

	cmn_err(CE_WARN, "unsupported IOCTL command: 0x%X", cmd);

	return (ENXIO);
}

int
_init(void)
{
	int	status;

	if ((status = ddi_soft_state_init(&storvsc_sstate,
	    sizeof (struct storvsc_softc), HS_MAX_ADAPTERS)) != 0) {
		cmn_err(CE_WARN, "ddi_soft_state_init() failed");
		return (status);
	}

	if ((status = scsi_hba_init(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "scsi_hba_init() failed");
		ddi_soft_state_fini(&storvsc_sstate);
		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "mod_install() failed");
		ddi_soft_state_fini(&storvsc_sstate);
		scsi_hba_fini(&modlinkage);
	}

	return (status);
}

int
_info(struct modinfo *modinfop)
{

	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	status;

	if ((status = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&storvsc_sstate);
		scsi_hba_fini(&modlinkage);
	}

	return (status);
}


/*
 * @brief StorVSC device detach function
 *
 * This function is responsible for safely detaching a
 * StorVSC device.  This includes waiting for inbound responses
 * to complete and freeing associated per-device structures.
 *
 * @param dev a device
 * returns 0 on success
 */
static int
storvsc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	storvsc_softc_t *sc;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	if ((sc = ddi_get_soft_state(storvsc_sstate, instance)) == NULL) {
		HS_WARN(dip, "failed to get soft state for instance %d",
		    instance);
		return (DDI_FAILURE);
	}

	mutex_enter(&sc->hs_lock);
	sc->hs_destroy = B_TRUE;

	/*
	 * At this point, all outbound traffic should be disabled. We
	 * only allow inbound traffic (responses) to proceed so that
	 * outstanding requests can be completed.
	 */
	if (sc->hs_num_out_reqs > 0) {
		sc->hs_drain_notify = B_TRUE;
		sema_p(&sc->hs_drain_sema);
		sc->hs_drain_notify = B_FALSE;
	}

	/*
	 * Since we have already drained, we don't need to busy wait.
	 * The call to close the channel will reset the callback
	 * under the protection of the incoming channel lock.
	 */

	vmbus_chan_close(sc->hs_chan);

	storvsc_fini_requests(sc);

	kstat_delete(sc->hs_stats);
	mutex_exit(&sc->hs_lock);
	ddi_soft_state_free(storvsc_sstate, instance);

	return (DDI_SUCCESS);
}

/*
 * @brief timeout handler for requests
 *
 * This function is called as a result of a callout expiring.
 *
 * @param arg pointer to a request
 */
static void
storvsc_timeout(void *arg)
{
	struct hv_storvsc_request *reqp = arg;
	storvsc_cmd_t *cmd = &reqp->hvs_cmd;
	struct storvsc_softc *sc = cmd->cmd_sc;
	struct scsi_pkt *pkt = reqp->pkt;

	cmd->cmd_flags |= STORVSC_FLAG_TIMED_OUT;
	storvsc_complete_command(cmd);

	HS_WARN(sc->hs_dip,
	    "IO (reqp = 0x%p) did not return for %u seconds.",
	    (void *)reqp, pkt->pkt_time);
	VSC_INCR_STAT(sc, vscstat_timeouts);
}

/*
 * @brief StorVSC device poll function
 *
 * This function is responsible for servicing requests when
 * interrupts are disabled (i.e when we are dumping core.)
 *
 * @param cmd the storvsc command that needs servicing
 */
static void
storvsc_poll(storvsc_cmd_t *cmd)
{
	struct scsi_pkt *pkt = CMD2PKT(cmd);
	int cycles = (pkt->pkt_time != 0) ?
	    STORVSC_POLL_CYCLES(pkt->pkt_time) :
	    STORVSC_POLL_CYCLES(SCSI_POLL_TIMEOUT);
	storvsc_softc_t *sc = cmd->cmd_sc;

	for (int i = 0; i < cycles; i++) {
		hv_storvsc_on_channel_callback(sc->hs_chan, sc);
		if ((cmd->cmd_flags & STORVSC_FLAG_DONE) != 0)
			return;

		if (((curthread->t_flag & T_INTR_THREAD) == 0) &&
		    !do_polled_io) {
			delay(drv_usectohz(STORVSC_POLL_DELAY_USECS));
		} else {
			/* busy wait */
			drv_usecwait(STORVSC_POLL_DELAY_USECS);
		}
	}

	/* Return error back to sd if the request times out */
	storvsc_timeout(PKT2REQ(pkt));
}


static void
storvsc_scsi_good_cmd(storvsc_cmd_t *cmd, uint8_t status)
{
	struct scsi_pkt *pkt = CMD2PKT(cmd);

	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_GOT_STATUS);
	if (cmd->cmd_flags & (STORVSC_FLAG_DMA_VALID))
		pkt->pkt_state |= STATE_XFERRED_DATA;
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_resid = 0;
	*(pkt->pkt_scbp) = status;
}

#define	SHORT_INQUIRY_LENGTH    36

static uint32_t
is_scsi_valid(const struct scsi_inquiry *inq)
{
	if ((inq->inq_dtype & DTYPE_MASK) == DTYPE_UNKNOWN)
		return (0);
	if ((inq->inq_dtype & DPQ_MASK) == DPQ_NEVER)
		return (0);
	return (1);
}

/*
 * completion function before returning to SCSA
 *
 * I/O process has been completed and the result needs
 * to be passed to the SCSA layer.
 * Free resources related to this request.
 *
 * @param reqp pointer to a request structure
 */
static void
storvsc_io_done(struct hv_storvsc_request *reqp)
{
	struct vmscsi_req *vm_srb = &reqp->vstor_packet.u.vm_srb;
	storvsc_cmd_t *cmd = &reqp->hvs_cmd;
	struct scsi_pkt *pkt = CMD2PKT(cmd);
	dev_info_t *dip = cmd->cmd_sc->hs_dip;
	uchar_t scsi_status = (vm_srb->scsi_status & STORVSC_STATUS_MASK);

	if (reqp->timeout_id)
		(void) untimeout(reqp->timeout_id);

	/* XXX - what if the pkt was freed? */
	if (pkt->pkt_state & STATE_GOT_STATUS) {
		HS_NOTE(dip, "%s: cmd 0x%x, I/O was already handled, "
		    "dropping it", __func__, pkt->pkt_cdbp[0]);
		return;
	}

	*(pkt->pkt_scbp) = scsi_status;
	int srb_status = SRB_STATUS(vm_srb->srb_status);
	switch (scsi_status) {
		case STATUS_GOOD:
			if (srb_status != SRB_STATUS_SUCCESS) {
				/*
				 * If there are errors, for example, invalid
				 * LUN, host will inform VM through SRB status.
				 */
				if (srb_status == SRB_STATUS_INVALID_LUN) {
					HS_DEBUG(dip, 6,
					    "invalid LUN %d for op: 0x%x",
					    vm_srb->lun, pkt->pkt_cdbp[0]);
				} else {
					HS_WARN(dip,
					    "Unknown SRB flag: 0x%x for op: "
					    "0x%x", srb_status,
					    pkt->pkt_cdbp[0]);
				}

				/*
				 * XXX For a selection timeout, all of the LUNs
				 * on the target will be gone.  It works for
				 * SCSI disks, but does not work for IDE disks.
				 *
				 * For CMD_DEV_GONE, it will only get
				 * rid of the device(s) specified by the path.
				 */
				if (storvsc_get_storage_type(dip) ==
				    DRIVER_STORVSC) {
					pkt->pkt_reason = CMD_TIMEOUT;
					cmd->cmd_flags |=
					    STORVSC_FLAG_TIMED_OUT;
				} else {
					pkt->pkt_reason = CMD_DEV_GONE;
					cmd->cmd_flags |= STORVSC_FLAG_DEV_GONE;
				}
			} else {
				storvsc_scsi_good_cmd(cmd, STATUS_GOOD);
			}

			if ((pkt->pkt_cdbp != NULL) &&
			    (pkt->pkt_cdbp[0] == SCMD_INQUIRY) &&
			    (pkt->pkt_cdbp[1] == 0) &&
			    (pkt->pkt_cdbp[2] == 0) &&
			    srb_status == SRB_STATUS_SUCCESS) {
				int resp_xfer_len, resp_buf_len, data_len;
				buf_t *bp = cmd->cmd_bp;
				bp_mapin(bp);

				struct scsi_inquiry *inq =
				    (struct scsi_inquiry *)bp->b_un.b_addr;
				uint8_t *resp_buf = (uint8_t *)bp->b_un.b_addr;

				/* Get the buffer length reported by host */
				resp_xfer_len = vm_srb->transfer_len;
				/* Get the available buffer length */
				resp_buf_len = resp_xfer_len >= 5 ?
				    resp_buf[4] + 5 : 0;
				data_len = (resp_buf_len < resp_xfer_len) ?
				    resp_buf_len : resp_xfer_len;
				if (data_len >= 5) {
					HS_DEBUG(dip, 6, "?storvsc "
					    "inquiry (%d) [%x %x %x %x %x "
					    "... ]",
					    data_len, resp_buf[0],
					    resp_buf[1], resp_buf[2],
					    resp_buf[3], resp_buf[4]);
				}
				/*
				 * XXX: Manually fix the wrong response
				 * returned from WS2012
				 */
				if (!is_scsi_valid(inq) &&
				    (vmstor_proto_version ==
				    VMSTOR_PROTOCOL_VERSION_WIN8_1 ||
				    vmstor_proto_version ==
				    VMSTOR_PROTOCOL_VERSION_WIN8 ||
				    vmstor_proto_version ==
				    VMSTOR_PROTOCOL_VERSION_WIN7)) {
					if (data_len >= 4 &&
					    (resp_buf[2] == 0 ||
					    resp_buf[3] == 0)) {
						/*
						 * SPC-3
						 */
						inq->inq_ansi = RDF_SCSI_SPC3;
						inq->inq_rdf = RDF_SCSI2;
						HS_NOTE(dip, "?storvsc "
						    "fix version and resp fmt "
						    "for 0x%x\n",
						    vmstor_proto_version);
					}
				} else if (data_len >= SHORT_INQUIRY_LENGTH) {
					/*
					 * XXX: Upgrade SPC2 to SPC3 if host
					 * is WIN8 or WIN2012 R2 in order to
					 * support UNMAP feature.
					 */
					if (strncmp(
					    inq->inq_vid, "Msft", 4) == 0 &&
					    inq->inq_ansi == RDF_SCSI_SPC2 &&
					    (vmstor_proto_version ==
					    VMSTOR_PROTOCOL_VERSION_WIN8_1 ||
					    vmstor_proto_version ==
					    VMSTOR_PROTOCOL_VERSION_WIN8)) {
						inq->inq_ansi = RDF_SCSI_SPC3;
						HS_DEBUG(dip, 5, "storvsc "
						    "upgrades SPC2 to SPC3");
					}
				}
			}
			break;
		case STATUS_CHECK:
			{
			struct scsi_arq_status *astat = (void*)(pkt->pkt_scbp);
			uint8_t		*sensedata;
			int		arq_size;

			pkt->pkt_state |= STATE_ARQ_DONE;

			if ((vm_srb->srb_status & SRB_STATUS_AUTOSENSE_VALID)
			    != 0) {
				arq_size = (cmd->cmd_rqslen >=
				    sense_buffer_size) ? sense_buffer_size :
				    cmd->cmd_rqslen;

				astat->sts_rqpkt_resid =  arq_size -
				    reqp->sense_info_len;
				astat->sts_rqpkt_resid = sense_buffer_size -
				    arq_size;
				sensedata = (uint8_t *)&astat->sts_sensedata;
				bcopy(cmd->cmd_arq_buf->b_un.b_addr, sensedata,
				    arq_size);

				pkt->pkt_state |= STATE_XARQ_DONE;
			} else {
				astat->sts_rqpkt_resid = 0;
			}

			astat->sts_rqpkt_statistics = 0;
			astat->sts_rqpkt_reason = CMD_CMPLT;
			(*(uint8_t *)&astat->sts_rqpkt_status) = STATUS_GOOD;
			astat->sts_rqpkt_state  = STATE_GOT_BUS |
			    STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_XFERRED_DATA | STATE_GOT_STATUS;

			if ((vm_srb->srb_status & SRB_STATUS_SUCCESS) != 0) {
				cmd->cmd_flags |= STORVSC_FLAG_SRB_ERROR;
				pkt->pkt_reason = CMD_TRAN_ERR;
				pkt->pkt_state |= (STATE_GOT_BUS |
				    STATE_GOT_TARGET | STATE_SENT_CMD |
				    STATE_GOT_STATUS);
			} else {
				storvsc_scsi_good_cmd(cmd,
				    (vm_srb->scsi_status & 0xFF));
			}
			}
			break;
		default:
			HS_WARN(dip, "Command 0x%x failed! "
			    "status %d, aborting", CMD2PKT(cmd)->pkt_cdbp[0],
			    vm_srb->scsi_status);
			/* for now, fail it */
			cmd->cmd_flags |= STORVSC_FLAG_ABORTED;
			break;
	}

	if (reqp->prp_list.gpa_range.gpa_len != 0) {
		pkt->pkt_resid = reqp->prp_list.gpa_range.gpa_len -
		    vm_srb->transfer_len;
		/* INQ hack, seems like host only sends std inq data 36 bytes */
		if ((pkt->pkt_cdbp[0] == SCMD_INQUIRY) &&
		    (vm_srb->transfer_len == 36)) {
			pkt->pkt_resid = 0;
		}
	}

	/* TODO:  timeout/retries & frozen (?) */
	storvsc_complete_command(cmd);
}

/*
 * @brief Determine type of storage device from GUID
 *
 * Using the type GUID, determine if this is a StorVSC (paravirtual
 * SCSI or BlkVSC (paravirtual IDE) device.
 *
 * @param dev a device
 * returns an enum
 */
static enum hv_storage_type
storvsc_get_storage_type(dev_info_t *dev)
{
	if (vmbus_probe_guid(dev, &gBlkVscDeviceType) == 0)
		return (DRIVER_BLKVSC);
	if (vmbus_probe_guid(dev, &gStorVscDeviceType) == 0)
		return (DRIVER_STORVSC);
	return (DRIVER_UNKNOWN);
}
