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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_1394_TARGETS_AV1394_ISOCH_H
#define	_SYS_1394_TARGETS_AV1394_ISOCH_H

/*
 * isoch module definitions
 */

#include <sys/note.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	COOKIES		100

/*
 * isoch DMA memory management: segments and pools
 *
 * isoch segment - a contiguous chunk of kernel memory
 */
typedef struct av1394_isoch_seg_s {
	caddr_t			is_kaddr;	/* segment kernel virt addr */
	int			is_size;	/* segment size */
	ddi_umem_cookie_t	is_umem_cookie;	/* umem cookie */
	size_t			is_umem_size;	/* umem size (page-aligned) */
	ddi_dma_handle_t	is_dma_hdl;	/* bind handle */
	ddi_dma_cookie_t	is_dma_cookie[COOKIES];
						/* dma cookie */
	uint_t			is_dma_ncookies;
						/* # of cookies */
} av1394_isoch_seg_t;

/*
 * isoch pool - a set of one or more isoch segments
 */
typedef struct av1394_isoch_pool_s {
	av1394_isoch_seg_t	*ip_seg;	/* array of segments */
	int			ip_nsegs;	/* # of valid segments */
	int			ip_alloc_size;	/* array alloc'd size */
	int			ip_size;	/* total pool size */
	int			ip_umem_size;	/* total alloc'd memory size */
} av1394_isoch_pool_t;

/*
 * many members are protected because they are modified during channel
 * initialization or/and during isoch transfer, both of which are
 * single-threaded processes. after that these members remain read-only.
 */
_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_isoch_seg_s))
_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_isoch_pool_s))

/*
 * IXL receive data block (one or more RECV_BUF commands will follow the label)
 */
typedef struct av1394_ir_ixl_data_s {
	ixl1394_label_t		rd_label;
	ixl1394_callback_t	rd_cb;		/* buffer completion callback */
	ixl1394_jump_t		rd_jump;	/* next command */
} av1394_ir_ixl_data_t;

_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_ir_ixl_data_s))

/*
 * isoch receive structure
 */
typedef struct av1394_ir_s {
	av1394_isoch_pool_t	ir_data_pool;	/* pool for data packets */
	/* IXL */
	ixl1394_command_t	*ir_ixlp;	/* IXL chain */
	av1394_ir_ixl_data_t	*ir_ixl_data;	/* data block array */
	ixl1394_xfer_buf_t	*ir_ixl_buf;	/* RECV_BUF command array */
	int			ir_ixl_nbufs;	/* # of commands in array */
	size_t			ir_ixl_bpf;	/* # of buffers per frame - 1 */
	size_t			ir_ixl_bufsz;	/* buffer size */
	size_t			ir_ixl_tailsz;	/* tail buffer size */
	/* xfer */
	int			ir_nfull;	/* # of full frames */
	int			ir_first_full;	/* first full frame */
	int			ir_nempty;	/* # of empty frames */
	int			ir_last_empty;	/* last produced frame */
	int			ir_hiwat;	/* high water mark */
	int			ir_lowat;	/* low water mark */
	int			ir_overflow_idx; /* overflow frame index */
	/* read() support */
	int			ir_read_idx;	/* first full frame */
	int			ir_read_cnt;	/* number of full frames */
	off_t			ir_read_off;	/* offset into the frame */
} av1394_ir_t;

_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_ir_s::{
	ir_ixlp
	ir_ixl_buf
	ir_ixl_nbufs
	ir_ixl_bpf
	ir_ixl_bufsz
	ir_ixl_tailsz
}))

/*
 * IXL transmit begin block, used to get a starting point for timestamping
 */
enum { AV1394_IT_IXL_BEGIN_NPOST = 3 };

typedef struct av1394_it_ixl_begin_s {
	ixl1394_label_t		be_label;
	ixl1394_xfer_pkt_t	be_empty_pre;	/* needed for next command */
	ixl1394_store_timestamp_t be_store_ts;	/* store timestamp */
	ixl1394_callback_t	be_cb;		/* timestamp handling */
	ixl1394_xfer_pkt_t	be_empty_post[AV1394_IT_IXL_BEGIN_NPOST];
	ixl1394_jump_t		be_jump;	/* next command */
} av1394_it_ixl_begin_t;

_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_it_ixl_begin_s))

/*
 * common part of transmit commands that are in a linked list
 */
typedef struct av1394_it_ixl_common_s {
	struct av1394_it_ixl_common_s	*tc_next;	/* next in the list */
	int				tc_size;	/* structure size */
} av1394_it_ixl_common_t;

/*
 * IXL transmit data block
 */
typedef struct av1394_it_ixl_buf_s {
	av1394_it_ixl_common_t	tb_common;
	int			tb_flags;
	int			tb_framenum;	/* frame number */
	struct av1394_ic_s	*tb_icp;
	ixl1394_label_t		tb_label;
	ixl1394_xfer_buf_t	tb_buf;		/* transmit packets */
	ixl1394_store_timestamp_t tb_store_ts;	/* cycle time feedback */
	ixl1394_callback_t	tb_cb;		/* callback */
	ixl1394_jump_t		tb_jump;	/* next command */
} av1394_it_ixl_buf_t;

_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_it_ixl_buf_s))

/* tb_flags */
enum {
	AV1394_IT_IXL_BUF_NEXT_EMPTY	= 0x01,	/* followed by empty CIP */
	AV1394_IT_IXL_BUF_SOF		= 0x02,	/* start of frame */
	AV1394_IT_IXL_BUF_EOF		= 0x04	/* end of frame */
};

/*
 * empty CIP
 */
typedef struct av1394_it_ixl_empty_cip_s {
	av1394_it_ixl_common_t	te_common;
	ixl1394_label_t		te_label;
	ixl1394_xfer_pkt_t	te_pkt;
	ixl1394_jump_t		te_jump;	/* next command */
} av1394_it_ixl_empty_cip_t;

_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_it_ixl_empty_cip_s))

/*
 * per-frame information
 */
typedef struct av1394_it_frame_info_s {
	caddr_t			fi_ts_off;	/* where to put a timestamp */
	int			fi_ncycs;	/* # of bus cycles */
	av1394_it_ixl_buf_t	*fi_first_buf;	/* first IXL buffer */
	av1394_it_ixl_buf_t	*fi_last_buf;	/* last IXL buffer */
} av1394_it_frame_info_t;

_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_it_frame_info_s))

/*
 * timestamp type
 */
typedef union av1394_it_ts {
	uint16_t	ts_syt;		/* SYT timestamp */
} av1394_it_ts_t;

/*
 * isoch transmit structure
 */
typedef struct av1394_it_s {
	av1394_isoch_pool_t	it_data_pool;	/* pool for data packets */
	/* IXL */
	ixl1394_command_t	*it_ixlp;	/* IXL chain */
	av1394_it_ixl_begin_t	it_ixl_begin;	/* begin block */
	av1394_it_ixl_common_t	*it_ixl_data;	/* data block */
	av1394_it_frame_info_t	*it_frame_info;	/* frame info array */
	av1394_it_ixl_empty_cip_t *it_skipped_cip; /* last skipped CIP */
	/* xfer */
	int			it_first_empty; /* first empty frame # */
	int			it_nempty;	/* # of empty frames */
	int			it_last_full;	/* last full frame # */
	int			it_nfull;	/* # of full frames */
	int			it_hiwat;	/* high water mark */
	int			it_lowat;	/* low water mark */
	int			it_start_thre;	/* xfer start threshold */
	av1394_it_ts_t		it_ts_init;	/* initial timestamp */
	/* underrun data */
	int			it_underrun_idx; /* underrun frame index */
	ixl1394_command_t	*it_saved_label; /* saved buffer label */
	/* write() support */
	int			it_write_idx;	/* first empty frame */
	int			it_write_cnt;	/* # of empty frames */
	off_t			it_write_off;	/* offset into the frame */
} av1394_it_t;

_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_it_s::{
	it_ixlp
	it_ixl_begin
	it_ixl_data
	it_frame_info
	it_ts_init
	it_skipped_cip
}))

/* misc channel parameters */
typedef struct av1394_ic_param_s {
	int		cp_bus_speed;	/* bus speed */
	int		cp_dbs;		/* DBS */
	int		cp_fn;		/* FN */
	int		cp_n;		/* rate numerator */
	int		cp_d;		/* rate denominator */
	int		cp_ts_mode;	/* timestamp mode */
} av1394_ic_param_t;

/* channel state */
typedef enum {
	AV1394_IC_IDLE,		/* nothing happens */
	AV1394_IC_STARTED,	/* channel has been started */
	AV1394_IC_DMA,		/* DMA transfer is in progress */
	AV1394_IC_SUSPENDED	/* transfer on the channel suspended */
} av1394_ic_state_t;

/*
 * isoch channel structure, common for both recv and xmit
 */
typedef struct av1394_ic_s {
	kmutex_t		ic_mutex;	/* structure mutex */
	struct av1394_inst_s	*ic_avp;	/* backpointer to instance */
	int			ic_num;		/* channel # */
	int			ic_dir;		/* xfer direction */
	av1394_ic_state_t	ic_state;	/* state */
	int			ic_pktsz;	/* packet size */
	int			ic_npkts;	/* # of packets/frame */
	size_t			ic_framesz;	/* frame size (pktsz * npkts) */
	int			ic_nframes;	/* # of frames */
	av1394_ic_param_t	ic_param;	/* misc parameters */
	size_t			ic_mmap_sz;	/* mmap size */
	off_t			ic_mmap_off;	/* mmap offset */
	t1394_isoch_single_handle_t ic_sii_hdl;	/* isoch single handle */
	t1394_isoch_dma_handle_t ic_isoch_hdl;	/* 1394 isoch handle */
	kcondvar_t		ic_xfer_cv;	/* xfer cv */
	int			ic_preq;	/* postponed request */
	av1394_ir_t		ic_ir;		/* recv */
	av1394_it_t		ic_it;		/* xmit */
} av1394_ic_t;

_NOTE(MUTEX_PROTECTS_DATA(av1394_ic_s::ic_mutex, av1394_ic_s))
_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_ic_s::{
	ic_avp
	ic_num
	ic_dir
	ic_sii_hdl
	ic_isoch_hdl
	ic_pktsz
	ic_npkts
	ic_framesz
	ic_nframes
	ic_param
	ic_mmap_sz
	ic_mmap_off
}))

/* xfer directions */
enum {
	AV1394_IR,
	AV1394_IT
};

/* CIP type */
enum {
	AV1394_CIP_FULL,
	AV1394_CIP_EMPTY
};

/* misc constants */
enum {
	AV1394_IC_FRAME_SIZE_MAX = 1024 * 1024,	/* max frame size */
	AV1394_MEM_MAX_PERCENT	= (100/10),	/* max percent of physmem */
	AV1394_SEGSZ_MAX_SHIFT	= 16,		/* maximum segment size */
	AV1394_SEGSZ_MAX	= (1UL << AV1394_SEGSZ_MAX_SHIFT),
	AV1394_SEGSZ_MAX_OFFSET	= AV1394_SEGSZ_MAX - 1,
	AV1394_IXL_BUFSZ_MAX	= 57344,	/* max buf size (uint16_t) */
						/* 57344 is ptob(btop(65535)) */
	AV1394_IR_NFRAMES_MIN	= 3,		/* minimum frame count */
	AV1394_IT_NFRAMES_MIN	= 3,		/* minimum frame count */
	AV1394_CIPSZ		= 8,		/* CIP header size */
	AV1394_DV_NTSC_FRAMESZ	= 250,		/* DV-NTSC frame size in pkts */
	AV1394_DV_PAL_FRAMESZ	= 300		/* DV-PAL frame size in pkts */
};

#define	AV1394_TS_MODE_GET_OFF(mode)	((mode) & 0xff)
#define	AV1394_TS_MODE_GET_SIZE(mode)	(((mode) >> 8) & 0xff)

/* private ISOCH_INIT flag */
#define	IEC61883_PRIV_ISOCH_NOALLOC	0x40000000

/*
 * autoxmit (isoch xmit via write(2)) support
 */
typedef struct av1394_isoch_autoxmit_s {
	uchar_t			ax_ciph[AV1394_CIPSZ];	/* first CIP hdr */
	boolean_t		ax_copy_ciph;		/* need to copy hdr */
	int			ax_fmt;			/* data format */
} av1394_isoch_autoxmit_t;

/* autoxmit formats */
enum {
	AV1394_ISOCH_AUTOXMIT_DV	= 0x10,
	AV1394_ISOCH_AUTOXMIT_UNKNOWN	= 0,
	AV1394_ISOCH_AUTOXMIT_DV_NTSC	= 1 | AV1394_ISOCH_AUTOXMIT_DV,
	AV1394_ISOCH_AUTOXMIT_DV_PAL	= 2 | AV1394_ISOCH_AUTOXMIT_DV
};


/*
 * User processes calling mmap(2) pass the 'offset' and 'len' arguments,
 * returned by IEC61883_ISOCH_INIT ioctl. These arguments uniquely identify
 * the DMA buffer associated with a channel. For each isochronous channel
 * a part of this "address space" should be allocated to prevent conflicts
 * with other channels.
 */
typedef struct av1394_as_s {
	off_t		as_end;		/* address space end */
} av1394_as_t;


/*
 * CMP (Connection Management Procedures)
 *
 * PCR address map (Ref: IEC 61883-1 Fig 14)
 */
#define	AV1394_PCR_ADDR_START		0xFFFFF0000900
#define	AV1394_PCR_ADDR_OMPR		0xFFFFF0000900
#define	AV1394_PCR_ADDR_OPCR0		0xFFFFF0000904
#define	AV1394_PCR_ADDR_NOPCR		31
#define	AV1394_PCR_ADDR_IMPR		0xFFFFF0000980
#define	AV1394_PCR_ADDR_IPCR0		0xFFFFF0000984
#define	AV1394_PCR_ADDR_NIPCR		31

/* initial values and bus reset masks (Ref: IEC 61883-1 Fig 10-13) */
#define	AV1394_OMPR_INIT_VAL		0xBFFFFF00
#define	AV1394_IMPR_INIT_VAL		0x80FFFF00
#define	AV1394_PCR_INIT_VAL		0x00000000	/* both iPCR and oPCR */
#define	AV1394_OPCR_BR_CLEAR_MASK	0x7FC03C00
#define	AV1394_IPCR_BR_CLEAR_MASK	0x7FC0FFFF

/*
 * local plug control register
 */
typedef struct av1394_pcr_s {
	uint32_t		pcr_val;	/* value */
	t1394_addr_handle_t	pcr_addr_hdl;	/* address handle */
} av1394_pcr_t;

enum {
	AV1394_OMPR_IDX		= 0,	/* oMPR index */
	AV1394_OPCR0_IDX	= 1,	/* oPCR0 index */
	AV1394_IMPR_IDX		= 32,	/* iMPR index */
	AV1394_IPCR0_IDX	= 33,	/* iPCR0 index */
	AV1394_NPCR		= 64	/* total number of PCRs */
};

/* plug handle manipulation */
enum {
	AV1394_PCR_REMOTE	= 0x40000000
};

/*
 * per-instance CMP structure
 */
typedef struct av1394_cmp_s {
	krwlock_t	cmp_pcr_rwlock;		/* rwlock for PCRs */
	av1394_pcr_t	*cmp_pcr[AV1394_NPCR];	/* array of PCRs */
} av1394_cmp_t;

_NOTE(SCHEME_PROTECTS_DATA("cmp_pcr_rwlock", av1394_cmp_s::cmp_pcr))


/*
 * per-instance soft state structure
 */
typedef struct av1394_isoch_s {
	kmutex_t		i_mutex;	/* structure mutex */
	int			i_nopen;	/* number of opens */
	av1394_cmp_t		i_cmp;		/* CMP information */
	av1394_ic_t		*i_ic[64];	/* array of channels */
	av1394_as_t		i_mmap_as;	/* mmap virtual addr space */
	ddi_softintr_t		i_softintr_id;	/* soft interrupt id */
	uint64_t		i_softintr_ch;	/* channels to service */
	av1394_isoch_autoxmit_t	i_autoxmit;	/* autoxmit support */
} av1394_isoch_t;

_NOTE(MUTEX_PROTECTS_DATA(av1394_isoch_s::i_mutex, av1394_isoch_s))
_NOTE(DATA_READABLE_WITHOUT_LOCK(av1394_isoch_s::{
	i_ic
	i_softintr_id
}))
_NOTE(SCHEME_PROTECTS_DATA("single-threaded", av1394_isoch_autoxmit_s))

_NOTE(LOCK_ORDER(av1394_isoch_s::i_mutex av1394_ic_s::ic_mutex))

/* postponed request types */
enum {
	AV1394_PREQ_IR_OVERFLOW		= 0x01,
	AV1394_PREQ_IT_UNDERRUN		= 0x02
};


/* TNF probes */
#define	AV1394_TNF_CMP			"1394 av1394 cmp "
#define	AV1394_TNF_CMP_STACK		"1394 av1394 cmp stacktrace "
#define	AV1394_TNF_CMP_ERROR		"1394 av1394 cmp error "
#define	AV1394_TNF_ISOCH		"1394 av1394 isoch "
#define	AV1394_TNF_ISOCH_STACK		"1394 av1394 isoch stacktrace "
#define	AV1394_TNF_ISOCH_ERROR		"1394 av1394 isoch error "


/* isoch channel */
int	av1394_ic_open(struct av1394_inst_s *, int);
int	av1394_ic_close(struct av1394_inst_s *, int);
int	av1394_ic_init(struct av1394_inst_s *avp, iec61883_isoch_init_t *ii,
	av1394_ic_t **icpp);
void	av1394_ic_fini(av1394_ic_t *icp);
int	av1394_ic_alloc_pool(av1394_isoch_pool_t *pool, size_t segsz, int cnt,
	int mincnt);
void	av1394_ic_free_pool(av1394_isoch_pool_t *pool);
int	av1394_ic_dma_setup(av1394_ic_t *icp, av1394_isoch_pool_t *pool);
void	av1394_ic_dma_cleanup(av1394_ic_t *icp, av1394_isoch_pool_t *pool);
int	av1394_ic_ixl_seg_decomp(size_t segsz, size_t pktsz, size_t *bufszp,
	size_t *tailszp);
void	av1394_ic_dma_sync_frames(av1394_ic_t *icp, int idx, int cnt,
		av1394_isoch_pool_t *pool, uint_t type);
int	av1394_ic_start(av1394_ic_t *icp);
int	av1394_ic_stop(av1394_ic_t *icp);
void	av1394_ic_ixl_dump(ixl1394_command_t *cmd);
void	av1394_ic_trigger_softintr(av1394_ic_t *icp, int num, int preq);

/* isoch receive */
int	av1394_ir_init(av1394_ic_t *icp, int *error);
void	av1394_ir_fini(av1394_ic_t *icp);
int	av1394_ir_start(av1394_ic_t *icp);
int	av1394_ir_stop(av1394_ic_t *icp);
int	av1394_ir_recv(av1394_ic_t *icp, iec61883_recv_t *recv);
int	av1394_ir_read(av1394_ic_t *icp, struct uio *uiop);
void	av1394_ir_overflow(av1394_ic_t *icp);

/* isoch transmit */
int	av1394_it_init(av1394_ic_t *icp, int *error);
void	av1394_it_fini(av1394_ic_t *icp);
int	av1394_it_start(av1394_ic_t *icp);
int	av1394_it_stop(av1394_ic_t *icp);
int	av1394_it_xmit(av1394_ic_t *icp, iec61883_xmit_t *xmit);
int	av1394_it_write(av1394_ic_t *icp, struct uio *uiop);
void	av1394_it_underrun(av1394_ic_t *icp);

/* address space for mmap(2) */
void av1394_as_init(av1394_as_t *as);
void av1394_as_fini(av1394_as_t *as);
off_t	av1394_as_alloc(av1394_as_t *as, size_t size);
void av1394_as_free(av1394_as_t *as, off_t);

/* CMP */
int	av1394_cmp_init(struct av1394_inst_s *avp);
void	av1394_cmp_fini(struct av1394_inst_s *avp);
void	av1394_cmp_bus_reset(struct av1394_inst_s *avp);
void	av1394_cmp_close(struct av1394_inst_s *avp);
int	av1394_ioctl_plug_init(struct av1394_inst_s *, void *, int);
int	av1394_ioctl_plug_fini(struct av1394_inst_s *, void *, int);
int	av1394_ioctl_plug_reg_read(struct av1394_inst_s *, void *, int);
int	av1394_ioctl_plug_reg_cas(struct av1394_inst_s *, void *, int);

/* isoch common */
int	av1394_isoch_attach(struct av1394_inst_s *);
void	av1394_isoch_detach(struct av1394_inst_s *);
int	av1394_isoch_cpr_suspend(struct av1394_inst_s *);
int	av1394_isoch_cpr_resume(struct av1394_inst_s *);
void	av1394_isoch_bus_reset(struct av1394_inst_s *);
void	av1394_isoch_disconnect(struct av1394_inst_s *);
void	av1394_isoch_reconnect(struct av1394_inst_s *);
int	av1394_isoch_open(struct av1394_inst_s *, int);
int	av1394_isoch_close(struct av1394_inst_s *, int);
int	av1394_isoch_read(struct av1394_inst_s *, struct uio *);
int	av1394_isoch_write(struct av1394_inst_s *, struct uio *);
int	av1394_isoch_ioctl(struct av1394_inst_s *, int, intptr_t, int, int *);
int	av1394_isoch_devmap(struct av1394_inst_s *, devmap_cookie_t, offset_t,
		size_t, size_t *, uint_t);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_1394_TARGETS_AV1394_ISOCH_H */
