/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SCSI_ADAPTERS_SFVAR_H
#define	_SYS_SCSI_ADAPTERS_SFVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FC-AL FCP driver definitions
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * this is to generate unique minor numbers for each minor
 * node type being created. because of the limitations by SCSA,
 * we have to use minor number values from 32 to 63 for the HBA
 * drivers use
 */
#define	SF_BASE_MINOR		32
#define	SF_DEVCTL_MINOR		(SF_BASE_MINOR + 1)
#define	SF_FC_MINOR		(SF_BASE_MINOR + 2)
#define	SF_INST_SHIFT4MINOR	6
#define	SF_INST2DEVCTL_MINOR(x)	(((x) << SF_INST_SHIFT4MINOR) | SF_DEVCTL_MINOR)
#define	SF_INST2FC_MINOR(x)	(((x) << SF_INST_SHIFT4MINOR) | SF_FC_MINOR)
#define	SF_MINOR2INST(x)	((x) >> SF_INST_SHIFT4MINOR)

#define	SF_INIT_ITEMS		5
#define	SF_MAX_TARGETS		126
#define	SF_MAX_LILP_ENTRIES	126

#define	SF_NUM_HASH_QUEUES	32
#define	SF_HASH(x, y)	((x[0]+x[1]+x[2]+x[3]+x[4]+x[5]+x[6]+x[7]) &\
(SF_NUM_HASH_QUEUES-1))


/*
 * sf driver needs to be sanitized for exporting some of its
 * macros/variables to userland programs.
 */
#ifdef	_KERNEL

/*
 * sf instance structure
 */

struct sf {
	struct scsi_hba_tran *sf_tran;
	dev_info_t	*sf_dip;
	struct sf	*sf_next;
	struct sf	*sf_sibling;
	kmutex_t	sf_mutex;
	kmutex_t	sf_cr_mutex;
	uint_t		sf_state;
	int64_t		sf_reset_time;	/* reset/lip init time for bus_config */
	struct sf_target *sf_targets[SF_MAX_TARGETS];
	struct sf_target *sf_wwn_lists[SF_NUM_HASH_QUEUES];
	void		*sf_socp;	/* pointer to socal state */
	struct fcal_transport *sf_sochandle;
	kmutex_t	sf_cmd_mutex;
	int		sf_throttle;
	int		sf_ncmds;
	int		sf_ncmds_exp_avg;
	int		sf_device_count;
	uint_t		sf_use_lock;
	uint_t		sf_timer;
	uint_t		sf_online_timer;
	int		sf_take_core;
	struct kmem_cache *sf_pkt_cache;
	struct sf_pkt *sf_pkt_head; /* packet queue */
	struct sf_pkt *sf_pkt_tail;
	struct sf_els_hdr *sf_els_list;
	struct sf_reset_list	*sf_reset_list;
	kcondvar_t	sf_cr_cv;
	uint_t		sf_cr_pool_cnt;
	struct sf_cr_pool *sf_cr_pool; /* list of command/response pools */
	uchar_t		sf_al_pa;
	uchar_t		sf_busy;
	uchar_t		sf_flag;
	uchar_t		sf_cr_flag; /* synchronize creation of new cr pools */
	uint_t		sf_lip_cnt;
	struct scsi_reset_notify_entry  *sf_reset_notify_listf;
	struct fcal_lilp_map	*sf_lilp_map;
	ddi_dma_handle_t	sf_lilp_dmahandle;
	ddi_acc_handle_t	sf_lilp_acchandle;
	ddi_dma_cookie_t	sf_lilp_dmacookie;
	kstat_t		*sf_ksp;
	kmutex_t	sf_hp_daemon_mutex;
	kcondvar_t	sf_hp_daemon_cv;
	struct sf_hp_elem *sf_hp_elem_head;
	struct sf_hp_elem *sf_hp_elem_tail;
	/*
	 * Event handling
	 */
	ndi_event_definition_t	*sf_event_defs;
	ndi_event_hdl_t		sf_event_hdl;
	ndi_event_set_t		sf_events;
	struct	sf_stats	sf_stats;
	uchar_t		sf_hp_exit;	/* hotplugging thread exit flag */
	uchar_t		sf_check_n_close;
		/* check if unopened sf is being closed */
	kt_did_t	sf_hp_tid;	/* hotplug thread id */
};

#define	SF_STATE_INIT		0x01
#define	SF_STATE_OFFLINE	0x02
#define	SF_STATE_ONLINE		0x04
#define	SF_STATE_ONLINING	0x08
#define	SF_STATE_SUSPENDED	0x10		/* driver has been suspended */

#define	SF_EVENT_TAG_INSERT	0
#define	SF_EVENT_TAG_REMOVE	1

/*
 * pool of sf command response blocks
 */

struct  sf_cr_pool {
	struct	sf_cr_pool	*next;
	struct	sf_cr_free_elem *free;
	struct	sf		*sf;
	caddr_t			cmd_base;	/* start addr of this chunk */
	ddi_dma_handle_t	cmd_dma_handle; /* dma mapping for this chunk */
	ddi_acc_handle_t	cmd_acc_handle;
	caddr_t			rsp_base;
	ddi_dma_handle_t	rsp_dma_handle;
	ddi_acc_handle_t	rsp_acc_handle;
	uint_t			nfree;
	uint_t			ntot;
};

#define	SF_CR_POOL_MAX		32	/* allows 4096 outstanding packets */

#define	SF_ELEMS_IN_POOL	128
#define	SF_LOG2_ELEMS_IN_POOL	7	/* LOG2 SF_ELEMS_IN_POOL */
#define	SF_FREE_CR_EPSILON	64	/* SF_ELEMS_IN_POOL /2 */

/*
 * sf command/response free structure which is overlaid on fcp_cmd
 */

struct  sf_cr_free_elem {
	struct		sf_cr_free_elem *next;
	caddr_t		rsp;		/* ptr to corresponding rsp */
	uint_t		cmd_dmac;	/* dmac_address for cmd */
	uint_t		rsp_dmac;	/* dmac_address for rsp */
};

/*
 * list of targets for reset delay handling
 */

struct sf_reset_list {
	struct sf_reset_list	*next;
	struct sf_target	*target;
	clock_t			timeout;
	uint_t			lip_cnt;
};

/*
 * structure used to store hotplug event callback info
 */

struct sf_hp_event {
	int (*callback)();
	void *arg;
};


/*
 * sf per target structure
 */

struct sf_target	{
	struct sf_pkt *sft_pkt_head; /* queue of active commands */
	struct sf_pkt *sft_pkt_tail;
	kmutex_t	sft_mutex;
	kcondvar_t	sft_cv;
	kmutex_t	sft_pkt_mutex;
	dev_info_t	*sft_dip;
	uchar_t		sft_node_wwn[FC_WWN_SIZE];
	uchar_t		sft_port_wwn[FC_WWN_SIZE];
	union {
		/* It's easier to shove around an int64 than a byte array */
		uchar_t	b[FCP_LUN_SIZE];
		int64_t	l;
	}		sft_lun;
	/* XXXX The RAID LUN field is used to implement FCP Annex C */
#ifdef RAID_LUNS
	uint_t		sft_raid_lun;
#define	SCSA_LUN(t)	(int64_t)(t)->sft_raid_lun
#else
#define	SCSA_LUN(t)	(t)->sft_lun.l
#endif
	uchar_t		sft_hard_address;
	uchar_t		sft_al_pa;
	uchar_t		sft_device_type;
	uchar_t		sft_scan_count;
	uint_t		sft_alive;
	uint_t		sft_state;
	uint_t		sft_lip_cnt;
	struct scsi_hba_tran *sft_tran;
	struct sf_target	*sft_next;
	struct sf_target	*sft_next_lun;
	struct sf_hp_event sft_insert_ev;
	struct sf_hp_event sft_remove_ev;
	struct scsi_inquiry	sft_inq;
};

#define	SF_TARGET_INIT_DONE	0x1
#define	SF_TARGET_BUSY		0x2
#define	SF_TARGET_OFFLINE	0x4
#define	SF_TARGET_MARK		0x8

/*
 * sf packet
 */

#define	PKT2CMD(pkt)		((struct sf_pkt *)pkt->pkt_ha_private)
#define	CMD2PKT(cmd)		((cmd)->cmd_pkt)
#ifdef	_LP64
#define	PKT_PRIV_SIZE		2
#define	PKT_PRIV_LEN		16
#else /* _ILP32 */
#define	PKT_PRIV_SIZE		1
#define	PKT_PRIV_LEN		8
#endif


struct sf_pkt {
	struct sf_pkt		*cmd_forw;
	struct sf_pkt		*cmd_back;
	struct sf_pkt		*cmd_next;
	struct scsi_pkt		*cmd_pkt;
	fcal_packet_t		*cmd_fp_pkt;
	uint_t		cmd_state;
	uint_t		cmd_timeout;
	char		cmd_scsi_scb[sizeof (struct scsi_arq_status)];
	uint32_t	cmd_dmacount;
	ddi_dma_handle_t	cmd_dmahandle;  /* dma handle */
	ddi_dma_cookie_t	cmd_dmacookie;  /* current dma cookie */
	uint_t		cmd_flags;	/* private flags */
						/* needs ZEROING */
	uint_t		cmd_cdblen;	/* length of cdb */
					/* needs to be INITialized */
	uint_t		cmd_scblen;	/* length of scb */
					/* needs to be INITialized */
	uint_t		cmd_privlen;	/* length of tgt private */
					/* needs to be INITialized */
	struct	sf_cr_pool	*cmd_cr_pool; /* pool to which cmd/rsp belong */
	struct fcp_cmd		*cmd_block;
	struct fcp_rsp		*cmd_rsp_block;
	kmutex_t	cmd_abort_mutex;	/* packet abort mutex */
	uint_t		cmd_dmac;
	uint_t		cmd_rsp_dmac;
	uint64_t		cmd_pkt_private[PKT_PRIV_LEN];
			/* default target private area */
};

#define	SF_STATE_IDLE		0x1
#define	SF_STATE_ISSUED		0x2
#define	SF_STATE_ABORTING	0x4

/*
 * Define size of extended scsi cmd pkt (ie. includes ARQ)
 */
#define	EXTCMDS_STATUS_SIZE  (sizeof (struct scsi_arq_status))

/*
 * These are the defined flags for this structure.
 */
#define	CFLAG_DMAVALID		0x0010	/* dma mapping valid */
#define	CFLAG_DMASEND		0x0020	/* data is going 'out' */
#define	CFLAG_CMDIOPB		0x0040	/* this is an 'iopb' packet */
#define	CFLAG_CDBEXTERN		0x0100	/* cdb kmem_alloc'd */
#define	CFLAG_SCBEXTERN		0x0200	/* scb kmem_alloc'd */
#define	CFLAG_FREE		0x0400	/* packet is on free list */
#define	CFLAG_PRIVEXTERN	0x1000	/* target private was */
					/* kmem_alloc'd */
#define	CFLAG_IN_QUEUE		0x2000	/* command in sf queue */

struct sf_els_hdr {
	struct sf	*sf;
	caddr_t		cmd;
	caddr_t		rsp;
	uchar_t		els_code;
	uchar_t		delayed_retry;
	ddi_dma_handle_t	cmd_dma_handle;
	ddi_dma_handle_t	rsp_dma_handle;
	ddi_acc_handle_t	cmd_acc_handle;
	ddi_acc_handle_t	rsp_acc_handle;
	uint_t		dest_nport_id;
	struct	sf_els_hdr	*next;
	struct	sf_els_hdr	*prev;
	uint_t		size;
	uint_t		timeout;
	uint_t		retries;
	struct fcal_packet	*fpkt;
	uint_t		lip_cnt;
	uchar_t		port_wwn[FC_WWN_SIZE];
	uchar_t		node_wwn[FC_WWN_SIZE];
	struct sf_target *target;
	ddi_dma_handle_t	data_dma_handle;
	ddi_acc_handle_t	data_acc_handle;
	caddr_t			data_buf;
};

union sf_els_cmd {
	struct la_els_logi logi;
	struct la_els_logo logo;
	struct la_els_prli prli;
	struct la_els_adisc adisc;
	struct fcp_cmd cmd;
};

union sf_els_rsp {
	struct la_els_logi logi;
	struct la_els_logo logo;
	struct la_els_prli prli;
	struct la_els_adisc adisc;
	uchar_t rsp[FCP_MAX_RSP_IU_SIZE];
};

struct sf_hp_elem {
	struct sf_hp_elem *next;
	dev_info_t	*dip;
	int		what;
	struct sf_target *target;
	struct sf	*sf;
};
#define	SF_ONLINE	0
#define	SF_OFFLINE	1


#define	ADDR2SF(ap)	(struct sf *)((ap)->a_hba_tran->tran_hba_private)
#define	ADDR2TARGET(ap)	(struct sf_target *)((ap)->a_hba_tran->\
    tran_tgt_private)
#define	SF_ONLINE_TIMEOUT	180
#define	SF_OFFLINE_TIMEOUT	45
#define	SF_RESET_TIMEOUT	10
#define	SF_ELS_TIMEOUT		5
#define	SF_INVALID_TIMEOUT	0x7fffffff
#define	SF_FCP_TIMEOUT		30
#define	SF_BSY_TIMEOUT		10
#define	SF_ABORT_TIMEOUT	10000000	/* in usec */
#define	SF_POLL_TIMEOUT	60
#define	SF_TARGET_RESET_DELAY	250000		/* in usec */

#define	SF_DECR_DELTA		5
#define	SF_INCR_DELTA		5

#define	SF_LO_CMD_DELTA	512
#define	SF_HI_CMD_DELTA	256

#define	SF_ELS_RETRIES		4
#define	SF_BSY_RETRIES		7

#define	SF_INIT_WAIT_TIMEOUT	60000000
#define		SF_CORE_CMD_TIMEOUT		0x01
#define		SF_CORE_BAD_ABORT		0x02
#define		SF_CORE_ABORT_TIMEOUT		0x04
#define		SF_CORE_ELS_TIMEOUT		0x08
#define		SF_CORE_ELS_FAILED		0x10
#define		SF_CORE_LILP_FAILED		0x20
#define		SF_CORE_OFFLINE_TIMEOUT		0x40
#define		SF_CORE_LIP_FAILED		0x80
#define		SF_CORE_OFFLINE_TARGET		0x100
#define		SF_CORE_INCOMPLETE_DMA		0x200
#define		SF_CORE_REPORTLUN_TIMEOUT	0x400
#define		SF_CORE_INQUIRY_TIMEOUT		0x800
#define		SF_CORE_BAD_DMA			0x1000

#define		SF_BAD_DMA_MAGIC	0xdeafbead

#define	TRUE		1
#define	FALSE		0
#define	UNDEFINED	-1


/*
 * The initiator must allocate a minimum of 16 bytes for the response
 * to the REPORT_LUNS command.  Since there is 8 bytes of overhead and
 * each LUN is 4 bytes, this means that the minimum size is 2 LUNs.  We
 * will define the structure that way to prevent any spurious check
 * conditions.
 *
 * There is no maximum size for the response.
 *
 * By default we support 256 LUNs for the moment, which means 256*8+16
 * or 2064 bytes total size.
 */

#define	REPORT_LUNS_MIN_LUNS	2
#define	REPORT_LUNS_DEFAULT	256
#define	REPORT_LUNS_SIZE	((REPORT_LUNS_DEFAULT)*sizeof (uint32_t) \
				+2*sizeof (uint32_t))

/*
 * SCSI Report_Luns Data
 *
 * Format of data returned as a result of an REPORT_LUNS command.
 *
 */

struct scsi_report_luns {
	/* Number of bytes of data the target has available to send. */
	uint32_t	lun_list_len;
	uint32_t	reserved;
	uint64_t	lun[REPORT_LUNS_MIN_LUNS];
};

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_SFVAR_H */
