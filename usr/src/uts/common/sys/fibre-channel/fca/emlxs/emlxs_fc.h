/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_FC_H
#define	_EMLXS_FC_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct emlxs_buf
{
	fc_packet_t		*pkt;		/* scsi_pkt reference */
	struct emlxs_port	*port;		/* pointer to port */
	void			*bmp;		/* Save the buffer pointer */
						/* list for later use. */
	struct emlxs_buf	*fc_fwd;	/* Use it by chip_Q */
	struct emlxs_buf	*fc_bkwd;	/* Use it by chip_Q */
	struct emlxs_buf	*next;		/* Use it when the iodone */
	struct emlxs_node 	*node;
	void			*channel;	/* Save channel and used by */
						/* abort */
	struct emlxs_buf	*fpkt;		/* Flush pkt pointer */
	struct XRIobj		*xrip;		/* Exchange resource */
	IOCBQ			iocbq;
	kmutex_t		mtx;
	uint32_t		pkt_flags;
	uint32_t		iotag;		/* iotag for this cmd */
	uint32_t		ticks;		/* save the timeout ticks */
						/* for the fc_packet_t */
	uint32_t		abort_attempts;
	uint32_t		lun;
#define	EMLXS_LUN_NONE		0xFFFFFFFF

	uint32_t		class;		/* Save class and used by */
						/* abort */
	uint32_t		ucmd;		/* Unsolicted command that */
						/* this packet is responding */
						/* to, if any */
	int32_t			flush_count;	/* Valid only in flush pkts */
	uint32_t		did;

#ifdef SFCT_SUPPORT
	kmutex_t		fct_mtx;
	fc_packet_t		*fct_pkt;
	fct_cmd_t		*fct_cmd;

	uint8_t			fct_type;

#define	EMLXS_FCT_ELS_CMD		0x01	/* Unsolicted */
#define	EMLXS_FCT_ELS_REQ		0x02	/* Solicited */
#define	EMLXS_FCT_ELS_RSP		0x04
#define	EMLXS_FCT_CT_REQ		0x08	/* Solicited */
#define	EMLXS_FCT_FCP_CMD		0x10	/* Unsolicted */
#define	EMLXS_FCT_FCP_DATA		0x20
#define	EMLXS_FCT_FCP_STATUS		0x40


	uint8_t			fct_flags;

#define	EMLXS_FCT_SEND_STATUS		0x01
#define	EMLXS_FCT_ABORT_INP		0x02
#define	EMLXS_FCT_IO_INP		0x04
#define	EMLXS_FCT_PLOGI_RECEIVED	0x10
#define	EMLXS_FCT_REGISTERED		0x20

	uint16_t		fct_state;

#define	EMLXS_FCT_FCP_CMD_RECEIVED	1
#define	EMLXS_FCT_ELS_CMD_RECEIVED	2
#define	EMLXS_FCT_CMD_POSTED		3
#define	EMLXS_FCT_CMD_WAITQ		4
#define	EMLXS_FCT_SEND_CMD_RSP		5
#define	EMLXS_FCT_SEND_ELS_RSP		6
#define	EMLXS_FCT_SEND_ELS_REQ		7
#define	EMLXS_FCT_SEND_CT_REQ		8
#define	EMLXS_FCT_RSP_PENDING		9
#define	EMLXS_FCT_REQ_PENDING		10
#define	EMLXS_FCT_REG_PENDING		11
#define	EMLXS_FCT_REG_COMPLETE		12
#define	EMLXS_FCT_OWNED			13
#define	EMLXS_FCT_SEND_FCP_DATA		14
#define	EMLXS_FCT_SEND_FCP_STATUS	15
#define	EMLXS_FCT_DATA_PENDING		16
#define	EMLXS_FCT_STATUS_PENDING	17
#define	EMLXS_FCT_PKT_COMPLETE		18
#define	EMLXS_FCT_PKT_FCPRSP_COMPLETE	19
#define	EMLXS_FCT_PKT_ELSRSP_COMPLETE	20
#define	EMLXS_FCT_PKT_ELSCMD_COMPLETE	21
#define	EMLXS_FCT_PKT_CTCMD_COMPLETE	22
#define	EMLXS_FCT_REQ_COMPLETE		23
#define	EMLXS_FCT_CLOSE_PENDING		24
#define	EMLXS_FCT_ABORT_PENDING		25
#define	EMLXS_FCT_ABORT_DONE		26
#define	EMLXS_FCT_IO_DONE		27

#define	EMLXS_FCT_IOCB_ISSUED		256 /* For tracing only */
#define	EMLXS_FCT_IOCB_COMPLETE		257 /* For tracing only */

	stmf_data_buf_t		*fct_buf;

#endif /* SFCT_SUPPORT */

#ifdef SAN_DIAG_SUPPORT
	hrtime_t		sd_start_time;
#endif /* SAN_DIAG_SUPPORT */

} emlxs_buf_t;



#ifdef FCT_IO_TRACE
#define	EMLXS_FCT_STATE_CHG(_fct_cmd, _cmd_sbp, _state)	\
	(_cmd_sbp)->fct_state = _state;			\
	emlxs_fct_io_trace((_cmd_sbp)->port, _fct_cmd, _state)
#else
/* define to set fct_state */
#define	EMLXS_FCT_STATE_CHG(_fct_cmd, _cmd_sbp, _state)	\
	(_cmd_sbp)->fct_state = _state
#endif /* FCT_IO_TRACE */


/* pkt_flags */
#define	PACKET_IN_COMPLETION	0x00000001
#define	PACKET_IN_TXQ		0x00000002
#define	PACKET_IN_CHIPQ		0x00000004
#define	PACKET_IN_DONEQ		0x00000008

#define	PACKET_FCP_RESET	0x00000030
#define	PACKET_FCP_TGT_RESET	0x00000010
#define	PACKET_FCP_LUN_RESET	0x00000020
#define	PACKET_POLLED		0x00000040

#ifdef EMLXS_I386
#define	PACKET_FCP_SWAPPED	0x00000100
#define	PACKET_ELS_SWAPPED	0x00000200
#define	PACKET_CT_SWAPPED	0x00000400
#define	PACKET_CSP_SWAPPED	0x00000800
#endif	/* EMLXS_I386 */

#define	PACKET_STALE		0x00001000

#define	PACKET_IN_TIMEOUT	0x00010000
#define	PACKET_IN_FLUSH		0x00020000
#define	PACKET_IN_ABORT		0x00040000
#define	PACKET_XRI_CLOSED	0x00080000 /* An XRI abort/close was issued */

#define	PACKET_CHIP_COMP	0x00100000
#define	PACKET_COMPLETED	0x00200000
#define	PACKET_ULP_OWNED	0x00400000

#define	PACKET_STATE_VALID	0x01000000
#define	PACKET_FCP_RSP_VALID	0x02000000
#define	PACKET_ELS_RSP_VALID	0x04000000
#define	PACKET_CT_RSP_VALID	0x08000000

#define	PACKET_DELAY_REQUIRED	0x10000000
#define	PACKET_ALLOCATED	0x40000000
#define	PACKET_VALID		0x80000000


#define	STALE_PACKET		((emlxs_buf_t *)0xFFFFFFFF)


/*
 * From fc_error.h pkt_reason (except for state = NPORT_RJT, FABRIC_RJT,
 * NPORT_BSY, FABRIC_BSY, LS_RJT, BA_RJT, FS_RJT)
 *
 * FCA unique error codes can begin after FC_REASON_FCA_UNIQUE.
 * Each FCA defines its own set with values greater >= 0x7F
 */
#define	FC_REASON_FCA_DEFINED   0x100


/*
 * Device VPD save area
 */

typedef struct emlxs_vpd
{
	uint32_t	biuRev;
	uint32_t	smRev;
	uint32_t	smFwRev;
	uint32_t	endecRev;
	uint16_t	rBit;
	uint8_t		fcphHigh;
	uint8_t		fcphLow;
	uint8_t		feaLevelHigh;
	uint8_t		feaLevelLow;

	uint32_t	postKernRev;
	char		postKernName[32];

	uint32_t	opFwRev;
	char		opFwName[32];
	char		opFwLabel[32];

	uint32_t	sli1FwRev;
	char		sli1FwName[32];
	char		sli1FwLabel[32];

	uint32_t	sli2FwRev;
	char		sli2FwName[32];
	char		sli2FwLabel[32];

	uint32_t	sli3FwRev;
	char		sli3FwName[32];
	char		sli3FwLabel[32];

	uint32_t	sli4FwRev;
	char		sli4FwName[32];
	char		sli4FwLabel[32];

	char		fw_version[32];
	char		fw_label[32];

	char		fcode_version[32];
	char		boot_version[32];

	char		serial_num[32];
	char		part_num[32];
	char		port_num[20];
	char		eng_change[32];
	char		manufacturer[80];
	char		model[80];
	char		model_desc[256];
	char		prog_types[256];
	char		id[256];

	uint32_t	port_index;
	uint16_t	link_speed;
} emlxs_vpd_t;


typedef struct emlxs_queue
{
	void		*q_first;	/* queue first element */
	void		*q_last;	/* queue last element */
	uint16_t	q_cnt;	/* current length of queue */
	uint16_t	q_max;	/* max length queue can get */
} emlxs_queue_t;
typedef emlxs_queue_t Q;



/*
 * This structure is used when allocating a buffer pool.
 * Note: this should be identical to gasket buf_info (fldl.h).
 */
typedef struct emlxs_buf_info
{
	int32_t		size;	/* Specifies the number of bytes to allocate. */
	int32_t		align;	/* The desired address boundary. */

	int32_t		flags;

#define	FC_MBUF_DMA		0x01	/* blocks are for DMA */
#define	FC_MBUF_PHYSONLY	0x02	/* For malloc - map a given virtual */
					/* address to physical address (skip */
					/* the malloc). */
					/* For free - just unmap the given */
					/* physical address (skip the free). */
#define	FC_MBUF_IOCTL		0x04	/* called from dfc_ioctl */
#define	FC_MBUF_UNLOCK		0x08	/* called with driver unlocked */
#define	FC_MBUF_SNGLSG		0x10	/* allocate a single contiguous */
					/* physical memory */
#define	FC_MBUF_DMA32		0x20

	uint64_t	phys;		/* specifies physical buffer pointer */
	void		*virt;		/* specifies virtual buffer pointer */
	void		*data_handle;
	void		*dma_handle;
} emlxs_buf_info_t;
typedef emlxs_buf_info_t MBUF_INFO;


#define	EMLXS_MAX_HBQ   	16	/* Max HBQs handled by firmware */
#define	EMLXS_ELS_HBQ_ID	0
#define	EMLXS_IP_HBQ_ID		1
#define	EMLXS_CT_HBQ_ID		2
#define	EMLXS_FCT_HBQ_ID	3

#ifdef SFCT_SUPPORT
#define	EMLXS_NUM_HBQ		4	/* Number of HBQs supported by driver */
#else
#define	EMLXS_NUM_HBQ		3	/* Number of HBQs supported by driver */
#endif /* SFCT_SUPPORT */


/*
 * An IO Channel is a object that comprises a xmit/cmpl
 * path for IOs.
 * For SLI3, an IO path maps to a ring (cmd/rsp)
 * For SLI4, an IO path map to a queue pair (WQ/CQ)
 */
typedef struct emlxs_channel
{
	struct emlxs_hba *hba;			/* ptr to hba for channel */
	void		*iopath;		/* ptr to SLI3/4 io path */

	kmutex_t	rsp_lock;
	IOCBQ		*rsp_head;	/* deferred completion head */
	IOCBQ		*rsp_tail;	/* deferred completion tail */
	emlxs_thread_t  intr_thread;


	uint16_t	channelno;
	uint16_t	chan_flag;

#define	EMLXS_NEEDS_TRIGGER 1

	/* Protected by EMLXS_TX_CHANNEL_LOCK */
	emlxs_queue_t	nodeq;			/* Node service queue */

	kmutex_t	channel_cmd_lock;
	uint32_t	timeout;

	/* Channel command counters */
	uint32_t	ulpSendCmd;
	uint32_t	ulpCmplCmd;
	uint32_t	hbaSendCmd;
	uint32_t	hbaCmplCmd;
	uint32_t	hbaSendCmd_sbp;
	uint32_t	hbaCmplCmd_sbp;

} emlxs_channel_t;
typedef emlxs_channel_t CHANNEL;

/*
 * Should be able to handle max number of io paths for a
 * SLI4 HBA (EMLXS_MAX_WQS) or for a SLI3 HBA (MAX_RINGS)
 */
#define	MAX_CHANNEL EMLXS_MSI_MAX_INTRS


/* Structure used to access adapter rings */
typedef struct emlxs_ring
{
	void		*fc_cmdringaddr;	/* virtual offset for cmd */
						/* rings */
	void		*fc_rspringaddr;	/* virtual offset for rsp */
						/* rings */

	void		*fc_mpon;		/* index ptr for match */
						/* structure */
	void		*fc_mpoff;		/* index ptr for match */
						/* structure */
	struct emlxs_hba *hba;			/* ptr to hba for ring */

	uint8_t		fc_numCiocb;		/* number of command iocb's */
						/* per ring */
	uint8_t		fc_numRiocb;		/* number of response iocb's */
						/* per ring */
	uint8_t		fc_rspidx;		/* current index in response */
						/* ring */
	uint8_t		fc_cmdidx;		/* current index in command */
						/* ring */
	uint8_t		fc_port_rspidx;
	uint8_t		fc_port_cmdidx;
	uint8_t		ringno;

	uint16_t	fc_missbufcnt;		/* buf cnt we need to repost */
	CHANNEL		*channelp;


} emlxs_ring_t;
typedef emlxs_ring_t RING;


#ifdef SAN_DIAG_SUPPORT
/*
 * Although right now it's just 1 field, SAN Diag anticipates that this
 * structure will grow in the future.
 */
typedef struct sd_timestat_level0 {
	int		count;
} sd_timestat_level0_t;
#endif

typedef struct emlxs_node
{
	struct emlxs_node	*nlp_list_next;
	struct emlxs_node	*nlp_list_prev;

	NAME_TYPE		nlp_portname;	/* port name */
	NAME_TYPE		nlp_nodename;	/* node name */

	uint32_t		nlp_DID;	/* fibre channel D_ID */

	uint16_t		nlp_Rpi;	/* login id returned by */
						/* REG_LOGIN */
	uint16_t		nlp_Xri;	/* login id returned by */
						/* REG_LOGIN */

	uint8_t			nlp_fcp_info;	/* Remote class info */

	/* nlp_fcp_info */
#define	NLP_FCP_TGT_DEVICE	0x10	/* FCP TGT device */
#define	NLP_FCP_INI_DEVICE	0x20	/* FCP Initiator device */
#define	NLP_FCP_2_DEVICE	0x40	/* FCP-2 TGT device */
#define	NLP_EMLX_VPORT		0x80    /* Virtual port */

	uint8_t			dfc_state;
#define	EMLXS_SET_DFC_STATE(_n, _state)	if (_n && _n->nlp_active)\
		{(_n)->dfc_state = (_state); }

	uint32_t		nlp_force_rscn;
	uint32_t		nlp_tag;	/* Tag used by port_offline */
	uint32_t		flag;

#define	NODE_POOL_ALLOCATED 	0x00000001

	SERV_PARM		sparm;

	/* Protected by EMLXS_TX_CHANNEL_LOCK */
	uint32_t		nlp_active;	/* Node active flag */
	uint32_t		nlp_base;
	uint32_t		nlp_flag[MAX_CHANNEL];	/* Node level channel */
							/* flags */

	/* nlp_flag */
#define	NLP_CLOSED		0x1
#define	NLP_OFFLINE		0x2
#define	NLP_RPI_XRI		0x4

	uint32_t		nlp_tics[MAX_CHANNEL];	/* gate timeout */
	emlxs_queue_t		nlp_tx[MAX_CHANNEL];	/* Transmit Q head */
	emlxs_queue_t		nlp_ptx[MAX_CHANNEL];	/* Priority transmit */
							/* Queue head */
	void			*nlp_next[MAX_CHANNEL];	/* Service Request */
							/* Queue pointer used */
							/* when node needs */
							/* servicing */
#ifdef DHCHAP_SUPPORT
	emlxs_node_dhc_t	node_dhc;
#endif	/* DHCHAP_SUPPORT */

#ifdef SAN_DIAG_SUPPORT
	sd_timestat_level0_t	sd_dev_bucket[SD_IO_LATENCY_MAX_BUCKETS];
#endif

	struct RPIobj		*rpip;	/* SLI4 only */
#define	EMLXS_NODE_TO_RPI(_p, _n)	\
	((_n)?((_n->rpip)?_n->rpip:emlxs_rpi_find(_p, _n->nlp_Rpi)):NULL)

#ifdef NODE_THROTTLE_SUPPORT
	uint32_t io_throttle;
	uint32_t io_active;
#endif /* NODE_THROTTLE_SUPPORT */

} emlxs_node_t;
typedef emlxs_node_t NODELIST;



#define	NADDR_LEN	6	/* MAC network address length */
typedef struct emlxs_fcip_nethdr
{
	NAME_TYPE	fc_destname;	/* destination port name */
	NAME_TYPE	fc_srcname;	/* source port name */
} emlxs_fcip_nethdr_t;
typedef emlxs_fcip_nethdr_t NETHDR;


#define	MEM_NLP		0	/* memory segment to hold node list entries */
#define	MEM_IOCB	1	/* memory segment to hold iocb commands */
#define	MEM_MBOX	2	/* memory segment to hold mailbox cmds  */
#define	MEM_BPL		3	/* and to hold buffer ptr lists - SLI2   */
#define	MEM_BUF		4	/* memory segment to hold buffer data   */
#define	MEM_ELSBUF	4	/* memory segment to hold buffer data   */
#define	MEM_IPBUF	5	/* memory segment to hold IP buffer data */
#define	MEM_CTBUF	6	/* memory segment to hold CT buffer data */
#define	MEM_FCTBUF	7	/* memory segment to hold FCT buffer data */

#ifdef SFCT_SUPPORT
#define	FC_MAX_SEG	8
#define	MEM_FCTSEG	10 /* must be greater than FC_MAX_SEG */
#else
#define	FC_MAX_SEG	7
#endif /* SFCT_SUPPORT */


/* A BPL entry is 12 bytes. Subtract 2 for command and response buffers */
#define	BPL_TO_SGLLEN(_bpl)	((_bpl/12)-2)
#define	MEM_BPL_SIZE		36 /* Default size */

/* A SGL entry is 16 bytes. Subtract 2 for command and response buffers */
#define	SGL_TO_SGLLEN(_sgl)	((_sgl/16)-2)
#define	MEM_SGL_SIZE		4096 /* Default size */

#define	MEM_BUF_SIZE		1024
#define	MEM_BUF_COUNT		64

#define	MEM_ELSBUF_SIZE   	MEM_BUF_SIZE
#define	MEM_ELSBUF_COUNT  	hba->max_nodes
#define	MEM_IPBUF_SIZE  	65535
#define	MEM_IPBUF_COUNT		60
#define	MEM_CTBUF_SIZE		MAX_CT_PAYLOAD	/* (1024*320) */
#define	MEM_CTBUF_COUNT		8
#define	MEM_FCTBUF_SIZE  	65535
#define	MEM_FCTBUF_COUNT	128

typedef struct emlxs_memseg
{
	void			*fc_memget_ptr;
	void			*fc_memget_end;
	void			*fc_memput_ptr;
	void			*fc_memput_end;

	uint32_t		fc_total_memsize;
	uint32_t		fc_memsize;		/* size of mem blks */
	uint32_t		fc_numblks;		/* no of mem blks */
	uint32_t		fc_memget_cnt;		/* no of mem get blks */
	uint32_t		fc_memput_cnt;		/* no of mem put blks */
	uint32_t		fc_memflag;  /* emlxs_buf_info_t FLAGS */
#define	FC_MEMSEG_PUT_ENABLED	0x20000000
#define	FC_MEMSEG_GET_ENABLED	0x40000000
#define	FC_MEMSEG_DYNAMIC	0x80000000

	uint32_t		fc_memalign;
	uint32_t		fc_memtag;
	char			fc_label[32];

	uint32_t		fc_hi_water;
	uint32_t		fc_lo_water;
	uint32_t		fc_step;  /* Dyn increment.  Zero = static */
	uint32_t		fc_low;   /* Lowest free count (dyn only) */
	uint32_t		fc_last;  /* Last fc_numblks (dyn only) */

} emlxs_memseg_t;
typedef emlxs_memseg_t MEMSEG;


/* Board stat counters */
typedef struct emlxs_stats
{
	uint32_t	LinkUp;
	uint32_t	LinkDown;
	uint32_t	LinkEvent;
	uint32_t	LinkMultiEvent;

	uint32_t	MboxIssued;
	uint32_t	MboxCompleted;	/* MboxError + MbxGood */
	uint32_t	MboxGood;
	uint32_t	MboxError;
	uint32_t	MboxBusy;
	uint32_t	MboxInvalid;

	uint32_t	IocbIssued[MAX_CHANNEL];
	uint32_t	IocbReceived[MAX_CHANNEL];
	uint32_t	IocbTxPut[MAX_CHANNEL];
	uint32_t	IocbTxGet[MAX_CHANNEL];
	uint32_t	IocbRingFull[MAX_CHANNEL];
	uint32_t	IocbThrottled;

	uint32_t	IntrEvent[8];

	uint32_t	FcpIssued;
	uint32_t	FcpCompleted;	/* FcpGood + FcpError */
	uint32_t	FcpGood;
	uint32_t	FcpError;

	uint32_t	FcpEvent;	/* FcpStray + FcpCompleted */
	uint32_t	FcpStray;
#ifdef SFCT_SUPPORT
	uint32_t	FctRingEvent;
	uint32_t	FctRingError;
	uint32_t	FctRingDropped;
#endif /* SFCT_SUPPORT */

	uint32_t	ElsEvent;	/* ElsStray + ElsCmplt (cmd + rsp) */
	uint32_t	ElsStray;

	uint32_t	ElsCmdIssued;
	uint32_t	ElsCmdCompleted;	/* ElsCmdGood + ElsCmdError */
	uint32_t	ElsCmdGood;
	uint32_t	ElsCmdError;

	uint32_t	ElsRspIssued;
	uint32_t	ElsRspCompleted;

	uint32_t	ElsRcvEvent;	/* ElsRcvErr + ElsRcvDrop + ElsCmdRcv */
	uint32_t	ElsRcvError;
	uint32_t	ElsRcvDropped;
	uint32_t	ElsCmdReceived;	/* ElsRscnRcv + ElsPlogiRcv + ... */
	uint32_t	ElsRscnReceived;
	uint32_t	ElsFlogiReceived;
	uint32_t	ElsPlogiReceived;
	uint32_t	ElsPrliReceived;
	uint32_t	ElsPrloReceived;
	uint32_t	ElsLogoReceived;
	uint32_t	ElsAdiscReceived;
	uint32_t	ElsAuthReceived;
	uint32_t	ElsGenReceived;

	uint32_t	CtEvent;	/* CtStray + CtCompleted (cmd + rsp) */
	uint32_t	CtStray;

	uint32_t	CtCmdIssued;
	uint32_t	CtCmdCompleted;	/* CtCmdGood + CtCmdError */
	uint32_t	CtCmdGood;
	uint32_t	CtCmdError;

	uint32_t	CtRspIssued;
	uint32_t	CtRspCompleted;

	uint32_t	CtRcvEvent;	/* CtRcvError + CtRcvDrop + CtCmdRcvd */
	uint32_t	CtRcvError;
	uint32_t	CtRcvDropped;
	uint32_t	CtCmdReceived;

	uint32_t	IpEvent;	/* IpStray + IpSeqCmpl + IpBcastCmpl */
	uint32_t	IpStray;

	uint32_t	IpSeqIssued;
	uint32_t	IpSeqCompleted;	/* IpSeqGood + IpSeqError */
	uint32_t	IpSeqGood;
	uint32_t	IpSeqError;

	uint32_t	IpBcastIssued;
	uint32_t	IpBcastCompleted;	/* IpBcastGood + IpBcastError */
	uint32_t	IpBcastGood;
	uint32_t	IpBcastError;

	uint32_t	IpRcvEvent;	/* IpDrop + IpSeqRcv + IpBcastRcv */
	uint32_t	IpDropped;
	uint32_t	IpSeqReceived;
	uint32_t	IpBcastReceived;

	uint32_t	IpUbPosted;
	uint32_t	ElsUbPosted;
	uint32_t	CtUbPosted;
#ifdef SFCT_SUPPORT
	uint32_t	FctUbPosted;
#endif /* SFCT_SUPPORT */

	uint32_t	ResetTime;	/* Time of last reset */

	uint32_t	ElsTestReceived;
	uint32_t	ElsEstcReceived;
	uint32_t	ElsFarprReceived;
	uint32_t	ElsEchoReceived;
	uint32_t	ElsRlsReceived;
	uint32_t	ElsRtvReceived;

} emlxs_stats_t;


#define	FC_MAX_ADPTMSG   (8*28)	/* max size of a msg from adapter */

#define	EMLXS_NUM_THREADS	8
#define	EMLXS_MIN_TASKS		8
#define	EMLXS_MAX_TASKS		8

#define	EMLXS_NUM_HASH_QUES	32
#define	EMLXS_DID_HASH(x)	((x) & (EMLXS_NUM_HASH_QUES - 1))


/* pkt_tran_flag */
#define	FC_TRAN_COMPLETED	0x8000


typedef struct emlxs_dfc_event
{
	uint32_t	pid;
	uint32_t	event;
	uint32_t	last_id;

	void		*dataout;
	uint32_t	size;
	uint32_t	mode;
} emlxs_dfc_event_t;


typedef struct emlxs_hba_event
{
	uint32_t	last_id;
	uint32_t	new;
	uint32_t	missed;
} emlxs_hba_event_t;


#ifdef SFCT_SUPPORT

#define	TGTPORTSTAT			port->fct_stat

/*
 * FctP2IOXcnt will count IOs by their fcpDL. Counters
 * are for buckets of various power of 2 sizes.
 * Bucket 0  <  512  > 0
 * Bucket 1  >= 512  < 1024
 * Bucket 2  >= 1024 < 2048
 * Bucket 3  >= 2048 < 4096
 * Bucket 4  >= 4096 < 8192
 * Bucket 5  >= 8192 < 16K
 * Bucket 6  >= 16K  < 32K
 * Bucket 7  >= 32K  < 64K
 * Bucket 8  >= 64K  < 128K
 * Bucket 9  >= 128K < 256K
 * Bucket 10 >= 256K < 512K
 * Bucket 11 >= 512K < 1MB
 * Bucket 12 >= 1MB  < 2MB
 * Bucket 13 >= 2MB  < 4MB
 * Bucket 14 >= 4MB  < 8MB
 * Bucket 15 >= 8MB
 */
#define	MAX_TGTPORT_IOCNT  16


/*
 * These routines will bump the right counter, based on
 * the size of the IO inputed, with the least number of
 * comparisions.  A max of 5 comparisions is only needed
 * to classify the IO in one of 16 ranges. A binary search
 * to locate the high bit in the size is used.
 */
#define	EMLXS_BUMP_RDIOCTR(port, cnt) \
{ \
	/* Use binary search to find the first high bit */ \
	if (cnt & 0xffff0000) { \
		if (cnt & 0xff800000) { \
			TGTPORTSTAT.FctP2IORcnt[15]++; \
		} \
		else { \
			/* It must be 0x007f0000 */ \
			if (cnt & 0x00700000) { \
				if (cnt & 0x00400000) { \
					TGTPORTSTAT.FctP2IORcnt[14]++; \
				} \
				else { \
					/* it must be 0x00300000 */ \
					if (cnt & 0x00200000) { \
						TGTPORTSTAT.FctP2IORcnt[13]++; \
					} \
					else { \
						/* It must be 0x00100000 */ \
						TGTPORTSTAT.FctP2IORcnt[12]++; \
					} \
				} \
			} \
			else { \
				/* It must be 0x000f0000 */ \
				if (cnt & 0x000c0000) {	\
					if (cnt & 0x00080000) {	\
						TGTPORTSTAT.FctP2IORcnt[11]++; \
					} \
					else { \
						/* It must be 0x00040000 */ \
						TGTPORTSTAT.FctP2IORcnt[10]++; \
					} \
				} \
				else { \
					/* It must be 0x00030000 */ \
					if (cnt & 0x00020000) {	\
						TGTPORTSTAT.FctP2IORcnt[9]++; \
					} \
					else { \
						/* It must be 0x00010000 */ \
						TGTPORTSTAT.FctP2IORcnt[8]++; \
					} \
				} \
			} \
		} \
	} \
	else { \
		if (cnt & 0x0000fe00) { \
			if (cnt & 0x0000f000) { \
				if (cnt & 0x0000c000) { \
					if (cnt & 0x00008000) { \
						TGTPORTSTAT.FctP2IORcnt[7]++; \
					} \
					else { \
						/* It must be 0x00004000 */ \
						TGTPORTSTAT.FctP2IORcnt[6]++; \
					} \
				} \
				else { \
					/* It must be 0x00000300 */ \
					if (cnt & 0x00000200) { \
						TGTPORTSTAT.FctP2IORcnt[5]++; \
					} \
					else { \
						/* It must be 0x00000100 */ \
						TGTPORTSTAT.FctP2IORcnt[4]++; \
					} \
				} \
			} \
			else { \
				/* It must be 0x00000e00 */ \
				if (cnt & 0x00000800) { \
					TGTPORTSTAT.FctP2IORcnt[3]++; \
				} \
				else { \
					/* It must be 0x00000600 */ \
					if (cnt & 0x00000400) { \
						TGTPORTSTAT.FctP2IORcnt[2]++; \
					} \
					else { \
						/* It must be 0x00000200 */ \
						TGTPORTSTAT.FctP2IORcnt[1]++; \
					} \
				} \
			} \
		} \
		else { \
			/* It must be 0x000001ff */ \
			TGTPORTSTAT.FctP2IORcnt[0]++; \
		} \
	} \
}


#define	EMLXS_BUMP_WRIOCTR(port, cnt) \
{ \
/* Use binary search to find the first high bit */ \
	if (cnt & 0xffff0000) { \
		if (cnt & 0xff800000) { \
			TGTPORTSTAT.FctP2IOWcnt[15]++; \
		} \
		else { \
			/* It must be 0x007f0000 */ \
			if (cnt & 0x00700000) { \
				if (cnt & 0x00400000) { \
					TGTPORTSTAT.FctP2IOWcnt[14]++; \
				} \
				else { \
					/* It must be 0x00300000 */ \
					if (cnt & 0x00200000) { \
						TGTPORTSTAT.FctP2IOWcnt[13]++; \
					} \
					else { \
						/* It must be 0x00100000 */ \
						TGTPORTSTAT.FctP2IOWcnt[12]++; \
					} \
				} \
			} \
			else { \
				/* It must be 0x000f0000 */ \
				if (cnt & 0x000c0000) { \
					if (cnt & 0x00080000) { \
						TGTPORTSTAT.FctP2IOWcnt[11]++; \
					} \
					else { \
						/* it must be 0x00040000 */ \
						TGTPORTSTAT.FctP2IOWcnt[10]++; \
					} \
				} \
				else { \
					/* It must be 0x00030000 */ \
					if (cnt & 0x00020000) { \
						TGTPORTSTAT.FctP2IOWcnt[9]++; \
					} \
					else { \
						/* It must be 0x00010000 */ \
						TGTPORTSTAT.FctP2IOWcnt[8]++; \
					} \
				} \
			} \
		} \
	} \
	else { \
		if (cnt & 0x0000fe00) { \
			if (cnt & 0x0000f000) { \
				if (cnt & 0x0000c000) { \
					if (cnt & 0x00008000) { \
						TGTPORTSTAT.FctP2IOWcnt[7]++; \
					} \
					else { \
						/* It must be 0x00004000 */ \
						TGTPORTSTAT.FctP2IOWcnt[6]++; \
					} \
				} \
				else { \
					/* It must be 0x00000300 */ \
					if (cnt & 0x00000200) { \
						TGTPORTSTAT.FctP2IOWcnt[5]++; \
					} \
					else { \
						/* It must be 0x00000100 */ \
						TGTPORTSTAT.FctP2IOWcnt[4]++; \
					} \
				} \
			} \
			else { \
				/* It must be 0x00000e00 */ \
				if (cnt & 0x00000800) { \
					TGTPORTSTAT.FctP2IOWcnt[3]++; \
				} \
				else { \
					/* It must be 0x00000600 */ \
					if (cnt & 0x00000400) { \
						TGTPORTSTAT.FctP2IOWcnt[2]++; \
					} \
					else { \
						/* It must be 0x00000200 */ \
						TGTPORTSTAT.FctP2IOWcnt[1]++; \
					} \
				} \
			} \
		} \
		else { \
			/* It must be 0x000001ff */ \
			TGTPORTSTAT.FctP2IOWcnt[0]++; \
		} \
	} \
}

typedef struct emlxs_tgtport_stat
{
	/* IO counters */
	uint64_t	FctP2IOWcnt[MAX_TGTPORT_IOCNT]; /* Writes */
	uint64_t	FctP2IORcnt[MAX_TGTPORT_IOCNT]; /* Reads  */
	uint64_t	FctIOCmdCnt;			/* Other, ie TUR */
	uint64_t	FctCmdReceived;			/* total IOs */
	uint64_t	FctReadBytes;			/* total read bytes */
	uint64_t	FctWriteBytes;			/* total write bytes */

	/* IOCB handling counters */
	uint64_t	FctEvent;	/* FctStray + FctCompleted */
	uint64_t	FctCompleted;	/* FctCmplGood + FctCmplError */
	uint64_t	FctCmplGood;

	uint32_t	FctCmplError;
	uint32_t	FctStray;

	/* Fct event counters */
	uint32_t	FctRcvDropped;
	uint32_t	FctOverQDepth;
	uint32_t	FctOutstandingIO;
	uint32_t	FctFailedPortRegister;
	uint32_t	FctPortRegister;
	uint32_t	FctPortDeregister;

	uint32_t	FctAbortSent;
	uint32_t	FctNoBuffer;
	uint32_t	FctScsiStatusErr;
	uint32_t	FctScsiQfullErr;
	uint32_t	FctScsiResidOver;
	uint32_t	FctScsiResidUnder;
	uint32_t	FctScsiSenseErr;

	uint32_t	FctFiller1;
} emlxs_tgtport_stat_t;

#ifdef FCT_IO_TRACE
#define	MAX_IO_TRACE	67
typedef struct emlxs_iotrace
{
	fct_cmd_t	*fct_cmd;
	uint32_t	xri;
	uint8_t		marker;  /* 0xff */
	uint8_t		trc[MAX_IO_TRACE]; /* trc[0] = index */
} emlxs_iotrace_t;
#endif /* FCT_IO_TRACE */
#endif /* SFCT_SUPPORT */


#include <emlxs_fcf.h>

/*
 *     Port Information Data Structure
 */

typedef struct emlxs_port
{
	struct emlxs_hba	*hba;

	/* Virtual port management */
	struct VPIobj		VPIobj;
	struct VPIobj		*vpip; /* &VPIobj */

	uint32_t		vpi;	/* Legacy vpi == vpip->index */
	uint32_t		mode;
	uint32_t		mode_mask; /* User configured */
#define	MODE_NONE			0x00000000
#define	MODE_INITIATOR			0x00000001
#define	MODE_TARGET			0x00000002
#define	MODE_ALL			0x00000003

	uint32_t		flag;
#define	EMLXS_PORT_ENABLED		0x00000001 /* vport setting */
#define	EMLXS_PORT_CONFIG		0x00000002 /* vport setting */

#define	EMLXS_INI_ENABLED		0x00000010 /* emlxs_mode_init */
#define	EMLXS_INI_BOUND			0x00000020 /* emlxs_fca_bind_port */
#define	EMLXS_TGT_ENABLED		0x00000040 /* emlxs_mode_init */
#define	EMLXS_TGT_BOUND			0x00000080 /* emlxs_fct_bind_port */
#define	EMLXS_PORT_BOUND		(EMLXS_INI_BOUND|EMLXS_TGT_BOUND)

#define	EMLXS_PORT_IP_UP		0x00000100
#define	EMLXS_PORT_RESTRICTED		0x00000200 /* Restrict logins */

#define	EMLXS_PORT_REG_VPI		0x00010000 /* SLI3 */
#define	EMLXS_PORT_REG_VPI_CMPL		0x00020000 /* SLI3 */

#define	EMLXS_PORT_FLOGI_CMPL		0x01000000	/* Fabric login */
							/* completed */

#define	EMLXS_PORT_RESET_MASK		0x0000FFFF	/* Flags to keep */
							/* across hard reset */
#define	EMLXS_PORT_LINKDOWN_MASK	0x00FFFFFF	/* Flags to keep */
							/* across link reset */

	uint32_t		options;
#define	EMLXS_OPT_RESTRICT		0x00000001 /* Force restricted */
						/* logins */
#define	EMLXS_OPT_UNRESTRICT		0x00000002 /* Force Unrestricted */
						/* logins */
#define	EMLXS_OPT_RESTRICT_MASK		0x00000003


	/* FC world wide names */
	NAME_TYPE		wwnn;
	NAME_TYPE		wwpn;
	char			snn[256];
	char			spn[256];

	/* Common service paramters */
	SERV_PARM		sparam;
	SERV_PARM		fabric_sparam;
	SERV_PARM		prev_fabric_sparam;

	/* fc_id management */
	uint32_t		did;
	uint32_t		prev_did;

	/* support FC_PORT_GET_P2P_INFO only */
	uint32_t		rdid;

	/* FC_AL management */
	uint8_t			lip_type;
	uint8_t			granted_alpa;
	uint8_t			alpa_map[128];

	/* Node management */
	emlxs_node_t		node_base;
	uint32_t		node_count;
	krwlock_t		node_rwlock;
	emlxs_node_t		*node_table[EMLXS_NUM_HASH_QUES];

	/* Polled packet management */
	kcondvar_t		pkt_lock_cv;	/* pkt polling */
	kmutex_t		pkt_lock;	/* pkt polling */

	/* ULP */
	uint32_t		ulp_busy;
	uint32_t		ulp_statec;
	void			(*ulp_statec_cb) ();	/* Port state change */
							/* callback routine */
	void			(*ulp_unsol_cb) ();	/* unsolicited event */
							/* callback routine */
	opaque_t		ulp_handle;

	/* ULP unsolicited buffers */
	kmutex_t		ub_lock;
	uint32_t		ub_count;
	emlxs_unsol_buf_t	*ub_pool;
	uint32_t		ub_post[MAX_CHANNEL];
	uint32_t		ub_timer;

	emlxs_ub_priv_t		*ub_wait_head;	/* Unsolicited IO received */
						/* before link up */
	emlxs_ub_priv_t		*ub_wait_tail;	/* Unsolicited IO received */
						/* before link up */

#ifdef DHCHAP_SUPPORT
	emlxs_port_dhc_t	port_dhc;
#endif	/* DHCHAP_SUPPORT */

#ifdef SFCT_SUPPORT
	emlxs_memseg_t	*fct_memseg; /* Array */
	uint32_t fct_memseg_cnt;

/* Default buffer counts */
#define	FCT_BUF_COUNT_2K		16
#define	FCT_BUF_COUNT_4K		0
#define	FCT_BUF_COUNT_8K		16
#define	FCT_BUF_COUNT_16K		0
#define	FCT_BUF_COUNT_32K		0
#define	FCT_BUF_COUNT_64K		16
#define	FCT_BUF_COUNT_128K		16
#define	FCT_BUF_COUNT_256K		0

	char			cfd_name[24];
	stmf_port_provider_t	*port_provider;
	fct_local_port_t	*fct_port;
	uint8_t			fct_els_only_bmap;
	uint32_t		fct_flags;

#define	FCT_STATE_PORT_ONLINE		0x00000001
#define	FCT_STATE_NOT_ACKED		0x00000002
#define	FCT_STATE_LINK_UP		0x00000010
#define	FCT_STATE_LINK_UP_ACKED		0x00000020
#define	FCT_STATE_FLOGI_CMPL		0x00000040

	emlxs_tgtport_stat_t	fct_stat;

	/* Used to save fct_cmd for deferred unsol ELS commands, except FLOGI */
	emlxs_buf_t		*fct_wait_head;
	emlxs_buf_t		*fct_wait_tail;

	/* Used to save context for deferred unsol FLOGIs */
	fct_flogi_xchg_t	fx;

#ifdef FCT_IO_TRACE
	emlxs_iotrace_t		*iotrace;
	uint16_t		iotrace_cnt;
	uint16_t		iotrace_index;
	kmutex_t		iotrace_mtx;
#endif /* FCT_IO_TRACE */

#endif /* SFCT_SUPPORT */

	uint32_t		clean_address_timer;
	emlxs_buf_t		*clean_address_sbp;

#ifdef SAN_DIAG_SUPPORT
	uint8_t			sd_io_latency_state;
#define	SD_INVALID	0x00
#define	SD_COLLECTING	0x01
#define	SD_STOPPED	0x02

	/* SD event management list */
	uint32_t		sd_event_mask;   /* bit-mask */
	emlxs_dfc_event_t	sd_events[MAX_DFC_EVENTS];
#endif

} emlxs_port_t;


/* Host Attn reg */
#define	FC_HA_REG(_hba)		((volatile uint32_t *) \
				    ((_hba)->sli.sli3.ha_reg_addr))

/* Chip Attn reg */
#define	FC_CA_REG(_hba)		((volatile uint32_t *) \
				    ((_hba)->sli.sli3.ca_reg_addr))

/* Host Status reg */
#define	FC_HS_REG(_hba)		((volatile uint32_t *) \
				    ((_hba)->sli.sli3.hs_reg_addr))

/* Host Cntl reg */
#define	FC_HC_REG(_hba)		((volatile uint32_t *) \
				    ((_hba)->sli.sli3.hc_reg_addr))

/* BIU Configuration reg */
#define	FC_BC_REG(_hba)		((volatile uint32_t *) \
				    ((_hba)->sli.sli3.bc_reg_addr))

/* Used by SBUS adapter */
/* TITAN Cntl reg */
#define	FC_SHC_REG(_hba)	((volatile uint32_t *) \
				    ((_hba)->sli.sli3.shc_reg_addr))

/* TITAN Status reg */
#define	FC_SHS_REG(_hba)	((volatile uint32_t *) \
				    ((_hba)->sli.sli3.shs_reg_addr))

/* TITAN Update reg */
#define	FC_SHU_REG(_hba)	((volatile uint32_t *) \
				    ((_hba)->sli.sli3.shu_reg_addr))

/* MPU Semaphore reg */
#define	FC_SEMA_REG(_hba)	((volatile uint32_t *)\
				    ((_hba)->sli.sli4.MPUEPSemaphore_reg_addr))

/* Bootstrap Mailbox Doorbell reg */
#define	FC_MBDB_REG(_hba)	((volatile uint32_t *) \
				    ((_hba)->sli.sli4.MBDB_reg_addr))

/* MQ Doorbell reg */
#define	FC_MQDB_REG(_hba)	((volatile uint32_t *) \
				    ((_hba)->sli.sli4.MQDB_reg_addr))

/* CQ Doorbell reg */
#define	FC_CQDB_REG(_hba)	((volatile uint32_t *) \
				    ((_hba)->sli.sli4.CQDB_reg_addr))

/* WQ Doorbell reg */
#define	FC_WQDB_REG(_hba)	((volatile uint32_t *) \
				    ((_hba)->sli.sli4.WQDB_reg_addr))

/* RQ Doorbell reg */
#define	FC_RQDB_REG(_hba)	((volatile uint32_t *) \
				    ((_hba)->sli.sli4.RQDB_reg_addr))


#define	FC_SLIM2_MAILBOX(_hba)	((MAILBOX *)(_hba)->sli.sli3.slim2.virt)

#define	FC_SLIM1_MAILBOX(_hba)	((MAILBOX *)(_hba)->sli.sli3.slim_addr)

#define	FC_MAILBOX(_hba)	(((_hba)->flag & FC_SLIM2_MODE) ? \
	FC_SLIM2_MAILBOX(_hba) : FC_SLIM1_MAILBOX(_hba))

#define	WRITE_CSR_REG(_hba, _regp, _value) ddi_put32(\
	(_hba)->sli.sli3.csr_acc_handle, (uint32_t *)(_regp), \
	(uint32_t)(_value))

#define	READ_CSR_REG(_hba, _regp) ddi_get32(\
	(_hba)->sli.sli3.csr_acc_handle, (uint32_t *)(_regp))

#define	WRITE_SLIM_ADDR(_hba, _regp, _value) ddi_put32(\
	(_hba)->sli.sli3.slim_acc_handle, (uint32_t *)(_regp), \
	(uint32_t)(_value))

#define	READ_SLIM_ADDR(_hba, _regp) ddi_get32(\
	(_hba)->sli.sli3.slim_acc_handle, (uint32_t *)(_regp))

#define	WRITE_SLIM_COPY(_hba, _bufp, _slimp, _wcnt) ddi_rep_put32(\
	(_hba)->sli.sli3.slim_acc_handle, (uint32_t *)(_bufp), \
	(uint32_t *)(_slimp), (_wcnt), DDI_DEV_AUTOINCR)

#define	READ_SLIM_COPY(_hba, _bufp, _slimp, _wcnt) ddi_rep_get32(\
	(_hba)->sli.sli3.slim_acc_handle, (uint32_t *)(_bufp), \
	(uint32_t *)(_slimp), (_wcnt), DDI_DEV_AUTOINCR)

/* Used by SBUS adapter */
#define	WRITE_SBUS_CSR_REG(_hba, _regp, _value)	ddi_put32(\
	(_hba)->sli.sli3.sbus_csr_handle, (uint32_t *)(_regp), \
	(uint32_t)(_value))

#define	READ_SBUS_CSR_REG(_hba, _regp) ddi_get32(\
	(_hba)->sli.sli3.sbus_csr_handle, (uint32_t *)(_regp))

#define	SBUS_WRITE_FLASH_COPY(_hba, _offset, _value) ddi_put8(\
	(_hba)->sli.sli3.sbus_flash_acc_handle, \
	(uint8_t *)((volatile uint8_t *)(_hba)->sli.sli3.sbus_flash_addr + \
	(_offset)), (uint8_t)(_value))

#define	SBUS_READ_FLASH_COPY(_hba, _offset) ddi_get8(\
	(_hba)->sli.sli3.sbus_flash_acc_handle, \
	(uint8_t *)((volatile uint8_t *)(_hba)->sli.sli3.sbus_flash_addr + \
	(_offset)))

/* SLI4 registers */
#define	WRITE_BAR0_REG(_hba, _regp, _value) ddi_put32(\
	(_hba)->sli.sli4.bar0_acc_handle, (uint32_t *)(_regp), \
	(uint32_t)(_value))

#define	READ_BAR0_REG(_hba, _regp) ddi_get32(\
	(_hba)->sli.sli4.bar0_acc_handle, (uint32_t *)(_regp))

#define	WRITE_BAR1_REG(_hba, _regp, _value) ddi_put32(\
	(_hba)->sli.sli4.bar1_acc_handle, (uint32_t *)(_regp), \
	(uint32_t)(_value))

#define	READ_BAR1_REG(_hba, _regp) ddi_get32(\
	(_hba)->sli.sli4.bar1_acc_handle, (uint32_t *)(_regp))

#define	WRITE_BAR2_REG(_hba, _regp, _value) ddi_put32(\
	(_hba)->sli.sli4.bar2_acc_handle, (uint32_t *)(_regp), \
	(uint32_t)(_value))

#define	READ_BAR2_REG(_hba, _regp) ddi_get32(\
	(_hba)->sli.sli4.bar2_acc_handle, (uint32_t *)(_regp))


#define	EMLXS_STATE_CHANGE(_hba, _state)\
{									\
	mutex_enter(&EMLXS_PORT_LOCK);					\
	EMLXS_STATE_CHANGE_LOCKED((_hba), (_state));			\
	mutex_exit(&EMLXS_PORT_LOCK);					\
}

/* Used when EMLXS_PORT_LOCK is already held */
#define	EMLXS_STATE_CHANGE_LOCKED(_hba, _state)			\
{									\
	if ((_hba)->state != (_state))					\
	{								\
		uint32_t _st = _state;					\
		EMLXS_MSGF(EMLXS_CONTEXT,				\
			&emlxs_state_msg, "%s --> %s",			\
			emlxs_ffstate_xlate((_hba)->state),		\
			emlxs_ffstate_xlate(_state));			\
			(_hba)->state = (_state);			\
		if ((_st) == FC_ERROR)					\
		{							\
			(_hba)->flag |= FC_HARDWARE_ERROR;		\
		}							\
	}								\
}

#ifdef FMA_SUPPORT
#define	EMLXS_CHK_ACC_HANDLE(_hba, _acc) \
	if (emlxs_fm_check_acc_handle(_hba, _acc) != DDI_FM_OK) { \
		EMLXS_MSGF(EMLXS_CONTEXT, \
		    &emlxs_invalid_access_handle_msg, NULL); \
	}
#endif  /* FMA_SUPPORT */

/*
 * This is the HBA control area for the adapter
 */

#ifdef MODSYM_SUPPORT

typedef struct emlxs_modsym
{
	ddi_modhandle_t  mod_fctl;	/* For Leadville */

	/* Leadville (fctl) */
	int		(*fc_fca_attach)(dev_info_t *, fc_fca_tran_t *);
	int		(*fc_fca_detach)(dev_info_t *);
	int		(*fc_fca_init)(struct dev_ops *);

#ifdef SFCT_SUPPORT
	uint32_t	fct_modopen;
	uint32_t	reserved;  /* Padding for alignment */

	ddi_modhandle_t  mod_fct;	/* For Comstar */
	ddi_modhandle_t  mod_stmf;	/* For Comstar */

	/* Comstar (fct) */
	void*	(*fct_alloc)(fct_struct_id_t, int, int);
	void	(*fct_free)(void *);
	void*	(*fct_scsi_task_alloc)(void *, uint16_t, uint32_t, uint8_t *,
			uint16_t, uint16_t);
	int	(*fct_register_local_port)(fct_local_port_t *);
	void	(*fct_deregister_local_port)(fct_local_port_t *);
	void	(*fct_handle_event)(fct_local_port_t *, int, uint32_t, caddr_t);
	void	(*fct_post_rcvd_cmd)(fct_cmd_t *, stmf_data_buf_t *);
	void	(*fct_ctl)(void *, int, void *);
	void	(*fct_queue_cmd_for_termination)(fct_cmd_t *, fct_status_t);
	void	(*fct_send_response_done)(fct_cmd_t *, fct_status_t, uint32_t);
	void	(*fct_send_cmd_done)(fct_cmd_t *, fct_status_t, uint32_t);
	void	(*fct_scsi_data_xfer_done)(fct_cmd_t *, stmf_data_buf_t *,
			uint32_t);
	fct_status_t	(*fct_port_shutdown)
				(fct_local_port_t *, uint32_t, char *);
	fct_status_t	(*fct_port_initialize)
				(fct_local_port_t *, uint32_t, char *);
	void		(*fct_cmd_fca_aborted)
				(fct_cmd_t *, fct_status_t, int);
	fct_status_t	(*fct_handle_rcvd_flogi)
				(fct_local_port_t *, fct_flogi_xchg_t *);

	/* Comstar (stmf) */
	void*  (*stmf_alloc)(stmf_struct_id_t, int, int);
	void   (*stmf_free)(void *);
	void	(*stmf_deregister_port_provider) (stmf_port_provider_t *);
	int	(*stmf_register_port_provider) (stmf_port_provider_t *);
#endif /* SFCT_SUPPORT */
} emlxs_modsym_t;
extern emlxs_modsym_t emlxs_modsym;

#define	MODSYM(_f)	emlxs_modsym._f

#else

#define	MODSYM(_f)	_f

#endif /* MODSYM_SUPPORT */



typedef struct RPIHdrTmplate
{
	uint32_t	Word[16];  /* 64 bytes */
} RPIHdrTmplate_t;


typedef struct EQ_DESC
{
	uint16_t	host_index;
	uint16_t	max_index;
	uint16_t	qid;
	uint16_t	msix_vector;
	kmutex_t	lastwq_lock;
	uint16_t	lastwq;
	MBUF_INFO	addr;

	/* Statistics */
	uint32_t	max_proc;
	uint32_t	isr_count;
	uint32_t	num_proc;
} EQ_DESC_t;


typedef struct CQ_DESC
{
	uint16_t	host_index;
	uint16_t	max_index;
	uint16_t	qid;
	uint16_t	eqid;
	uint16_t	type;
#define	EMLXS_CQ_TYPE_GROUP1	1  /* associated with a MQ and async events */
#define	EMLXS_CQ_TYPE_GROUP2	2  /* associated with a WQ and RQ */
	uint16_t	rsvd;

	MBUF_INFO	addr;
	CHANNEL		*channelp; /* ptr to CHANNEL associated with CQ */

	/* Statistics */
	uint32_t	max_proc;
	uint32_t	isr_count;
	uint32_t	num_proc;
} CQ_DESC_t;


typedef struct WQ_DESC
{
	uint16_t	host_index;
	uint16_t	max_index;
	uint16_t	port_index;
	uint16_t	release_depth;
#define	WQE_RELEASE_DEPTH	(8 * EMLXS_NUM_WQ_PAGES)
	uint16_t	qid;
	uint16_t	cqid;
	MBUF_INFO	addr;

	/* Statistics */
	uint32_t	num_proc;
	uint32_t	num_busy;
} WQ_DESC_t;


typedef struct RQ_DESC
{
	uint16_t	host_index;
	uint16_t	max_index;
	uint16_t	qid;
	uint16_t	cqid;

	MBUF_INFO	addr;
	MBUF_INFO	rqb[RQ_DEPTH];

	kmutex_t	lock;

	/* Statistics */
	uint32_t	num_proc;
} RQ_DESC_t;


typedef struct RXQ_DESC
{
	kmutex_t	lock;
	emlxs_queue_t	active;

} RXQ_DESC_t;


typedef struct MQ_DESC
{
	uint16_t	host_index;
	uint16_t	max_index;
	uint16_t	qid;
	uint16_t	cqid;
	MBUF_INFO	addr;
} MQ_DESC_t;


/* Define the number of queues the driver will be using */
#define	EMLXS_MAX_EQS	EMLXS_MSI_MAX_INTRS
#define	EMLXS_MAX_WQS	EMLXS_MAX_WQS_PER_EQ * EMLXS_MAX_EQS
#define	EMLXS_MAX_RQS	2	/* ONLY 1 pair is allowed */
#define	EMLXS_MAX_MQS	1

/* One CQ for each WQ & (RQ pair) plus one for the MQ */
#define	EMLXS_MAX_CQS	(EMLXS_MAX_WQS + (EMLXS_MAX_RQS/2) + 1)

/* The First CQ created is ALWAYS for mbox / event handling */
#define	EMLXS_CQ_MBOX		0

/* The Second CQ created is ALWAYS for unsol rcv handling */
/* At this time we are allowing ONLY 1 pair of RQs */
#define	EMLXS_CQ_RCV		1

/* The remaining CQs are for WQ completions */
#define	EMLXS_CQ_OFFSET_WQ	2


/* FCFI RQ Configuration */
#define	EMLXS_FCFI_RQ0_INDEX	0
#define	EMLXS_FCFI_RQ0_RMASK	0 /* match all */
#define	EMLXS_FCFI_RQ0_RCTL	0 /* match all */
#define	EMLXS_FCFI_RQ0_TMASK	0 /* match all */
#define	EMLXS_FCFI_RQ0_TYPE	0 /* match all */

#define	EMLXS_RXQ_ELS		0
#define	EMLXS_RXQ_CT		1
#define	EMLXS_MAX_RXQS		2

#define	PCI_CONFIG_SIZE   0x80

typedef struct emlxs_sli3
{
	/* SLIM management */
	MATCHMAP	slim2;

	/* HBQ management */
	uint32_t	hbq_count;	/* Total number of HBQs */
					/* configured */
	HBQ_INIT_t	hbq_table[EMLXS_NUM_HBQ];

	/* Adapter memory management */
	caddr_t		csr_addr;
	caddr_t		slim_addr;
	ddi_acc_handle_t csr_acc_handle;
	ddi_acc_handle_t slim_acc_handle;

	/* SBUS adapter management */
	caddr_t		sbus_flash_addr;	/* Virt addr of R/W */
						/* Flash */
	caddr_t		sbus_core_addr;		/* Virt addr of TITAN */
						/* CORE */
	caddr_t		sbus_csr_addr;		/* Virt addr of TITAN */
						/* CSR */
	ddi_acc_handle_t sbus_flash_acc_handle;
	ddi_acc_handle_t sbus_core_acc_handle;
	ddi_acc_handle_t sbus_csr_handle;

	/* SLI 2/3 Adapter register management */
	uint32_t	*bc_reg_addr;	/* virtual offset for BIU */
					/* config reg */
	uint32_t	*ha_reg_addr;	/* virtual offset for host */
					/* attn reg */
	uint32_t	*hc_reg_addr;	/* virtual offset for host */
					/* ctl reg */
	uint32_t	*ca_reg_addr;	/* virtual offset for FF */
					/* attn reg */
	uint32_t	*hs_reg_addr;	/* virtual offset for */
					/* status reg */
	uint32_t	*shc_reg_addr;	/* virtual offset for SBUS */
					/* Ctrl reg */
	uint32_t	*shs_reg_addr;	/* virtual offset for SBUS */
					/* Status reg */
	uint32_t	*shu_reg_addr;	/* virtual offset for SBUS */
					/* Update reg */
	uint16_t	hgp_ring_offset;
	uint16_t	hgp_hbq_offset;
	uint16_t	iocb_cmd_size;
	uint16_t	iocb_rsp_size;
	uint32_t	hc_copy;	/* local copy of HC register */

	/* Ring management */
	uint32_t	ring_count;
	emlxs_ring_t	ring[MAX_RINGS];
	kmutex_t	ring_cmd_lock[MAX_RINGS];
	uint8_t		ring_masks[4];	/* number of masks/rings used */
	uint8_t		ring_rval[6];
	uint8_t		ring_rmask[6];
	uint8_t		ring_tval[6];
	uint8_t		ring_tmask[6];

	/* Protected by EMLXS_FCTAB_LOCK */
	MATCHMAP	**bpl_table; /* iotag table for */
					/* bpl buffers */
	uint32_t	mem_bpl_size;
} emlxs_sli3_t;

typedef struct emlxs_sli4
{
	MATCHMAP	bootstrapmb;
	caddr_t		bar0_addr;
	caddr_t		bar1_addr;
	caddr_t		bar2_addr;
	ddi_acc_handle_t bar0_acc_handle;
	ddi_acc_handle_t bar1_acc_handle;
	ddi_acc_handle_t bar2_acc_handle;

	/* SLI4 Adapter register management */
	uint32_t	*MPUEPSemaphore_reg_addr;
	uint32_t	*MBDB_reg_addr;

	uint32_t	*CQDB_reg_addr;
	uint32_t	*MQDB_reg_addr;
	uint32_t	*WQDB_reg_addr;
	uint32_t	*RQDB_reg_addr;
	uint32_t	*SEMA_reg_addr;
	uint32_t	*STATUS_reg_addr;
	uint32_t	*CNTL_reg_addr;
	uint32_t	*ERR1_reg_addr;
	uint32_t	*ERR2_reg_addr;
	uint32_t	*PHYSDEV_reg_addr;

	uint32_t	flag;
#define	EMLXS_SLI4_INTR_ENABLED		0x00000001
#define	EMLXS_SLI4_HW_ERROR		0x00000002
#define	EMLXS_SLI4_DOWN_LINK		0x00000004
#define	EMLXS_SLI4_PHON			0x00000008
#define	EMLXS_SLI4_PHWQ			0x00000010
#define	EMLXS_SLI4_NULL_XRI		0x00000020

#define	EMLXS_SLI4_FCF_INIT		0x10000000
#define	EMLXS_SLI4_FCOE_MODE		0x80000000

#define	SLI4_FCOE_MODE	(hba->sli.sli4.flag & EMLXS_SLI4_FCOE_MODE)
#define	SLI4_FC_MODE	(!SLI4_FCOE_MODE)



	uint16_t	XRICount;
	uint16_t	XRIExtCount;
	uint16_t	XRIExtSize;
	uint16_t	XRIBase[MAX_EXTENTS];

	uint16_t	RPICount;
	uint16_t	RPIExtCount;
	uint16_t	RPIExtSize;
	uint16_t	RPIBase[MAX_EXTENTS];

	uint16_t	VPICount;
	uint16_t	VPIExtCount;
	uint16_t	VPIExtSize;
	uint16_t	VPIBase[MAX_EXTENTS];

	uint16_t	VFICount;
	uint16_t	VFIExtCount;
	uint16_t	VFIExtSize;
	uint16_t	VFIBase[MAX_EXTENTS];

	uint16_t	FCFICount;

	kmutex_t	fcf_lock;
	FCFTable_t	fcftab;
	VFIobj_t	*VFI_table;

	/* Save Config Region 23 info */
	tlv_fcoe_t	cfgFCOE;
	tlv_fcfconnectlist_t	cfgFCF;

	MBUF_INFO	slim2;
	MBUF_INFO	dump_region;
#define	EMLXS_DUMP_REGION_SIZE	1024

	RPIobj_t	*RPIp;
	MBUF_INFO	HeaderTmplate;
	XRIobj_t	*XRIp;

	/* Double linked list for available XRIs */
	XRIobj_t	*XRIfree_f;
	XRIobj_t	*XRIfree_b;
	uint32_t	xrif_count;
	uint32_t	mem_sgl_size;

	/* Double linked list for XRIs in use */
	XRIobj_t	*XRIinuse_f;
	XRIobj_t	*XRIinuse_b;
	uint32_t	xria_count;

	kmutex_t	que_lock[EMLXS_MAX_WQS];
	EQ_DESC_t	eq[EMLXS_MAX_EQS];
	CQ_DESC_t	cq[EMLXS_MAX_CQS];
	WQ_DESC_t	wq[EMLXS_MAX_WQS];
	RQ_DESC_t	rq[EMLXS_MAX_RQS];
	RXQ_DESC_t	rxq[EMLXS_MAX_RXQS];
	MQ_DESC_t	mq;
	uint32_t	que_stat_timer;

	uint32_t	ue_mask_lo;
	uint32_t	ue_mask_hi;

	sli_params_t	param;

	uint8_t port_name[4];
	uint32_t link_number;

} emlxs_sli4_t;


typedef struct emlxs_sli_api
{
	int		(*sli_map_hdw)();
	void		(*sli_unmap_hdw)();
	int32_t		(*sli_online)();
	void		(*sli_offline)();
	uint32_t	(*sli_hba_reset)();
	void		(*sli_hba_kill)();
	void		(*sli_issue_iocb_cmd)();
	uint32_t	(*sli_issue_mbox_cmd)();
	uint32_t	(*sli_prep_fct_iocb)();
	uint32_t	(*sli_prep_fcp_iocb)();
	uint32_t	(*sli_prep_ip_iocb)();
	uint32_t	(*sli_prep_els_iocb)();
	uint32_t	(*sli_prep_ct_iocb)();
	void		(*sli_poll_intr)();
	int32_t		(*sli_intx_intr)();
	uint32_t	(*sli_msi_intr)();
	void		(*sli_disable_intr)();
	void		(*sli_timer)();
	void		(*sli_poll_erratt)();
	uint32_t	(*sli_reg_did)();
	uint32_t	(*sli_unreg_node)();

} emlxs_sli_api_t;


typedef struct emlxs_hba
{
	dev_info_t	*dip;
	int32_t		emlxinst;
	int32_t		ddiinst;
	uint8_t		pci_function_number;
	uint8_t		pci_device_number;
	uint8_t		pci_bus_number;
	uint8_t		pci_cap_offset[PCI_CAP_MAX_PTR];
	uint16_t	pci_ecap_offset[PCI_EXT_CAP_MAX_PTR];

#ifdef FMA_SUPPORT
	int32_t		fm_caps;	/* FMA capabilities */
#endif	/* FMA_SUPPORT */
	fc_fca_tran_t	*fca_tran;

	/* DMA attributes */
	ddi_dma_attr_t	dma_attr;
	ddi_dma_attr_t	dma_attr_ro;
	ddi_dma_attr_t	dma_attr_1sg;
	ddi_dma_attr_t	dma_attr_fcip_rsp;

	/* HBA Info */
	emlxs_model_t	model_info;
	emlxs_vpd_t	vpd;	/* vital product data */
	NAME_TYPE	wwnn;
	NAME_TYPE	wwpn;
	char		snn[256];
	char		spn[256];
	PROG_ID		load_list[MAX_LOAD_ENTRY];
	WAKE_UP_PARMS	wakeup_parms;
	uint32_t	max_nodes;
	uint32_t	io_throttle;
	uint32_t	io_active;
	uint32_t	bus_type;
#define	PCI_FC  	0
#define	SBUS_FC		1
	uint32_t	sli_intf;
#define	SLI_INTF_VALID_MASK		0xe0000000
#define	SLI_INTF_VALID			0xc0000000

#define	SLI_INTF_HINT2_MASK		0x1f000000
#define	SLI_INTF_HINT2_0		0x00000000

#define	SLI_INTF_HINT1_MASK		0x00ff0000
#define	SLI_INTF_HINT1_0		0x00000000
#define	SLI_INTF_HINT1_1		0x00010000
#define	SLI_INTF_HINT1_2		0x00020000

#define	SLI_INTF_IF_TYPE_MASK		0x0000f000
#define	SLI_INTF_IF_TYPE_0		0x00000000
#define	SLI_INTF_IF_TYPE_1		0x00001000
#define	SLI_INTF_IF_TYPE_2		0x00002000
#define	SLI_INTF_IF_TYPE_3		0x00003000

#define	SLI_INTF_FAMILY_MASK		0x00000f00
#define	SLI_INTF_FAMILY_BE2		0x00000000
#define	SLI_INTF_FAMILY_BE3		0x00000100
#define	SLI_INTF_FAMILY_LANCER_A	0x00000a00
#define	SLI_INTF_FAMILY_LANCER_B	0x00000b00

#define	SLI_INTF_SLI_REV_MASK		0x000000f0
#define	SLI_INTF_SLI_REV_NONE		0x00000000
#define	SLI_INTF_SLI_REV_3		0x00000030
#define	SLI_INTF_SLI_REV_4		0x00000040

#define	SLI_INTF_RESERVED1		0x0000000e

#define	SLI_INTF_FUNC_TYPE_MASK		0x00000001
#define	SLI_INTF_FUNC_PF		0x00000000
#define	SLI_INTF_FUNC_VF		0x00000001

	/* Link management */
	uint32_t	link_event_tag;
	uint8_t		topology;
	uint8_t		linkspeed;
	uint16_t	qos_linkspeed;
	uint32_t	linkup_wait_flag;
	kcondvar_t	linkup_lock_cv;
	kmutex_t	linkup_lock;

	/* Memory Pool management */
	emlxs_memseg_t	memseg[FC_MAX_SEG];	/* memory for buffer */
							/* structures */
	kmutex_t	memget_lock;	/* locks all memory pools get */
	kmutex_t	memput_lock;	/* locks all memory pools put */
	uint32_t	mem_timer;

	/* Fibre Channel Service Parameters */
	SERV_PARM	sparam;
	uint32_t	fc_edtov;	/* E_D_TOV timer value */
	uint32_t	fc_arbtov;	/* ARB_TOV timer value */
	uint32_t	fc_ratov;	/* R_A_TOV timer value */
	uint32_t	fc_rttov;	/* R_T_TOV timer value */
	uint32_t	fc_altov;	/* AL_TOV timer value */
	uint32_t	fc_crtov;	/* C_R_TOV timer value */
	uint32_t	fc_citov;	/* C_I_TOV timer value */

	/* Adapter State management */
	int32_t		state;
#define	FC_ERROR		0x01	/* Adapter shutdown */
#define	FC_KILLED		0x02	/* Adapter interlocked/killed */
#define	FC_WARM_START		0x03	/* Adapter reset, but not restarted */
#define	FC_INIT_START		0x10	/* Adapter restarted */
#define	FC_INIT_NVPARAMS	0x11
#define	FC_INIT_REV		0x12
#define	FC_INIT_CFGPORT		0x13
#define	FC_INIT_CFGRING		0x14
#define	FC_INIT_INITLINK	0x15
#define	FC_LINK_DOWN		0x20
#define	FC_LINK_DOWN_PERSIST	0x21
#define	FC_LINK_UP		0x30
#define	FC_CLEAR_LA		0x31
#define	FC_READY		0x40

	uint32_t	flag;
#define	FC_ONLINING_MODE	0x00000001
#define	FC_ONLINE_MODE		0x00000002
#define	FC_OFFLINING_MODE	0x00000004
#define	FC_OFFLINE_MODE		0x00000008

#define	FC_NPIV_ENABLED		0x00000010	/* NPIV enabled on adapter    */
#define	FC_NPIV_SUPPORTED	0x00000020	/* NPIV supported on fabric   */
#define	FC_NPIV_UNSUPPORTED	0x00000040	/* NPIV unsupported on fabric */
#define	FC_NPIV_LINKUP		0x00000100	/* NPIV enabled, supported, */
						/* and link is ready */
#define	FC_NPIV_DELAY_REQUIRED	0x00000200	/* Delay issuing FLOGI/FDISC */
						/* and NameServer cmds */

#define	FC_BOOTSTRAPMB_INIT	0x00000400
#define	FC_FIP_SUPPORTED	0x00000800	/* FIP supported */

#define	FC_FABRIC_ATTACHED	0x00001000
#define	FC_PT_TO_PT		0x00002000
#define	FC_BYPASSED_MODE	0x00004000
#define	FC_MENLO_MODE		0x00008000	/* Menlo maintenance mode */

#define	FC_DUMP_SAFE		0x00010000	/* Safe to DUMP */
#define	FC_DUMP_ACTIVE		0x00020000	/* DUMP in progress */
#define	FC_NEW_FABRIC		0x00040000

#define	FC_SLIM2_MODE		0x00100000	/* SLIM in host memory */
#define	FC_INTERLOCKED		0x00200000
#define	FC_HBQ_ENABLED		0x00400000
#define	FC_ASYNC_EVENTS		0x00800000

#define	FC_ILB_MODE		0x01000000
#define	FC_ELB_MODE		0x02000000
#define	FC_LOOPBACK_MODE	0x03000000	/* Loopback Mode Mask */
#define	FC_DUMP			0x04000000	/* DUMP in progress */
#define	FC_SHUTDOWN		0x08000000	/* SHUTDOWN in progress */

#define	FC_OVERTEMP_EVENT	0x10000000	/* FC_ERROR reason: */
						/* over temperature event */
#define	FC_MBOX_TIMEOUT		0x20000000	/* FC_ERROR reason: */
						/* mailbox timeout event */
#define	FC_DMA_CHECK_ERROR	0x40000000	/* Shared memory (slim,..) */
						/* DMA handle went bad */
#define	FC_HARDWARE_ERROR	0x80000000	/* FC_ERROR state triggered */

#define	FC_RESET_MASK		0x00030C1F	/* Bits to protect during */
						/* a hard reset */
#define	FC_LINKDOWN_MASK	0xFFF30C1F	/* Bits to protect during */
						/* a linkdown */

	uint32_t fw_timer;
	uint32_t fw_flag;
#define	FW_UPDATE_NEEDED	0x00000001
#define	FW_UPDATE_KERNEL	0x00000002

	uint32_t temperature;			/* Last reported temperature */

	/* SBUS adapter management */
	caddr_t		sbus_pci_addr;		/* Virt addr of TITAN */
						/* pci config */
	ddi_acc_handle_t sbus_pci_handle;

	/* PCI BUS adapter management */
	caddr_t		pci_addr;
	ddi_acc_handle_t pci_acc_handle;

	uint32_t	sli_mode;
#define	EMLXS_HBA_SLI1_MODE	1
#define	EMLXS_HBA_SLI2_MODE	2
#define	EMLXS_HBA_SLI3_MODE	3
#define	EMLXS_HBA_SLI4_MODE	4

	/* SLI private data */
	union {
		emlxs_sli3_t sli3;
		emlxs_sli4_t sli4;
	} sli;

	/* SLI API entry point routines */
	emlxs_sli_api_t sli_api;

	uint32_t	io_poll_count;	/* Number of poll commands */
					/* in progress */

	/* IO Completion management */
	uint32_t	iodone_count;	/* Number of IO's on done Q */
	/* Protected by EMLXS_PORT_LOCK  */
	emlxs_buf_t	*iodone_list;	/* fc_packet being deferred */
	emlxs_buf_t	*iodone_tail;	/* fc_packet being deferred */
	emlxs_thread_t	iodone_thread;
	emlxs_thread_t	*spawn_thread_head;
	emlxs_thread_t	*spawn_thread_tail;
	kmutex_t	spawn_lock;
	uint32_t	spawn_open;

	/* IO Channel management */
	int32_t		chan_count;
	emlxs_channel_t	chan[MAX_CHANNEL];
	kmutex_t	channel_tx_lock;
	uint8_t		channel_fcp;	/* Default channel to use for FCP IO */
#define	CHANNEL_FCT channel_fcp
	uint8_t		channel_ip;	/* Default channel to use for IP IO */
	uint8_t		channel_els;	/* Default channel to use for ELS IO */
	uint8_t		channel_ct;	/* Default channel to use for CT IO */

	/* IOTag management */
	emlxs_buf_t	**fc_table;	/* sc_buf pointers indexed by */
					/* iotag */
	uint16_t	fc_iotag;	/* used to identify I/Os */
	uint16_t	fc_oor_iotag;	/* OutOfRange (fc_table) iotags */
					/* typically used for Abort/close */
#define	EMLXS_MAX_ABORT_TAG	0x7fff
	uint16_t	max_iotag;	/* ALL IOCBs except aborts */
	kmutex_t	iotag_lock;
	uint32_t	io_count;		/* No of IO holding */
						/* regular iotag */
	uint32_t	channel_tx_count;	/* No of IO on tx Q */

	/* Mailbox Management */
	uint32_t	mbox_queue_flag;
	emlxs_queue_t	mbox_queue;
	void		*mbox_mqe;	/* active mbox mqe */
	void		*mbox_mbq;	/* active MAILBOXQ */
	kcondvar_t	mbox_lock_cv;	/* MBX_SLEEP */
	kmutex_t	mbox_lock;	/* MBX_SLEEP */
	uint32_t	mbox_timer;

	/* Interrupt management */
	void		*intr_arg;
	uint32_t	intr_unclaimed;
	uint32_t	intr_autoClear;
	uint32_t	intr_busy_cnt;

	uint32_t	intr_flags;
#define	EMLXS_INTX_INITED	0x0001
#define	EMLXS_INTX_ADDED	0x0002
#define	EMLXS_MSI_ENABLED	0x0010
#define	EMLXS_MSI_INITED	0x0020
#define	EMLXS_MSI_ADDED		0x0040
#define	EMLXS_INTR_INITED	(EMLXS_INTX_INITED|EMLXS_MSI_INITED)
#define	EMLXS_INTR_ADDED	(EMLXS_INTX_ADDED|EMLXS_MSI_ADDED)

#ifdef MSI_SUPPORT
	ddi_intr_handle_t *intr_htable;
	uint32_t	*intr_pri;
	int32_t		*intr_cap;
	uint32_t	intr_count;
	uint32_t	intr_type;
	uint32_t	intr_cond;
	uint32_t	intr_map[EMLXS_MSI_MAX_INTRS];
	uint32_t	intr_mask;

	kmutex_t	msiid_lock; /* for last_msiid */
	int		last_msiid;

	kmutex_t	intr_lock[EMLXS_MSI_MAX_INTRS];
	int			chan2msi[MAX_CHANNEL];
					/* Index is the channel id */
	int			msi2chan[EMLXS_MSI_MAX_INTRS];
					/* Index is the MSX-X msg id */
#endif	/* MSI_SUPPORT */

	uint32_t	heartbeat_timer;
	uint32_t	heartbeat_flag;
	uint32_t	heartbeat_active;

	/* IOCTL management */
	kmutex_t	ioctl_lock;
	uint32_t	ioctl_flags;
#define	EMLXS_OPEN		0x00000001
#define	EMLXS_OPEN_EXCLUSIVE	0x00000002

	/* Timer management */
	kcondvar_t	timer_lock_cv;
	kmutex_t	timer_lock;
	timeout_id_t	timer_id;
	uint32_t	timer_tics;
	uint32_t	timer_flags;
#define	EMLXS_TIMER_STARTED	0x0000001
#define	EMLXS_TIMER_BUSY	0x0000002
#define	EMLXS_TIMER_KILL	0x0000004
#define	EMLXS_TIMER_ENDED	0x0000008

	/* Misc Timers */
	uint32_t	linkup_timer;
	uint32_t	discovery_timer;
	uint32_t	pkt_timer;

	/* Power Management */
	uint32_t	pm_state;
	/* pm_state */
#define	EMLXS_PM_IN_ATTACH	0x00000001
#define	EMLXS_PM_IN_DETACH	0x00000002
#define	EMLXS_PM_IN_SOL_CB	0x00000010
#define	EMLXS_PM_IN_UNSOL_CB	0x00000020
#define	EMLXS_PM_IN_LINK_RESET	0x00000100
#define	EMLXS_PM_IN_HARD_RESET	0x00000200
#define	EMLXS_PM_SUSPENDED	0x01000000

	uint32_t	pm_level;
	/* pm_level */
#define	EMLXS_PM_ADAPTER_DOWN	0
#define	EMLXS_PM_ADAPTER_UP	1

	uint32_t	pm_busy;
	kmutex_t	pm_lock;
	uint8_t		pm_config[PCI_CONFIG_SIZE];
#ifdef IDLE_TIMER
	uint32_t	pm_idle_timer;
	uint32_t	pm_active;	/* Only used by timer */
#endif	/* IDLE_TIMER */

	/* Loopback management */
	uint32_t	loopback_tics;
	void		*loopback_pkt;

	/* Event management */
	emlxs_event_queue_t event_queue;
	uint32_t	event_mask;
	uint32_t	event_timer;
	emlxs_dfc_event_t dfc_event[MAX_DFC_EVENTS];
	emlxs_hba_event_t hba_event;

	/* Parameter management */
	emlxs_config_t	config[NUM_CFG_PARAM];

	/* Driver stat management */
	kstat_t		*kstat;
	emlxs_stats_t	stats;

	/* Log management */
	emlxs_msg_log_t	log;

	/* Port managment */
	uint32_t	vpi_max;
	uint32_t	vpi_high;
	uint32_t	num_of_ports;

	kmutex_t	port_lock;	/* locks port, nodes, rings */
	emlxs_port_t	port[MAX_VPORTS + 1];	/* port specific info */
						/* Last one is for */
						/* NPIV ready test */

#ifdef DHCHAP_SUPPORT
	kmutex_t	dhc_lock;
	kmutex_t	auth_lock;
	emlxs_auth_cfg_t	auth_cfg;	/* Default auth_cfg. */
						/* Points to list of entries. */
						/* Protected by auth_lock */
	uint32_t	auth_cfg_count;
	emlxs_auth_key_t	auth_key;	/* Default auth_key. */
						/* Points to list of entries. */
						/* Protected by auth_lock */
	uint32_t	auth_key_count;
	uint32_t	rdn_flag;
#endif	/* DHCHAP_SUPPORT */

#ifdef TEST_SUPPORT
	uint32_t	underrun_counter;
#endif /* TEST_SUPPORT */

#ifdef MODFW_SUPPORT
	ddi_modhandle_t	fw_modhandle;
#endif /* MODFW_SUPPORT */

#ifdef DUMP_SUPPORT
	emlxs_file_t	dump_txtfile;
	emlxs_file_t	dump_dmpfile;
	emlxs_file_t	dump_ceefile;
	kmutex_t	dump_lock;
#define	EMLXS_DUMP_LOCK		hba->dump_lock
#define	EMLXS_TXT_FILE		1
#define	EMLXS_DMP_FILE		2
#define	EMLXS_CEE_FILE		3

#define	EMLXS_DRV_DUMP		0
#define	EMLXS_TEMP_DUMP		1
#define	EMLXS_USER_DUMP		2

#endif /* DUMP_SUPPORT */

	uint32_t	reset_request;
#define	FC_LINK_RESET		1
#define	FC_PORT_RESET		2

	uint32_t	reset_state;
#define	FC_LINK_RESET_INP		1
#define	FC_PORT_RESET_INP		2

} emlxs_hba_t;

#define	EMLXS_SLI_MAP_HDW 		(hba->sli_api.sli_map_hdw)
#define	EMLXS_SLI_UNMAP_HDW		(hba->sli_api.sli_unmap_hdw)
#define	EMLXS_SLI_ONLINE		(hba->sli_api.sli_online)
#define	EMLXS_SLI_OFFLINE		(hba->sli_api.sli_offline)
#define	EMLXS_SLI_HBA_RESET		(hba->sli_api.sli_hba_reset)
#define	EMLXS_SLI_HBA_KILL		(hba->sli_api.sli_hba_kill)
#define	EMLXS_SLI_ISSUE_IOCB_CMD	(hba->sli_api.sli_issue_iocb_cmd)
#define	EMLXS_SLI_ISSUE_MBOX_CMD	(hba->sli_api.sli_issue_mbox_cmd)
#define	EMLXS_SLI_PREP_FCT_IOCB		(hba->sli_api.sli_prep_fct_iocb)
#define	EMLXS_SLI_PREP_FCP_IOCB		(hba->sli_api.sli_prep_fcp_iocb)
#define	EMLXS_SLI_PREP_IP_IOCB		(hba->sli_api.sli_prep_ip_iocb)
#define	EMLXS_SLI_PREP_ELS_IOCB		(hba->sli_api.sli_prep_els_iocb)
#define	EMLXS_SLI_PREP_CT_IOCB		(hba->sli_api.sli_prep_ct_iocb)
#define	EMLXS_SLI_POLL_INTR		(hba->sli_api.sli_poll_intr)
#define	EMLXS_SLI_INTX_INTR		(hba->sli_api.sli_intx_intr)
#define	EMLXS_SLI_MSI_INTR		(hba->sli_api.sli_msi_intr)
#define	EMLXS_SLI_DISABLE_INTR		(hba->sli_api.sli_disable_intr)
#define	EMLXS_SLI_TIMER			(hba->sli_api.sli_timer)
#define	EMLXS_SLI_POLL_ERRATT		(hba->sli_api.sli_poll_erratt)
#define	EMLXS_SLI_REG_DID		(hba->sli_api.sli_reg_did)
#define	EMLXS_SLI_UNREG_NODE		(hba->sli_api.sli_unreg_node)

#define	EMLXS_HBA_T  1  /* flag emlxs_hba_t is already typedefed */

#ifdef MSI_SUPPORT
#define	EMLXS_INTR_INIT(_hba, _m)		emlxs_msi_init(_hba, _m)
#define	EMLXS_INTR_UNINIT(_hba)			emlxs_msi_uninit(_hba)
#define	EMLXS_INTR_ADD(_hba)			emlxs_msi_add(_hba)
#define	EMLXS_INTR_REMOVE(_hba)			emlxs_msi_remove(_hba)
#else
#define	EMLXS_INTR_INIT(_hba, _m)		emlxs_intx_init(_hba, _m)
#define	EMLXS_INTR_UNINIT(_hba)			emlxs_intx_uninit(_hba)
#define	EMLXS_INTR_ADD(_hba)			emlxs_intx_add(_hba)
#define	EMLXS_INTR_REMOVE(_hba)			emlxs_intx_remove(_hba)
#endif	/* MSI_SUPPORT */


/* Power Management Component */
#define	EMLXS_PM_ADAPTER	0


#define	DRV_TIME	(uint32_t)(ddi_get_time() - emlxs_device.drv_timestamp)

#define	HBA			port->hba
#define	PPORT			hba->port[0]
#define	VPORT(x)		hba->port[x]
#define	EMLXS_TIMER_LOCK	hba->timer_lock
#define	VPD			hba->vpd
#define	CFG			hba->config[0]
#define	LOG			hba->log
#define	EVENTQ			hba->event_queue
#define	EMLXS_MBOX_LOCK		hba->mbox_lock
#define	EMLXS_MBOX_CV		hba->mbox_lock_cv
#define	EMLXS_LINKUP_LOCK	hba->linkup_lock
#define	EMLXS_LINKUP_CV		hba->linkup_lock_cv
#define	EMLXS_TX_CHANNEL_LOCK	hba->channel_tx_lock	/* ring txq lock */
#define	EMLXS_MEMGET_LOCK	hba->memget_lock	/* mempool get lock */
#define	EMLXS_MEMPUT_LOCK	hba->memput_lock	/* mempool put lock */
#define	EMLXS_IOCTL_LOCK	hba->ioctl_lock		/* ioctl lock */
#define	EMLXS_SPAWN_LOCK	hba->spawn_lock		/* spawn lock */
#define	EMLXS_PM_LOCK		hba->pm_lock		/* pm lock */
#define	HBASTATS		hba->stats
#define	EMLXS_CMD_RING_LOCK(n)	hba->sli.sli3.ring_cmd_lock[n]

#define	EMLXS_QUE_LOCK(n)	hba->sli.sli4.que_lock[n]
#define	EMLXS_MSIID_LOCK	hba->msiid_lock

#define	EMLXS_FCTAB_LOCK	hba->iotag_lock

#define	EMLXS_FCF_LOCK		hba->sli.sli4.fcf_lock

#define	EMLXS_PORT_LOCK		hba->port_lock		/* locks ports, */
							/* nodes, rings */
#define	EMLXS_INTR_LOCK(_id)	hba->intr_lock[_id]	/* locks intr threads */

#define	EMLXS_PKT_LOCK		port->pkt_lock		/* used for pkt */
							/* polling */
#define	EMLXS_PKT_CV		port->pkt_lock_cv	/* Used for pkt */
							/* polling */
#define	EMLXS_UB_LOCK		port->ub_lock		/* locks unsolicited */
							/* buffer pool */

/* These SWAPs will swap on any platform */
#define	SWAP32_BUFFER(_b, _c)		emlxs_swap32_buffer(_b, _c)
#define	SWAP32_BCOPY(_s, _d, _c)	emlxs_swap32_bcopy(_s, _d, _c)

#define	SWAP64(_x)	((((uint64_t)(_x) & 0xFF)<<56) | \
			    (((uint64_t)(_x) & 0xFF00)<<40) | \
			    (((uint64_t)(_x) & 0xFF0000)<<24) | \
			    (((uint64_t)(_x) & 0xFF000000)<<8) | \
			    (((uint64_t)(_x) & 0xFF00000000)>>8) | \
			    (((uint64_t)(_x) & 0xFF0000000000)>>24) | \
			    (((uint64_t)(_x) & 0xFF000000000000)>>40) | \
			    (((uint64_t)(_x) & 0xFF00000000000000)>>56))

#define	SWAP32(_x)	((((uint32_t)(_x) & 0xFF)<<24) | \
			    (((uint32_t)(_x) & 0xFF00)<<8) | \
			    (((uint32_t)(_x) & 0xFF0000)>>8) | \
			    (((uint32_t)(_x) & 0xFF000000)>>24))

#define	SWAP16(_x)	((((uint16_t)(_x) & 0xFF)<<8) | \
			    (((uint16_t)(_x) & 0xFF00)>>8))

#define	SWAP24_LO(_x)	((((uint32_t)(_x) & 0xFF)<<16) | \
			    ((uint32_t)(_x) & 0xFF00FF00) | \
			    (((uint32_t)(_x) & 0x00FF0000)>>16))

#define	SWAP24_HI(_x)	(((uint32_t)(_x) & 0x00FF00FF) | \
			    (((uint32_t)(_x) & 0x0000FF00)<<16) | \
			    (((uint32_t)(_x) & 0xFF000000)>>16))

/* These LE_SWAPs will only swap on a LE platform */
#ifdef EMLXS_LITTLE_ENDIAN
#define	LE_SWAP32_BUFFER(_b, _c)	SWAP32_BUFFER(_b, _c)
#define	LE_SWAP32_BCOPY(_s, _d, _c)	SWAP32_BCOPY(_s, _d, _c)
#define	LE_SWAP64(_x)			SWAP64(_x)
#define	LE_SWAP32(_x)			SWAP32(_x)
#define	LE_SWAP16(_x)			SWAP16(_x)
#define	LE_SWAP24_LO(_x)		SWAP24_LO(X)
#define	LE_SWAP24_HI(_x)		SWAP24_HI(X)

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
#undef	LE_SWAP24_LO
#define	LE_SWAP24_LO(_x)		(_x)
#undef	LE_SWAP24_HI
#define	LE_SWAP24_HI(_x)		(_x)
#endif	/* EMLXS_MODREV2X */

#else /* BIG ENDIAN */
#define	LE_SWAP32_BUFFER(_b, _c)
#define	LE_SWAP32_BCOPY(_s, _d, _c)	bcopy(_s, _d, _c)
#define	LE_SWAP64(_x)			(_x)
#define	LE_SWAP32(_x)			(_x)
#define	LE_SWAP16(_x)			(_x)
#define	LE_SWAP24_LO(_x)		(_x)
#define	LE_SWAP24_HI(_x)		(_x)
#endif /* EMLXS_LITTLE_ENDIAN */

/* These BE_SWAPs will only swap on a BE platform */
#ifdef EMLXS_BIG_ENDIAN
#define	BE_SWAP32_BUFFER(_b, _c)	SWAP32_BUFFER(_b, _c)
#define	BE_SWAP32_BCOPY(_s, _d, _c)	SWAP32_BCOPY(_s, _d, _c)
#define	BE_SWAP64(_x)			SWAP64(_x)
#define	BE_SWAP32(_x)			SWAP32(_x)
#define	BE_SWAP16(_x)			SWAP16(_x)
#else /* LITTLE ENDIAN */
#define	BE_SWAP32_BUFFER(_b, _c)
#define	BE_SWAP32_BCOPY(_s, _d, _c)	bcopy(_s, _d, _c)
#define	BE_SWAP64(_x)			(_x)
#define	BE_SWAP32(_x)			(_x)
#define	BE_SWAP16(_x)			(_x)
#endif /* EMLXS_BIG_ENDIAN */

#define	EMLXS_DFC_RESET_ALL			0x10
#define	EMLXS_DFC_RESET_ALL_FORCE_DUMP		0x11

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_FC_H */
