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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#ifndef _EMLXS_FC_H
#define	_EMLXS_FC_H

#ifdef	__cplusplus
extern "C" {
#endif


/* ULP Patches: */
/* #define	ULP_PATCH1 -  Obsolete */

/* This patch enables the driver to auto respond to unsolicited LOGO's */
/* This is needed because ULP is sometimes doesn't reply itself */
#define	ULP_PATCH2

/* This patch enables the driver to auto respond to unsolicited PRLI's */
/* This is needed because ULP is known to panic sometimes */
#define	ULP_PATCH3

/* This patch enables the driver to auto respond to unsolicited PRLO's */
/* This is needed because ULP is known to panic sometimes */
#define	ULP_PATCH4

/* This patch enables the driver to fail pkt abort requests */
#define	ULP_PATCH5

/* This patch enables the driver to generate an RSCN for unsolicited PRLO's */
/* and LOGO's */
#define	ULP_PATCH6

/* Sun Disk Array Patches: */

/* This patch enables the driver to fix a residual underrun issue with */
/* check conditions */
#define	FCP_UNDERRUN_PATCH1

/* This patch enables the driver to fix a residual underrun issue with */
/* SCSI inquiry commands */
#define	FCP_UNDERRUN_PATCH2

/* This patch enables the driver to adjust MAX_RRDY on private loop */
/* #define	MAX_RRDY_PATCH */


typedef struct emlxs_buf {
	fc_packet_t *pkt;		/* scsi_pkt reference */
	struct emlxs_port *port;	/* pointer to port */
	void *bmp;			/* Save the buffer pointer list */
	struct emlxs_buf *fc_fwd;	/* Use it by chip_Q */
	struct emlxs_buf *fc_bkwd;	/* Use it by chip_Q */
	struct emlxs_buf *next;		/* Use it when the iodone */
	void *node;			/* Save node and used by abort */
	void *ring;			/* Save ring and used by abort */
	struct emlxs_buf *fpkt;		/* Flush pkt pointer */
	IOCBQ iocbq;
	kmutex_t mtx;
	uint32_t pkt_flags;
	uint32_t iotag;		/* iotag for this cmd */
	uint32_t ticks;		/* save the timeout ticks for the fc_packet_t */
	uint32_t abort_attempts;
	uint32_t lun;		/* Save LUN id and used by abort */
	uint32_t class;		/* Save class and used by abort */
	uint32_t ucmd;		/* Unsolicted command that this packet is */
				/* responding to, if any */
	int32_t flush_count;	/* Valid only in flush pkts */
	uint32_t did;

#ifdef SFCT_SUPPORT
	fc_packet_t *fct_pkt;
	fct_cmd_t *fct_cmd;

	uint8_t fct_type;

#define	EMLXS_FCT_ELS_CMD		0x01	/* Unsolicted */
#define	EMLXS_FCT_ELS_REQ		0x02	/* Solicited */
#define	EMLXS_FCT_ELS_RSP		0x04

#define	EMLXS_FCT_CT_REQ		0x08	/* Solicited */

#define	EMLXS_FCT_FCP_CMD		0x10	/* Unsolicted */
#define	EMLXS_FCT_FCP_DATA		0x20
#define	EMLXS_FCT_FCP_STATUS		0x40


	uint8_t fct_flags;

#define	EMLXS_FCT_SEND_STATUS		0x01
#define	EMLXS_FCT_ABORT			0x02
#define	EMLXS_FCT_ABORT_COMPLETE	0x04
#define	EMLXS_FCT_REGISTERED		0x10
#define	EMLXS_FCT_FLOGI			0x20

	uint16_t fct_state;
#define	EMLXS_FCT_REQ_CREATED		1
#define	EMLXS_FCT_CMD_RECEIVED		2

#define	EMLXS_FCT_REG_PENDING		3
#define	EMLXS_FCT_REG_COMPLETE		4

#define	EMLXS_FCT_REQ_PENDING		5
#define	EMLXS_FCT_DATA_PENDING		6
#define	EMLXS_FCT_STATUS_PENDING	7
#define	EMLXS_FCT_RSP_PENDING		8

#define	EMLXS_FCT_REQ_COMPLETE		9
#define	EMLXS_FCT_DATA_COMPLETE		10
#define	EMLXS_FCT_STATUS_COMPLETE	11
#define	EMLXS_FCT_RSP_COMPLETE		12

	stmf_data_buf_t *fct_buf;

#endif	/* SFCT_SUPPORT */

} emlxs_buf_t;


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
#define	PACKET_XRI_CLOSED	0x00080000	/* An XRI abort or XRI close */
						/* was issued */

#define	PACKET_CHIP_COMP	0x00100000
#define	PACKET_COMPLETED	0x00200000
#define	PACKET_RETURNED		0x00400000

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

typedef struct emlxs_vpd {

	uint32_t biuRev;
	uint32_t smRev;
	uint32_t smFwRev;
	uint32_t endecRev;
	uint16_t rBit;
	uint8_t fcphHigh;
	uint8_t fcphLow;
	uint8_t feaLevelHigh;
	uint8_t feaLevelLow;

	uint32_t postKernRev;
	char postKernName[32];

	uint32_t opFwRev;
	char opFwName[32];
	char opFwLabel[32];

	uint32_t sli1FwRev;
	char sli1FwName[32];
	char sli1FwLabel[32];

	uint32_t sli2FwRev;
	char sli2FwName[32];
	char sli2FwLabel[32];

	uint32_t sli3FwRev;
	char sli3FwName[32];
	char sli3FwLabel[32];

	uint32_t sli4FwRev;
	char sli4FwName[32];
	char sli4FwLabel[32];

	char fw_version[32];
	char fw_label[32];

	char fcode_version[32];
	char boot_version[32];

	char serial_num[32];
	char part_num[32];
	char port_num[20];
	char eng_change[32];
	char manufacturer[80];
	char model[80];
	char model_desc[256];
	char prog_types[256];
	char id[80];

	uint32_t port_index;
	uint8_t link_speed;

} emlxs_vpd_t;


typedef struct emlxs_queue {
	uint8_t *q_first;	/* queue first element */
	uint8_t *q_last;	/* queue last element */
	uint16_t q_cnt;	/* current length of queue */
	uint16_t q_max;	/* max length queue can get */

} emlxs_queue_t;
typedef emlxs_queue_t Q;



/*
 * This structure is used when allocating a buffer pool.
 * Note: this should be identical to gasket buf_info (fldl.h).
 */
typedef struct emlxs_buf_info {
	int32_t size;		/* Specifies the number of bytes to allocate. */
	int32_t align;		/* The desired address boundary. */

	int32_t flags;

#define	FC_MBUF_DMA		0x01	/* blocks are for DMA */
#define	FC_MBUF_PHYSONLY	0x02	/* For malloc - map a given virtual */
					/* address to physical (skip malloc) */
					/*  For free - just unmap the given  */
					/* physical address (skip the free). */
#define	FC_MBUF_IOCTL		0x04	/* called from dfc_ioctl */
#define	FC_MBUF_UNLOCK		0x08	/* called with driver unlocked */
#define	FC_MBUF_SNGLSG		0x10	/* alloc single contiguous physical */
					/* memory */
#define	FC_MBUF_DMA32		0x20

	uint64_t phys;	/* specifies the physical buffer pointer */
	void *virt;	/* specifies the virtual buffer pointer */
	void *data_handle;
	void *dma_handle;

} emlxs_buf_info_t;
typedef emlxs_buf_info_t MBUF_INFO;



#ifdef SLI3_SUPPORT

#define	EMLXS_MAX_HBQ   	16	/* Max HBQs handled by firmware */
#define	EMLXS_ELS_HBQ_ID	0
#define	EMLXS_IP_HBQ_ID		1
#define	EMLXS_CT_HBQ_ID		2
#define	EMLXS_FCT_HBQ_ID	3

#ifdef SFCT_SUPPORT
#define	EMLXS_NUM_HBQ		4	/* Number of HBQs supported by driver */
#else
#define	EMLXS_NUM_HBQ		3	/* Number of HBQs supported by driver */
#endif	/* SFCT_SUPPORT */

#endif	/* SLI3_SUPPORT */



/* Structure used to access adapter rings */
typedef struct emlxs_ring {
	IOCBQ *fc_iocbhd;	/* ptr to head iocb rsp list for ring */
	IOCBQ *fc_iocbtl;	/* ptr to tail iocb rsp list for ring */
	void *fc_cmdringaddr;	/* virtual offset for cmd rings */
	void *fc_rspringaddr;	/* virtual offset for rsp rings */

	emlxs_buf_t **fc_table;	/* sc_buf pointers indexed by iotag */
	uint8_t *fc_mpon;	/* index ptr for match structure */
	uint8_t *fc_mpoff;	/* index ptr for match structure */
	struct emlxs_hba *hba;	/* ptr to hba for ring */

	kmutex_t rsp_lock;
	IOCBQ *rsp_head;	/* deferred completion head */
	IOCBQ *rsp_tail;	/* deferred completion tail */
	emlxs_thread_t intr_thread;

	uint8_t fc_numCiocb;	/* number of command iocb's per ring */
	uint8_t fc_numRiocb;	/* number of rsp iocb's per ring */
	uint8_t fc_rspidx;	/* current index in response ring */
	uint8_t fc_cmdidx;	/* current index in command ring */
	uint8_t fc_port_rspidx;
	uint8_t fc_port_cmdidx;
	uint8_t ringno;

	uint16_t fc_missbufcnt;	/* buf cnt we need to repost */
	uint16_t fc_iotag;	/* used to identify I/Os */
	uint16_t fc_abort_iotag;	/* used to identify Abort or close */
					/* requests */
	uint16_t max_iotag;

	uint32_t timeout;

	/* Protected by EMLXS_RINGTX_LOCK */
	emlxs_queue_t nodeq;	/* Node service queue */

} emlxs_ring_t;
typedef emlxs_ring_t RING;


typedef struct emlxs_node {
	struct emlxs_node *nlp_list_next;
	struct emlxs_node *nlp_list_prev;

	NAME_TYPE nlp_portname;	/* port name */
	NAME_TYPE nlp_nodename;	/* node name */

	uint32_t nlp_DID;	/* fibre channel D_ID of entry */
	uint32_t nlp_oldDID;

	uint16_t nlp_Rpi;	/* login id returned by REG_LOGIN */
	uint16_t nlp_Xri;	/* login id returned by REG_LOGIN */

	uint8_t nlp_fcp_info;	/* Remote class info */

	/* nlp_fcp_info */
#define	NLP_FCP_TGT_DEVICE	0x10	/* FCP TGT device */
#define	NLP_FCP_INI_DEVICE	0x20	/* FCP Initiator device */
#define	NLP_FCP_2_DEVICE	0x40	/* FCP-2 TGT device */

	uint32_t nlp_tag;	/* Tag used by port_offline */
	uint32_t flag;

#define	NODE_POOL_ALLOCATED	0x00000001

	SERV_PARM sparm;

	/* Protected by EMLXS_RINGTX_LOCK */
	uint32_t nlp_active;	/* Node active flag */
	uint32_t nlp_base;
	uint32_t nlp_flag[MAX_RINGS];	/* Node level ring flags */

	/* nlp_flag */
#define	NLP_CLOSED		0x1	/* Node closed */
#define	NLP_TIMER		0x2	/* Node timer is active */
#define	NLP_RPI_XRI		0x4	/* Create xri for entry */

	uint32_t nlp_tics[MAX_RINGS];	/* gate timeout */
	emlxs_queue_t nlp_tx[MAX_RINGS];	/* Transmit Q head */
	emlxs_queue_t nlp_ptx[MAX_RINGS];	/* Priority transmit Q head */
	void *nlp_next[MAX_RINGS];	/* Service Request Q pointer - used */
					/* when node needs servicing */
#ifdef DHCHAP_SUPPORT
	emlxs_node_dhc_t node_dhc;
#endif	/* DHCHAP_SUPPORT */

} emlxs_node_t;
typedef emlxs_node_t NODELIST;



#define	NADDR_LEN	6	/* MAC network address length */
typedef struct emlxs_fcip_nethdr {
	NAME_TYPE fc_destname;	/* destination port name */
	NAME_TYPE fc_srcname;	/* source port name */

} emlxs_fcip_nethdr_t;
typedef emlxs_fcip_nethdr_t NETHDR;


#define	MEM_NLP		0	/* memory segment to hold node list entries */
#define	MEM_IOCB	1	/* memory segment to hold iocb commands */
#define	MEM_MBOX	2	/* memory segment to hold mailbox cmds */
#define	MEM_BPL		3	/* and to hold buffer ptr lists - SLI2 */
#define	MEM_BUF		4	/* memory segment to hold buffer data */
#define	MEM_ELSBUF	4	/* memory segment to hold buffer data */
#define	MEM_IPBUF	5	/* memory segment to hold IP buffer data */
#define	MEM_CTBUF	6	/* memory segment to hold CT buffer data */
#define	MEM_FCTBUF	7	/* memory segment to hold FCT buffer data */

#ifdef SFCT_SUPPORT
#define	FC_MAX_SEG	8
#else
#define	FC_MAX_SEG	7
#endif	/* SFCT_SUPPORT */


/* A BPL entry is 12 bytes. Subtract 2 for command and response buffers */
#define	BPL_TO_SGLLEN(_bpl) ((_bpl/12)-2)

#define	MEM_BPL_SIZE		1024	/* Default size */

#ifdef EMLXS_I386
#define	EMLXS_SGLLEN		BPL_TO_SGLLEN(MEM_BPL_SIZE)
#else	/* EMLXS_SPARC */
#define	EMLXS_SGLLEN		1
#endif	/* EMLXS_I386 */

#define	MEM_BUF_SIZE		1024
#define	MEM_BUF_COUNT		64

#define	MEM_ELSBUF_SIZE		MEM_BUF_SIZE
#define	MEM_ELSBUF_COUNT	hba->max_nodes
#define	MEM_IPBUF_SIZE		65535
#define	MEM_IPBUF_COUNT		60
#define	MEM_CTBUF_SIZE		MAX_CT_PAYLOAD	/* (1024*320) */
#define	MEM_CTBUF_COUNT		8
#define	MEM_FCTBUF_SIZE		65535
#define	MEM_FCTBUF_COUNT	128

#define	MEM_SEG_MASK		0xff	/* mask off the priority bit */
#define	MEM_PRI 		0x100	/* Priority bit: exceed low water */



typedef struct emlxs_memseg {
	uint8_t *fc_memget_ptr;
	uint8_t *fc_memget_end;
	uint8_t *fc_memput_ptr;
	uint8_t *fc_memput_end;

	uint8_t *fc_memstart_virt;	/* beginning address of the memory */
					/* block */
	uint64_t fc_memstart_phys;	/* beginning address of the memory */
					/* block */
	ddi_dma_handle_t fc_mem_dma_handle;
	ddi_acc_handle_t fc_mem_dat_handle;
	uint32_t fc_total_memsize;
	uint32_t fc_memsize;	/* size of memory blocks */
	uint32_t fc_numblks;	/* number of memory blocks */
	uint32_t fc_memget_cnt;	/* number of memory get blocks */
	uint32_t fc_memput_cnt;	/* number of memory put blocks */
	uint32_t fc_memflag;	/* what to do when list is exhausted */
	uint32_t fc_lowmem;	/* low water mark, used w/MEM_PRI flag */

} emlxs_memseg_t;
typedef emlxs_memseg_t MEMSEG;


#define	FC_MEM_ERR	1	/* return error memflag */
#define	FC_MEM_GETMORE	2	/* get more memory memflag */
#define	FC_MEM_DMA	4	/* blocks are for DMA */
#define	FC_MEM_LOWHIT	8	/* low water mark was hit */
#define	FC_MEMPAD	16	/* offset used for a FC_MEM_DMA buffer */

/* Board stat counters */
typedef struct emlxs_stats {
	uint32_t LinkUp;
	uint32_t LinkDown;
	uint32_t LinkEvent;
	uint32_t LinkMultiEvent;

	uint32_t MboxIssued;
	uint32_t MboxCompleted;	/* MboxCompleted = MboxError + MbxGood */
	uint32_t MboxGood;
	uint32_t MboxError;
	uint32_t MboxBusy;
	uint32_t MboxInvalid;

	uint32_t IocbIssued[MAX_RINGS];
	uint32_t IocbReceived[MAX_RINGS];
	uint32_t IocbTxPut[MAX_RINGS];
	uint32_t IocbTxGet[MAX_RINGS];
	uint32_t IocbRingFull[MAX_RINGS];
	uint32_t IocbThrottled;

	uint32_t IntrEvent[8];

	uint32_t FcpIssued;
	uint32_t FcpCompleted;	/* = FcpGood + FcpError */
	uint32_t FcpGood;
	uint32_t FcpError;

	uint32_t FcpEvent;	/* = FcpStray + FcpCompleted */
	uint32_t FcpStray;
#ifdef SFCT_SUPPORT
	uint32_t FctRingEvent;
	uint32_t FctRingError;
	uint32_t FctRingDropped;
#endif	/* SFCT_SUPPORT */

	uint32_t ElsEvent;	/* = ElsStray + ElsCmdCompleted + */
				/* ElsRspCompleted */
	uint32_t ElsStray;

	uint32_t ElsCmdIssued;
	uint32_t ElsCmdCompleted;	/* = ElsCmdGood + ElsCmdError */
	uint32_t ElsCmdGood;
	uint32_t ElsCmdError;

	uint32_t ElsRspIssued;
	uint32_t ElsRspCompleted;

	uint32_t ElsRcvEvent;	/* = ElsRcvError + ElsRcvDropped + */
				/* ElsCmdReceived */
	uint32_t ElsRcvError;
	uint32_t ElsRcvDropped;
	uint32_t ElsCmdReceived;	/* = ElsRscnReceived + */
					/* ElsPlogiReceived + ... */
	uint32_t ElsRscnReceived;
	uint32_t ElsFlogiReceived;
	uint32_t ElsPlogiReceived;
	uint32_t ElsPrliReceived;
	uint32_t ElsPrloReceived;
	uint32_t ElsLogoReceived;
	uint32_t ElsAdiscReceived;
	uint32_t ElsAuthReceived;
	uint32_t ElsGenReceived;

	uint32_t CtEvent;	/* = CtStray + CtCmdCompleted + */
				/* CtRspCompleted */
	uint32_t CtStray;

	uint32_t CtCmdIssued;
	uint32_t CtCmdCompleted;	/* = CtCmdGood + CtCmdError */
	uint32_t CtCmdGood;
	uint32_t CtCmdError;

	uint32_t CtRspIssued;
	uint32_t CtRspCompleted;

	uint32_t CtRcvEvent;	/* = CtRcvError + CtRcvDropped + */
				/* CtCmdReceived */
	uint32_t CtRcvError;
	uint32_t CtRcvDropped;
	uint32_t CtCmdReceived;

	uint32_t IpEvent;	/* = IpStray + IpSeqCompleted + */
				/* IpBcastCompleted */
	uint32_t IpStray;

	uint32_t IpSeqIssued;
	uint32_t IpSeqCompleted;	/* = IpSeqGood + IpSeqError */
	uint32_t IpSeqGood;
	uint32_t IpSeqError;

	uint32_t IpBcastIssued;
	uint32_t IpBcastCompleted;	/* = IpBcastGood + IpBcastError */
	uint32_t IpBcastGood;
	uint32_t IpBcastError;

	uint32_t IpRcvEvent;	/* = IpDropped + IpSeqReceived + */
				/* IpBcastReceived */
	uint32_t IpDropped;
	uint32_t IpSeqReceived;
	uint32_t IpBcastReceived;

	uint32_t IpUbPosted;
	uint32_t ElsUbPosted;
	uint32_t CtUbPosted;
#ifdef SFCT_SUPPORT
	uint32_t FctUbPosted;
#endif	/* SFCT_SUPPORT */

	uint32_t ResetTime;	/* Time of last reset */

} emlxs_stats_t;


#define	FC_MAX_ADPTMSG		(8*28)	/* max size of a msg from adapter */

#define	EMLXS_NUM_THREADS	8
#define	EMLXS_MIN_TASKS		8
#define	EMLXS_MAX_TASKS		8

#define	EMLXS_NUM_HASH_QUES	32
#define	EMLXS_DID_HASH(x)	((x) & (EMLXS_NUM_HASH_QUES - 1))


/* pkt_tran_flag */
#define	FC_TRAN_COMPLETED	0x8000


typedef struct emlxs_dfc_event {
	uint32_t pid;
	uint32_t event;
	uint32_t last_id;

	void *dataout;
	uint32_t size;
	uint32_t mode;

} emlxs_dfc_event_t;


typedef struct emlxs_hba_event {
	uint32_t last_id;
	uint32_t new;
	uint32_t missed;

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
#define	MAX_TGTPORT_IOCNT	16


/*
 * These routines will bump the right counter, based on
 * the size of the IO inputed, with the least number of
 * comparisions.  A max of 5 comparisions is only needed
 * to classify the IO in one of 16 ranges. A binary search
 * to locate the high bit in the size is used.
 */
#define	emlxs_bump_rdioctr(port, cnt)					\
{									\
	/* Use binary search to find the first high bit */		\
	if (cnt & 0xffff0000) {						\
		if (cnt & 0xff800000) {					\
			TGTPORTSTAT.FctP2IORcnt[15]++;			\
		}							\
		else {							\
			/* It must be 0x007f0000 */			\
			if (cnt & 0x00700000) {				\
				if (cnt & 0x00400000) {			\
					TGTPORTSTAT.FctP2IORcnt[14]++;	\
				}					\
				else {					\
					/* It must be 0x00300000 */	\
					if (cnt & 0x00200000) {		\
						TGTPORTSTAT.FctP2IORcnt[13]++;\
					}				\
					else {				\
						/* It must be 0x00100000 */   \
						TGTPORTSTAT.FctP2IORcnt[12]++;\
					}				\
				}					\
			}						\
			else {						\
				/* It must be 0x000f0000 */		\
				if (cnt & 0x000c0000) {			\
					if (cnt & 0x00080000) {		\
						TGTPORTSTAT.FctP2IORcnt[11]++; \
					}				\
					else {				\
						/* It must be 0x00040000  */   \
						TGTPORTSTAT.FctP2IORcnt[10]++; \
					}				\
				}					\
				else {					\
					/* It must be 0x00030000 */	\
					if (cnt & 0x00020000) {		\
						TGTPORTSTAT.FctP2IORcnt[9]++;  \
					}				\
					else {				\
						/* It must be 0x00010000   */  \
						TGTPORTSTAT.FctP2IORcnt[8]++;  \
					}				\
				}					\
			}						\
		}							\
	}								\
	else {								\
		if (cnt & 0x0000fe00) {					\
			if (cnt & 0x0000f000) {				\
				if (cnt & 0x0000c000) {			\
					if (cnt & 0x00008000) {		\
						TGTPORTSTAT.FctP2IORcnt[7]++;  \
					}				\
					else {				\
						/* It must be 0x00004000   */  \
						TGTPORTSTAT.FctP2IORcnt[6]++;  \
					}				\
				}					\
				else {					\
					/* It must be 0x00000300 */	\
					if (cnt & 0x00000200) {		\
						TGTPORTSTAT.FctP2IORcnt[5]++;  \
					}				\
					else {				\
						/* It must be 0x00000100   */  \
						TGTPORTSTAT.FctP2IORcnt[4]++;  \
					}				\
				}					\
			}						\
			else {						\
				/* It must be 0x00000e00 */		\
				if (cnt & 0x00000800) {			\
					TGTPORTSTAT.FctP2IORcnt[3]++;	\
				}					\
				else {					\
					/* It must be 0x00000600 */	\
					if (cnt & 0x00000400) {		\
						TGTPORTSTAT.FctP2IORcnt[2]++;  \
					}				\
					else {				\
						/* It must be 0x00000200   */  \
						TGTPORTSTAT.FctP2IORcnt[1]++;  \
					}				\
				}					\
			}						\
		}							\
		else {							\
			/* It must be 0x000001ff */			\
			TGTPORTSTAT.FctP2IORcnt[0]++;			\
		}							\
	}								\
}

#define	emlxs_bump_wrioctr(port, cnt)					\
{									\
	/* Use binary search to find the first high bit */		\
	if (cnt & 0xffff0000) {						\
		if (cnt & 0xff800000) {					\
			TGTPORTSTAT.FctP2IOWcnt[15]++;			\
		}							\
		else {							\
			/* It must be 0x007f0000 */			\
			if (cnt & 0x00700000) {				\
				if (cnt & 0x00400000) {			\
					TGTPORTSTAT.FctP2IOWcnt[14]++;	\
				}					\
				else {					\
					/* It must be 0x00300000 */	\
					if (cnt & 0x00200000) {		\
						TGTPORTSTAT.FctP2IOWcnt[13]++; \
					}				\
					else {				\
						/* It must be 0x00100000   */  \
						TGTPORTSTAT.FctP2IOWcnt[12]++; \
					}				\
				}					\
			}						\
			else {						\
				/* It must be 0x000f0000 */		\
				if (cnt & 0x000c0000) {			\
					if (cnt & 0x00080000) {		\
						TGTPORTSTAT.FctP2IOWcnt[11]++; \
					}				\
					else {				\
						/* It must be 0x00040000   */  \
						TGTPORTSTAT.FctP2IOWcnt[10]++; \
					}				\
				}					\
				else {					\
					/* It must be 0x00030000 */	\
					if (cnt & 0x00020000) {		\
						TGTPORTSTAT.FctP2IOWcnt[9]++; \
					}				\
					else {				\
						/* It must be 0x00010000  */  \
						TGTPORTSTAT.FctP2IOWcnt[8]++; \
					}				\
				}					\
			}						\
		}							\
	}								\
	else {								\
		if (cnt & 0x0000fe00) {					\
			if (cnt & 0x0000f000) {				\
				if (cnt & 0x0000c000) {			\
					if (cnt & 0x00008000) {		\
						TGTPORTSTAT.FctP2IOWcnt[7]++; \
					}				\
					else {				\
						/* It must be 0x00004000  */  \
						TGTPORTSTAT.FctP2IOWcnt[6]++; \
					}				\
				}					\
				else {					\
					/* It must be 0x00000300 */	\
					if (cnt & 0x00000200) {		\
						TGTPORTSTAT.FctP2IOWcnt[5]++; \
					}				\
					else {				\
						/* It must be 0x00000100  */  \
						TGTPORTSTAT.FctP2IOWcnt[4]++; \
					}				\
				}					\
			}						\
			else {						\
				/* It must be 0x00000e00 */		\
				if (cnt & 0x00000800) {			\
					TGTPORTSTAT.FctP2IOWcnt[3]++;	\
				}					\
				else {					\
					/* It must be 0x00000600 */	\
					if (cnt & 0x00000400) {		\
						TGTPORTSTAT.FctP2IOWcnt[2]++; \
					}				\
					else {				\
						/* It must be 0x00000200  */  \
						TGTPORTSTAT.FctP2IOWcnt[1]++; \
					}				\
				}					\
			}						\
		}							\
		else {							\
			/* It must be 0x000001ff */			\
			TGTPORTSTAT.FctP2IOWcnt[0]++;			\
		}							\
	}								\
}

typedef struct emlxs_tgtport_stat {
	/* IO counters */
	uint64_t FctP2IOWcnt[MAX_TGTPORT_IOCNT];	/* Writes */
	uint64_t FctP2IORcnt[MAX_TGTPORT_IOCNT];	/* Reads  */
	uint64_t FctIOCmdCnt;	/* Other, ie TUR */
	uint64_t FctCmdReceived;	/* total IOs */
	uint64_t FctReadBytes;	/* total bytes Read */
	uint64_t FctWriteBytes;	/* total bytes Written */

	/* IOCB handling counters */
	uint64_t FctEvent;	/* = FctStray + FctCompleted */
	uint64_t FctCompleted;	/* = FctCmplGood + FctCmplError */
	uint64_t FctCmplGood;

	uint32_t FctCmplError;
	uint32_t FctStray;

	/* Fct event counters */
	uint32_t FctRcvDropped;
	uint32_t FctOverQDepth;
	uint32_t FctOutstandingIO;
	uint32_t FctFailedPortRegister;
	uint32_t FctPortRegister;
	uint32_t FctPortDeregister;

	uint32_t FctAbortSent;
	uint32_t FctNoBuffer;
	uint32_t FctScsiStatusErr;
	uint32_t FctScsiQfullErr;
	uint32_t FctScsiResidOver;
	uint32_t FctScsiResidUnder;
	uint32_t FctScsiSenseErr;

	uint32_t FctFiller1;
} emlxs_tgtport_stat_t;
#endif	/* SFCT_SUPPORT */


/*
 * Port Information Data Structure
 */

typedef struct emlxs_port {
	struct emlxs_hba *hba;

	/* Virtual port management */
	uint32_t vpi;
	uint32_t flag;
#define	EMLXS_PORT_ENABLE		0x00000001
#define	EMLXS_PORT_BOUND		0x00000002

#define	EMLXS_PORT_REGISTERED		0x00010000	/* VPI registered */
#define	EMLXS_PORT_IP_UP		0x00000010
#define	EMLXS_PORT_CONFIG		0x00000020
#define	EMLXS_PORT_RESTRICTED		0x00000040	/* Restrict login flg */
#define	EMLXS_PORT_FLOGI_CMPL		0x00000080	/* Fabric login cmpl */

#define	EMLXS_PORT_RESET_MASK		0x0000FFFF	/* Flags kept across */
							/* a hard reset */
#define	EMLXS_PORT_LINKDOWN_MASK	0xFFFFFFFF	/* Flags kept across */
							/* a link reset */

	uint32_t options;
#define	EMLXS_OPT_RESTRICT		0x00000001	/* Force restricted */
							/* logins   */
#define	EMLXS_OPT_UNRESTRICT		0x00000002	/* Force Unrestricted */
							/* logins */
#define	EMLXS_OPT_RESTRICT_MASK		0x00000003


	/* FC world wide names */
	NAME_TYPE wwnn;
	NAME_TYPE wwpn;
	char snn[256];
	char spn[256];

	/* Common service paramters */
	SERV_PARM sparam;
	SERV_PARM fabric_sparam;

	/* fc_id management */
	uint32_t did;
	uint32_t prev_did;

	/* FC_AL management */
	uint8_t lip_type;
	uint8_t alpa_map[128];

	/* Node management */
	emlxs_node_t node_base;
	uint32_t node_count;
	krwlock_t node_rwlock;
	emlxs_node_t *node_table[EMLXS_NUM_HASH_QUES];

	/* Polled packet management */
	kcondvar_t pkt_lock_cv;	/* pkt polling */
	kmutex_t pkt_lock;	/* pkt polling */

	/* ULP */
	uint32_t ulp_statec;
	void (*ulp_statec_cb) ();	/* Port state change callback routine */
	void (*ulp_unsol_cb) ();	/* unsolicited event callback routine */
	opaque_t ulp_handle;

	/* ULP unsolicited buffers */
	kmutex_t ub_lock;
	uint32_t ub_count;
	emlxs_unsol_buf_t *ub_pool;
	uint32_t ub_post[MAX_RINGS];
	uint32_t ub_timer;

	emlxs_ub_priv_t *ub_wait_head;	/* Unsolicited IO received before */
					/* link up */
	emlxs_ub_priv_t *ub_wait_tail;	/* Unsolicited IO received before */
					/* link up */


#ifdef DHCHAP_SUPPORT
	emlxs_port_dhc_t port_dhc;
#endif	/* DHCHAP_SUPPORT */

	uint16_t ini_mode;
	uint16_t tgt_mode;

#ifdef SFCT_SUPPORT

#define	FCT_BUF_COUNT_512		256
#define	FCT_BUF_COUNT_8K		128
#define	FCT_BUF_COUNT_64K		64
#define	FCT_BUF_COUNT_128K		64
#define	FCT_MAX_BUCKETS			16
#define	FCT_DMEM_MAX_BUF_SIZE		(2 * 65536)

	struct emlxs_fct_dmem_bucket dmem_bucket[FCT_MAX_BUCKETS];
	int fct_queue_depth;

	char cfd_name[24];
	stmf_port_provider_t *port_provider;
	fct_local_port_t *fct_port;
	uint32_t fct_flags;

#define	FCT_STATE_PORT_ONLINE	0x00000001
#define	FCT_STATE_NOT_ACKED	0x00000002
#define	FCT_STATE_LINK_UP	0x00000010

	emlxs_buf_t *fct_wait_head;
	emlxs_buf_t *fct_wait_tail;
	emlxs_tgtport_stat_t fct_stat;

#endif	/* SFCT_SUPPORT */

} emlxs_port_t;



/* Host Attn reg */
#define	FC_HA_REG(_hba, _sa)	((volatile uint32_t *) \
				((volatile char *)_sa + ((_hba)->ha_reg_addr)))

/* Chip Attn reg */
#define	FC_CA_REG(_hba, _sa)	((volatile uint32_t *) \
				((volatile char *)_sa + ((_hba)->ca_reg_addr)))

/* Host Status reg */
#define	FC_HS_REG(_hba, _sa)	((volatile uint32_t *) \
				((volatile char *)_sa + ((_hba)->hs_reg_addr)))

/* Host Cntl reg */
#define	FC_HC_REG(_hba, _sa)	((volatile uint32_t *) \
				((volatile char *)_sa + ((_hba)->hc_reg_addr)))

/* BIU Configuration reg */
#define	FC_BC_REG(_hba, _sa)	((volatile uint32_t *) \
				((volatile char *)_sa + ((_hba)->bc_reg_addr)))

/* Used by SBUS adapter */
/* TITAN Cntl reg */
#define	FC_SHC_REG(_hba, _sa)	((volatile uint32_t *) \
				((volatile char *)_sa + ((_hba)->shc_reg_addr)))

/* TITAN Status reg */
#define	FC_SHS_REG(_hba, _sa)	((volatile uint32_t *) \
				((volatile char *)_sa + ((_hba)->shs_reg_addr)))

/* TITAN Update reg */
#define	FC_SHU_REG(_hba, _sa)	((volatile uint32_t *) \
				((volatile char *)_sa + ((_hba)->shu_reg_addr)))


#define	FC_SLIM2_MAILBOX(_hba)	((MAILBOX *)(_hba)->slim2.virt)

#define	FC_SLIM1_MAILBOX(_hba)	((MAILBOX *)(_hba)->slim_addr)

#define	FC_MAILBOX(_hba)	(((_hba)->flag & FC_SLIM2_MODE) ? \
				FC_SLIM2_MAILBOX(_hba):FC_SLIM1_MAILBOX(_hba))

#define	WRITE_CSR_REG(_hba, _regp, _value)	\
	(void) ddi_put32((_hba)->csr_acc_handle,\
	(uint32_t *)(_regp),\
	(uint32_t)(_value))

#define	READ_CSR_REG(_hba, _regp)	\
	ddi_get32((_hba)->csr_acc_handle,\
	(uint32_t *)(_regp))

#define	WRITE_SLIM_ADDR(_hba, _regp, _value)	\
	(void) ddi_put32((_hba)->slim_acc_handle,\
	(uint32_t *)(_regp),\
	(uint32_t)(_value))

#define	READ_SLIM_ADDR(_hba, _regp)	\
	ddi_get32((_hba)->slim_acc_handle,\
	(uint32_t *)(_regp))

#define	WRITE_SLIM_COPY(_hba, _bufp, _slimp, _wcnt)	\
	(void) ddi_rep_put32((_hba)->slim_acc_handle,\
	(uint32_t *)(_bufp),\
	(uint32_t *)(_slimp),\
	(_wcnt),\
	DDI_DEV_AUTOINCR)

#define	READ_SLIM_COPY(_hba, _bufp, _slimp, _wcnt)	\
	(void) ddi_rep_get32((_hba)->slim_acc_handle,\
	(uint32_t *)(_bufp),\
	(uint32_t *)(_slimp),\
	(_wcnt),\
	DDI_DEV_AUTOINCR)

#define	WRITE_FLASH_COPY(_hba, _bufp, _flashp, _wcnt)	\
	(void) ddi_rep_put32((_hba)->fc_flash_handle,\
	(uint32_t *)(_bufp),\
	(uint32_t *)(_flashp),\
	(_wcnt),\
	DDI_DEV_AUTOINCR)

#define	READ_FLASH_COPY(_hba, _bufp, _flashp, _wcnt)	\
	(void) ddi_rep_get32((_hba)->fc_flash_handle, (uint32_t *)(_bufp),\
	(uint32_t *)(_flashp),\
	(_wcnt),\
	DDI_DEV_AUTOINCR)

/* Used by SBUS adapter */
#define	WRITE_SBUS_CSR_REG(_hba, _regp, _value)		\
	(void) ddi_put32((_hba)->sbus_csr_handle,\
	(uint32_t *)(_regp),\
	(uint32_t)(_value))

#define	READ_SBUS_CSR_REG(_hba, _regp)		\
	ddi_get32((_hba)->sbus_csr_handle,\
	(uint32_t *)(_regp))

#define	SBUS_WRITE_FLASH_COPY(_hba, _offset, _value)	\
	(void) ddi_put8((_hba)->sbus_flash_acc_handle,\
	(uint8_t *)((volatile uint8_t *)(_hba)->sbus_flash_addr + (_offset)),\
	(uint8_t)(_value))

#define	SBUS_READ_FLASH_COPY(_hba, _offset)	\
	ddi_get8((_hba)->sbus_flash_acc_handle,\
	(uint8_t *)((volatile uint8_t *)(_hba)->sbus_flash_addr + (_offset)))

#define	emlxs_ffstate_change(_hba, _state)				\
{									\
	mutex_enter(&EMLXS_PORT_LOCK);					\
	emlxs_ffstate_change_locked((_hba), (_state));			\
	mutex_exit(&EMLXS_PORT_LOCK);					\
}

/* Used when EMLXS_PORT_LOCK is already held */
#define	emlxs_ffstate_change_locked(_hba, _state)			\
{									\
	if ((_hba)->state != (_state))					\
	{								\
		uint32_t _st = _state;					\
		EMLXS_MSGF(EMLXS_CONTEXT,				\
			&emlxs_state_msg, "%s --> %s",			\
			emlxs_ffstate_xlate((_hba)->state),		\
			emlxs_ffstate_xlate(_state));			\
		(_hba)->state = (_state);				\
		if ((_st) == FC_ERROR)				\
		{							\
			(_hba)->flag |= FC_HARDWARE_ERROR;		\
		}							\
	}								\
}

/*
 * This is the HBA control area for the adapter
 */

#ifdef MODSYM_SUPPORT

typedef struct emlxs_modsym {
	ddi_modhandle_t mod_fctl;	/* For Leadville */

	/* Leadville (fctl) */
	int (*fc_fca_attach) (dev_info_t *, fc_fca_tran_t *);
	int (*fc_fca_detach) (dev_info_t *);
	int (*fc_fca_init) (struct dev_ops *);

#ifdef SFCT_SUPPORT
	ddi_modhandle_t mod_fct;	/* For Comstar */
	ddi_modhandle_t mod_stmf;	/* For Comstar */

	/* Comstar (fct) */
	void *(*fct_alloc) (int, int, int);
	void (*fct_free) (void *);
	void *(*fct_scsi_task_alloc) (void *, int, int, uint8_t *, int, int);
	int (*fct_register_local_port) (fct_local_port_t *);
	void (*fct_deregister_local_port) (fct_local_port_t *);
	void (*fct_handle_event) (fct_local_port_t *, int, int, int);
	void (*fct_post_rcvd_cmd) (fct_cmd_t *, int);
	void (*fct_ctl) (void *, int, stmf_change_status_t *);
	void (*fct_send_response_done) (fct_cmd_t *, int, int);
	void (*fct_send_cmd_done) (fct_cmd_t *, int, int);
	void (*fct_scsi_data_xfer_done) (fct_cmd_t *, stmf_data_buf_t *, int);
	fct_status_t(*fct_port_shutdown) (fct_local_port_t *, uint32_t, char *);
	fct_status_t(*fct_port_initialize)
		(fct_local_port_t *, uint32_t, char *);
	fct_status_t(*fct_handle_rcvd_flogi)
		(fct_local_port_t *, fct_flogi_xchg_t *);

	/* Comstar (stmf) */
	void *(*stmf_alloc) (int, int, int);
	void (*stmf_free) (void *);
	void (*stmf_deregister_port_provider) (stmf_port_provider_t *);
	int (*stmf_register_port_provider) (stmf_port_provider_t *);

#endif	/* SFCT_SUPPORT */

} emlxs_modsym_t;
extern emlxs_modsym_t emlxs_modsym;

#define	MODSYM(_f)		emlxs_modsym._f

#else

#define	MODSYM(_f)		_f

#endif	/* MODSYM_SUPPORT */



#define	PCI_CONFIG_SIZE		0x80

typedef struct emlxs_hba {
	dev_info_t *dip;
	int32_t emlxinst;
	int32_t ddiinst;
	fc_fca_tran_t *fca_tran;

	/* HBA Info */
	emlxs_model_t model_info;
	emlxs_vpd_t vpd;	/* vital product data */
	NAME_TYPE wwnn;
	NAME_TYPE wwpn;
	char snn[256];
	char spn[256];
	PROG_ID load_list[MAX_LOAD_ENTRY];
	WAKE_UP_PARMS wakeup_parms;
	uint32_t max_nodes;
	uint32_t io_throttle;
	uint32_t io_active;
	uint32_t bus_type;
#define	PCI_FC		0
#define	SBUS_FC		1

	/* Link management */
	uint32_t link_event_tag;
	uint8_t topology;
	uint8_t linkspeed;
	uint32_t linkup_wait_flag;
	kcondvar_t linkup_lock_cv;
	kmutex_t linkup_lock;

	/* Memory Pool management */
	uint32_t mem_bpl_size;
	emlxs_memseg_t memseg[FC_MAX_SEG];	/* memory for buffers */
						/* structures */
	kmutex_t memget_lock;	/* locks all memory pools get */
	kmutex_t memput_lock;	/* locks all memory pools put */

	/* Fibre Channel Service Parameters */
	SERV_PARM sparam;
	uint32_t fc_edtov;	/* E_D_TOV timer value */
	uint32_t fc_arbtov;	/* ARB_TOV timer value */
	uint32_t fc_ratov;	/* R_A_TOV timer value */
	uint32_t fc_rttov;	/* R_T_TOV timer value */
	uint32_t fc_altov;	/* AL_TOV timer value */
	uint32_t fc_crtov;	/* C_R_TOV timer value */
	uint32_t fc_citov;	/* C_I_TOV timer value */

	/* SLIM management */
	uint32_t sli_mode;
	MATCHMAP slim2;
#ifdef SLI3_SUPPORT
	/* HBQ management */
	uint32_t hbq_count;	/* Total number of HBQs configured */
	HBQ_INIT_t hbq_table[EMLXS_NUM_HBQ];
#endif	/* SLI3_SUPPORT	 */


	/* Adapter State management */
	int32_t state;
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
#define	FC_LINK_UP		0x30
#define	FC_CLEAR_LA		0x31
#define	FC_READY		0x40

	uint32_t flag;
#define	FC_ONLINING_MODE	0x00000001
#define	FC_ONLINE_MODE		0x00000002
#define	FC_OFFLINING_MODE	0x00000004
#define	FC_OFFLINE_MODE		0x00000008

#define	FC_NPIV_ENABLED		0x00000010	/* NPIV enabled on adapter */
#define	FC_NPIV_SUPPORTED	0x00000020	/* NPIV supported on fabric */
#define	FC_NPIV_UNSUPPORTED	0x00000040	/* NPIV unsupported on fabric */
#define	FC_NPIV_LINKUP		0x00000100	/* NPIV enabled, supported, */
						/* and link is ready */
#define	FC_NPIV_DELAY_REQUIRED	0x00000200	/* Delay issuing FLOGI/FDISC */
						/* and NameServer cmds */

#define	FC_FABRIC_ATTACHED	0x00001000
#define	FC_PT_TO_PT		0x00002000
#define	FC_BYPASSED_MODE	0x00004000
#define	FC_MENLO_MODE		0x00008000	/* Indicates Menlo */
						/* maintenance mode */

#define	FC_SLIM2_MODE		0x00100000	/* SLIM in host memory */
#define	FC_INTERLOCKED		0x00200000
#define	FC_HBQ_ENABLED		0x00400000
#define	FC_ASYNC_EVENTS		0x00800000

#define	FC_ILB_MODE		0x01000000
#define	FC_ELB_MODE		0x02000000
#define	FC_LOOPBACK_MODE	0x03000000	/* Loopback Mode Mask */
#define	FC_SHUTDOWN		0x08000000	/* SHUTDOWN in progress */

#define	FC_OVERTEMP_EVENT	0x10000000	/* FC_ERROR reason: over */
						/* temperature event */
#define	FC_MBOX_TIMEOUT		0x20000000	/* FC_ERROR reason: mailbox */
						/* timeout event */
#define	FC_HARDWARE_ERROR	0x80000000	/* FC_ERROR state triggered */

#define	FC_RESET_MASK		0x0000001F	/* Bits to protect during a */
						/* hard reset */
#define	FC_LINKDOWN_MASK	0xFFF0001F	/* Bits to protect during a */
						/* linkdown */


	/* Adapter memory management */
	caddr_t csr_addr;
	caddr_t slim_addr;
	caddr_t pci_addr;
	ddi_acc_handle_t csr_acc_handle;
	ddi_acc_handle_t slim_acc_handle;
	ddi_acc_handle_t pci_acc_handle;

	/* SBUS adapter management */
	caddr_t sbus_flash_addr;	/* Virt addr of R/W Flash */
	caddr_t sbus_core_addr;	/* Virt addr of TITAN CORE */
	caddr_t sbus_pci_addr;	/* Virt addr of TITAN pci config */
	caddr_t sbus_csr_addr;	/* Virt addr of TITAN CSR */
	ddi_acc_handle_t sbus_flash_acc_handle;
	ddi_acc_handle_t sbus_core_acc_handle;
	ddi_acc_handle_t sbus_pci_handle;
	ddi_acc_handle_t sbus_csr_handle;

	/* Adapter register management */
	uint32_t bc_reg_addr;	/* virtual offset for BIU config reg */
	uint32_t ha_reg_addr;	/* virtual offset for host attn reg */
	uint32_t hc_reg_addr;	/* virtual offset for host ctl reg */
	uint32_t ca_reg_addr;	/* virtual offset for FF attn reg */
	uint32_t hs_reg_addr;	/* virtual offset for status reg */
	uint32_t shc_reg_addr;	/* virtual offset for SBUS Ctrl reg */
	uint32_t shs_reg_addr;	/* virtual offset for SBUS Status reg */
	uint32_t shu_reg_addr;	/* virtual offset for SBUS Update reg */
	uint16_t hgp_ring_offset;
	uint16_t hgp_hbq_offset;
	uint16_t iocb_cmd_size;
	uint16_t iocb_rsp_size;
	uint32_t hc_copy;	/* local copy of HC register */

	uint32_t io_poll_count;	/* Number of poll commands */
				/* in progress */

	/* IO Completion management */
	uint32_t iodone_count;	/* Number of IO's on done queue */
	/* Protected by EMLXS_PORT_LOCK  */
	emlxs_buf_t *iodone_list;	/* fc_packet being deferred */
	emlxs_buf_t *iodone_tail;	/* fc_packet being deferred */
	emlxs_thread_t iodone_thread;

	/* Ring management */
	int32_t ring_count;
	emlxs_ring_t ring[MAX_RINGS];
	kmutex_t ring_cmd_lock[MAX_RINGS];
	uint8_t ring_masks[4];	/* number of masks/rings being used */
	uint8_t ring_rval[6];
	uint8_t ring_rmask[6];
	uint8_t ring_tval[6];
	uint8_t ring_tmask[6];

	kmutex_t ring_tx_lock;
	uint32_t ring_tx_count[MAX_RINGS];	/* Number of IO's on tx queue */

	/* Mailbox Management */
	uint32_t mbox_queue_flag;
	emlxs_queue_t mbox_queue;
	uint8_t *mbox_bp;	/* buffer pointer for mbox command */
	uint8_t *mbox_sbp;	/* emlxs_buf_t pointer for mbox command used */
				/* by reg_login only */
	uint8_t *mbox_ubp;	/* fc_unsol_buf_t pointer for mbox command */
				/* used by reg_login only */
	uint8_t *mbox_iocbq;	/* IOCBQ pointer for mbox command. used by */
				/* reg_login only */
	uint8_t *mbox_mbq;	/* MBX_SLEEP context */
	uint32_t mbox_mbqflag;
	kcondvar_t mbox_lock_cv;	/* MBX_SLEEP */
	kmutex_t mbox_lock;	/* MBX_SLEEP */
	uint32_t mbox_timer;

#ifdef MBOX_EXT_SUPPORT
	uint8_t *mbox_ext;	/* ptr to mailbox extension buffer */
	uint32_t mbox_ext_size;	/* size of mailbox extension buffer */
#endif	/* MBOX_EXT_SUPPORT */

	/* IOtag management */
	emlxs_buf_t **iotag_table;
	kmutex_t iotag_lock[MAX_RINGS];
	uint32_t io_count[MAX_RINGS];	/* Number of IO's holding a regular */
					/* (non-abort) iotag */
	/* Protected by EMLXS_FCTAB_LOCK */
#ifdef EMLXS_SPARC
	MATCHMAP fcp_bpl_mp;
	MATCHMAP *fcp_bpl_table;	/* iotag table for bpl buffers */
#endif	/* EMLXS_SPARC */

	/* Interrupt management */
	void *intr_arg;
	uint32_t intr_unclaimed;
	uint32_t intr_autoClear;
	uint32_t intr_flags;
#define	EMLXS_INTX_INITED	0x0001
#define	EMLXS_INTX_ADDED	0x0002
#define	EMLXS_MSI_ENABLED	0x0010
#define	EMLXS_MSI_INITED	0x0020
#define	EMLXS_MSI_ADDED		0x0040
#define	EMLXS_INTR_INITED	EMLXS_INTX_INITED|EMLXS_MSI_INITED)
#define	EMLXS_INTR_ADDED	EMLXS_INTX_ADDED|EMLXS_MSI_ADDED)

#ifdef MSI_SUPPORT
	ddi_intr_handle_t *intr_htable;
	uint32_t *intr_pri;
	int32_t *intr_cap;
	uint32_t intr_count;
	uint32_t intr_type;
	uint32_t intr_cond;
	uint32_t intr_map[EMLXS_MSI_MAX_INTRS];
	uint32_t intr_mask;
	uint32_t msi_cap_offset;
#define	MSI_CAP_ID	0x05

	uint32_t msix_cap_offset;
#define	MSIX_CAP_ID	0x11

	kmutex_t intr_lock[EMLXS_MSI_MAX_INTRS];
#endif	/* MSI_SUPPORT */

	uint32_t heartbeat_timer;
	uint32_t heartbeat_flag;
	uint32_t heartbeat_active;

	/* IOCTL management */
	kmutex_t ioctl_lock;
	uint32_t ioctl_flags;
#define	EMLXS_OPEN		0x00000001
#define	EMLXS_OPEN_EXCLUSIVE	0x00000002

	/* Timer management */
	kcondvar_t timer_lock_cv;
	kmutex_t timer_lock;
	timeout_id_t timer_id;
	uint32_t timer_tics;
	uint32_t timer_flags;
#define	EMLXS_TIMER_STARTED	0x0000001
#define	EMLXS_TIMER_BUSY	0x0000002
#define	EMLXS_TIMER_KILL	0x0000004
#define	EMLXS_TIMER_ENDED	0x0000008

	/* Misc Timers */
	uint32_t linkup_timer;
	uint32_t discovery_timer;
	uint32_t pkt_timer;

	/* Power Management */
	uint32_t pm_state;
	/* pm_state */
#define	EMLXS_PM_IN_ATTACH	0x00000001
#define	EMLXS_PM_IN_DETACH	0x00000002
#define	EMLXS_PM_IN_SOL_CB	0x00000010
#define	EMLXS_PM_IN_UNSOL_CB	0x00000020
#define	EMLXS_PM_IN_LINK_RESET	0x00000100
#define	EMLXS_PM_IN_HARD_RESET	0x00000200
#define	EMLXS_PM_SUSPENDED	0x01000000

	uint32_t pm_level;
	/* pm_level */
#define	EMLXS_PM_ADAPTER_DOWN	0
#define	EMLXS_PM_ADAPTER_UP	1

	uint32_t pm_busy;
	kmutex_t pm_lock;
	uint8_t pm_config[PCI_CONFIG_SIZE];
#ifdef IDLE_TIMER
	uint32_t pm_idle_timer;
	uint32_t pm_active;	/* Only used by timer */
#endif	/* IDLE_TIMER */


#ifdef DFC_SUPPORT
	/* Loopback management */
	uint32_t loopback_tics;
	void *loopback_pkt;
#endif	/* DFC_SUPPORT */

	/* Event management */
	uint32_t log_events;
	emlxs_dfc_event_t dfc_event[MAX_DFC_EVENTS];
	emlxs_hba_event_t hba_event;

	/* Parameter management */
	emlxs_config_t config[NUM_CFG_PARAM];

	/* Driver stat management */
	kstat_t *kstat;
	emlxs_stats_t stats;

	/* Log management */
	emlxs_msg_log_t log;

	/* Port managment */
	uint32_t vpi_max;
	uint32_t vpi_high;
	uint32_t num_of_ports;

	kmutex_t port_lock;	/* locks port, nodes, rings */
	emlxs_port_t port[MAX_VPORTS + 1];	/* port specific info, the */
						/* last one is for NPIV ready */
						/* test */

#ifdef DHCHAP_SUPPORT
	kmutex_t dhc_lock;
	kmutex_t auth_lock;
	emlxs_auth_cfg_t auth_cfg;	/* Default auth_cfg. Points to link */
					/* list of entries. Protected by */
					/* auth_lock */
	uint32_t auth_cfg_count;
	emlxs_auth_key_t auth_key;	/* Default auth_key. Points to link */
					/* list of entries. Protected by */
					/* auth_lock */
	uint32_t auth_key_count;
	uint32_t rdn_flag;
#endif	/* DHCHAP_SUPPORT */

	uint16_t ini_mode;
	uint16_t tgt_mode;

#ifdef TEST_SUPPORT
	uint32_t underrun_counter;
#endif	/* TEST_SUPPORT */

} emlxs_hba_t;

#define	EMLXS_HBA_T	1	/* flag emlxs_hba_t is already typedefed */


#ifdef MSI_SUPPORT
#define	EMLXS_INTR_INIT(_hba, _m)	emlxs_msi_init(_hba, _m)
#define	EMLXS_INTR_UNINIT(_hba)		emlxs_msi_uninit(_hba)
#define	EMLXS_INTR_ADD(_hba)		emlxs_msi_add(_hba)
#define	EMLXS_INTR_REMOVE(_hba)		emlxs_msi_remove(_hba)
#else
#define	EMLXS_INTR_INIT(_hba, _m)	emlxs_intx_init(_hba, _m)
#define	EMLXS_INTR_UNINIT(_hba)		emlxs_intx_uninit(_hba)
#define	EMLXS_INTR_ADD(_hba)		emlxs_intx_add(_hba)
#define	EMLXS_INTR_REMOVE(_hba)		emlxs_intx_remove(_hba)
#endif	/* MSI_SUPPORT */


/* Power Management Component */
#define	EMLXS_PM_ADAPTER		0


#define	DRV_TIME			(uint32_t)(ddi_get_time() - \
						emlxs_device.drv_timestamp)

#define	HBA				port->hba
#define	PPORT				hba->port[0]
#define	VPORT(x)			hba->port[x]
#define	EMLXS_TIMER_LOCK		hba->timer_lock
#define	VPD				hba->vpd
#define	CFG				hba->config[0]
#define	LOG				hba->log
#define	EMLXS_MBOX_LOCK			hba->mbox_lock
#define	EMLXS_MBOX_CV			hba->mbox_lock_cv
#define	EMLXS_LINKUP_LOCK		hba->linkup_lock
#define	EMLXS_LINKUP_CV			hba->linkup_lock_cv
#define	EMLXS_RINGTX_LOCK		hba->ring_tx_lock
#define	EMLXS_MEMGET_LOCK		hba->memget_lock
#define	EMLXS_MEMPUT_LOCK		hba->memput_lock
#define	EMLXS_IOCTL_LOCK		hba->ioctl_lock	/* locks ioctl calls */
#define	HBASTATS			hba->stats
#define	EMLXS_CMD_RING_LOCK(n)		hba->ring_cmd_lock[n]
#define	EMLXS_FCTAB_LOCK(n)		hba->iotag_lock[n]
#define	EMLXS_PORT_LOCK			hba->port_lock	/* locks port, */
							/* nodes, rings */
#define	EMLXS_INTR_LOCK(_id)		hba->intr_lock[_id]	/* locks intr */
								/* threads */

#define	EMLXS_PKT_LOCK			port->pkt_lock	/* for pkt polling */
#define	EMLXS_PKT_CV			port->pkt_lock_cv
#define	EMLXS_UB_LOCK			port->ub_lock	/* locks unsolicited */
							/* buffer pool */

#ifdef EMLXS_LITTLE_ENDIAN
#define	SWAP_SHORT(x)   (x)
#define	SWAP_LONG(x)    (x)
#define	SWAP_DATA64(x)  ((((x) & 0xFF)<<56) | (((x) & 0xFF00)<< 40) | \
			(((x) & 0xFF0000)<<24) | (((x) & 0xFF000000)<<8) | \
			(((x) & 0xFF00000000)>>8) | \
			(((x) & 0xFF0000000000)>>24) | \
			(((x) & 0xFF000000000000)>>40) | \
			(((x) & 0xFF00000000000000)>>56))
#define	SWAP_DATA32(x)	((((x) & 0xFF)<<24) | (((x) & 0xFF00)<<8) | \
			(((x) & 0xFF0000)>>8) | (((x) & 0xFF000000)>>24))
#define	SWAP_DATA16(x)  ((((x) & 0xFF) << 8) | ((x) >> 8))
#define	PCIMEM_SHORT(x) SWAP_SHORT(x)
#define	PCIMEM_LONG(x)  SWAP_LONG(x)
#define	PCIMEM_DATA(x)  SWAP_DATA32(x)


#if (EMLXS_MODREVX == EMLXS_MODREV2X)
#define	SWAP_DATA24_LO(x)    (x)
#define	SWAP_DATA24_HI(x)    (x)
#endif	/* EMLXS_MODREV2X */

#if (EMLXS_MODREVX == EMLXS_MODREV3X)
#define	SWAP_DATA24_LO(x)    ((((x) & 0xFF)<<16) | ((x) & 0xFF00FF00) | \
					(((x) & 0x00FF0000)>>16))
#define	SWAP_DATA24_HI(x)    (((x) & 0x00FF00FF) | (((x) & 0x0000FF00)<<16) | \
					(((x) & 0xFF000000)>>16))
#endif	/* EMLXS_MODREV3X */

#endif	/* EMLXS_LITTLE_ENDIAN */



#ifdef EMLXS_BIG_ENDIAN

#define	SWAP_SHORT(x)   ((((x) & 0xFF) << 8) | ((x) >> 8))
#define	SWAP_LONG(x)    ((((x) & 0xFF)<<24) | (((x) & 0xFF00)<<8) | \
			(((x) & 0xFF0000)>>8) | (((x) & 0xFF000000)>>24))

#define	SWAP_DATA64(x)		(x)
#define	SWAP_DATA32(x)		(x)
#define	SWAP_DATA16(x)		(x)

#define	PCIMEM_SHORT(x)		SWAP_SHORT(x)
#define	PCIMEM_LONG(x)		SWAP_LONG(x)
#define	PCIMEM_DATA(x)		SWAP_DATA32(x)

#define	SWAP_DATA24_LO(x)	(x)
#define	SWAP_DATA24_HI(x)	(x)

#endif	/* EMLXS_BIG_ENDIAN */

#define	SWAP_ALWAYS(x)  ((((x) & 0xFF)<<24) | (((x) & 0xFF00)<<8) | \
			(((x) & 0xFF0000)>>8) | (((x) & 0xFF000000)>>24))
#define	SWAP_ALWAYS16(x) ((((x) & 0xFF) << 8) | ((x) >> 8))

/*
 * For PCI configuration
 */
#define	ADDR_LO(addr)   ((int)(addr) & 0xffff)	/* low 16 bits */
#define	ADDR_HI(addr)   (((int)(addr) >> 16) & 0xffff)	/* high 16 bits */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_FC_H */
