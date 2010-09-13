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

#ifndef	_FCPVAR_H
#define	_FCPVAR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Maximum number of times FCP will re-issue a REPORTS_LUNS command if the
 * device couldn't return all of them in the submitted buffer.
 */
#define	FCP_MAX_REPORTLUNS_ATTEMPTS	2
/*
 * Maximum number of LUNs supported.  This limit is enforced to accommodate
 * certain HBAs.
 */
#define	FCP_MAX_LUNS_SUPPORTED		65535

/*
 * Stuff to be defined in fc_ulpif.h FIXIT
 */
#define	PORT_DEVICE_CREATE	0x40
#define	SCMD_REPORT_LUN		0xa0	/* SCSI cmd to report on LUNs */
#define	SCMD_INQUIRY_LWWN_SIZE	32	/* Max WWN size */
#define	SCMD_INQUIRY_PAGE83	0xF0	/* Internal opcode for page 0x83 */
#define	FC4_SCSI_FCP		0x08	/* our (SCSI) FC4 type number */

#define	FCP_QUEUE_DELAY	(4)
#define	FCP_FAILED_DELAY	20
#define	FCP_RESET_DELAY		3	/* target reset delay of 3 secs */
#define	FCP_OFFLINE_DELAY	20	/* 20 seconds is 2*RA_TOV_els */

/*
 * Highest possible timeout value to indicate
 * the watch thread to return the I/O
 */
#define	FCP_INVALID_TIMEOUT	(0xFFFFFFFF)

/*
 * The max inquiry page 83 size as expected in the code today
 * is 0xf0 bytes. Defining a constant to make it easy incase
 * this needs to be changed at a later time.
 */
#define	SCMD_MAX_INQUIRY_PAGE83_SIZE	0xF0
/*
 * Events generated for Target drivers; "SUNW,sf:" prefix
 * is a legacy fcal stuff hardcoded into ssd via the use of
 * FCAL_INSERT_EVENT defined in an fcal header file; We
 * just need to continue to use this.
 */
#define	FCAL_INSERT_EVENT	"SUNW,sf:DEVICE-INSERTION.1"
#define	FCAL_REMOVE_EVENT	"SUNW,sf:DEVICE-REMOVAL.1"

/*
 * for debug trace
 */
#define	FCP_STACK_DEPTH	14


/*
 * All the stuff above needs to move intp appropriate header files.
 */

#define	FCP_NUM_HASH			128

#define	FCP_HASH(x)			((x[0] + x[1] + x[2] + x[3] +\
					x[4] + x[5] + x[6] + x[7]) & \
					(FCP_NUM_HASH-1))

#define	FCP_STATEC_MASK			(FC_STATE_OFFLINE | FC_STATE_ONLINE |\
					FC_STATE_LOOP | FC_STATE_NAMESERVICE |\
					FC_STATE_RESET |\
					FC_STATE_RESET_REQUESTED |\
					FC_STATE_LIP | FC_STATE_DEVICE_CHANGE)

#define	PKT_PRIV_SIZE			2

#ifdef	KSTATS_CODE
/*
 * fcp_stats : Statistics provided for fcp.
 */
struct fcp_stats {
	uint_t	version;		/* version of this struct */
	uint_t	lip_count;		/* lips forced by fcp */
	uint_t	link_reset_count;	/* lip failures, ie, no ONLINE */
					/* response after forcing lip */
	uint_t	ncmds;			/* outstanding commands */
	uint_t	throttle_limit;		/* current throttle limit */
	char	drvr_name[MAXNAMELEN];	/* Name of driver, NULL term. */
};
#endif

/*
 * Structure fcp_port
 * --------------------
 *
 * This structure is the FCP representation of an N_Port on a local FC HBA card.
 * This is the master structure off of which all the others will be hanging at
 * some point and is the Solaris per-instance soft-state structure.
 */
typedef struct fcp_port {
	/*
	 * This mutex protects the access to this structure (or most of its
	 * fields).
	 */
	kmutex_t		port_mutex;
	/*
	 * This is the link to the next fcp_port structure in the global
	 * list.  The head of the global list is fcp_port_head and is
	 * defined in fcp.c.  This field is NULL for the last element of
	 * the global list.
	 */
	struct fcp_port		*port_next;
	/*
	 * This field points to the head of a list of internal requests that
	 * will be retried later.  Examples of internal requests are:
	 * 'Send a PRLI ELS', 'Send a PRLO ELS', 'Send a PLOGI ELS' or
	 * 'Send an Inquiry command'.  If the submission of the request to the
	 * fp/fctl module failed (for a set of specific reasons) and the
	 * request can be resubmitted later, it is queued here.	 The watchdog
	 * timer (fcp_watch()) will walk this queue and resubmit the requests.
	 */
	struct fcp_ipkt		*port_ipkt_list;
	/*
	 * This seems to be used as a temporary device counter during a
	 * discovery process (or reconfiguration as some comments put it).
	 * It seems to be initialized in fcp_statec_callback() with the
	 * number of devices that fp/fctl saw after the line came up and
	 * is supposed to reached zero when the reconfiguration process is
	 * over.
	 */
	int			port_tmp_cnt;
	/*
	 * This is supposed to indicate the state of this port.	 It is a
	 * bitmap which means several bits can be set simultaneously.  The list
	 * of the different bits and their meaning is given further down in
	 * this file.
	 */
	uint32_t		port_state;
	/*
	 * This field is initialized at the very end of the function
	 * fcp_handle_port_attach() if the attachment of the port was
	 * successful.	It is set to the value stored in lbolt64 at the
	 * time of the attachment.  This value is only used in the function
	 * fcp_scsi_bus_config().  It is used to determine the value of the
	 * parameter timeout when ndi_busop_bus_config() and cv_wait() are
	 * called.  It actually serves to figure out how long the enumeration
	 * can be delayed (the max value being FCP_INIT_WAIT_TIMEOUT).
	 */
	int64_t			port_attach_time;
	/*
	 * This field contains the topology of the SAN the port is connected
	 * to.
	 */
	uint32_t		port_topology;
	/*
	 * This field contains the local port ID.  It is provided by fp/fctl
	 * when calling fcp_statec_callback() and fcp_port_attach().  This
	 * value is used to build Fibre Channel headers (like for PLOGI or
	 * PRLI).
	 */
	uint32_t		port_id;
	/*
	 * This field keeps track of the physical port state (fcp_port being
	 * more like the FCP software port state).  The information stored here
	 * is provided by fp/fctl except in two instances: in
	 * fcp_handle_port_attach() and fcp_handle_port_resume(). The values
	 * this field can take are defined in fctl.h.
	 */
	uint32_t		port_phys_state;
	/*
	 * This field points to the first element of a list of fcp_reset_elem
	 * structures.	Those structures are created when the target driver
	 * calls fcp_reset_target().  The target or the LUN specified by the
	 * target driver is reset by sending a Task Management command.	 After
	 * the response has been received, a fcp_reset_elem structure is
	 * queued here and will remain queued for FCP_RESET_DELAY.  While
	 * the fcp_reset_elem structure is in this queue the LUNs of
	 * the target to reset or the LUN to reset is set to LUN_BUSY state.
	 * In fcp_watch() the timeout is tested.  If the timout has expired,
	 * the fcp_reset_elem structure is unqueued and freed, and all the
	 * active commands for the target or LUNs are aborted.
	 */
	struct fcp_reset_elem	*port_reset_list;
	/*
	 * This points to the first element of a list of fcp_tgt_elem
	 * structures.	This list is a list of targets to offline.  The list
	 * is walked in fcp_watch(). After the target is offlined the
	 * structure fcp_tgt_elem is freed.
	 */
	struct fcp_tgt_elem	*port_offline_tgts;
	/*
	 * This points to the first element of a list of fcp_lun_elem
	 * structures.	This list is a list of LUNs to offline.	 The list
	 * is walked in fcp_watch(). After the lun is offlined the
	 * structure fcp_lun_elem is freed.
	 */
	struct fcp_lun_elem	*port_offline_luns;
	/*
	 * This field is a counter initialized to 1 when the port attaches.
	 * It is incremented when the line goes from online to offline and
	 * vice versa.	It is also incremented when the port detaches.	The
	 * value stored in this counter is used as a reference in time of the
	 * link state.	For example, when the line comes up internal requests
	 * are generated (fcp_ipkt) such as PRLI and INQUIRY.  Those requests
	 * are tagged with the value contained in this field at the time the
	 * request is built.  When the callback for the request is called, the
	 * current value of port_link_cnt is checked against the one set in
	 * the internal request structure.  If they don't match, it means the
	 * the request is not relevant anymore to the current line state and
	 * must be discarded (in between a request is issued and the callback
	 * routine is called the line may have bounced).  This is the way FCP
	 * identifies the requests that were hanging out when the state of the
	 * line changed.
	 */
	uint32_t		port_link_cnt;
	/*
	 * This field, as its name suggests, specifies a deadline for the
	 * overall discovery process.  It is initialized in three cases:
	 *
	 * 1) When the line goes from the offline state to the online state.
	 * 2) When the FP/FCTL called fcp_statec_callback() indicating that
	 *    a notification was received from the fabric indicating that a new
	 *    port showed up or that one disappeared.
	 * 3) In the fcp_create_on_demand() function (called because of an
	 *    ioctl).
	 *
	 * In all instances it is set to:
	 *
	 *	fcp_watchdog_time + FCP_ICMD_DEADLINE
	 *
	 * In all those instances a discovery process is started or extended
	 * (2).	 The value stored in port_deadline is only checked in one
	 * function: fcp_is_retryable().  That function checks if an
	 * internal command (fcp_ipkt) is retryable or not.  Usually
	 * there's a counter that limits the number of times a command is
	 * retried (Max value is FCP_MAX_RETRIES).  However, even if the
	 * counter hasn't exceeded that value, the command will not be retried
	 * past the deadline.  This means that the discovery process has to
	 * be finished before port_deadline.  In other words, an internal
	 * command retry capability is limited numerically and in time.
	 */
	int			port_deadline;
	/*
	 * This is the Node WWN of the local port.  It is initialized
	 * during the port attachment.
	 */
	la_wwn_t		port_nwwn;
	/*
	 * This is the Port WWN of the local port.  It is initialized during
	 * the port attachment.
	 */
	la_wwn_t		port_pwwn;
	/*
	 * This is the fp/fctl port handle.
	 */
	opaque_t		*port_fp_handle;
	/*
	 * The following 4 fields handle the queue of fcp_pkt outstanding for
	 * this port.
	 *
	 *   port_pkt_mutex	Protects the access to the queue
	 *   port_pkt_head	Points to the head of the queue
	 *   port_pkt_tail	Points to the tail of the queue
	 *   port_npkts	Number of commands outstanding (used only when
	 *			DEBUG is defined).
	 */
	kmutex_t		port_pkt_mutex;
	uint32_t		port_npkts;
	struct fcp_pkt		*port_pkt_head;
	struct fcp_pkt		*port_pkt_tail;
	/*
	 * This field is the counter of allocated and currently active
	 * fcp_ipkt.
	 */
	int			port_ipkt_cnt;
	/*
	 * Port instance provided by FP/FCTL.  It is actually deduced using
	 * ddi_get_instance() in fcp_port_attach().
	 */
	uint32_t		port_instance;
	/*
	 * Maximum number of exchanges the underlying physical FibreChannel
	 * port can handle.  This field is initialized during the port
	 * attachment but is never used.
	 */
	uint32_t		port_max_exch;
	/*
	 * This port stores the behavior expected of the underlying FCA driver
	 * when a port reset occurs.  The values stored here are defined in the
	 * file fc_types.h.
	 */
	fc_reset_action_t	port_reset_action;
	/*
	 * This port stores the DMA behavior of the underlying FCA driver.  It
	 * is checked only once in fcp_prepare_pkt() and, as the comment
	 * suggests, to work around an issue with an Intel PCI bridge.
	 */
	fc_dma_behavior_t	port_cmds_dma_flags;
	/*
	 * The value stored here indicates if the underlying FCA driver
	 * supports DMA transfers with non SCSI data (Ex: PRLI request).
	 */
	fc_fcp_dma_t		port_fcp_dma;
	/*
	 * This field contains the size of the private space required by the
	 * underlying FCA driver in a FibreChannel packet (fc_packet_t).
	 */
	uint32_t		port_priv_pkt_len;
	/*
	 * This field contains the port's modlink info.	 It is provided by
	 * FP/FCTL during the port attachment.
	 */
	struct modlinkage	port_fp_modlinkage;
	/*
	 * DMA attributes for data packets, commands and responses.
	 */
	ddi_dma_attr_t		port_data_dma_attr;
	ddi_dma_attr_t		port_cmd_dma_attr;
	ddi_dma_attr_t		port_resp_dma_attr;
	ddi_device_acc_attr_t	port_dma_acc_attr;
	/*
	 * Field containing the hba_tran structure registered with SCSA.
	 */
	struct scsi_hba_tran	*port_tran;
	/*
	 * Device info structure provided by fp/fctl when the port attaches and
	 * representing the local physical fibre channel port.
	 */
	dev_info_t		*port_dip;
	/*
	 * Head of the list of callback routines to call when a bus reset
	 * occurs.  This list is  populated by the targets drivers by calling
	 * fcp_scsi_reset_notify() (tran_reset_notify(9E)).
	 */
	struct scsi_reset_notify_entry	*port_reset_notify_listf;
	/*
	 * for framework event management
	 */
	ndi_event_definition_t	*port_ndi_event_defs;
	ndi_event_hdl_t		port_ndi_event_hdl;
	ndi_event_set_t		port_ndi_events;
	/*
	 * hash lists of targets attached to this port.	  The hashing is based
	 * on the WWN.
	 */
	struct fcp_tgt		*port_tgt_hash_table[FCP_NUM_HASH];
	/*
	 * per-Port control flag.  By default mpxio is enabled on ports unless
	 * explicitly disabled through driver.conf.
	 */
	int			port_mpxio;
	/*
	 * Value used as a flag to determine if the throttling has been
	 * set/initialized in the FCA driver.
	 */
	int			port_notify;
	/*
	 * This field contains a string initialized at attachment time and used
	 * when calling the function the function fc_trace_debug() (through
	 * the macro FCP_TRACE and FCP_DTRACE) to identify the port that
	 * logged the message.
	 */
	char			port_instbuf[24];
	uchar_t			port_boot_wwn[FC_WWN_SIZE];

#ifdef	DEBUG
	/*
	 * Use once in fcp_finish_init() when calling getpcstack().
	 */
	int			port_finish_depth;
	pc_t			port_finish_stack[FCP_STACK_DEPTH];
#endif /* DEBUG */
	/*
	 * Condition variable used during the bus enumeration process.
	 */
	kcondvar_t		port_config_cv;
	/*
	 * Size (in bytes) required to hold the cookies of a scatter/gather
	 * list.
	 */
	int			port_dmacookie_sz;
} fcp_port_t;

/*
 * We need to save the target change count values in a map tag so as
 * to uniquely identify the cause and handle it better as they change
 * counts are bound to change upon receiving more state changes.
 */
typedef int fcp_map_tag_t;

/*
 * fcp_state definitions.
 */
#define	FCP_STATE_INIT			0x0001
#define	FCP_STATE_OFFLINE		0x0002
#define	FCP_STATE_ONLINE		0x0004
#define	FCP_STATE_SUSPENDED		0x0008
#define	FCP_STATE_POWER_DOWN		0x0010
#define	FCP_STATE_ONLINING		0x0020
#define	FCP_STATE_DETACHING		0x0040
#define	FCP_STATE_IN_WATCHDOG		0x0080
#define	FCP_STATE_IN_MDI		0x0100	/* Not in S8/S9 */
#define	FCP_STATE_NS_REG_FAILED		0x0200	/* Diff value from S8/S9 */
/*
 * FCP_STATE_IN_CB_DEVC indicates that we're handling a state change
 * notification that will be changing the state of devices.  This is an
 * indication to fcp_scsi_start that the target's status might change.
 */
#define	FCP_STATE_IN_CB_DEVC		0x0400

/*
 * FCP_STATE_FCA_IS_NODMA indicates that FCA doesn't support DMA at all
 */
#define	FCP_STATE_FCA_IS_NODMA		0x80000000

#define	FCP_MAX_DEVICES			127

/* To remember that dip was allocated for a lun on this target. */

#define	FCP_DEVICE_CREATED		0x1

#define	FCP_EVENT_TAG_INSERT		0
#define	FCP_EVENT_TAG_REMOVE		1

/*
 * fcp_pkt: FCP packet
 * ---------------------
 *
 * This structure is the one initialized/created in the tran_init_pkt(9E).  It
 * embeds the fc_packet structure eventually passed to fp/fctl as well as
 * the scsi_pkt returned by tran_init_pkt(9E) to the target driver.  There is
 * a 1-to-1 correlation between the scsi_pkt, the fcp_pkt and the
 * fc_packet.
 *
 * This is what a fcp_pkt looks like after allocation:
 *
 *			+================================+
 *		 +--->	|	 struct scsi_pkt	 |
 *		 |	|				 |
 *		 | +--- | pkt_ha_private		 |
 *		 | |	|				 |
 *		 | |	+================================+
 *		 | |
 *		 | |	+================================+
 *		 | +--> |	 struct fcp_pkt		 | <---------+
 *		 +----- | cmd_pkt			 |	     |
 *			|		      cmd_fp_pkt | ---+	     |
 *	     +--------->| cmd_fcp_rsp[]			 |    |	     |
 *	     | +------->| cmd_fcp_cmd[]			 |    |	     |
 *	     | |	|--------------------------------|    |	     |
 *	     | |	|	 struct fc_packet	 | <--+	     |
 *	     | |	|				 |	     |
 *	     | |	|		 pkt_ulp_private | ----------+
 *	     | |	|		 pkt_fca_private | -----+
 *	     | |	|		 pkt_data_cookie | ---+ |
 *	     | |	| pkt_cmdlen			 |    | |
 *	     | |(a)	| pkt_rsplen			 |    | |
 *	     | +--------| .......... pkt_cmd ........... | ---|-|-------+
 *	     |	(a)	|		  pkt_cmd_cookie | ---|-|-----+ |
 *	     +----------| .......... pkt_resp .......... | ---|-|---+ | |
 *			|		 pkt_resp_cookie | ---|-|-+ | | |
 *			| pkt_cmd_dma			 |    | | | | | |
 *			| pkt_cmd_acc			 |    | | | | | |
 *			+================================+    | | | | | |
 *			|	  dma_cookies		 | <--+ | | | | |
 *			|				 |	| | | | |
 *			+================================+	| | | | |
 *			|	  fca_private		 | <----+ | | | |
 *			|				 |	  | | | |
 *			+================================+	  | | | |
 *								  | | | |
 *								  | | | |
 *			+================================+   (b)  | | | |
 *			|	 fcp_resp cookies	 | <------+ | | |
 *			|				 |	    | | |
 *			+================================+	    | | |
 *								    | | |
 *			+================================+   (b)    | | |
 *			|	     fcp_resp		 | <--------+ | |
 *			|   (DMA resources associated)	 |	      | |
 *			+================================+	      | |
 *								      | |
 *								      | |
 *								      | |
 *			+================================+   (b)      | |
 *			|	  fcp_cmd cookies	 | <----------+ |
 *			|				 |		|
 *			+================================+		|
 *									|
 *			+================================+   (b)	|
 *			|	     fcp_cmd		 | <------------+
 *			|   (DMA resources associated)	 |
 *			+================================+
 *
 *
 * (a)	The underlying FCA does NOT support DMA for this field
 * (b)	The underlying FCA supports DMA for this field
 */
typedef struct fcp_pkt {
	/*
	 * The two following fields are used to queue fcp_pkt in the double
	 * link list of the lun structure.  The packet is queued in
	 * tran_init_pkt(9E) and unqueued in tran_destroy_pkt(9E).
	 */
	struct fcp_pkt		*cmd_forw;
	struct fcp_pkt		*cmd_back;
	/*
	 * This field is used to queue the packet in the single link list of the
	 * port structure.  The port keeps a list of all the commands issued
	 * through it and scans it, for example, when all of those commands
	 * have to be aborted.
	 */
	struct fcp_pkt		*cmd_next;
	/*
	 * This field points back to the scsi_pkt.
	 */
	struct scsi_pkt		*cmd_pkt;
	/*
	 * This field points to the field cmd_fc_packet defined further in this
	 * same structure.
	 */
	struct fc_packet	*cmd_fp_pkt;
	/*
	 * Structure where the FCP_CMD information unit is going to be built.
	 */
	fcp_cmd_t		cmd_fcp_cmd;
	/*
	 * State of the packet.	 The values for the state seem to indicate
	 * that it isn't a bitmap.  However, in several instances the code
	 * treats it as a bitmap doing a "&= ~FCP_PKT_ISSUED" to it
	 * eventhough the value stored is always checked using "!=" and "==".
	 */
	uint_t			cmd_state;
	/*
	 * This field is a bitmap indicating if
	 * the cmd is queued
	 */
	uint_t			cmd_flags;
	/* Contains the number of bytes DMA mappped. */
	uint_t			cmd_dmacount;
	/*
	 * Contains the timeout value for the packet.  This is not a delay or
	 * a delta but an absolute value.
	 */
	uint_t			cmd_timeout;
	/*
	 * This array is used to store the FCP_RSP information unit returned by
	 * the device when the underlying FCA cannot DMA it in.
	 */
	char			cmd_fcp_rsp[FCP_MAX_RSP_IU_SIZE];
	/*
	 * This is the fc_packet structure used to forward the request to
	 * fp/fctl.
	 */
	struct fc_packet	cmd_fc_packet;
} fcp_pkt_t;

/*
 * fcp_ipkt : Packet for internal commands.
 * ------------------------------------------
 *
 *			+================================+
 *			|	 struct fcp_ipkt	 | <---------+
 *			|	 (kmem_zalloc())	 |	     |
 *			|		       ipkt_fpkt | ---+	     |
 *			|				 |    |	     |
 *			|     ipkt_cmdlen = cmd_len	 |    |	     |
 *			|				 |    |	     |
 *			|				 |    |	     |
 *			|				 |    |	     |
 *			|--------------------------------|    |	     |
 *			|	 struct fc_packet	 | <--+	     |
 *			|				 |	     |
 *			|		 pkt_ulp_private | ----------+
 *			|		 pkt_fca_private | -----+
 *			|		 pkt_data_cookie | ---+ |
 *			|	    pkt_cmdlen		 |    | |
 *			|	    pkt_rsplen		 |    | |
 *			| pkt_cmd ...................... | ---|-|-------+
 *			|		  pkt_cmd_cookie | ---|-|-----+ |
 *			| pkt_resp ..................... | ---|-|---+ | |
 *			|		 pkt_resp_cookie | ---|-|-+ | | |
 *			|	   pkt_cmd_dma		 |    | | | | | |
 *			|	   pkt_cmd_acc		 |    | | | | | |
 *			+================================+    | | | | | |
 *			|	  dma_cookies		 | <--+ | | | | |
 *			|				 |	| | | | |
 *			|				 |	| | | | |
 *			|				 |	| | | | |
 *			+================================+	| | | | |
 *			|	  fca_private		 | <----+ | | | |
 *			|				 |	  | | | |
 *			|				 |	  | | | |
 *			|				 |	  | | | |
 *			+================================+	  | | | |
 *								  | | | |
 *								  | | | |
 *			+================================+   (b)  | | | |
 *			|	 fcp_resp cookies	 | <------+ | | |
 *			|				 |	    | | |
 *			+================================+	    | | |
 *								    | | |
 *			+================================+   (b)    | | |
 *			|	     fcp_resp		 | <--------+ | |
 *			|   (DMA resources associated)	 |	      | |
 *			+================================+	      | |
 *								      | |
 *								      | |
 *								      | |
 *			+================================+   (b)      | |
 *			|	  fcp_cmd cookies	 | <----------+ |
 *			|				 |		|
 *			+================================+		|
 *									|
 *			+================================+   (b)	|
 *			|	     fcp_cmd		 | <------------+
 *			|   (DMA resources associated)	 |
 *			+================================+
 *
 * (a)	The underlying FCA does NOT support DMA for this field
 * (b)	The underlying FCA supports DMA for this field
 */
typedef struct fcp_ipkt {
	/*
	 * Pointer to the port (fcp_port) in behalf of which this internal
	 * packet was allocated.
	 */
	struct fcp_port		*ipkt_port;
	/*
	 * Pointer to the target (fcp_tgt) in behalf of which this internal
	 * packet was allocated.
	 */
	struct fcp_tgt		*ipkt_tgt;
	/*
	 * Pointer to the lun (fcp_lun) in behalf of which this internal
	 * packet was allocated.  This field is only meaningful when the
	 * internal packet has been allocated for a "scsi passthru" command or
	 * for an internal SCSI command such as REPORT LUNs and INQUIRY.
	 */
	struct fcp_lun		*ipkt_lun;
	/*
	 * Fields used to queue the internal packet into the double linked list
	 * of the FCP port (fcp_port).
	 */
	struct fcp_ipkt		*ipkt_next;
	struct fcp_ipkt		*ipkt_prev;
	/*
	 * This field points to the field ipkt_fc_packet defined farther in
	 * this same structure.
	 */
	struct fc_packet	*ipkt_fpkt;
	/*
	 * This is the timeout value for the internal packet.  It seems to
	 * increase with the number of retries.	 It is initialized like this
	 * in the code:
	 *
	 *   icmd->ipkt_restart = fcp_watchdog_time + icmd->ipkt_retries++
	 *
	 * First time ipkt_retries is zero.  As it increases, the timeout
	 * value for the internal packet also increases.
	 */
	uint32_t		ipkt_restart;
	/*
	 * Link state counter when the internal packet was built.
	 */
	uint32_t		ipkt_link_cnt;
	int			ipkt_cause;
	uint32_t		ipkt_cmdlen;
	uint32_t		ipkt_resplen;
	uint32_t		ipkt_datalen;
	/*
	 * Counter of the times an internal packet has been retried.  Its
	 * value is checked against FCP_MAX_RETRIES.
	 */
	uint32_t		ipkt_retries;
	uint32_t		ipkt_change_cnt;
	int			ipkt_nodma;
	/*
	 * Semaphore used to wait for completion on.
	 */
	ksema_t			ipkt_sema;
	/*
	 * Opcode indicating what internal command the packet contains (PLOGI,
	 * PRLI, INQUIRY...).
	 */
	uchar_t			ipkt_opcode;
	/*
	 * FC packet.
	 */
	struct fc_packet	ipkt_fc_packet;
} fcp_ipkt_t;

/*
 * cmd_state definitions
 */
#define	FCP_PKT_IDLE			0x1
#define	FCP_PKT_ISSUED			0x2
#define	FCP_PKT_ABORTING		0x3

/*
 * These are the defined cmd_flags for this structure.
 */
#define	CFLAG_NONE		0x0000
#define	CFLAG_IS_READ		0x0001
#define	CFLAG_IN_QUEUE		0x0002	/* command in fcp queue */

/*
 * Target structure
 * ----------------
 *
 * This structure holds the information relative to a SCSI target.  This
 * structure doesn't represent the object registered with the OS (NDI or
 * MPxIO...).
 */
typedef struct fcp_tgt {
	/*
	 * This field is used to queue the target structure in one of the
	 * buckets of the fcp_port target hash table port_tgt_hash_table[].
	 */
	struct fcp_tgt		*tgt_next;
	/* Points to the fcp_port the target belongs to. */
	struct fcp_port		*tgt_port;
	/*
	 * This field is a bitmap indicating the state of the target.  Several
	 * bits can be set simultaneously.
	 */
	uint32_t		tgt_state;
	/*
	 * State controlling if the LUNs attached to this target will be
	 * automatically onlined or not.
	 */
	uint32_t		tgt_node_state;
	/*
	 * Mutex protecting this structure.
	 */
	kmutex_t		tgt_mutex;
	/*
	 * List of LUNs (single link list).
	 */
	struct fcp_lun		*tgt_lun;
	opaque_t		tgt_fca_dev;
	/*
	 * Number of LUNs in this target.
	 */
	uint_t			tgt_lun_cnt;
	/*
	 * Counter of LUNs to probe.  It is used during the discovery
	 * process.  Starts with the number of LUNs returned by REPORT_LUN
	 * and is decremented until it reaches zero.
	 */
	uint_t			tgt_tmp_cnt;
	/*
	 * fp/fctl handle for the "port_device".
	 */
	opaque_t		tgt_pd_handle;
	/*
	 * Node World Wide Name.
	 */
	la_wwn_t		tgt_node_wwn;
	/*
	 * Port World Wide Name.
	 */
	la_wwn_t		tgt_port_wwn;
	/*
	 * Fibre Channel Port ID.
	 */
	uint32_t		tgt_d_id;
	/*
	 * Fibre Channel Port ID.  Uses bit fields to represent it.
	 */
	uint32_t		tgt_hard_addr;
	/*
	 * Becomes 1 when the LUNs are created.
	 */
	uchar_t			tgt_device_created;
	/*
	 * Counter of how many REPORT_LUN commands were sent.  It is used to
	 * allow the REPORT_LUN command to be sent twice in case the buffer
	 * allocated the first time wasn't big enough.
	 */
	uchar_t			tgt_report_lun_cnt;
	/*
	 * This field is incremented each time the field tgt_state is updated.
	 * Its use is similar to the use of the field port_link_cnt in the
	 * fcp_port structure.	The internal packets are, for example, tagged
	 * with the value stored here.
	 */
	uint32_t		tgt_change_cnt;
	/*
	 * This field contains the cause of the last change in state.
	 */
	int			tgt_statec_cause;
	/*
	 * The following two fields indicate whether the remote port is an
	 * FCP initiator or an FCP target.  They are treated as booleans.
	 */
	uchar_t			tgt_icap;	/* Initiator */
	uchar_t			tgt_tcap;	/* Target */
#ifdef	DEBUG
	/*
	 * Updated in fcp_call_finish_init_held() when DEBUG  is defined
	 */
	int			tgt_tmp_cnt_depth;
	pc_t			tgt_tmp_cnt_stack[FCP_STACK_DEPTH];
#endif /* DEBUG */
	/*
	 * This field holds the timer id of the timer started when a LUN
	 * reconfiguration is needed for the target.  The reconfiguration
	 * is done in the timeout function.
	 */
	timeout_id_t		tgt_tid;
	int			tgt_done;
	/*
	 * Bitmap used to trace the discovery process.
	 */
	uint32_t		tgt_trace;
	/*
	 * This field is used when the code is sorting out which devices
	 * were known which ones are new and which ones went away.
	 */
	uint32_t		tgt_aux_state;
	/*
	 * Number of internal packets allocated in behalf of the target.
	 */
	int			tgt_ipkt_cnt;
	/*
	 * used to detect user unconfig when auto configuration is enabled.
	 */
	uint32_t		tgt_manual_config_only;
} fcp_tgt_t;

/*
 * Target States
 */
#define	FCP_TGT_INIT		0x01
#define	FCP_TGT_BUSY		0x02
#define	FCP_TGT_MARK		0x04
#define	FCP_TGT_OFFLINE		0x08
#define	FCP_TGT_ORPHAN		0x80
#define	FCP_TGT_ILLREQ		0x10

/*
 * Target Aux Stat
 */
#define	FCP_TGT_TAGGED		0x01

/*
 * Target discovery tracing
 */
#define	FCP_TGT_TRACE_1		0x00000001
#define	FCP_TGT_TRACE_2		0x00000002
#define	FCP_TGT_TRACE_3		0x00000004
#define	FCP_TGT_TRACE_4		0x00000008
#define	FCP_TGT_TRACE_5		0x00000010
#define	FCP_TGT_TRACE_6		0x00000020
#define	FCP_TGT_TRACE_7		0x00000040
#define	FCP_TGT_TRACE_8		0x00000080
#define	FCP_TGT_TRACE_9		0x00000100
#define	FCP_TGT_TRACE_10	0x00000200
#define	FCP_TGT_TRACE_11	0x00000400
#define	FCP_TGT_TRACE_12	0x00000800
#define	FCP_TGT_TRACE_13	0x00001000
#define	FCP_TGT_TRACE_14	0x00002000
#define	FCP_TGT_TRACE_15	0x00004000
#define	FCP_TGT_TRACE_16	0x00008000
#define	FCP_TGT_TRACE_17	0x00010000
#define	FCP_TGT_TRACE_18	0x00020000
#define	FCP_TGT_TRACE_19	0x00040000
#define	FCP_TGT_TRACE_20	0x00080000
#define	FCP_TGT_TRACE_21	0x00100000
#define	FCP_TGT_TRACE_22	0x00200000
#define	FCP_TGT_TRACE_23	0x00400000
#define	FCP_TGT_TRACE_24	0x00800000
#define	FCP_TGT_TRACE_25	0x01000000
#define	FCP_TGT_TRACE_26	0x02000000
#define	FCP_TGT_TRACE_27	0x04000000
#define	FCP_TGT_TRACE_28	0x08000000
#define	FCP_TGT_TRACE_29	0x10000000

#ifndef	__lock_lint

#define	FCP_TGT_TRACE(ptgt, tcount, bit) {\
	if (ptgt) {\
		if (ptgt->tgt_change_cnt == tcount) {\
			ptgt->tgt_trace |= bit;\
		}\
	}\
}

#else	/* __lock_lint */

#define	FCP_TGT_TRACE(ptgt, tcount, bit)

#endif /* __lock_lint */


/*
 * state change cause
 */
#define	FCP_CAUSE_TGT_CHANGE	0x01
#define	FCP_CAUSE_LINK_CHANGE	0x02
#define	FCP_CAUSE_LINK_DOWN	0x04
#define	FCP_CAUSE_USER_CREATE	0x08


/*
 * Target node states (applicable to LUNs behind the target)
 */
#define	FCP_TGT_NODE_NONE	0x00	/* No node exists */
#define	FCP_TGT_NODE_ON_DEMAND	0x01	/* create only upon request */
#define	FCP_TGT_NODE_PRESENT	0x02	/* Node exists; rediscover it */


#define	FCP_NO_CHANGE		0x1
#define	FCP_LINK_CHANGE		0x2
#define	FCP_DEV_CHANGE		0x3


/* hotplug event struct */
struct fcp_hp_event {
	int (*callback)();
	void *arg;
};

/*
 * We talk to both NDI and MDI framework to enumerate our child devices.
 * We internally define a generic child handle and assign either dev_info
 * or mdi_pathinfo handle depending on the device.
 */
typedef void		*child_info_t;

#define	CIP(child)	((child_info_t *)(child))
#define	DIP(child)	((dev_info_t *)(child))
#define	PIP(child)	((mdi_pathinfo_t *)(child))

/*
 * LUN structure
 * -------------
 *
 * This structure holds the information relative to a SCSI LUN.	 This
 * structure is the one representing the object registered with the OS (NDI
 * or MPxIO...).
 */
typedef struct fcp_lun {
	/*
	 * Mutex protecting the access to this structure.
	 */
	kmutex_t		lun_mutex;
	/*
	 * Logical unit number.	 It is a SCSI3 format.
	 */
	fcp_ent_addr_t		lun_addr;
	/*
	 * The two following fields are respectively the head and tail of a
	 * double link list of fcp_packets.  It is populated in
	 * tran_init_pkt(9E) (fcp_scsi_init_pkt) and emptied in
	 * tran_destroy_pkt(9E) (fcp_scsi_destroy_pkt).
	 */
	struct fcp_pkt		*lun_pkt_head;
	struct fcp_pkt		*lun_pkt_tail;
	/*
	 * This field is treated like a union.	It may contain the dev_info_t
	 * or the mdi_pathinfo_t depending on how the device associated with
	 * this LUN was registered.
	 */
	child_info_t		*lun_cip;
	/*
	 * Online/Offline event count.
	 */
	int			lun_event_count;
	/*
	 * Back pointer to the target the LUN belongs to.
	 */
	struct fcp_tgt		*lun_tgt;
	/*
	 * Bit map reflecting the state of the LUN.
	 */
	uint_t			lun_state;
	/*
	 * LUN type (disk, tape...).  The value stored here is taken from the
	 * inquiry data.
	 */
	uchar_t			lun_type;
	/*
	 * This field is incremented each time fcp_scsi_tgt_init()
	 * (tran_tgt_init(9E)) is called and decremented each time
	 * fcp_scsi_tgt_free() (tran_tgt_free(9E)) is called.  The
	 * incrementation and decrementation will also have an effect on
	 * lun_state bit FCP_SCSI_LUN_TGT_INIT.
	 */
	uchar_t			lun_tgt_count;
	/*
	 * LUN number as it is returned by REPORT_LUNS.
	 */
	uint16_t		lun_num;
	/*
	 * Pointer to the next LUN.
	 */
	struct fcp_lun		*lun_next;
	/*
	 * lun level association with scsi_device
	 */
	struct scsi_device	*lun_sd;
	/*
	 * per-Lun control flag.  A value of '1' means the LUN is managed by
	 * mpxio.  A value of '0' means the LUN has been physically enumerated
	 * as a child of corresponding port driver node.
	 */
	int			lun_mpxio;
	/*
	 * Length of the GUID.
	 */
	size_t			lun_guid_size;
	/*
	 * Pointer to a buffer that contains the GUID.
	 */
	char			*lun_guid;
	/*
	 * Pointer to a buffer that contains the old GUID.
	 */
	char			*lun_old_guid;
	/*
	 * Length of the old GUID
	 */
	size_t			lun_old_guid_size;
	/*
	 * Bitmap used to track the LUN discovery process.
	 */
	uint32_t		lun_trace;
	/*
	 * Bitmap representing the SCSI capabilities.
	 */
	uchar_t			lun_cap;
	/*
	 * LUN inquiry data (as returned by the INQUIRY command).
	 */
	struct scsi_inquiry	lun_inq;
} fcp_lun_t;


/*
 * Lun discovery tracing
 */
#define	FCP_LUN_TRACE_1		0x0000001
#define	FCP_LUN_TRACE_2		0x0000002
#define	FCP_LUN_TRACE_3		0x0000004
#define	FCP_LUN_TRACE_4		0x0000008
#define	FCP_LUN_TRACE_5		0x0000010
#define	FCP_LUN_TRACE_6		0x0000020
#define	FCP_LUN_TRACE_7		0x0000040
#define	FCP_LUN_TRACE_8		0x0000080
#define	FCP_LUN_TRACE_9		0x0000100
#define	FCP_LUN_TRACE_10	0x0000200
#define	FCP_LUN_TRACE_11	0x0000400
#define	FCP_LUN_TRACE_12	0x0000800
#define	FCP_LUN_TRACE_13	0x0001000
#define	FCP_LUN_TRACE_14	0x0002000
#define	FCP_LUN_TRACE_15	0x0004000
#define	FCP_LUN_TRACE_16	0x0008000
#define	FCP_LUN_TRACE_17	0x0010000
#define	FCP_LUN_TRACE_18	0x0020000
#define	FCP_LUN_TRACE_19	0x0040000
#define	FCP_LUN_TRACE_20	0x0080000
#define	FCP_LUN_TRACE_21	0x0100000
#define	FCP_LUN_TRACE_22	0x0200000
#define	FCP_LUN_TRACE_23	0x0400000
#define	FCP_LUN_TRACE_24	0x0800000
#define	FCP_LUN_TRACE_25	0x1000000
#define	FCP_LUN_TRACE_26	0x2000000
#define	FCP_LUN_TRACE_27	0x4000000
#define	FCP_LUN_TRACE_28	0x8000000


#define	FCP_LUN_TRACE(plun, bit) {\
	if (plun && plun->lun_tgt) {\
		mutex_enter(&plun->lun_tgt->tgt_mutex);\
		plun->lun_trace |= bit;\
		mutex_exit(&plun->lun_tgt->tgt_mutex);\
	}\
}

#define	FCP_LUN_CAP_RESET	0x01

/*
 * Lun State -- these have the same values as the target states so
 * that they can be interchanged (in cases where the same state occurs
 * for both targets and luns)
 */

#define	FCP_LUN_INIT		FCP_TGT_INIT
#define	FCP_LUN_BUSY		FCP_TGT_BUSY
#define	FCP_LUN_MARK		FCP_TGT_MARK
#define	FCP_LUN_OFFLINE		FCP_TGT_OFFLINE
#define	FCP_SCSI_LUN_TGT_INIT	0x20	/* target/LUNs all inited */
#define	FCP_LUN_DISAPPEARED	0x40
/*
 * Use the below flag with caution as it is can cause a delay in
 * fcp_scsi_start() which is in the normal I/O performance path
 */
#define	FCP_LUN_ONLINING	0x80
/*
 * Set the below flag when the DTYPE or GUID of a LUN changes during discovery
 */
#define	FCP_LUN_CHANGED	0x100
/*
 * This flag is used specifically for the special lun: lun 0.
 */
#define	FCP_LUN_DEVICE_NOT_CONNECTED	0x200

/*
 * Report Lun Format
 */
struct fcp_reportlun_resp {
	uint32_t	num_lun;	/* num LUNs * 8 */
	uint32_t	reserved;
	longlong_t	lun_string[1];
};

/*
 * This structure actually represents a request executed by the hot plug task.
 */
struct fcp_hp_elem {
	/*
	 * FCP port concerned by the request.
	 */
	struct fcp_port	*port;
	/*
	 * LUN concerned by the request.
	 */
	struct fcp_lun	*lun;
	/*
	 * dev_info_t or mdi_pathinfo_t pointer.
	 */
	child_info_t		*cip;
	/*
	 * lun_mpxio when the event is submitted
	 */
	int			old_lun_mpxio;
	/*
	 * What to do (offline, online...).
	 */
	int			what;
	/*
	 * FLags used when calling NDI fucntions.
	 */
	int			flags;
	/*
	 * Link state change count when the structure was created.
	 */
	int			link_cnt;
	/*
	 * Target state change count when the structure was created.
	 */
	int			tgt_cnt;
	/*
	 * Online/Offline count when this event was queued.
	 */
	int			event_cnt;
	/*
	 * This is the flag protected by the mutex and condition variable
	 * defined further in this structure.  It is the flag indicating
	 * that the hot plug task is done with the treatment of the structure.
	 */
	int			wait;
	/*
	 * This is where the result of the request is returned when the sender
	 * waits for the completion.
	 */
	int			result;
	/*
	 * Condition variable used when wait is true.
	 */
	kcondvar_t		cv;
	/*
	 * Mutex used in conjunction with the previous condition variable.
	 */
	kmutex_t		mutex;
};


struct fcp_reset_elem {
	struct fcp_reset_elem	*next;
	struct fcp_tgt		*tgt;
	struct fcp_lun		*lun;
	clock_t			timeout;
	uint_t			tgt_cnt;
};

/*
 * This structure is used to offline targets.  It is queued in the FCP port
 * structure single linked list port_offline_tgts and walked by the watchdog
 * timer.
 */
struct fcp_tgt_elem {
	/*
	 * Points to the next element of the list.
	 */
	struct fcp_tgt_elem	*next;
	/*
	 * Points to the target to offline.
	 */
	struct fcp_tgt		*ptgt;
	/*
	 * Absolute time after which the target must be offlined.
	 */
	int			time;
	/*
	 * Link state change count when the structure was created.
	 */
	int			link_cnt;
	/*
	 * Target state change count when the structure was created.
	 */
	int			tgt_cnt;
	/*
	 * Flags providing information for the offline (when calling mdi or
	 * ndi).
	 */
	int			flags;
};

/*
 * This structure is used to offline LUNs.  It is queued in the FCP port
 * structure single linked list port_offline_luns and walked by the watchdog
 * timer.
 */
struct fcp_lun_elem {
	/*
	 * Points to the next element of the list.
	 */
	struct fcp_lun_elem	*next;
	/*
	 * Points to the LUN to offline.
	 */
	struct fcp_lun		*plun;
	/*
	 * Absolute time after which the LUN must be offlined.
	 */
	int			time;
	/*
	 * Link state change count when the structure was created.
	 */
	int			link_cnt;
	/*
	 * Target state change count when the structure was created.
	 */
	int			tgt_cnt;
	/*
	 * Flags providing information for the offline (when calling mdi or
	 * ndi).
	 */
	int			flags;
};

/*
 * LUN masking
 */
typedef struct fcp_black_list_entry {
	/*
	 * Points to the next element of the list.
	 */
	struct fcp_black_list_entry	*next;
	/*
	 * Port WWN of the target.
	 */
	la_wwn_t			wwn;
	/*
	 * LUN number which need to be masked.
	 */
	uint32_t			lun;
	/*
	 * Counter of access times.
	 */
	int				masked;
} fcp_black_list_entry_t;

#define	ADDR2FCP(ap)	((struct fcp_port *)		\
		((ap)->a_hba_tran->tran_hba_private))
#define	ADDR2LUN(ap)	((struct fcp_lun *)				\
		scsi_device_hba_private_get(scsi_address_device(ap)))
#define	CMD2PKT(cmd)	((cmd)->cmd_pkt)
#define	PKT2CMD(pkt)	((struct fcp_pkt *)((pkt)->pkt_ha_private))

/*
 * timeout values
 */
#define	FCP_ELS_TIMEOUT		20	/* 20 seconds */
#define	FCP_SCSI_CMD_TIMEOUT	25	/* 30 seconds */
#define	FCP_POLL_TIMEOUT	60	/* 60 seconds */
#define	FCP_TIMEOUT_DELTA	2	/* 2 seconds */
#define	FCP_ICMD_DEADLINE	120	/* 60 seconds */
#define	FCP_MAX_RETRIES		4


#if !defined(__lint)
_NOTE(MUTEX_PROTECTS_DATA(fcp_port::port_mutex,
    fcp_port::port_state fcp_tgt::tgt_change_cnt
    fcp_port::fcp_next fcp_port::port_tgt_hash_table
    fcp_port::port_link_cnt fcp_port::port_reset_list
    fcp_port::port_tmp_cnt fcp_port::port_ipkt_list
    fcp_tgt::tgt_next))

_NOTE(MUTEX_PROTECTS_DATA(fcp_port::port_pkt_mutex,
    fcp_port::port_pkt_head fcp_port::port_pkt_tail
    fcp_port::port_npkts))

_NOTE(MUTEX_PROTECTS_DATA(fcp_tgt::tgt_mutex,
    fcp_tgt::tgt_state	fcp_tgt::tgt_device_created
    fcp_tgt::tgt_icap fcp_tgt::tgt_tcap
    fcp_tgt::tgt_tid fcp_tgt::tgt_pd_handle fcp_tgt::tgt_tmp_cnt
    fcp_tgt::tgt_statec_cause fcp_lun::lun_next fcp_lun::lun_state))

_NOTE(LOCK_ORDER(fcp_port::fcp_mutex fcp_tgt::tgt_mutex))
_NOTE(LOCK_ORDER(fcp_tgt::tgt_mutex fcp_lun::lun_mutex))

_NOTE(MUTEX_PROTECTS_DATA(fcp_lun::lun_mutex,
    fcp_lun::lun_pkt_head fcp_lun::lun_pkt_tail
    fcp_lun::lun_cip fcp_lun::lun_mpxio))

_NOTE(DATA_READABLE_WITHOUT_LOCK( fcp_tgt::tgt_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK( fcp_tgt::tgt_pd_handle))

_NOTE(DATA_READABLE_WITHOUT_LOCK(fcp_tgt::tgt_tid))


_NOTE(SCHEME_PROTECTS_DATA("Safe Data",
    fcp_port::port_dma_acc_attr
    fcp_port::port_fcp_dma fcp_port::fcp_tran
    fcp_port::port_ndi_events fcp_port::port_ndi_event_defs
    fcp_port::port_pkt_cache fcp_port::port_dip fcp_port::port_phys_state
    fcp_port::port_reset_action fcp_port::port_cmds_dma_flags
    fcp_port::port_fp_handle fcp_port::port_instance
    fcp_port::port_fp_modlinkage fcp_port::port_max_exch
    fcp_port::port_priv_pkt_len fcp_port::port_id
    fcp_port::port_topology fcp_port::port_deadline fcp_port::port_mpxio
    fcp_tgt::tgt_d_id fcp_tgt::tgt_hard_addr fcp_tgt::tgt_lun_cnt
    fcp_tgt::tgt_port fcp_lun::lun_num fcp_lun::lun_tgt
    fcp_lun::lun_type
    fcp_lun::lun_guid_size fcp_lun::lun_guid
    fcp_hp_elem::lun fcp_hp_elem::flags fcp_hp_elem::cip
    fcp_hp_elem::what fcp_hp_elem::tgt_cnt fcp_hp_elem::tgt_cnt
    fcp_hp_elem::link_cnt fcp_reset_elem fcp_pkt fcp_ipkt
    scsi_pkt scsi_arq_status scsi_device scsi_hba_tran scsi_cdb))
#endif	/* __lint */

/*
 * Local variable "pptr" must exist before using these
 */
#define	FCP_CP_IN(s, d, handle, len)					\
	{								\
		if (!((pptr)->port_state & FCP_STATE_FCA_IS_NODMA)) {	\
			ddi_rep_get8((handle), (uint8_t *)(d),		\
			    (uint8_t *)(s), (len), DDI_DEV_AUTOINCR);	\
		} else {						\
			bcopy((s), (d), (len));				\
		}							\
	}

#define	FCP_CP_OUT(s, d, handle, len)				\
	{								\
		if (!((pptr)->port_state & FCP_STATE_FCA_IS_NODMA)) {	\
			ddi_rep_put8((handle), (uint8_t *)(s),		\
			    (uint8_t *)(d), (len), DDI_DEV_AUTOINCR);	\
		} else {						\
			bcopy((s), (d), (len));				\
		}							\
	}

#define	FCP_ONLINE			0x1
#define	FCP_OFFLINE			0x2
#define	FCP_MPXIO_PATH_CLEAR_BUSY	0x3
#define	FCP_MPXIO_PATH_SET_BUSY		0x4

#define	FCP_IDLE			0x00
#define	FCP_OPEN			0x01
#define	FCP_EXCL			0x02
#define	FCP_BUSY			0x04

#define	LFA(x)				(x & 0xFFFF00)
#define	FCP_SET				1
#define	FCP_RESET			0

/* init() and attach() wait timeout values (in usecs) */
#define	FCP_INIT_WAIT_TIMEOUT		60000000	/* 60 seconds */
#define	FCP_ATTACH_WAIT_TIMEOUT		10000000	/* 10 seconds */

#ifdef	TRUE
#undef	TRUE
#endif
#define	TRUE			1

#ifdef	FALSE
#undef	FALSE
#endif
#define	FALSE			0

#define	UNDEFINED		-1

/* for softstate */
#define	FCP_INIT_ITEMS	5

#ifdef	__cplusplus
}
#endif

#endif	/* _FCPVAR_H */
