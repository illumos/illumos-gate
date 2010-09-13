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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SCSI_ADAPTERS_FASVAR_H
#define	_SYS_SCSI_ADAPTERS_FASVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * QLogic FAS (Enhanced	Scsi Processor)	Definitions,
 * Software && Hardware.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>

/*
 * Compile options
 */
#if DEBUG
#define	FASDEBUG		/* turn	on debugging code */
#define	FASTEST
#endif /* DEBUG	*/

/*
 * Software Definitions
 */
#define	POLL_TIMEOUT		(2 * SCSI_POLL_TIMEOUT * 1000000)
#define	SHORT_POLL_TIMEOUT	(1000000) /* in	usec, about 1 secs */
#define	FAS_MUTEX(fas)		(&(fas)->f_mutex)
#define	FAS_CV(fas)		(&(fas)->f_cv)
#define	FAS_INITIAL_SOFT_SPACE	4	/* Used	for the	softstate_init func */
#define	FAS_QUIESCE_TIMEOUT	1	/* 1 sec */

/*
 * Data	Structure for this Host	Adapter.
 *
 * structure to	hold active outstanding	cmds
 */
struct f_slots {
	ushort_t		f_dups;
	ushort_t		f_tags;
	int			f_timeout;
	int			f_timebase;
				/* t_slot size is 1 for	non-tagged, and	*/
				/* 256 for tagged targets		*/
	ushort_t		f_n_slots; /* number of	a_slots		*/
	ushort_t		f_size;
	struct fas_cmd		*f_slot[1];	/* may be for 256 for TQ */
};

#define	FAS_F_SLOTS_SIZE_TQ	(sizeof	(struct	f_slots) + \
			(sizeof	(struct	fas_cmd	*) * (NTAGS -1)))
#define	FAS_F_SLOT_SIZE		(sizeof	(struct	f_slots))

/*
 * HBA interface macros
 */
#define	SDEV2TRAN(sd)		((sd)->sd_address.a_hba_tran)
#define	SDEV2ADDR(sd)		(&((sd)->sd_address))
#define	PKT2TRAN(pkt)		((pkt)->pkt_address.a_hba_tran)
#define	ADDR2TRAN(ap)		((ap)->a_hba_tran)

#define	TRAN2FAS(tran)		((struct fas *)(tran)->tran_hba_private)
#define	SDEV2FAS(sd)		(TRAN2FAS(SDEV2TRAN(sd)))
#define	PKT2FAS(pkt)		(TRAN2FAS(PKT2TRAN(pkt)))
#define	ADDR2FAS(ap)		(TRAN2FAS(ADDR2TRAN(ap)))


/*
 * soft	state information for this host	adapter
 */
#define	N_SLOTS			(NTARGETS_WIDE*NLUNS_PER_TARGET)
#define	REG_TRACE_BUF_SIZE	1024

struct fas {
	int		f_instance;
	/*
	 * Transport structure for this	instance of the	hba
	 */
	scsi_hba_tran_t	*f_tran;

	/*
	 * dev_info_t reference
	 */
	dev_info_t	*f_dev;

	/*
	 * mutex to protect softstate and hw regs
	 */
	kmutex_t	f_mutex;

	/*
	 * Interrupt block cookie
	 */
	ddi_iblock_cookie_t	f_iblock;

	/*
	 * Next	in a linked list of host adapters
	 */
	struct fas	*f_next;

	/*
	 * Type	byte for this host adapter
	 * and rev of the FEPS chip
	 */
	uchar_t		f_type;
	uchar_t		f_hm_rev;

	/*
	 * value for configuration register 1.
	 * Also	contains Initiator Id.
	 */
	uint8_t		f_fasconf;

	/*
	 * value for configuration register 2
	 */
	uint8_t		f_fasconf2;

	/*
	 * value for configuration register 3
	 */
	uint8_t		f_fasconf3[NTARGETS_WIDE];
	uint8_t		f_fasconf3_reg_last;

	/*
	 * clock conversion register value for this host adapter.
	 * clock cycle value * 1000 for	this host adapter,
	 * to retain 5 significant digits.
	 */
	uchar_t		f_clock_conv;
	ushort_t	f_clock_cycle;

	/*
	 * selection timeout register value
	 */
	uint8_t		f_stval;

	/*
	 * State of the	host adapter
	 */
	uchar_t	f_sdtr_sent;	/* Count of sync data negotiation messages: */
				/* zeroed for every selection attempt, */
				/* every reconnection, and every disconnect */
				/* interrupt. Each SYNCHRONOUS DATA TRANSFER */
				/* message, both coming	from the target, and */
				/* sent	to the target, causes this tag to be */
				/* incremented.	This allows the	received */
				/* message handling to determine whether */
				/* a received SYNCHRONOUS DATA TRANSFER	*/
				/* message is in response to one that we */
				/* sent. */
	uchar_t	f_wdtr_sent;	/* same	for wide negotations */
	uchar_t	f_stat;		/* soft	copy of	status register	*/
	uchar_t	f_stat2;	/* soft	copy of	status2	register */
	uchar_t	f_intr;		/* soft	copy of	interrupt register */
	uchar_t	f_step;		/* soft	copy of	step register */
	uchar_t	f_abort_msg_sent; /* indicates that abort message went out */
	uchar_t	f_reset_msg_sent; /* indicates that device reset message */
				/* went	out */
	uchar_t	f_last_cmd;	/* last	cmd sent to fas	chip */

	ushort_t f_state;	/* state of the	driver */
	ushort_t f_laststate;	/* last	state of the driver */
	uchar_t	f_suspended;	/* true	if driver is suspended */
	uchar_t	f_dslot;	/* delta to next slot */
	uchar_t	f_idcode;	/* chips idcode	*/
	uchar_t	f_polled_intr;	/* current interrupt was polled. */

	/*
	 * Message handling: enough space is reserved for the expected length
	 * of all messages we could either send	or receive.
	 *
	 * For sending,	we expect to send only SYNCHRONOUS extended messages
	 * (5 bytes). We keep a	history	of the last message sent, and in order
	 * to control which message to send, an	output message length is set
	 * to indicate whether and how much of the message area	is to be used
	 * in sending a	message. If a target shifts to message out phase
	 * unexpectedly, the default action will be to send a MSG_NOP message.
	 *
	 * After the successful	transmission of	a message, the initial message
	 * byte	is moved to the	f_last_msgout area for tracking	what was the
	 * last	message	sent.
	 */

#define	OMSGSIZE	12
	uchar_t		f_cur_msgout[OMSGSIZE];
	uchar_t		f_last_msgout;
	uchar_t		f_omsglen;


	/*
	 * We expect, at, most,	to receive a maximum of	7 bytes
	 * of an incoming extended message (MODIFY DATA	POINTER),
	 * and thus reserve enough space for that.
	 */
#define	IMSGSIZE	8
	uchar_t		f_imsgarea[IMSGSIZE];

	/*
	 * These are used to index how far we've
	 * gone	in receiving incoming  messages.
	 */
	uchar_t		f_imsglen;
	uchar_t		f_imsgindex;

	/*
	 * Saved last msgin.
	 */
	uchar_t		f_last_msgin;

	/*
	 * round robin scheduling of requests in fas_ustart()
	 */
	uchar_t		f_next_slot;

	/*
	 * save	reselecting slot when waiting for tag bytes
	 */
	uchar_t		f_resel_slot;

	/*
	 * Target information
	 *	Synchronous SCSI Information,
	 *	Disconnect/reconnect capabilities
	 *	Noise Susceptibility
	 */
	uchar_t	f_offset[NTARGETS_WIDE]; /* synch offset + req-ack delay */
	uchar_t	f_sync_period[NTARGETS_WIDE]; /* synch period reg val */
	uchar_t	f_neg_period[NTARGETS_WIDE]; /*	synch periods (negotiated) */
	ushort_t f_backoff;		/* sync/wide backoff bit mask */
	uchar_t	f_req_ack_delay;	/* req ack delay in offset reg */
	uchar_t	f_offset_reg_last;	/* save	last offset value */
	uchar_t	f_period_reg_last;	/* save	last period value */

	/*
	 * fifo	length and fifo	contents stored	here before reading intr reg
	 */
	uchar_t		f_fifolen;
	uchar_t		f_fifo[2*FIFOSIZE];

	/*
	 * These ushort_t's are  bit maps	for targets
	 */
	ushort_t	f_wide_known;	/* wide	negotiate on	next cmd */
	ushort_t	f_nowide;	/* no wide for this target */
	ushort_t	f_wide_enabled;	/* wide	enabled	for this target	*/

	ushort_t	f_sync_known;	/* sync	negotiate on next cmd */
	ushort_t	f_nosync;	/* no sync for this target */
	ushort_t	f_sync_enabled;	/* sync	enabled	for this target	*/

	/*
	 * This ushort_t is a bit map for targets to
	 * disable sync on request from the target driver
	 */
	ushort_t	f_force_async;
	ushort_t	f_force_narrow;

	/*
	 * This	ushort_t is a bit map for targets who don't appear
	 * to be able to support tagged	commands.
	 */
	ushort_t	f_notag;

	/*
	 * This ushort_t is a bit map for targets who need to have
	 * their properties update deferred.
	 */
	ushort_t	f_props_update;

	/*
	 * scsi_options	for bus	and per	target
	 */
	int		f_target_scsi_options_defined;
	int		f_scsi_options;
	int		f_target_scsi_options[NTARGETS_WIDE];

	/*
	 * tag age limit per bus
	 */
	int		f_scsi_tag_age_limit;

	/*
	 * scsi	reset delay per	bus
	 */
	uint_t		f_scsi_reset_delay;

	/*
	 * Scratch Buffer, allocated out of iopbmap for	commands
	 * The same size as the	FAS's fifo.
	 */
	uchar_t		*f_cmdarea;

	/*
	 * shadow copy of dma_csr to avoid unnecessary I/O reads which are
	 * expensive
	 */
	uint32_t	f_dma_csr;

	/*
	 * Scratch Buffer DMA cookie and handle	for cmdarea
	 */
	ddi_dma_cookie_t	f_dmacookie;
	ddi_dma_handle_t	f_dmahandle;

	/*
	 * dma attrs for fas scsi engine
	 */
	ddi_dma_attr_t		*f_dma_attr;

	/*
	 * critical counters
	 */
	short	f_ncmds;	/* number of commands stored here at present */
	short	f_ndisc;	/* number of disconnected cmds at present */

	/*
	 * Hardware pointers
	 *
	 * Pointer to mapped in	FAS registers
	 */
	volatile struct	fasreg *f_reg;

	/*
	 * Pointer to mapped in	DMA Gate Array registers
	 */

	volatile struct	dma    *f_dma;

	/*
	 * last	and current state, queues
	 */
	uint32_t		f_lastdma;	/* last	dma address */
	uint32_t		f_lastcount;	/* last	dma count */

	struct fas_cmd		*f_current_sp;	/* currently active cmd	*/
	struct f_slots		*f_active[N_SLOTS]; /* outstanding cmds	*/

	struct fas_cmd		*f_readyf[N_SLOTS]; /* waiting cmds */
	struct fas_cmd		*f_readyb[N_SLOTS];

				/*
				 * if throttle >= 0 then
				 * continue submitting cmds
				 * if throttle == 0 then hold cmds
				 * if throttle == -1 then drain
				 * if throttle == -2 do special handling
				 * for queue full
				 * f_throttle and f_tcmds are not part of
				 * f_active so fas_ustart() can	walk thru
				 * these more efficiently
				 */
	short			f_throttle[N_SLOTS];

				/*
				 * number of disconnected + active commands
				 * (i.e. stored in the f_active list) for
				 * the slot
				 */
	short			f_tcmds[N_SLOTS];

				/*
				 * if a	device reset has been performed, a
				 * delay is required before accessing the target
				 * again; reset	delays are in milli secs
				 * (assuming that reset	watchdog runs every
				 * scsi-watchdog-tick  milli secs;
				 * the watchdog	decrements the reset delay)
				 */
	int			f_reset_delay[NTARGETS_WIDE];

	/*
	 * list	for auto request sense packets
	 */
	struct fas_cmd		*f_arq_pkt[N_SLOTS];

	/*
	 * queue of packets that need callback and other callback info
	 */
	struct fas_cmd		*f_c_qf;
	struct fas_cmd		*f_c_qb;
	kmutex_t		f_c_mutex;
	int			f_c_in_callback;

	/*
	 * a queue for packets in case the fas mutex is	locked
	 */
	kmutex_t		f_waitQ_mutex;
	struct fas_cmd		*f_waitf;
	struct fas_cmd		*f_waitb;

	/*
	 * list	of reset notification requests
	 */
	struct scsi_reset_notify_entry	 *f_reset_notify_listf;

	/*
	 * qfull handling
	 */
	uchar_t			f_qfull_retries[NTARGETS_WIDE];
	ushort_t		f_qfull_retry_interval[NTARGETS_WIDE];
	timeout_id_t		f_restart_cmd_timeid;

	/*
	 * kmem	cache for packets
	 */
	struct kmem_cache	*f_kmem_cache;

	/*
	 * data access handle for register mapping
	 */
	ddi_acc_handle_t	f_regs_acc_handle;
	/*
	 * data access handle for cmd area
	 */
	ddi_acc_handle_t	f_cmdarea_acc_handle;
	/*
	 * data access handle for dma
	 */
	ddi_acc_handle_t	f_dmar_acc_handle;

	/*
	 * state flags
	 */
	uint_t			f_flags;

	/*
	 * cv for bus quiesce/unquiesce
	 */
	kcondvar_t		f_cv;

	/*
	 * soft state flags
	 */
	uint_t			f_softstate;

	/*
	 * quiesce timeout ID
	 */
	timeout_id_t		f_quiesce_timeid;

	/*
	 * kstat_intr support
	 */
	struct kstat		*f_intr_kstat;

#ifdef FASDEBUG
	/*
	 * register trace for debugging
	 */
	uint_t			f_reg_trace_index;
	uint_t			f_reg_trace[REG_TRACE_BUF_SIZE+1];

	uint_t			f_reserved[256];

	uint_t			f_reg_reads;
	uint_t			f_reg_dma_reads;
	uint_t			f_reg_writes;
	uint_t			f_reg_dma_writes;
	uint_t			f_reg_cmds;
	uint_t			f_total_cmds;
#endif
};
_NOTE(MUTEX_PROTECTS_DATA(fas::f_mutex,	fas))
_NOTE(MUTEX_PROTECTS_DATA(fas::f_waitQ_mutex, fas::f_waitf fas::f_waitb))
_NOTE(MUTEX_PROTECTS_DATA(fas::f_c_mutex, fas::f_c_qf fas::f_c_qb
	fas::f_c_in_callback))
_NOTE(DATA_READABLE_WITHOUT_LOCK(fas::f_flags))

_NOTE(SCHEME_PROTECTS_DATA("unique per packet or safe sharing",
    scsi_cdb scsi_status scsi_pkt buf))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_device scsi_address))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", fas::f_next fas::f_state))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
	fas::f_dma fas::f_dma_attr fas::f_hm_rev))
_NOTE(SCHEME_PROTECTS_DATA("stable data",
	fas::f_target_scsi_options fas::f_scsi_options))
_NOTE(SCHEME_PROTECTS_DATA("stable data", fas::f_instance))
_NOTE(SCHEME_PROTECTS_DATA("only debugging",
	fas::f_reg_trace_index fas::f_reg_trace))
_NOTE(SCHEME_PROTECTS_DATA("protected by kmem lock", fas::f_kmem_cache))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
	fas::f_notag fas::f_suspended fas::f_ndisc))
_NOTE(SCHEME_PROTECTS_DATA("stable data", fas::f_dev fas::f_tran))
_NOTE(SCHEME_PROTECTS_DATA("only debugging", fas::f_reg_dma_reads))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", fas::f_quiesce_timeid))

/*
 * kstat_intr support
 */

#define	FAS_KSTAT_INTR(fas)  KSTAT_INTR_PTR(fas->f_intr_kstat)->\
					intrs[KSTAT_INTR_HARD]++

/*
 * defaults for	the global properties
 */
#define	DEFAULT_SCSI_OPTIONS	SCSI_OPTIONS_DR
#define	DEFAULT_TAG_AGE_LIMIT	2
#define	DEFAULT_WD_TICK		10

/*
 * define for f_flags
 */
#define	FAS_FLG_NOTIMEOUTS	0x0001	/* disallow timeout rescheduling */

#define	FAS_CAN_SCHED	((fas->f_flags & FAS_FLG_NOTIMEOUTS) == 0)

/*
 * f_req_ack_delay:
 */
#define	DEFAULT_REQ_ACK_DELAY	0x50	/* delay assert	period by 1/2 cycle */

/*
 * Representations of Driver states (stored in tags f_state && f_laststate).
 *
 * Totally idle. There may or may not disconnected commands still
 * running on targets.
 */
#define	STATE_FREE	0x00

/*
 * Selecting States. These states represent a selection	attempt
 * for a target.
 */
#define	STATE_SELECT_NORMAL	0x0100
#define	STATE_SELECT_N_STOP	0x0200
#define	STATE_SELECT_N_SENDMSG	0x0400
#define	STATE_SYNC_ASKING	0x0800
#define	STATE_SELECT_N_TAG	0x1000
#define	STATE_SELECTING		0xFF00	/* Select mask */


/*
 * When	the driver is neither idle nor selecting, it is	in one of
 * the information transfer phases. These states are not unique
 * bit patterns- they are simple numbers used to mark transitions.
 * They	must start at 1	and proceed sequentially upwards and
 * match the indexing of function vectors declared in the function
 * fas_phasemanage().
 */
#define	STATE_ITPHASES		0x00FF	/* Phase mask */

/*
 * These states	cover finishing	sending	a command out (if it wasn't
 * sent	as a side-effect of selecting),	or the case of starting
 * a command that was linked to	the previous command (i.e., no
 * selection phase for this particular command as the target
 * remained connected when the previous	command	completed).
 */
#define	ACTS_CMD_START		0x01
#define	ACTS_CMD_DONE		0x02

/*
 * These states	are the	begin and end of sending out a message.
 * The message to be sent is stored in the field f_msgout (see above).
 */
#define	ACTS_MSG_OUT		0x03
#define	ACTS_MSG_OUT_DONE	0x04

/*
 * These states	are the	beginning, middle, and end of incoming messages.
 *
 */
#define	ACTS_MSG_IN		0x05
#define	ACTS_MSG_IN_MORE	0x06
#define	ACTS_MSG_IN_DONE	0x07

/*
 * This	state is reached when the target may be	getting
 * ready to clear the bus (disconnect or command complete).
 */
#define	ACTS_CLEARING		0x08

/*
 * These states	elide the begin	and end	of a DATA phase
 */
#define	ACTS_DATA		0x09
#define	ACTS_DATA_DONE		0x0A

/*
 * This	state indicates	that we	were in	status phase. We handle	status
 * phase by issuing the	FAS command 'CMD_COMP_SEQ' which causes	the
 * FAS to read the status byte,	and then to read a message in (presumably
 * one of COMMAND COMPLETE, LINKED COMMAND COMPLETE or LINKED COMMAND
 * COMPLETE WITH FLAG).
 *
 * This	state is what is expected to follow after the issuance of the
 * FAS command 'CMD_COMP_SEQ'.
 */
#define	ACTS_C_CMPLT		0x0B

/*
 * This	state is used by the driver to indicate	that it
 * is in the middle of processing a reselection	attempt.
 */
#define	ACTS_RESEL		0x0C

/*
 * This	state is used by the driver to indicate	that it	doesn't	know
 * what	the next state is, and that it should look at the FAS's	status
 * register to find out	what SCSI bus phase we are in in order to select
 * the next state to transition	to.
 */
#define	ACTS_UNKNOWN		0x0D

/*
 * This	state is used by the driver to indicate	that a self-inititated
 * Bus reset is	in progress.
 */
#define	ACTS_RESET		0x0E

/*
 * Hiwater mark	of vectored states
 */
#define	ACTS_ENDVEC		0x0E

/*
 * XXX - needs to distinguish between bus states and internal states
 */

/*
 * This	state is used by the driver to indicate	to itself that it is
 * in the middle of aborting things.
 */
#define	ACTS_ABORTING		0x1D

/*
 * This	state is used by the driver to just hold the state of
 * the softc structure while it	is either aborting or resetting
 * everything.
 */
#define	ACTS_FROZEN		0x1F


/*
 * Interrupt dispatch actions
 */
#define	ACTION_RETURN		-1	/* return from interrupt */
#define	ACTION_FINSEL		0x00	/* finish selection */
#define	ACTION_RESEL		0x01	/* handle reselection */
#define	ACTION_PHASEMANAGE	0x02	/* manage phases */
#define	ACTION_FINISH		0x03	/* this	command	done */
#define	ACTION_FINRST		0x04	/* finish reset	recovery */
#define	ACTION_SEARCH		0x05	/* search for new command to start */
#define	ACTION_ABORT_CURCMD	0x06	/* abort current command */
#define	ACTION_ABORT_ALLCMDS	0x07	/* abort all commands */
#define	ACTION_RESET		0x08	/* reset bus */
#define	ACTION_SELECT		0x09	/* handle selection */

/*
 * Proxy command definitions.
 *
 * At certain times, we	need to	run a proxy command for	a target
 * (if only to select a	target and send	a message).
 *
 * We use the tail end of the cdb that is internal to the fas_cmd
 * structure to	store the proxy	code, the proxy	data (e.g., the
 * message to send).
 *
 * We also store a boolean result code in this area so that the
 * user	of a proxy command knows whether it succeeded.
 */

/*
 * Offsets into	the cmd_cdb[] array (in fas_cmd) for proxy data
 */
#define	FAS_PROXY_TYPE		CDB_GROUP0
#define	FAS_PROXY_RESULT	FAS_PROXY_TYPE+1
#define	FAS_PROXY_DATA		FAS_PROXY_RESULT+1

/*
 * Currently supported proxy types
 */

#define	FAS_PROXY_SNDMSG	1

/*
 * Reset actions
 */
#define	FAS_RESET_FAS		0x1	/* reset FAS chip */
#define	FAS_RESET_DMA		0x2	/* reset DMA gate array	*/
#define	FAS_RESET_BRESET	0x4	/* reset SCSI bus */
#define	FAS_RESET_IGNORE_BRESET	0x8	/* ignore SCSI Bus RESET interrupt */
					/* while resetting bus.	*/
#define	FAS_RESET_SCSIBUS	(FAS_RESET_BRESET|FAS_RESET_IGNORE_BRESET)
#define	FAS_RESET_SOFTC		0x10	/* reset SOFTC structure */

#define	FAS_RESET_HW		(FAS_RESET_FAS|FAS_RESET_DMA|FAS_RESET_SCSIBUS)
#define	FAS_RESET_ALL		(FAS_RESET_HW|FAS_RESET_SOFTC)

#define	FAS_RESET_MSG		0x20

#define	FAS_RESET_SPIN_DELAY_USEC	20
#define	FAS_RESET_SPIN_MAX_LOOP		1000

/*
 * f_softstate flags
 */
#define	FAS_SS_DRAINING		0x02
#define	FAS_SS_QUIESCED		0x04

/*
 * Debugging macros and	defines
 */
#ifdef	FASDEBUG
/*PRINTFLIKE2*/
extern void fas_dprintf(struct fas *fas, const char *fmt, ...)
	__KPRINTFLIKE(2);

#define	INFORMATIVE	(fasdebug)
#define	IDEBUGGING	((fasdebug) && \
			((fas->f_instance == fasdebug_instance)	|| \
			(fasdebug_instance == -1)))
#define	DDEBUGGING	((fasdebug > 1)	&& \
			((fas->f_instance == fasdebug_instance)	|| \
			(fasdebug_instance == -1)))

#define	EDEBUGGING	((fasdebug > 2)	&& \
			((fas->f_instance == fasdebug_instance)	|| \
			(fasdebug_instance == -1)))

#define	EPRINTF(str)		if (EDEBUGGING)	fas_dprintf(fas, str)
#define	EPRINTF1(str, a)	if (EDEBUGGING)	fas_dprintf(fas, str, a)
#define	EPRINTF2(str, a, b)	if (EDEBUGGING)	fas_dprintf(fas, str, a, b)
#define	EPRINTF3(str, a, b, c)	if (EDEBUGGING)	fas_dprintf(fas, str, a, b, c)
#define	EPRINTF4(str, a, b, c, d)	\
	if (EDEBUGGING)	fas_dprintf(fas, str, a, b, c, d)
#define	EPRINTF5(str, a, b, c, d, e)	\
	if (EDEBUGGING)	fas_dprintf(fas, str, a, b, c, d, e)
#define	EPRINTF6(str, a, b, c, d, e, f)	\
	if (EDEBUGGING)	fas_dprintf(fas, str, a, b, c, d, e, f)

#define	DPRINTF(str)		if (DDEBUGGING)	fas_dprintf(fas, str)
#define	DPRINTF1(str, a)	if (DDEBUGGING)	fas_dprintf(fas, str, a)
#define	DPRINTF2(str, a, b)	if (DDEBUGGING)	fas_dprintf(fas, str, a, b)
#define	DPRINTF3(str, a, b, c)	if (DDEBUGGING)	fas_dprintf(fas, str, a, b, c)
#define	DPRINTF4(str, a, b, c, d)	\
	if (DDEBUGGING)	fas_dprintf(fas, str, a, b, c, d)
#define	DPRINTF5(str, a, b, c, d, e)	\
	if (DDEBUGGING)	fas_dprintf(fas, str, a, b, c, d, e)
#define	DPRINTF6(str, a, b, c, d, e, f)	\
	if (DDEBUGGING)	fas_dprintf(fas, str, a, b, c, d, e, f)

#define	IPRINTF(str)		if (IDEBUGGING)	fas_dprintf(fas, str)
#define	IPRINTF1(str, a)	if (IDEBUGGING)	fas_dprintf(fas, str, a)
#define	IPRINTF2(str, a, b)	if (IDEBUGGING)	fas_dprintf(fas, str, a, b)
#define	IPRINTF3(str, a, b, c)	if (IDEBUGGING)	fas_dprintf(fas, str, a, b, c)
#define	IPRINTF4(str, a, b, c, d)	\
	if (IDEBUGGING)	fas_dprintf(fas, str, a, b, c, d)
#define	IPRINTF5(str, a, b, c, d, e)	\
	if (IDEBUGGING)	fas_dprintf(fas, str, a, b, c, d, e)
#define	IPRINTF6(str, a, b, c, d, e, f)	\
	if (IDEBUGGING)	fas_dprintf(fas, str, a, b, c, d, e, f)

#else	/* FASDEBUG */

#define	EPRINTF(str)
#define	EPRINTF1(str, a)
#define	EPRINTF2(str, a, b)
#define	EPRINTF3(str, a, b, c)
#define	EPRINTF4(str, a, b, c, d)
#define	EPRINTF5(str, a, b, c, d, e)
#define	EPRINTF6(str, a, b, c, d, e, f)
#define	DPRINTF(str)
#define	DPRINTF1(str, a)
#define	DPRINTF2(str, a, b)
#define	DPRINTF3(str, a, b, c)
#define	DPRINTF4(str, a, b, c, d)
#define	DPRINTF5(str, a, b, c, d, e)
#define	DPRINTF6(str, a, b, c, d, e, f)
#define	IPRINTF(str)
#define	IPRINTF1(str, a)
#define	IPRINTF2(str, a, b)
#define	IPRINTF3(str, a, b, c)
#define	IPRINTF4(str, a, b, c, d)
#define	IPRINTF5(str, a, b, c, d, e)
#define	IPRINTF6(str, a, b, c, d, e, f)

#endif	/* FASDEBUG */

/*
 * Shorthand macros and	defines
 */

/*
 * Short hand defines
 */
#define	ALL_TARGETS	0xffff

#define	MAX_THROTTLE	254	/* 1 tag used for non-tagged cmds, 1 rsvd */
#define	HOLD_THROTTLE	0
#define	DRAIN_THROTTLE	-1
#define	QFULL_THROTTLE	-2

#define	NODISC(tgt)		(fas->f_nodisc & (1<<(tgt)))
#define	NOTAG(tgt)		(fas->f_notag &	(1<<(tgt)))
#define	TAGGED(tgt)		((fas->f_notag & (1<<(tgt))) ==	0)
#define	SYNC_KNOWN(tgt)		(fas->f_sync_known & (1<<(tgt)))

#define	NEXTSLOT(slot, d)	((slot)+(d)) & ((N_SLOTS)-1)
#define	MY_ID(fas)		((fas)->f_fasconf & FAS_CONF_BUSID)
#define	INTPENDING(fas)		(fas_dma_reg_read((fas), \
				    &((fas)->f_dma->dma_csr))&DMA_INT_MASK)

#define	Tgt(sp)	((sp)->cmd_pkt->pkt_address.a_target)
#define	Lun(sp)	((sp)->cmd_pkt->pkt_address.a_lun)

#define	New_state(fas, state)\
	(fas)->f_laststate = (fas)->f_state, (fas)->f_state = (state)

#define	CNUM		(fas->f_instance)
#define	TRUE		1
#define	FALSE		0
#define	UNDEFINED	-1
#define	INVALID_MSG	0x7f

/*
 * Default is to have 10 retries on receiving QFULL status and
 * each retry to be after 100 ms.
 */
#define	QFULL_RETRIES		10
#define	QFULL_RETRY_INTERVAL	100

/*
 * FEPS chip revision
 */
#define	FAS_HM_REV(fas)		(fas)->f_hm_rev

/*
 * Some	manifest miscellaneous constants
 */

#define	MEG		(1000 *	1000)
#define	FIVE_MEG	(5 * MEG)
#define	TEN_MEG		(10 * MEG)
#define	TWENTY_MEG	(20 * MEG)
#define	TWENTYFIVE_MEG	(25 * MEG)
#define	FORTY_MEG	(40 * MEG)
#define	FAS_FREQ_SLOP	(25000)

/*
 * wide	support
 */
#define	FAS_XFER_WIDTH	1

#define	FAS_EMPTY_CALLBACKQ(fas)  fas_empty_callbackQ(fas)

#define	FAS_CHECK_WAITQ_AND_FAS_MUTEX_EXIT(fas)	\
	mutex_enter(&fas->f_waitQ_mutex); \
	if (fas->f_waitf) { \
		fas_empty_waitQ(fas); \
	} \
	mutex_exit(FAS_MUTEX(fas)); \
	mutex_exit(&fas->f_waitQ_mutex);

/*
 * flags for fas_accept_pkt
 */
#define	NO_TRAN_BUSY	0	/* fas_accept_pkt may not bounce these pkts */
#define	TRAN_BUSY_OK	1	/* fas_accept_pkt may bounce these pkts */

/*
 * reset delay tick
 */
#define	FAS_WATCH_RESET_DELAY_TICK 50	/* specified in	milli seconds */

/*
 * 2 ms timeout on receiving tag on reconnect
 */
#define	RECONNECT_TAG_RCV_TIMEOUT 2000	/* allow up to 2 ms */


/*
 * auto	request	sense
 */
#define	RQ_MAKECOM_COMMON(pktp,	flag, cmd)   \
	(pktp)->pkt_flags = (flag), \
	((union	scsi_cdb *)(pktp)->pkt_cdbp)->scc_cmd =	(cmd), \
	((union	scsi_cdb *)(pktp)->pkt_cdbp)->scc_lun =	\
	    (pktp)->pkt_address.a_lun

#define	RQ_MAKECOM_G0(pktp, flag, cmd, addr, cnt)    \
	RQ_MAKECOM_COMMON((pktp), (flag), (cmd)), \
	FORMG0ADDR(((union scsi_cdb *)(pktp)->pkt_cdbp), (addr)), \
	FORMG0COUNT(((union scsi_cdb *)(pktp)->pkt_cdbp), (cnt))

#define	NEW_TIMEOUT	1

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_FASVAR_H */
