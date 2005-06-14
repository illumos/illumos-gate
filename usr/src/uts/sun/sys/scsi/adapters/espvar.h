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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_SCSI_ADAPTERS_ESPVAR_H
#define	_SYS_SCSI_ADAPTERS_ESPVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/note.h>

/*
 * Emulex ESP (Enhanced Scsi Processor) Definitions,
 * Software && Hardware.
 */

/*
 * General SCSI includes
 */
#include <sys/scsi/scsi.h>


/*
 * Include hardware definitions for the ESP generation chips.
 */
#include <sys/scsi/adapters/espreg.h>
#include <sys/scsi/adapters/espcmd.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Compile options
 */
#if DEBUG

#define	ESPDEBUG		/* turn on debugging code */
#define	ESPTEST

#ifdef ESPTEST
#define	ESP_TEST_PARITY		/* turn on parity test code */
#define	ESP_TEST_ABORT		/* turn on abort test code */
#define	ESP_TEST_RESET		/* turn on device reset code */
#define	ESP_TEST_TIMEOUT	/* turn on timeout test code */
#define	ESP_TEST_BUS_RESET	/* turn on bus reset code */
#define	ESP_TEST_RQSENSE	/* test rqsense with renegotiation */
#define	ESP_NEW_HW_DEBUG	/* turn on debug code for new h/w */
#define	ESP_TEST_UNTAGGED	/* turn on untagged/tagged mix test */
#endif /* ESPTEST */

#endif /* DEBUG */

/*
 * Software Definitions
 */

#define	POLL_TIMEOUT		(2 * SCSI_POLL_TIMEOUT * 1000000)
#define	SHORT_POLL_TIMEOUT	(1000000) /* in usec, about 1 secs */
#define	ESP_MUTEX		(&esp->e_mutex)
#define	ESP_INIT_SOFT_STATE	5

/*
 * Data Structure for this Host Adapter.
 */


/*
 * Tag lookup array structure
 */
struct t_slots {
	short			e_dups;
	uchar_t			e_tags;
	int			e_timeout;
	int			e_timebase;
	struct esp_cmd 	*t_slot[NTAGS];
};


/*
 * this structure collects all info about a callback thread; this
 * thread may be shared between a number of esps
 */
struct callback_info {
	struct callback_info	*c_next;
	struct esp_cmd		*c_qf;
	struct esp_cmd		*c_qb;
	kmutex_t		c_mutex;
	kcondvar_t		c_cv;
	kthread_t		*c_thread;
	uint_t			c_qlen;
	uchar_t			c_id;
	uchar_t			c_cb_now_qlen;
	uchar_t			c_spawned;
	uchar_t			c_count;
	uchar_t			c_signal_needed;
	uchar_t			c_exit;		/* terminate this thread */
	kcondvar_t		c_cvd;		/* terminate cv */
};

_NOTE(MUTEX_PROTECTS_DATA(callback_info::c_mutex, callback_info))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", callback_info::c_next))

#define	N_SLOTS			(NTARGETS*NLUNS_PER_TARGET)


/*
 * HBA interface macros
 */
#define	SDEV2TRAN(sd)		((sd)->sd_address.a_hba_tran)
#define	SDEV2ADDR(sd)		(&((sd)->sd_address))
#define	PKT2TRAN(pkt)		((pkt)->pkt_address.a_hba_tran)
#define	ADDR2TRAN(ap)		((ap)->a_hba_tran)

#define	TRAN2ESP(tran)		((struct esp *)(tran)->tran_hba_private)
#define	SDEV2ESP(sd)		(TRAN2ESP(SDEV2TRAN(sd)))
#define	PKT2ESP(pkt)		(TRAN2ESP(PKT2TRAN(pkt)))
#define	ADDR2ESP(ap)		(TRAN2ESP(ADDR2TRAN(ap)))


/*
 * Configuration information for this host adapter
 */
struct esp {

	/*
	 * Transport structure for this instance of the hba
	 */
	scsi_hba_tran_t	*e_tran;

	/*
	 * dev_info_t reference
	 */
	dev_info_t	*e_dev;

	/*
	 * mutex
	 */
	kmutex_t	e_mutex;

	/*
	 * Interrupt block cookie
	 */
	ddi_iblock_cookie_t	e_iblock;

	/*
	 * Next in a linked list of host adapters
	 */

	struct esp	*e_next;

	/*
	 * Type byte for this host adapter (53C90, 53C90A, ESP-236),
	 * part unique id code, and rev of the dma engine
	 */
	uchar_t		e_type;
	uchar_t		e_idcode;
	uchar_t		e_dma_rev;

	/*
	 * value for configuration register 1.
	 * Also contains Initiator Id.
	 */
	uchar_t		e_espconf;

	/*
	 * value for configuration register 2 (ESP100A)
	 */
	uchar_t		e_espconf2;

	/*
	 * value for configuration register 3 (ESP236/FAS)
	 */
	uchar_t		e_espconf3[NTARGETS];
	uchar_t		e_espconf3_fastscsi;
	uchar_t		e_espconf3_last;

	/*
	 * clock conversion register value for this host adapter.
	 * clock cycle value * 1000 for this host adapter,
	 * to retain 5 significant digits.
	 */
	uchar_t		e_clock_conv;
	ushort_t	e_clock_cycle;

	/*
	 * selection timeout register value
	 */
	uchar_t		e_stval;

	/*
	 * State of the host adapter
	 */
	uchar_t	e_sdtr;		/* Count of sync data negotiation messages: */
				/* zeroed for every selection attempt, */
				/* every reconnection, and every disconnect */
				/* interrupt. Each SYNCHRONOUS DATA TRANSFER */
				/* message, both coming from the target, and */
				/* sent to the target, causes this tag to be */
				/* incremented. This allows the received */
				/* message handling to determine whether */
				/* a received SYNCHRONOUS DATA TRANSFER */
				/* message is in response to one that we */
				/* sent. */
	uchar_t	e_stat;		/* soft copy of status register */
	uchar_t	e_intr;		/* soft copy of interrupt register */
	uchar_t	e_step;		/* soft copy of step register */
	uchar_t	e_abort;	/* indicates that an abort message went out */
	uchar_t	e_reset;	/* indicates that a device reset message */
				/* went out */
	uchar_t	e_last_cmd;	/* last cmd sent to esp chip */

	ushort_t e_state;	/* state of the driver */
	ushort_t e_laststate;	/* last state of the driver */
	uchar_t e_suspended;	/* true if driver is suspended */

	/*
	 * Message handling: enough space is reserved for the expected length
	 * of all messages we could either send or receive.
	 *
	 * For sending, we expect to send only SYNCHRONOUS extended messages
	 * (5 bytes). We keep a history of the last message sent, and in order
	 * to control which message to send, an output message length is set
	 * to indicate whether and how much of the message area is to be used
	 * in sending a message. If a target shifts to message out phase
	 * unexpectedly, the default action will be to send a MSG_NOP message.
	 *
	 * After the successful transmission of a message, the initial message
	 * byte is moved to the e_last_msgout area for tracking what was the
	 * last message sent.
	 */

#define	OMSGSIZE	12
	uchar_t		e_cur_msgout[OMSGSIZE];
	uchar_t		e_last_msgout;
	uchar_t		e_omsglen;


	/*
	 * We expect, at, most, to receive a maximum of 7 bytes
	 * of an incoming extended message (MODIFY DATA POINTER),
	 * and thus reserve enough space for that.
	 */
#define	IMSGSIZE	8
	uchar_t		e_imsgarea[IMSGSIZE];

	/*
	 * These are used to index how far we've
	 * gone in receiving incoming  messages.
	 */
	uchar_t		e_imsglen;
	uchar_t		e_imsgindex;

	/*
	 * Saved last msgin.
	 */
	uchar_t		e_last_msgin;

	/*
	 * Target information
	 *	Synchronous SCSI Information,
	 *	Disconnect/reconnect capabilities
	 *	Noise Susceptibility
	 */
	uchar_t	e_offset[NTARGETS];	/* synchronous offset */
	uchar_t	e_period[NTARGETS];	/* synchronous periods */
	uchar_t	e_neg_period[NTARGETS]; /* synchronous periods (negotiated) */
	uchar_t	e_backoff[NTARGETS];	/* synchronous period compensation */
					/* 0: no backoff 1: do backoff now */
					/* 2: no backoff now but goto async */
					/* on next failure */
	uchar_t	e_default_period[NTARGETS]; /* default sync period */
	uchar_t	e_req_ack_delay;	/* req ack delay in offset reg */
	uchar_t	e_offset_last;		/* save last offset value */
	uchar_t	e_period_last;		/* save last period value */

	/*
	 * This uchar_t is a bit map for targets
	 * whose SYNC capabilities are known.
	 */
	uchar_t		e_sync_known;

	/*
	 * This uchar_t is a bit map for targets
	 * for disabling sync on request from
	 * target driver setcap
	 */
	uchar_t		e_force_async;

	/*
	 * This uchar_t is a bit map for targets who
	 * don't appear to be able to disconnect.
	 */
	uchar_t		e_nodisc;

	/*
	 * This uchar_t is a bit map for targets
	 * who seem to be susceptible to noise.
	 */
	uchar_t		e_weak;

	/*
	 * This byte is a bit map for targets who don't appear
	 * to be able to support tagged commands.
	 */
	uchar_t		e_notag;

	/*
	 * scsi options, scsi_tag_age_limit  per esp
	 */
	uchar_t		e_target_scsi_options_defined;

	uchar_t		e_polled_intr;	/* current interrupt was polled. */

	/*
	 * This ushort_t is a bit map for targets who need to have
	 * their properties update deferred.
	 */
	ushort_t	e_props_update;

	int		e_scsi_options;
	int		e_target_scsi_options[NTARGETS];
	int		e_scsi_tag_age_limit;

	/*
	 * various chip and system idiosyncracies
	 */
	uint_t		e_options;

	/*
	 * scsi reset delay per esp
	 */
	uint_t		e_scsi_reset_delay;

	/*
	 * Scratch Buffer, allocated out of iopbmap for commands
	 * The same size as the ESP's fifo.
	 */
	volatile uchar_t *e_cmdarea;

	/*
	 * shadow copy of dmaga_csr to avoid unnecessary I/O reads which are
	 * expensive
	 */
	uint32_t	e_dmaga_csr;

	/*
	 * Scratch Buffer DMA cookie
	 */
	ddi_dma_cookie_t	e_dmacookie;
	ddi_dma_handle_t	e_dmahandle;

	/*
	 * dma attrs for esp
	 */
	ddi_dma_attr_t		*e_dma_attr;

	/*
	 * Instrumentation
	 */
	short	e_ncmds;	/* number of commands stored here at present */
	short	e_ndisc;	/* number of disconnected cmds at present */

	/*
	 * Hardware pointers
	 *
	 * Pointer to mapped in ESP registers
	 */
	volatile struct espreg *e_reg;

	/*
	 * Pointer to mapped in DMA Gate Array registers
	 */

	volatile struct dmaga  *e_dma;

	/*
	 * last and current state, queues
	 */
	uint32_t		e_lastdma;	/* last dma address */
	uint32_t		e_lastcount;	/* last dma count */
	uint32_t		e_esc_read_count; /* read count for cmdarea */
	uchar_t			e_dslot;	/* delta to next slot */
	short			e_last_slot;	/* last active target/lun */
	short			e_cur_slot;	/* current active target/lun */
	short			e_next_slot;	/* round robin scheduling */

	struct esp_cmd		*e_slots[N_SLOTS];

	struct esp_cmd		*e_readyf[N_SLOTS];
	struct esp_cmd		*e_readyb[N_SLOTS];

	struct t_slots		*e_tagQ[N_SLOTS];

				/*
				 * if throttle >= 0 then
				 * continue submitting cmds
				 * if throttle == 0 then hold cmds
				 * if throttle < 0 then drain
				 */
	short			e_throttle[N_SLOTS];
	short			e_tcmds[N_SLOTS];

				/*
				 * if a device reset has been performed, a
				 * delay is required before accessing the target
				 * again; reset delays are in milli secs
				 * (assuming that reset watchdog runs every
				 * ESP_WATCH_RESET_DELAY_TICK milli secs;
				 * watchdog decrements the reset delay)
				 */
	int			e_reset_delay[NTARGETS];

	struct esp_cmd		*e_arq_pkt[N_SLOTS];
	struct scsi_extended_sense *e_rq_sense_data[N_SLOTS];
	struct esp_cmd		*e_save_pkt[N_SLOTS];

	/*
	 * callback thread info for this esp; the thread may be shared
	 */
	uint_t			e_callback_signal_needed;
	struct callback_info	*e_callback_info;

	/*
	 * a queue for packets in case the esp mutex is locked
	 */
	kmutex_t		e_startQ_mutex;
	struct esp_cmd		*e_startf;
	struct esp_cmd		*e_startb;

	struct kmem_cache	*e_kmem_cache;

	/*
	 * list of reset notification requests
	 */
	struct scsi_reset_notify_entry   *e_reset_notify_listf;

	/*
	 * QFULL handling related timeouts and limits.
	 */
	timeout_id_t	e_restart_cmd_timeid;
	uchar_t	e_qfull_retries[NTARGETS];
	ushort_t e_qfull_retry_interval[NTARGETS];

	/*
	 * data access handle for register mapping
	 */
	ddi_acc_handle_t	e_regs_acc_handle;
	/*
	 * data access handle for cmdarea
	 */
	ddi_acc_handle_t	e_cmdarea_acc_handle;

	/*
	 * state flags
	 */
	int	e_flags;
	/*
	 * Interrupt kstat
	 */
	struct kstat		*e_intr_kstat;

#ifdef ESP_KSTATS
	/*
	 * stats per slot
	 */
	struct	kstat		*e_slot_stats[N_SLOTS];

	/*
	 * scsi bus statistics
	 */
	struct	kstat		*e_scsi_bus_stats;
#endif

#define	NPHASE 16
#ifdef	ESPDEBUG
	/*
	 * SCSI analyzer function data structures.
	 */
	int	e_xfer;				/* size of current transfer */
	short	e_phase_index;			/* next entry in table */
	struct	scsi_phases {			/* SCSI analyzer structure */
		short	e_save_state;
		short	e_save_stat;
		int	e_val1, e_val2;
		int	e_reserved;
	} e_phase[NPHASE];
#endif	/* ESPDEBUG */
};

_NOTE(MUTEX_PROTECTS_DATA(esp::e_mutex, esp))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", \
	esp::e_next esp::e_callback_info esp::e_state esp::e_nodisc))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
	esp::e_callback_signal_needed))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
	esp::e_dma esp::e_dma_attr esp::e_dma_rev))
_NOTE(SCHEME_PROTECTS_DATA("stable data",
	esp::e_target_scsi_options esp::e_scsi_options))
_NOTE(SCHEME_PROTECTS_DATA("protected by kmem lock", esp::e_kmem_cache))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
	esp::e_notag esp::e_suspended esp::e_ndisc))
_NOTE(SCHEME_PROTECTS_DATA("stable data", esp::e_dev esp::e_tran))
_NOTE(MUTEX_PROTECTS_DATA(esp::e_startQ_mutex, esp::e_startf esp::e_startb))
_NOTE(DATA_READABLE_WITHOUT_LOCK(esp::e_flags))

/*
 * e_req_ack_delay:
 * the values for req/ack delay have been emperically determined; a value
 * of 0x20 for 101 was found to be preferable but this caused "illegal
 * cmd interrupt" when a xfer > 64K was broken up (we were still using
 * the 16 bit counter) in data phase; after restarting the xfer, the esp
 * immediately returned "illegal cmd" because it is not legal to give a
 * cmd while ACK is left asserted; it is not known yet why ACK is left
 * asserted if this delay is 0x20; anyway, emulex now recommends 0x50
 * The sunergy macio chip has more problems than the c2 with the value 0x20.
 */
#define	DEFAULT_REQ_ACK_DELAY_101 0x50	/* delay assert period by 1/2 cycle */
#define	DEFAULT_REQ_ACK_DELAY_236 0x10	/* delay assert period by 1/2 cycle */

/*
 * define for e_options
 */
#define	ESP_OPT_SBUS_RERUNS	0x0001	/* ESC has rerun problem */
#define	ESP_OPT_FAS		0x0002	/* FAS type */
#define	ESP_OPT_DMA_OUT_TAG	0x0004	/* can dma out tags */
#define	ESP_OPT_MASK_OFF_STAT	0x0008	/* mask off status reserved bit */
#define	ESP_OPT_DIFFERENTIAL	0x0010	/* differential scsi */
#define	ESP_OPT_STACKED_CMDS	0x0020	/* use stacked cmd for MSG_ACPT */
#define	ESP_OPT_ACCEPT_STEP567	0x0040	/* step register may report 5,6,7 */
					/* instead of 4 */
#define	ESP_OPT_SLOW_FIFO_FLUSH	0x0080	/* wait for fifo empty after flush */

/*
 * define for e_flags
 */
#define	ESP_FLG_NOTIMEOUTS	0x0001	/* disallow timeout rescheduling */

#define	ESP_CAN_SCHED	((esp->e_flags & ESP_FLG_NOTIMEOUTS) == 0)

#ifdef	ESPDEBUG
/*
 * Log state and phase history of activity
 */
#define	LOG_STATE(esp, arg0, arg1, arg2, arg3) { \
	esp->e_phase[esp->e_phase_index].e_save_state = arg0; \
	esp->e_phase[esp->e_phase_index].e_save_stat = arg1; \
	esp->e_phase[esp->e_phase_index].e_val1 = arg2; \
	esp->e_phase[esp->e_phase_index].e_val2 = arg3; \
	esp->e_phase[esp->e_phase_index].e_reserved = 0xbadfeed; \
	esp->e_phase_index = (++esp->e_phase_index) & (NPHASE-1); \
};
#else	/* ESPDEBUG */
#define	LOG_STATE(esp, arg0, arg1, arg2, arg3) {};
#endif	/* ESPDEBUG */

/*
 * Representations of Driver states (stored in tags e_state && e_laststate).
 */

/*
 * Totally idle. There may or may not disconnected commands still
 * running on targets.
 */

#define	STATE_FREE	0x00

/*
 * Selecting States. These states represent a selection attempt
 * for a target.
 */

#define	STATE_SELECT_NORMAL	0x0100
#define	STATE_SELECT_N_STOP	0x0200
#define	STATE_SELECT_N_SENDMSG	0x0400
#define	STATE_SYNC_ASKING	0x0800
#define	STATE_SELECT_N_TAG	0x1000
#define	STATE_SELECTING		0xFF00	/* Select mask */


/*
 * When the driver is neither idle nor selecting, it is in one of
 * the information transfer phases. These states are not unique
 * bit patterns- they are simple numbers used to mark transitions.
 * They must start at 1 and proceed sequentially upwards and
 * match the indexing of function vectors declared in the function
 * esp_phasemanage().
 */

#define	STATE_ITPHASES		0x00FF	/* Phase mask */

/*
 * These states cover finishing sending a command out (if it wasn't
 * sent as a side-effect of selecting), or the case of starting
 * a command that was linked to the previous command (i.e., no
 * selection phase for this particular command as the target
 * remained connected when the previous command completed).
 */

#define	ACTS_CMD_START		0x01
#define	ACTS_CMD_DONE		0x02

/*
 * These states are the begin and end of sending out a message.
 * The message to be sent is stored in the field e_msgout (see above).
 */

#define	ACTS_MSG_OUT		0x03
#define	ACTS_MSG_OUT_DONE	0x04

/*
 * These states are the beginning, middle, and end of incoming messages.
 *
 */

#define	ACTS_MSG_IN		0x05
#define	ACTS_MSG_IN_MORE	0x06
#define	ACTS_MSG_IN_DONE	0x07


/*
 * This state is reached when the target may be getting
 * ready to clear the bus (disconnect or command complete).
 */

#define	ACTS_CLEARING		0x08


/*
 * These states elide the begin and end of a DATA phase
 */

#define	ACTS_DATA		0x09
#define	ACTS_DATA_DONE		0x0A

/*
 * This state indicates that we were in status phase. We handle status
 * phase by issuing the ESP command 'CMD_COMP_SEQ' which causes the
 * ESP to read the status byte, and then to read a message in (presumably
 * one of COMMAND COMPLETE, LINKED COMMAND COMPLETE or LINKED COMMAND
 * COMPLETE WITH FLAG).
 *
 * This state is what is expected to follow after the issuance of the
 * ESP command 'CMD_COMP_SEQ'.
 */

#define	ACTS_C_CMPLT		0x0B

/*
 * This state is used by the driver to indicate that it
 * is in the middle of processing a reselection attempt.
 */

#define	ACTS_RESEL		0x0C

/*
 * Hiwater mark of vectored states
 */

#define	ACTS_ENDVEC		0x0C

/*
 * This state is used by the driver to indicate that it doesn't know
 * what the next state is, and that it should look at the ESP's status
 * register to find out what SCSI bus phase we are in in order to select
 * the next state to transition to.
 */

#define	ACTS_UNKNOWN		0x1A

/*
 * This state is used by the driver to indicate that a self-inititated
 * Bus reset is in progress.
 */

#define	ACTS_RESET		0x1C


/*
 * This state is used by the driver to indicate to itself that it is
 * in the middle of aborting things.
 */

#define	ACTS_ABORTING		0x1D

/*
 * This state is used by the driver to indicate to itself that it is
 * in the middle of spanning a target driver completion call.
 */

#define	ACTS_SPANNING		0x1E

/*
 * This state is used by the driver to just hold the state of
 * the softc structure while it is either aborting or resetting
 * everything.
 */

#define	ACTS_FROZEN		0x1F


/*
 * These additional states are only used by the scsi bus analyzer.
 */
#define	ACTS_PREEMPTED		0x21
#define	ACTS_PROXY		0x22
#define	ACTS_SYNCHOUT		0x23
#define	ACTS_CMD_LOST		0x24
#define	ACTS_DATAOUT		0x25
#define	ACTS_DATAIN		0x26
#define	ACTS_STATUS		0x27
#define	ACTS_DISCONNECT		0x28
#define	ACTS_NOP		0x29
#define	ACTS_REJECT		0x2A
#define	ACTS_RESTOREDP		0x2B
#define	ACTS_SAVEDP		0x2C
#define	ACTS_BAD_RESEL		0x2D
#define	ACTS_LOG		0x0F
#define	ACTS_SELECT		0x2E	   /* ACTS_FREE too */
#define	ACTS_TAG		0x2F
#define	ACTS_CMD		0x30

#define	ACTS_NEW_STATE		0x40
#define	ACTS_ESP_CMD		0x41

/*
 * Interrupt dispatch actions
 */

#define	ACTION_RETURN		-1	/* return from interrupt */
#define	ACTION_FINSEL		0	/* finish selection */
#define	ACTION_RESEL		1	/* handle reselection */
#define	ACTION_PHASEMANAGE	2	/* manage phases */
#define	ACTION_FINISH		3	/* this command done */
#define	ACTION_FINRST		4	/* finish reset recovery */
#define	ACTION_SEARCH		5	/* search for new command to start */
#define	ACTION_ABORT_CURCMD	6	/* abort current command */
#define	ACTION_ABORT_ALLCMDS	7	/* abort all commands */
#define	ACTION_RESET		8	/* reset bus */
#define	ACTION_SELECT		9	/* handle selection */

/*
 * Proxy command definitions.
 *
 * At certain times, we need to run a proxy command for a target
 * (if only to select a target and send a message).
 *
 * We use the tail end of the cdb that is internal to the esp_cmd
 * structure to store the proxy code, the proxy data (e.g., the
 * message to send).
 *
 * We also store a boolean result code in this area so that the
 * user of a proxy command knows whether it succeeded.
 */

/*
 * Offsets into the cmd_db[] array for proxy data
 */

#define	ESP_PROXY_TYPE		CDB_GROUP0
#define	ESP_PROXY_RESULT	ESP_PROXY_TYPE+1
#define	ESP_PROXY_DATA		ESP_PROXY_RESULT+1

/*
 * Currently supported proxy types
 */

#define	ESP_PROXY_SNDMSG	1

/*
 * Reset actions
 */

#define	ESP_RESET_ESP		0x1	/* reset ESP chip */
#define	ESP_RESET_DMA		0x2	/* reset DMA gate array */
#define	ESP_RESET_BRESET	0x4	/* reset SCSI bus */
#define	ESP_RESET_SCSIBUS	(ESP_RESET_BRESET)
#define	ESP_RESET_SOFTC		0x10	/* reset SOFTC structure */

#define	ESP_RESET_HW		(ESP_RESET_ESP|ESP_RESET_DMA|ESP_RESET_SCSIBUS)
#define	ESP_RESET_ALL		(ESP_RESET_HW|ESP_RESET_SOFTC)

#define	ESP_RESET_MSG		0x20

/*
 * Debugging macros and defines
 */

#ifdef	ESPDEBUG

#define	INFORMATIVE	(espdebug)
#define	DEBUGGING	(espdebug > 1)

#define	EPRINTF(str)		if (espdebug > 1) eprintf(esp, str)
#define	EPRINTF1(str, a)	if (espdebug > 1) eprintf(esp, str, a)
#define	EPRINTF2(str, a, b)	if (espdebug > 1) eprintf(esp, str, a, b)
#define	EPRINTF3(str, a, b, c)	if (espdebug > 1) eprintf(esp, str, a, b, c)
#define	EPRINTF4(str, a, b, c, d)	\
	if (espdebug > 1) eprintf(esp, str, a, b, c, d)
#define	EPRINTF5(str, a, b, c, d, e)	\
	if (espdebug > 1) eprintf(esp, str, a, b, c, d, e)
#define	EPRINTF6(str, a, b, c, d, e, f)	\
	if (espdebug > 1) eprintf(esp, str, a, b, c, d, e, f)

#define	IPRINTF(str)		if (espdebug) eprintf(esp, str)
#define	IPRINTF1(str, a)	if (espdebug) eprintf(esp, str, a)
#define	IPRINTF2(str, a, b)	if (espdebug) eprintf(esp, str, a, b)
#define	IPRINTF3(str, a, b, c)	if (espdebug) eprintf(esp, str, a, b, c)
#define	IPRINTF4(str, a, b, c, d)	\
	if (espdebug) eprintf(esp, str, a, b, c, d)
#define	IPRINTF5(str, a, b, c, d, e)	\
	if (espdebug) eprintf(esp, str, a, b, c, d, e)
#define	IPRINTF6(str, a, b, c, d, e, f) \
	if (espdebug) eprintf(esp, str, a, b, c, d, e, f)

#else	/* ESPDEBUG */

#define	EPRINTF(str)
#define	EPRINTF1(str, a)
#define	EPRINTF2(str, a, b)
#define	EPRINTF3(str, a, b, c)
#define	EPRINTF4(str, a, b, c, d)
#define	EPRINTF5(str, a, b, c, d, e)
#define	EPRINTF6(str, a, b, c, d, e, f)
#define	IPRINTF(str)
#define	IPRINTF1(str, a)
#define	IPRINTF2(str, a, b)
#define	IPRINTF3(str, a, b, c)
#define	IPRINTF4(str, a, b, c, d)
#define	IPRINTF5(str, a, b, c, d, e)
#define	IPRINTF6(str, a, b, c, d, e, f)

#endif	/* ESPDEBUG */

/*
 * Shorthand macros and defines
 */

/*
 * Short hand defines
 */

#define	SAME_CMD	0
#define	INT_CMD		1
#define	NEW_CMD		2


#define	CLEAR_THROTTLE	512
#define	HOLD_THROTTLE	0
#define	DRAIN_THROTTLE	-1
#define	QFULL_THROTTLE	-2

#define	PAD_LIMIT	1025

#define	NODISC(tgt)		(esp->e_nodisc & (1<<(tgt)))
#define	NOTAG(tgt)		(esp->e_notag & (1<<(tgt)))
#define	TAGGED(tgt)		((esp->e_notag & (1<<(tgt))) == 0)
#define	SYNC_KNOWN(tgt)		(esp->e_sync_known & (1<<(tgt)))
#define	CURRENT_CMD(esp)	((esp)->e_slots[(esp)->e_cur_slot])

#define	SLOT(sp)		((short)(Tgt((sp)) * NLUNS_PER_TARGET|\
				    (Lun((sp)))))
#define	NEXTSLOT(slot, d)	((slot)+(d)) & ((N_SLOTS)-1)
#define	FIFO_CNT(ep)		((ep)->esp_fifo_flag & 0x1f)
#define	MY_ID(esp)		((esp)->e_espconf & ESP_CONF_BUSID)
#define	INTPENDING(esp)		((esp)->e_dma->dmaga_csr&DMAGA_INT_MASK)

#define	Tgt(sp) ((sp)->cmd_pkt.pkt_address.a_target)
#define	Lun(sp) ((sp)->cmd_pkt.pkt_address.a_lun)

#ifdef ESP_KSTATS
#define	IOSP(slot)	(KSTAT_IO_PTR(esp->e_slot_stats[slot]))
#define	IOSP_SCSI_BUS	(KSTAT_IO_PTR(esp->e_scsi_bus_stats))

#define	ESP_KSTAT_SCSI_BUS(esp) \
	if (esp_do_bus_kstats) { \
		if (esp->e_laststate == STATE_FREE && \
		    esp->e_state != STATE_FREE) { \
			if (esp->e_scsi_bus_stats) { \
				kstat_runq_enter(IOSP_SCSI_BUS); \
			} \
		} else if (esp->e_laststate != STATE_FREE && \
		    esp->e_state == STATE_FREE) { \
			if (esp->e_scsi_bus_stats) { \
				kstat_runq_exit(IOSP_SCSI_BUS); \
			} \
		} \
	}

#define	New_state(esp, state)\
	(esp)->e_laststate = (esp)->e_state, (esp)->e_state = (state); \
	ESP_KSTAT_SCSI_BUS(esp)
#else
#define	New_state(esp, state)\
	(esp)->e_laststate = (esp)->e_state, (esp)->e_state = (state)
#endif

#define	ESP_KSTAT_INTR(esp)  KSTAT_INTR_PTR(esp->e_intr_kstat)->\
				intrs[KSTAT_INTR_HARD]++

#define	Esp_cmd(esp, cmd)\
	(esp)->e_reg->esp_cmd = (cmd), (esp)->e_last_cmd = (cmd)

#define	ESP_PREEMPT(esp)	\
	New_state((esp), STATE_FREE); (esp)->e_last_slot = (esp)->e_cur_slot, \
	(esp)->e_cur_slot = UNDEFINED

#define	CNUM		(ddi_get_instance(esp->e_dev))
#define	TRUE		1
#define	FALSE		0
#define	UNDEFINED	-1
#define	INVALID_MSG	0x7f


#define	ESP_DMAGA_REV(esp)	(esp)->e_dma_rev

/*
 * Some manifest miscellaneous constants
 */

#define	MEG		(1000 * 1000)
#define	FIVE_MEG	(5 * MEG)
#define	TEN_MEG		(10 * MEG)
#define	TWENTY_MEG	(20 * MEG)
#define	TWENTYFIVE_MEG	(25 * MEG)
#define	FORTY_MEG	(40 * MEG)
#define	ESP_FREQ_SLOP	(25000)

/*
 * DMA macros; we use a shadow copy of the dmaga_csr to save unnecessary
 * reads
 */
#define	ESP_DMA_WRITE(esp, count, base) { \
	register volatile struct espreg *ep = esp->e_reg; \
	register volatile struct dmaga *dmar = esp->e_dma; \
	SET_ESP_COUNT(ep, count); \
	esp->e_dmaga_csr |= DMAGA_WRITE | DMAGA_ENDVMA; \
	dmar->dmaga_csr = esp->e_dmaga_csr; \
	if (ESP_DMAGA_REV(esp) == ESC1_REV1) { \
		SET_DMAESC_COUNT(dmar, count); \
	} \
	dmar->dmaga_addr = esp->e_lastdma = base; \
}

#define	ESP_DMA_READ(esp, count, base) { \
	register volatile struct espreg *ep = esp->e_reg; \
	register volatile struct dmaga *dmar = esp->e_dma; \
	SET_ESP_COUNT(ep, count); \
	esp->e_dmaga_csr |= \
	    (esp->e_dmaga_csr & ~DMAGA_WRITE) | DMAGA_ENDVMA; \
	dmar->dmaga_csr = esp->e_dmaga_csr; \
	dmar->dmaga_addr = esp->e_lastdma = base; \
}

#define	ESP_SET_ESC_READ_COUNT(esp, count, base) { \
	if ((esp->e_options & ESP_OPT_SBUS_RERUNS) && \
		(((base + count) & (MMU_PAGESIZE-1)) != 0)) { \
		register uint_t addr1 = (uint_t)base; \
		register uint_t addr2 = (uint_t) \
		    (base + count + MMU_PAGESIZE) & (~(MMU_PAGESIZE-1)); \
		register uint_t spec_count = (uint_t)(addr2 - addr1); \
		    SET_DMAESC_COUNT(esp->e_dma, spec_count); \
	} else \
		SET_DMAESC_COUNT(esp->e_dma, count); \
}


/*
 * For DMA gate arrays, the PACKCNT field of the DMA
 * CSR register indicates how many bytes are still
 * latched up and need to be drained to memory.
 *
 * For the DMA+ CSR, the PACKCNT field will either
 * be zero or non-zero, indicating a empty/non-empty
 * D_CACHE. The DRAIN bit has no effect.
 *
 * DON'T flush the dma if there is a dma request pending; this could
 * cause an abandonned rerun read which would hang the xbox
 */
#define	DMA_DRAIN_TIMEOUT (200*100)

#define	ESP_FLUSH_DMA(esp) \
	if (esp->e_dmaga_csr & DMAGA_REQPEND) { \
		while (esp->e_dma->dmaga_csr & DMAGA_REQPEND); \
	} \
	esp->e_dmaga_csr |= DMAGA_FLUSH; \
	esp->e_dmaga_csr &=  \
	    ~(DMAGA_ENDVMA | DMAGA_WRITE | DMAGA_ENATC); \
	esp->e_dma->dmaga_csr = esp->e_dmaga_csr; \
	esp->e_dmaga_csr &= ~DMAGA_FLUSH; \

#define	ESP_DRAIN_DMA(esp)  { \
	int i = 0; \
	register volatile struct dmaga *dmap = esp->e_dma; \
	if (DMAGA_NPACKED(dmap)) { \
		if ((ESP_DMAGA_REV(esp) != ESC1_REV1) && \
		    (ESP_DMAGA_REV(esp) != DMA_REV3)) { \
			esp->e_dmaga_csr |= DMAGA_DRAIN; \
			dmap->dmaga_csr = esp->e_dmaga_csr; \
			esp->e_dmaga_csr &= ~DMAGA_DRAIN; \
		} \
		EPRINTF("draining dma\n"); \
		for (i = 0; i < DMA_DRAIN_TIMEOUT; i++) { \
			drv_usecwait(1); \
			if (DMAGA_NPACKED(dmap) == 0) \
				break; \
		} \
	} \
	if ((i >= DMA_DRAIN_TIMEOUT) && (DMAGA_NPACKED(dmap))) { \
		esplog(esp, CE_WARN, "dma did not drain\n"); \
		return (ACTION_RESET); \
	} \
	ESP_FLUSH_DMA(esp); \
}

#define	esp_chip_disconnect(esp, sp) \
{ \
	if (esp->e_ndisc) \
		Esp_cmd(esp, CMD_EN_RESEL); \
	if (esp->e_cur_slot != UNDEFINED && sp) { \
		if ((sp->cmd_pkt.pkt_flags & FLAG_NOPARITY) && \
		    (esp->e_target_scsi_options[Tgt(sp)] & \
			SCSI_OPTIONS_PARITY)) { \
			esp->e_reg->esp_conf = esp->e_espconf; \
		} \
	} \
	esp->e_sdtr = 0; \
}

/*
 * this macro is called without mutex held; there is a race but
 * it is on the safe side
 */
#define	ESP_WAKEUP_CALLBACK_THREAD(esp) \
	{ \
		register struct callback_info *cb_info = \
			esp->e_callback_info; \
		if (esp->e_callback_signal_needed) { \
			esp->e_callback_signal_needed = 0; \
			esp_wakeup_callback_thread(cb_info); \
		} \
	}


#define	ESP_CHECK_STARTQ_AND_ESP_MUTEX_EXIT(esp) \
	mutex_enter(&esp->e_startQ_mutex); \
	if (esp->e_startf) { \
		esp_empty_startQ(esp); \
	} \
	mutex_exit(ESP_MUTEX); \
	mutex_exit(&esp->e_startQ_mutex);

/*
 * flags for _esp_start
 */
#define	NO_TRAN_BUSY	0	/* _esp_start should not bounce these pkts */
#define	TRAN_BUSY_OK	1	/* _esp_start may bounce these pkts */

/*
 * reset delay tick
 */
#define	ESP_WATCH_RESET_DELAY_TICK 50	/* specified in milli seconds */

/*
 * 2 ms timeout on receiving tag on reconnect
 */
#define	RECONNECT_TAG_RCV_TIMEOUT 2000	/* allow up to 2 ms */

/*
 * Default is to have 10 retries on receiving QFULL status and
 * each retry to be after 100 ms.
 */
#define	QFULL_RETRIES		10
#define	QFULL_RETRY_INTERVAL	100

/*
 * auto request sense
 */
#define	RQ_MAKECOM_COMMON(pktp, flag, cmd)   \
	(pktp)->pkt_flags = (flag), \
	((union scsi_cdb *)(pktp)->pkt_cdbp)->scc_cmd = (cmd), \
	((union scsi_cdb *)(pktp)->pkt_cdbp)->scc_lun = \
	    (pktp)->pkt_address.a_lun

#define	RQ_MAKECOM_G0(pktp, flag, cmd, addr, cnt)    \
	RQ_MAKECOM_COMMON((pktp), (flag), (cmd)), \
	FORMG0ADDR(((union scsi_cdb *)(pktp)->pkt_cdbp), (addr)), \
	FORMG0COUNT(((union scsi_cdb *)(pktp)->pkt_cdbp), (cnt))


/*
 * packet completion
 */
#define	MARK_PKT(sp, reason, stat)\
	if (sp->cmd_pkt.pkt_reason == CMD_CMPLT) {\
		sp->cmd_pkt.pkt_reason = reason; \
	} \
	sp->cmd_pkt.pkt_statistics |= stat;


#define	COMPLETE_PKT(sp, reason, stat) \
	MARK_PKT(sp, reason, stat); \
	esp_call_pkt_comp(esp, sp)

#define	NEW_TIMEOUT	1

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_ESPVAR_H */
