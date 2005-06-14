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
 * Copyright (c) 1991-1992, 1997-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_AUDIOVAR_H
#define	_SYS_AUDIOVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The audio driver is divided into generic (device-independent) and
 * device-specific modules.  The generic routines handle most STREAMS
 * protocol issues, communicating with the device-specific code via
 * function callouts and a chained control block structure.
 *
 * Separate control block lists are maintained for reading (record) and
 * writing (play).  These control blocks simulate a chained-DMA
 * structure, in that each block controls the transfer of data between
 * the device and a single contiguous memory segment.
 *
 * The command block contains buffer start and stop addresses, a link
 * address to the next block in the chain, a 'done' flag, a 'skip' flag
 * (indicating that this command block contains no data), and a pointer
 * to the STREAMS data block structure which is private to the generic
 * driver.
 *
 * The device-specific audio driver code is expected to honor the 'skip'
 * flag and set the 'done' flag when it has completed processing the
 * command block (i.e., the data transfer, if any, is complete).  For
 * record command blocks, it is also expected to add to the 'data'
 * pointer the number of bytes successfully read from the device.
 *
 * The device-specific driver module must initialize the static STREAMS
 * control structures and must provide an identify routine (sbus-only),
 * an attach routine, and an open routine.  The open routine verifies the
 * device unit number and calls the generic open routine with the address
 * of the audio_state structure for that unit.
 *
 * The generic audio driver makes calls to the device-specific code
 * through an ops-vector table.  The following routines must be provided:
 *
 * The 'close' routine is called after either the play or record stream
 * is closed.  It may perform device-specific cleanup and initialization.
 *
 * void dev_close(as)
 * 	aud_stream_t		*as;	// Pointer to audio device state
 *
 *
 * The 'ioctl' routine is called from the STREAMS write put procedure
 * when a non-generic ioctl is encountered (AUDIO_SETINFO, AUDIO_GETINFO,
 * and AUDIO_DRAIN are the generic ioctls).  Any required data mblk_t is
 * allocated; its address is given by mp->b_cont (if this is a read/write
 * ioctl, the user-supplied buffer at mp->b_cont is reused).  If data is
 * successfully returned, the iocp->ioc_count field should be set with
 * the number of bytes returned.  If an error occurs, the 'ioctl' routine
 * should set iocp->ioc_error to the appropriate error code.  Otherwise,
 * the returned value should be AUDRETURN_CHANGE if a device state change
 * occurred (in which case a signal is sent to the control device, if
 * any) and AUDRETURN_NOCHANGE if no signal should be sent. If the ioctl
 * can not complete right away, it should return AUDRETURN_DELAYED
 * indicating that it will ack the ioctl at a later time.
 *
 * aud_return_t dev_ioctl(as, mp, iocp)
 * 	aud_stream_t	*as;		// Pointer to audio device state
 * 	mblk_t		*mp;		// ioctl STREAMS message block
 * 	struct iocblk	*iocp;		// M_IOCTL message data
 *
 *
 * The 'start' routine is called to start i/o.  Ordinarily, it is called
 * from the device-specific 'queuecmd' routine, but it is also called
 * when paused output is resumed.
 *
 * void dev_start(as)
 * 	aud_stream_t	*as;		// Pointer to audio device state
 *
 *
 * The 'stop' routine is called to stop i/o.  It is called when i/o is
 * paused, flushed, or the device is closed.  Note that currently queued
 * command blocks should not be flushed by this routine, since i/o may be
 * resumed from the current point.
 *
 * void dev_stop(as)
 * 	aud_stream_t	*as;		// Pointer to audio device state
 *
 *
 * The 'setflag' routine is called to get a single device-specific flag.
 * The flag argument is either AUD_ACTIVE (return the active flag) or
 * AUD_ERRORRESET (zero the error flag, returning its previous value).
 * (The val argument is currently ignored.)
 *
 * void dev_setflag(as, flag, val)
 * 	aud_stream_t	*as;		// Pointer to audio device state
 * 	enum aud_opflag	flag;		// AUD_ACTIVE || AUD_ERRORESET
 *
 *
 * The 'setinfo' routine is called to get or set device-specific fields
 * in the audio state structure.  If mp is NULL, the sample counters and
 * active flags should be set in v.  If mp is not NULL, then
 * mp->b_cont->data points to the audio_info_t structure supplied in an
 * AUDIO_SETINFO ioctl (ip).  All device-specific fields (gains, ports,
 * sample counts) in both v and the device itself should be updated, as
 * long as the corresponding field in ip is not set to AUD_INIT_VALUE.
 * When the sample counters are set, the value returned in v should be
 * the previous value. If the setinfo can not complete right away, it
 * should return AUDRETURN_DELAYED indicating that it will ack the ioctl
 * at a later time. If an error occurs on setinfo, the iocp->ioc_error
 * should be set as in dev_ioctl
 *
 * aud_return_t dev_setinfo(as, mp, iocp)
 * 	aud_stream_t	*as;		// Pointer to audio device state
 * 	mblk_t		*mp;		// user info structure or NULL
 * 	struct iocblk	*iocp;		// M_IOCTL message data
 *
 *
 * The 'queuecmd' routine is called whenever a new command block is
 * linked into the chained command list.  The device-specific code must
 * ensure that the command is enqueued to the device and that i/o, if not
 * currently active, is started.
 *
 * void dev_queuecmd(as, cmdp)
 * 	aud_stream_t	*as;		// Pointer to audio device state
 * 	struct aud_cmd	*cmdp;		// new command block to queue
 *
 *
 * The 'flushcmd' routine is called whenever the chained command list is
 * flushed.  It is only called after i/o has been stopped (via the 'stop'
 * routine) and after the command list in the audio state structure has
 * been cleared.  The device-specific code should flush the device's
 * queued command list.
 *
 * void dev_flushcmd(as)
 * 	aud_stream_t	*as;		// Pointer to audio device state
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Various generic audio driver constants
 */
#define	AUD_INITVALUE	(~0)
#define	Modify(X)	((uint_t)(X) != AUD_INITVALUE)
#define	Modifys(X)	((X) != (ushort_t)AUD_INITVALUE)
#define	Modifyc(X)	((X) != (uchar_t)AUD_INITVALUE)


/*
 * Define the virtual chained-DMA control structure
 */
typedef struct aud_cmd aud_cmd_t;
struct aud_cmd {
	/*
	 * Data pointers
	 */
	uchar_t *data;		/* address of next transfer */
	uchar_t *enddata;	/* address+1 of last transfer */

	/*
	 * Linked list management
	 */
	aud_cmd_t *next;	/* pointer to next or NULL */
	aud_cmd_t *lastfragment; /* last fragment in packet */

	/*
	 * Flags
	 */
	uint_t :0;		/* Force word alignment */
	uchar_t skip;		/* TRUE => no xfers on buffer */
	uchar_t done;		/* TRUE => buffer processed */

	uchar_t iotype;		/* copy of mblk's db_type */
	boolean_t processed;	/* TRUE if processed cmd at head of list */

	audtrace_hdr_t tracehdr; /* trace info */

	/*
	 * Device-independent private, opaque storage
	 */
	void *dihandle;
};


/*
 * Define the list-head for queued control structures
 */
typedef struct aud_cmdlist aud_cmdlist_t;
struct aud_cmdlist {
	aud_cmd_t *head;	/* First queued command block */
	aud_cmd_t *tail;	/* Last queued command block */
	aud_cmd_t *free;	/* Head of free list */
};


/*
 * Define possible return values from the setinfo and ioctl calls
 */
typedef enum {
	AUDRETURN_CHANGE,
	AUDRETURN_NOCHANGE,
	AUDRETURN_DELAYED
} aud_return_t;


/*
 * Define legal values for the 'flag' argument to the 'setflag' callout
 */
enum aud_opflag {
	AUD_ACTIVE,		/* active flag */
	AUD_ERRORRESET		/* error flag (reset after read) */
};


/*
 * The audio stream type determines the legal operations for a stream in the
 * generic portion of an audio driver.
 */
typedef enum {
	AUDTYPE_NONE = 00,	/* Not a legal device */
	AUDTYPE_DATA = 01,	/* Data, IOCTL, etc., but not signals */
	AUDTYPE_CONTROL = 02,	/* IOCTL, etc., but not M_DATA */
	AUDTYPE_BOTH = 03	/* Anything is ok, signals delivered */
} aud_streamtype_t;

#define	ISPLAYSTREAM(as)	(ISDATASTREAM(as) && (as->openflag & FWRITE))
#define	ISRECORDSTREAM(as)	(ISDATASTREAM(as) && (as->openflag & FREAD))
#define	ISDATASTREAM(as)	(((as->type) & (AUDTYPE_DATA)) != 0)
#define	ISCONTROLSTREAM(as)	(((as->type) & (AUDTYPE_CONTROL)) != 0)


typedef enum {
	AUDMODE_NONE = 00,	/* Not a legal mode */
	AUDMODE_AUDIO = 01,	/* Transparent audio mode */
	AUDMODE_HDLC = 02	/* HDLC datacomm mode */
} aud_modetype_t;


/*
 * This structure describes the state of the audio device and queues
 */
typedef struct aud_state aud_state_t;
struct aud_state {
	/*
	 * Back-pointer to the device-dependent audio state
	 */
	void *ddstate;

	/*
	 * Device-independent audio state
	 */
	uint_t monitor_gain;	/* input to output mix: 0 - 255 */
	boolean_t output_muted;	/* true if output is muted */
	uint_t hw_features;	/* hardware features this driver supports */
	uint_t sw_features;	/* software features this driver supports */
	uint_t sw_features_enabled;	/* supported SW features enabled */

	/*
	 * Audio ops vector
	 */
	struct aud_ops *ops;
};

/*
 * STREAMS routines pass the address of a 'struct audstream' when calling
 * put and service procedures.  This structure points to the STREAMS
 * queues and back to the containing 'struct aud_state'.
 */
typedef struct aud_stream aud_stream_t;
struct aud_stream {
	aud_state_t *distate;	/* pointer to driver data */
	aud_streamtype_t type;	/* defines legal operations */
	aud_modetype_t mode;	/* Audio or HDLC data */
	boolean_t signals_okay;	/* Can send sigs up this aud_stream */

	/*
	 * Sideways pointers to related aud_stream_t structures
	 */
	aud_stream_t *control_as; /* control stream */
	aud_stream_t *output_as; /* play stream */
	aud_stream_t *input_as;	/* record stream */

	/*
	 * Software state
	 */
	aud_cmdlist_t cmdlist;	/* command chains */
	audio_prinfo_t info;	/* info for this stream side */
	int openflag;		/* open flag & (FREAD|FWRITE) */
	boolean_t draining;	/* TRUE if output draining */
	int maxfrag_size;	/* max aud_cmd_t fragment size */
	struct {
		int action;		/* IOCTL action */
		mblk_t *mp;		/* Pending ioctl */
		ulong_t priv;		/* private state */
		uint_t ioctl_id;	/* from ioc_id */
		cred_t *credp;		/* from ioc_cr */
		int reason;		/* HW implementation dep. reason */
		boolean_t (*handler)(aud_stream_t *, mblk_t *, int,
		    boolean_t);
	} dioctl;		/* Delayed ioctls */
	uint_t sequence;	/* packet sequence number */

	/*
	 * STREAMS information
	 */
	queue_t *readq;		/* STREAMS read queue */
	queue_t *writeq;	/* STREAMS write queue */
	queue_t *traceq;	/* STREAMS trace queue */

	/*
	 * OS-Dependent information
	 *
	 * NB - For now we lock on a per-unit basis, so this points to
	 * the mutex of the unit it belongs to.  Other arrangements can
	 * be made later
	 *
	 * The condition variable in a output stream is used to wait for
	 * output to drain.
	 *
	 * The condition variable in a control stream is used to wait on
	 * open if the device is in use.
	 */
	kmutex_t *lock;		/* low-level lock */
	kcondvar_t cv;		/* generic condition variable */
};

#define	LOCK_AS(as)	mutex_enter((as)->lock)
#define	UNLOCK_AS(as)	mutex_exit((as)->lock)
#define	ASSERT_ASLOCKED(as) ASSERT(MUTEX_HELD((as)->lock))

#define	AUDIOCACTION_INIT	(0) /* no ioctl in progress */
#define	AUDIOCACTION_WAIT	(1) /* copyout response not received */
#define	AUDIOCACTION_WAITING	(2) /* read to ack/nak */


/*
 * Argument for audio_sensig
 */
typedef enum {
	AUDIO_SENDSIG_NONE = 0,	/* Default */
	AUDIO_SENDSIG_EXPLICIT,	/* Send signal up this aud_stream only */
	AUDIO_SENDSIG_ALL	/* Send signal up all related aud_streams */
} audio_sendsig_t;


/*
 * Define the ops-vector table for device-specific callouts
 *
 * close	close routine
 * ioctl	ioctl routine
 * start	routine to start I/O on a stream
 * stop		routine to stop I/O on a stream
 * setflag	routine to get or set a flag value
 * setinfo	routine to get or set the audio state structure
 * queuecmd	routine to queue a command on the HW command list
 * flushcmd	routine to flush the HW's command list
 */
typedef struct aud_ops	aud_ops_t;
struct aud_ops {
#ifdef __STDC__
	void (*close)(aud_stream_t *);
	aud_return_t (*ioctl)(aud_stream_t *, queue_t *, mblk_t *);
	aud_return_t (*mproto)(aud_stream_t *, mblk_t *);
	void (*start)(aud_stream_t *);
	void (*stop)(aud_stream_t *);
	uint_t (*setflag)(aud_stream_t *, enum aud_opflag, uint_t);
	aud_return_t (*setinfo)(aud_stream_t *, mblk_t *, int *);
	void (*queuecmd)(aud_stream_t *, aud_cmd_t *);
	void (*flushcmd)(aud_stream_t *);
#else /* __STDC__ */
	void (*close)();
	aud_return_t (*ioctl)();
	aud_return_t (*mproto)();
	void (*start)();
	void (*stop)();
	uint_t (*setflag)();
	aud_return_t (*setinfo)();
	void (*queuecmd)();
	void (*flushcmd)();
#endif /* __STDC__ */
};


/*
 * Define pseudo-routine names for the device-specific callouts
 */
#define	AUD_CLOSE(A)		(*(A)->distate->ops->close)(A)
#define	AUD_IOCTL(A, Q, M)	(*(A)->distate->ops->ioctl)(A, Q, M)
#define	AUD_MPROTO(A, M)	(*(A)->distate->ops->mproto)(A, M)
#define	AUD_START(A)		(*(A)->distate->ops->start)(A)
#define	AUD_STOP(A)		(*(A)->distate->ops->stop)(A)
#define	AUD_SETFLAG(A, F, X)	(*(A)->distate->ops->setflag)(A, F, X)
#define	AUD_GETFLAG(A, F)	(*(A)->distate->ops->setflag)(A, F, \
    AUD_INITVALUE)
#define	AUD_SETINFO(A, M, E)	(*(A)->distate->ops->setinfo)(A, M, E)
#define	AUD_GETINFO(A)		(*(A)->distate->ops->setinfo)(A, NULL, NULL)
#define	AUD_QUEUECMD(A, C)	(*(A)->distate->ops->queuecmd)(A, C)
#define	AUD_FLUSHCMD(A)		(*(A)->distate->ops->flushcmd)(A)


/*
 * Device Independent Audio driver function prototypes
 */
#ifdef __STDC__
extern int	audio_open(aud_stream_t *, queue_t *, dev_t *, int, int);
extern int	audio_close(queue_t *, int, cred_t *);
extern int	audio_wput(queue_t *, mblk_t *);
extern int	audio_wsrv(queue_t *);
extern int	audio_rput(queue_t *, mblk_t *);
extern int	audio_rsrv(queue_t *);
extern void	audio_gc_output(aud_stream_t *);
extern void	audio_process_output(aud_stream_t *);
extern void	audio_process_input(aud_stream_t *);
extern void	audio_sendsig(aud_stream_t *, audio_sendsig_t);
extern void	audio_flush_cmdlist(aud_stream_t *);
extern void	audio_ack(queue_t *, mblk_t *, int);
extern void	audio_copyout(queue_t *, mblk_t *, caddr_t, uint_t);
extern void	audio_pause_play(aud_stream_t *);
extern void	audio_pause_record(aud_stream_t *);
extern void	audio_resume_play(aud_stream_t *);
extern void	audio_resume_record(aud_stream_t *);
extern void	audio_trace(aud_stream_t *, aud_cmd_t *);
extern void	audio_trace_hdr(aud_stream_t *, audtrace_hdr_t *);
#else /* __STDC__ */
extern int	audio_open();
extern int	audio_close();
extern int	audio_wput();
extern int	audio_wsrv();
extern int	audio_rput();
extern int	audio_rsrv();
extern void	audio_gc_output();
extern void	audio_process_output();
extern void	audio_process_input();
extern void	audio_sendsig();
extern void	audio_flush_cmdlist();
extern void	audio_ack();
extern void	audio_copyout();
extern void	audio_pause_play();
extern void	audio_pause_record();
extern void	audio_resume_play();
extern void	audio_resume_record();
extern void	audio_trace()
extern void	audio_trace_hdr();
#endif /* __STDC__ */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AUDIOVAR_H */
