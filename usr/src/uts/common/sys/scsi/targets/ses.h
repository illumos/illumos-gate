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
 * Enclosure Services Device target driver
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SCSI_TARGETS_SES_H
#define	_SYS_SCSI_TARGETS_SES_H

#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Useful defines and typedefs
 */
#define	EOK			0

#define	INVOP			0x10

#define	BP_PKT(bp)		((struct scsi_pkt *)(bp)->av_back)
#define	SET_BP_PKT(bp, s)	(bp)->av_back = (struct buf *)(s)

#define	SCBP(pkt)		((struct scsi_status *)(pkt)->pkt_scbp)
#define	SCBP_C(pkt)		((*(pkt)->pkt_scbp) & STATUS_MASK)
#define	Scsidevp		struct scsi_device *
#define	Scsipktp		struct scsi_pkt *
#define	Uscmd			struct uscsi_cmd

#define	SES_SCSI_DEVP		(un->ses_scsi_devp)
#define	SES_DEVP(softc)		((softc)->ses_devp)
#define	SES_DEVINFO(softc)	(SES_DEVP(softc)->sd_dev)
#define	SES_RQSENSE(softc)	(SES_DEVP(softc)->sd_sense)
#define	SES_ROUTE(softc)	(&SES_DEVP(softc)->sd_address)
#define	SES_MUTEX		(&ssc->ses_devp->sd_mutex)

#define	ISOPEN(softc)		((softc)->ses_lyropen || (softc)->ses_oflag)
#define	UNUSED_PARAMETER(x)	x = x


/*
 * SAF-TE specific defines- Mandatory ones only...
 */

/*
 * READ BUFFER ('get' commands) IDs- placed in offset 2 of cdb
 */
#define	SAFTE_RD_RDCFG	0x00	/* read enclosure configuration */
#define	SAFTE_RD_RDESTS	0x01	/* read enclosure status */
#define	SAFTE_RD_RDDSTS	0x04	/* read drive slot status */

/*
 * WRITE BUFFER ('set' commands) IDs- placed in offset 0 of databuf
 */
#define	SAFTE_WT_DSTAT	0x10	/* write device slot status */
#define	SAFTE_WT_SLTOP	0x12	/* perform slot operation */
#define	SAFTE_WT_FANSPD	0x13	/* set fan speed */
#define	SAFTE_WT_ACTPWS	0x14	/* turn on/off power supply */
#define	SAFTE_WT_GLOBAL	0x15	/* send global command */


/*
 * Includes
 */
#include <sys/scsi/targets/sesio.h>


/*
 * Private info (Device Info. Private)
 *
 * Pointed to by the un_private pointer
 * of one of the SCSI_DEVICE structures.
 */
typedef struct ses_softc ses_softc_t;

typedef struct {
	int (*softc_init)(ses_softc_t *, int);
	int (*init_enc)(ses_softc_t *);
	int (*get_encstat)(ses_softc_t *, int);
	int (*set_encstat)(ses_softc_t *, uchar_t, int);
	int (*get_objstat)(ses_softc_t *, ses_objarg *, int);
	int (*set_objstat)(ses_softc_t *, ses_objarg *, int);
} encvec;

typedef enum { SES_TYPE, SAFT_TYPE, SEN_TYPE } enctyp;

typedef struct {
	uchar_t		enctype;	/* enclosure type */
	uchar_t		subenclosure;	/* subenclosure id */
	ushort_t	svalid	: 1,	/* enclosure information valid */
			priv	: 15;	/* private data, per object */
	uchar_t		encstat[4];	/* state && stats */
} encobj;

#ifndef	__lint				/* no warlock for X86 */
#ifdef	_KERNEL
_NOTE(MUTEX_PROTECTS_DATA(scsi_device::sd_mutex, encobj))
_NOTE(DATA_READABLE_WITHOUT_LOCK(encobj::priv))
_NOTE(DATA_READABLE_WITHOUT_LOCK(encobj::svalid))
_NOTE(DATA_READABLE_WITHOUT_LOCK(encobj::enctype))
_NOTE(DATA_READABLE_WITHOUT_LOCK(encobj::encstat))
_NOTE(DATA_READABLE_WITHOUT_LOCK(encobj::subenclosure))
#endif	/* _KERNEL */
#endif	/* __lint */


/*
 * Overall Status is bits 0..3- status validity reserved at bit 7
 */
#define	ENCI_SVALID	0x80

struct ses_softc {
	enctyp		ses_type;	/* type of enclosure */
	encvec		ses_vec;	/* vector to handlers */
	uint_t		ses_nobjects;	/* number of objects */
	void *		ses_private;	/* private data */
	encobj *	ses_objmap;	/* objects */
	uchar_t		ses_encstat;	/* overall status */
	Scsidevp  	ses_devp;	/* backpointer to owning SCSI device */
	struct buf 	*ses_rqbp;	/* request sense buf pointer */
	Scsipktp	ses_rqpkt;	/* SCSI Request Sense Packet */
	struct buf 	*ses_sbufp;	/* for use in internal io */
	timeout_id_t	ses_restart_id; /* restart timeout id */
	kcondvar_t	ses_sbufcv;	/* cv on sbuf */
	uchar_t		ses_sbufbsy;	/* sbuf busy flag */
	uchar_t		ses_oflag;	/* nonzero if opened (nonlayered) */
	uchar_t		ses_present;	/* device present */
	uchar_t		ses_suspended;	/* nonzero if suspended */
	uchar_t		ses_arq;	/* auto request sense enabled */
	uint_t 		ses_lyropen;	/* layered open count */
	int 		ses_retries;	/* retry count */
	/*
	 * Associated storage for the special buf.
	 * Since we're single threaded on sbuf anyway,
	 * we might as well save ourselves a pile of
	 * grief and allocate local uscsicmd and
	 * ancillary storage here.
	 */
	Uscmd		ses_uscsicmd;
	uchar_t		ses_srqcdb[CDB_SIZE];
	uchar_t		ses_srqsbuf[MAX_SENSE_LENGTH];
};

#ifndef	__lint				/* no warlock for X86 */
#ifdef	_KERNEL
_NOTE(MUTEX_PROTECTS_DATA(scsi_device::sd_mutex, ses_softc))
_NOTE(MUTEX_PROTECTS_DATA(scsi_device::sd_mutex, ses_softc::ses_lyropen))

_NOTE(SCHEME_PROTECTS_DATA("not shared", scsi_arq_status))
_NOTE(SCHEME_PROTECTS_DATA("not shared", ses_softc::ses_restart_id))
_NOTE(SCHEME_PROTECTS_DATA("not shared", ses_softc::ses_retries))
_NOTE(SCHEME_PROTECTS_DATA("not shared", ses_softc::ses_present))
_NOTE(SCHEME_PROTECTS_DATA("not shared", ses_softc::ses_suspended))
_NOTE(SCHEME_PROTECTS_DATA("stable data",
	ses_softc::ses_type
	ses_softc::ses_vec
	ses_softc::ses_nobjects
	ses_softc::ses_devp
	ses_softc::ses_arq))

_NOTE(SCHEME_PROTECTS_DATA("sbufp cv",
	ses_softc::ses_sbufp
	ses_softc::ses_rqpkt
	ses_softc::ses_rqbp
	ses_softc::ses_sbufbsy
	ses_softc::ses_uscsicmd
	ses_softc::ses_srqcdb
	ses_softc::ses_srqsbuf
	ses_softc::ses_uscsicmd))

_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", scsi_pkt buf uio scsi_cdb))
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", scsi_extended_sense scsi_status))
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", uscsi_cmd))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_device))

_NOTE(DATA_READABLE_WITHOUT_LOCK(ses_softc::ses_encstat))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ses_softc::ses_objmap))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ses_softc::ses_private))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ses_softc::ses_lyropen))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ses_softc::ses_oflag))

_NOTE(SCHEME_PROTECTS_DATA("absurdities", ses_objarg))
#endif	/* _KERNEL */
#endif	/* __lint */


/*
 * Compile options to turn on debugging code
 */
#ifdef	DEBUG
#define	SES_DEBUG
#endif	/* DEBUG */

#if defined(_KERNEL) || defined(_KMEMUSER)

#define	SES_CE_DEBUG		((1  << 8) | CE_CONT)
#define	SES_CE_DEBUG1		((2  << 8) | CE_CONT)
#define	SES_CE_DEBUG2		((3  << 8) | CE_CONT)
#define	SES_CE_DEBUG3		((4  << 8) | CE_CONT)
#define	SES_CE_DEBUG4		((5  << 8) | CE_CONT)
#define	SES_CE_DEBUG5		((6  << 8) | CE_CONT)
#define	SES_CE_DEBUG6		((7  << 8) | CE_CONT)
#define	SES_CE_DEBUG7		((8  << 8) | CE_CONT)
#define	SES_CE_DEBUG8		((9  << 8) | CE_CONT)
#define	SES_CE_DEBUG9		((10 << 8) | CE_CONT)

#ifndef SES_DEBUG
#define	ses_debug		0
#endif	/* SES_DEBUG */

#define	SES_LOG			if (ses_debug) ses_log
#define	SES_DEBUG_ENTER		if (ses_debug) debug_enter


/*
 * Various I/O timeouts.
 *
 * These are hard-coded and not adjustable. The restart macro
 * time input is in milliseconds with 1 msec. the minimum setting.
 *
 */
#define	SES_IO_TIME		  60 /* standard I/O time (sec.) */
#define	SES_RESTART_TIME	 100 /* I/O restart time (ms.) */
#define	SES_BUSY_TIME		500 /* I/O busy restart time (ms.) */

#define	SES_ENABLE_RESTART(ms_time, pkt) { \
	ssc->ses_restart_id = timeout(ses_restart, (void *) pkt, \
	    (ms_time)? (drv_usectohz(ms_time * 1000)) : \
	    drv_usectohz(1000)); \
}


/*
 * Number of times we'll retry a normal operation.
 *
 * Note, retries have differnt weights to max retries.
 * Unit Attention and request sense have the most retries.
 * Command retries have the least.
 *
 * For no auto-request sense operation, the SES_RETRY_MULTIPLIER
 * must be greater than the command RETRY_COUNT.  Then the request
 * sense commands won't impact the command retries.
 */
#define	SES_RETRY_COUNT		4
#define	SES_RETRY_MULTIPLIER	8

#define	SES_CMD_RETRY		SES_RETRY_MULTIPLIER
#define	SES_NO_RETRY		0
#define	SES_SENSE_RETRY		1
#define	SES_BUSY_RETRY		4

/* Retry weight is 1 */
#define	SES_CMD_RETRY1(retry) \
	retry += (retry > 0)? (SES_RETRY_MULTIPLIER -1) : 0;

/* Retry weight is 2 */
#define	SES_CMD_RETRY2(retry) \
	retry += (retry > 0)? (SES_RETRY_MULTIPLIER -2) : 0;

/* Retry weight is 4 */
#define	SES_CMD_RETRY4(retry) \
	retry += (retry > 0)? (SES_RETRY_MULTIPLIER -4) : 0;


/*
 * ses_present definitions
 */
#define	SES_CLOSED		0
#define	SES_OPENING		1
#define	SES_OPEN		2


/*
 * ses_callback action codes
 */
#define	COMMAND_DONE		0
#define	COMMAND_DONE_ERROR	1
#define	QUE_COMMAND_NOW		3
#define	QUE_COMMAND		4
#define	QUE_SENSE		5


/*
 * PF bit for RECEIVE DIAG command;
 * needed for RSM first release hw.
 */
#define	SCSI_ESI_PF	0x10
#define	SEN_ID		"UNISYS           SUN_SEN"
#define	SEN_ID_LEN	24

#define	SET_BP_ERROR(bp, err)	bioerror(bp, err);

/*
 * Common Driver Functions
 */
#if	defined(_KERNEL)
extern void ses_log(ses_softc_t *, int, const char *, ...);
extern int ses_runcmd(ses_softc_t *, Uscmd *);
extern int ses_uscsi_cmd(ses_softc_t *, Uscmd *, int);
extern int ses_io_time;

#ifdef	DEBUG
extern int ses_debug;
#endif /* DEBUG */

#endif	/* defined(_KERNEL) */


#endif	/* defined(_KERNEL) || defined(_KMEMUSER) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_TARGETS_SES_H */
