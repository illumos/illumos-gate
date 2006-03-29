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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IOSRAMVAR_H
#define	_SYS_IOSRAMVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Data sizes used by the original author
 */
#ifndef UINT32SZ
#define	UINT32SZ	sizeof (uint32_t)
#define	UINT64SZ	sizeof (uint64_t)
#endif

/*
 * Values used for tunnel switching
 */
#define	OBP_TSWITCH_REQREPLY	0		/* request reply from SSC */
#define	OBP_TSWITCH_NOREPLY	1		/* don't wait for reply */
#define	IOSRAM_TSWITCH_RETRY	20		/* # of times to wait for */
						/*   current tunnel switch to */
						/*   end when starting a new */
						/*   one */
/*
 * When performing back-to-back tunnel switches, we have to make sure that
 * HWAD (the SC-side implementation) has time to find the new tunnel from
 * one switch before we invalidate it for the next switch.  To ensure that,
 * we make sure that the time between consecutive tunnel switches is at
 * least twice the polling rate HWAD uses to detect the new tunnel.
 */
#define	IOSRAM_TSWITCH_DELAY_US	100000

/*
 * Values used for hash table maintenance
 */
#define	IOSRAM_HASHSZ	0x20		/* # hash entries */
#define	IOSRAM_HASH(key)	((((key) >> 24) ^ ((key) >> 16) ^\
				((key) >> 9) ^ (key)) & (IOSRAM_HASHSZ - 1))

/*
 * A pair of flags is associated with each IOSRAM chunk in the IOSRAM TOC.
 * These flags are stored sequentially in the "SC Domain Communication Data"
 * ('SDCD') IOSRAM chunk.  The data-valid/int-pending flags are one byte each
 * and stored sequentially with data-valid flag being the first.  The following
 * macros define the offset of the flags for each IOSRAM chunk based upon its
 * location (index) in the IOSRAM TOC.
 */
#define	IOSRAM_DATAVALID_FLAGOFF(index)		(2 * (index))
#define	IOSRAM_INTPENDING_FLAGOFF(index)	(2 * (index) + 1)

/*
 * IOSRAM node properties (per IOSRAM node)
 */
#define	IOSRAM_REG_PROP		"reg"
#define	IOSRAM_TUNNELOK_PROP	"tunnel-capable"

/*
 * Other IOSRAM properties (on chosen node and parent hierarchy)
 */
#define	IOSRAM_CHOSEN_PROP	"iosram"
#define	IOSRAM_PORTID_PROP	"portid"

/*
 * Interrupt priority (PIL) used for IOSRAM interrupts.  The value 5 was
 * chosen somewhat arbitrarily based on the fact that it is higher than
 * disks and lower than networks.
 */
#define	IOSRAM_PIL	5

/*
 * IOSRAM header structure, located at the beginning of IOSRAM.
 *
 * NOTE - New fields may be appended to this structure, but no existing fields
 *        may be altered in any way!!!
 */
typedef struct {
	uint32_t	status;
	uint32_t	version;
	uint32_t	toc_offset;
	uint32_t	sms_mbox_version;
	uint32_t	os_mbox_version;
	uint32_t	obp_mbox_version;
	uint32_t	sms_change_mask;
	uint32_t	os_change_mask;
} iosram_hdr_t;

/*
 * Values for the status field
 */
#define	IOSRAM_INVALID		0x494e5644	/* 'INVD' */
#define	IOSRAM_VALID		0x56414c44	/* 'VALD' */
#define	IOSRAM_INTRANSIT	0x494e5452	/* 'INTR' */

/*
 * Maximum IOSRAM Protocol version understood by this implementation
 */
#define	IOSRAM_MAX_PROTOCOL_VERSION		1

/*
 * Bit definitions for *_change_mask fields
 */
#define	IOSRAM_HDRFIELD_SMS_MBOX_VER	0x00000001
#define	IOSRAM_HDRFIELD_OS_MBOX_VER	0x00000002
#define	IOSRAM_HDRFIELD_TOC_INDEX	0x00000004

/*
 * Macros used to access fields in the header
 */
#define	IOSRAM_GET_HDRFIELD32(softp, field)	\
	(ddi_get32((softp)->handle, &((iosram_hdr_t *)(softp)->iosramp)->field))
#define	IOSRAM_SET_HDRFIELD32(softp, field, val)	\
	(ddi_put32((softp)->handle, &((iosram_hdr_t *)(softp)->iosramp)->field,\
	(val)))

/*
 * IOSRAM contains various data chunks and the key, location and size of
 * each IOSRAM chunk is communicated to the IOSRAM driver in the form of a
 * Table of Contents.  This structre contains one entry for each IOSRAM
 * chunk, as well as an initial index entry.  Each entry has the following
 * structure.
 *
 * NOTE - Although the unused field may be renamed for some use in the future,
 *        no other modification to this structure is allowed!!!
 */

typedef struct {
	uint32_t	key;		/* IOSRAM chunk key */
	uint32_t	off;		/* IOSRAM chunk starting offset */
	uint32_t	len;		/* IOSRAM chunk length */
	uint32_t	unused;		/* currently unused */
} iosram_toc_entry_t;

/*
 * Special values used in some TOC entries
 */
#define	IOSRAM_FLAGS_KEY	0x53444344	/* 'SDCD' - flags chunk key */
#define	IOSRAM_INDEX_KEY	0x494e4458	/* 'INDX' - index entry key */
#define	IOSRAM_INDEX_OFF	0xFFFFFFFF	/* index entry offset */


/*
 * IOSRAM flags structure.  An array of these - one for every IOSRAM chunk - is
 * stored in the SDCD chunk.
 */
typedef struct {
	uint8_t	data_valid;
	uint8_t	int_pending;
} iosram_flags_t;

/*
 * IOSRAM callback data structure
 */
typedef struct {
	uchar_t		busy;		/* cback handler is active/busy */
	uchar_t		unregister;	/* delayed callback unregistration */
	void		(*handler)();	/* cback handler */
	void		*arg;		/* cback handler arg */
} iosram_cback_t;


/*
 * IOSRAM per chunk state
 */
typedef struct iosram_chunk {
	iosram_toc_entry_t toc_data;	/* Data from TOC entry */
	iosram_cback_t	cback;		/* callback info */
	uint8_t		*basep;		/* kvaddr for this IOSRAM chunk */
	iosram_flags_t	*flagsp;
	struct iosram_chunk *hash;	/* next entry in the hash list */
} iosram_chunk_t;


/*
 * IOSRAM per instance state
 */

typedef struct iosramsoft {
	struct iosramsoft *prev;	/* ptr for linked list */
	struct iosramsoft *next;	/* ptr for linked list */

	boolean_t	suspended;	/* TRUE if driver suspended */
	int		instance;	/* driver instance number */
	dev_info_t	*dip;		/* device information */

	uchar_t		*iosramp;	/* IOSRAM mapped vaddr */
	int		iosramlen; 	/* IOSRAM length */
	int		nchunks;	/* # IOSRAM chunks */
	iosram_chunk_t	*chunks;	/* ptr to iosram_chunk array */
	iosram_chunk_t	*flags_chunk;	/* ptr to flags chunk */
	ddi_acc_handle_t handle;	/* IOSRAM map handle */

	ddi_iblock_cookie_t real_iblk;	/* real intr iblock cookie */
	ddi_iblock_cookie_t soft_iblk;	/* soft intr iblock cookie */
	ddi_softintr_t	softintr_id;	/* soft interrupt ID */
	ushort_t	intr_busy;	/* softintr handler busy */
	ushort_t	intr_pending;	/* interrupt pending */

	int		state;		/* IOSRAM state (see below) */
	int		portid;		/* Card port ID for tswitch */
	uint32_t	tswitch_ok;	/* # successful tunnel switch */
	uint32_t	tswitch_fail;	/* # failed tunnel switch */

	ddi_acc_handle_t sbbc_handle;	/* SBBC regs map handle */
	iosram_sbbc_region_t *sbbc_region; /* region of SBBC registers */
	uint32_t	int_enable_sav;	/* save int enable reg. on suspend */
	kmutex_t	intr_mutex;	/* real interrupt handler mutex */
} iosramsoft_t;


/* IOSRAM state value */
#define	IOSRAM_STATE_INIT	0x0001	/* initialization */
#define	IOSRAM_STATE_SLAVE	0x0002	/* SLAVE IOSRAM */
#define	IOSRAM_STATE_MASTER	0x0004	/* MASTER IOSRAM */
#define	IOSRAM_STATE_MAPPED	0x0008	/* IOSRAM mapped */

#define	IOSRAM_STATE_TSWITCH	0x0010	/* tunnel switch source/target */
#define	IOSRAM_STATE_DETACH	0x0020	/* IOSRAM instance being detached */


#if DEBUG
#define	IOSRAM_STATS	1		/* enable IOSRAM statistics */
#define	IOSRAM_LOG	1		/* enable IOSRAM logging */
#endif

#if IOSRAM_STATS

/*
 * IOSRAM statistics
 */
struct iosram_stat {
	uint32_t	read;		/* calls to iosram_read */
	uint32_t	write;		/* calls to iosram_{force_}write */
	uint32_t	getflag;	/* calls to iosram_getflag */
	uint32_t	setflag;	/* calls to iosram_getflag */
	uint32_t	tswitch;	/* # tunnel switch */
	uint32_t	callbacks;	/* # callbacks invoked */
	uint32_t	intr_recv;	/* # interrupts received */
	uint32_t	sintr_recv;	/* # softintr received */
	uint32_t	intr_send;	/* # interrupts sent */
	uint64_t	bread;		/* # bytes read */
	uint64_t	bwrite;		/* # bytes written */
};

#define	IOSRAM_STAT(field)		iosram_stats.field++
#define	IOSRAM_STAT_ADD(field, amount)	iosram_stats.field += (uint64_t)amount
#define	IOSRAM_STAT_SET(field, count)	iosram_stats.field = (uint64_t)count

#else /* !IOSRAM_STATS */

#define	IOSRAM_STAT(field)
#define	IOSRAM_STAT_ADD(field, amount)
#define	IOSRAM_STAT_SET(field, count)

#endif /* !IOSRAM_STATS */


#if IOSRAM_LOG

/*
 * IOSRAM log related structures and extern declarations
 */

#define	IOSRAM_MAXLOG	64

typedef struct {
	uint32_t	seq;		/* logseg# */
	clock_t		tstamp;		/* time stamp */
	caddr_t		fmt;		/* format ptr */
	intptr_t 	arg1;		/* first arg */
	intptr_t 	arg2;		/* second arg */
	intptr_t 	arg3;		/* third arg */
	intptr_t 	arg4;		/* fourth arg */
} iosram_log_t;

#define	IOSRAMLOG(level, fmt, a1, a2, a3, a4)			\
	if (iosram_log_level >= level) {			\
		iosram_log(fmt, (intptr_t)a1, (intptr_t)a2, 	\
			(intptr_t)a3, (intptr_t)a4);		\
	}

extern int	iosram_log_level;
extern uint32_t	iosram_logseq;
extern iosram_log_t iosram_logbuf[IOSRAM_MAXLOG];
extern void iosram_log(caddr_t, intptr_t, intptr_t, intptr_t, intptr_t);

#else	/* !IOSRAM_LOG */

#define	IOSRAMLOG(level, fmt, a1, a2, a3, a4)

#endif	/* !IOSRAM_LOG */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IOSRAMVAR_H */
