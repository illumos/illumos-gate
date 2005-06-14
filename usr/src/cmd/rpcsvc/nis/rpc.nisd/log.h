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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 *	Definitions for this server's log implementation. This is server
 * dependent and may change from implementation to implementation.
 */

#ifndef _RPC_NISD_LOG_H
#define	_RPC_NISD_LOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	LOG_FILE	"/var/nis/trans.log"

/*
 * old_stamp_item is used to keep track of the timestamps for all the
 * directories that have been removed from the transaction log.
 */

struct old_stamp_item {
	NIS_HASH_ITEM	item;
	u_long		utime;
	int		stamped;
	u_long		xid;
};
typedef struct old_stamp_item old_stamp_item;


struct stamp_item {
	NIS_HASH_ITEM	item;
	u_long		utime;
};
typedef struct stamp_item stamp_item;

/*
 * The update log is mapped into memory from the file "trans.log".
 * This mapping is accomplished by the nis_main function when it starts.
 * When the directory checkpoints, it may truncate the log by making a
 * copy of it.
 */
struct log_upd {
	u_long		lu_magic;   /* Update magic number		*/
	u_long		lu_xid;	    /* Update transaction ID		*/
	u_long		lu_time;    /* Time of this update		*/
	nis_name	lu_dirname; /* Directory of this update		*/
	struct log_upd	*lu_next;   /* pointer to next update		*/
	struct log_upd	*lu_prev;   /* pointer to previous update	*/
	u_long		lu_size;    /* size of the data buffer		*/
	u_char		lu_data[4]; /* pointer to XDR'd log_entry	*/
};
typedef struct log_upd log_upd;

struct log_hdr {
	u_long		lh_magic;  /* Log header magic number	    */
	u_long		lh_state;  /* Updating/Stable/Checkpointing */
	struct log_hdr	*lh_addr;  /* Current address		    */
	u_long		lh_num;	   /* Number of updates in the log  */
	u_long		lh_xid;	   /* Last stable transaction	    */
	u_long		lh_first;  /* Timestamp of earliest update  */
	u_long		lh_last;   /* Timestamp of last update	    */
	log_upd		*lh_head;  /* pointer to the "first" update */
	log_upd		*lh_tail;  /* pointer to the "last" update  */
};
typedef struct log_hdr log_hdr;

#define	LOG_HDR_MAGIC	0x5551212	/* It is a directory service! */
#define	LOG_UPD_MAGIC	0x5552223
#define	LOG_UPD_MODMAG	0x5553332	/* Part of a modify operation */

					/* Tune these */
/* XXX these need to be tuned */
#define	MAXLOGLEN	0x10000000	/* 256 MB log file 	*/
#define	HIWATER		0x800000	/* 8 MB high water mark */
#define	FILE_BLK_SZ	0x10000		/* grow file based log by 64K */

#define	LOG_STABLE	1
#define	LOG_CHECKPOINT	2
#define	LOG_UPDATE	3
#define	LOG_RESYNC	4

#define	BACKUP_LOG	".BACKUP_LOG"

/*
 * Flags used for __log_resync() routine.  These flags are mainly used
 * to check if msync() should be called or not.  msync() is used to flush
 * the current mmap area to the the disk.  nislog program should never
 * call msync().
 */
#define	FNISD	0	/* called from nisd */
#define	FNISLOG	1	/* called from nislog program */
#define	FCHKPT	2	/* called from checkpointing section */

/*
 * This macro returns the next longword aligned address.
 */
#define	NISRNDUP(x) (((x) & 3) ? ((x) + 4) & ~3 : (x))

/*
 * This macro defines the linear XID size of a transaction update
 * in the file. The "end address" of the log, and the log size in bytes.
 */
#define	XID_SIZE(u)	(NISRNDUP(sizeof (log_upd) + 		\
				(u)->lu_size +			\
				strlen((u)->lu_dirname)+1))

#define	LOG_END(log)	NISRNDUP(((u_long)(log->lh_tail) +	\
				XID_SIZE(log->lh_tail)))
#define	LOG_SIZE(log) 	(LOG_END(log) - (u_long)(log))

/* Function prototypes */
#ifdef __STDC__
extern char *__make_name(log_entry *);
extern int __log_resync(log_hdr *, int);
extern bool_t xdr_log_entry(XDR *, log_entry *);
#else
extern char *__make_name();
extern int __log_resync();
extern bool_t xdr_log_entry();
#endif

/* global data */
extern log_hdr	*__nis_log;

#ifdef	__cplusplus
}
#endif

#endif	/* _RPC_NISD_LOG_H */
