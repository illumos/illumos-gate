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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NFSLOGD_H
#define	_NFSLOGD_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <tzfile.h>
#include <sys/types.h>
#include <nfs/nfs_log.h>
#include "../lib/nfslog_config.h"
#include "buffer_list.h"

#define	NFSLOGD_PIDFILE		"/var/run/nfslogd.pid"
#define	NFSLOG_OPTIONS_FILE	"/etc/default/nfslogd"

#define	MIN_PROCESSING_SIZE	512*1024	/* Minimum size buffer */
						/* should reach before */
						/* processing */
#define	IDLE_TIME		300	/* Max time to wait w/o processing */
					/* in seconds */
#define	MAX_LOGS_PRESERVE	10	/* Number of log files to keep for */
					/* cycling */
#define	MAPPING_UPDATE_INTERVAL	(SECSPERDAY)	/* frequency of updates to */
						/* dbm records in seconds  */
#define	CYCLE_FREQUENCY		24	/* in hours */
#define	PRUNE_TIMEOUT		(SECSPERHOUR * 168)
#define	NFSLOG_UMASK		0137	/* for creating tables and logs */

/*
 * RPC dispatch table for logging. Indexed by program, version, proc.
 * Based on NFS dispatch table, but differs in that it does not xdr
 * encode/decode arguments and results.
 */
struct nfsl_proc_disp {
	void	(*nfsl_dis_args)();	/* prt elf nl args from rpc args */
	void	(*nfsl_dis_res)();	/* prt elf nl res from rpc res */
	char	*procname;		/* string describing the proc */
};

struct nfsl_vers_disp {
	int	nfsl_dis_nprocs;			/* number of procs */
	struct nfsl_proc_disp	*nfsl_dis_proc_table;	/* proc array */
};

struct nfsl_prog_disp {
	rpcprog_t	nfsl_dis_prog;		/* program number */
	rpcvers_t	nfsl_dis_versmin;	/* minimum version number */
	int		nfsl_dis_nvers;		/* number of version values */
	struct nfsl_vers_disp	*nfsl_dis_vers_table;	/* versions array */
	char	*progname;		/* string describing the program */
};

struct nfsl_log_file {
	char	*path;		/* pathname of file */
	FILE	*fp;		/* file pointer */
	char	*buf;		/* buffer where output queued before print */
	int	bufoffset;	/* current offset in (memory) buffer */
	struct nfsl_log_file	*next;	/* next file in list */
	struct nfsl_log_file	*prev;	/* next file in list */
};

/*
 * The following four structures are used for processing the buffer file.
 */
struct valid_rpcs {
	rpcprog_t	prog;
	rpcvers_t	versmin;
	rpcvers_t	versmax;
};

/*
 * Simple struct for keeping track of the offset and length of
 * records processed from the buffer file.  This is used for the logic
 * of rewriting the buffer header of that last record processed.
 * Since records within the buffer file can be 'out of order' and nfslogd
 * sorts those records, we need to keep track of what has been processed
 * and where.  This record keeping is then used to decide when to rewrite
 * the buffer header and to decide the correct offset for that rewrite.
 */
struct processed_records {
	struct processed_records *next;
	struct processed_records *prev;
	u_offset_t start_offset;
	unsigned int len;
	unsigned int num_recs;
};

struct nfslog_buf {
	struct nfslog_buf	*next;
	struct nfslog_buf	*prev;
	char	*bufpath;			/* buffer file name */
	int	fd;				/* buffer file fd */
	flock_t fl;				/* buffer file lock */
	u_offset_t	filesize;		/* file size */
	intptr_t mmap_addr;			/* address of mmap */
	u_offset_t next_rec;			/* address of next record */
	unsigned int last_rec_id;		/* last record id processed */
	nfslog_buffer_header	bh;		/* file buffer header */
	struct nfslog_lr *bh_lrp;
	int num_lrps;
	struct nfslog_lr *lrps;			/* raw records - not cooked */
	/* Next fields used for tracking processed records from buf file */
	u_offset_t last_record_offset;		/* value last written to hdr */
	struct processed_records *prp;		/* list of processed chunks */
	int num_pr_queued;			/* # of processed records */
};

struct nfslog_lr {
	struct	nfslog_lr *next;
	struct	nfslog_lr *prev;
	u_offset_t f_offset;			/* offset for ondisk file */
	intptr_t record;			/* mmap address of record */
	unsigned int recsize;			/* size of this record */
	caddr_t buffer;				/* used if mmap fails */
	XDR	xdrs;
	nfslog_request_record	log_record;	/* decoded record */
	bool_t			(*xdrargs)();	/* xdr function for FREE */
	bool_t			(*xdrres)();	/* xdr function for FREE */
	struct nfslog_buf *lbp;
};

/*
 * Following defines are used as a parameter to nfslog_open_trans()
 * The bit mask passed to this function will determine which operations
 * are placed in the log.
 */
#define	TRANSTOLOG_OPER_READ	0x00000001
#define	TRANSTOLOG_OPER_WRITE	0x00000002
#define	TRANSTOLOG_OPER_SETATTR	0x00000004
#define	TRANSTOLOG_OPER_REMOVE	0x00000008
#define	TRANSTOLOG_OPER_MKDIR	0x00000010
#define	TRANSTOLOG_OPER_CREATE	0x00000020
#define	TRANSTOLOG_OPER_RMDIR	0x00000040
#define	TRANSTOLOG_OPER_RENAME	0x00000080
#define	TRANSTOLOG_OPER_MKNOD	0x00000100
#define	TRANSTOLOG_OPER_LINK	0x00000200
#define	TRANSTOLOG_OPER_SYMLINK	0x00000400
#define	TRANSTOLOG_OPER_READWRITE \
	(TRANSTOLOG_OPER_READ | TRANSTOLOG_OPER_WRITE)
#define	TRANSTOLOG_ALL ((uint32_t)~0)

extern int debug;
extern boolean_t test;
extern int max_logs_preserve;
extern uint_t idle_time;
extern boolean_t keep_running;
extern boolean_t quick_cleaning;

extern int cycle_log(char *, int);
extern int prune_dbs(char *);
extern int process_buffer(
	struct buffer_ent *, nfsl_config_t **, int, int, int *);
extern struct nfslog_buf *nfslog_open_buf(char *, int *);
extern void nfslog_close_buf(struct nfslog_buf *, int);
extern struct nfslog_lr	*nfslog_get_logrecord(struct nfslog_buf *);
extern void nfslog_free_logrecord(struct nfslog_lr *, bool_t);

extern int nfslog_process_fh_rec(struct nfslog_lr *,
		char *, char **, char **, bool_t);

extern void *nfslog_open_elf_file(char *, nfslog_buffer_header *, int *);
extern void nfslog_close_elf_file(void **);
extern int nfslog_process_elf_rec(void *, nfslog_request_record *,
		char *, char *);

struct nfslog_trans_file;
extern void *nfslog_open_trans_file(char *, uint32_t, uint32_t, int *);

extern void nfslog_process_trans_timeout(struct nfslog_trans_file *,
		uint32_t);
extern int nfslog_process_trans_rec(void *,
		nfslog_request_record *, char *, char *, char *);
extern void nfslog_close_transactions(void **);

extern void nfslog_opaque_print_buf(void *, int, char *, int *, int);
#ifdef	__cplusplus
}
#endif

#endif /* _NFSLOGD_H */
