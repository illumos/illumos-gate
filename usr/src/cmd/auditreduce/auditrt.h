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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _AUDITRT_H
#define	_AUDITRT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Auditreduce data structures.
 */

/*
 * File Control Block
 * Controls a single file.
 * These are held by the pcb's in audit_pcbs[] in a linked list.
 * There is one fcb for each file controlled by the pcb,
 * and all of the files in a list have the same suffix in their names.
 */
struct audit_fcb {
	struct audit_fcb *fcb_next;	/* ptr to next fcb in list */
	int	fcb_flags;	/* flags - see below */
	time_t	fcb_start;	/* start time from filename */
	time_t	fcb_end;	/* end time from filename */
	char	*fcb_suffix;	/* ptr to suffix in fcb_file */
	char	*fcb_name;	/* ptr to name in fcb_file */
	char	fcb_file[1];	/* full path and name string */
};

typedef struct audit_fcb audit_fcb_t;

/*
 * Flags for fcb_flags.
 */
#define	FF_NOTTERM	0x01	/* file is "not_terminated" */
#define	FF_DELETE	0x02	/* we may delete this file if requested */

/*
 * Process Control Block
 * A pcb comes in two types:
 * It controls either:
 *
 * 1.	A single group of pcbs (processes that are lower on the process tree).
 *	These are the pcb's that the process tree is built from.
 *	These are allocated as needed while the process tree is	being built.
 *
 * 2.	A single group of files (fcbs).
 *	All of the files in one pcb have the same suffix in their filename.
 *	They are controlled by the leaf nodes of the process tree.
 *	They are found in audit_pcbs[].
 *	They are initially setup by process_fileopt() when the files to be
 *	processes are gathered together. Then they are parsed out to
 *	the leaf nodes by mfork().
 *	A particular leaf node's range of audit_pcbs[] is determined
 *	in the call to mfork() by the lo and hi paramters.
 */
struct audit_pcb {
	struct audit_pcb *pcb_below;	/* ptr to group of pcb's */
	struct audit_pcb *pcb_next;	/* ptr to next - for list in mproc() */
	int	pcb_procno;	/* subprocess # */
	int	pcb_nrecs;	/* how many records read (current pcb/file) */
	int	pcb_nprecs;	/* how many records put (current pcb/file) */
	int	pcb_flags;	/* flags - see below */
	int	pcb_count;	/* count of active pcb's */
	int	pcb_lo;		/* low index for pcb's */
	int	pcb_hi;		/* hi index for pcb's */
	int	pcb_size;	/* size of current record buffer */
	time_t	pcb_time;	/* time of current record */
	time_t	pcb_otime;	/* time of previous record */
	char	*pcb_rec;	/* ptr to current record buffer */
	char	*pcb_suffix;	/* ptr to suffix name (string) */
	audit_fcb_t *pcb_first;	/* ptr to first fcb_ */
	audit_fcb_t *pcb_last;	/* ptr to last fcb_ */
	audit_fcb_t *pcb_cur;	/* ptr to current fcb_ */
	audit_fcb_t *pcb_dfirst; /* ptr to first fcb_ for deleting */
	audit_fcb_t *pcb_dlast;	/* ptr to last fcb_ for deleting */
	FILE	 *pcb_fpr;	/* read stream */
	FILE	 *pcb_fpw;	/* write stream */
};

typedef struct audit_pcb audit_pcb_t;

/*
 * Flags for pcb_flags
 */
#define	PF_ROOT		0x01	/* current pcb is the root of process tree */
#define	PF_LEAF		0x02	/* current pcb is a leaf of process tree */
#define	PF_USEFILE	0x04	/* current pcb uses files as input, not pipes */

/*
 * Message selection options
 */
#define	M_AFTER		0x0001	/* 'a' after a time */
#define	M_BEFORE	0x0002	/* 'b' before a time */
#define	M_CLASS		0x0004	/* 'c' event class */
#define	M_GROUPE 	0x0008	/* 'f' effective group-id */
#define	M_GROUPR 	0x0010	/* 'g' real group-id */
#define	M_OBJECT	0x0020	/* 'o' object */
#define	M_SUBJECT	0x0040	/* 'j' subject */
#define	M_TYPE		0x0080	/* 'm' event type */
#define	M_USERA		0x0100	/* 'u' audit user */
#define	M_USERE		0x0200	/* 'e' effective user */
#define	M_USERR		0x0400	/* 'r' real user */
#define	M_LABEL		0x0800	/* 'l' mandatory label range */
#define	M_ZONENAME	0x1000	/* 'z' zone name */
#define	M_SID		0x2000	/* 's' session ID */
#define	M_SORF		0x4000	/* success or failure of event */
#define	M_TID		0x8000	/* 't' terminal ID */
/*
 * object types
 */

/* XXX Why is this a bit map?  There can be only one M_OBJECT. */

#define	OBJ_LP		0x00001  /* 'o' lp object */
#define	OBJ_MSG		0x00002  /* 'o' msgq object */
#define	OBJ_PATH	0x00004  /* 'o' file system object */
#define	OBJ_PROC	0x00008  /* 'o' process object */
#define	OBJ_SEM		0x00010  /* 'o' semaphore object */
#define	OBJ_SHM		0x00020  /* 'o' shared memory object */
#define	OBJ_SOCK	0x00040  /* 'o' socket object */
#define	OBJ_FGROUP	0x00080  /* 'o' file group */
#define	OBJ_FOWNER	0x00100  /* 'o' file owner */
#define	OBJ_MSGGROUP	0x00200	 /* 'o' msgq [c]group */
#define	OBJ_MSGOWNER	0x00400  /* 'o' msgq [c]owner */
#define	OBJ_PGROUP	0x00800  /* 'o' process [e]group */
#define	OBJ_POWNER	0x01000  /* 'o' process [e]owner */
#define	OBJ_SEMGROUP	0x02000  /* 'o' semaphore [c]group */
#define	OBJ_SEMOWNER	0x04000  /* 'o' semaphore [c]owner */
#define	OBJ_SHMGROUP	0x08000  /* 'o' shared memory [c]group */
#define	OBJ_SHMOWNER	0x10000  /* 'o' shared memory [c]owner */
#define	OBJ_FMRI	0x20000  /* 'o' fmri object */
#define	OBJ_USER	0x40000  /* 'o' user object */
#define	OBJ_WSID	0x80000  /* 'o' windows sid object */

#define	SOCKFLG_MACHINE 0	/* search socket token by machine name */
#define	SOCKFLG_PORT    1	/* search socket token by port number */

/*
 * Global variables
 */
extern unsigned short m_type;	/* 'm' message type */
extern gid_t	m_groupr;	/* 'g' real group-id */
extern gid_t	m_groupe;	/* 'f' effective group-id */
extern uid_t	m_usera;	/* 'u' audit user */
extern uid_t	m_userr;	/* 'r' real user */
extern uid_t	m_usere;	/* 'f' effective user */
extern au_asid_t m_sid;		/* 's' session-id */
extern time_t	m_after;	/* 'a' after a time */
extern time_t	m_before;	/* 'b' before a time */
extern audit_state_t mask;	/* used with m_class */
extern char	*zonename;	/* 'z' zonename */

extern m_range_t *m_label;	/* 'l' mandatory label range */
extern int	flags;
extern int	checkflags;
extern int	socket_flag;
extern int	ip_type;
extern uchar_t	ip_ipv6[16];	/* ip ipv6 object identifier */
extern int	obj_flag;	/* 'o' object type */
extern int	obj_id;		/* object identifier */
extern gid_t	obj_group;	/* object group */
extern uid_t	obj_owner;	/* object owner */
extern int	subj_id; 	/* subject identifier */
extern char	ipc_type;	/* 'o' object type - tell what type of IPC */
extern scf_pattern_t fmri;	/* 'o' fmri value */
extern uid_t	obj_user;	/* 'o' user value */

/*
 * File selection options
 */
extern char	*f_machine;	/* 'M' machine (suffix) type */
extern char	*f_root;	/* 'R' audit root */
extern char	*f_server;	/* 'S' server */
extern char	*f_outfile;	/* 'W' output file */
extern int	f_all;		/* 'A' all records from a file */
extern int	f_complete;	/* 'C' only completed files */
extern int	f_delete;	/* 'D' delete when done */
extern int	f_quiet;	/* 'Q' sshhhh! */
extern int	f_verbose;	/* 'V' verbose */
extern int	f_stdin;	/* '-' read from stdin */
extern int	f_cmdline;	/*	files specified on the command line */
extern int	new_mode;	/* 'N' new object selection mode */

/*
 * Error reporting
 * Error_str is set whenever an error occurs to point to a string describing
 * the error. When the error message is printed error_str is also
 * printed to describe exactly what went wrong.
 * Errbuf is used to build messages with variables in them.
 */
extern char	*error_str;	/* current error message */
extern char	errbuf[];	/* buffer for building error message */
extern char	*ar;		/* => "auditreduce:" */

/*
 * Control blocks
 * Audit_pcbs[] is an array of pcbs that control files directly.
 * In the program's initialization phase it will gather all of the input
 * files it needs to process. Each file will have one fcb allocated for it,
 * and each fcb will belong to one pcb from audit_pcbs[]. All of the files
 * in a single pcb will have the same suffix in their filenames. If the
 * number of active pcbs in audit_pcbs[] is greater that the number of open
 * files a single process can have then the program will need to fork
 * subprocesses to handle all of the files.
 */
extern audit_pcb_t *audit_pcbs;	/* file-holding pcb's */
extern int	pcbsize;	/* current size of audit_pcbs[] */
extern int	pcbnum;		/* total # of active pcbs in audit_pcbs[] */

/*
 * Time values
 */
extern time_t f_start;		/* time of start rec for outfile */
extern time_t f_end;		/* time of end rec for outfile */
extern time_t time_now;		/* time program began */

/*
 * Counting vars
 */
extern int	filenum;	/* number of files total */

/*
 * Global variable, class of current record being processed.
 */
extern int	global_class;

#ifdef	__cplusplus
}
#endif

#endif /* _AUDITRT_H */
