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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BSM_AUDIT_KERNEL_H
#define	_BSM_AUDIT_KERNEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the basic auditing control structure definitions.
 */

#include <c2/audit_kevents.h>
#include <sys/priv_impl.h>
#include <sys/taskq.h>
#include <sys/zone.h>

#include <sys/tsol/label.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This table contains the mapping from the system call ID to a corresponding
 * audit event.
 *
 *   au_init() is a function called at the beginning of the system call that
 *   performs any necessary setup/processing. It maps the call into the
 *   appropriate event, depending on the system call arguments. It is called
 *   by audit_start() from trap.c .
 *
 *   au_event is the audit event associated with the system call. Most of the
 *   time it will map directly from the system call i.e. There is one system
 *   call associated with the event. In some cases, such as shmsys, or open,
 *   the au_start() function will map the system call to more than one event,
 *   depending on the system call arguments.
 *
 *   au_start() is a function that provides per system call processing at the
 *   beginning of a system call. It is mainly concerned with preseving the
 *   audit record components that may be altered so that we can determine
 *   what the original paramater was before as well as after the system call.
 *   It is possible that au_start() may be taken away. It might be cleaner to
 *   define flags in au_ctrl to save a designated argument. For the moment we
 *   support both mechanisms, however the use of au_start() will be reviewed
 *   for 4.1.1 and CMW and ZEUS to see if such a general method is justified.
 *
 *   au_finish() is a function that provides per system call processing at the
 *   completion of a system call. In certain circumstances, the type of audit
 *   event depends on intermidiate results during the processing of the system
 *   call. It is called in audit_finish() from trap.c .
 *
 *   au_ctrl is a control vector that indicates what processing might have to
 *   be performed, even if there is no auditing for this system call. At
 *   present this is mostly for path processing for chmod, chroot. We need to
 *   process the path information in vfs_lookup, even when we are not auditing
 *   the system call in the case of chdir and chroot.
 */
/*
 * Defines for au_ctrl
 */
#define	S2E_SP  PAD_SAVPATH	/* save path for later use */
#define	S2E_MLD PAD_MLD		/* only one lookup per system call */
#define	S2E_NPT PAD_NOPATH	/* force no path in audit record */
#define	S2E_PUB PAD_PUBLIC_EV	/* syscall is defined as a public op */

/*
 * At present, we are using the audit classes imbedded with in the kernel. Each
 * event has a bit mask determining which classes the event is associated.
 * The table audit_e2s maps the audit event ID to the audit state.
 *
 * Note that this may change radically. If we use a bit vector for the audit
 * class, we can allow granularity at the event ID for each user. In this
 * case, the vector would be determined at user level and passed to the kernel
 * via the setaudit system call.
 */

/*
 * The audit_pad structure holds paths for the current root and directory
 * for the process, as well as for open files and directly manipulated objects.
 * The reference count minimizes data copies since the process's current
 * directory changes very seldom.
 */
struct audit_path {
	uint_t		audp_ref;	/* reference count */
	uint_t		audp_size;	/* allocated size of this structure */
	uint_t		audp_cnt;	/* number of path sections */
	char		*audp_sect[1];	/* path section pointers */
					/* audp_sect[0] is the path name */
					/* audp_sect[1+] are attribute paths */
};

/*
 * The structure of the terminal ID within the kernel is different from the
 * terminal ID in user space. It is a combination of port and IP address.
 */

struct au_termid {
	dev_t	at_port;
	uint_t	at_type;
	uint_t	at_addr[4];
};
typedef struct au_termid au_termid_t;

/*
 * Attributes for deferring the queuing of an event.
 */
typedef struct au_defer_info {
	struct au_defer_info	*audi_next;	/* next on linked list */
	void	 *audi_ad;		/* audit record */
	int	audi_e_type;		/* audit event id */
	int	audi_e_mod;		/* audit event modifier */
	int	audi_flag;		/* au_close*() flags */
	timestruc_t	audi_atime;	/* audit event timestamp */
} au_defer_info_t;

/*
 * The structure p_audit_data hangs off of the process structure. It contains
 * all of the audit information necessary to manage the audit record generation
 * for each process.
 *
 * The pad_lock is constructed in the kmem_cache; the rest is combined
 * in a sub structure so it can be copied/zeroed in one statement.
 *
 * The members have been reordered for maximum packing on 64 bit Solaris.
 */
struct p_audit_data {
	kmutex_t	pad_lock;	/* lock pad data during changes */
	struct _pad_data {
		struct audit_path	*pad_root;	/* process root path */
		struct audit_path	*pad_cwd;	/* process cwd path */
		au_mask_t		pad_newmask;	/* pending new mask */
		int			pad_flags;
	} pad_data;
};
typedef struct p_audit_data p_audit_data_t;

#define	pad_root	pad_data.pad_root
#define	pad_cwd		pad_data.pad_cwd
#define	pad_newmask	pad_data.pad_newmask
#define	pad_flags	pad_data.pad_flags

/*
 * Defines for pad_flags
 */
#define	PAD_SETMASK 	0x00000001	/* need to complete pending setmask */

extern kmem_cache_t *au_pad_cache;

/*
 * Defines for pad_ctrl
 */
#define	PAD_SAVPATH 	0x00000001	/* save path for further processing */
#define	PAD_MLD		0x00000002	/* system call involves MLD */
#define	PAD_NOPATH  	0x00000004	/* force no paths in audit record */
#define	PAD_ABSPATH 	0x00000008	/* path from lookup is absolute */
#define	PAD_NOATTRB 	0x00000010	/* do not automatically add attribute */
					/* 0x20, 0x40 unused */
#define	PAD_LFLOAT  	0x00000080	/* Label float */
#define	PAD_NOAUDIT 	0x00000100	/* discard audit record */
#define	PAD_PATHFND 	0x00000200	/* found path, don't retry lookup */
#define	PAD_SPRIV   	0x00000400	/* succ priv use. extra audit_finish */
#define	PAD_FPRIV   	0x00000800	/* fail priv use. extra audit_finish */
#define	PAD_SMAC    	0x00001000	/* succ mac use. extra audit_finish */
#define	PAD_FMAC    	0x00002000	/* fail mac use. extra audit_finish */
#define	PAD_AUDITME 	0x00004000	/* audit me because of NFS operation */
#define	PAD_ATPATH  	0x00008000	/* attribute file lookup */
#define	PAD_TRUE_CREATE 0x00010000	/* true create, file not found */
#define	PAD_CORE	0x00020000	/* save attribute during core dump */
#define	PAD_ERRJMP	0x00040000	/* abort record generation on error */
#define	PAD_PUBLIC_EV	0x00080000	/* syscall is defined as a public op */

/*
 * The structure t_audit_data hangs off of the thread structure. It contains
 * all of the audit information necessary to manage the audit record generation
 * for each thread.
 *
 */

struct t_audit_data {
	kthread_id_t  tad_thread;	/* DEBUG pointer to parent thread */
	unsigned int  tad_scid;		/* system call ID for finish */
	short	tad_event;	/* event for audit record */
	short	tad_evmod;	/* event modifier for audit record */
	int	tad_ctrl;	/* audit control/status flags */
	void	*tad_errjmp;	/* error longjmp (audit record aborted) */
	int	tad_flag;	/* to audit or not to audit */
	struct audit_path	*tad_aupath;	/* captured at vfs_lookup */
	struct audit_path	*tad_atpath;	/* openat prefix, path of fd */
	struct vnode *tad_vn;	/* saved inode from vfs_lookup */
	caddr_t tad_ad;		/* base of accumulated audit data */
	au_defer_info_t	*tad_defer_head;	/* queue of records to defer */
						/* until syscall end: */
	au_defer_info_t	*tad_defer_tail;	/* tail of defer queue */
	priv_set_t tad_sprivs;	/* saved (success) used privs */
	priv_set_t tad_fprivs;	/* saved (failed) used privs */
};
typedef struct t_audit_data t_audit_data_t;

/*
 * The f_audit_data structure hangs off of the file structure. It contains
 * three fields of data. The audit ID, the audit state, and a path name.
 */

struct f_audit_data {
	kthread_id_t	fad_thread;	/* DEBUG creating thread */
	int		fad_flags;	/* audit control flags */
	struct audit_path	*fad_aupath;	/* path from vfs_lookup */
};
typedef struct f_audit_data f_audit_data_t;

#define	FAD_READ	0x0001		/* read system call seen */
#define	FAD_WRITE	0x0002		/* write system call seen */

#define	P2A(p)	(p->p_audit_data)
#define	T2A(t)	(t->t_audit_data)
#define	U2A(u)	(curthread->t_audit_data)
#define	F2A(f)	(f->f_audit_data)

#define	u_ad    ((U2A(u))->tad_ad)
#define	ad_ctrl ((U2A(u))->tad_ctrl)
#define	ad_flag ((U2A(u))->tad_flag)

#define	AU_BUFSIZE	128		/* buffer size for the buffer pool */

struct au_buff {
	char		buf[AU_BUFSIZE];
	struct au_buff	*next_buf;
	struct au_buff	*next_rec;
	ushort_t	rec_len;
	uchar_t		len;
	uchar_t		flag;
};

typedef struct au_buff au_buff_t;

/*
 * Kernel audit queue structure.
 */
struct audit_queue {
	au_buff_t *head;	/* head of queue */
	au_buff_t *tail;	/* tail of queue */
	ssize_t	cnt;		/* number elements on queue */
	size_t	hiwater;	/* high water mark to block */
	size_t	lowater;	/* low water mark to restart */
	size_t	bufsz;		/* audit trail write buffer size */
	size_t	buflen;		/* audit trail buffer length in use */
	clock_t	delay;		/* delay before flushing queue */
	int	wt_block;	/* writer is blocked (1) */
	int	rd_block;	/* reader is blocked (1) */
	kmutex_t lock;		/* mutex lock for queue modification */
	kcondvar_t write_cv;	/* sleep structure for write block */
	kcondvar_t read_cv;	/* sleep structure for read block */
};


union rval;
struct audit_s2e {
	au_event_t (*au_init)(au_event_t);
				/* convert au_event to real audit event ID */

	int au_event;		/* default audit event for this system call */
	void (*au_start)(struct t_audit_data *);
				/* pre-system call audit processing */
	void (*au_finish)(struct t_audit_data *, int, union rval *);
				/* post-system call audit processing */
	int au_ctrl;		/* control flags for auditing actions */
};

extern struct audit_s2e audit_s2e[];

#define	AUK_VALID	0x5A5A5A5A
#define	AUK_INVALID	0
/*
 * per zone audit context
 */
struct au_kcontext {
	uint32_t		auk_valid;
	zoneid_t		auk_zid;

	boolean_t		auk_hostaddr_valid;
	int			auk_sequence;
	int			auk_auditstate;
	int			auk_output_active;
	struct vnode		*auk_current_vp;
	int			auk_policy;

	struct audit_queue	auk_queue;

	au_dbuf_t		*auk_dbuffer;	/* auditdoor output */

	au_stat_t		auk_statistics;

	struct auditinfo_addr	auk_info;
	kmutex_t		auk_eagain_mutex; /* door call retry */
	kcondvar_t		auk_eagain_cv;
	kmutex_t		auk_fstat_lock;	/* audit file statistics lock */
	au_fstat_t		auk_file_stat;	/* file statistics */

	taskq_t			*auk_taskq;	/* output thread */

	/* Only one audit svc per zone at a time */
	/* With the elimination of auditsvc, can this also go? see 6648414 */
	kmutex_t 		auk_svc_lock;

	au_state_t		auk_ets[MAX_KEVENTS + 1];
};
#ifndef AUK_CONTEXT_T
#define	AUK_CONTEXT_T
typedef struct au_kcontext au_kcontext_t;
#endif

extern zone_key_t au_zone_key;

/*
 * Kernel auditing external variables
 */
extern int audit_policy;
extern int audit_active;
extern int audit_load;
extern int au_auditstate;

extern struct audit_queue au_queue;
extern struct p_audit_data *pad0;
extern struct t_audit_data *tad0;

/*
 * audit_path support routines
 */
void au_pathhold(struct audit_path *);
void au_pathrele(struct audit_path *);
struct audit_path *au_pathdup(const struct audit_path *, int, int);

/*
 * Macros to hide asynchronous, non-blocking audit record start and finish
 * processing.
 *
 * NOTE: must be used in (void) funcction () { ... }
 */

#define	AUDIT_ASYNC_START(rp, audit_event, sorf) \
{ \
	label_t jb; \
	if (setjmp(&jb)) { \
		/* cleanup any residual audit data */ \
		audit_async_drop((caddr_t *)&(rp), 0); \
		return; \
	} \
	/* auditing enabled and we're preselected for this event? */ \
	if (audit_async_start(&jb, audit_event, sorf)) { \
		return; \
	} \
}

#define	AUDIT_ASYNC_FINISH(rp, audit_event, event_modifier) \
	audit_async_finish((caddr_t *)&(rp), audit_event, event_modifier);


#ifdef	_KERNEL
au_buff_t *au_get_buff(void), *au_free_buff(au_buff_t *);
#endif

/*
 * Macro for uniform "subject" token(s) generation
 */
#define	AUDIT_SETSUBJ_GENERIC(u, c, a, k, p)		\
	(au_write((u), au_to_subject(crgetuid(c),	\
	    crgetgid(c), crgetruid(c), crgetrgid(c),	\
	    p, (a)->ai_auid, (a)->ai_asid,		\
	    &((a)->ai_termid))));			\
	((is_system_labeled()) ?  au_write((u),		\
	    au_to_label(CR_SL((c)))) : (void) 0);	\
	(((k)->auk_policy & AUDIT_GROUP) ? au_write((u),\
	    au_to_groups(crgetgroups(c),		\
	    crgetngroups(c))) : (void) 0)

#define	AUDIT_SETSUBJ(u, c, a, k)      		\
	AUDIT_SETSUBJ_GENERIC(u, c, a, k, curproc->p_pid)

/*
 * Macros for type conversion
 */

/* au_membuf head, to typed data */
#define	memtod(x, t)	((t)x->buf)

/* au_membuf types */
#define	MT_FREE		0	/* should be on free list */
#define	MT_DATA		1	/* dynamic (data) allocation */

/* flags to au_memget */
#define	DONTWAIT	0
#define	WAIT		1

#define	AU_PACK	1	/* pack data in au_append_rec() */
#define	AU_LINK 0	/* link data in au_append_rec() */

/* flags to async routines */
#define	AU_BACKEND	1	/* called from softcall backend */

#ifdef __cplusplus
}
#endif

#endif /* _BSM_AUDIT_KERNEL_H */
