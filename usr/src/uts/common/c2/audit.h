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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains the declarations of the various data structures
 * used by the auditing module(s).
 */

#ifndef	_BSM_AUDIT_H
#define	_BSM_AUDIT_H

#ifdef __cplusplus
extern "C" {
#endif


#include <sys/shm.h>	/* for shmid_ds structure */
#include <sys/sem.h>	/* for semid_ds structure */
#include <sys/msg.h>	/* for msqid_ds structure */
#include <sys/atomic.h>	/* using atomics */
#include <sys/secflags.h>

/*
 * Audit conditions, statements reguarding what's to be done with
 * audit records.  None of the "global state" is returned by an
 * auditconfig -getcond call.  AUC_NOSPACE no longer seems used.
 */
/* global state */
#define	AUC_UNSET	0	/* on/off hasn't been decided */
#define	AUC_ENABLED	1	/* loaded and enabled */
/* pseudo state used in libbsm */
#define	AUC_DISABLED	0x100	/* c2audit module is excluded */
/* local zone state */
#define	AUC_AUDITING	0x1	/* audit daemon is active */
#define	AUC_NOAUDIT	0x2	/* audit daemon is not active */
#define	AUC_INIT_AUDIT	0x4	/* audit ready but auditd has not run */
#define	AUC_NOSPACE	0x8	/* audit enabled, no space for audit records */

/*
 * The user id -2 is never audited - in fact, a setauid(AU_NOAUDITID)
 * will turn off auditing.
 */
#define	AU_NOAUDITID	((au_id_t)-2)

/*
 * success/failure bits for asynchronous events
 */

#define	AUM_SUCC	1	/* use the system success preselection mask */
#define	AUM_FAIL	2	/* use the system failure preselection mask */


/*
 * Defines for event modifier field
 */
#define	PAD_READ	0x0001		/* object read */
#define	PAD_WRITE	0x0002		/* object write */
#define	PAD_NONATTR	0x4000		/* non-attributable event */
#define	PAD_FAILURE	0x8000		/* fail audit event */
#define	PAD_SPRIVUSE	0x0080		/* successfully used privileged */
#define	PAD_FPRIVUSE	0x0100		/* failed use of privileged */

/*
 * Some typedefs for the fundamentals
 */
typedef uint_t au_asid_t;
typedef uint_t  au_class_t;
typedef ushort_t au_event_t;
typedef ushort_t au_emod_t;
typedef uid_t au_id_t;

/*
 * An audit event mask.
 */
#define	AU_MASK_ALL	0xFFFFFFFF	/* all bits on for unsigned int */
#define	AU_MASK_NONE	0x0		/* all bits off = no:invalid class */

struct au_mask {
	unsigned int	am_success;	/* success bits */
	unsigned int	am_failure;	/* failure bits */
};
typedef struct au_mask au_mask_t;
#define	as_success am_success
#define	as_failure am_failure

/*
 * The structure of the terminal ID (ipv4)
 */
struct au_tid {
	dev_t port;
	uint_t machine;
};

#if defined(_SYSCALL32)
struct au_tid32 {
	uint_t port;
	uint_t machine;
};

typedef struct au_tid32 au_tid32_t;
#endif

typedef struct au_tid au_tid_t;

/*
 * The structure of the terminal ID (ipv6)
 */
struct au_tid_addr {
	dev_t  at_port;
	uint_t at_type;
	uint_t at_addr[4];
};

struct au_port_s {
	uint32_t at_major;	/* major # */
	uint32_t at_minor;	/* minor # */
};
typedef struct au_port_s au_port_t;

struct au_tid_addr64 {
	au_port_t	at_port;
	uint_t		at_type;
	uint_t		at_addr[4];
};
typedef struct au_tid_addr64 au_tid64_addr_t;

#if defined(_SYSCALL32)
struct au_tid_addr32 {
	uint_t at_port;
	uint_t at_type;
	uint_t at_addr[4];
};

typedef struct au_tid_addr32 au_tid32_addr_t;
#endif

typedef struct au_tid_addr au_tid_addr_t;

struct au_ip {
	uint16_t	at_r_port;	/* remote port */
	uint16_t	at_l_port;	/* local port */
	uint32_t	at_type;	/* AU_IPv4,... */
	uint32_t	at_addr[4];	/* remote IP */
};
typedef struct au_ip au_ip_t;

/*
 * Generic network address structure
 */
struct au_generic_tid {
	uchar_t	gt_type;	/* AU_IPADR, AU_DEVICE,... */
	union {
		au_ip_t		at_ip;
		au_port_t	at_dev;
	} gt_adr;
};
typedef struct au_generic_tid au_generic_tid_t;

/*
 * au_generic_tid_t gt_type values
 * 0 is reserved for uninitialized data
 */
#define	AU_IPADR	1
#define	AU_ETHER	2
#define	AU_DEVICE	3

/*
 * at_type values - address length used to identify address type
 */
#define	AU_IPv4 4	/* ipv4 type IP address */
#define	AU_IPv6 16	/* ipv6 type IP address */

/*
 * Compatability with SunOS 4.x BSM module
 *
 * New code should not contain audit_state_t,
 * au_state_t, nor au_termid as these types
 * may go away in future releases.
 *
 * typedef new-5.x-bsm-name old-4.x-bsm-name
 */

typedef au_class_t au_state_t;
typedef au_mask_t audit_state_t;
typedef au_id_t auid_t;
#define	ai_state ai_mask;

/*
 * Opcodes for bsm system calls
 */

#define	BSM_GETAUID		19
#define	BSM_SETAUID		20
#define	BSM_GETAUDIT		21
#define	BSM_SETAUDIT		22
/*				23	OBSOLETE */
/*				24	OBSOLETE */
#define	BSM_AUDIT		25
/* 				26	OBSOLETE */
/* 				27	EOL announced for Sol 10 */
/*				28	OBSOLETE */
#define	BSM_AUDITCTL		29
/*				30	OBSOLETE */
/*				31	OBSOLETE */
/*				32	OBSOLETE */
/*				33	OBSOLETE */
/*				34	OBSOLETE */
#define	BSM_GETAUDIT_ADDR	35
#define	BSM_SETAUDIT_ADDR	36
#define	BSM_AUDITDOOR		37

/*
 * auditon(2) commands
 */
#define	A_GETPOLICY	2	/* get audit policy */
#define	A_SETPOLICY	3	/* set audit policy */
#define	A_GETKMASK	4	/* get non-attributable event audit mask */
#define	A_SETKMASK	5	/* set non-attributable event audit mask */
#define	A_GETQCTRL	6	/* get kernel audit queue ctrl parameters */
#define	A_SETQCTRL	7	/* set kernel audit queue ctrl parameters */
#define	A_GETCWD	8	/* get process current working directory */
#define	A_GETCAR	9	/* get process current active root */
#define	A_GETSTAT	12	/* get audit statistics */
#define	A_SETSTAT	13	/* (re)set audit statistics */
#define	A_SETUMASK	14	/* set preselection mask for procs with auid */
#define	A_SETSMASK	15	/* set preselection mask for procs with asid */
#define	A_GETCOND	20	/* get audit system on/off condition */
#define	A_SETCOND	21	/* set audit system on/off condition */
#define	A_GETCLASS	22	/* get audit event to class mapping */
#define	A_SETCLASS	23	/* set audit event to class mapping */
#define	A_GETPINFO	24	/* get audit info for an arbitrary pid */
#define	A_SETPMASK	25	/* set preselection mask for an given pid */
#define	A_GETPINFO_ADDR	28	/* get audit info for an arbitrary pid */
#define	A_GETKAUDIT	29	/* get kernel audit characteristics */
#define	A_SETKAUDIT	30	/* set kernel audit characteristics */
#define	A_GETAMASK	31	/* set user default audit event mask */
#define	A_SETAMASK	32	/* get user default audit event mask */

/*
 * Audit Policy parameters (32 bits)
 */
#define	AUDIT_CNT	0x0001	/* do NOT sleep undelivered synch events */
#define	AUDIT_AHLT	0x0002	/* HALT machine on undelivered async event */
#define	AUDIT_ARGV	0x0004	/* include argv with execv system call events */
#define	AUDIT_ARGE	0x0008	/* include arge with execv system call events */
#define	AUDIT_SEQ	0x0010	/* include sequence attribute */
#define	AUDIT_GROUP	0x0040	/* include group attribute with each record */
#define	AUDIT_TRAIL	0x0080	/* include trailer token */
#define	AUDIT_PATH	0x0100	/* allow multiple paths per event */
#define	AUDIT_SCNT	0x0200	/* sleep user events but not kernel events */
#define	AUDIT_PUBLIC	0x0400	/* audit even "public" files */
#define	AUDIT_ZONENAME	0x0800	/* emit zonename token */
#define	AUDIT_PERZONE	0x1000	/* auditd and audit queue for each zone */
#define	AUDIT_WINDATA_DOWN	0x2000	/* include paste downgraded data */
#define	AUDIT_WINDATA_UP	0x4000	/* include paste upgraded data */

/*
 * If AUDIT_GLOBAL changes, corresponding changes are required in
 * audit_syscalls.c's setpolicy().
 */
#define	AUDIT_GLOBAL	(AUDIT_AHLT | AUDIT_PERZONE)
#define	AUDIT_LOCAL	(AUDIT_CNT | AUDIT_ARGV | AUDIT_ARGE |\
			AUDIT_SEQ | AUDIT_GROUP | AUDIT_TRAIL | AUDIT_PATH |\
			AUDIT_PUBLIC | AUDIT_SCNT | AUDIT_ZONENAME |\
			AUDIT_WINDATA_DOWN | AUDIT_WINDATA_UP)

/*
 * Kernel audit queue control parameters
 *
 *	audit record recording blocks at hiwater # undelived records
 *	audit record recording resumes at lowwater # undelivered audit records
 *	bufsz determines how big the data xfers will be to the audit trail
 */
struct au_qctrl {
	size_t	aq_hiwater;	/* kernel audit queue, high water mark */
	size_t	aq_lowater;	/* kernel audit queue, low  water mark */
	size_t	aq_bufsz;	/* kernel audit queue, write size to trail */
	clock_t	aq_delay;	/* delay before flushing audit queue */
};

#if defined(_SYSCALL32)
struct au_qctrl32 {
	size32_t	aq_hiwater;
	size32_t	aq_lowater;
	size32_t	aq_bufsz;
	clock32_t	aq_delay;
};
#endif


/*
 * default values of hiwater and lowater (note hi > lo)
 */
#define	AQ_HIWATER  100
#define	AQ_MAXHIGH  100000
#define	AQ_LOWATER  10
#define	AQ_BUFSZ    8192
#define	AQ_MAXBUFSZ 1048576
#define	AQ_DELAY    20
#define	AQ_MAXDELAY 20000

struct auditinfo {
	au_id_t		ai_auid;
	au_mask_t	ai_mask;
	au_tid_t	ai_termid;
	au_asid_t	ai_asid;
};

#if defined(_SYSCALL32)
struct auditinfo32 {
	au_id_t		ai_auid;
	au_mask_t	ai_mask;
	au_tid32_t	ai_termid;
	au_asid_t	ai_asid;
};

typedef struct auditinfo32 auditinfo32_t;
#endif

typedef struct auditinfo auditinfo_t;

struct k_auditinfo_addr {
	au_id_t		ai_auid;
	au_mask_t	ai_amask;	/* user default preselection mask */
	au_mask_t	ai_namask;	/* non-attributable mask */
	au_tid_addr_t	ai_termid;
	au_asid_t	ai_asid;
};
typedef struct k_auditinfo_addr k_auditinfo_addr_t;

struct auditinfo_addr {
	au_id_t		ai_auid;
	au_mask_t	ai_mask;
	au_tid_addr_t	ai_termid;
	au_asid_t	ai_asid;
};

struct auditinfo_addr64 {
	au_id_t		ai_auid;
	au_mask_t	ai_mask;
	au_tid64_addr_t	ai_termid;
	au_asid_t	ai_asid;
};
typedef struct auditinfo_addr64 auditinfo64_addr_t;

#if defined(_SYSCALL32)
struct auditinfo_addr32 {
	au_id_t		ai_auid;
	au_mask_t	ai_mask;
	au_tid32_addr_t	ai_termid;
	au_asid_t	ai_asid;
};

typedef struct auditinfo_addr32 auditinfo32_addr_t;
#endif

typedef struct auditinfo_addr auditinfo_addr_t;

struct auditpinfo {
	pid_t		ap_pid;
	au_id_t		ap_auid;
	au_mask_t	ap_mask;
	au_tid_t	ap_termid;
	au_asid_t	ap_asid;
};

#if defined(_SYSCALL32)
struct auditpinfo32 {
	pid_t		ap_pid;
	au_id_t		ap_auid;
	au_mask_t	ap_mask;
	au_tid32_t	ap_termid;
	au_asid_t	ap_asid;
};
#endif


struct auditpinfo_addr {
	pid_t		ap_pid;
	au_id_t		ap_auid;
	au_mask_t	ap_mask;
	au_tid_addr_t	ap_termid;
	au_asid_t	ap_asid;
};

#if defined(_SYSCALL32)
struct auditpinfo_addr32 {
	pid_t		ap_pid;
	au_id_t		ap_auid;
	au_mask_t	ap_mask;
	au_tid32_addr_t	ap_termid;
	au_asid_t	ap_asid;
};
#endif


struct au_evclass_map {
	au_event_t	ec_number;
	au_class_t	ec_class;
};
typedef struct au_evclass_map au_evclass_map_t;

/*
 * Audit stat structures (used to be in audit_stat.h
 */

struct audit_stat {
	unsigned int as_version;	/* version of kernel audit code */
	unsigned int as_numevent;	/* number of kernel audit events */
	uint32_t as_generated;		/* # records processed */
	uint32_t as_nonattrib;		/* # non-attributed records produced */
	uint32_t as_kernel;		/* # records produced by kernel */
	uint32_t as_audit;		/* # records processed by audit(2) */
	uint32_t as_auditctl;		/* # records processed by auditctl(2) */
	uint32_t as_enqueue;		/* # records put onto audit queue */
	uint32_t as_written;		/* # records written to audit trail */
	uint32_t as_wblocked;		/* # times write blked on audit queue */
	uint32_t as_rblocked;		/* # times read blked on audit queue */
	uint32_t as_dropped;		/* # of dropped audit records */
	uint32_t as_totalsize;		/* total number bytes of audit data */
	uint32_t as_memused;		/* no longer used */
};
typedef struct audit_stat au_stat_t;

/* get kernel audit context dependent on AUDIT_PERZONE policy */
#define	GET_KCTX_PZ	(audit_policy & AUDIT_PERZONE) ?\
			    curproc->p_zone->zone_audit_kctxt :\
			    global_zone->zone_audit_kctxt
/* get kernel audit context of global zone */
#define	GET_KCTX_GZ	global_zone->zone_audit_kctxt
/* get kernel audit context of non-global zone */
#define	GET_KCTX_NGZ	curproc->p_zone->zone_audit_kctxt

#define	AS_INC(a, b, c) atomic_add_32(&(c->auk_statistics.a), (b))
#define	AS_DEC(a, b, c) atomic_add_32(&(c->auk_statistics.a), -(b))

/*
 * audit token IPC types (shm, sem, msg) [for ipc attribute]
 */

#define	AT_IPC_MSG	((char)1)		/* message IPC id */
#define	AT_IPC_SEM	((char)2)		/* semaphore IPC id */
#define	AT_IPC_SHM	((char)3)		/* shared memory IPC id */

#if defined(_KERNEL)

#ifdef __cplusplus
}
#endif

#include <sys/types.h>
#include <sys/model.h>
#include <sys/proc.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <netinet/in.h>
#include <c2/audit_door_infc.h>
#include <sys/crypto/ioctladmin.h>
#include <sys/netstack.h>
#include <sys/zone.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fcntla;
struct t_audit_data;
struct audit_path;
struct priv_set;
struct devplcysys;

struct auditcalls {
	long	code;
	long	a1;
	long	a2;
	long	a3;
	long	a4;
	long	a5;
};

int	audit(caddr_t, int);
int	auditsys(struct auditcalls *, union rval *); /* fake stub */
void	audit_cryptoadm(int, char *, crypto_mech_name_t *,
	    uint_t, uint_t, uint32_t, int);
void	audit_init(void);
void	audit_init_module(void);
void	audit_newproc(struct proc *);
void	audit_pfree(struct proc *);
void	audit_thread_create(kthread_id_t);
void	audit_thread_free(kthread_id_t);
int	audit_savepath(struct pathname *, struct vnode *, struct vnode *,
		int, cred_t *);
void	audit_anchorpath(struct pathname *, int);
void	audit_symlink(struct pathname *, struct pathname *);
void	audit_symlink_create(struct vnode *, char *, char *, int);
int	object_is_public(struct vattr *);
void	audit_attributes(struct vnode *);
void	audit_falloc(struct file *);
void	audit_unfalloc(struct file *);
void	audit_exit(int, int);
void	audit_core_start(int);
void	audit_core_finish(int);
void	audit_strgetmsg(struct vnode *, struct strbuf *, struct strbuf *,
		unsigned char *, int *, int);
void	audit_strputmsg(struct vnode *, struct strbuf *, struct strbuf *,
		unsigned char, int, int);
void	audit_closef(struct file *);
void	audit_setf(struct file *, int);
void	audit_reboot(void);
void	audit_vncreate_start(void);
void	audit_setfsat_path(int argnum);
void	audit_vncreate_finish(struct vnode *, int);
void	audit_exec(const char *, const char *, ssize_t, ssize_t, cred_t *);
void	audit_enterprom(int);
void	audit_exitprom(int);
void	audit_chdirec(struct vnode *, struct vnode **);
void	audit_sock(int, struct queue *, struct msgb *, int);
int	audit_start(unsigned int, unsigned int, uint32_t, int, klwp_t *);
void	audit_finish(unsigned int, unsigned int, int, union rval *);
int	audit_async_start(label_t *, au_event_t, int);
void	audit_async_finish(caddr_t *, au_event_t, au_emod_t, timestruc_t *);
void	audit_async_discard_backend(void *);
void	audit_async_done(caddr_t *, int);
void	audit_async_drop(caddr_t *, int);

#ifndef AUK_CONTEXT_T
#define	AUK_CONTEXT_T
typedef struct au_kcontext au_kcontext_t;
#endif

/* Zone audit context setup routine */
void au_zone_setup(void);

/*
 * c2audit module states
 */
#define	C2AUDIT_DISABLED    0	/* c2audit module excluded in /etc/system */
#define	C2AUDIT_UNLOADED    1	/* c2audit module not loaded */
#define	C2AUDIT_LOADED	    2	/* c2audit module loaded */

uint32_t    audit_getstate(void);
int	    au_zone_getstate(const au_kcontext_t *);

/* The audit mask defining in which case is auditing enabled */
#define	AU_AUDIT_MASK	(AUC_AUDITING | AUC_NOSPACE)

/*
 * Get the given zone audit status. zcontext != NULL serves
 * as a protection when c2audit module is not loaded.
 */
#define	AU_ZONE_AUDITING(zcontext)	    \
	(audit_active == C2AUDIT_LOADED &&  \
	    ((AU_AUDIT_MASK) & au_zone_getstate((zcontext))))

/*
 * Get auditing status
 */
#define	AU_AUDITING() (audit_getstate())

int	audit_success(au_kcontext_t *, struct t_audit_data *, int, cred_t *);
int	auditme(au_kcontext_t *, struct t_audit_data *, au_state_t);
void	audit_fixpath(struct audit_path *, int);
void	audit_ipc(int, int, void *);
void	audit_ipcget(int, void *);
void	audit_fdsend(int, struct file *, int);
void	audit_fdrecv(int, struct file *);
void	audit_priv(int, const struct priv_set *, int);
void	audit_setppriv(int, int, const struct priv_set *, const cred_t *);
void	audit_psecflags(proc_t *, psecflagwhich_t,
    const secflagdelta_t *);
void	audit_devpolicy(int, const struct devplcysys *);
void	audit_update_context(proc_t *, cred_t *);
void	audit_kssl(int, void *, int);
void	audit_pf_policy(int, cred_t *, netstack_t *, char *, boolean_t, int,
    pid_t);
void	audit_sec_attributes(caddr_t *, struct vnode *);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _BSM_AUDIT_H */
