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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/mode.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/t_lock.h>
#include <sys/poll.h>
#include <sys/debug.h>
#include <sys/cred.h>
#include <sys/lockfs.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_panic.h>
#include <sys/fs/ufs_lockfs.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_mount.h>
#include <sys/fs/ufs_prot.h>
#include <sys/fs/ufs_bio.h>
#include <sys/pathname.h>
#include <sys/utsname.h>
#include <sys/conf.h>

/* handy */
#define	abs(x)		((x) < 0? -(x): (x))

#if defined(DEBUG)

#define	DBGLVL_NONE	0x00000000
#define	DBGLVL_MAJOR	0x00000100
#define	DBGLVL_MINOR	0x00000200
#define	DBGLVL_MINUTE	0x00000400
#define	DBGLVL_TRIVIA	0x00000800
#define	DBGLVL_HIDEOUS	0x00001000

#define	DBGFLG_NONE		0x00000000
#define	DBGFLG_NOPANIC		0x00000001
#define	DBGFLG_LVLONLY		0x00000002
#define	DBGFLG_FIXWOULDPANIC	0x00000004

#define	DBGFLG_FLAGMASK		0x0000000F
#define	DBGFLG_LEVELMASK	~DBGFLG_FLAGMASK

#define	DEBUG_FLAGS	(ufs_fix_failure_dbg & DBGFLG_FLAGMASK)
#define	DEBUG_LEVEL	(ufs_fix_failure_dbg & DBGFLG_LEVELMASK)

unsigned int ufs_fix_failure_dbg =	DBGLVL_NONE | DBGFLG_NONE;

#define	DCALL(dbg_level, call)						\
	{								\
		if (DEBUG_LEVEL != DBGLVL_NONE) {			\
			if (DEBUG_FLAGS & DBGFLG_LVLONLY) {		\
				if (DEBUG_LEVEL & dbg_level) {		\
					call;				\
				}					\
			} else {					\
				if (dbg_level <= DEBUG_LEVEL) {		\
					call;				\
				}					\
			}						\
		}							\
	}

#define	DPRINTF(dbg_level, msg)		DCALL(dbg_level, printf msg)

#define	MAJOR(msg)			DPRINTF(DBGLVL_MAJOR, msg)
#define	MINOR(msg)			DPRINTF(DBGLVL_MINOR, msg)
#define	MINUTE(msg)			DPRINTF(DBGLVL_MINUTE, msg)
#define	TRIVIA(msg)			DPRINTF(DBGLVL_TRIVIA, msg)
#define	HIDEOUS(msg)			DPRINTF(DBGLVL_HIDEOUS, msg)

#else	/* !DEBUG */

#define	DCALL(ignored_dbg_level, ignored_routine)
#define	MAJOR(ignored)
#define	MINOR(ignored)
#define	MINUTE(ignored)
#define	TRIVIA(ignored)
#define	HIDEOUS(ignored)

#endif /* DEBUG */

#define	NULLSTR(str)	(!(str) || *(str) == '\0'? "<null>" : (str))
#define	NULSTRING	""

/* somewhat arbitrary limits, in seconds */
/* all probably ought to be different, but these are convenient for debugging */
const time_t	UF_TOO_LONG		= 128;	/* max. wait for fsck start */

/* all of these are in units of seconds used for retry period while ... */
const time_t	UF_FIXSTART_PERIOD	= 16;	/* awaiting fsck start */
const time_t	UF_FIXPOLL_PERIOD	= 256;	/* awaiting fsck finish */
const time_t	UF_SHORT_ERROR_PERIOD	= 4;	/* after (lockfs) error */
const time_t	UF_LONG_ERROR_PERIOD	= 512;	/* after (lockfs) error */

#define	NO_ERROR		0
#define	LOCKFS_OLOCK		LOCKFS_MAXLOCK+1

const ulong_t	GB			= 1024 * 1024 * 1024;
const ulong_t	SecondsPerGig		= 1024;	/* ~17 minutes (overestimate) */

/*
 * per filesystem flags
 */
const int	UFSFX_PANIC		= (UFSMNT_ONERROR_PANIC >> 4);
const int	UFSFX_LCKONLY		= (UFSMNT_ONERROR_LOCK >> 4);
const int	UFSFX_LCKUMOUNT		= (UFSMNT_ONERROR_UMOUNT >> 4);
const int	UFSFX_DEFAULT		= (UFSMNT_ONERROR_DEFAULT >> 4);
const int	UFSFX_REPAIR_START	= 0x10000000;

/* return protocols */

typedef enum triage_return_code {
	TRIAGE_DEAD = -1,
	TRIAGE_NO_SPIRIT,
	TRIAGE_ATTEND_TO
} triage_t;

typedef enum statefunc_return_code {
	SFRC_SUCCESS = 1,
	SFRC_FAIL = 0
} sfrc_t;

/* external references */
/* in ufs_thread.c */
extern int	ufs_thread_run(struct ufs_q *, callb_cpr_t *cprinfop);
extern int	ufs_checkaccton(vnode_t *);		/* in ufs_lockfs.c */
extern int	ufs_checkswapon(vnode_t *);		/* in ufs_lockfs.c */

extern struct pollhead		ufs_pollhd;		/* in ufs_vnops.c */

/* globals */
struct	ufs_q	 ufs_fix;

/*
 * patchable constants:
 *   These are set in ufsfx_init() [called at modload]
 */
struct ufs_failure_tunable {
	long	 uft_too_long;		/* limit repair startup time */
	long	 uft_fixstart_period;	/* pre-repair start period */
	long	 uft_fixpoll_period;	/* post-fsck start period */
	long	 uft_short_err_period;	/* post-error short period */
	long	 uft_long_err_period;	/* post-error long period */
} ufsfx_tune;

/* internal statistics of events */
struct uf_statistics {
	ulong_t		ufst_lock_violations;
	ulong_t		ufst_current_races;
	ulong_t		ufst_unmount_failures;
	ulong_t		ufst_num_fixed;
	ulong_t		ufst_num_failed;
	ulong_t		ufst_cpu_waste;
	time_t		ufst_last_start_tm;
	kmutex_t	ufst_mutex;
} uf_stats;

typedef enum state_action {
	UFA_ERROR = -1,		/* internal error */
	UFA_FOUND,		/* found uf in state */
	UFA_SET			/* change uf to state */
} ufsa_t;

/* state definition */
typedef struct uf_state_desc {
	int	  ud_v;					/* value */
	char	 *ud_name;				/* name */
	sfrc_t	(*ud_sfp)(ufs_failure_t *, ufsa_t, ufs_failure_states_t);
							/* per-state actions */
	ufs_failure_states_t	  ud_prev;		/* valid prev. states */

	struct uf_state_desc_attr {
		unsigned	terminal:1;	/* no action req. if found */
		unsigned	at_fail:1;	/* state set by thread */
						/* encountering the error */
		unsigned	unused;
	} ud_attr;
} ufsd_t;

/*
 * forward references
 */

/* thread to watch for failures */
static void	ufsfx_thread_fix_failures(void *);
static int 	ufsfx_do_failure_q(void);
static void	ufsfx_kill_fix_failure_thread(void *);

/* routines called when failure occurs */
static int		 ufs_fault_v(vnode_t *, char *, va_list)
	__KVPRINTFLIKE(2);
static ufs_failure_t	*init_failure(vnode_t *, char *, va_list)
	__KVPRINTFLIKE(2);
static void		 queue_failure(ufs_failure_t *);
/*PRINTFLIKE2*/
static void		 real_panic(ufs_failure_t *, const char *, ...)
	__KPRINTFLIKE(2);
static void		 real_panic_v(ufs_failure_t *, const char *, va_list)
	__KVPRINTFLIKE(2);
static triage_t		 triage(vnode_t *);

/* routines called when failure record is acted upon */
static sfrc_t	set_state(ufs_failure_t *, ufs_failure_states_t);
static int	state_trans_valid(ufs_failure_states_t, ufs_failure_states_t);
static int	terminal_state(ufs_failure_states_t);

/* routines called when states entered/found */
static sfrc_t	sf_minimum(ufs_failure_t *, ufsa_t, ufs_failure_states_t);
static sfrc_t	sf_undef(ufs_failure_t *, ufsa_t, ufs_failure_states_t);
static sfrc_t	sf_init(ufs_failure_t *, ufsa_t, ufs_failure_states_t);
static sfrc_t	sf_queue(ufs_failure_t *, ufsa_t, ufs_failure_states_t);
static sfrc_t	sf_found_queue(ufs_failure_t *);
static sfrc_t	sf_nonterm_cmn(ufs_failure_t *, ufsa_t, ufs_failure_states_t);
static sfrc_t	sf_term_cmn(ufs_failure_t *, ufsa_t, ufs_failure_states_t);
static sfrc_t	sf_panic(ufs_failure_t *, ufsa_t, ufs_failure_states_t);
static sfrc_t	sf_set_trylck(ufs_failure_t *);
static sfrc_t	sf_set_locked(ufs_failure_t *);
static sfrc_t	sf_found_trylck(ufs_failure_t *);
static sfrc_t	sf_found_lock_fix_cmn(ufs_failure_t *, ufs_failure_states_t);
static sfrc_t	sf_found_umount(ufs_failure_t *);

/* support routines, called by sf_nonterm_cmn and sf_term_cmn */
static time_t 	trylock_time_exceeded(ufs_failure_t *);
static void 	pester_msg(ufs_failure_t *, int);
static int 	get_lockfs_status(ufs_failure_t *, struct lockfs *);
static void 	alloc_lockfs_comment(ufs_failure_t *, struct lockfs *);
static int 	set_lockfs(ufs_failure_t *, struct lockfs *);
static int 	lockfs_failure(ufs_failure_t *);
static int 	lockfs_success(ufs_failure_t *);
static int	fsck_active(ufs_failure_t *);

/* low-level support routines */
static ufsd_t	*get_state_desc(ufs_failure_states_t);
static char	*fs_name(ufs_failure_t *);

#if defined(DEBUG)
static char	*state_name(ufs_failure_states_t);
static char	*lock_name(struct lockfs *);
static char	*err_name(int);
static char	*act_name(ufsa_t);
static void	 dump_uf_list(char *msg);
static void	 dump_uf(ufs_failure_t *, int i);
#endif /* DEBUG */
/*
 *
 * State Transitions:
 *
 * normally:
 * if flagged to be locked but not unmounted:	(UFSMNT_ONERROR_LOCK)
 *	UNDEF -> INIT -> QUEUE -> TRYLCK -> LOCKED -> FIXING -> FIXED
 *
 * The only difference between these two is that the fsck must be started
 * manually.
 *
 * if flagged to be unmounted:			(UFSMNT_ONERROR_UMOUNT)
 *	UNDEF -> INIT -> QUEUE -> TRYLCK -> LOCKED -> UMOUNT -> NOTFIX
 *
 * if flagged to panic:				(UFSMNT_ONERROR_PANIC)
 *	UNDEF -> INIT -> PANIC
 *
 * if a secondary panic on a file system which has an active failure
 * record:
 *	UNDEF -> INIT -> QUEUE -> REPLICA
 *
 * UNDEF, INIT, QUEUE all are set in the context of the failing thread.
 * All other states (except possibly PANIC) are set in by the monitor
 * (lock) thread.
 *
 */

ufsd_t	state_desc[] =
{
	{ UF_ILLEGAL,	"in an unknown state",	sf_minimum,	UF_ILLEGAL,
								{ 0, 1, 0 } },
	{ UF_UNDEF,	"undefined",		sf_undef,	UF_UNDEF,
								{ 0, 1, 0 } },
	{ UF_INIT,	"being initialized",	sf_init,	UF_UNDEF,
								{ 0, 1, 0 } },
	{ UF_QUEUE,	"queued",		sf_queue,	UF_INIT,
								{ 0, 1, 0 } },
	{ UF_TRYLCK,	"trying to be locked",	sf_nonterm_cmn,
						UF_QUEUE,	{ 0, 0, 0 } },
	{ UF_LOCKED,	"locked",		sf_nonterm_cmn,
					UF_TRYLCK | UF_FIXING,	{ 0, 0, 0 } },
	{ UF_UMOUNT,	"being unmounted",	sf_nonterm_cmn,

#if defined(DEBUG)
					UF_PANIC |
#endif /* DEBUG */
					UF_TRYLCK | UF_LOCKED, 	{ 0, 0, 0 } },
	{ UF_FIXING,	"being fixed",		sf_nonterm_cmn,
						UF_LOCKED,	{ 0, 0, 0 } },
	{ UF_FIXED,	"fixed",		sf_term_cmn,
						UF_FIXING,	{ 1, 0, 0 } },
	{ UF_NOTFIX,	"not fixed",		sf_term_cmn,

#if defined(DEBUG)
							UF_PANIC |
#endif /* DEBUG */

	    UF_QUEUE | UF_TRYLCK | UF_LOCKED | UF_UMOUNT | UF_FIXING,
								{ 1, 0, 0 } },
	{ UF_REPLICA,	"a replica",		sf_term_cmn,
						UF_QUEUE,	{ 1, 0, 0 } },
	{ UF_PANIC,	"panicking",		sf_panic,
		/* XXX make this narrower */	UF_ALLSTATES,	{ 0, 0, 0 } },
	{ UF_UNDEF,	NULL,			((sfrc_t (*)()) NULL),
						UF_UNDEF, 	{ 0, 0, 0 } }
};

/* unified collection */
struct ufsfx_info {
	struct uf_statistics		*ufi_statp;
	struct ufs_failure_tunable	*ufi_tunep;
	ufsd_t				*ufi_statetab;
} uffsinfo;

#if defined(DEBUG)
struct action_description {
	ufsa_t	 ad_v;
	char	*ad_name;
};

#define	EUNK		(-1)

struct error_description {
	int	 ed_errno;
	char	*ed_name;
} err_desc[] =
{
	{ EUNK,		"<unexpected errno?>"	},
	{ EINVAL,	"EINVAL"		},
	{ EACCES,	"EACCES"		},
	{ EPERM,	"EPERM"			},
	{ EIO,		"EIO"			},
	{ EDEADLK,	"EDEADLK"		},
	{ EBUSY,	"EBUSY"			},
	{ EAGAIN,	"EAGAIN"		},
	{ ERESTART,	"ERESTART"		},
	{ ETIMEDOUT,	"ETIMEDOUT"		},
	{ NO_ERROR,	"Ok"			},
	{ EUNK,		NULL 			}
};

struct action_description act_desc[] =
{
	{ UFA_ERROR,	"<unexpected action?>"	},
	{ UFA_FOUND,	"\"found\""	},
	{ UFA_SET,	"\"set\""	},
	{ UFA_ERROR,	NULL			},
};

#define	LOCKFS_BADLOCK	(-1)

struct lock_description {
	int	 ld_type;
	char	*ld_name;
} lock_desc[] =
{
	{ LOCKFS_BADLOCK,	"<unexpected lock?>"	},
	{ LOCKFS_ULOCK,		"Unlock"		},
	{ LOCKFS_ELOCK,		"Error Lock"		},
	{ LOCKFS_HLOCK,		"Hard Lock"		},
	{ LOCKFS_OLOCK,		"Old Lock"		},
	{ LOCKFS_BADLOCK,	NULL			}
};

#endif /* DEBUG */

/*
 * ufs_fault, ufs_fault_v
 *
 *  called instead of cmn_err(CE_PANIC, ...) by ufs routines
 *  when a failure is detected to put the file system into an
 *  error state (if possible) or to devolve to a panic otherwise
 *
 * vnode is some vnode in this file system, used to find the way
 * to ufsvfs, vfsp etc.  Since a panic can be called from many
 * levels, the vnode is the most convenient hook to pass through.
 *
 */

/*PRINTFLIKE2*/
int
ufs_fault(vnode_t *vp, char *fmt, ...)
{
	va_list	adx;
	int	error;

	MINOR(("[ufs_fault"));

	va_start(adx, fmt);
	error = ufs_fault_v(vp, fmt, adx);
	va_end(adx);

	MINOR((": %s (%d)]\n", err_name(error), error));
	return (error);
}

const char *nullfmt = "<null format?>";

static int
ufs_fault_v(vnode_t *vp, char *fmt, va_list adx)
{
	ufs_failure_t		*new = NULL;
	ufsvfs_t		*ufsvfsp;
	triage_t		 fix;
	int			 err = ERESTART;
	int			need_vfslock;

	MINOR(("[ufs_fault_v"));

	if (fmt == NULL)
		fmt = (char *)nullfmt;

	fix = triage(vp);

	if (vp) {
		ufsvfsp = (struct ufsvfs *)vp->v_vfsp->vfs_data;

		/*
		 * Something bad has happened. That is why we are here.
		 *
		 * In order for the bad thing to be recorded in the superblock
		 * we need to write to the superblock directly.
		 * In the case that logging is enabled the logging code
		 * would normally intercept our write as a delta to the log,
		 * thus we mark the filesystem FSBAD in any case.
		 */
		need_vfslock = !MUTEX_HELD(&ufsvfsp->vfs_lock);

		if (need_vfslock) {
			mutex_enter(&ufsvfsp->vfs_lock);
		}

		ufsvfsp->vfs_fs->fs_clean = FSBAD;
		ASSERT(SEMA_HELD(&ufsvfsp->vfs_bufp->b_sem));
		ufsvfsp->vfs_bufp->b_flags &=
		    ~(B_ASYNC | B_READ | B_DONE | B_ERROR | B_DELWRI);

		(void) bdev_strategy(ufsvfsp->vfs_bufp);
		(void) biowait(ufsvfsp->vfs_bufp);

		if (need_vfslock) {
			mutex_exit(&ufsvfsp->vfs_lock);
		}
	}

	switch (fix) {

	default:
	case TRIAGE_DEAD:
	case TRIAGE_NO_SPIRIT:

		real_panic_v(new, fmt, adx);
		/* LINTED: warning: logical expression always true: op "||" */
		ASSERT(DEBUG);
		err = EAGAIN;

#if defined(DEBUG)
		if (!(DEBUG_FLAGS & DBGFLG_FIXWOULDPANIC)) {
			break;
		}
		/* FALLTHROUGH */

#else
		break;

#endif /* DEBUG */

	case TRIAGE_ATTEND_TO:

		/* q thread not running yet? */
		if (mutex_tryenter(&ufs_fix.uq_mutex)) {
			if (!ufs_fix.uq_threadp) {
				mutex_exit(&ufs_fix.uq_mutex);
				ufs_thread_start(&ufs_fix,
				    ufsfx_thread_fix_failures, NULL);
				ufs_fix.uq_threadp->t_flag |= T_DONTBLOCK;
				mutex_enter(&ufs_fix.uq_mutex);
			} else {
				/*
				 * We got the lock but we are not the current
				 * threadp so we have to release the lock.
				 */
				mutex_exit(&ufs_fix.uq_mutex);
			}
		} else {
			MINOR((": fix failure thread already running "));
			/*
			 * No need to log another failure as one is already
			 * being logged.
			 */
			break;
		}

		if (ufs_fix.uq_threadp && ufs_fix.uq_threadp == curthread) {
			mutex_exit(&ufs_fix.uq_mutex);
			cmn_err(CE_WARN, "ufs_fault_v: recursive ufs_fault");
		} else {
			/*
			 * Must check if we actually still own the lock and
			 * if so then release the lock and move on with life.
			 */
			if (mutex_owner(&ufs_fix.uq_mutex) == curthread)
				mutex_exit(&ufs_fix.uq_mutex);
		}

		new = init_failure(vp, fmt, adx);
		if (new != NULL) {
			queue_failure(new);
			break;
		}
		real_panic_v(new, fmt, adx);
		break;

	}
	MINOR(("] "));
	return (err);
}

/*
 * triage()
 *
 *  Attempt to fix iff:
 *    - the system is not already panicking
 *    - this file system isn't explicitly marked not to be fixed
 *    - we can connect to the user-level daemon
 * These conditions are detectable later, but if we can determine
 * them in the failing threads context the core dump may be more
 * useful.
 *
 */

static triage_t
triage(vnode_t *vp)
{
	struct inode	 *ip;
	int		  need_unlock_vfs;
	int		  fs_flags;

	MINUTE(("[triage"));

	if (panicstr) {
		MINUTE((
		": already panicking: \"%s\" => TRIAGE_DEAD]\n", panicstr));
		return (TRIAGE_DEAD);
	}

	if (!vp || !(ip = VTOI(vp)) || !ip->i_ufsvfs) {
		MINUTE((
	": vp, ip or ufsvfs is NULL; can't determine fs => TRIAGE_DEAD]\n"));
		return (TRIAGE_DEAD);
	}

	/* use tryenter and continue no matter what since we're panicky */
	need_unlock_vfs = !MUTEX_HELD(&ip->i_ufsvfs->vfs_lock);
	if (need_unlock_vfs)
		need_unlock_vfs = mutex_tryenter(&ip->i_ufsvfs->vfs_lock);

	fs_flags = ip->i_ufsvfs->vfs_fsfx.fx_flags;
	if (need_unlock_vfs)
		mutex_exit(&ip->i_ufsvfs->vfs_lock);

	if (fs_flags & UFSFX_PANIC) {
		MINUTE((
		": filesystem marked \"panic\" => TRIAGE_NO_SPIRIT]\n"));
		return (TRIAGE_NO_SPIRIT);
	}

	if (ufs_checkaccton(vp) != 0) {
		MINUTE((
		": filesystem would deadlock (accounting) => TRIAGE_DEAD]\n"));
		return (TRIAGE_DEAD);
	}

	if (ufs_checkswapon(vp) != 0) {
		MINUTE((
		": filesystem would deadlock (swapping) => TRIAGE_DEAD]\n"));
		return (TRIAGE_DEAD);
	}

	MINUTE((": return TRIAGE_ATTEND_TO] "));
	return (TRIAGE_ATTEND_TO);
}

/*
 * init failure
 *
 * This routine allocates a failure struct and initializes
 * it's member elements.
 * Space is allocated for copies of dynamic identifying fs structures
 * passed in.  Without a much more segmented kernel architecture
 * this is as protected as we can make it (for now.)
 */
static ufs_failure_t *
init_failure(vnode_t *vp, char *fmt, va_list adx)
{
	ufs_failure_t	*new;
	struct inode	*ip;
	int		 initialization_worked = 0;
	int		 need_vfs_unlock;

	MINOR(("[init_failure"));

	new = kmem_zalloc(sizeof (ufs_failure_t), KM_NOSLEEP);
	if (!new) {
		MINOR((": kmem_zalloc failed]\n"));
		return (NULL);
	}

	/*
	 * enough information to make a fix attempt possible?
	 */
	if (!vp || !(ip = VTOI(vp)) || !ip->i_ufsvfs || !vp->v_vfsp ||
	    !ip->i_ufsvfs->vfs_bufp || !ITOF(ip) || !fmt)
		goto errout;

	if (vp->v_type != VREG && vp->v_type != VDIR &&
	    vp->v_type != VBLK && vp->v_type != VCHR &&
	    vp->v_type != VLNK && vp->v_type != VFIFO &&
	    vp->v_type != VSOCK)
		goto errout;

	if (ip->i_ufsvfs->vfs_root->v_type != VREG &&
	    ip->i_ufsvfs->vfs_root->v_type != VDIR &&
	    ip->i_ufsvfs->vfs_root->v_type != VBLK &&
	    ip->i_ufsvfs->vfs_root->v_type != VCHR &&
	    ip->i_ufsvfs->vfs_root->v_type != VLNK &&
	    ip->i_ufsvfs->vfs_root->v_type != VFIFO &&
	    ip->i_ufsvfs->vfs_root->v_type != VSOCK)
		goto errout;

	if ((ITOF(ip)->fs_magic != FS_MAGIC) &&
	    (ITOF(ip)->fs_magic != MTB_UFS_MAGIC))
		goto errout;

	/* intialize values */

	(void) vsnprintf(new->uf_panic_str, LOCKFS_MAXCOMMENTLEN - 1, fmt, adx);

	new->uf_ufsvfsp = ip->i_ufsvfs;
	new->uf_vfsp    = ip->i_vfs;

	mutex_init(&new->uf_mutex, NULL, MUTEX_DEFAULT, NULL);
	need_vfs_unlock = !MUTEX_HELD(&ip->i_ufsvfs->vfs_lock);

	if (need_vfs_unlock) {
		if (!mutex_tryenter(&ip->i_ufsvfs->vfs_lock)) {
			/*
			 * not much alternative here, but we're panicking
			 * already, it couldn't be worse - so just
			 * proceed optimistically and take note.
			 */
			mutex_enter(&uf_stats.ufst_mutex);
			uf_stats.ufst_lock_violations++;
			mutex_exit(&uf_stats.ufst_mutex);
			MINOR((": couldn't get vfs lock"))
			need_vfs_unlock = 0;
		}
	}

	if (mutex_tryenter(&new->uf_mutex)) {
		initialization_worked = set_state(new, UF_INIT);
		mutex_exit(&new->uf_mutex);
	}

	if (need_vfs_unlock)
		mutex_exit(&ip->i_ufsvfs->vfs_lock);

	if (initialization_worked) {
		MINOR(("] "));
		return (new);
	}
	/* FALLTHROUGH */

errout:
	if (new)
		kmem_free(new, sizeof (ufs_failure_t));
	MINOR((": failed]\n"));
	return (NULL);
}

static void
queue_failure(ufs_failure_t *new)
{
	MINOR(("[queue_failure"));

	mutex_enter(&ufs_fix.uq_mutex);

	if (ufs_fix.uq_ufhead)
		insque(new, &ufs_fix.uq_ufhead);
	else
		ufs_fix.uq_ufhead = new;

	if (mutex_tryenter(&new->uf_mutex)) {
		(void) set_state(new, UF_QUEUE);
		mutex_exit(&new->uf_mutex);
	}

	mutex_enter(&uf_stats.ufst_mutex);		/* force wakeup */
	ufs_fix.uq_ne = ufs_fix.uq_lowat = uf_stats.ufst_num_failed;
	mutex_exit(&uf_stats.ufst_mutex);

	cv_broadcast(&ufs_fix.uq_cv);

	DCALL(DBGLVL_MAJOR, cmn_err(CE_WARN, new->uf_panic_str ?
	    new->uf_panic_str : "queue_failure: NULL panic str?"));
	mutex_exit(&ufs_fix.uq_mutex);

	MINOR(("] "));
}

/*PRINTFLIKE2*/
static void
real_panic(ufs_failure_t *f, const char *fmt, ...)
{
	va_list	adx;

	MINUTE(("[real_panic "));

	va_start(adx, fmt);
	real_panic_v(f, fmt, adx);
	va_end(adx);

	MINUTE((": return?!]\n"));
}

static void
real_panic_v(ufs_failure_t *f, const char *fmt, va_list adx)
{
	int seriousness = CE_PANIC;
	int need_unlock;

	MINUTE(("[real_panic_v "));

	if (f && f->uf_ufsvfsp)
		TRANS_SETERROR(f->uf_ufsvfsp);

#if defined(DEBUG)
	if (DEBUG_FLAGS & DBGFLG_NOPANIC) {
		seriousness = CE_WARN;
		cmn_err(CE_WARN, "real_panic: EWOULDPANIC\n");
	}
#endif /* DEBUG */

	delay(hz >> 1);			/* allow previous warnings to get out */

	if (!f && fmt)
		vcmn_err(seriousness, fmt, adx);
	else
		cmn_err(seriousness, f && f->uf_panic_str? f->uf_panic_str:
		    "real_panic: <unknown panic?>");

	if (f) {
		need_unlock = !MUTEX_HELD(&f->uf_mutex);
		if (need_unlock) {
			mutex_enter(&f->uf_mutex);
		}

		f->uf_retry = -1;
		(void) set_state(f, UF_PANIC);

		if (need_unlock) {
			mutex_exit(&f->uf_mutex);
		}
	}
	MINUTE((": return?!]\n"));
}

/*
 * initializes ufs panic structs, locks, etc
 */
void
ufsfx_init(void)
{

	MINUTE(("[ufsfx_init"));

	/* patchable; unchanged while running, so no lock is needed */
	ufsfx_tune.uft_too_long		= UF_TOO_LONG;
	ufsfx_tune.uft_fixstart_period	= UF_FIXSTART_PERIOD;
	ufsfx_tune.uft_fixpoll_period	= UF_FIXPOLL_PERIOD;
	ufsfx_tune.uft_short_err_period	= UF_SHORT_ERROR_PERIOD;
	ufsfx_tune.uft_long_err_period	= UF_LONG_ERROR_PERIOD;

	uffsinfo.ufi_statp	= &uf_stats;
	uffsinfo.ufi_tunep	= &ufsfx_tune;
	uffsinfo.ufi_statetab	= &state_desc[0];

	mutex_init(&uf_stats.ufst_mutex, NULL, MUTEX_DEFAULT, NULL);
	ufs_thread_init(&ufs_fix, /* maxne */ 1);

	MINUTE(("] "));
}

/*
 * initializes per-ufs values
 * returns 0 (ok) or errno
 */
int
ufsfx_mount(struct ufsvfs *ufsvfsp, int flags)
{
	MINUTE(("[ufsfx_mount (%d)", flags));
	/* don't check/need vfs_lock because it's still being initialized */

	ufsvfsp->vfs_fsfx.fx_flags = (flags & UFSMNT_ONERROR_FLGMASK) >> 4;

	MINUTE((": %s: fx_flags:%ld,",
	    ufsvfsp->vfs_fs->fs_fsmnt, ufsvfsp->vfs_fsfx.fx_flags));
	/*
	 *	onerror={panic ^ lock only ^ unmount}
	 */

	if (ufsvfsp->vfs_fsfx.fx_flags & UFSFX_PANIC) {
		MINUTE((" PANIC"));

	} else if (ufsvfsp->vfs_fsfx.fx_flags & UFSFX_LCKONLY) {
		MINUTE((" LCKONLY"));

	} else if (ufsvfsp->vfs_fsfx.fx_flags & UFSFX_LCKUMOUNT) {
		MINUTE((" LCKUMOUNT"));

	} else {
		ufsvfsp->vfs_fsfx.fx_flags = UFSFX_DEFAULT;
		ASSERT(ufsvfsp->vfs_fsfx.fx_flags &
		    (UFSMNT_ONERROR_FLGMASK >> 4));
		MINUTE((" DEFAULT"));
	}

	pollwakeup(&ufs_pollhd, POLLPRI);
	MINUTE(("]\n"));
	return (0);
}

/*
 * ufsfx_unmount
 *
 * called during unmount
 */
void
ufsfx_unmount(struct ufsvfs *ufsvfsp)
{
	ufs_failure_t	*f;
	int		 must_unlock_list;

	MINUTE(("[ufsfx_unmount"));

	if (!ufsvfsp) {
		MINUTE((": no ufsvfsp]"));
		return;
	}

	if ((must_unlock_list = !MUTEX_HELD(&ufs_fix.uq_mutex)) != 0)
		mutex_enter(&ufs_fix.uq_mutex);

	for (f = ufs_fix.uq_ufhead; f; f = f->uf_next) {
		int must_unlock_failure;

		must_unlock_failure = !MUTEX_HELD(&f->uf_mutex);
		if (must_unlock_failure) {
			mutex_enter(&f->uf_mutex);
		}

		if (f->uf_ufsvfsp == ufsvfsp) {

			/*
			 * if we owned the failure record lock, then this
			 * is probably a fix failure-triggered unmount, so
			 * the warning is not appropriate or needed
			 */

			/* XXX if rebooting don't print this? */
			if (!terminal_state(f->uf_s) && must_unlock_failure) {
				cmn_err(CE_WARN,
				    "Unmounting %s while error-locked",
				    fs_name(f));
			}

			f->uf_ufsvfsp		= NULL;
			f->uf_vfs_ufsfxp	= NULL;
			f->uf_vfs_lockp		= NULL;
			f->uf_bp		= NULL;
			f->uf_vfsp		= NULL;
			f->uf_retry		= -1;
		}

		if (must_unlock_failure)
			mutex_exit(&f->uf_mutex);
	}
	if (must_unlock_list)
		mutex_exit(&ufs_fix.uq_mutex);

	pollwakeup(&ufs_pollhd, POLLPRI | POLLHUP);
	MINUTE(("] "));
}

/*
 * ufsfx_(un)lockfs
 *
 * provides hook from lockfs code so we can recognize unlock/relock
 *  This is called after it is certain that the (un)lock will succeed.
 */
void
ufsfx_unlockfs(struct ufsvfs *ufsvfsp)
{
	ufs_failure_t	*f;
	int		 need_unlock;
	int		 need_unlock_list;
	int		 informed = 0;

	MINUTE(("[ufsfx_unlockfs"));

	if (!ufsvfsp)
		return;

	need_unlock_list = !MUTEX_HELD(&ufs_fix.uq_mutex);

	if (need_unlock_list)
		mutex_enter(&ufs_fix.uq_mutex);

	for (f = ufs_fix.uq_ufhead; f; f = f->uf_next) {

		need_unlock = !MUTEX_HELD(&f->uf_mutex);
		if (need_unlock)
			mutex_enter(&f->uf_mutex);

		if (f->uf_ufsvfsp == ufsvfsp && !terminal_state(f->uf_s)) {
			if (!(f->uf_s & UF_FIXING)) {
				/*
				 * This might happen if we don't notice that
				 * the fs gets marked FSFIX before it is
				 * marked FSCLEAN, as might occur if the
				 * the superblock was hammered directly.
				 */
				if (!informed) {
					informed = 1;
					cmn_err(CE_NOTE,
					    "Unlock of %s succeeded before "
					    "fs_clean marked FSFIX?",
					    fs_name(f));
				}

				/*
				 * pass through fixing state so
				 * transition protocol is satisfied
				 */
				if (!set_state(f, UF_FIXING)) {
					MINUTE((": failed] "));
				}
			}

			if (!set_state(f, UF_FIXED)) {
				/* it's already fixed, so don't panic now */
				MINUTE((": failed] "));
			}
		}

		if (need_unlock)
			mutex_exit(&f->uf_mutex);
	}
	if (need_unlock_list)
		mutex_exit(&ufs_fix.uq_mutex);
	MINUTE(("] "));
}

void
ufsfx_lockfs(struct ufsvfs *ufsvfsp)
{
	ufs_failure_t	*f;
	int		 need_unlock;
	int		 need_unlock_list;

	MINUTE(("[ufsfx_lockfs"));

	if (!ufsvfsp)
		return;

	need_unlock_list = !MUTEX_HELD(&ufs_fix.uq_mutex);

	if (need_unlock_list)
		mutex_enter(&ufs_fix.uq_mutex);

	for (f = ufs_fix.uq_ufhead; f; f = f->uf_next) {

		need_unlock = !MUTEX_HELD(&f->uf_mutex);
		if (need_unlock)
			mutex_enter(&f->uf_mutex);

		if (f->uf_ufsvfsp == ufsvfsp && !terminal_state(f->uf_s) &&
		    f->uf_s != UF_PANIC) {
			switch (f->uf_s) {

			default:
				cmn_err(CE_WARN,
				    "fs %s not in state "
				    "UF_TRYLCK, UF_LOCKED or UF_FIXING",
				    fs_name(f));
				break;

			case UF_TRYLCK:
				if (!set_state(f, UF_LOCKED)) {
					MINUTE((": failed] "));
				}
				break;

			case UF_LOCKED:
				if (!set_state(f, UF_FIXING)) {
					MINUTE((": failed] "));
				}
				break;

			case UF_FIXING:
				break;

			}
		}

		if (need_unlock)
			mutex_exit(&f->uf_mutex);
	}
	if (need_unlock_list)
		mutex_exit(&ufs_fix.uq_mutex);

	MINUTE(("] "));
}

/*
 * error lock, trigger fsck and unlock those fs with failures
 * blatantly copied from the hlock routine, although this routine
 * triggers differently in order to use uq_ne as meaningful data.
 */
/* ARGSUSED */
void
ufsfx_thread_fix_failures(void *ignored)
{
	int		retry;
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, &ufs_fix.uq_mutex, callb_generic_cpr,
	    "ufsfixfail");

	MINUTE(("[ufsfx_thread_fix_failures] "));

	for (;;) {
		/* sleep until there is work to do */

		mutex_enter(&ufs_fix.uq_mutex);
		(void) ufs_thread_run(&ufs_fix, &cprinfo);
		ufs_fix.uq_ne = 0;
		mutex_exit(&ufs_fix.uq_mutex);

		/* process failures on our q */
		do {
			retry = ufsfx_do_failure_q();
			if (retry) {
				mutex_enter(&ufs_fix.uq_mutex);
				CALLB_CPR_SAFE_BEGIN(&cprinfo);
				(void) cv_reltimedwait(&ufs_fix.uq_cv,
				    &ufs_fix.uq_mutex, (hz * retry),
				    TR_CLOCK_TICK);
				CALLB_CPR_SAFE_END(&cprinfo,
				    &ufs_fix.uq_mutex);
				mutex_exit(&ufs_fix.uq_mutex);
			}
		} while (retry);
	}
	/* NOTREACHED */
}


/*
 * watch for fix-on-panic work
 *
 * returns # of seconds to sleep before trying again
 * and zero if no retry is needed
 */

int
ufsfx_do_failure_q(void)
{
	ufs_failure_t	*f;
	long		 retry = 1;
	ufsd_t		*s;

	MAJOR(("[ufsfx_do_failure_q"));
	DCALL(DBGLVL_HIDEOUS, dump_uf_list(NULL));

	if (!mutex_tryenter(&ufs_fix.uq_mutex))
		return (retry);

	retry = 0;
rescan_q:

	/*
	 * walk down failure list
	 *  depending on state of each failure, do whatever
	 *  is appropriate to move it to the next state
	 *  taking note of whether retry gets set
	 *
	 * retry protocol:
	 * wakeup in shortest required time for any failure
	 *   retry == 0; nothing more to do (terminal state)
	 *   retry < 0; reprocess queue immediately, retry will
	 *		be abs(retry) for the next cycle
	 *   retry > 0; schedule wakeup for retry seconds
	 */

	for (f = ufs_fix.uq_ufhead; f; f = f->uf_next) {

		if (!mutex_tryenter(&f->uf_mutex)) {
			retry = 1;
			continue;
		}
		s = get_state_desc(f->uf_s);

		MINOR((": found%s: %s, \"%s: %s\"\n",
		    s->ud_attr.terminal ? " old" : "",
		    fs_name(f), state_name(f->uf_s), f->uf_panic_str));

		if (s->ud_attr.terminal) {
			mutex_exit(&f->uf_mutex);
			continue;
		}

		if (s->ud_sfp)
			(*s->ud_sfp)(f, UFA_FOUND, f->uf_s);

		ASSERT(terminal_state(f->uf_s) || f->uf_retry != 0);

		if (f->uf_retry != 0) {
			if (retry > f->uf_retry || retry == 0)
				retry = f->uf_retry;
			if (f->uf_retry < 0)
				f->uf_retry = abs(f->uf_retry);
		}
		mutex_exit(&f->uf_mutex);
	}


	if (retry < 0) {
		retry = abs(retry);
		goto rescan_q;
	}

	mutex_exit(&ufs_fix.uq_mutex);

	DCALL(DBGLVL_HIDEOUS, dump_uf_list(NULL));
	MAJOR((": retry=%ld, good night]\n\n", retry));

	return (retry);
}

static void
pester_msg(ufs_failure_t *f, int seriousness)
{
	MINUTE(("[pester_msg"));
	ASSERT(f->uf_s & (UF_LOCKED | UF_FIXING));

	/*
	 * XXX if seems too long for this fs, poke administrator
	 * XXX to run fsck manually (and change retry time?)
	 */
	cmn_err(seriousness, "Waiting for repair of %s to %s",
	    fs_name(f), f->uf_s & UF_LOCKED ? "start" : "finish");
	MINUTE(("]"));
}

static time_t
trylock_time_exceeded(ufs_failure_t *f)
{
	time_t		toolong;
	extern time_t	time;

	MINUTE(("[trylock_time_exceeded"));
	ASSERT(MUTEX_HELD(&f->uf_mutex));

	toolong = (time_t)ufsfx_tune.uft_too_long + f->uf_entered_tm;
	if (time > toolong)
		cmn_err(CE_WARN, "error-lock timeout exceeded: %s", fs_name(f));

	MINUTE(("] "));
	return (time <= toolong? 0: time - toolong);
}

static int
get_lockfs_status(ufs_failure_t *f, struct lockfs *lfp)
{
	MINUTE(("[get_lockfs_status"));

	if (!f->uf_ufsvfsp) {
		MINUTE((": ufsvfsp is NULL]\n"));
		return (0);
	}

	ASSERT(MUTEX_HELD(&f->uf_mutex));
	ASSERT(MUTEX_NOT_HELD(f->uf_vfs_lockp));
	ASSERT(!vfs_lock_held(f->uf_vfsp));
	ASSERT(f->uf_ufsvfsp->vfs_root != NULL);

	f->uf_lf_err = ufs_fiolfss(f->uf_ufsvfsp->vfs_root, lfp);

	if (f->uf_lf_err) {
		f->uf_retry = ufsfx_tune.uft_short_err_period;
	}

	MINUTE(("] "));
	return (1);
}

static sfrc_t
set_state(ufs_failure_t *f, ufs_failure_states_t new_state)
{
	ufsd_t		*s;
	sfrc_t		 sfrc = SFRC_FAIL;
	int		 need_unlock;
	extern time_t	 time;

	HIDEOUS(("[set_state: new state:%s", state_name(new_state)));
	ASSERT(f);
	ASSERT(MUTEX_HELD(&f->uf_mutex));

	/*
	 * if someone else is panicking, just let panic sync proceed
	 */
	if (panicstr) {
		(void) set_state(f, UF_NOTFIX);
		HIDEOUS((": state reset: not fixed] "));
		return (sfrc);
	}

	/*
	 * bad state transition, an internal error
	 */
	if (!state_trans_valid(f->uf_s, new_state)) {
		/* recursion */
		if (!(f->uf_s & UF_PANIC) && !(new_state & UF_PANIC))
			(void) set_state(f, UF_PANIC);
		MINOR((": state reset: transition failure (\"%s\"->\"%s\")] ",
		    state_name(f->uf_s), state_name(new_state)));
		return (sfrc);
	}

	s = get_state_desc(new_state);

	need_unlock = !MUTEX_HELD(&ufs_fix.uq_mutex);
	if (need_unlock)
		mutex_enter(&ufs_fix.uq_mutex);

	if (s->ud_attr.at_fail && ufs_fix.uq_threadp &&
	    curthread == ufs_fix.uq_threadp) {
		cmn_err(CE_WARN, "set_state: probable recursive panic of %s",
		    fs_name(f));
	}
	if (need_unlock)
		mutex_exit(&ufs_fix.uq_mutex);

	/* NULL state functions always succeed */
	sfrc = !s->ud_sfp? SFRC_SUCCESS: (*s->ud_sfp)(f, UFA_SET, new_state);

	if (sfrc == SFRC_SUCCESS && f->uf_s != new_state) {
		f->uf_s = new_state;
		f->uf_entered_tm = time;
		f->uf_counter = 0;
	}

	HIDEOUS(("]\n"));
	return (sfrc);
}

static ufsd_t *
get_state_desc(ufs_failure_states_t state)
{
	ufsd_t *s;

	HIDEOUS(("[get_state_desc"));

	for (s = &state_desc[1]; s->ud_name != NULL; s++) {
		if (s->ud_v == state) {
			HIDEOUS(("] "));
			return (s);
		}
	}

	HIDEOUS(("] "));
	return (&state_desc[0]);	/* default */
}

static sfrc_t
sf_undef(ufs_failure_t *f, ufsa_t a, ufs_failure_states_t s)
{
	sfrc_t rc;

	TRIVIA(("[sf_undef, action is %s, state is %s\n",
	    act_name(a), state_name(s)));
	ASSERT(s == UF_UNDEF);

	/* shouldn't find null failure records or ever set one */
	rc = set_state(f, UF_NOTFIX);

	TRIVIA(("] "));
	return (rc);
}


static sfrc_t
sf_init(
	ufs_failure_t	*f,
	ufsa_t	 a,
	ufs_failure_states_t	 s)
{
	sfrc_t		rc = SFRC_FAIL;
	extern time_t	time;

	TRIVIA(("[sf_init, action is %s", act_name(a)));
	ASSERT(s & UF_INIT);

	switch (a) {
	case UFA_SET:
		f->uf_begin_tm = time;
		f->uf_retry = 1;
		if (!f->uf_ufsvfsp) {
			(void) set_state(f, UF_PANIC);
			TRIVIA((": NULL ufsvfsp]\n"));
			return (rc);
		}
		/*
		 * because we can call panic from many different levels,
		 * we can't be sure that we've got the vfs_lock at this
		 * point.  However, there's not much alternative and if
		 * we don't (have the lock) the worst case is we'll just
		 * panic again
		 */
		f->uf_vfs_lockp		= &f->uf_ufsvfsp->vfs_lock;
		f->uf_vfs_ufsfxp	= &f->uf_ufsvfsp->vfs_fsfx;

		if (!f->uf_ufsvfsp->vfs_bufp) {
			(void) set_state(f, UF_PANIC);
			TRIVIA((": NULL vfs_bufp]\n"));
			return (rc);
		}
		f->uf_bp = f->uf_ufsvfsp->vfs_bufp;

		if (!f->uf_ufsvfsp->vfs_bufp->b_un.b_fs) {
			(void) set_state(f, UF_PANIC);
			TRIVIA((": NULL vfs_fs]\n"));
			return (rc);
		}

		/* vfs_fs = vfs_bufp->b_un.b_fs */
		bcopy(f->uf_ufsvfsp->vfs_fs->fs_fsmnt, f->uf_fsname, MAXMNTLEN);

		f->uf_lf.lf_lock  = LOCKFS_ELOCK;	/* primer */

		if (!f->uf_vfsp || f->uf_vfsp->vfs_dev == NODEV) {
			(void) set_state(f, UF_PANIC);
			TRIVIA((": NULL vfsp or vfs_dev == NODEV"));
			return (rc);
		}
		f->uf_dev = f->uf_vfsp->vfs_dev;

		rc = SFRC_SUCCESS;
		break;

	case UFA_FOUND:
	default:
		/* failures marked init shouldn't even be on the queue yet */
		rc = set_state(f, UF_QUEUE);
		TRIVIA((": found failure with state init]\n"));
	}

	TRIVIA(("] "));
	return (rc);
}

static sfrc_t
sf_queue(
	ufs_failure_t	*f,
	ufsa_t	 a,
	ufs_failure_states_t	 s)
{
	sfrc_t		rc = SFRC_FAIL;

	TRIVIA(("[sf_queue, action is %s", act_name(a)));
	ASSERT(s & UF_QUEUE);

	if (!f->uf_ufsvfsp) {
		TRIVIA((": NULL ufsvfsp]\n"));
		return (rc);
	}

	switch (a) {
	case UFA_FOUND:
		rc = sf_found_queue(f);
		break;

	case UFA_SET:

		ASSERT(MUTEX_HELD(&ufs_fix.uq_mutex));

		mutex_enter(&uf_stats.ufst_mutex);
		uf_stats.ufst_num_failed++;
		mutex_exit(&uf_stats.ufst_mutex);

		/*
		 * if can't get the vfs lock, just wait until
		 * UF_TRYLCK to set fx_current
		 */
		if (mutex_tryenter(f->uf_vfs_lockp)) {
			f->uf_vfs_ufsfxp->fx_current = f;
			mutex_exit(f->uf_vfs_lockp);
		} else {
			mutex_enter(&uf_stats.ufst_mutex);
			uf_stats.ufst_current_races++;
			mutex_exit(&uf_stats.ufst_mutex);
		}

		f->uf_retry = 1;
		rc = SFRC_SUCCESS;
		TRIVIA(("] "));
		break;

	default:
		(void) set_state(f, UF_PANIC);
		TRIVIA((": failed] "));
	}

	return (rc);
}

static sfrc_t
sf_found_queue(ufs_failure_t *f)
{
	int		replica;
	sfrc_t		rc = SFRC_FAIL;

	TRIVIA(("[sf_found_queue"));

	/*
	 * don't need to check for null ufsvfsp because
	 * unmount must own list's ufs_fix.uq_mutex
	 * to mark it null and we own that lock since
	 * we got here.
	 */

	ASSERT(MUTEX_HELD(&ufs_fix.uq_mutex));
	ASSERT(MUTEX_NOT_HELD(f->uf_vfs_lockp));

	if (!mutex_tryenter(f->uf_vfs_lockp)) {
		TRIVIA((": tryenter(vfslockp) failed; retry]\n"));
		f->uf_retry = 1;
		return (rc);
	}

	replica = f->uf_vfs_ufsfxp && f->uf_vfs_ufsfxp->fx_current != NULL &&
	    f->uf_vfs_ufsfxp->fx_current != f &&
	    !terminal_state(f->uf_vfs_ufsfxp->fx_current->uf_s);

	/*
	 * copy general flags to this ufs_failure so we don't
	 * need to refer back to the ufsvfs, or, more importantly,
	 * don't need to keep acquiring (trying to acquire) vfs_lockp
	 *
	 * The most restrictive option wins:
	 *  panic > errlock only > errlock+unmount > repair
	 * XXX panic > elock > elock > elock+umount
	 */
	if (f->uf_vfs_ufsfxp->fx_flags & UFSFX_PANIC) {
		if (!set_state(f, UF_PANIC)) {
			TRIVIA((": marked panic but was queued?"));
			real_panic(f, " ");
			/*NOTREACHED*/
		}
		mutex_exit(f->uf_vfs_lockp);
		return (rc);
	}
	f->uf_flags = f->uf_vfs_ufsfxp->fx_flags;

	if (replica) {
		if (!set_state(f, UF_REPLICA)) {
			f->uf_retry = 1;
			TRIVIA((": set to replica failed] "));
		} else {
			TRIVIA(("] "));
		}
		mutex_exit(f->uf_vfs_lockp);
		return (rc);
	}
	mutex_exit(f->uf_vfs_lockp);

	if (!set_state(f, UF_TRYLCK)) {
		TRIVIA((": failed] "));
	} else {
		rc = SFRC_SUCCESS;
	}
	return (rc);
}

static sfrc_t
sf_nonterm_cmn(ufs_failure_t *f, ufsa_t a, ufs_failure_states_t s)
{
	sfrc_t	rc = SFRC_FAIL;

	TRIVIA(("[sf_nonterm_cmn, action: %s, %s", act_name(a), state_name(s)));
	ASSERT(s & (UF_TRYLCK | UF_LOCKED | UF_UMOUNT | UF_FIXING));
	ASSERT(!terminal_state(s));

	if (!f->uf_ufsvfsp && !(f->uf_s & UF_UMOUNT)) {
		TRIVIA((": NULL ufsvfsp (state != UMOUNT)]\n"));
		(void) set_state(f, UF_NOTFIX);
		return (rc);
	}

	switch (a) {
	case UFA_SET:
		switch (s) {
		case UF_TRYLCK:
			ASSERT(MUTEX_NOT_HELD(f->uf_vfs_lockp));
			rc = sf_set_trylck(f);
			break;

		case UF_LOCKED:
			rc = sf_set_locked(f);
			break;

		case UF_FIXING:
			f->uf_flags |= UFSFX_REPAIR_START;
			f->uf_retry  = ufsfx_tune.uft_fixpoll_period;
			rc = SFRC_SUCCESS;
			break;

		case UF_UMOUNT:
			f->uf_retry = -ufsfx_tune.uft_short_err_period;
			rc = SFRC_SUCCESS;
			break;

		default:
			(void) set_state(f, UF_PANIC);
			TRIVIA((": failed] "));
		}
		break;

	case UFA_FOUND:

		switch (s) {
		case UF_TRYLCK:
			rc = sf_found_trylck(f);
			break;

		case UF_LOCKED:
		case UF_FIXING:
			rc = sf_found_lock_fix_cmn(f, s);
			break;

		case UF_UMOUNT:
			rc = sf_found_umount(f);
			break;

		default:
			(void) set_state(f, UF_PANIC);
			TRIVIA((": failed] "));
			break;
		}
		break;
	default:
		(void) set_state(f, UF_PANIC);
		TRIVIA((": failed] "));
		break;
	}

	TRIVIA(("] "));
	return (rc);
}

static sfrc_t
sf_set_trylck(ufs_failure_t *f)
{
	TRIVIA(("[sf_set_trylck"));

	if (!mutex_tryenter(f->uf_vfs_lockp)) {
		TRIVIA((": tryenter(vfslockp) failed; retry]\n"));
		f->uf_retry = 1;
		return (SFRC_FAIL);
	}

	if (!f->uf_vfs_ufsfxp->fx_current)
		f->uf_vfs_ufsfxp->fx_current = f;

	mutex_exit(f->uf_vfs_lockp);

	f->uf_lf.lf_flags = 0;
	f->uf_lf.lf_lock  = LOCKFS_ELOCK;
	f->uf_retry = -ufsfx_tune.uft_fixstart_period;
	TRIVIA(("] "));
	return (SFRC_SUCCESS);
}

static sfrc_t
sf_found_trylck(ufs_failure_t *f)
{
	struct lockfs lockfs_status;

	TRIVIA(("[sf_found_trylck"));

	if (trylock_time_exceeded(f) > 0) {
		(void) set_state(f, UF_PANIC);
		TRIVIA((": failed] "));
		return (SFRC_FAIL);
	}

	if (!get_lockfs_status(f, &lockfs_status)) {
		(void) set_state(f, UF_PANIC);
		TRIVIA((": failed] "));
		return (SFRC_FAIL);
	}

	if (f->uf_lf_err == NO_ERROR)
		f->uf_lf.lf_key = lockfs_status.lf_key;

	if (!set_lockfs(f, &lockfs_status)) {
		(void) set_state(f, UF_PANIC);
		TRIVIA((": failed] "));
		return (SFRC_FAIL);
	}
	TRIVIA(("] "));
	return (SFRC_SUCCESS);
}

static sfrc_t
sf_set_locked(ufs_failure_t *f)
{
	TRIVIA(("[sf_set_locked"));

	f->uf_retry = -ufsfx_tune.uft_fixstart_period;

#if defined(DEBUG)
	if (f->uf_flags & UFSFX_REPAIR_START)
		TRIVIA(("clearing UFSFX_REPAIR_START "));
#endif /* DEBUG */

	f->uf_flags &= ~UFSFX_REPAIR_START;

	if (f->uf_s & UF_TRYLCK) {
		cmn_err(CE_WARN, "Error-locked %s: \"%s\"",
		    fs_name(f), f->uf_panic_str);

		if (f->uf_flags & UFSFX_LCKONLY)
			cmn_err(CE_WARN, "Manual repair of %s required",
			    fs_name(f));
	}

	/*
	 * just reset to current state
	 */
#if defined(DEBUG)
	TRIVIA(("locked->locked "));
#endif /* DEBUG */

	TRIVIA(("] "));
	return (SFRC_SUCCESS);
}

static sfrc_t
sf_found_lock_fix_cmn(ufs_failure_t *f, ufs_failure_states_t s)
{
	time_t		toolong;
	extern time_t	time;
	struct buf	*bp			= NULL;
	struct fs	*dfs;
	time_t		 concerned, anxious;
	sfrc_t		 rc			= SFRC_FAIL;
	ulong_t		 gb_size;

	TRIVIA(("[sf_found_lock_fix_cmn (\"%s\")", state_name(s)));

	if (s & UF_LOCKED) {
		ASSERT(MUTEX_HELD(&f->uf_mutex));

		toolong =
		    time > (ufsfx_tune.uft_too_long + f->uf_entered_tm);
		TRIVIA(("%stoolong", !toolong? "not": ""));
		HIDEOUS((": time:%ld, too long:%ld, entered_tm:%ld ",
		    time, ufsfx_tune.uft_too_long, f->uf_entered_tm));

		if (f->uf_flags & UFSFX_LCKUMOUNT) {
			if (set_state(f, UF_UMOUNT)) {
				TRIVIA(("] "));
				rc = SFRC_SUCCESS;
			} else {
				TRIVIA((": failed] "));
				f->uf_retry = 1;
			}
			return (rc);
		}
		if (!toolong) {
			rc = SFRC_SUCCESS;
		} else {
			if (!(f->uf_flags & UFSFX_REPAIR_START)) {
				cmn_err(CE_WARN, "%s repair of %s not started.",
				    (f->uf_flags & UFSFX_LCKONLY) ?
				    "Manual" : "Automatic", fs_name(f));

				f->uf_retry = ufsfx_tune.uft_long_err_period;
			} else {
				f->uf_retry = ufsfx_tune.uft_long_err_period;
				cmn_err(CE_WARN, "Repair of %s is not timely; "
				    "operator attention is required.",
				    fs_name(f));
			}
			TRIVIA(("] "));
			return (rc);
		}
	}

#if defined(DEBUG)
	else {
		ASSERT(s & UF_FIXING);
	}
#endif /* DEBUG */

	/*
	 * get on disk superblock; force it to really
	 * come from the disk
	 */
	(void) bfinval(f->uf_dev, 0);
	bp = UFS_BREAD(f->uf_ufsvfsp, f->uf_dev, SBLOCK, SBSIZE);
	if (bp) {
		bp->b_flags |= (B_STALE | B_AGE);
		dfs = bp->b_un.b_fs;
	}

	if (!bp || (bp->b_flags & B_ERROR) || ((dfs->fs_magic != FS_MAGIC) &&
	    (dfs->fs_magic != MTB_UFS_MAGIC))) {
		TRIVIA((": UFS_BREAD(SBLOCK) failed]\n"));
		f->uf_retry = 1;
		goto out;
	}

	/* fsck started but we haven't noticed yet? */
	if (!(s & UF_FIXING) && dfs->fs_clean == FSFIX) {
		if (!set_state(f, UF_FIXING)) {
			TRIVIA((": failed]\n"));
			f->uf_retry = 1;
			goto out;
		}
	}

	/* fsck started but didn't succeed? */
	if ((s & UF_FIXING) && ((dfs->fs_clean == FSBAD) || !fsck_active(f))) {
		TRIVIA((": fs_clean: %d", (int)dfs->fs_clean));
		(void) set_state(f, UF_LOCKED);
		cmn_err(CE_WARN, "%s: Manual repair is necessary.", fs_name(f));
		f->uf_retry = ufsfx_tune.uft_long_err_period;
		goto out;
	}

	gb_size = (dfs->fs_size * dfs->fs_bshift) / GB;
	toolong = (time_t)((gb_size == 0? 1: gb_size) * SecondsPerGig);

	/* fsck started but doesn't seem to be proceeding? */
	if ((s & UF_FIXING) && dfs->fs_clean == FSFIX) {
		if (time > f->uf_entered_tm + toolong) {

			cmn_err(CE_WARN,
			    "Repair completion timeout exceeded on %s; "
			    "manual fsck may be required", fs_name(f));
			f->uf_retry = ufsfx_tune.uft_long_err_period;
		}
	}

	concerned = f->uf_entered_tm + (toolong / 3);
	anxious = f->uf_entered_tm + ((2 * toolong) / 3);

	if (time > concerned)
		pester_msg(f, time > anxious? CE_WARN: CE_NOTE);

	TRIVIA(("] "));

out:
	if (bp)
		brelse(bp);

	return (rc);
}

static sfrc_t
sf_found_umount(ufs_failure_t *f)
{
	extern time_t	 time;
	sfrc_t		 rc			= SFRC_FAIL;
	struct vfs	*vfsp			= f->uf_vfsp;
	struct ufsvfs	*ufsvfsp		= f->uf_ufsvfsp;
	int		 toolong		= 0;
	int		 err			= 0;

	TRIVIA(("[sf_found_umount"));

	toolong = time > ufsfx_tune.uft_too_long + f->uf_entered_tm;
	if (toolong) {
		TRIVIA((": unmount time limit exceeded] "));
		goto out;
	}

	if (!vfsp || !ufsvfsp) {	/* trivial case */
		TRIVIA((": NULL vfsp and/or ufsvfsp, already unmounted?] "));
		goto out;
	}

	if (!ULOCKFS_IS_ELOCK(&ufsvfsp->vfs_ulockfs)) {
		TRIVIA((": !not error locked?"));
		err = EINVAL;
		goto out;
	}

	/* The vn_vfsunlock will be done in dounmount() [.../common/fs/vfs.c] */
	if (vn_vfswlock(vfsp->vfs_vnodecovered)) {
		TRIVIA((": couldn't lock coveredvp"));
		err = EBUSY;
		goto out;
	}

	if ((err = dounmount(vfsp, 0, kcred)) != 0) {

		/* take note, but not many alternatives here */
		mutex_enter(&uf_stats.ufst_mutex);
		uf_stats.ufst_unmount_failures++;
		mutex_exit(&uf_stats.ufst_mutex);

		TRIVIA((": unmount failed] "));
	} else {
		cmn_err(CE_NOTE, "unmounted error-locked %s", fs_name(f));
	}

out:
	if (toolong || (err != EBUSY && err != EAGAIN))
		rc = set_state(f, UF_NOTFIX);

	TRIVIA(("] "));
	return (rc);
}

static sfrc_t
sf_term_cmn(ufs_failure_t *f, ufsa_t a, ufs_failure_states_t s)
{
	extern time_t	time;
	sfrc_t		rc = SFRC_FAIL;

	TRIVIA(("[sf_term_cmn, action is %s, state is %s",
	    act_name(a), state_name(s)));
	ASSERT(s & (UF_FIXED | UF_NOTFIX | UF_REPLICA));
	ASSERT(terminal_state(s));

	if (!f->uf_ufsvfsp && !(f->uf_s & (UF_UMOUNT | UF_NOTFIX))) {
		TRIVIA((": NULL ufsvfsp (state != UMOUNT | NOTFIX)]\n"));
		return (rc);
	}

	switch (a) {
	case UFA_SET:
		switch (s) {
		case UF_NOTFIX:
		case UF_FIXED:
		{
			int need_lock_vfs;

			if (f->uf_ufsvfsp && f->uf_vfs_lockp)
				need_lock_vfs = !MUTEX_HELD(f->uf_vfs_lockp);
			else
				need_lock_vfs = 0;

			if (need_lock_vfs && !mutex_tryenter(f->uf_vfs_lockp)) {
				TRIVIA((": tryenter(vfslockp) fail; retry]\n"));
				f->uf_retry = 1;
				break;
			}

			f->uf_end_tm = time;
			f->uf_lf.lf_lock = LOCKFS_OLOCK;
			f->uf_retry = 0;

			if (f->uf_vfs_ufsfxp)
				f->uf_vfs_ufsfxp->fx_current = NULL;

			if (need_lock_vfs)
				mutex_exit(f->uf_vfs_lockp);

			cmn_err(CE_NOTE, (s & UF_NOTFIX)? "Could not fix %s":
			    "%s is now accessible", fs_name(f));

			if (s & UF_FIXED) {
				mutex_enter(&uf_stats.ufst_mutex);
				uf_stats.ufst_num_fixed++;
				mutex_exit(&uf_stats.ufst_mutex);
			}
			(void) timeout(ufsfx_kill_fix_failure_thread,
			    (void *)(ufsfx_tune.uft_short_err_period * hz),
			    ufsfx_tune.uft_short_err_period * hz);
			rc = SFRC_SUCCESS;
			break;
		}
		case UF_REPLICA:

			ASSERT(MUTEX_HELD(f->uf_vfs_lockp));

			/* not actually a replica? */
			if (f->uf_vfs_ufsfxp && f->uf_vfs_ufsfxp->fx_current &&
			    f->uf_vfs_ufsfxp->fx_current != f &&
			    !terminal_state(
			    f->uf_vfs_ufsfxp->fx_current->uf_s)) {

				f->uf_orig = f->uf_vfs_ufsfxp->fx_current;
				f->uf_retry = 0;
				rc = SFRC_SUCCESS;
			} else {
				TRIVIA((": NULL fx_current]\n"));
				f->uf_retry = 1;
			}

			break;

		default:
			rc = set_state(f, UF_PANIC);
			TRIVIA((": failed] "));
			break;
		}
		break;

	case UFA_FOUND:
		/*
		 * XXX de-allocate these after some period?
		 * XXX or move to an historical list?
		 * XXX or have an ioctl which reaps them?
		 */
		/*
		 * For now, since we don't expect lots of failures
		 * to occur (to the point of memory shortages),
		 * just punt
		 */

		/* be sure we're not wasting cpu on old failures */
		if (f->uf_retry != 0) {
			mutex_enter(&uf_stats.ufst_mutex);
			uf_stats.ufst_cpu_waste++;
			mutex_exit(&uf_stats.ufst_mutex);
			f->uf_retry = 0;
		}
		rc = SFRC_SUCCESS;
		break;

	default:
		(void) set_state(f, UF_PANIC);
		TRIVIA((": failed] "));
		break;
	}

	TRIVIA(("] "));
	return (rc);
}

static sfrc_t
sf_panic(
	ufs_failure_t	*f,
	ufsa_t	 a,
	ufs_failure_states_t	 s)
{
	sfrc_t	rc = SFRC_FAIL;

	TRIVIA(("[sf_panic, action is %s, prev. state is %s",
	    act_name(a), state_name(f->uf_s)));
	ASSERT(s & UF_PANIC);

	switch (a) {
	case UFA_SET:
		f->uf_retry = -ufsfx_tune.uft_short_err_period;
		rc = SFRC_SUCCESS;
		break;

	case UFA_FOUND:
	default:
		real_panic(f, " ");

		/* LINTED: warning: logical expression always true: op "||" */
		ASSERT(DEBUG);

		(void) set_state(f, UF_UMOUNT);	/* XXX UF_NOTFIX? */

		break;
	}

	TRIVIA(("] "));
	return (rc);
}

/*
 * minimum state function
 */
static sfrc_t
sf_minimum(
	ufs_failure_t	*f,
	ufsa_t	 a, /* LINTED argument unused in function: ignored */
	ufs_failure_states_t	 ignored)
{
	sfrc_t rc = SFRC_FAIL;

	TRIVIA(("[sf_minimum, action is %s", act_name(a)));

	switch (a) {
	case UFA_SET:
		f->uf_retry = 0;
		/* FALLTHROUGH */

	case UFA_FOUND:
		rc = SFRC_SUCCESS;
		break;

	default:
		(void) set_state(f, UF_PANIC);
		TRIVIA((": failed] "));
		break;
	}

	TRIVIA(("] "));
	return (rc);
}

static int
state_trans_valid(ufs_failure_states_t from, ufs_failure_states_t to)
{
	ufsd_t	*s;
	int	 valid;

	HIDEOUS(("[state_trans_valid"));

	if (from & to)
		return (1);

	s = get_state_desc(to);

	/*
	 * extra test is necessary since we want UF_UNDEF = 0,
	 * (to detect freshly allocated memory)
	 * but can't check for that value with a bit test
	 */
	valid = (to & UF_INIT)? from == s->ud_prev: from & s->ud_prev;

	HIDEOUS((": %svalid] ", valid? "": "in"));
	return (valid);
}

static int
terminal_state(ufs_failure_states_t state)
{
	ufsd_t	*s;

	HIDEOUS(("[terminal_state"));

	s = get_state_desc(state);

	HIDEOUS((": %sterminal] ", s->ud_attr.terminal? "": "not "));
	return ((int)s->ud_attr.terminal);
}

static void
alloc_lockfs_comment(ufs_failure_t *f, struct lockfs *lfp)
{
	MINUTE(("[alloc_lockfs_comment"));
	ASSERT(MUTEX_HELD(&f->uf_mutex));

	/*
	 * ufs_fiolfs expects a kmem_alloc'ed comment;
	 * it frees the comment if the lock fails
	 * or else when the lock is unlocked.
	 */

	f->uf_lf.lf_comment = kmem_zalloc(LOCKFS_MAXCOMMENTLEN, KM_NOSLEEP);
	if (f->uf_lf.lf_comment) {
		char	*from;
		size_t	 len;

		/*
		 * use panic string if there's no previous comment
		 * or if we're setting the error lock
		 */
		if ((LOCKFS_IS_ELOCK(&f->uf_lf) || !lfp->lf_comment ||
		    lfp->lf_comlen <= 0)) {
			from = f->uf_panic_str;
			len = LOCKFS_MAXCOMMENTLEN;
		} else {
			from = lfp->lf_comment;
			len = lfp->lf_comlen;
		}

		bcopy(from, f->uf_lf.lf_comment, len);
		f->uf_lf.lf_comlen = len;

	} else {
		f->uf_lf.lf_comlen = 0;
	}
	MINUTE(("] "));
}

static int
set_lockfs(ufs_failure_t *f, struct lockfs *lfp)
{
	int	(*handle_lockfs_rc)(ufs_failure_t *);
	int	  rc;

	MINUTE(("[set_lockfs"));
	ASSERT(MUTEX_HELD(&f->uf_mutex));
	ASSERT(!vfs_lock_held(f->uf_vfsp));
	ASSERT(MUTEX_NOT_HELD(f->uf_vfs_lockp));

	if (!f->uf_ufsvfsp) {
		MINUTE((": ufsvfsp is NULL]\n"));
		return (0);
	}

	ASSERT(MUTEX_NOT_HELD(&f->uf_ufsvfsp->vfs_ulockfs.ul_lock));

	if (!f->uf_ufsvfsp->vfs_root) {
		MINUTE((": vfs_root is NULL]\n"));
		return (0);
	}

	alloc_lockfs_comment(f, lfp);
	f->uf_lf_err = 0;

	if (!LOCKFS_IS_ELOCK(lfp)) {
		lfp->lf_lock = f->uf_lf.lf_lock = LOCKFS_ELOCK;
		VN_HOLD(f->uf_ufsvfsp->vfs_root);
		f->uf_lf_err =
		    ufs__fiolfs(f->uf_ufsvfsp->vfs_root,
		    &f->uf_lf, /* from_user */ 0, /* from_log */ 0);
		VN_RELE(f->uf_ufsvfsp->vfs_root);
	}

	handle_lockfs_rc = f->uf_lf_err != 0? lockfs_failure: lockfs_success;
	rc = handle_lockfs_rc(f);

	MINUTE(("] "));
	return (rc);
}

static int
lockfs_failure(ufs_failure_t *f)
{
	int	error;
	ufs_failure_states_t	s;

	TRIVIA(("[lockfs_failure"));
	ASSERT(MUTEX_HELD(&f->uf_mutex));

	if (!f->uf_ufsvfsp) {
		TRIVIA((": ufsvfsp is NULL]\n"));
		return (0);
	}

	error = f->uf_lf_err;
	switch (error) {
			/* non-transient errors: */
	case EACCES:	/* disk/in-core metadata reconciliation failed  */
	case EPERM:	/* inode reconciliation failed; incore inode changed? */
	case EIO:	/* device is hard-locked or not responding */
	case EROFS:	/* device is write-locked */
	case EDEADLK:	/* can't lockfs; deadlock would result; */
			/* Swapping or saving accounting records */
			/* onto this fs can cause this errno. */

		MINOR(("ufs_fiolfs(\"%s\") of %s failed: %s (%d)",
		    fs_name(f), lock_name(&f->uf_lf),
		    err_name(error), error));

		/*
		 * if can't get lock, then fallback to panic, unless
		 * unless unmount was requested (although unmount will
		 * probably fail if the lock failed, so we'll panic
		 * anyway
		 */

		s = ((f->uf_flags & UFSFX_LCKUMOUNT) && error != EDEADLK) ?
		    UF_UMOUNT: UF_PANIC;

		if (!set_state(f, s)) {
			real_panic(f, " ");
			/*NOTREACHED*/
			break;
		}
		break;


	case EBUSY:
	case EAGAIN:

		f->uf_retry = ufsfx_tune.uft_short_err_period;
		if (curthread->t_flag & T_DONTPEND) {
			curthread->t_flag &= ~T_DONTPEND;

		} else if (!(f->uf_s & (UF_LOCKED | UF_FIXING))) {
			ufs_failure_states_t state;
			/*
			 * if we didn't know that the fix had started,
			 * take note
			 */
			state = error == EBUSY? UF_LOCKED: UF_FIXING;
			if (!set_state(f, state)) {
				TRIVIA((": failed] "));
				return (0);
			}
		}
		break;

	default:	/* some other non-fatal error */
		MINOR(("lockfs(\"%s\") of %s returned %s (%d)",
		    lock_name(&f->uf_lf), fs_name(f),
		    err_name(f->uf_lf_err), f->uf_lf_err));

		f->uf_retry = ufsfx_tune.uft_short_err_period;
		break;

	case EINVAL:	/* unmounted? */
		(void) set_state(f, UF_NOTFIX);
		break;
	}
	TRIVIA(("] "));
	return (1);
}

static int
lockfs_success(ufs_failure_t *f)
{
	TRIVIA(("[lockfs_success"));
	ASSERT(MUTEX_HELD(&f->uf_mutex));

	if (!f->uf_ufsvfsp) {
		TRIVIA((": ufsvfsp is NULL]\n"));
		return (0);
	}

	switch (f->uf_lf.lf_lock) {
	case LOCKFS_ELOCK:	/* error lock worked */

		if (!set_state(f, UF_LOCKED)) {
			TRIVIA((": failed] "));
			return (0);
		}
		break;

	case LOCKFS_ULOCK: 			/* unlock worked */
		/*
		 * how'd we get here?
		 * This should be done from fsck's unlock,
		 * not from this thread's context.
		 */
		cmn_err(CE_WARN, "Unlocked error-lock of %s", fs_name(f));
		ufsfx_unlockfs(f->uf_ufsvfsp);
		break;

	default:
		if (!set_state(f, UF_NOTFIX)) {
			TRIVIA((": failed] "));
			return (0);
		}
		break;
	}
	TRIVIA(("] "));
	return (1);
}

/*
 * when fsck is running it puts its pid into the lockfs
 * comment structure, prefaced by PIDSTR
 */
const char *PIDSTR = "[pid:";
static int
fsck_active(ufs_failure_t *f)
{
	char		*cp;
	int		 i, found, errlocked;
	size_t		 comlen;
	const int	 PIDSTRLEN = (int)strlen(PIDSTR);
	struct ulockfs	*ulp = &f->uf_ufsvfsp->vfs_ulockfs;

	TRIVIA(("[fsck_active"));

	ASSERT(f);
	ASSERT(f->uf_s & UF_FIXING);
	ASSERT(MUTEX_HELD(&f->uf_mutex));
	ASSERT(f->uf_ufsvfsp);
	ASSERT(MUTEX_NOT_HELD(f->uf_vfs_lockp));
	ASSERT(MUTEX_NOT_HELD(&ulp->ul_lock));

	mutex_enter(&ulp->ul_lock);
	cp = ulp->ul_lockfs.lf_comment;
	comlen = ulp->ul_lockfs.lf_comlen;
	errlocked = (int)ULOCKFS_IS_ELOCK(ulp);
	mutex_exit(&ulp->ul_lock);

	if (!cp || comlen == 0) {
		TRIVIA((": null comment or comlen <= 0, found:0]"));
		return (0);
	}

	for (found = i = 0; !found && i < (comlen - PIDSTRLEN); i++, cp++)
		found = strncmp(cp, PIDSTR, PIDSTRLEN) == 0;

	TRIVIA(("found:%d, is_elock:%d]", found, errlocked));
	return (errlocked & found);
}

static const char unknown_fs[]		= "<unknown fs>";
static const char null_failure[] = "<NULL ufs failure record; unknown fs>";
static const char mutated_vfs_bufp[]	= "<mutated vfs_bufp, unknown fs>";
static const char mutated_vfs_fs[]	= "<mutated vfs_fs, unknown fs>";

static char *
fs_name(ufs_failure_t *f)
{
	HIDEOUS(("[fs_name"));
	ASSERT(MUTEX_HELD(&f->uf_mutex));

	if (!f) {
		HIDEOUS((": failure ptr is NULL]\n"));
		return ((char *)null_failure);
	}

	if (f->uf_fsname[0] != '\0') {
		HIDEOUS((": return (uf_fsname)]\n"));
		return (f->uf_fsname);
	}

	if (MUTEX_HELD(f->uf_vfs_lockp)) {
		if (f->uf_bp != f->uf_ufsvfsp->vfs_bufp) {
			HIDEOUS((": vfs_bufp mutated from 0x%p to 0x%p\n",
			    (void *)f->uf_bp, (void *)f->uf_ufsvfsp->vfs_bufp));
			return ((char *)mutated_vfs_bufp);
		}
		if (f->uf_fs != f->uf_ufsvfsp->vfs_fs) {
			HIDEOUS((": vfs_bufp mutated from 0x%p to 0x%p\n",
			    (void *)f->uf_fs, (void *)f->uf_ufsvfsp->vfs_fs));
			return ((char *)mutated_vfs_fs);
		}
		if (f->uf_ufsvfsp && f->uf_bp && f->uf_fs &&
		    *f->uf_fs->fs_fsmnt != '\0') {
			HIDEOUS((": return (fs_fsmnt)]\n"));
			return (f->uf_fs->fs_fsmnt);
		}
	}

	HIDEOUS((": unknown file system]\n"));
	return ((char *)unknown_fs);
}

#if defined(DEBUG)
static char *
lock_name(struct lockfs *lfp)
{
	struct lock_description	*l;
	char			*lname;

	HIDEOUS(("[lock_name"));

	lname = lock_desc[0].ld_name;
	for (l = &lock_desc[1]; l->ld_name != NULL; l++) {
		if (lfp && lfp->lf_lock == l->ld_type) {
			lname = l->ld_name;
			break;
		}
	}
	HIDEOUS(("]"));
	return (lname);
}

static char *
state_name(ufs_failure_states_t state)
{
	ufsd_t	*s;

	HIDEOUS(("[state_name"));

	s = get_state_desc(state);

	HIDEOUS(("]"));
	return (s->ud_name);
}

static char *
err_name(int error)
{
	struct error_description *e;

	HIDEOUS(("[err_name"));

	for (e = &err_desc[1]; e->ed_name != NULL; e++) {
		if (error == e->ed_errno) {
			HIDEOUS(("]"));
			return (e->ed_name);
		}
	}
	HIDEOUS(("]"));
	return (err_desc[0].ed_name);
}

static char *
act_name(ufsa_t action)
{
	struct action_description *a;

	HIDEOUS(("[act_name"));

	for (a = &act_desc[1]; a->ad_name != NULL; a++) {
		if (action == a->ad_v) {
			HIDEOUS(("]"));
			return (a->ad_name);
		}
	}
	HIDEOUS(("]"));
	return (act_desc[0].ad_name);
}

/*
 * dump failure list
 */
static void
dump_uf_list(char *msg)
{
	ufs_failure_t	*f;
	int		 i;
	int		 list_was_locked = MUTEX_HELD(&ufs_fix.uq_mutex);

	if (!list_was_locked && !mutex_tryenter(&ufs_fix.uq_mutex)) {
		printf("dump_uf_list: couldn't get list lock\n");
		return;
	}

	if (msg) {
		printf("\n%s", msg);
	}
	printf("\ndump_uf_list:\n\tuq_lowat: %d, uq_ne: %d\n",
	    ufs_fix.uq_lowat, ufs_fix.uq_ne);

	mutex_enter(&uf_stats.ufst_mutex);
	printf("\tuf_stats.current_races: %ld\n", uf_stats.ufst_current_races);
	printf("\tuf_stats.num_failed: %ld\n", uf_stats.ufst_num_failed);
	printf("\tuf_stats.num_fixed: %ld\n", uf_stats.ufst_num_fixed);
	printf("\tuf_stats.cpu_waste: %ld\n", uf_stats.ufst_cpu_waste);
	printf("\tuf_stats.lock_violations: %ld, unmount_failures: %ld\n",
	    uf_stats.ufst_lock_violations, uf_stats.ufst_unmount_failures);
	mutex_exit(&uf_stats.ufst_mutex);

	for (f = ufs_fix.uq_ufhead, i = 1; f; f = f->uf_next, i++) {

		if (!mutex_tryenter(&f->uf_mutex)) {
			printf("%d.\t\"skipped - try enter failed\"\n", i);
			continue;
		}

		dump_uf(f, i);

		mutex_exit(&f->uf_mutex);
	}

	printf("\n");

	if (!list_was_locked)
		mutex_exit(&ufs_fix.uq_mutex);
}

static void
dump_uf(ufs_failure_t *f, int i)
{
	if (!f) {
		printf("dump_uf: NULL failure record\n");
		return;
	}

	printf("%d.\t\"%s\" is %s.\n",
	    i, fs_name(f), state_name(f->uf_s));
	printf("\t\"%s\"\tAddr: 0x%p\n", f->uf_panic_str, (void *)f);
	printf("\tNext: 0x%p\t\tPrev: 0x%p\n",
	    (void *)f->uf_next, (void *)f->uf_prev);

	if (f->uf_orig)
		printf("\tOriginal failure: 0x%p \"%s\"\n",
		    (void *)f->uf_orig, f->uf_orig->uf_panic_str);

	printf("\tUfsvfs: 0x%p\t\tVfs_lockp: 0x%p\n",
	    (void *)f->uf_ufsvfsp, (void *)f->uf_vfs_lockp);
	printf("\tVfs_fsfxp: 0x%p\n", (void *)f->uf_vfs_ufsfxp);
	printf("\tVfs_bufp: 0x%p", (void *)f->uf_bp);

	if (f->uf_bp)
		printf("\t\tVfs_fs: 0x%p\n", (void *)f->uf_fs);
	else
		printf("\n");

	printf("\tBegin: 0x%lx\tEntered: 0x%lx\tEnd: 0x%lx\n",
	    f->uf_begin_tm, f->uf_entered_tm, f->uf_end_tm);

	printf("\tFlags: (%d) %s%s%s%s", f->uf_flags,
	    f->uf_flags & UFSFX_LCKONLY?	 "\"lock only\" "	: "",
	    f->uf_flags & UFSFX_LCKUMOUNT?	 "\"lock+unmount\" "	: "",
	    f->uf_flags & UFSFX_REPAIR_START? "\"started repair\" "	: "",
	    f->uf_flags == 0?                "<none>"               : "");

	printf("\tRetry: %ld seconds\n", f->uf_retry);

	printf("\tLockfs:\ttype: %s\terror: %s (%d)\n",
	    lock_name(&f->uf_lf), err_name(f->uf_lf_err), f->uf_lf_err);

}
#endif /* DEBUG */

/*
 * returns # of ufs_failures in a non-terminal state on queue
 * used to coordinate with hlock thread (see ufs_thread.c)
 * and to determine when the error lock thread may exit
 */

int
ufsfx_get_failure_qlen(void)
{
	ufs_failure_t	*f;
	ufsd_t		*s;
	int		 qlen = 0;

	MINUTE(("[ufsfx_get_failure_qlen"));

	if (!mutex_tryenter(&ufs_fix.uq_mutex))
		return (-1);

	/*
	 * walk down failure list
	 */

	for (f = ufs_fix.uq_ufhead; f; f = f->uf_next) {

		if (!mutex_tryenter(&f->uf_mutex))
			continue;

		s = get_state_desc(f->uf_s);

		if (s->ud_attr.terminal) {
			mutex_exit(&f->uf_mutex);
			continue;
		}

		MINUTE((": found: %s, \"%s: %s\"\n",
		    fs_name(f), state_name(f->uf_s), f->uf_panic_str));

		qlen++;
		mutex_exit(&f->uf_mutex);
	}

	mutex_exit(&ufs_fix.uq_mutex);

	MINUTE((": qlen=%d]\n", qlen));

	return (qlen);
}

/*
 * timeout routine
 *  called to shutdown fix failure thread and server daemon
 */
static void
ufsfx_kill_fix_failure_thread(void *arg)
{
	clock_t odelta = (clock_t)arg;
	int	qlen;

	MAJOR(("[ufsfx_kill_fix_failure_thread"));

	qlen = ufsfx_get_failure_qlen();

	if (qlen < 0) {
		clock_t delta;

		delta = odelta << 1;
		if (delta <= 0)
			delta = INT_MAX;

		(void) timeout(ufsfx_kill_fix_failure_thread,
		    (void *)delta, delta);
		MAJOR((": rescheduled"));

	} else if (qlen == 0) {
		ufs_thread_exit(&ufs_fix);
		MAJOR((": killed"));
	}
	/*
	 * else
	 *  let timeout expire
	 */
	MAJOR(("]\n"));
}
