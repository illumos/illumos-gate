/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

/*
 * The Linux auditing system provides a fairly complex rule-based syntax
 * for configuring what actions are to be audited. The user-level details
 * are generally described in the Linux audit.rules(7), auditctl(8), and
 * auditd(8) man pages. The user/kernel netlink API does not seem to be
 * documented. The Linux kernel source and the user-level auditd source must
 * be used to understand the interface we have to emulate. The relevant Linux
 * source files are:
 *   include/uapi/linux/audit.h
 *   include/linux/audit.h
 *   kernel/audit.c
 *
 * The lx_netlink module implements the API used for getting or changing the
 * audit configuration. For rule-oriented operations (list, append, delete),
 * an lx_audit_rule_t structure (or sequence when listing) is passed in/out of
 * the kernel. The netlink code calls into the lx_audit_append_rule or
 * lx_audit_delete_rule functions here to perform the relevant operation.
 * Within the lx_audit_rule_t structure, each member has the following
 * meaning:
 * lxar_flag:	corresponds to user-level list (e.g. "exit" for syscall return)
 * lxar_action:	user-level action (e.g. "always")
 * lxar_fld_cnt: number of fields specified in lxar_fields, lxar_values, and
 *		lxar_flg_flag arrays
 * lxar_mask:	syscall number bitmask the rule applies to (bit position in
 *		the array corresponds to the syscall number)
 * laxr_fields:	array of fields in the rule (i.e. each -F on user-level rule).
 *		A numeric code (e.g. LX_RF_AUDIT_ARCH) is assigned to each
 *		possible field.
 * lxar_values:	array of numeric field values (e.g. the internal b64 value on
 *		the -F AUDIT_ARCH=b64 rule)
 * lxar_fld_flag: array of field operators (e.g. the '=' operator on the
 *		-F AUDIT_ARCH=b64 rule)
 * lxar_buflen:	length of the buffer data immediately following
 * lxar_buf:	A variable amount of additional field string data. Non-numeric
 *		field values are passed here. For example, the string associated
 *		with the '-F key=...' or -F path=...' rules. For string values,
 *		the corresponding lxar_values entry is the length of the string.
 *		The strings in lxar_buf are not C strings because they are not
 *		NULL terminated. The character data is pulled out of lxar_buf
 *		in chunks specified by the value and the pointer into the buf
 *		is advanced accordingly.
 *
 * There are two primary kinds of actions which we are currently interested in
 * auditing;
 * 1) system call return
 *    this corresponds to user-level "exit" rule actions
 * 2) file system related actions
 *    this corresponds to user-level file system watch rules (-w)
 *
 * Only system call return is currently implemented, and only a very limited
 * subset of all of the possible rule selection behavior.
 *
 * The Linux audit rule syntax defines that all selection criteria within a
 * rule is ANDed together before an audit record is created. However, multiple
 * rules can be defined for a specific syscall. For example, this user-level
 * syntax defines two different rules for the "open" syscall:
 *     -a always,exit -F arch=b64 -S open -F auid>=1000 -F key=user-open
 *     -a always,exit -F arch=b64 -S open -F auid=0 -F key=priv-open
 * The first rule would cause an audit record to be created when an "open"
 * syscall returns and the syscall was performed by a process with a
 * loginuid >= 1000. The key added to that audit record would be "user-open".
 * The second rule would create an audit record if the loginuid was 0 and the
 * record's key would be "priv-open".
 *
 * When auditing is enabled for a syscall return, we have to look at multiple
 * rules and create an audit record for each rule that matches the selection
 * criteria.
 *
 * Although the current implementation is limited, the overall structure is
 * designed to be enhanced as more auditing support is added over time.
 *
 * By default, auditing is not enabled for a zone and no internal audit data
 * exists. When the first netlink audit msg is received, the zone's audit state
 * (lx_audit_state_t) is allocated (via lx_audit_init) and attached to the
 * zone's lx brand-specific data (lxzd_audit_state). Once allocated, the audit
 * data will persist until the zone halts.
 *
 * Audit records are enqueued onto the lxast_ev_queue and a worker thread
 * (lx_audit_worker) is responsible for dequeueing the audit records and
 * sending them up to the user-level auditd.
 *
 * Audit rules are stored in the lxast_rules list. This is an internal list
 * consisting of elements of type lx_audit_rule_ent_t. Each element contains
 * the input rule (lxare_rule) along with some additional data parsed out of
 * the rule when it is appended (currently only the arch and key).
 *
 * When auditing is enabled for a syscall, the appropriate entry in the
 * lxast_sys64_rulep (or lxast_sys32_rulep) array will point to the first
 * rule that is applicable to the syscall. When that syscall returns, rule
 * matching proceeds from that rule to the end of the rule list.
 *
 * New rules are always appended at the end of the list and Linux expects that
 * rules are matched in order.
 *
 * If the rule list ever gets large enough that a linear search, anchored off
 * the syscall pointer, becomes a performance bottleneck, then we'll have to
 * explore alternate implementations. However, use of auditing is not that
 * common to begin with, and most syscalls are typically not audited, so as
 * long as the number of rules is in the order of tens, then the current
 * implementation should be fine.
 *
 * When a rule is deleted, all associated syscall entries (lxast_sys64_rulep or
 * lxast_sys32_rulep) are cleared, then the rule list is searched to see if
 * there are any remaining rules which are applicable to the syscall(s). If so,
 * pointers are reestablished in the relevant lxast_sys64_rulep (or 32) array.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/ddi.h>
#include <sys/zone.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/tihdr.h>
#include <sys/sockio.h>
#include <sys/brand.h>
#include <sys/debug.h>
#include <sys/ucred.h>
#include <sys/session.h>
#include <sys/lx_types.h>
#include <sys/lx_audit.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <sys/lx_socket.h>
#include <sys/bitmap.h>
#include <sockcommon.h>

#define	LX_AUDIT_FEATURE_VERSION	1

/*
 * Audit status mask values (lxas_mask in structure defined below)
 * See Linux include/uapi/linux/audit.h
 */
#define	LX_AUDIT_STATUS_ENABLED			0x001
#define	LX_AUDIT_STATUS_FAILURE			0x002
#define	LX_AUDIT_STATUS_PID			0x004
#define	LX_AUDIT_STATUS_RATE_LIMIT		0x008
#define	LX_AUDIT_STATUS_BACKLOG_LIMIT		0x010
#define	LX_AUDIT_STATUS_BACKLOG_WAIT_TIME	0x020
#define	LX_AUDIT_STATUS_LOST			0x040

/*
 * Audit features
 * See Linux include/uapi/linux/audit.h
 */
#define	LX_AUDIT_F_BACKLOG_LIMIT	0x001
#define	LX_AUDIT_F_BACKLOG_WAIT_TIME	0x002
#define	LX_AUDIT_F_EXECUTABLE_PATH	0x004
#define	LX_AUDIT_F_EXCLUDE_EXTEND	0x008
#define	LX_AUDIT_F_SESSIONID_FILTER	0x010
#define	LX_AUDIT_F_LOST_RESET		0x020
#define	LX_AUDIT_F_FILTER_FS		0x040

#define	LX_AUDIT_FEATURE_ALL	(LX_AUDIT_F_BACKLOG_LIMIT | \
	LX_AUDIT_F_BACKLOG_WAIT_TIME | LX_AUDIT_F_EXECUTABLE_PATH | \
	LX_AUDIT_F_EXCLUDE_EXTEND | LX_AUDIT_F_SESSIONID_FILTER | \
	LX_AUDIT_F_LOST_RESET | LX_AUDIT_F_FILTER_FS)


/* Audit events */
#define	LX_AUDIT_SYSCALL	1300	/* syscall */
#define	LX_AUDIT_PATH		1302	/* file path */
#define	LX_AUDIT_CONFIG_CHANGE	1305	/* configuration change */
#define	LX_AUDIT_CWD		1307	/* current working directory */
#define	LX_AUDIT_EXECVE		1309	/* exec args */
#define	LX_AUDIT_EOE		1320	/* end of multi-record event */

#define	LX_AUDIT_BITMASK_SIZE		64
#define	LX_AUDIT_MAX_KEY_LEN		256

/* Audit rule filter type */
#define	LX_AUDIT_FILTER_USER		0	/* user generated msgs */
#define	LX_AUDIT_FILTER_TASK		1	/* task creation */
#define	LX_AUDIT_FILTER_ENTRY		2	/* syscall entry - obsolete */
#define	LX_AUDIT_FILTER_WATCH		3	/* fs watch */
#define	LX_AUDIT_FILTER_EXIT		4	/* syscall return */
#define	LX_AUDIT_FILTER_TYPE		5	/* audit log start */
#define	LX_AUDIT_FILTER_FS		6	/* audit inode child */

/* Audit rule action type */
#define	LX_AUDIT_ACT_NEVER		0
#define	LX_AUDIT_ACT_POSSIBLE		1
#define	LX_AUDIT_ACT_ALWAYS		2	/* the common case */

#define	LX_AUDIT_RULE_MAX_FIELDS	64

/* Linux defaults */
#define	LX_AUDIT_DEF_BACKLOG_LIMIT	64
#define	LX_AUDIT_DEF_WAIT_TIME		(60 * HZ_TO_LX_USERHZ(hz))

/*
 * Audit rule field types
 * Linux defines a lot of Rule Field values in include/uapi/linux/audit.h.
 * We currently only handle a few.
 */
#define	LX_RF_AUDIT_LOGINUID	9	/* e.g. auid>=1000 */
#define	LX_RF_AUDIT_ARCH	11	/* e.g.	-F arch=b64 */
#define	LX_RF_AUDIT_WATCH	105	/* user-level -w rule */
#define	LX_RF_AUDIT_PERM	106	/* user-level -p option */
#define	LX_RF_AUDIT_FILTERKEY	210	/* user-level -k key option */

/*
 * Audit rule field operators
 * Linux defines the operator values in include/uapi/linux/audit.h.
 * These 4 bits are combined in various ways for additional operators.
 */
#define	LX_OF_AUDIT_BM	0x08000000			/* bit mask (&) */
#define	LX_OF_AUDIT_LT	0x10000000
#define	LX_OF_AUDIT_GT	0x20000000
#define	LX_OF_AUDIT_EQ	0x40000000
#define	LX_OF_AUDIT_NE	(LX_OF_AUDIT_LT | LX_OF_AUDIT_GT)
#define	LX_OF_AUDIT_BT	(LX_OF_AUDIT_BM | LX_OF_AUDIT_EQ) /* bit test (&=) */
#define	LX_OF_AUDIT_LE	(LX_OF_AUDIT_LT | LX_OF_AUDIT_EQ)
#define	LX_OF_AUDIT_GE	(LX_OF_AUDIT_GT | LX_OF_AUDIT_EQ)
#define	LX_OF_AUDIT_ALL	(LX_OF_AUDIT_EQ | LX_OF_AUDIT_NE | LX_OF_AUDIT_BM)

/*
 * Audit rule arch specification
 * See Linux EM_X86_64 and EM_386 defs.
 * -F arch=b64 looks like: 0xc000003e
 * -F arch=b32 looks like: 0x40000003
 * If no arch is specified (possible with '-S syslog', '-S all', or '-w <file>')
 * the rule applies to both architectures and LX_RF_AUDIT_ARCH is not passed.
 */
#define	LX_AUDIT_ARCH64		0xc000003e
#define	LX_AUDIT_ARCH32		0x40000003

/*
 * See Linux include/uapi/linux/audit.h, AUDIT_MESSAGE_TEXT_MAX is 8560.
 * The auditd src has MAX_AUDIT_MESSAGE_LENGTH as 8970.
 * Until necessary, we'll limit ourselves to a smaller length.
 */
#define	LX_AUDIT_MESSAGE_TEXT_MAX	1024

typedef struct lx_audit_features {
	uint32_t	lxaf_version;
	uint32_t	lxaf_mask;
	uint32_t	lxaf_features;
	uint32_t	lxaf_lock;
} lx_audit_features_t;

typedef struct lx_audit_status {
	uint32_t	lxas_mask;
	uint32_t	lxas_enabled;
	uint32_t	lxas_failure;
	uint32_t	lxas_pid;
	uint32_t	lxas_rate_limit;
	uint32_t	lxas_backlog_limit;
	uint32_t	lxas_lost;
	uint32_t	lxas_backlog;
	/* LINTED: E_ANONYMOUS_UNION_DECL */
	union {
		uint32_t	lxas_version;
		uint32_t	lxas_feature_bitmap;
	};
	uint32_t	lxas_backlog_wait_time;
} lx_audit_status_t;

typedef struct lx_audit_rule {
	uint32_t	lxar_flag;
	uint32_t	lxar_action;
	uint32_t	lxar_fld_cnt;
	uint32_t	lxar_mask[LX_AUDIT_BITMASK_SIZE];
	uint32_t	lxar_fields[LX_AUDIT_RULE_MAX_FIELDS];
	uint32_t	lxar_values[LX_AUDIT_RULE_MAX_FIELDS];
	uint32_t	lxar_fld_flag[LX_AUDIT_RULE_MAX_FIELDS];
	uint32_t	lxar_buflen;
	/* LINTED: E_ZERO_OR_NEGATIVE_SUBSCRIPT */
	char		lxar_buf[0];
} lx_audit_rule_t;

/*
 * Internal structure for an audit rule.
 * Each rule is on the zone's top-level list of all rules (lxast_rules).
 * This structure also holds the parsed character string fields from the
 * original input rule (lxar_buf) so that we don't need to re-parse that
 * data on every match.
 */
typedef struct lx_audit_rule_ent {
	list_node_t	lxare_link;
	lx_audit_rule_t lxare_rule;
	char		*lxare_buf;
	boolean_t	lxare_is32bit;
	boolean_t	lxare_is64bit;
	char		*lxare_key;
} lx_audit_rule_ent_t;

typedef enum lx_audit_fail {
	LXAE_SILENT,
	LXAE_PRINT,	/* default */
	LXAE_PANIC	/* reboot the zone */
} lx_audit_fail_t;

typedef struct lx_audit_record {
	list_node_t	lxar_link;
	uint32_t	lxar_type;
	char		*lxar_msg;
} lx_audit_record_t;

/*
 * Per-zone audit state
 * Lazy allocated when first needed.
 *
 * lxast_rate_limit
 *    Currently unused, but can be get/set. Linux default is 0.
 * lxast_backlog_limit
 *    The maximum number of outstanding audit events allowed (the Linux kernel
 *    default is 64). If the limit is reached, lxast_failure determines what
 *    to do.
 * lxast_backlog_wait_time
 *    Currently unused, but can be get/set. Linux default is 60HZ.
 */
typedef struct lx_audit_state {
	lx_audit_fail_t	lxast_failure;		/* failure behavior */
	uint32_t	lxast_rate_limit;
	uint32_t	lxast_backlog_limit;
	uint32_t	lxast_backlog_wait_time;
	lx_audit_rule_ent_t *lxast_sys32_rulep[LX_NSYSCALLS];
	lx_audit_rule_ent_t *lxast_sys64_rulep[LX_NSYSCALLS];
	kcondvar_t	lxast_worker_cv;
	kmutex_t	lxast_lock;		/* protects members below */
	pid_t		lxast_pid;		/* auditd pid */
	uint64_t	lxast_seq;		/* event sequence num */
	uint32_t	lxast_backlog;		/* num of queued events */
	uint32_t	lxast_lost;		/* num of lost events */
	void		*lxast_sock;		/* auditd lx_netlink_sock_t */
	boolean_t	lxast_exit;		/* taskq worker should quit */
	boolean_t	lxast_panicing;		/* audit forcing reboot? */
	kthread_t	*lxast_worker;
	list_t		lxast_ev_queue;		/* audit record queue */
	list_t		lxast_rules;		/* the list of rules */
} lx_audit_state_t;

/*
 * Function pointer to netlink function used by audit worker threads to send
 * audit messages up to the user-level auditd.
 */
static int (*lx_audit_emit_msg)(void *, uint_t, const char *, uint_t);
static kmutex_t	lx_audit_em_lock;		/* protects emit_msg above */

/* From uts/common/brand/lx/syscall/lx_socket.c */
extern long lx_socket(int, int, int);
/* From uts/common/syscall/close.c */
extern int close(int);

static int
lx_audit_emit_syscall_event(uint_t mtype, void *lxsock, const char *msg)
{
	int err;

	err = lx_audit_emit_msg(lxsock, mtype, msg, LX_AUDIT_MESSAGE_TEXT_MAX);
	if (err != 0)
		return (err);
	err = lx_audit_emit_msg(lxsock, 0, NULL, 0);
	return (err);
}

/*
 * Worker thread for audit record output up to user-level auditd.
 */
static void
lx_audit_worker(void *a)
{
	lx_audit_state_t *asp = (lx_audit_state_t *)a;
	lx_audit_record_t *rp;
	int err;

	VERIFY(asp != NULL);

	mutex_enter(&asp->lxast_lock);

	while (!asp->lxast_exit) {

		if (asp->lxast_backlog == 0 || asp->lxast_sock == NULL ||
		    asp->lxast_pid == 0) {
			cv_wait(&asp->lxast_worker_cv, &asp->lxast_lock);
			continue;
		}

		rp = list_remove_head(&asp->lxast_ev_queue);
		asp->lxast_backlog--;

		err = lx_audit_emit_syscall_event(rp->lxar_type,
		    asp->lxast_sock, rp->lxar_msg);
		if (err != ENOMEM) {
			kmem_free(rp->lxar_msg, LX_AUDIT_MESSAGE_TEXT_MAX);
			kmem_free(rp, sizeof (lx_audit_record_t));
		} else {
			/*
			 * Put it back on the list, drop the mutex so that
			 * any other audit-related action could occur (such as
			 * socket deletion), then wait briefly before retry.
			 */
			list_insert_head(&asp->lxast_ev_queue, rp);
			asp->lxast_backlog++;
			mutex_exit(&asp->lxast_lock);
			/* wait 1/10th second and try again */
			delay(drv_usectohz(100000));
			mutex_enter(&asp->lxast_lock);
		}
	}

	/* Leave state ready for new worker when auditing restarted */
	asp->lxast_exit = B_FALSE;
	mutex_exit(&asp->lxast_lock);

	thread_exit();
}

static void
lx_audit_set_worker(uint32_t pid, void *lxsock,
    void (*cb)(void *, boolean_t))
{
	lx_audit_state_t *asp = ztolxzd(curzone)->lxzd_audit_state;

	ASSERT(asp != NULL);
	ASSERT(MUTEX_HELD(&asp->lxast_lock));

	/* First, stop any existing worker thread */
	while (asp->lxast_sock != NULL) {
		mutex_exit(&asp->lxast_lock);
		lx_audit_stop_worker(NULL, cb);
		mutex_enter(&asp->lxast_lock);
		/* unlikely we loop, but handle racing setters */
	}

	VERIFY(asp->lxast_pid == 0);
	VERIFY(asp->lxast_sock == NULL);
	VERIFY(asp->lxast_exit == B_FALSE);
	VERIFY(asp->lxast_worker == NULL);
	if (pid != 0) {
		/* Start a worker with the new socket */
		asp->lxast_sock = lxsock;
		cb(asp->lxast_sock, B_TRUE);
		asp->lxast_pid = pid;
		asp->lxast_worker = thread_create(NULL, 0, lx_audit_worker,
		    asp, 0, curzone->zone_zsched, TS_RUN, minclsyspri);
	}
}

static boolean_t
lx_audit_match_val(uint32_t op, uint32_t ruleval, uint32_t curval)
{
	switch (op) {
	case LX_OF_AUDIT_LT:
		return (curval < ruleval);
	case LX_OF_AUDIT_GT:
		return (curval > ruleval);
	case LX_OF_AUDIT_EQ:
		return (curval == ruleval);
	case LX_OF_AUDIT_NE:
		return (curval != ruleval);
	case LX_OF_AUDIT_LE:
		return (curval <= ruleval);
	case LX_OF_AUDIT_GE:
		return (curval >= ruleval);
	case LX_OF_AUDIT_BM:	/* bit mask - any bit is set? */
		return ((curval & ruleval) != 0);
	case LX_OF_AUDIT_BT:	/* bit test - all bits must be set */
		return ((curval & ruleval) == ruleval);
	default:
		break;
	}
	return (B_FALSE);
}

/*
 * Per the Linux audit.rules(7) man page, a rule with an auid of -1 means the
 * process does not have a loginuid. We'll use the absence of a session on the
 * process to mimic this behavior.
 */
static uint32_t
lx_audit_get_auid()
{
	sess_t *s;
	uint32_t v;

	/*
	 * A process with no session has:
	 * s_dev == 0xffffffffffffffff
	 * s_vp == NULL
	 * s_cred == NULL
	 */
	s = curproc->p_sessp;
	if (s != NULL && s->s_vp != NULL) {
		v = crgetsuid(CRED());
	} else {
		v = UINT32_MAX;	/* emulate auid of -1 */
	}

	return (v);
}

/*
 * Determine if the rule matches.
 * Currently, we're actually just checking LX_RF_AUDIT_LOGINUID (-F auid)
 * fields, but as we add support for additional field matching, this function
 * should be enhanced.
 */
static boolean_t
lx_audit_syscall_rule_match(lx_audit_rule_ent_t *erp)
{
	uint32_t i, v;
	lx_audit_rule_t *rp = &erp->lxare_rule;

	for (i = 0; i < rp->lxar_fld_cnt; i++) {
		uint32_t ftype, fval, fop;

		ftype = rp->lxar_fields[i];
		if (ftype != LX_RF_AUDIT_LOGINUID)
			continue;

		fop = rp->lxar_fld_flag[i];
		fval = rp->lxar_values[i];
		v = lx_audit_get_auid();

		if (!lx_audit_match_val(fop, fval, v))
			return (B_FALSE);
	}
	return (B_TRUE);
}

static int
lx_audit_write(file_t *fp, const char *msg)
{
	int fflag;
	ssize_t count;
	size_t nwrite = 0;
	struct uio auio;
	struct iovec aiov;

	count = strlen(msg);
	fflag = fp->f_flag;

	aiov.iov_base = (void *) msg;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fp->f_offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_DEFAULT;

	return (lx_write_common(fp, &auio, &nwrite, B_FALSE));
}

/*
 * We first try to send the msg out to the zone's logging service, then
 * fallback to the zone's console, although in practice, that is unlikely to
 * be useful to most users.
 */
static void
lx_audit_log_msg(const char *msg)
{
	int fd;
	struct sockaddr_un addr;
	struct sonode *so;
	uint_t alen;
	uint_t sizediff = (sizeof (addr) - sizeof (addr.sun_path));
	file_t *fp;
	int err;
	vnode_t *vp;

	ttolwp(curthread)->lwp_errno = 0;
	fd = lx_socket(LX_AF_UNIX, LX_SOCK_DGRAM, 0);
	if (ttolwp(curthread)->lwp_errno != 0)
		goto trycons;

	bzero((char *)&addr, sizeof (addr));
	addr.sun_family = AF_UNIX;
	(void) strncpy(addr.sun_path, "/dev/log", sizeof (addr.sun_path) - 1);
	alen = strlen(addr.sun_path) + 1 + sizediff;

	/*
	 * We can't use lx_connect here since that expects to be called from
	 * user-land, so we do the (streamlined) connect ourselves.
	 */
	if ((so = getsonode(fd, &err, &fp)) == NULL) {
		(void) close(fd);
		goto trycons;
	}

	err = socket_connect(so, (struct sockaddr *)&addr, alen, fp->f_flag,
	    _SOCONNECT_XPG4_2, CRED());

	if (err == 0)
		err = lx_audit_write(fp, msg);

	releasef(fd);		/* release getsonode hold */
	(void) close(fd);

	if (err == 0)
		return;

trycons:
	/* "open" the console device */
	if (lookupnameatcred("/dev/console", UIO_SYSSPACE, FOLLOW, NULLVPP,
	    &vp, NULL, CRED()) != 0)
		return;

	if (falloc(vp, FWRITE, &fp, &fd) != 0) {
		VN_RELE(vp);
		return;
	}
	mutex_exit(&fp->f_tlock);
	setf(fd, fp);

	/* nothing left to do if console write fails */
	(void) lx_audit_write(fp, msg);
	close(fd);
}

static void
lx_audit_fail(lx_audit_state_t *asp, const char *msg)
{
	ASSERT(MUTEX_HELD(&asp->lxast_lock));

	if (asp->lxast_failure == LXAE_PRINT ||
	    asp->lxast_failure == LXAE_PANIC) {
		/*
		 * Linux can ratelimit the amount of log spam here, so we'll
		 * do something similar, especially since this could be called
		 * on many syscall returns if the audit daemon is down or
		 * not consuming audit records for some other reason.
		 */
		if (asp->lxast_lost % 100 == 0)
			lx_audit_log_msg(msg);
		if (asp->lxast_failure == LXAE_PANIC &&
		    !asp->lxast_panicing) {
			/*
			 * Reboot the zone so that no audit records are lost.
			 * We delay a second to give the zone's logger a chance
			 * to handle the log message. We have to drop the lock
			 * here in case the zone's logger itself is making
			 * syscalls which would be audited, although that
			 * wouldn't be the ideal configuration.
			 */
			asp->lxast_panicing = B_TRUE;
			mutex_exit(&asp->lxast_lock);
			lx_audit_log_msg("audit: panic");
			delay(drv_usectohz(1000000));
			zone_kadmin(A_SHUTDOWN, AD_BOOT, NULL, kcred);
			mutex_enter(&asp->lxast_lock);
		}
	}
	asp->lxast_lost++;
}

/*
 * This formats the input string into a format that matches Linux. The input
 * strings are small right now (<= PSARGSZ) so for simpicity we're using
 * a temporary buffer of adequate size.
 */
static void
lx_audit_fmt_str(char *dst, char *str, uint_t dlen)
{
	char *sp, tmp[100];

	(void) strlcpy(tmp, str, sizeof (tmp));
	if ((sp = strchr(tmp, ' ')) != NULL)
		*sp = '\0';

	if ((sp = strchr(tmp, '"')) == NULL) {
		(void) snprintf(dst, dlen, "\"%s\"", tmp);
	} else {
		char *p, *dp;
		uint_t olen = 0;

		ASSERT(dlen > 2);
		dlen -= 2;	/* leave room for terminating nul */
		dp = dst;
		for (p = str; *p != '\0' && olen < dlen; p++) {
			(void) sprintf(dp, "%02x", *p);
			dp += 2;
			olen += 2;
		}
		*dp = '\0';
	}
}

/*
 * Format and enqueue a syscall audit record.
 */
static void
lx_audit_syscall_fmt_rcd(int sysnum, uint32_t arch, long ret,
    lx_audit_state_t *asp, lx_audit_rule_ent_t *erp, uint64_t seq,
    timestruc_t *tsp)
{
	klwp_t *lwp;
	proc_t *p;
	uint32_t items, sessid;
	lx_lwp_data_t *lwpd;
	lx_audit_record_t *rp;
	cred_t *cr = CRED();
	minor_t minor;
	char key[LX_AUDIT_MAX_KEY_LEN + 6]; /* for key="%s" formatting */
	char exe[PSARGSZ * 2 + 8], comm[MAXCOMLEN * 2 + 8];

	ASSERT(MUTEX_HELD(&asp->lxast_lock));

	if (asp->lxast_backlog >= asp->lxast_backlog_limit) {
		lx_audit_fail(asp, "audit: backlog limit exceeded");
		return;
	}

	if (arch == LX_AUDIT_ARCH32) {
		items = MIN(4, lx_sysent32[sysnum].sy_narg);
	} else {
		ASSERT3U(arch, ==, LX_AUDIT_ARCH64);
		items = MIN(4, lx_sysent64[sysnum].sy_narg);
	}

	lwp = ttolwp(curthread);
	lwpd = lwptolxlwp(lwp);
	p = curproc;

	/*
	 * For the key, if no key has been set on the rule, Linux formats the
	 * string "(null)" (with no quotes - i.e. key=(null)).
	 */
	if (erp->lxare_key != NULL) {
		(void) snprintf(key, sizeof (key), "key=\"%s\"",
		    erp->lxare_key);
	} else {
		(void) snprintf(key, sizeof (key), "key=(null)");
	}

	rp = kmem_alloc(sizeof (lx_audit_record_t), KM_NOSLEEP);
	if (rp == NULL) {
		lx_audit_fail(asp, "audit: no kernel memory");
		return;
	}
	rp->lxar_msg = kmem_zalloc(LX_AUDIT_MESSAGE_TEXT_MAX, KM_NOSLEEP);
	if (rp->lxar_msg == NULL) {
		kmem_free(rp, sizeof (lx_audit_record_t));
		lx_audit_fail(asp, "audit: no kernel memory");
		return;
	}
	rp->lxar_type = LX_AUDIT_SYSCALL;

	mutex_enter(&p->p_splock);
	sessid = p->p_sessp->s_sid;
	minor = getminor(p->p_sessp->s_dev);
	mutex_exit(&p->p_splock);

	mutex_enter(&p->p_lock);
	lx_audit_fmt_str(exe, p->p_user.u_psargs, sizeof (exe));
	lx_audit_fmt_str(comm, p->p_user.u_comm, sizeof (comm));
	mutex_exit(&p->p_lock);

	/*
	 * See Linux audit_log_exit() for how a syscall exit record is
	 * formatted.
	 *
	 * For "arch" value, see Linux AUDIT_ARCH_IA64, AUDIT_ARCH_I386,
	 * __AUDIT_ARCH_64BIT and __AUDIT_ARCH_LE definitions.
	 *
	 * For fsuid/fsgid, see lx_setfsuid/lx_setfsgid for how we handle that.
	 */
	(void) snprintf(rp->lxar_msg, LX_AUDIT_MESSAGE_TEXT_MAX,
	    "audit(%lu.%03lu:%lu): arch=%x syscall=%u "
	    "success=%s exit=%ld a0=%lu a1=%lu a2=%lu a3=%lu items=%u "
	    "ppid=%u pid=%u auid=%u uid=%u gid=%u euid=%u suid=%u "
	    "fsuid=%u egid=%u sgid=%u fsgid=%u tty=pts%u ses=%u "
	    "comm=%s exe=%s %s",
	    (uint64_t)tsp->tv_sec,			/* zone's timestamp */
	    (uint64_t)tsp->tv_nsec / 1000000,
	    seq,					/* serial number */
	    arch,					/* arch */
	    sysnum,					/* syscall */
	    (lwp->lwp_errno == 0 ? "yes" : "no"),	/* success */
	    ret,					/* exit */
	    lwpd->br_syscall_args[0],			/* a0 */
	    lwpd->br_syscall_args[1],			/* a1 */
	    lwpd->br_syscall_args[2],			/* a2 */
	    lwpd->br_syscall_args[3],			/* a3 */
	    items,					/* items */
	    lx_lwp_ppid(lwp, NULL, NULL),		/* ppid */
	    (lwpd->br_pid == curzone->zone_proc_initpid ? 1 : lwpd->br_pid),
	    lx_audit_get_auid(),			/* auid */
	    crgetruid(cr),				/* uid */
	    crgetrgid(cr),				/* gid */
	    crgetuid(cr),				/* euid */
	    crgetsuid(cr),				/* saved uid */
	    crgetuid(cr),				/* fsuid */
	    crgetgid(cr),				/* egid */
	    crgetsgid(cr),				/* saved gid */
	    crgetgid(cr),				/* fsgid */
	    minor,					/* tty */
	    sessid,					/* ses */
	    comm,					/* comm */
	    exe,					/* exe */
	    key);					/* key="VAL" */

	list_insert_tail(&asp->lxast_ev_queue, rp);
	if (asp->lxast_backlog == 0)
		cv_signal(&asp->lxast_worker_cv);
	asp->lxast_backlog++;
}

/*
 * Get the next rule in the list that is generally applicable to the given
 * syscall.
 */
static lx_audit_rule_ent_t *
lx_audit_next_applicable_rule(int sysnum, uint32_t arch, lx_audit_state_t *asp,
    lx_audit_rule_ent_t *erp)
{
	ASSERT(MUTEX_HELD(&asp->lxast_lock));

	for (erp = list_next(&asp->lxast_rules, erp);
	    erp != NULL;
	    erp = list_next(&asp->lxast_rules, erp)) {
		lx_audit_rule_t *r = &erp->lxare_rule;

		/* Determine if the rule in the list has the same ARCH. */
		if (arch == LX_AUDIT_ARCH32 && !erp->lxare_is32bit)
			continue;
		if (arch == LX_AUDIT_ARCH64 && !erp->lxare_is64bit)
			continue;

		/* Determine if this rule applies to the relevant syscall. */
		if (BT_TEST32(r->lxar_mask, sysnum))
			return (erp);
	}

	return (NULL);
}

void
lx_audit_syscall_exit(int sysnum, long ret)
{
	lx_zone_data_t *lxzd = ztolxzd(curzone);
	lx_audit_state_t *asp;
	uint64_t seq;
	lx_audit_rule_ent_t *erp;
	timestruc_t ts;
	uint32_t arch;

	if (lxzd->lxzd_audit_enabled == LXAE_DISABLED)
		return;

	asp = lxzd->lxzd_audit_state;
	ASSERT(asp != NULL);

	if (get_udatamodel() == DATAMODEL_ILP32) {
		arch = LX_AUDIT_ARCH32;
	} else {
		ASSERT(get_udatamodel() == DATAMODEL_LP64);
		arch = LX_AUDIT_ARCH64;
	}

	/*
	 * Fast top-level check to see if we're auditing this syscall.
	 * We don't take the mutex for this since there is no need.
	 */
	if (arch == LX_AUDIT_ARCH32) {
		if (asp->lxast_sys32_rulep[sysnum] == NULL)
			return;
	} else {
		if (asp->lxast_sys64_rulep[sysnum] == NULL)
			return;
	}

	mutex_enter(&asp->lxast_lock);
	if (arch == LX_AUDIT_ARCH32) {
		erp = asp->lxast_sys32_rulep[sysnum];
	} else {
		erp = asp->lxast_sys64_rulep[sysnum];
	}

	if (erp == NULL) {
		/* Hit a race and the syscall is no longer being audited */
		mutex_exit(&asp->lxast_lock);
		return;
	}

	/*
	 * All of the records in the set (i.e. same serial number) have
	 * the same timestamp.
	 */
	seq = asp->lxast_seq++;
	gethrestime(&ts);
	ts.tv_sec -= curzone->zone_boot_time;

	/*
	 * We have to determine if the first rule associated with the syscall,
	 * or any subsequent applicable rules, match.
	 *
	 * The first rule associated with the syscall may (or may not) match,
	 * but there can be additional rules which might also match. The first
	 * possible rule is always the one that enables the syscall auditing,
	 * but we also have to iterate to the end of the list to see if any
	 * other rules are applicable to this syscall.
	 */
	for (; erp != NULL;
	    erp = lx_audit_next_applicable_rule(sysnum, arch, asp, erp)) {
		if (!lx_audit_syscall_rule_match(erp))
			continue;

		lx_audit_syscall_fmt_rcd(sysnum, arch, ret, asp, erp, seq, &ts);
	}

	/*
	 * TODO: Currently we only output a single SYSCALL record.
	 * Real Linux emits a set of audit records for a syscall exit event
	 * (e.g. for an unlink syscall):
	 * type=SYSCALL
	 * type=CWD
	 * type=PATH - one for the parent dir
	 * type=PATH - one for the actual file unlinked
	 * type=PROCTITLE - (this one seems worthless)
	 * followed by an AUDIT_EOE message (which seems to be ignored).
	 *
	 * For syscalls that don't change files in the file system (e.g. ioctl)
	 * there are no PATH records.
	 */
	mutex_exit(&asp->lxast_lock);
}

/*
 * Determine which syscalls this rule applies to and setup a fast pointer for
 * the syscall to enable it's rule match.
 *
 * We have to look at each bit and translate the external syscall bits into the
 * internal syscall number.
 */
static void
lx_enable_syscall_rule(lx_audit_state_t *asp, lx_audit_rule_t *rulep,
    lx_audit_rule_ent_t *rp)
{
	uint_t sysnum;

	ASSERT(MUTEX_HELD(&asp->lxast_lock));

	for (sysnum = 0; sysnum < LX_NSYSCALLS; sysnum++) {
		if (BT_TEST32(rulep->lxar_mask, sysnum)) {
			if (rp->lxare_is32bit) {
				if (asp->lxast_sys32_rulep[sysnum] == NULL)
					asp->lxast_sys32_rulep[sysnum] = rp;
			}
			if (rp->lxare_is64bit) {
				if (asp->lxast_sys64_rulep[sysnum] == NULL)
					asp->lxast_sys64_rulep[sysnum] = rp;
			}
		}
	}
}

int
lx_audit_append_rule(void *r, uint_t datalen)
{
	lx_audit_rule_t *rulep = (lx_audit_rule_t *)r;
	char *datap;
	uint_t i;
	lx_audit_rule_ent_t *rp;
	lx_audit_state_t *asp;
	boolean_t is_32bit = B_TRUE, is_64bit = B_TRUE, sys_found = B_FALSE;
	char *tdp;
	char key[LX_AUDIT_MAX_KEY_LEN + 1];
	uint32_t tlen;

	if (ztolxzd(curproc->p_zone)->lxzd_audit_enabled == LXAE_LOCKED)
		return (EPERM);

	if (datalen < sizeof (lx_audit_rule_t))
		return (EINVAL);
	datalen -= sizeof (lx_audit_rule_t);

	if (rulep->lxar_fld_cnt > LX_AUDIT_RULE_MAX_FIELDS)
		return (EINVAL);

	if (rulep->lxar_buflen > datalen)
		return (EINVAL);

	datap = rulep->lxar_buf;

	/*
	 * First check the rule to determine if we support the flag, actions,
	 * and all of the fields specified (since currently, our rule support
	 * is incomplete).
	 *
	 * NOTE: We currently only handle syscall exit rules.
	 */
	if (rulep->lxar_flag != LX_AUDIT_FILTER_EXIT ||
	    rulep->lxar_action != LX_AUDIT_ACT_ALWAYS)
		return (ENOTSUP);
	if (rulep->lxar_fld_cnt > LX_AUDIT_RULE_MAX_FIELDS)
		return (EINVAL);
	tdp = datap;
	tlen = rulep->lxar_buflen;
	key[0] = '\0';
	for (i = 0; i < rulep->lxar_fld_cnt; i++) {
		uint32_t ftype, fval, fop;

		fop = rulep->lxar_fld_flag[i];
		ftype = rulep->lxar_fields[i];
		fval = rulep->lxar_values[i];
		DTRACE_PROBE3(lx__audit__field, uint32_t, fop,
		    uint32_t, ftype, uint32_t, fval);

		if (ftype == LX_RF_AUDIT_ARCH) {
			if (fop != LX_OF_AUDIT_EQ)
				return (ENOTSUP);
			if (!is_32bit || !is_64bit)
				return (EINVAL);
			if (fval == LX_AUDIT_ARCH64) {
				is_32bit = B_FALSE;
			} else if (fval == LX_AUDIT_ARCH32) {
				is_64bit = B_FALSE;
			} else {
				return (ENOTSUP);
			}
		} else if (ftype == LX_RF_AUDIT_LOGINUID) {
			if ((fop & LX_OF_AUDIT_ALL) == 0)
				return (ENOTSUP);
		} else if (ftype == LX_RF_AUDIT_FILTERKEY) {
			if (fop != LX_OF_AUDIT_EQ)
				return (ENOTSUP);
			if (tlen < fval || fval > LX_AUDIT_MAX_KEY_LEN)
				return (EINVAL);
			if (key[0] != '\0')
				return (EINVAL);
			/* while we're here, save the parsed key */
			bcopy(tdp, key, fval);
			key[fval] = '\0';
			tdp += fval;
			tlen -= fval;
		} else {
			/*
			 * TODO: expand the support for additional Linux field
			 * options.
			 */
			return (ENOTSUP);
		}
	}
	for (i = 0; i < LX_NSYSCALLS; i++) {
		if (BT_TEST32(rulep->lxar_mask, i)) {
			/* At least one syscall enabled in this mask entry */
			sys_found = B_TRUE;
			break;
		}
	}
	if (!sys_found)
		return (ENOTSUP);

	asp = ztolxzd(curzone)->lxzd_audit_state;
	ASSERT(asp != NULL);

	/*
	 * We have confirmed that we can handle the rule specified.
	 * Before taking the lock, allocate and setup the internal rule struct.
	 */
	rp = kmem_alloc(sizeof (lx_audit_rule_ent_t), KM_SLEEP);
	bcopy(rulep, &rp->lxare_rule, sizeof (lx_audit_rule_t));
	rp->lxare_buf = kmem_alloc(rulep->lxar_buflen, KM_SLEEP);
	bcopy(datap, rp->lxare_buf, rulep->lxar_buflen);
	rp->lxare_is32bit = is_32bit;
	rp->lxare_is64bit = is_64bit;
	if (key[0] == '\0') {
		rp->lxare_key = NULL;
	} else {
		int slen = strlen(key);
		rp->lxare_key = kmem_alloc(slen + 1, KM_SLEEP);
		(void) strlcpy(rp->lxare_key, key, slen + 1);
	}

	mutex_enter(&asp->lxast_lock);
	/* Save the rule on our top-level list. */
	list_insert_tail(&asp->lxast_rules, rp);
	/* Enable tracing on the relevant syscalls. */
	lx_enable_syscall_rule(asp, rulep, rp);
	mutex_exit(&asp->lxast_lock);

	return (0);
}

int
lx_audit_delete_rule(void *r, uint_t datalen)
{
	lx_audit_rule_t *rulep = (lx_audit_rule_t *)r;
	char *datap;
	uint_t sysnum;
	lx_audit_state_t *asp;
	lx_audit_rule_ent_t *erp;

	if (ztolxzd(curproc->p_zone)->lxzd_audit_enabled == LXAE_LOCKED)
		return (EPERM);

	if (datalen < sizeof (lx_audit_rule_t))
		return (EINVAL);
	datalen -= sizeof (lx_audit_rule_t);

	if (rulep->lxar_fld_cnt > LX_AUDIT_RULE_MAX_FIELDS)
		return (EINVAL);

	if (rulep->lxar_buflen > datalen)
		return (EINVAL);

	datap = rulep->lxar_buf;

	asp = ztolxzd(curzone)->lxzd_audit_state;
	ASSERT(asp != NULL);

	mutex_enter(&asp->lxast_lock);

	/* Find the matching rule from the rule list */
	for (erp = list_head(&asp->lxast_rules);
	    erp != NULL;
	    erp = list_next(&asp->lxast_rules, erp)) {
		lx_audit_rule_t *r;
		uint_t i;
		boolean_t mtch;

		r = &erp->lxare_rule;
		if (rulep->lxar_flag != r->lxar_flag)
			continue;
		if (rulep->lxar_action != r->lxar_action)
			continue;
		if (rulep->lxar_fld_cnt != r->lxar_fld_cnt)
			continue;
		for (i = 0, mtch = B_TRUE; i < LX_AUDIT_BITMASK_SIZE; i++) {
			if (rulep->lxar_mask[i] != r->lxar_mask[i]) {
				mtch = B_FALSE;
				break;
			}
		}
		if (!mtch)
			continue;

		for (i = 0, mtch = B_TRUE; i < rulep->lxar_fld_cnt; i++) {
			if (rulep->lxar_fields[i] != r->lxar_fields[i] ||
			    rulep->lxar_values[i] != r->lxar_values[i] ||
			    rulep->lxar_fld_flag[i] != r->lxar_fld_flag[i]) {
				mtch = B_FALSE;
				break;
			}
		}
		if (!mtch)
			continue;
		if (rulep->lxar_buflen != r->lxar_buflen)
			continue;
		if (bcmp(datap, erp->lxare_buf, r->lxar_buflen) == 0)
			break;
	}

	/* There is no matching rule */
	if (erp == NULL) {
		mutex_exit(&asp->lxast_lock);
		return (ENOENT);
	}

	/*
	 * Disable each relevant syscall enabling.
	 */
	for (sysnum = 0; sysnum < LX_NSYSCALLS; sysnum++) {
		if (BT_TEST32(rulep->lxar_mask, sysnum)) {
			/*
			 * If this was the first rule on the list for the
			 * given syscall (likely, since usually only one rule
			 * per syscall) then either disable tracing for that
			 * syscall, or point to the next applicable rule in the
			 * list.
			 */
			if (erp->lxare_is32bit) {
				if (asp->lxast_sys32_rulep[sysnum] == erp) {
					asp->lxast_sys32_rulep[sysnum] =
					    lx_audit_next_applicable_rule(
					    sysnum, LX_AUDIT_ARCH32, asp, erp);
				}
			}
			if (erp->lxare_is64bit) {
				if (asp->lxast_sys64_rulep[sysnum] == erp) {
					asp->lxast_sys64_rulep[sysnum] =
					    lx_audit_next_applicable_rule(
					    sysnum, LX_AUDIT_ARCH64, asp, erp);
				}
			}
		}
	}

	/* Remove the rule from the top-level list */
	list_remove(&asp->lxast_rules, erp);

	kmem_free(erp->lxare_buf, erp->lxare_rule.lxar_buflen);
	if (erp->lxare_key != NULL)
		kmem_free(erp->lxare_key, strlen(erp->lxare_key) + 1);
	kmem_free(erp, sizeof (lx_audit_rule_ent_t));

	mutex_exit(&asp->lxast_lock);
	return (0);
}

void
lx_audit_emit_user_msg(uint_t mtype, uint_t len, char *datap)
{
	lx_zone_data_t *lxzd = ztolxzd(curzone);
	lx_audit_state_t *asp;
	lx_audit_record_t *rp;
	timestruc_t ts;
	uint_t sessid;
	proc_t *p = curproc;
	lx_lwp_data_t *lwpd = lwptolxlwp(ttolwp(curthread));
	uint_t prelen, alen;
	char msg[LX_AUDIT_MESSAGE_TEXT_MAX];

	/*
	 * For user messages, auditing may not actually be initialized. If not,
	 * just return.
	 */
	if (lxzd->lxzd_audit_enabled == LXAE_DISABLED ||
	    lxzd->lxzd_audit_state == NULL)
		return;

	mutex_enter(&p->p_splock);
	sessid = p->p_sessp->s_sid;
	mutex_exit(&p->p_splock);

	asp = lxzd->lxzd_audit_state;
	ASSERT(asp != NULL);

	mutex_enter(&asp->lxast_lock);

	if (asp->lxast_backlog >= asp->lxast_backlog_limit) {
		lx_audit_fail(asp, "audit: backlog limit exceeded");
		mutex_exit(&asp->lxast_lock);
		return;
	}

	rp = kmem_alloc(sizeof (lx_audit_record_t), KM_NOSLEEP);
	if (rp == NULL) {
		lx_audit_fail(asp, "audit: no kernel memory");
		mutex_exit(&asp->lxast_lock);
		return;
	}
	rp->lxar_msg = kmem_zalloc(LX_AUDIT_MESSAGE_TEXT_MAX, KM_NOSLEEP);
	if (rp->lxar_msg == NULL) {
		lx_audit_fail(asp, "audit: no kernel memory");
		mutex_exit(&asp->lxast_lock);
		kmem_free(rp, sizeof (lx_audit_record_t));
		return;
	}
	rp->lxar_type = mtype;
	bcopy(datap, msg, len);
	msg[len] = '\0';

	gethrestime(&ts);
	ts.tv_sec -= curzone->zone_boot_time;

	(void) snprintf(rp->lxar_msg, LX_AUDIT_MESSAGE_TEXT_MAX,
	    "audit(%lu.%03lu:%lu): pid=%u uid=%u auid=%u ses=%u msg=\'",
	    (uint64_t)ts.tv_sec,			/* zone's timestamp */
	    (uint64_t)ts.tv_nsec / 1000000,
	    asp->lxast_seq++,				/* serial number */
	    (lwpd->br_pid == curzone->zone_proc_initpid ? 1 : lwpd->br_pid),
	    crgetruid(CRED()),				/* uid */
	    lx_audit_get_auid(),			/* auid */
	    sessid);					/* ses */

	prelen = strlen(rp->lxar_msg);
	alen = LX_AUDIT_MESSAGE_TEXT_MAX - prelen - 2;
	(void) strlcat(rp->lxar_msg + prelen, msg, alen);
	(void) strlcat(rp->lxar_msg, "\'", LX_AUDIT_MESSAGE_TEXT_MAX);

	list_insert_tail(&asp->lxast_ev_queue, rp);
	if (asp->lxast_backlog == 0)
		cv_signal(&asp->lxast_worker_cv);
	asp->lxast_backlog++;
	mutex_exit(&asp->lxast_lock);
}

void
lx_audit_list_rules(void *reply,
    void (*cb)(void *, void *, uint_t, void *, uint_t))
{
	lx_audit_state_t *asp;
	lx_audit_rule_ent_t *rp;

	asp = ztolxzd(curzone)->lxzd_audit_state;
	ASSERT(asp != NULL);

	/*
	 * Output the rule list
	 */
	mutex_enter(&asp->lxast_lock);
	for (rp = list_head(&asp->lxast_rules); rp != NULL;
	    rp = list_next(&asp->lxast_rules, rp)) {
		cb(reply, &rp->lxare_rule, sizeof (lx_audit_rule_t),
		    rp->lxare_buf, rp->lxare_rule.lxar_buflen);
	}
	mutex_exit(&asp->lxast_lock);
}

void
lx_audit_get_feature(void *reply, void (*cb)(void *, void *, uint_t))
{
	lx_audit_features_t af;

	af.lxaf_version = LX_AUDIT_FEATURE_VERSION;
	af.lxaf_mask = 0xffffffff;
	af.lxaf_features = 0;
	af.lxaf_lock = 0;

	cb(reply, &af, sizeof (af));
}

void
lx_audit_get(void *reply, void (*cb)(void *, void *, uint_t))
{
	lx_audit_status_t status;
	lx_zone_data_t *lxzd;
	lx_audit_state_t *asp;

	lxzd = ztolxzd(curproc->p_zone);
	asp = lxzd->lxzd_audit_state;
	ASSERT(asp != NULL);

	bzero(&status, sizeof (status));

	mutex_enter(&asp->lxast_lock);
	status.lxas_enabled = lxzd->lxzd_audit_enabled;
	status.lxas_failure = asp->lxast_failure;
	status.lxas_pid = asp->lxast_pid;
	status.lxas_rate_limit = asp->lxast_rate_limit;
	status.lxas_backlog_limit = asp->lxast_backlog_limit;
	status.lxas_lost = asp->lxast_lost;
	status.lxas_backlog = asp->lxast_backlog;
	status.lxas_backlog_wait_time = asp->lxast_backlog_wait_time;
	status.lxas_feature_bitmap = LX_AUDIT_FEATURE_ALL;
	mutex_exit(&asp->lxast_lock);

	cb(reply, &status, sizeof (status));
}

int
lx_audit_set(void *lxsock, void *s, uint_t datalen,
    void (*cb)(void *, boolean_t))
{
	lx_audit_status_t *statusp = (lx_audit_status_t *)s;
	lx_zone_data_t *lxzd;
	lx_audit_state_t *asp;

	/*
	 * Unfortunately, some user-level code does not send down a full
	 * lx_audit_status_t structure in the message (e.g. this occurs on
	 * CentOS7). Only the structure up to, but not including, the embedded
	 * union is being sent in. This appears to be a result of the user-level
	 * code being built for older versions of the kernel. To handle this,
	 * we have to subtract the last 8 bytes from the size in order to
	 * accomodate this code. We'll revalidate with the full size if
	 * LX_AUDIT_STATUS_BACKLOG_WAIT_TIME were to be set in the mask.
	 */
	if (datalen < sizeof (lx_audit_status_t) - 8)
		return (EINVAL);

	lxzd = ztolxzd(curproc->p_zone);
	asp = lxzd->lxzd_audit_state;
	ASSERT(asp != NULL);

	/* Once the config is locked, we only allow changing the auditd pid */
	mutex_enter(&asp->lxast_lock);
	if (lxzd->lxzd_audit_enabled == LXAE_LOCKED &&
	    (statusp->lxas_mask & ~LX_AUDIT_STATUS_PID)) {
		mutex_exit(&asp->lxast_lock);
		return (EPERM);
	}

	if (statusp->lxas_mask & LX_AUDIT_STATUS_FAILURE) {
		switch (statusp->lxas_failure) {
		case LXAE_SILENT:
		case LXAE_PRINT:
		case LXAE_PANIC:
			asp->lxast_failure = statusp->lxas_failure;
			break;
		default:
			mutex_exit(&asp->lxast_lock);
			return (EINVAL);
		}
	}
	if (statusp->lxas_mask & LX_AUDIT_STATUS_PID) {
		/*
		 * The process that sets the pid is the daemon, so this is the
		 * socket we'll write audit records out to.
		 */
		lx_audit_set_worker(statusp->lxas_pid, lxsock, cb);
	}
	if (statusp->lxas_mask & LX_AUDIT_STATUS_RATE_LIMIT) {
		asp->lxast_rate_limit = statusp->lxas_rate_limit;
	}
	if (statusp->lxas_mask & LX_AUDIT_STATUS_BACKLOG_LIMIT) {
		asp->lxast_backlog_limit = statusp->lxas_backlog_limit;
	}
	if (statusp->lxas_mask & LX_AUDIT_STATUS_BACKLOG_WAIT_TIME) {
		/*
		 * See the comment above. We have to revalidate the full struct
		 * size since we previously only validated for a shorter struct.
		 */
		if (datalen < sizeof (lx_audit_status_t)) {
			mutex_exit(&asp->lxast_lock);
			return (EINVAL);
		}
		asp->lxast_backlog_wait_time = statusp->lxas_backlog_wait_time;
	}
	if (statusp->lxas_mask & LX_AUDIT_STATUS_LOST) {
		asp->lxast_lost = statusp->lxas_lost;
	}

	if (statusp->lxas_mask & LX_AUDIT_STATUS_ENABLED) {
		switch (statusp->lxas_enabled) {
		case 0:
			lxzd->lxzd_audit_enabled = LXAE_DISABLED;
			break;
		case 1:
			lxzd->lxzd_audit_enabled = LXAE_ENABLED;
			break;
		case 2:
			lxzd->lxzd_audit_enabled = LXAE_LOCKED;
			break;
		default:
			mutex_exit(&asp->lxast_lock);
			return (EINVAL);
		}
	}
	mutex_exit(&asp->lxast_lock);

	return (0);
}

void
lx_audit_stop_worker(void *s, void (*cb)(void *, boolean_t))
{
	lx_audit_state_t *asp = ztolxzd(curzone)->lxzd_audit_state;
	kt_did_t tid = 0;

	ASSERT(asp != NULL);
	mutex_enter(&asp->lxast_lock);
	if (s == NULL) {
		s = asp->lxast_sock;
	} else {
		VERIFY(s == asp->lxast_sock);
	}
	asp->lxast_sock = NULL;
	asp->lxast_pid = 0;
	if (asp->lxast_worker != NULL) {
		tid = asp->lxast_worker->t_did;
		asp->lxast_worker = NULL;
		asp->lxast_exit = B_TRUE;
		cv_signal(&asp->lxast_worker_cv);
	}
	if (s != NULL)
		cb(s, B_FALSE);
	mutex_exit(&asp->lxast_lock);

	if (tid != 0)
		thread_join(tid);
}

/*
 * Called when audit netlink message received, in order to perform lazy
 * allocation of audit state for the zone. We also perform the one-time step to
 * cache the netlink callback used by the audit worker thread to send messages
 * up to the auditd.
 */
void
lx_audit_init(int (*cb)(void *, uint_t, const char *, uint_t))
{
	lx_zone_data_t *lxzd = ztolxzd(curzone);
	lx_audit_state_t *asp;

	mutex_enter(&lxzd->lxzd_lock);

	if (lxzd->lxzd_audit_state != NULL) {
		mutex_exit(&lxzd->lxzd_lock);
		return;
	}

	asp = kmem_zalloc(sizeof (lx_audit_state_t), KM_SLEEP);

	mutex_init(&asp->lxast_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&asp->lxast_worker_cv, NULL, CV_DEFAULT, NULL);
	list_create(&asp->lxast_ev_queue, sizeof (lx_audit_record_t),
	    offsetof(lx_audit_record_t, lxar_link));
	list_create(&asp->lxast_rules, sizeof (lx_audit_rule_ent_t),
	    offsetof(lx_audit_rule_ent_t, lxare_link));
	asp->lxast_failure = LXAE_PRINT;
	asp->lxast_backlog_limit = LX_AUDIT_DEF_BACKLOG_LIMIT;
	asp->lxast_backlog_wait_time = LX_AUDIT_DEF_WAIT_TIME;

	lxzd->lxzd_audit_state = asp;

	mutex_exit(&lxzd->lxzd_lock);

	mutex_enter(&lx_audit_em_lock);
	if (lx_audit_emit_msg == NULL)
		lx_audit_emit_msg = cb;
	mutex_exit(&lx_audit_em_lock);
}

/*
 * Called when netlink module is unloading so that we can clear the cached
 * netlink callback used by the audit worker thread to send messages up to the
 * auditd.
 */
void
lx_audit_cleanup(void)
{
	mutex_enter(&lx_audit_em_lock);
	lx_audit_emit_msg = NULL;
	mutex_exit(&lx_audit_em_lock);
}

/*
 * Called when the zone is being destroyed, not when auditing is being disabled.
 * Note that zsched has already exited and any lxast_worker thread has exited.
 */
void
lx_audit_fini(zone_t *zone)
{
	lx_zone_data_t *lxzd = ztolxzd(zone);
	lx_audit_state_t *asp;
	lx_audit_record_t *rp;
	lx_audit_rule_ent_t *erp;

	ASSERT(MUTEX_HELD(&lxzd->lxzd_lock));

	if ((asp = lxzd->lxzd_audit_state) == NULL)
		return;

	mutex_enter(&asp->lxast_lock);

	VERIFY(asp->lxast_worker == NULL);

	rp = list_remove_head(&asp->lxast_ev_queue);
	while (rp != NULL) {
		kmem_free(rp->lxar_msg, LX_AUDIT_MESSAGE_TEXT_MAX);
		kmem_free(rp, sizeof (lx_audit_record_t));
		rp = list_remove_head(&asp->lxast_ev_queue);
	}

	list_destroy(&asp->lxast_ev_queue);
	asp->lxast_backlog = 0;
	asp->lxast_pid = 0;

	erp = list_remove_head(&asp->lxast_rules);
	while (erp != NULL) {
		kmem_free(erp->lxare_buf, erp->lxare_rule.lxar_buflen);
		if (erp->lxare_key != NULL)
			kmem_free(erp->lxare_key, strlen(erp->lxare_key) + 1);
		kmem_free(erp, sizeof (lx_audit_rule_ent_t));
		erp = list_remove_head(&asp->lxast_rules);
	}
	list_destroy(&asp->lxast_rules);

	mutex_exit(&asp->lxast_lock);

	cv_destroy(&asp->lxast_worker_cv);
	mutex_destroy(&asp->lxast_lock);
	lxzd->lxzd_audit_state = NULL;
	kmem_free(asp, sizeof (lx_audit_state_t));
}

/*
 * Audit initialization/cleanup when lx brand module is loaded and
 * unloaded.
 */
void
lx_audit_ld()
{
	mutex_init(&lx_audit_em_lock, NULL, MUTEX_DEFAULT, NULL);
}

void
lx_audit_unld()
{
	mutex_destroy(&lx_audit_em_lock);
}
