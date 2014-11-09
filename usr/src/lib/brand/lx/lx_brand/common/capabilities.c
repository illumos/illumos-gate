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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * LX Brand emulation of capget/capset syscalls
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/lx_types.h>
#include <sys/lx_syscall.h>
#include <sys/syscall.h>
#include <alloca.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/lx_misc.h>
#include <priv.h>

typedef struct {
	uint32_t version;
	int pid;
} lx_cap_user_header_t;

typedef struct {
	uint32_t effective;
	uint32_t permitted;
	uint32_t inheritable;
} lx_cap_user_data_t;

typedef struct {
	priv_set_t *p_effective;
	priv_set_t *p_permitted;
	priv_set_t *p_inheritable;
} lx_cap_privs_t;

#define	LX_CAP_UPDATE_PERMITTED		0x1
#define	LX_CAP_UPDATE_EFFECTIVE		0x2
#define	LX_CAP_UPDATE_INHERITABLE	0x4


#define	LX_CAP_MAXLEN	2

typedef struct {
	uint32_t effective[LX_CAP_MAXLEN];
	uint32_t permitted[LX_CAP_MAXLEN];
	uint32_t inheritable[LX_CAP_MAXLEN];
} lx_cap_data_t;

#define	LX_CAP_VERSION_1	0x19980330
#define	LX_CAP_VERSION_2	0x20071026	/* deprecated by Linux */
#define	LX_CAP_VERSION_3	0x20080522

/*
 * Even though we lack mappings for capabilities higher than 36, it's valuable
 * to test all the way out to the end of the second field.  This ensures that
 * new capabilities we lack support for are not silently accepted.
 */
#define	LX_CAP_MAX_CHECK		63
#define	LX_CAP_MAX_VALID		36

#define	LX_CAP_CAPISSET(id, cap) \
	(((id < 32) && (((0x1 << id) & cap[0]) != 0)) || \
	((id >= 32) && (((0x1 << (id - 32) & cap[1]) != 0))))

#define	LX_CAP_CAPSET(id, cap) \
	if (id < 32) { cap[0] |= (0x1 << id); } \
	else { cap[1] |= (0x1 << (id - 32)); }

static const char *lx_cap_map_chown[] = {
	PRIV_FILE_CHOWN,
	PRIV_FILE_CHOWN_SELF,
	NULL
};
static const char *lx_cap_map_dac_override[] = {
	PRIV_FILE_DAC_READ,
	PRIV_FILE_DAC_WRITE,
	PRIV_FILE_DAC_EXECUTE,
	NULL
};
static const char *lx_cap_map_dac_read_search[] = {
	PRIV_FILE_DAC_SEARCH,
	PRIV_FILE_DAC_READ,
	NULL
};
static const char *lx_cap_map_fowner[] = { PRIV_FILE_OWNER, NULL };
static const char *lx_cap_map_fsetid[] = { PRIV_FILE_SETID, NULL };
static const char *lx_cap_map_kill[] = { PRIV_PROC_OWNER, NULL };
/*
 * One way that Linux capabilities(7) differs from Illumos privileges(5) is
 * that it distinguishes between setuid and setgroups rights.  This will be a
 * problem if an lx-branded process requests to drop only CAP_SETUID but not
 * CAP_SETGID.
 *
 * In that case, CAP_SETUID will be maintained.
 */
static const char *lx_cap_map_setgid[] = { PRIV_PROC_SETID, NULL };
static const char *lx_cap_map_setuid[] = { PRIV_PROC_SETID, NULL };
static const char *lx_cap_map_linux_immutable[] = { PRIV_FILE_FLAG_SET, NULL };
static const char *lx_cap_map_bind_service[] = { PRIV_NET_PRIVADDR, NULL };
static const char *lx_cap_map_net_admin[] = {
	PRIV_SYS_IPC_CONFIG,
	PRIV_SYS_DL_CONFIG,
	NULL
};
static const char *lx_cap_map_net_raw[] = {
	PRIV_NET_RAWACCESS,
	PRIV_NET_ICMPACCESS,
	NULL
};
static const char *lx_cap_map_ipc_lock[] = { PRIV_PROC_LOCK_MEMORY, NULL };
static const char *lx_cap_map_ipc_owner[] = {
	PRIV_IPC_DAC_READ,
	PRIV_IPC_DAC_WRITE,
	PRIV_IPC_OWNER,
	NULL
};
static const char *lx_cap_map_sys_chroot[] = { PRIV_PROC_CHROOT, NULL };
static const char *lx_cap_map_sys_admin[] = {
	PRIV_SYS_MOUNT,
	PRIV_SYS_ADMIN,
	NULL
};
static const char *lx_cap_map_sys_nice[] = { PRIV_PROC_PRIOUP, NULL };
static const char *lx_cap_map_sys_resource[] = { PRIV_SYS_RESOURCE, NULL };
static const char *lx_cap_map_audit_write[] = { PRIV_PROC_AUDIT, NULL };
static const char *lx_cap_map_audit_control[] = { PRIV_SYS_AUDIT, NULL };

/*
 * Mapping of Linux capabilities -> Illumos privileges
 * The ID definitions can be found in the Linux sources here:
 * include/uapi/linux/capability.h
 *
 * Order is critical.
 */
static const char ** lx_cap_mapping[LX_CAP_MAX_VALID + 1] = {
	lx_cap_map_chown,		/* CAP_CHOWN */
	lx_cap_map_dac_override,	/* CAP_DAC_OVERRIDE */
	lx_cap_map_dac_read_search,	/* CAP_DAC_READ_SEARCH */
	lx_cap_map_fowner,		/* CAP_FOWNER */
	lx_cap_map_fsetid,		/* CAP_FSETID */
	lx_cap_map_kill,		/* CAP_KILL */
	lx_cap_map_setgid,		/* CAP_SETGID */
	lx_cap_map_setuid,		/* CAP_SETUID */
	NULL,				/* CAP_SETPCAP */
	lx_cap_map_linux_immutable,	/* CAP_LINUX_IMMUTABLE */
	lx_cap_map_bind_service,	/* CAP_BIND_SERVICE */
	NULL,				/* CAP_BROADCAST */
	lx_cap_map_net_admin,		/* CAP_NET_ADMIN */
	lx_cap_map_net_raw,		/* CAP_NET_RAW */
	lx_cap_map_ipc_lock,		/* CAP_IPC_LOCK */
	lx_cap_map_ipc_owner,		/* CAP_IPC_OWNER */
	NULL,				/* CAP_MODULE */
	NULL,				/* CAP_RAWIO */
	lx_cap_map_sys_chroot,		/* CAP_SYS_CHROOT */
	NULL,				/* CAP_PTRACE */
	NULL,				/* CAP_PACCT */
	lx_cap_map_sys_admin,		/* CAP_SYS_ADMIN */
	NULL,				/* CAP_BOOT */
	lx_cap_map_sys_nice,		/* CAP_SYS_NICE */
	lx_cap_map_sys_resource,	/* CAP_SYS_RESOURCE */
	NULL,				/* CAP_SYS_TIME */
	NULL,				/* CAP_SYS_TTY_CONFIG */
	NULL,				/* CAP_MKNOD */
	NULL,				/* CAP_LEASE */
	lx_cap_map_audit_write,		/* CAP_AUDIT_WRITE */
	lx_cap_map_audit_control,	/* CAP_AUDIT_CONTROL */
	NULL,				/* CAP_SETFCAP */
	NULL,				/* CAP_MAC_OVERRIDE */
	NULL,				/* CAP_MAC_ADMIN */
	NULL,				/* CAP_SYSLOG */
	NULL,				/* CAP_WAKE_ALARM */
	NULL				/* CAP_BLOCK_SUSPEND */
};

/* track priv_set_t size, set on entry to lx_capset/lx_capget */
static unsigned int lx_cap_priv_size = 0;

/* safely allocate priv_set_t triplet on the stack */
#define	LX_CAP_ALLOC_PRIVS(ptr)	\
	do { \
		ptr = SAFE_ALLOCA(sizeof (lx_cap_privs_t) + \
		    (3 * lx_cap_priv_size)); \
		if (ptr != NULL) { \
			ptr->p_effective = (void *) ptr + \
			    sizeof (lx_cap_privs_t); \
			ptr->p_permitted = (void *) ptr + \
			    sizeof (lx_cap_privs_t) + \
			    lx_cap_priv_size;\
			ptr->p_inheritable = (void *) ptr + \
			    sizeof (lx_cap_privs_t) + \
			    2 * lx_cap_priv_size; \
		} \
	} while (0)

static long
lx_cap_update_priv(priv_set_t *priv, const uint32_t cap[])
{
	int i, j;
	boolean_t cap_set;
	boolean_t priv_set;
	boolean_t updated = B_FALSE;
	for (i = 0; i <= LX_CAP_MAX_CHECK; i++) {
		cap_set = LX_CAP_CAPISSET(i, cap);
		if (lx_cap_mapping[i] == NULL || i > LX_CAP_MAX_VALID) {
			/* don't allow setting unsupported caps */
			if (cap_set)
				return (-1);
			else
				continue;
		}
		for (j = 0; lx_cap_mapping[i][j] != NULL; j++) {
			priv_set = priv_ismember(priv, lx_cap_mapping[i][j]);
			if (priv_set && !cap_set) {
				priv_delset(priv, lx_cap_mapping[i][j]);
				updated = B_TRUE;
			} else if (!priv_set && cap_set) {
				priv_addset(priv, lx_cap_mapping[i][j]);
				updated = B_TRUE;
			}
		}
	}
	if (updated)
		return (1);
	else
		return (0);
}

static long
lx_cap_to_priv(lx_cap_data_t *cap, lx_cap_privs_t *priv)
{
	long changes = 0;
	long result;

	result = lx_cap_update_priv(priv->p_permitted, cap->permitted);
	if (result < 0)
		return (-1);
	else if (result > 0)
		changes |= LX_CAP_UPDATE_PERMITTED;

	result = lx_cap_update_priv(priv->p_effective, cap->effective);
	if (result < 0)
		return (-1);
	else if (result > 0)
		changes |= LX_CAP_UPDATE_EFFECTIVE;

	result = lx_cap_update_priv(priv->p_inheritable, cap->inheritable);
	if (result < 0)
		return (-1);
	else if (result > 0)
		changes |= LX_CAP_UPDATE_INHERITABLE;

	return (changes);
}

static void
lx_cap_from_priv(const priv_set_t *priv, uint32_t cap[])
{
	int i, j;
	boolean_t valid;
	memset(cap, '\0', sizeof (uint32_t) * LX_CAP_MAXLEN);
	for (i = 0; i <= LX_CAP_MAX_VALID; i++) {
		if (lx_cap_mapping[i] == NULL) {
			continue;
		}
		valid = B_TRUE;
		for (j = 0; lx_cap_mapping[i][j] != NULL; j++) {
			if (!priv_ismember(priv,
			    lx_cap_mapping[i][j])) {
				valid = B_FALSE;
			}
		}
		if (valid) {
			LX_CAP_CAPSET(i, cap);
		}
	}
}

static long
lx_cap_read_cap(const lx_cap_user_header_t *uhp, const lx_cap_user_data_t *udp,
    lx_cap_data_t *cd)
{
	lx_cap_user_header_t uh;
	lx_cap_user_data_t ud_buf;
	int cap_count;
	int i;

	if (uucopy(uhp, &uh, sizeof (uh)) != 0)
		return (-errno);

	switch (uh.version) {
	case LX_CAP_VERSION_1:
		cap_count = 1;
		break;
	case LX_CAP_VERSION_2:
	case LX_CAP_VERSION_3:
		cap_count = 2;
		break;
	default:
		return (-EINVAL);
	}

	/* Only allow capset on calling process */
	if (uh.pid != 0 && uh.pid != getpid())
		return (-EPERM);

	/* zero the struct in case cap_count < 2 */
	memset(cd, '\0', sizeof (lx_cap_data_t));

	for (i = 0; i < cap_count; i++) {
		if (uucopy(udp + i, &ud_buf, sizeof (ud_buf)) != 0)
			return (-errno);
		cd->permitted[i] = ud_buf.permitted;
		cd->effective[i] = ud_buf.effective;
		cd->inheritable[i] = ud_buf.inheritable;
	}
	return (0);
}

long
lx_capget(uintptr_t p1, uintptr_t p2)
{
	const priv_impl_info_t *impl;
	lx_cap_user_header_t *uhp = (lx_cap_user_header_t *)p1;
	lx_cap_user_data_t *udp = (lx_cap_user_data_t *)p2;
	lx_cap_user_header_t uh;
	lx_cap_privs_t *privs;
	lx_cap_data_t cd_result;
	lx_cap_user_data_t cd_buf;
	int cap_count;
	int i;

	if (lx_cap_priv_size == 0) {
		impl = getprivimplinfo();
		lx_cap_priv_size = sizeof (priv_chunk_t) * impl->priv_setsize;
	}

	if (uucopy(uhp, &uh, sizeof (uh)) != 0)
		return (-errno);

	switch (uh.version) {
	case LX_CAP_VERSION_1:
		cap_count = 1;
		break;
	case LX_CAP_VERSION_2:
	case LX_CAP_VERSION_3:
		cap_count = 2;
		break;
	default:
		return (-EINVAL);
	}

	/*
	 * Only allow capget on the calling process.
	 * If a pid is specified, lie about being able to locate it.
	 */
	if (uh.pid > 0 && uh.pid != getpid())
		return (-ESRCH);
	if (uh.pid < 0)
		return (-EINVAL);

	LX_CAP_ALLOC_PRIVS(privs);
	if (privs == NULL)
		return (-ENOMEM);

	if (getppriv(PRIV_PERMITTED, privs->p_permitted) != 0)
		return (-errno);
	if (getppriv(PRIV_EFFECTIVE, privs->p_effective) != 0)
		return (-errno);
	if (getppriv(PRIV_INHERITABLE, privs->p_inheritable) != 0)
		return (-errno);

	lx_cap_from_priv(privs->p_permitted, cd_result.permitted);
	lx_cap_from_priv(privs->p_effective, cd_result.effective);
	lx_cap_from_priv(privs->p_inheritable, cd_result.inheritable);

	/* convert to output format */
	for (i = 0; i < cap_count; i++) {
		cd_buf.effective = cd_result.effective[i];
		cd_buf.permitted = cd_result.permitted[i];
		cd_buf.inheritable = cd_result.inheritable[i];
		if (uucopy(&cd_buf, udp + i, sizeof (cd_buf)) != 0)
			return (-errno);
	}

	return (0);
}

long
lx_capset(uintptr_t p1, uintptr_t p2)
{
	const priv_impl_info_t *impl;
	lx_cap_data_t cd;
	lx_cap_privs_t *privs;
	long result;

	if (lx_cap_priv_size == 0) {
		impl = getprivimplinfo();
		lx_cap_priv_size = sizeof (priv_chunk_t) * impl->priv_setsize;
	}

	/* verify header and read in desired capabilities */
	result = lx_cap_read_cap((lx_cap_user_header_t *)p1,
	    (lx_cap_user_data_t *)p2, &cd);
	if (result != 0)
		return (result);

	LX_CAP_ALLOC_PRIVS(privs);
	if (privs == NULL)
		return (-ENOMEM);

	/* fetch current privs to compare against */
	if (getppriv(PRIV_PERMITTED, privs->p_permitted) != 0)
		return (-errno);
	if (getppriv(PRIV_EFFECTIVE, privs->p_effective) != 0)
		return (-errno);
	if (getppriv(PRIV_INHERITABLE, privs->p_inheritable) != 0)
		return (-errno);


	result = lx_cap_to_priv(&cd, privs);
	if (result < 0)
		return (-EPERM);

	/* report success if no changes needed */
	if (result == 0)
		return (0);

	/* Ensure the effective/inheritable caps aren't > permitted */
	if (!priv_issubset(privs->p_effective, privs->p_permitted) ||
	    !priv_issubset(privs->p_inheritable, privs->p_permitted))
		return (-EPERM);

	/*
	 * Here is where things become racy.  Linux updates all three
	 * capability sets simultaneously in the capset syscall.  In order to
	 * emulate capabilities via privileges, three setppriv operations are
	 * required in sequence.  If one or two should fail, there is not a
	 * mechanism to convey the incomplete operation to the caller.
	 *
	 * We do two things to make this less risky:
	 * 1. Verify that both the desired effective and inheritable
	 *    sets are subsets of the desired permitted set.
	 * 2. Perform the setppriv of the permitted set first.
	 *
	 * Should the setppriv(permitted) fail, we can safely bail out with an
	 * error.  If it succeeds, the setppriv of effective and inheritable
	 * are likely to succeed given that they've been verified legal.
	 *
	 * If the partial error does happen, we'll be forced to report failure
	 * even though the privileges were altered.
	 */

	if ((result & LX_CAP_UPDATE_PERMITTED) != 0) {
		/* failure here is totally safe */
		if (setppriv(PRIV_SET, PRIV_PERMITTED, privs->p_permitted) != 0)
			return (-errno);
	}
	if ((result & LX_CAP_UPDATE_EFFECTIVE) != 0) {
		/* failure here is a bummer */
		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, privs->p_effective) != 0)
			return (-errno);
	}
	if ((result & LX_CAP_UPDATE_EFFECTIVE) != 0) {
		/* failure here is a major bummer */
		if (setppriv(PRIV_SET, PRIV_INHERITABLE,
		    privs->p_inheritable) != 0)
			return (-errno);
	}

	return (0);
}
