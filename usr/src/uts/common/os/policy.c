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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cred_impl.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/acct.h>
#include <sys/ipc_impl.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/policy.h>
#include <sys/kobj.h>
#include <sys/msg.h>
#include <sys/devpolicy.h>
#include <c2/audit.h>
#include <sys/varargs.h>
#include <sys/klpd.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <sys/zone.h>
#include <inet/optcom.h>
#include <sys/sdt.h>
#include <sys/vfs.h>
#include <sys/mntent.h>
#include <sys/contract_impl.h>
#include <sys/dld_ioc.h>

/*
 * There are two possible layers of privilege routines and two possible
 * levels of secpolicy.  Plus one other we may not be interested in, so
 * we may need as many as 6 but no more.
 */
#define	MAXPRIVSTACK		6

int priv_debug = 0;
int priv_basic_test = -1;

/*
 * This file contains the majority of the policy routines.
 * Since the policy routines are defined by function and not
 * by privilege, there is quite a bit of duplication of
 * functions.
 *
 * The secpolicy functions must not make assumptions about
 * locks held or not held as any lock can be held while they're
 * being called.
 *
 * Credentials are read-only so no special precautions need to
 * be taken while locking them.
 *
 * When a new policy check needs to be added to the system the
 * following procedure should be followed:
 *
 *		Pick an appropriate secpolicy_*() function
 *			-> done if one exists.
 *		Create a new secpolicy function, preferably with
 *		a descriptive name using the standard template.
 *		Pick an appropriate privilege for the policy.
 *		If no appropraite privilege exists, define new one
 *		(this should be done with extreme care; in most cases
 *		little is gained by adding another privilege)
 *
 * WHY ROOT IS STILL SPECIAL.
 *
 * In a number of the policy functions, there are still explicit
 * checks for uid 0.  The rationale behind these is that many root
 * owned files/objects hold configuration information which can give full
 * privileges to the user once written to.  To prevent escalation
 * of privilege by allowing just a single privilege to modify root owned
 * objects, we've added these root specific checks where we considered
 * them necessary: modifying root owned files, changing uids to 0, etc.
 *
 * PRIVILEGE ESCALATION AND ZONES.
 *
 * A number of operations potentially allow the caller to achieve
 * privileges beyond the ones normally required to perform the operation.
 * For example, if allowed to create a setuid 0 executable, a process can
 * gain privileges beyond PRIV_FILE_SETID.  Zones, however, place
 * restrictions on the ability to gain privileges beyond those available
 * within the zone through file and process manipulation.  Hence, such
 * operations require that the caller have an effective set that includes
 * all privileges available within the current zone, or all privileges
 * if executing in the global zone.
 *
 * This is indicated in the priv_policy* policy checking functions
 * through a combination of parameters.  The "priv" parameter indicates
 * the privilege that is required, and the "allzone" parameter indicates
 * whether or not all privileges in the zone are required.  In addition,
 * priv can be set to PRIV_ALL to indicate that all privileges are
 * required (regardless of zone).  There are three scenarios of interest:
 * (1) operation requires a specific privilege
 * (2) operation requires a specific privilege, and requires all
 *     privileges available within the zone (or all privileges if in
 *     the global zone)
 * (3) operation requires all privileges, regardless of zone
 *
 * For (1), priv should be set to the specific privilege, and allzone
 * should be set to B_FALSE.
 * For (2), priv should be set to the specific privilege, and allzone
 * should be set to B_TRUE.
 * For (3), priv should be set to PRIV_ALL, and allzone should be set
 * to B_FALSE.
 *
 */

/*
 * The privileges are checked against the Effective set for
 * ordinary processes and checked against the Limit set
 * for euid 0 processes that haven't manipulated their privilege
 * sets.
 */
#define	HAS_ALLPRIVS(cr)	priv_isfullset(&CR_OEPRIV(cr))
#define	ZONEPRIVS(cr)		((cr)->cr_zone->zone_privset)
#define	HAS_ALLZONEPRIVS(cr)	priv_issubset(ZONEPRIVS(cr), &CR_OEPRIV(cr))
#define	HAS_PRIVILEGE(cr, pr)	((pr) == PRIV_ALL ? \
					HAS_ALLPRIVS(cr) : \
					PRIV_ISASSERT(&CR_OEPRIV(cr), pr))

#define	FAST_BASIC_CHECK(cr, priv)	\
	if (PRIV_ISASSERT(&CR_OEPRIV(cr), priv)) { \
		DTRACE_PROBE2(priv__ok, int, priv, boolean_t, B_FALSE); \
		return (0); \
	}

/*
 * Policy checking functions.
 *
 * All of the system's policy should be implemented here.
 */

/*
 * Private functions which take an additional va_list argument to
 * implement an object specific policy override.
 */
static int priv_policy_ap(const cred_t *, int, boolean_t, int,
    const char *, va_list);
static int priv_policy_va(const cred_t *, int, boolean_t, int,
    const char *, ...);

/*
 * Generic policy calls
 *
 * The "bottom" functions of policy control
 */
static char *
mprintf(const char *fmt, ...)
{
	va_list args;
	char *buf;
	size_t len;

	va_start(args, fmt);
	len = vsnprintf(NULL, 0, fmt, args) + 1;
	va_end(args);

	buf = kmem_alloc(len, KM_NOSLEEP);

	if (buf == NULL)
		return (NULL);

	va_start(args, fmt);
	(void) vsnprintf(buf, len, fmt, args);
	va_end(args);

	return (buf);
}

/*
 * priv_policy_errmsg()
 *
 * Generate an error message if privilege debugging is enabled system wide
 * or for this particular process.
 */

#define	FMTHDR	"%s[%d]: missing privilege \"%s\" (euid = %d, syscall = %d)"
#define	FMTMSG	" for \"%s\""
#define	FMTFUN	" needed at %s+0x%lx"

/* The maximum size privilege format: the concatenation of the above */
#define	FMTMAX	FMTHDR FMTMSG FMTFUN "\n"

static void
priv_policy_errmsg(const cred_t *cr, int priv, const char *msg)
{
	struct proc *me;
	pc_t stack[MAXPRIVSTACK];
	int depth;
	int i;
	char *sym;
	ulong_t off;
	const char *pname;

	char *cmd;
	char fmt[sizeof (FMTMAX)];

	if ((me = curproc) == &p0)
		return;

	/* Privileges must be defined  */
	ASSERT(priv == PRIV_ALL || priv == PRIV_MULTIPLE ||
	    priv == PRIV_ALLZONE || priv == PRIV_GLOBAL ||
	    priv_getbynum(priv) != NULL);

	if (priv == PRIV_ALLZONE && INGLOBALZONE(me))
		priv = PRIV_ALL;

	if (curthread->t_pre_sys)
		ttolwp(curthread)->lwp_badpriv = (short)priv;

	if (priv_debug == 0 && (CR_FLAGS(cr) & PRIV_DEBUG) == 0)
		return;

	(void) strcpy(fmt, FMTHDR);

	if (me->p_user.u_comm[0])
		cmd = &me->p_user.u_comm[0];
	else
		cmd = "priv_policy";

	if (msg != NULL && *msg != '\0') {
		(void) strcat(fmt, FMTMSG);
	} else {
		(void) strcat(fmt, "%s");
		msg = "";
	}

	sym = NULL;

	depth = getpcstack(stack, MAXPRIVSTACK);

	/*
	 * Try to find the first interesting function on the stack.
	 * priv_policy* that's us, so completely uninteresting.
	 * suser(), drv_priv(), secpolicy_* are also called from
	 * too many locations to convey useful information.
	 */
	for (i = 0; i < depth; i++) {
		sym = kobj_getsymname((uintptr_t)stack[i], &off);
		if (sym != NULL &&
		    strstr(sym, "hasprocperm") == 0 &&
		    strcmp("suser", sym) != 0 &&
		    strcmp("ipcaccess", sym) != 0 &&
		    strcmp("drv_priv", sym) != 0 &&
		    strncmp("secpolicy_", sym, 10) != 0 &&
		    strncmp("priv_policy", sym, 11) != 0)
			break;
	}

	if (sym != NULL)
		(void) strcat(fmt, FMTFUN);

	(void) strcat(fmt, "\n");

	switch (priv) {
	case PRIV_ALL:
		pname = "ALL";
		break;
	case PRIV_MULTIPLE:
		pname = "MULTIPLE";
		break;
	case PRIV_ALLZONE:
		pname = "ZONE";
		break;
	case PRIV_GLOBAL:
		pname = "GLOBAL";
		break;
	default:
		pname = priv_getbynum(priv);
		break;
	}

	if (CR_FLAGS(cr) & PRIV_DEBUG) {
		/* Remember last message, just like lwp_badpriv. */
		if (curthread->t_pdmsg != NULL) {
			kmem_free(curthread->t_pdmsg,
			    strlen(curthread->t_pdmsg) + 1);
		}

		curthread->t_pdmsg = mprintf(fmt, cmd, me->p_pid, pname,
		    cr->cr_uid, curthread->t_sysnum, msg, sym, off);

		curthread->t_post_sys = 1;
	}
	if (priv_debug) {
		cmn_err(CE_NOTE, fmt, cmd, me->p_pid, pname, cr->cr_uid,
		    curthread->t_sysnum, msg, sym, off);
	}
}

/*
 * Override the policy, if appropriate.  Return 0 if the external
 * policy engine approves.
 */
static int
priv_policy_override(const cred_t *cr, int priv, boolean_t allzone, va_list ap)
{
	priv_set_t set;
	int ret;

	if (!(CR_FLAGS(cr) & PRIV_XPOLICY))
		return (-1);

	if (priv == PRIV_ALL) {
		priv_fillset(&set);
	} else if (allzone) {
		set = *ZONEPRIVS(cr);
	} else {
		priv_emptyset(&set);
		priv_addset(&set, priv);
	}
	ret = klpd_call(cr, &set, ap);
	return (ret);
}

static int
priv_policy_override_set(const cred_t *cr, const priv_set_t *req, va_list ap)
{
	if (CR_FLAGS(cr) & PRIV_PFEXEC)
		return (check_user_privs(cr, req));
	if (CR_FLAGS(cr) & PRIV_XPOLICY) {
		return (klpd_call(cr, req, ap));
	}
	return (-1);
}

static int
priv_policy_override_set_va(const cred_t *cr, const priv_set_t *req, ...)
{
	va_list ap;
	int ret;

	va_start(ap, req);
	ret = priv_policy_override_set(cr, req, ap);
	va_end(ap);
	return (ret);
}

/*
 * Audit failure, log error message.
 */
static void
priv_policy_err(const cred_t *cr, int priv, boolean_t allzone, const char *msg)
{

	if (AU_AUDITING())
		audit_priv(priv, allzone ? ZONEPRIVS(cr) : NULL, 0);
	DTRACE_PROBE2(priv__err, int, priv, boolean_t, allzone);

	if (priv_debug || (CR_FLAGS(cr) & PRIV_DEBUG) ||
	    curthread->t_pre_sys) {
		if (allzone && !HAS_ALLZONEPRIVS(cr)) {
			priv_policy_errmsg(cr, PRIV_ALLZONE, msg);
		} else {
			ASSERT(!HAS_PRIVILEGE(cr, priv));
			priv_policy_errmsg(cr, priv, msg);
		}
	}
}

/*
 * priv_policy_ap()
 * return 0 or error.
 * See block comment above for a description of "priv" and "allzone" usage.
 */
static int
priv_policy_ap(const cred_t *cr, int priv, boolean_t allzone, int err,
    const char *msg, va_list ap)
{
	if ((HAS_PRIVILEGE(cr, priv) && (!allzone || HAS_ALLZONEPRIVS(cr))) ||
	    (!servicing_interrupt() &&
	    priv_policy_override(cr, priv, allzone, ap) == 0)) {
		if ((allzone || priv == PRIV_ALL ||
		    !PRIV_ISASSERT(priv_basic, priv)) &&
		    !servicing_interrupt()) {
			PTOU(curproc)->u_acflag |= ASU; /* Needed for SVVS */
			if (AU_AUDITING())
				audit_priv(priv,
				    allzone ? ZONEPRIVS(cr) : NULL, 1);
		}
		err = 0;
		DTRACE_PROBE2(priv__ok, int, priv, boolean_t, allzone);
	} else if (!servicing_interrupt()) {
		/* Failure audited in this procedure */
		priv_policy_err(cr, priv, allzone, msg);
	}
	return (err);
}

int
priv_policy_va(const cred_t *cr, int priv, boolean_t allzone, int err,
    const char *msg, ...)
{
	int ret;
	va_list ap;

	va_start(ap, msg);
	ret = priv_policy_ap(cr, priv, allzone, err, msg, ap);
	va_end(ap);

	return (ret);
}

int
priv_policy(const cred_t *cr, int priv, boolean_t allzone, int err,
    const char *msg)
{
	return (priv_policy_va(cr, priv, allzone, err, msg, KLPDARG_NONE));
}

/*
 * Return B_TRUE for sufficient privileges, B_FALSE for insufficient privileges.
 */
boolean_t
priv_policy_choice(const cred_t *cr, int priv, boolean_t allzone)
{
	boolean_t res = HAS_PRIVILEGE(cr, priv) &&
	    (!allzone || HAS_ALLZONEPRIVS(cr));

	/* Audit success only */
	if (res && AU_AUDITING() &&
	    (allzone || priv == PRIV_ALL || !PRIV_ISASSERT(priv_basic, priv)) &&
	    !servicing_interrupt()) {
		audit_priv(priv, allzone ? ZONEPRIVS(cr) : NULL, 1);
	}
	if (res) {
		DTRACE_PROBE2(priv__ok, int, priv, boolean_t, allzone);
	} else {
		DTRACE_PROBE2(priv__err, int, priv, boolean_t, allzone);
	}
	return (res);
}

/*
 * Non-auditing variant of priv_policy_choice().
 */
boolean_t
priv_policy_only(const cred_t *cr, int priv, boolean_t allzone)
{
	boolean_t res = HAS_PRIVILEGE(cr, priv) &&
	    (!allzone || HAS_ALLZONEPRIVS(cr));

	if (res) {
		DTRACE_PROBE2(priv__ok, int, priv, boolean_t, allzone);
	} else {
		DTRACE_PROBE2(priv__err, int, priv, boolean_t, allzone);
	}
	return (res);
}

/*
 * Check whether all privileges in the required set are present.
 */
static int
secpolicy_require_set(const cred_t *cr, const priv_set_t *req,
    const char *msg, ...)
{
	int priv;
	int pfound = -1;
	priv_set_t pset;
	va_list ap;
	int ret;

	if (req == PRIV_FULLSET ? HAS_ALLPRIVS(cr) : priv_issubset(req,
	    &CR_OEPRIV(cr))) {
		return (0);
	}

	va_start(ap, msg);
	ret = priv_policy_override_set(cr, req, ap);
	va_end(ap);
	if (ret == 0)
		return (0);

	if (req == PRIV_FULLSET || priv_isfullset(req)) {
		priv_policy_err(cr, PRIV_ALL, B_FALSE, msg);
		return (EACCES);
	}

	pset = CR_OEPRIV(cr);		/* present privileges */
	priv_inverse(&pset);		/* all non present privileges */
	priv_intersect(req, &pset);	/* the actual missing privs */

	if (AU_AUDITING())
		audit_priv(PRIV_NONE, &pset, 0);
	/*
	 * Privilege debugging; special case "one privilege in set".
	 */
	if (priv_debug || (CR_FLAGS(cr) & PRIV_DEBUG) || curthread->t_pre_sys) {
		for (priv = 0; priv < nprivs; priv++) {
			if (priv_ismember(&pset, priv)) {
				if (pfound != -1) {
					/* Multiple missing privs */
					priv_policy_errmsg(cr, PRIV_MULTIPLE,
					    msg);
					return (EACCES);
				}
				pfound = priv;
			}
		}
		ASSERT(pfound != -1);
		/* Just the one missing privilege */
		priv_policy_errmsg(cr, pfound, msg);
	}

	return (EACCES);
}

/*
 * Called when an operation requires that the caller be in the
 * global zone, regardless of privilege.
 */
static int
priv_policy_global(const cred_t *cr)
{
	if (crgetzoneid(cr) == GLOBAL_ZONEID)
		return (0);	/* success */

	if (priv_debug || (CR_FLAGS(cr) & PRIV_DEBUG) ||
	    curthread->t_pre_sys) {
		priv_policy_errmsg(cr, PRIV_GLOBAL, NULL);
	}
	return (EPERM);
}

/*
 * Raising process priority
 */
int
secpolicy_raisepriority(const cred_t *cr)
{
	if (PRIV_POLICY(cr, PRIV_PROC_PRIOUP, B_FALSE, EPERM, NULL) == 0)
		return (0);
	return (secpolicy_setpriority(cr));
}

/*
 * Changing process priority or scheduling class
 */
int
secpolicy_setpriority(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_PRIOCNTL, B_FALSE, EPERM, NULL));
}

/*
 * Binding to a privileged port, port must be specified in host byte
 * order.
 * When adding a new privilege which allows binding to currently privileged
 * ports, then you MUST also allow processes with PRIV_NET_PRIVADDR bind
 * to these ports because of backward compatibility.
 */
int
secpolicy_net_privaddr(const cred_t *cr, in_port_t port, int proto)
{
	char *reason;
	int priv;

	switch (port) {
	case 137:
	case 138:
	case 139:
	case 445:
		/*
		 * NBT and SMB ports, these are normal privileged ports,
		 * allow bind only if the SYS_SMB or NET_PRIVADDR privilege
		 * is present.
		 * Try both, if neither is present return an error for
		 * priv SYS_SMB.
		 */
		if (PRIV_POLICY_ONLY(cr, PRIV_NET_PRIVADDR, B_FALSE))
			priv = PRIV_NET_PRIVADDR;
		else
			priv = PRIV_SYS_SMB;
		reason = "NBT or SMB port";
		break;

	case 2049:
	case 4045:
		/*
		 * NFS ports, these are extra privileged ports, allow bind
		 * only if the SYS_NFS privilege is present.
		 */
		priv = PRIV_SYS_NFS;
		reason = "NFS port";
		break;

	default:
		priv = PRIV_NET_PRIVADDR;
		reason = NULL;
		break;

	}

	return (priv_policy_va(cr, priv, B_FALSE, EACCES, reason,
	    KLPDARG_PORT, (int)proto, (int)port, KLPDARG_NOMORE));
}

/*
 * Binding to a multilevel port on a trusted (labeled) system.
 */
int
secpolicy_net_bindmlp(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_NET_BINDMLP, B_FALSE, EACCES, NULL));
}

/*
 * Allow a communication between a zone and an unlabeled host when their
 * labels don't match.
 */
int
secpolicy_net_mac_aware(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_NET_MAC_AWARE, B_FALSE, EACCES, NULL));
}

/*
 * Allow a privileged process to transmit traffic without explicit labels
 */
int
secpolicy_net_mac_implicit(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_NET_MAC_IMPLICIT, B_FALSE, EACCES, NULL));
}

/*
 * Common routine which determines whether a given credential can
 * act on a given mount.
 * When called through mount, the parameter needoptcheck is a pointer
 * to a boolean variable which will be set to either true or false,
 * depending on whether the mount policy should change the mount options.
 * In all other cases, needoptcheck should be a NULL pointer.
 */
static int
secpolicy_fs_common(cred_t *cr, vnode_t *mvp, const vfs_t *vfsp,
    boolean_t *needoptcheck)
{
	boolean_t allzone = B_FALSE;
	boolean_t mounting = needoptcheck != NULL;

	/*
	 * Short circuit the following cases:
	 *	vfsp == NULL or mvp == NULL (pure privilege check)
	 *	have all privileges - no further checks required
	 *	and no mount options need to be set.
	 */
	if (vfsp == NULL || mvp == NULL || HAS_ALLPRIVS(cr)) {
		if (mounting)
			*needoptcheck = B_FALSE;

		return (priv_policy_va(cr, PRIV_SYS_MOUNT, allzone, EPERM,
		    NULL, KLPDARG_VNODE, mvp, (char *)NULL, KLPDARG_NOMORE));
	}

	/*
	 * When operating on an existing mount (either we're not mounting
	 * or we're doing a remount and VFS_REMOUNT will be set), zones
	 * can operate only on mounts established by the zone itself.
	 */
	if (!mounting || (vfsp->vfs_flag & VFS_REMOUNT) != 0) {
		zoneid_t zoneid = crgetzoneid(cr);

		if (zoneid != GLOBAL_ZONEID &&
		    vfsp->vfs_zone->zone_id != zoneid) {
			return (EPERM);
		}
	}

	if (mounting)
		*needoptcheck = B_TRUE;

	/*
	 * Overlay mounts may hide important stuff; if you can't write to a
	 * mount point but would be able to mount on top of it, you can
	 * escalate your privileges.
	 * So we go about asking the same questions namefs does when it
	 * decides whether you can mount over a file or not but with the
	 * added restriction that you can only mount on top of a regular
	 * file or directory.
	 * If we have all the zone's privileges, we skip all other checks,
	 * or else we may actually get in trouble inside the automounter.
	 */
	if ((mvp->v_flag & VROOT) != 0 ||
	    (mvp->v_type != VDIR && mvp->v_type != VREG) ||
	    HAS_ALLZONEPRIVS(cr)) {
		allzone = B_TRUE;
	} else {
		vattr_t va;
		int err;

		va.va_mask = AT_UID|AT_MODE;
		err = VOP_GETATTR(mvp, &va, 0, cr, NULL);
		if (err != 0)
			return (err);

		if ((err = secpolicy_vnode_owner(cr, va.va_uid)) != 0)
			return (err);

		if (secpolicy_vnode_access2(cr, mvp, va.va_uid, va.va_mode,
		    VWRITE) != 0) {
			return (EACCES);
		}
	}
	return (priv_policy_va(cr, PRIV_SYS_MOUNT, allzone, EPERM,
	    NULL, KLPDARG_VNODE, mvp, (char *)NULL, KLPDARG_NOMORE));
}

void
secpolicy_fs_mount_clearopts(cred_t *cr, struct vfs *vfsp)
{
	boolean_t amsuper = HAS_ALLZONEPRIVS(cr);

	/*
	 * check; if we don't have either "nosuid" or
	 * both "nosetuid" and "nodevices", then we add
	 * "nosuid"; this depends on how the current
	 * implementation works (it first checks nosuid).  In a
	 * zone, a user with all zone privileges can mount with
	 * "setuid" but never with "devices".
	 */
	if (!vfs_optionisset(vfsp, MNTOPT_NOSUID, NULL) &&
	    (!vfs_optionisset(vfsp, MNTOPT_NODEVICES, NULL) ||
	    !vfs_optionisset(vfsp, MNTOPT_NOSETUID, NULL))) {
		if (crgetzoneid(cr) == GLOBAL_ZONEID || !amsuper)
			vfs_setmntopt(vfsp, MNTOPT_NOSUID, NULL, 0);
		else
			vfs_setmntopt(vfsp, MNTOPT_NODEVICES, NULL, 0);
	}
	/*
	 * If we're not the local super user, we set the "restrict"
	 * option to indicate to automountd that this mount should
	 * be handled with care.
	 */
	if (!amsuper)
		vfs_setmntopt(vfsp, MNTOPT_RESTRICT, NULL, 0);

}

int
secpolicy_fs_allowed_mount(const char *fsname)
{
	struct vfssw *vswp;
	const char *p;
	size_t len;

	ASSERT(fsname != NULL);
	ASSERT(fsname[0] != '\0');

	if (INGLOBALZONE(curproc))
		return (0);

	vswp = vfs_getvfssw(fsname);
	if (vswp == NULL)
		return (ENOENT);

	if ((vswp->vsw_flag & VSW_ZMOUNT) != 0) {
		vfs_unrefvfssw(vswp);
		return (0);
	}

	vfs_unrefvfssw(vswp);

	p = curzone->zone_fs_allowed;
	len = strlen(fsname);

	while (p != NULL && *p != '\0') {
		if (strncmp(p, fsname, len) == 0) {
			char c = *(p + len);
			if (c == '\0' || c == ',')
				return (0);
		}

		/* skip to beyond the next comma */
		if ((p = strchr(p, ',')) != NULL)
			p++;
	}

	return (EPERM);
}

extern vnode_t *rootvp;
extern vfs_t *rootvfs;

int
secpolicy_fs_mount(cred_t *cr, vnode_t *mvp, struct vfs *vfsp)
{
	boolean_t needoptchk;
	int error;

	/*
	 * If it's a remount, get the underlying mount point,
	 * except for the root where we use the rootvp.
	 */
	if ((vfsp->vfs_flag & VFS_REMOUNT) != 0) {
		if (vfsp == rootvfs)
			mvp = rootvp;
		else
			mvp = vfsp->vfs_vnodecovered;
	}

	error = secpolicy_fs_common(cr, mvp, vfsp, &needoptchk);

	if (error == 0 && needoptchk) {
		secpolicy_fs_mount_clearopts(cr, vfsp);
	}

	return (error);
}

/*
 * Does the policy computations for "ownership" of a mount;
 * here ownership is defined as the ability to "mount"
 * the filesystem originally.  The rootvfs doesn't cover any
 * vnodes; we attribute its ownership to the rootvp.
 */
static int
secpolicy_fs_owner(cred_t *cr, const struct vfs *vfsp)
{
	vnode_t *mvp;

	if (vfsp == NULL)
		mvp = NULL;
	else if (vfsp == rootvfs)
		mvp = rootvp;
	else
		mvp = vfsp->vfs_vnodecovered;

	return (secpolicy_fs_common(cr, mvp, vfsp, NULL));
}

int
secpolicy_fs_unmount(cred_t *cr, struct vfs *vfsp)
{
	return (secpolicy_fs_owner(cr, vfsp));
}

/*
 * Quotas are a resource, but if one has the ability to mount a filesystem,
 * they should be able to modify quotas on it.
 */
int
secpolicy_fs_quota(const cred_t *cr, const vfs_t *vfsp)
{
	return (secpolicy_fs_owner((cred_t *)cr, vfsp));
}

/*
 * Exceeding minfree: also a per-mount resource constraint.
 */
int
secpolicy_fs_minfree(const cred_t *cr, const vfs_t *vfsp)
{
	return (secpolicy_fs_owner((cred_t *)cr, vfsp));
}

int
secpolicy_fs_config(const cred_t *cr, const vfs_t *vfsp)
{
	return (secpolicy_fs_owner((cred_t *)cr, vfsp));
}

/* ARGSUSED */
int
secpolicy_fs_linkdir(const cred_t *cr, const vfs_t *vfsp)
{
	return (PRIV_POLICY(cr, PRIV_SYS_LINKDIR, B_FALSE, EPERM, NULL));
}

/*
 * Name:        secpolicy_vnode_access()
 *
 * Parameters:  Process credential
 *		vnode
 *		uid of owner of vnode
 *		permission bits not granted to the caller when examining
 *		file mode bits (i.e., when a process wants to open a
 *		mode 444 file for VREAD|VWRITE, this function should be
 *		called only with a VWRITE argument).
 *
 * Normal:      Verifies that cred has the appropriate privileges to
 *              override the mode bits that were denied.
 *
 * Override:    file_dac_execute - if VEXEC bit was denied and vnode is
 *                      not a directory.
 *              file_dac_read - if VREAD bit was denied.
 *              file_dac_search - if VEXEC bit was denied and vnode is
 *                      a directory.
 *              file_dac_write - if VWRITE bit was denied.
 *
 *		Root owned files are special cased to protect system
 *		configuration files and such.
 *
 * Output:      EACCES - if privilege check fails.
 */

int
secpolicy_vnode_access(const cred_t *cr, vnode_t *vp, uid_t owner, mode_t mode)
{
	if ((mode & VREAD) && priv_policy_va(cr, PRIV_FILE_DAC_READ, B_FALSE,
	    EACCES, NULL, KLPDARG_VNODE, vp, (char *)NULL,
	    KLPDARG_NOMORE) != 0) {
		return (EACCES);
	}

	if (mode & VWRITE) {
		boolean_t allzone;

		if (owner == 0 && cr->cr_uid != 0)
			allzone = B_TRUE;
		else
			allzone = B_FALSE;
		if (priv_policy_va(cr, PRIV_FILE_DAC_WRITE, allzone, EACCES,
		    NULL, KLPDARG_VNODE, vp, (char *)NULL,
		    KLPDARG_NOMORE) != 0) {
			return (EACCES);
		}
	}

	if (mode & VEXEC) {
		/*
		 * Directories use file_dac_search to override the execute bit.
		 */
		int p = vp->v_type == VDIR ? PRIV_FILE_DAC_SEARCH :
		    PRIV_FILE_DAC_EXECUTE;

		return (priv_policy_va(cr, p, B_FALSE, EACCES, NULL,
		    KLPDARG_VNODE, vp, (char *)NULL, KLPDARG_NOMORE));
	}
	return (0);
}

/*
 * Like secpolicy_vnode_access() but we get the actual wanted mode and the
 * current mode of the file, not the missing bits.
 */
int
secpolicy_vnode_access2(const cred_t *cr, vnode_t *vp, uid_t owner,
    mode_t curmode, mode_t wantmode)
{
	mode_t mode;

	/* Inline the basic privileges tests. */
	if ((wantmode & VREAD) &&
	    !PRIV_ISASSERT(&CR_OEPRIV(cr), PRIV_FILE_READ) &&
	    priv_policy_va(cr, PRIV_FILE_READ, B_FALSE, EACCES, NULL,
	    KLPDARG_VNODE, vp, (char *)NULL, KLPDARG_NOMORE) != 0) {
		return (EACCES);
	}

	if ((wantmode & VWRITE) &&
	    !PRIV_ISASSERT(&CR_OEPRIV(cr), PRIV_FILE_WRITE) &&
	    priv_policy_va(cr, PRIV_FILE_WRITE, B_FALSE, EACCES, NULL,
	    KLPDARG_VNODE, vp, (char *)NULL, KLPDARG_NOMORE) != 0) {
		return (EACCES);
	}

	mode = ~curmode & wantmode;

	if (mode == 0)
		return (0);

	if ((mode & VREAD) && priv_policy_va(cr, PRIV_FILE_DAC_READ, B_FALSE,
	    EACCES, NULL, KLPDARG_VNODE, vp, (char *)NULL,
	    KLPDARG_NOMORE) != 0) {
		return (EACCES);
	}

	if (mode & VWRITE) {
		boolean_t allzone;

		if (owner == 0 && cr->cr_uid != 0)
			allzone = B_TRUE;
		else
			allzone = B_FALSE;
		if (priv_policy_va(cr, PRIV_FILE_DAC_WRITE, allzone, EACCES,
		    NULL, KLPDARG_VNODE, vp, (char *)NULL,
		    KLPDARG_NOMORE) != 0) {
			return (EACCES);
		}
	}

	if (mode & VEXEC) {
		/*
		 * Directories use file_dac_search to override the execute bit.
		 */
		int p = vp->v_type == VDIR ? PRIV_FILE_DAC_SEARCH :
		    PRIV_FILE_DAC_EXECUTE;

		return (priv_policy_va(cr, p, B_FALSE, EACCES, NULL,
		    KLPDARG_VNODE, vp, (char *)NULL, KLPDARG_NOMORE));
	}
	return (0);
}

/*
 * This is a special routine for ZFS; it is used to determine whether
 * any of the privileges in effect allow any form of access to the
 * file.  There's no reason to audit this or any reason to record
 * this.  More work is needed to do the "KPLD" stuff.
 */
int
secpolicy_vnode_any_access(const cred_t *cr, vnode_t *vp, uid_t owner)
{
	static int privs[] = {
	    PRIV_FILE_OWNER,
	    PRIV_FILE_CHOWN,
	    PRIV_FILE_DAC_READ,
	    PRIV_FILE_DAC_WRITE,
	    PRIV_FILE_DAC_EXECUTE,
	    PRIV_FILE_DAC_SEARCH,
	};
	int i;

	/* Same as secpolicy_vnode_setdac */
	if (owner == cr->cr_uid)
		return (0);

	for (i = 0; i < sizeof (privs)/sizeof (int); i++) {
		boolean_t allzone = B_FALSE;
		int priv;

		switch (priv = privs[i]) {
		case PRIV_FILE_DAC_EXECUTE:
			if (vp->v_type == VDIR)
				continue;
			break;
		case PRIV_FILE_DAC_SEARCH:
			if (vp->v_type != VDIR)
				continue;
			break;
		case PRIV_FILE_DAC_WRITE:
		case PRIV_FILE_OWNER:
		case PRIV_FILE_CHOWN:
			/* We know here that if owner == 0, that cr_uid != 0 */
			allzone = owner == 0;
			break;
		}
		if (PRIV_POLICY_CHOICE(cr, priv, allzone))
			return (0);
	}
	return (EPERM);
}

/*
 * Name:	secpolicy_vnode_setid_modify()
 *
 * Normal:	verify that subject can set the file setid flags.
 *
 * Output:	EPERM - if not privileged.
 */

static int
secpolicy_vnode_setid_modify(const cred_t *cr, uid_t owner)
{
	/* If changing to suid root, must have all zone privs */
	boolean_t allzone = B_TRUE;

	if (owner != 0) {
		if (owner == cr->cr_uid)
			return (0);
		allzone = B_FALSE;
	}
	return (PRIV_POLICY(cr, PRIV_FILE_SETID, allzone, EPERM, NULL));
}

/*
 * Are we allowed to retain the set-uid/set-gid bits when
 * changing ownership or when writing to a file?
 * "issuid" should be true when set-uid; only in that case
 * root ownership is checked (setgid is assumed).
 */
int
secpolicy_vnode_setid_retain(const cred_t *cred, boolean_t issuidroot)
{
	if (issuidroot && !HAS_ALLZONEPRIVS(cred))
		return (EPERM);

	return (!PRIV_POLICY_CHOICE(cred, PRIV_FILE_SETID, B_FALSE));
}

/*
 * Name:	secpolicy_vnode_setids_setgids()
 *
 * Normal:	verify that subject can set the file setgid flag.
 *
 * Output:	EPERM - if not privileged
 */

int
secpolicy_vnode_setids_setgids(const cred_t *cred, gid_t gid)
{
	if (!groupmember(gid, cred))
		return (PRIV_POLICY(cred, PRIV_FILE_SETID, B_FALSE, EPERM,
		    NULL));
	return (0);
}

/*
 * Name:	secpolicy_vnode_chown
 *
 * Normal:	Determine if subject can chown owner of a file.
 *
 * Output:	EPERM - if access denied
 */

int
secpolicy_vnode_chown(const cred_t *cred, uid_t owner)
{
	boolean_t is_owner = (owner == crgetuid(cred));
	boolean_t allzone = B_FALSE;
	int priv;

	if (!is_owner) {
		allzone = (owner == 0);
		priv = PRIV_FILE_CHOWN;
	} else {
		priv = HAS_PRIVILEGE(cred, PRIV_FILE_CHOWN) ?
		    PRIV_FILE_CHOWN : PRIV_FILE_CHOWN_SELF;
	}

	return (PRIV_POLICY(cred, priv, allzone, EPERM, NULL));
}

/*
 * Name:	secpolicy_vnode_create_gid
 *
 * Normal:	Determine if subject can change group ownership of a file.
 *
 * Output:	EPERM - if access denied
 */
int
secpolicy_vnode_create_gid(const cred_t *cred)
{
	if (HAS_PRIVILEGE(cred, PRIV_FILE_CHOWN))
		return (PRIV_POLICY(cred, PRIV_FILE_CHOWN, B_FALSE, EPERM,
		    NULL));
	else
		return (PRIV_POLICY(cred, PRIV_FILE_CHOWN_SELF, B_FALSE, EPERM,
		    NULL));
}

/*
 * Name:	secpolicy_vnode_utime_modify()
 *
 * Normal:	verify that subject can modify the utime on a file.
 *
 * Output:	EPERM - if access denied.
 */

static int
secpolicy_vnode_utime_modify(const cred_t *cred)
{
	return (PRIV_POLICY(cred, PRIV_FILE_OWNER, B_FALSE, EPERM,
	    "modify file times"));
}


/*
 * Name:	secpolicy_vnode_setdac()
 *
 * Normal:	verify that subject can modify the mode of a file.
 *		allzone privilege needed when modifying root owned object.
 *
 * Output:	EPERM - if access denied.
 */

int
secpolicy_vnode_setdac(const cred_t *cred, uid_t owner)
{
	if (owner == cred->cr_uid)
		return (0);

	return (PRIV_POLICY(cred, PRIV_FILE_OWNER, owner == 0, EPERM, NULL));
}
/*
 * Name:	secpolicy_vnode_stky_modify()
 *
 * Normal:	verify that subject can make a file a "sticky".
 *
 * Output:	EPERM - if access denied.
 */

int
secpolicy_vnode_stky_modify(const cred_t *cred)
{
	return (PRIV_POLICY(cred, PRIV_SYS_CONFIG, B_FALSE, EPERM,
	    "set file sticky"));
}

/*
 * Policy determines whether we can remove an entry from a directory,
 * regardless of permission bits.
 */
int
secpolicy_vnode_remove(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_FILE_OWNER, B_FALSE, EACCES,
	    "sticky directory"));
}

int
secpolicy_vnode_owner(const cred_t *cr, uid_t owner)
{
	boolean_t allzone = (owner == 0);

	if (owner == cr->cr_uid)
		return (0);

	return (PRIV_POLICY(cr, PRIV_FILE_OWNER, allzone, EPERM, NULL));
}

void
secpolicy_setid_clear(vattr_t *vap, cred_t *cr)
{
	if ((vap->va_mode & (S_ISUID | S_ISGID)) != 0 &&
	    secpolicy_vnode_setid_retain(cr,
	    (vap->va_mode & S_ISUID) != 0 &&
	    (vap->va_mask & AT_UID) != 0 && vap->va_uid == 0) != 0) {
		vap->va_mask |= AT_MODE;
		vap->va_mode &= ~(S_ISUID|S_ISGID);
	}
}

int
secpolicy_setid_setsticky_clear(vnode_t *vp, vattr_t *vap, const vattr_t *ovap,
    cred_t *cr)
{
	int error;

	if ((vap->va_mode & S_ISUID) != 0 &&
	    (error = secpolicy_vnode_setid_modify(cr,
	    ovap->va_uid)) != 0) {
		return (error);
	}

	/*
	 * Check privilege if attempting to set the
	 * sticky bit on a non-directory.
	 */
	if (vp->v_type != VDIR && (vap->va_mode & S_ISVTX) != 0 &&
	    secpolicy_vnode_stky_modify(cr) != 0) {
		vap->va_mode &= ~S_ISVTX;
	}

	/*
	 * Check for privilege if attempting to set the
	 * group-id bit.
	 */
	if ((vap->va_mode & S_ISGID) != 0 &&
	    secpolicy_vnode_setids_setgids(cr, ovap->va_gid) != 0) {
		vap->va_mode &= ~S_ISGID;
	}

	return (0);
}

#define	ATTR_FLAG_PRIV(attr, value, cr)	\
	PRIV_POLICY(cr, value ? PRIV_FILE_FLAG_SET : PRIV_ALL, \
	B_FALSE, EPERM, NULL)

/*
 * Check privileges for setting xvattr attributes
 */
int
secpolicy_xvattr(xvattr_t *xvap, uid_t owner, cred_t *cr, vtype_t vtype)
{
	xoptattr_t *xoap;
	int error = 0;

	if ((xoap = xva_getxoptattr(xvap)) == NULL)
		return (EINVAL);

	/*
	 * First process the DOS bits
	 */
	if (XVA_ISSET_REQ(xvap, XAT_ARCHIVE) ||
	    XVA_ISSET_REQ(xvap, XAT_HIDDEN) ||
	    XVA_ISSET_REQ(xvap, XAT_READONLY) ||
	    XVA_ISSET_REQ(xvap, XAT_SYSTEM) ||
	    XVA_ISSET_REQ(xvap, XAT_CREATETIME) ||
	    XVA_ISSET_REQ(xvap, XAT_OFFLINE) ||
	    XVA_ISSET_REQ(xvap, XAT_SPARSE)) {
		if ((error = secpolicy_vnode_owner(cr, owner)) != 0)
			return (error);
	}

	/*
	 * Now handle special attributes
	 */

	if (XVA_ISSET_REQ(xvap, XAT_IMMUTABLE))
		error = ATTR_FLAG_PRIV(XAT_IMMUTABLE,
		    xoap->xoa_immutable, cr);
	if (error == 0 && XVA_ISSET_REQ(xvap, XAT_NOUNLINK))
		error = ATTR_FLAG_PRIV(XAT_NOUNLINK,
		    xoap->xoa_nounlink, cr);
	if (error == 0 && XVA_ISSET_REQ(xvap, XAT_APPENDONLY))
		error = ATTR_FLAG_PRIV(XAT_APPENDONLY,
		    xoap->xoa_appendonly, cr);
	if (error == 0 && XVA_ISSET_REQ(xvap, XAT_NODUMP))
		error = ATTR_FLAG_PRIV(XAT_NODUMP,
		    xoap->xoa_nodump, cr);
	if (error == 0 && XVA_ISSET_REQ(xvap, XAT_OPAQUE))
		error = EPERM;
	if (error == 0 && XVA_ISSET_REQ(xvap, XAT_AV_QUARANTINED)) {
		error = ATTR_FLAG_PRIV(XAT_AV_QUARANTINED,
		    xoap->xoa_av_quarantined, cr);
		if (error == 0 && vtype != VREG && xoap->xoa_av_quarantined)
			error = EINVAL;
	}
	if (error == 0 && XVA_ISSET_REQ(xvap, XAT_AV_MODIFIED))
		error = ATTR_FLAG_PRIV(XAT_AV_MODIFIED,
		    xoap->xoa_av_modified, cr);
	if (error == 0 && XVA_ISSET_REQ(xvap, XAT_AV_SCANSTAMP)) {
		error = ATTR_FLAG_PRIV(XAT_AV_SCANSTAMP,
		    xoap->xoa_av_scanstamp, cr);
		if (error == 0 && vtype != VREG)
			error = EINVAL;
	}
	return (error);
}

/*
 * This function checks the policy decisions surrounding the
 * vop setattr call.
 *
 * It should be called after sufficient locks have been established
 * on the underlying data structures.  No concurrent modifications
 * should be allowed.
 *
 * The caller must pass in unlocked version of its vaccess function
 * this is required because vop_access function should lock the
 * node for reading.  A three argument function should be defined
 * which accepts the following argument:
 * 	A pointer to the internal "node" type (inode *)
 *	vnode access bits (VREAD|VWRITE|VEXEC)
 *	a pointer to the credential
 *
 * This function makes the following policy decisions:
 *
 *		- change permissions
 *			- permission to change file mode if not owner
 *			- permission to add sticky bit to non-directory
 *			- permission to add set-gid bit
 *
 * The ovap argument should include AT_MODE|AT_UID|AT_GID.
 *
 * If the vap argument does not include AT_MODE, the mode will be copied from
 * ovap.  In certain situations set-uid/set-gid bits need to be removed;
 * this is done by marking vap->va_mask to include AT_MODE and va_mode
 * is updated to the newly computed mode.
 */

int
secpolicy_vnode_setattr(cred_t *cr, struct vnode *vp, struct vattr *vap,
    const struct vattr *ovap, int flags,
    int unlocked_access(void *, int, cred_t *),
    void *node)
{
	int mask = vap->va_mask;
	int error = 0;
	boolean_t skipaclchk = (flags & ATTR_NOACLCHECK) ? B_TRUE : B_FALSE;

	if (mask & AT_SIZE) {
		if (vp->v_type == VDIR) {
			error = EISDIR;
			goto out;
		}

		/*
		 * If ATTR_NOACLCHECK is set in the flags, then we don't
		 * perform the secondary unlocked_access() call since the
		 * ACL (if any) is being checked there.
		 */
		if (skipaclchk == B_FALSE) {
			error = unlocked_access(node, VWRITE, cr);
			if (error)
				goto out;
		}
	}
	if (mask & AT_MODE) {
		/*
		 * If not the owner of the file then check privilege
		 * for two things: the privilege to set the mode at all
		 * and, if we're setting setuid, we also need permissions
		 * to add the set-uid bit, if we're not the owner.
		 * In the specific case of creating a set-uid root
		 * file, we need even more permissions.
		 */
		if ((error = secpolicy_vnode_setdac(cr, ovap->va_uid)) != 0)
			goto out;

		if ((error = secpolicy_setid_setsticky_clear(vp, vap,
		    ovap, cr)) != 0)
			goto out;
	} else
		vap->va_mode = ovap->va_mode;

	if (mask & (AT_UID|AT_GID)) {
		boolean_t checkpriv = B_FALSE;

		/*
		 * Chowning files.
		 *
		 * If you are the file owner:
		 *	chown to other uid		FILE_CHOWN_SELF
		 *	chown to gid (non-member) 	FILE_CHOWN_SELF
		 *	chown to gid (member) 		<none>
		 *
		 * Instead of PRIV_FILE_CHOWN_SELF, FILE_CHOWN is also
		 * acceptable but the first one is reported when debugging.
		 *
		 * If you are not the file owner:
		 *	chown from root			PRIV_FILE_CHOWN + zone
		 *	chown from other to any		PRIV_FILE_CHOWN
		 *
		 */
		if (cr->cr_uid != ovap->va_uid) {
			checkpriv = B_TRUE;
		} else {
			if (((mask & AT_UID) && vap->va_uid != ovap->va_uid) ||
			    ((mask & AT_GID) && vap->va_gid != ovap->va_gid &&
			    !groupmember(vap->va_gid, cr))) {
				checkpriv = B_TRUE;
			}
		}
		/*
		 * If necessary, check privilege to see if update can be done.
		 */
		if (checkpriv &&
		    (error = secpolicy_vnode_chown(cr, ovap->va_uid)) != 0) {
			goto out;
		}

		/*
		 * If the file has either the set UID or set GID bits
		 * set and the caller can set the bits, then leave them.
		 */
		secpolicy_setid_clear(vap, cr);
	}
	if (mask & (AT_ATIME|AT_MTIME)) {
		/*
		 * If not the file owner and not otherwise privileged,
		 * always return an error when setting the
		 * time other than the current (ATTR_UTIME flag set).
		 * If setting the current time (ATTR_UTIME not set) then
		 * unlocked_access will check permissions according to policy.
		 */
		if (cr->cr_uid != ovap->va_uid) {
			if (flags & ATTR_UTIME)
				error = secpolicy_vnode_utime_modify(cr);
			else if (skipaclchk == B_FALSE) {
				error = unlocked_access(node, VWRITE, cr);
				if (error == EACCES &&
				    secpolicy_vnode_utime_modify(cr) == 0)
					error = 0;
			}
			if (error)
				goto out;
		}
	}

	/*
	 * Check for optional attributes here by checking the following:
	 */
	if (mask & AT_XVATTR)
		error = secpolicy_xvattr((xvattr_t *)vap, ovap->va_uid, cr,
		    vp->v_type);
out:
	return (error);
}

/*
 * Name:	secpolicy_pcfs_modify_bootpartition()
 *
 * Normal:	verify that subject can modify a pcfs boot partition.
 *
 * Output:	EACCES - if privilege check failed.
 */
/*ARGSUSED*/
int
secpolicy_pcfs_modify_bootpartition(const cred_t *cred)
{
	return (PRIV_POLICY(cred, PRIV_ALL, B_FALSE, EACCES,
	    "modify pcfs boot partition"));
}

/*
 * System V IPC routines
 */
int
secpolicy_ipc_owner(const cred_t *cr, const struct kipc_perm *ip)
{
	if (crgetzoneid(cr) != ip->ipc_zoneid ||
	    (cr->cr_uid != ip->ipc_uid && cr->cr_uid != ip->ipc_cuid)) {
		boolean_t allzone = B_FALSE;
		if (ip->ipc_uid == 0 || ip->ipc_cuid == 0)
			allzone = B_TRUE;
		return (PRIV_POLICY(cr, PRIV_IPC_OWNER, allzone, EPERM, NULL));
	}
	return (0);
}

int
secpolicy_ipc_config(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_IPC_CONFIG, B_FALSE, EPERM, NULL));
}

int
secpolicy_ipc_access(const cred_t *cr, const struct kipc_perm *ip, mode_t mode)
{

	boolean_t allzone = B_FALSE;

	ASSERT((mode & (MSG_R|MSG_W)) != 0);

	if ((mode & MSG_R) &&
	    PRIV_POLICY(cr, PRIV_IPC_DAC_READ, allzone, EACCES, NULL) != 0)
		return (EACCES);

	if (mode & MSG_W) {
		if (cr->cr_uid != 0 && (ip->ipc_uid == 0 || ip->ipc_cuid == 0))
			allzone = B_TRUE;

		return (PRIV_POLICY(cr, PRIV_IPC_DAC_WRITE, allzone, EACCES,
		    NULL));
	}
	return (0);
}

int
secpolicy_rsm_access(const cred_t *cr, uid_t owner, mode_t mode)
{
	boolean_t allzone = B_FALSE;

	ASSERT((mode & (MSG_R|MSG_W)) != 0);

	if ((mode & MSG_R) &&
	    PRIV_POLICY(cr, PRIV_IPC_DAC_READ, allzone, EACCES, NULL) != 0)
		return (EACCES);

	if (mode & MSG_W) {
		if (cr->cr_uid != 0 && owner == 0)
			allzone = B_TRUE;

		return (PRIV_POLICY(cr, PRIV_IPC_DAC_WRITE, allzone, EACCES,
		    NULL));
	}
	return (0);
}

/*
 * Audit configuration.
 */
int
secpolicy_audit_config(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_AUDIT, B_FALSE, EPERM, NULL));
}

/*
 * Audit record generation.
 */
int
secpolicy_audit_modify(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_AUDIT, B_FALSE, EPERM, NULL));
}

/*
 * Get audit attributes.
 * Either PRIV_SYS_AUDIT or PRIV_PROC_AUDIT required; report the
 * "Least" of the two privileges on error.
 */
int
secpolicy_audit_getattr(const cred_t *cr, boolean_t checkonly)
{
	int priv;

	if (PRIV_POLICY_ONLY(cr, PRIV_SYS_AUDIT, B_FALSE))
		priv = PRIV_SYS_AUDIT;
	else
		priv = PRIV_PROC_AUDIT;

	if (checkonly)
		return (!PRIV_POLICY_ONLY(cr, priv, B_FALSE));
	else
		return (PRIV_POLICY(cr, priv, B_FALSE, EPERM, NULL));
}


/*
 * Locking physical memory
 */
int
secpolicy_lock_memory(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_LOCK_MEMORY, B_FALSE, EPERM, NULL));
}

/*
 * Accounting (both acct(2) and exacct).
 */
int
secpolicy_acct(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_ACCT, B_FALSE, EPERM, NULL));
}

/*
 * Is this process privileged to change its uids at will?
 * Uid 0 is still considered "special" and having the SETID
 * privilege is not sufficient to get uid 0.
 * Files are owned by root, so the privilege would give
 * full access and euid 0 is still effective.
 *
 * If you have the privilege and euid 0 only then do you
 * get the powers of root wrt uid 0.
 *
 * For gid manipulations, this is should be called with an
 * uid of -1.
 *
 */
int
secpolicy_allow_setid(const cred_t *cr, uid_t newuid, boolean_t checkonly)
{
	boolean_t allzone = B_FALSE;

	if (newuid == 0 && cr->cr_uid != 0 && cr->cr_suid != 0 &&
	    cr->cr_ruid != 0) {
		allzone = B_TRUE;
	}

	return (checkonly ? !PRIV_POLICY_ONLY(cr, PRIV_PROC_SETID, allzone) :
	    PRIV_POLICY(cr, PRIV_PROC_SETID, allzone, EPERM, NULL));
}


/*
 * Acting on a different process: if the mode is for writing,
 * the restrictions are more severe.  This is called after
 * we've verified that the uids do not match.
 */
int
secpolicy_proc_owner(const cred_t *scr, const cred_t *tcr, int mode)
{
	boolean_t allzone = B_FALSE;

	if ((mode & VWRITE) && scr->cr_uid != 0 &&
	    (tcr->cr_uid == 0 || tcr->cr_ruid == 0 || tcr->cr_suid == 0))
		allzone = B_TRUE;

	return (PRIV_POLICY(scr, PRIV_PROC_OWNER, allzone, EPERM, NULL));
}

int
secpolicy_proc_access(const cred_t *scr)
{
	return (PRIV_POLICY(scr, PRIV_PROC_OWNER, B_FALSE, EACCES, NULL));
}

int
secpolicy_proc_excl_open(const cred_t *scr)
{
	return (PRIV_POLICY(scr, PRIV_PROC_OWNER, B_FALSE, EBUSY, NULL));
}

int
secpolicy_proc_zone(const cred_t *scr)
{
	return (PRIV_POLICY(scr, PRIV_PROC_ZONE, B_FALSE, EPERM, NULL));
}

/*
 * Destroying the system
 */

int
secpolicy_kmdb(const cred_t *scr)
{
	return (PRIV_POLICY(scr, PRIV_ALL, B_FALSE, EPERM, NULL));
}

int
secpolicy_error_inject(const cred_t *scr)
{
	return (PRIV_POLICY(scr, PRIV_ALL, B_FALSE, EPERM, NULL));
}

/*
 * Processor sets, cpu configuration, resource pools.
 */
int
secpolicy_pset(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_RES_CONFIG, B_FALSE, EPERM, NULL));
}

/* Process security flags */
int
secpolicy_psecflags(const cred_t *cr, proc_t *tp, proc_t *sp)
{
	if (PRIV_POLICY(cr, PRIV_PROC_SECFLAGS, B_FALSE, EPERM, NULL) != 0)
		return (EPERM);

	if (!prochasprocperm(tp, sp, cr))
		return (EPERM);

	return (0);
}

/*
 * Processor set binding.
 */
int
secpolicy_pbind(const cred_t *cr)
{
	if (PRIV_POLICY_ONLY(cr, PRIV_SYS_RES_CONFIG, B_FALSE))
		return (secpolicy_pset(cr));
	return (PRIV_POLICY(cr, PRIV_SYS_RES_BIND, B_FALSE, EPERM, NULL));
}

int
secpolicy_ponline(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_RES_CONFIG, B_FALSE, EPERM, NULL));
}

int
secpolicy_pool(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_RES_CONFIG, B_FALSE, EPERM, NULL));
}

int
secpolicy_blacklist(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_RES_CONFIG, B_FALSE, EPERM, NULL));
}

/*
 * Catch all system configuration.
 */
int
secpolicy_sys_config(const cred_t *cr, boolean_t checkonly)
{
	if (checkonly) {
		return (PRIV_POLICY_ONLY(cr, PRIV_SYS_CONFIG, B_FALSE) ? 0 :
		    EPERM);
	} else {
		return (PRIV_POLICY(cr, PRIV_SYS_CONFIG, B_FALSE, EPERM, NULL));
	}
}

/*
 * Zone administration (halt, reboot, etc.) from within zone.
 */
int
secpolicy_zone_admin(const cred_t *cr, boolean_t checkonly)
{
	if (checkonly) {
		return (PRIV_POLICY_ONLY(cr, PRIV_SYS_ADMIN, B_FALSE) ? 0 :
		    EPERM);
	} else {
		return (PRIV_POLICY(cr, PRIV_SYS_ADMIN, B_FALSE, EPERM,
		    NULL));
	}
}

/*
 * Zone configuration (create, halt, enter).
 */
int
secpolicy_zone_config(const cred_t *cr)
{
	/*
	 * Require all privileges to avoid possibility of privilege
	 * escalation.
	 */
	return (secpolicy_require_set(cr, PRIV_FULLSET, NULL, KLPDARG_NONE));
}

/*
 * Various other system configuration calls
 */
int
secpolicy_coreadm(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_ADMIN, B_FALSE, EPERM, NULL));
}

int
secpolicy_systeminfo(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_ADMIN, B_FALSE, EPERM, NULL));
}

int
secpolicy_dispadm(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_CONFIG, B_FALSE, EPERM, NULL));
}

int
secpolicy_settime(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_TIME, B_FALSE, EPERM, NULL));
}

/*
 * For realtime users: high resolution clock.
 */
int
secpolicy_clock_highres(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_CLOCK_HIGHRES, B_FALSE, EPERM,
	    NULL));
}

/*
 * drv_priv() is documented as callable from interrupt context, not that
 * anyone ever does, but still.  No debugging or auditing can be done when
 * it is called from interrupt context.
 * returns 0 on succes, EPERM on failure.
 */
int
drv_priv(cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_DEVICES, B_FALSE, EPERM, NULL));
}

int
secpolicy_sys_devices(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_DEVICES, B_FALSE, EPERM, NULL));
}

int
secpolicy_excl_open(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_DEVICES, B_FALSE, EBUSY, NULL));
}

int
secpolicy_rctlsys(const cred_t *cr, boolean_t is_zone_rctl)
{
	/* zone.* rctls can only be set from the global zone */
	if (is_zone_rctl && priv_policy_global(cr) != 0)
		return (EPERM);
	return (PRIV_POLICY(cr, PRIV_SYS_RESOURCE, B_FALSE, EPERM, NULL));
}

int
secpolicy_resource(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_RESOURCE, B_FALSE, EPERM, NULL));
}

int
secpolicy_resource_anon_mem(const cred_t *cr)
{
	return (PRIV_POLICY_ONLY(cr, PRIV_SYS_RESOURCE, B_FALSE));
}

/*
 * Processes with a real uid of 0 escape any form of accounting, much
 * like before.
 */
int
secpolicy_newproc(const cred_t *cr)
{
	if (cr->cr_ruid == 0)
		return (0);

	return (PRIV_POLICY(cr, PRIV_SYS_RESOURCE, B_FALSE, EPERM, NULL));
}

/*
 * Networking
 */
int
secpolicy_net_rawaccess(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_NET_RAWACCESS, B_FALSE, EACCES, NULL));
}

int
secpolicy_net_observability(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_NET_OBSERVABILITY, B_FALSE, EACCES, NULL));
}

/*
 * Need this privilege for accessing the ICMP device
 */
int
secpolicy_net_icmpaccess(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_NET_ICMPACCESS, B_FALSE, EACCES, NULL));
}

/*
 * There are a few rare cases where the kernel generates ioctls() from
 * interrupt context with a credential of kcred rather than NULL.
 * In those cases, we take the safe and cheap test.
 */
int
secpolicy_net_config(const cred_t *cr, boolean_t checkonly)
{
	if (checkonly) {
		return (PRIV_POLICY_ONLY(cr, PRIV_SYS_NET_CONFIG, B_FALSE) ?
		    0 : EPERM);
	} else {
		return (PRIV_POLICY(cr, PRIV_SYS_NET_CONFIG, B_FALSE, EPERM,
		    NULL));
	}
}


/*
 * PRIV_SYS_NET_CONFIG is a superset of PRIV_SYS_IP_CONFIG.
 *
 * There are a few rare cases where the kernel generates ioctls() from
 * interrupt context with a credential of kcred rather than NULL.
 * In those cases, we take the safe and cheap test.
 */
int
secpolicy_ip_config(const cred_t *cr, boolean_t checkonly)
{
	if (PRIV_POLICY_ONLY(cr, PRIV_SYS_NET_CONFIG, B_FALSE))
		return (secpolicy_net_config(cr, checkonly));

	if (checkonly) {
		return (PRIV_POLICY_ONLY(cr, PRIV_SYS_IP_CONFIG, B_FALSE) ?
		    0 : EPERM);
	} else {
		return (PRIV_POLICY(cr, PRIV_SYS_IP_CONFIG, B_FALSE, EPERM,
		    NULL));
	}
}

/*
 * PRIV_SYS_NET_CONFIG is a superset of PRIV_SYS_DL_CONFIG.
 */
int
secpolicy_dl_config(const cred_t *cr)
{
	if (PRIV_POLICY_ONLY(cr, PRIV_SYS_NET_CONFIG, B_FALSE))
		return (secpolicy_net_config(cr, B_FALSE));
	return (PRIV_POLICY(cr, PRIV_SYS_DL_CONFIG, B_FALSE, EPERM, NULL));
}

/*
 * PRIV_SYS_DL_CONFIG is a superset of PRIV_SYS_IPTUN_CONFIG.
 */
int
secpolicy_iptun_config(const cred_t *cr)
{
	if (PRIV_POLICY_ONLY(cr, PRIV_SYS_NET_CONFIG, B_FALSE))
		return (secpolicy_net_config(cr, B_FALSE));
	if (PRIV_POLICY_ONLY(cr, PRIV_SYS_DL_CONFIG, B_FALSE))
		return (secpolicy_dl_config(cr));
	return (PRIV_POLICY(cr, PRIV_SYS_IPTUN_CONFIG, B_FALSE, EPERM, NULL));
}

/*
 * Map IP pseudo privileges to actual privileges.
 * So we don't need to recompile IP when we change the privileges.
 */
int
secpolicy_ip(const cred_t *cr, int netpriv, boolean_t checkonly)
{
	int priv = PRIV_ALL;

	switch (netpriv) {
	case OP_CONFIG:
		priv = PRIV_SYS_IP_CONFIG;
		break;
	case OP_RAW:
		priv = PRIV_NET_RAWACCESS;
		break;
	case OP_PRIVPORT:
		priv = PRIV_NET_PRIVADDR;
		break;
	}
	ASSERT(priv != PRIV_ALL);
	if (checkonly)
		return (PRIV_POLICY_ONLY(cr, priv, B_FALSE) ? 0 : EPERM);
	else
		return (PRIV_POLICY(cr, priv, B_FALSE, EPERM, NULL));
}

/*
 * Map network pseudo privileges to actual privileges.
 * So we don't need to recompile IP when we change the privileges.
 */
int
secpolicy_net(const cred_t *cr, int netpriv, boolean_t checkonly)
{
	int priv = PRIV_ALL;

	switch (netpriv) {
	case OP_CONFIG:
		priv = PRIV_SYS_NET_CONFIG;
		break;
	case OP_RAW:
		priv = PRIV_NET_RAWACCESS;
		break;
	case OP_PRIVPORT:
		priv = PRIV_NET_PRIVADDR;
		break;
	}
	ASSERT(priv != PRIV_ALL);
	if (checkonly)
		return (PRIV_POLICY_ONLY(cr, priv, B_FALSE) ? 0 : EPERM);
	else
		return (PRIV_POLICY(cr, priv, B_FALSE, EPERM, NULL));
}

/*
 * Checks for operations that are either client-only or are used by
 * both clients and servers.
 */
int
secpolicy_nfs(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_NFS, B_FALSE, EPERM, NULL));
}

/*
 * Special case for opening rpcmod: have NFS privileges or network
 * config privileges.
 */
int
secpolicy_rpcmod_open(const cred_t *cr)
{
	if (PRIV_POLICY_ONLY(cr, PRIV_SYS_NFS, B_FALSE))
		return (secpolicy_nfs(cr));
	else
		return (secpolicy_net_config(cr, NULL));
}

int
secpolicy_chroot(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_CHROOT, B_FALSE, EPERM, NULL));
}

int
secpolicy_tasksys(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_TASKID, B_FALSE, EPERM, NULL));
}

int
secpolicy_meminfo(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_MEMINFO, B_FALSE, EPERM, NULL));
}

int
secpolicy_pfexec_register(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_ADMIN, B_TRUE, EPERM, NULL));
}

/*
 * Basic privilege checks.
 */
int
secpolicy_basic_exec(const cred_t *cr, vnode_t *vp)
{
	FAST_BASIC_CHECK(cr, PRIV_PROC_EXEC);

	return (priv_policy_va(cr, PRIV_PROC_EXEC, B_FALSE, EPERM, NULL,
	    KLPDARG_VNODE, vp, (char *)NULL, KLPDARG_NOMORE));
}

int
secpolicy_basic_fork(const cred_t *cr)
{
	FAST_BASIC_CHECK(cr, PRIV_PROC_FORK);

	return (PRIV_POLICY(cr, PRIV_PROC_FORK, B_FALSE, EPERM, NULL));
}

int
secpolicy_basic_proc(const cred_t *cr)
{
	FAST_BASIC_CHECK(cr, PRIV_PROC_SESSION);

	return (PRIV_POLICY(cr, PRIV_PROC_SESSION, B_FALSE, EPERM, NULL));
}

/*
 * Slightly complicated because we don't want to trigger the policy too
 * often.  First we shortcircuit access to "self" (tp == sp) or if
 * we don't have the privilege but if we have permission
 * just return (0) and we don't flag the privilege as needed.
 * Else, we test for the privilege because we either have it or need it.
 */
int
secpolicy_basic_procinfo(const cred_t *cr, proc_t *tp, proc_t *sp)
{
	if (tp == sp ||
	    !HAS_PRIVILEGE(cr, PRIV_PROC_INFO) && prochasprocperm(tp, sp, cr)) {
		return (0);
	} else {
		return (PRIV_POLICY(cr, PRIV_PROC_INFO, B_FALSE, EPERM, NULL));
	}
}

int
secpolicy_basic_link(const cred_t *cr)
{
	FAST_BASIC_CHECK(cr, PRIV_FILE_LINK_ANY);

	return (PRIV_POLICY(cr, PRIV_FILE_LINK_ANY, B_FALSE, EPERM, NULL));
}

int
secpolicy_basic_net_access(const cred_t *cr)
{
	FAST_BASIC_CHECK(cr, PRIV_NET_ACCESS);

	return (PRIV_POLICY(cr, PRIV_NET_ACCESS, B_FALSE, EACCES, NULL));
}

/* ARGSUSED */
int
secpolicy_basic_file_read(const cred_t *cr, vnode_t *vp, const char *pn)
{
	FAST_BASIC_CHECK(cr, PRIV_FILE_READ);

	return (priv_policy_va(cr, PRIV_FILE_READ, B_FALSE, EACCES, NULL,
	    KLPDARG_VNODE, vp, (char *)pn, KLPDARG_NOMORE));
}

/* ARGSUSED */
int
secpolicy_basic_file_write(const cred_t *cr, vnode_t *vp, const char *pn)
{
	FAST_BASIC_CHECK(cr, PRIV_FILE_WRITE);

	return (priv_policy_va(cr, PRIV_FILE_WRITE, B_FALSE, EACCES, NULL,
	    KLPDARG_VNODE, vp, (char *)pn, KLPDARG_NOMORE));
}

/*
 * Additional device protection.
 *
 * Traditionally, a device has specific permissions on the node in
 * the filesystem which govern which devices can be opened by what
 * processes.  In certain cases, it is desirable to add extra
 * restrictions, as writing to certain devices is identical to
 * having a complete run of the system.
 *
 * This mechanism is called the device policy.
 *
 * When a device is opened, its policy entry is looked up in the
 * policy cache and checked.
 */
int
secpolicy_spec_open(const cred_t *cr, struct vnode *vp, int oflag)
{
	devplcy_t *plcy;
	int err;
	struct snode *csp = VTOS(common_specvp(vp));
	priv_set_t pset;

	mutex_enter(&csp->s_lock);

	if (csp->s_plcy == NULL || csp->s_plcy->dp_gen != devplcy_gen) {
		plcy = devpolicy_find(vp);
		if (csp->s_plcy)
			dpfree(csp->s_plcy);
		csp->s_plcy = plcy;
		ASSERT(plcy != NULL);
	} else
		plcy = csp->s_plcy;

	if (plcy == nullpolicy) {
		mutex_exit(&csp->s_lock);
		return (0);
	}

	dphold(plcy);

	mutex_exit(&csp->s_lock);

	if (oflag & FWRITE)
		pset = plcy->dp_wrp;
	else
		pset = plcy->dp_rdp;
	/*
	 * Special case:
	 * PRIV_SYS_NET_CONFIG is a superset of PRIV_SYS_IP_CONFIG.
	 * If PRIV_SYS_NET_CONFIG is present and PRIV_SYS_IP_CONFIG is
	 * required, replace PRIV_SYS_IP_CONFIG with PRIV_SYS_NET_CONFIG
	 * in the required privilege set before doing the check.
	 */
	if (priv_ismember(&pset, PRIV_SYS_IP_CONFIG) &&
	    priv_ismember(&CR_OEPRIV(cr), PRIV_SYS_NET_CONFIG) &&
	    !priv_ismember(&CR_OEPRIV(cr), PRIV_SYS_IP_CONFIG)) {
		priv_delset(&pset, PRIV_SYS_IP_CONFIG);
		priv_addset(&pset, PRIV_SYS_NET_CONFIG);
	}

	err = secpolicy_require_set(cr, &pset, "devpolicy", KLPDARG_NONE);
	dpfree(plcy);

	return (err);
}

int
secpolicy_modctl(const cred_t *cr, int cmd)
{
	switch (cmd) {
	case MODINFO:
	case MODGETMAJBIND:
	case MODGETPATH:
	case MODGETPATHLEN:
	case MODGETNAME:
	case MODGETFBNAME:
	case MODGETDEVPOLICY:
	case MODGETDEVPOLICYBYNAME:
	case MODDEVT2INSTANCE:
	case MODSIZEOF_DEVID:
	case MODGETDEVID:
	case MODSIZEOF_MINORNAME:
	case MODGETMINORNAME:
	case MODGETDEVFSPATH_LEN:
	case MODGETDEVFSPATH:
	case MODGETDEVFSPATH_MI_LEN:
	case MODGETDEVFSPATH_MI:
		/* Unprivileged */
		return (0);
	case MODLOAD:
	case MODSETDEVPOLICY:
		return (secpolicy_require_set(cr, PRIV_FULLSET, NULL,
		    KLPDARG_NONE));
	default:
		return (secpolicy_sys_config(cr, B_FALSE));
	}
}

int
secpolicy_console(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_DEVICES, B_FALSE, EPERM, NULL));
}

int
secpolicy_power_mgmt(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_DEVICES, B_FALSE, EPERM, NULL));
}

/*
 * Simulate terminal input; another escalation of privileges avenue.
 */

int
secpolicy_sti(const cred_t *cr)
{
	return (secpolicy_require_set(cr, PRIV_FULLSET, NULL, KLPDARG_NONE));
}

boolean_t
secpolicy_net_reply_equal(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_CONFIG, B_FALSE, EPERM, NULL));
}

int
secpolicy_swapctl(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_CONFIG, B_FALSE, EPERM, NULL));
}

int
secpolicy_cpc_cpu(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_CPC_CPU, B_FALSE, EACCES, NULL));
}

/*
 * secpolicy_contract_identity
 *
 * Determine if the subject may set the process contract FMRI value
 */
int
secpolicy_contract_identity(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_CONTRACT_IDENTITY, B_FALSE, EPERM, NULL));
}

/*
 * secpolicy_contract_observer
 *
 * Determine if the subject may observe a specific contract's events.
 */
int
secpolicy_contract_observer(const cred_t *cr, struct contract *ct)
{
	if (contract_owned(ct, cr, B_FALSE))
		return (0);
	return (PRIV_POLICY(cr, PRIV_CONTRACT_OBSERVER, B_FALSE, EPERM, NULL));
}

/*
 * secpolicy_contract_observer_choice
 *
 * Determine if the subject may observe any contract's events.  Just
 * tests privilege and audits on success.
 */
boolean_t
secpolicy_contract_observer_choice(const cred_t *cr)
{
	return (PRIV_POLICY_CHOICE(cr, PRIV_CONTRACT_OBSERVER, B_FALSE));
}

/*
 * secpolicy_contract_event
 *
 * Determine if the subject may request critical contract events or
 * reliable contract event delivery.
 */
int
secpolicy_contract_event(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_CONTRACT_EVENT, B_FALSE, EPERM, NULL));
}

/*
 * secpolicy_contract_event_choice
 *
 * Determine if the subject may retain contract events in its critical
 * set when a change in other terms would normally require a change in
 * the critical set.  Just tests privilege and audits on success.
 */
boolean_t
secpolicy_contract_event_choice(const cred_t *cr)
{
	return (PRIV_POLICY_CHOICE(cr, PRIV_CONTRACT_EVENT, B_FALSE));
}

/*
 * secpolicy_gart_access
 *
 * Determine if the subject has sufficient priveleges to make ioctls to agpgart
 * device.
 */
int
secpolicy_gart_access(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_GRAPHICS_ACCESS, B_FALSE, EPERM, NULL));
}

/*
 * secpolicy_gart_map
 *
 * Determine if the subject has sufficient priveleges to map aperture range
 * through agpgart driver.
 */
int
secpolicy_gart_map(const cred_t *cr)
{
	if (PRIV_POLICY_ONLY(cr, PRIV_GRAPHICS_ACCESS, B_FALSE)) {
		return (PRIV_POLICY(cr, PRIV_GRAPHICS_ACCESS, B_FALSE, EPERM,
		    NULL));
	} else {
		return (PRIV_POLICY(cr, PRIV_GRAPHICS_MAP, B_FALSE, EPERM,
		    NULL));
	}
}

/*
 * secpolicy_xhci
 *
 * Determine if the subject can observe and manipulate the xhci driver with a
 * dangerous blunt hammer.  Requires all privileges.
 */
int
secpolicy_xhci(const cred_t *cr)
{
	return (secpolicy_require_set(cr, PRIV_FULLSET, NULL, KLPDARG_NONE));
}

/*
 * secpolicy_zinject
 *
 * Determine if the subject can inject faults in the ZFS fault injection
 * framework.  Requires all privileges.
 */
int
secpolicy_zinject(const cred_t *cr)
{
	return (secpolicy_require_set(cr, PRIV_FULLSET, NULL, KLPDARG_NONE));
}

/*
 * secpolicy_zfs
 *
 * Determine if the subject has permission to manipulate ZFS datasets
 * (not pools).  Equivalent to the SYS_MOUNT privilege.
 */
int
secpolicy_zfs(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_MOUNT, B_FALSE, EPERM, NULL));
}

/*
 * secpolicy_idmap
 *
 * Determine if the calling process has permissions to register an SID
 * mapping daemon and allocate ephemeral IDs.
 */
int
secpolicy_idmap(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_FILE_SETID, B_TRUE, EPERM, NULL));
}

/*
 * secpolicy_ucode_update
 *
 * Determine if the subject has sufficient privilege to update microcode.
 */
int
secpolicy_ucode_update(const cred_t *scr)
{
	return (PRIV_POLICY(scr, PRIV_ALL, B_FALSE, EPERM, NULL));
}

/*
 * secpolicy_sadopen
 *
 * Determine if the subject has sufficient privilege to access /dev/sad/admin.
 * /dev/sad/admin appear in global zone and exclusive-IP zones only.
 * In global zone, sys_config is required.
 * In exclusive-IP zones, sys_ip_config is required.
 * Note that sys_config is prohibited in non-global zones.
 */
int
secpolicy_sadopen(const cred_t *credp)
{
	priv_set_t pset;

	priv_emptyset(&pset);

	if (crgetzoneid(credp) == GLOBAL_ZONEID)
		priv_addset(&pset, PRIV_SYS_CONFIG);
	else
		priv_addset(&pset, PRIV_SYS_IP_CONFIG);

	return (secpolicy_require_set(credp, &pset, "devpolicy", KLPDARG_NONE));
}


/*
 * Add privileges to a particular privilege set; this is called when the
 * current sets of privileges are not sufficient.  I.e., we should always
 * call the policy override functions from here.
 * What we are allowed to have is in the Observed Permitted set; so
 * we compute the difference between that and the newset.
 */
int
secpolicy_require_privs(const cred_t *cr, const priv_set_t *nset)
{
	priv_set_t rqd;

	rqd = CR_OPPRIV(cr);

	priv_inverse(&rqd);
	priv_intersect(nset, &rqd);

	return (secpolicy_require_set(cr, &rqd, NULL, KLPDARG_NONE));
}

/*
 * secpolicy_smb
 *
 * Determine if the cred_t has PRIV_SYS_SMB privilege, indicating
 * that it has permission to access the smbsrv kernel driver.
 * PRIV_POLICY checks the privilege and audits the check.
 *
 * Returns:
 * 0       Driver access is allowed.
 * EPERM   Driver access is NOT permitted.
 */
int
secpolicy_smb(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_SMB, B_FALSE, EPERM, NULL));
}

/*
 * secpolicy_vscan
 *
 * Determine if cred_t has the necessary privileges to access a file
 * for virus scanning and update its extended system attributes.
 * PRIV_FILE_DAC_SEARCH, PRIV_FILE_DAC_READ - file access
 * PRIV_FILE_FLAG_SET - set extended system attributes
 *
 * PRIV_POLICY checks the privilege and audits the check.
 *
 * Returns:
 * 0      file access for virus scanning allowed.
 * EPERM  file access for virus scanning is NOT permitted.
 */
int
secpolicy_vscan(const cred_t *cr)
{
	if ((PRIV_POLICY(cr, PRIV_FILE_DAC_SEARCH, B_FALSE, EPERM, NULL)) ||
	    (PRIV_POLICY(cr, PRIV_FILE_DAC_READ, B_FALSE, EPERM, NULL)) ||
	    (PRIV_POLICY(cr, PRIV_FILE_FLAG_SET, B_FALSE, EPERM, NULL))) {
		return (EPERM);
	}

	return (0);
}

/*
 * secpolicy_smbfs_login
 *
 * Determines if the caller can add and delete the smbfs login
 * password in the the nsmb kernel module for the CIFS client.
 *
 * Returns:
 * 0       access is allowed.
 * EPERM   access is NOT allowed.
 */
int
secpolicy_smbfs_login(const cred_t *cr, uid_t uid)
{
	uid_t cruid = crgetruid(cr);

	if (cruid == uid)
		return (0);
	return (PRIV_POLICY(cr, PRIV_PROC_OWNER, B_FALSE,
	    EPERM, NULL));
}

/*
 * secpolicy_xvm_control
 *
 * Determines if a caller can control the xVM hypervisor and/or running
 * domains (x86 specific).
 *
 * Returns:
 * 0       access is allowed.
 * EPERM   access is NOT allowed.
 */
int
secpolicy_xvm_control(const cred_t *cr)
{
	if (PRIV_POLICY(cr, PRIV_XVM_CONTROL, B_FALSE, EPERM, NULL))
		return (EPERM);
	return (0);
}

/*
 * secpolicy_ppp_config
 *
 * Determine if the subject has sufficient privileges to configure PPP and
 * PPP-related devices.
 */
int
secpolicy_ppp_config(const cred_t *cr)
{
	if (PRIV_POLICY_ONLY(cr, PRIV_SYS_NET_CONFIG, B_FALSE))
		return (secpolicy_net_config(cr, B_FALSE));
	return (PRIV_POLICY(cr, PRIV_SYS_PPP_CONFIG, B_FALSE, EPERM, NULL));
}
