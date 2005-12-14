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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/syscall.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/policy.h>
#include <sys/kobj.h>
#include <sys/msg.h>
#include <sys/devpolicy.h>
#include <c2/audit.h>
#include <sys/varargs.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <sys/zone.h>
#include <inet/common.h>
#include <inet/optcom.h>
#include <sys/sdt.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/mntent.h>
#include <sys/contract_impl.h>

#include <sys/sunddi.h>

/*
 * There are two possible layers of privilege routines and two possible
 * levels of secpolicy.  Plus one other we may not be interested in, so
 * we may need as many as 6 but no more.
 */
#define	MAXPRIVSTACK		6

int priv_debug = 0;

/*
 * This file contains the majority of the policy routines.
 * Since the policy routines are defined by function and not
 * by privilege, there is quite a bit of duplication of
 * functions.
 *
 * The secpolicy functions must not make asssumptions about
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

/*
 * Policy checking functions
 *
 * In future, these will migrate to several files when policy
 * becomes more or less pluggable.
 *
 * For now, there's only one policy and this is it.
 */

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
	} else {
		cmn_err(CE_NOTE, fmt, cmd, me->p_pid, pname, cr->cr_uid,
		    curthread->t_sysnum, msg, sym, off);
	}
}

/*
 * Audit failure, log error message.
 */
static void
priv_policy_err(const cred_t *cr, int priv, boolean_t allzone, const char *msg)
{

#ifdef C2_AUDIT
	if (audit_active)
		audit_priv(priv, allzone ? ZONEPRIVS(cr) : NULL, 0);
#endif
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
 * priv_policy()
 * return 0 or error.
 * See block comment above for a description of "priv" and "allzone" usage.
 */
int
priv_policy(const cred_t *cr, int priv, boolean_t allzone, int err,
    const char *msg)
{
	if (HAS_PRIVILEGE(cr, priv) && (!allzone || HAS_ALLZONEPRIVS(cr))) {
		if ((allzone || priv == PRIV_ALL ||
		    !PRIV_ISASSERT(priv_basic, priv)) &&
		    !servicing_interrupt()) {
			u.u_acflag |= ASU;		/* Needed for SVVS */
#ifdef C2_AUDIT
			if (audit_active)
				audit_priv(priv,
				    allzone ? ZONEPRIVS(cr) : NULL, 1);
#endif
		}
		err = 0;
		DTRACE_PROBE2(priv__ok, int, priv, boolean_t, allzone);
	} else if (!servicing_interrupt()) {
		/* Failure audited in this procedure */
		priv_policy_err(cr, priv, allzone, msg);
	}

	return (err);
}

/*
 * Return B_TRUE for sufficient privileges, B_FALSE for insufficient privileges.
 */
boolean_t
priv_policy_choice(const cred_t *cr, int priv, boolean_t allzone)
{
	boolean_t res = HAS_PRIVILEGE(cr, priv) &&
	    (!allzone || HAS_ALLZONEPRIVS(cr));

#ifdef C2_AUDIT
	/* Audit success only */
	if (res && audit_active &&
	    (allzone || priv == PRIV_ALL || !PRIV_ISASSERT(priv_basic, priv)) &&
	    !servicing_interrupt()) {
		audit_priv(priv, allzone ? ZONEPRIVS(cr) : NULL, 1);
	}
#endif
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
secpolicy_require_set(const cred_t *cr, const priv_set_t *req, const char *msg)
{
	int priv;
	int pfound = -1;
	priv_set_t pset;

	if (req == PRIV_FULLSET ? HAS_ALLPRIVS(cr) : priv_issubset(req,
							    &CR_OEPRIV(cr))) {
		return (0);
	}

	if (req == PRIV_FULLSET || priv_isfullset(req)) {
		priv_policy_err(cr, PRIV_ALL, B_FALSE, msg);
		return (EACCES);
	}

	pset = CR_OEPRIV(cr);		/* present privileges */
	priv_inverse(&pset);		/* all non present privileges */
	priv_intersect(req, &pset);	/* the actual missing privs */

#ifdef C2_AUDIT
	if (audit_active)
		audit_priv(PRIV_NONE, &pset, 0);
#endif
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
 * Changing process priority
 */
int
secpolicy_setpriority(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_PRIOCNTL, B_FALSE, EPERM, NULL));
}

/*
 * Binding to a privileged port, port must be specified in host byte
 * order.
 */
int
secpolicy_net_privaddr(const cred_t *cr, in_port_t port)
{
	/*
	 * NFS ports, these are extra privileged ports, allow bind
	 * only if the SYS_NFS privilege is present.
	 */
	if (port == 2049 || port == 4045)
		return (PRIV_POLICY(cr, PRIV_SYS_NFS, B_FALSE, EACCES,
		    "NFS port"));
	else
		return (PRIV_POLICY(cr, PRIV_NET_PRIVADDR, B_FALSE, EACCES,
		    NULL));
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

		return (PRIV_POLICY(cr, PRIV_SYS_MOUNT, allzone, EPERM, NULL));
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
		err = VOP_GETATTR(mvp, &va, 0, cr);
		if (err != 0)
			return (err);

		if ((err = secpolicy_vnode_owner(cr, va.va_uid)) != 0)
			return (err);

		if ((va.va_mode & VWRITE) == 0 &&
		    secpolicy_vnode_access(cr, mvp, va.va_uid, VWRITE) != 0) {
			return (EACCES);
		}
	}
	return (PRIV_POLICY(cr, PRIV_SYS_MOUNT, allzone, EPERM, NULL));
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
		boolean_t amsuper = HAS_ALLZONEPRIVS(cr);

		/*
		 * Third check; if we don't have either "nosuid" or
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
 * Quotas are a resource, but if one has the ability to mount a filesystem, he
 * should be able to modify quotas on it.
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

/* ARGSUSED */
int
secpolicy_vnode_access(const cred_t *cr, vnode_t *vp, uid_t owner, mode_t mode)
{
	if ((mode & VREAD) &&
	    PRIV_POLICY(cr, PRIV_FILE_DAC_READ, B_FALSE, EACCES, NULL) != 0)
		return (EACCES);

	if (mode & VWRITE) {
		boolean_t allzone;

		if (owner == 0 && cr->cr_uid != 0)
			allzone = B_TRUE;
		else
			allzone = B_FALSE;
		if (PRIV_POLICY(cr, PRIV_FILE_DAC_WRITE, allzone, EACCES, NULL)
		    != 0)
			return (EACCES);
	}

	if (mode & VEXEC) {
		/*
		 * Directories use file_dac_search to override the execute bit.
		 */
		vtype_t vtype = vp->v_type;

		if (vtype == VDIR)
			return (PRIV_POLICY(cr, PRIV_FILE_DAC_SEARCH, B_FALSE,
			    EACCES, NULL));
		else
			return (PRIV_POLICY(cr, PRIV_FILE_DAC_EXECUTE, B_FALSE,
			    EACCES, NULL));
	}
	return (0);
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
 * Create a file with a group different than any of the groups allowed:
 * the group of the directory the file is created in, the effective
 * group or any of the supplementary groups.
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

	if (mask & AT_SIZE) {
		if (vp->v_type == VDIR) {
			error = EISDIR;
			goto out;
		}
		error = unlocked_access(node, VWRITE, cr);
		if (error)
			goto out;
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

		if ((vap->va_mode & S_ISUID) != 0 &&
		    (error = secpolicy_vnode_setid_modify(cr,
							ovap->va_uid)) != 0) {
			goto out;
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

	} else
		vap->va_mode = ovap->va_mode;

	if (mask & (AT_UID|AT_GID)) {
		boolean_t checkpriv = B_FALSE;
		int priv;
		boolean_t allzone = B_FALSE;

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
			allzone = (ovap->va_uid == 0);
			priv = PRIV_FILE_CHOWN;
		} else {
			if (((mask & AT_UID) && vap->va_uid != ovap->va_uid) ||
			    ((mask & AT_GID) && vap->va_gid != ovap->va_gid &&
			    !groupmember(vap->va_gid, cr))) {
				checkpriv = B_TRUE;
				priv = HAS_PRIVILEGE(cr, PRIV_FILE_CHOWN) ?
				    PRIV_FILE_CHOWN : PRIV_FILE_CHOWN_SELF;
			}
		}
		/*
		 * If necessary, check privilege to see if update can be done.
		 */
		if (checkpriv &&
		    (error = PRIV_POLICY(cr, priv, allzone, EPERM, NULL))
		    != 0) {
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
			else {
				error = unlocked_access(node, VWRITE, cr);
				if (error == EACCES &&
				    secpolicy_vnode_utime_modify(cr) == 0)
					error = 0;
			}
			if (error)
				goto out;
		}
	}
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
secpolicy_audit_getattr(const cred_t *cr)
{
	if (!PRIV_POLICY_ONLY(cr, PRIV_SYS_AUDIT, B_FALSE)) {
		return (PRIV_POLICY(cr, PRIV_PROC_AUDIT, B_FALSE, EPERM,
		    NULL));
	} else {
		return (PRIV_POLICY(cr, PRIV_SYS_AUDIT, B_FALSE, EPERM, NULL));
	}
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

/*
 * Processor sets, cpu configuration, resource pools.
 */
int
secpolicy_pset(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_RES_CONFIG, B_FALSE, EPERM, NULL));
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
	return (secpolicy_require_set(cr, PRIV_FULLSET, NULL));
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

/*
 * Basic privilege checks.
 */
int
secpolicy_basic_exec(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_EXEC, B_FALSE, EPERM, NULL));
}

int
secpolicy_basic_fork(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_PROC_FORK, B_FALSE, EPERM, NULL));
}

int
secpolicy_basic_proc(const cred_t *cr)
{
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
	return (PRIV_POLICY(cr, PRIV_FILE_LINK_ANY, B_FALSE, EPERM, NULL));
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

	err = secpolicy_require_set(cr,
	    (oflag & FWRITE) ? &plcy->dp_wrp : &plcy->dp_rdp, "devpolicy");
	dpfree(plcy);

	return (err);
}

int
secpolicy_modctl(const cred_t *cr, int cmd)
{
	switch (cmd) {
	case MODINFO:
	case MODGETPATH:
	case MODGETPATHLEN:
	case MODGETFBNAME:
	case MODGETNAME:
	case MODGETDEVPOLICY:
	case MODGETDEVPOLICYBYNAME:
	case MODGETMAJBIND:
		/* Unprivileged */
		return (0);
	case MODLOAD:
	case MODSETDEVPOLICY:
		return (secpolicy_require_set(cr, PRIV_FULLSET, NULL));
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
	return (secpolicy_require_set(cr, PRIV_FULLSET, NULL));
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
 * Name:   secpolicy_gart_access
 *
 * Normal: Verify if the subject has sufficient priveleges to make ioctls
 *	   to agpgart device
 *
 * Output: EPERM - if not privileged
 *
 */
int
secpolicy_gart_access(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_GART_ACCESS, B_FALSE, EPERM, NULL));
}

/*
 * Name:   secpolicy_gart_map
 *
 * Normal: Verify if the subject has sufficient privelegs to map aperture
 *	   range through agpgart driver
 *
 * Output: EPERM - if not privileged
 *
 */
int
secpolicy_gart_map(const cred_t *cr)
{
	if (PRIV_POLICY(cr, PRIV_GART_ACCESS, B_FALSE, EPERM, NULL)) {
		return (PRIV_POLICY(cr, PRIV_GART_MAP, B_FALSE, EPERM, NULL));
	}
	return (0);
}

/*
 * secpolicy_zfs
 *
 * Determine if the user has permission to manipulate ZFS datasets (not pools).
 * Equivalent to the SYS_MOUNT privilege.
 */
int
secpolicy_zfs(const cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_MOUNT, B_FALSE, EPERM, NULL));
}
