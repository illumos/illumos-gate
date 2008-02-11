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

/*
 * This file contains the auditing system call code.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/session.h>	/* for session structure (auditctl(2) */
#include <sys/kmem.h>		/* for KM_SLEEP */
#include <sys/cred_impl.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/pathname.h>
#include <sys/acct.h>
#include <sys/stropts.h>
#include <sys/exec.h>
#include <sys/thread.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/disp.h>
#include <sys/kobj.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>
#include <sys/taskq.h>
#include <sys/zone.h>

#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_record.h>

#define	CLEAR_VAL	-1

#define	HEADER_SIZE64	1;
#define	HEADER_SIZE32	0;
#define	AU_MIN_FILE_SZ	0x80000	/* minumum audit file size */
#define	AUDIT_REC_SIZE	0x8000	/* maximum user audit record size */

extern kmutex_t pidlock;

extern pri_t		minclsyspri;		/* priority for taskq */

extern int audit_load;		/* defined in audit_start.c */

int		au_auditstate = AUC_UNSET;	/* global audit state */
int		audit_policy;	/* global audit policies in force */
static clock_t	au_resid = 15;	/* wait .15 sec before droping a rec */

static int	getauid(caddr_t);
static int	setauid(caddr_t);
static int	getaudit(caddr_t);
static int	getaudit_addr(caddr_t, int);
static int	setaudit(caddr_t);
static int	setaudit_addr(caddr_t, int);
static int	auditdoor(int);
static int	auditctl(int, caddr_t, int);
static int	audit_modsysent(char *, int, int (*)());
static void	au_output_thread();
/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>
#include "sys/syscall.h"

static struct sysent auditsysent = {
	6,
	0,
	_auditsys
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_syscallops;

static struct modlsys modlsys = {
	&mod_syscallops, "C2 system call", &auditsysent
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlsys, 0
};

int
_init()
{
	int retval;

	if (audit_load == 0)
		return (-1);

	/*
	 * We are going to do an ugly thing here.
	 *  Because auditsys is already defined as a regular
	 *  syscall we have to change the definition for syscall
	 *  auditsys. Basically or in the SE_LOADABLE flag for
	 *  auditsys. We no have a static loadable syscall. Also
	 *  create an rw_lock.
	 */

	if ((audit_modsysent("c2audit", SE_LOADABLE|SE_NOUNLOAD,
	    _auditsys)) == -1)
		return (-1);

	if ((retval = mod_install(&modlinkage)) != 0)
		return (retval);

	return (0);
}

int
_fini()
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * when auditing is updated to allow enable/disable without
 * reboot (and when the audit stubs are removed) *most* of these
 * calls should return an error when auditing is off -- some
 * for local zones only.
 */

int
_auditsys(struct auditcalls *uap, rval_t *rvp)
{
	int result = 0;

	switch (uap->code) {
	case BSM_GETAUID:
		result = getauid((caddr_t)uap->a1);
		break;
	case BSM_SETAUID:
		result = setauid((caddr_t)uap->a1);
		break;
	case BSM_GETAUDIT:
		result = getaudit((caddr_t)uap->a1);
		break;
	case BSM_GETAUDIT_ADDR:

		result = getaudit_addr((caddr_t)uap->a1, (int)uap->a2);
		break;
	case BSM_SETAUDIT:
		result = setaudit((caddr_t)uap->a1);
		break;
	case BSM_SETAUDIT_ADDR:
		result = setaudit_addr((caddr_t)uap->a1, (int)uap->a2);
		break;
	case BSM_AUDIT:
		result = audit((caddr_t)uap->a1, (int)uap->a2);
		break;
	case BSM_AUDITDOOR:
		result = auditdoor((int)uap->a1);
		break;
	case BSM_AUDITON:
	case BSM_AUDITCTL:
		result = auditctl((int)uap->a1, (caddr_t)uap->a2, (int)uap->a3);
		break;
	default:
		result = EINVAL;
	}
	rvp->r_vals = result;
	return (result);
}

/*
 * Return the audit user ID for the current process.  Currently only
 * the privileged processes may see the audit id.  That may change.
 * If copyout is unsucessful return EFAULT.
 */
static int
getauid(caddr_t auid_p)
{
	const auditinfo_addr_t	*ainfo;

	if (secpolicy_audit_getattr(CRED()) != 0)
		return (EPERM);

	ainfo = crgetauinfo(CRED());
	if (ainfo == NULL)
		return (EINVAL);

	if (copyout(&ainfo->ai_auid, auid_p, sizeof (au_id_t)))
		return (EFAULT);

	return (0);
}

/*
 * Set the audit userid, for a process.  This can only be changed by
 * privileged processes.  The audit userid is inherited across forks & execs.
 * Passed in is a pointer to the au_id_t; if copyin unsuccessful return EFAULT.
 */
static int
setauid(caddr_t auid_p)
{
	proc_t *p;
	au_id_t	auid;
	cred_t *newcred;
	auditinfo_addr_t *auinfo;

	if (secpolicy_audit_config(CRED()) != 0)
		return (EPERM);

	if (copyin(auid_p, &auid, sizeof (au_id_t))) {
		return (EFAULT);
	}

	newcred = cralloc();
	if ((auinfo = crgetauinfo_modifiable(newcred)) == NULL) {
		crfree(newcred);
		return (EINVAL);
	}

	/* grab p_crlock and switch to new cred */
	p = curproc;
	mutex_enter(&p->p_crlock);
	crcopy_to(p->p_cred, newcred);
	p->p_cred = newcred;

	auinfo->ai_auid = auid;			/* update the auid */

	/* unlock and broadcast the cred changes */
	mutex_exit(&p->p_crlock);
	crset(p, newcred);

	return (0);
}

/*
 * Get the audit state information from the current process.
 * Return EFAULT if copyout fails.
 */
static int
getaudit(caddr_t info_p)
{
	STRUCT_DECL(auditinfo, info);
	const auditinfo_addr_t	*ainfo;
	model_t	model;

	if (secpolicy_audit_getattr(CRED()) != 0)
		return (EPERM);

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	ainfo = crgetauinfo(CRED());
	if (ainfo == NULL)
		return (EINVAL);

	/* trying to read a process with an IPv6 address? */
	if (ainfo->ai_termid.at_type == AU_IPv6)
		return (EOVERFLOW);

	STRUCT_FSET(info, ai_auid, ainfo->ai_auid);
	STRUCT_FSET(info, ai_mask, ainfo->ai_mask);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, ainfo->ai_termid.at_port) == 0) {
			return (EOVERFLOW);
		}
		STRUCT_FSET(info, ai_termid.port, dev);
	} else
		STRUCT_FSET(info, ai_termid.port, ainfo->ai_termid.at_port);
#else
	STRUCT_FSET(info, ai_termid.port, ainfo->ai_termid.at_port);
#endif
	STRUCT_FSET(info, ai_termid.machine, ainfo->ai_termid.at_addr[0]);
	STRUCT_FSET(info, ai_asid, ainfo->ai_asid);

	if (copyout(STRUCT_BUF(info), info_p, STRUCT_SIZE(info)))
		return (EFAULT);

	return (0);
}

/*
 * Get the audit state information from the current process.
 * Return EFAULT if copyout fails.
 */
static int
getaudit_addr(caddr_t info_p, int len)
{
	STRUCT_DECL(auditinfo_addr, info);
	const auditinfo_addr_t	*ainfo;
	model_t	model;

	if (secpolicy_audit_getattr(CRED()) != 0)
		return (EPERM);

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (len < STRUCT_SIZE(info))
		return (EOVERFLOW);

	ainfo = crgetauinfo(CRED());

	if (ainfo == NULL)
		return (EINVAL);

	STRUCT_FSET(info, ai_auid, ainfo->ai_auid);
	STRUCT_FSET(info, ai_mask, ainfo->ai_mask);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, ainfo->ai_termid.at_port) == 0) {
			return (EOVERFLOW);
		}
		STRUCT_FSET(info, ai_termid.at_port, dev);
	} else
		STRUCT_FSET(info, ai_termid.at_port, ainfo->ai_termid.at_port);
#else
	STRUCT_FSET(info, ai_termid.at_port, ainfo->ai_termid.at_port);
#endif
	STRUCT_FSET(info, ai_termid.at_type, ainfo->ai_termid.at_type);
	STRUCT_FSET(info, ai_termid.at_addr[0], ainfo->ai_termid.at_addr[0]);
	STRUCT_FSET(info, ai_termid.at_addr[1], ainfo->ai_termid.at_addr[1]);
	STRUCT_FSET(info, ai_termid.at_addr[2], ainfo->ai_termid.at_addr[2]);
	STRUCT_FSET(info, ai_termid.at_addr[3], ainfo->ai_termid.at_addr[3]);
	STRUCT_FSET(info, ai_asid, ainfo->ai_asid);

	if (copyout(STRUCT_BUF(info), info_p, STRUCT_SIZE(info)))
		return (EFAULT);

	return (0);
}

/*
 * Set the audit state information for the current process.
 * Return EFAULT if copyout fails.
 */
static int
setaudit(caddr_t info_p)
{
	STRUCT_DECL(auditinfo, info);
	proc_t *p;
	cred_t	*newcred;
	model_t	model;
	auditinfo_addr_t *ainfo;

	if (secpolicy_audit_config(CRED()) != 0)
		return (EPERM);

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (copyin(info_p, STRUCT_BUF(info), STRUCT_SIZE(info)))
		return (EFAULT);

	newcred = cralloc();
	if ((ainfo = crgetauinfo_modifiable(newcred)) == NULL) {
		crfree(newcred);
		return (EINVAL);
	}

	/* grab p_crlock and switch to new cred */
	p = curproc;
	mutex_enter(&p->p_crlock);
	crcopy_to(p->p_cred, newcred);
	p->p_cred = newcred;

	/* Set audit mask, id, termid and session id as specified */
	ainfo->ai_auid = STRUCT_FGET(info, ai_auid);
#ifdef _LP64
	/* only convert to 64 bit if coming from a 32 bit binary */
	if (model == DATAMODEL_ILP32)
		ainfo->ai_termid.at_port =
		    DEVEXPL(STRUCT_FGET(info, ai_termid.port));
	else
		ainfo->ai_termid.at_port = STRUCT_FGET(info, ai_termid.port);
#else
	ainfo->ai_termid.at_port = STRUCT_FGET(info, ai_termid.port);
#endif
	ainfo->ai_termid.at_type = AU_IPv4;
	ainfo->ai_termid.at_addr[0] = STRUCT_FGET(info, ai_termid.machine);
	ainfo->ai_asid = STRUCT_FGET(info, ai_asid);
	ainfo->ai_mask = STRUCT_FGET(info, ai_mask);

	/* unlock and broadcast the cred changes */
	mutex_exit(&p->p_crlock);
	crset(p, newcred);

	return (0);
}

/*
 * Set the audit state information for the current process.
 * Return EFAULT if copyin fails.
 */
static int
setaudit_addr(caddr_t info_p, int len)
{
	STRUCT_DECL(auditinfo_addr, info);
	proc_t *p;
	cred_t	*newcred;
	model_t	model;
	int i;
	int type;
	auditinfo_addr_t *ainfo;

	if (secpolicy_audit_config(CRED()) != 0)
		return (EPERM);

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (len < STRUCT_SIZE(info))
		return (EOVERFLOW);

	if (copyin(info_p, STRUCT_BUF(info), STRUCT_SIZE(info)))
		return (EFAULT);

	type = STRUCT_FGET(info, ai_termid.at_type);
	if ((type != AU_IPv4) && (type != AU_IPv6))
		return (EINVAL);

	newcred = cralloc();
	if ((ainfo = crgetauinfo_modifiable(newcred)) == NULL) {
		crfree(newcred);
		return (EINVAL);
	}

	/* grab p_crlock and switch to new cred */
	p = curproc;
	mutex_enter(&p->p_crlock);
	crcopy_to(p->p_cred, newcred);
	p->p_cred = newcred;

	/* Set audit mask, id, termid and session id as specified */
	ainfo->ai_auid = STRUCT_FGET(info, ai_auid);
	ainfo->ai_mask = STRUCT_FGET(info, ai_mask);
#ifdef _LP64
	/* only convert to 64 bit if coming from a 32 bit binary */
	if (model == DATAMODEL_ILP32)
		ainfo->ai_termid.at_port =
		    DEVEXPL(STRUCT_FGET(info, ai_termid.at_port));
	else
		ainfo->ai_termid.at_port = STRUCT_FGET(info, ai_termid.at_port);
#else
	ainfo->ai_termid.at_port = STRUCT_FGET(info, ai_termid.at_port);
#endif
	ainfo->ai_termid.at_type = type;
	bzero(&ainfo->ai_termid.at_addr[0], sizeof (ainfo->ai_termid.at_addr));
	for (i = 0; i < (type/sizeof (int)); i++)
		ainfo->ai_termid.at_addr[i] =
		    STRUCT_FGET(info, ai_termid.at_addr[i]);

	if (ainfo->ai_termid.at_type == AU_IPv6 &&
	    IN6_IS_ADDR_V4MAPPED(((in6_addr_t *)ainfo->ai_termid.at_addr))) {
		ainfo->ai_termid.at_type = AU_IPv4;
		ainfo->ai_termid.at_addr[0] = ainfo->ai_termid.at_addr[3];
		ainfo->ai_termid.at_addr[1] = 0;
		ainfo->ai_termid.at_addr[2] = 0;
		ainfo->ai_termid.at_addr[3] = 0;
	}

	ainfo->ai_asid = STRUCT_FGET(info, ai_asid);

	/* unlock and broadcast the cred changes */
	mutex_exit(&p->p_crlock);
	crset(p, newcred);

	return (0);
}

/*
 * The audit system call. Trust what the user has sent down and save it
 * away in the audit file. User passes a complete audit record and its
 * length.  We will fill in the time stamp, check the header and the length
 * Put a trailer and a sequence token if policy requires.
 * In the future length might become size_t instead of an int.
 *
 * The call is valid whether or not AUDIT_PERZONE is set (think of
 * login to a zone).  When the local audit state (auk_auditstate) is
 * AUC_INIT_AUDIT, records are accepted even though auditd isn't
 * running.
 */
int
audit(caddr_t record, int length)
{
	char	c;
	int	count, l;
	token_t	*m, *n, *s, *ad;
	int	hdrlen, delta;
	adr_t	hadr;
	adr_t	sadr;
	int	size;	/* 0: 32 bit utility  1: 64 bit utility */
	int	host_len;
	size_t	zlen;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	/* if auditing not enabled, then don't generate an audit record */
	if (kctx->auk_auditstate != AUC_AUDITING &&
	    kctx->auk_auditstate != AUC_INIT_AUDIT)
		return (0);

	/* Only privileged processes can audit */
	if (secpolicy_audit_modify(CRED()) != 0)
		return (EPERM);

	/* Max user record size is 32K */
	if (length > AUDIT_REC_SIZE)
		return (E2BIG);

	/*
	 * The specified length must be at least as big as the smallest
	 * possible header token. Later after beginning to scan the
	 * header we'll determine the true minimum length according to
	 * the header type and attributes.
	 */
#define	AU_MIN_HEADER_LEN	(sizeof (char) + sizeof (int32_t) + \
	sizeof (char) + sizeof (short) + sizeof (short) + \
	(sizeof (int32_t) * 2))

	if (length < AU_MIN_HEADER_LEN)
		return (EINVAL);

	/* Read in user's audit record */
	count = length;
	m = n = s = ad = NULL;
	while (count) {
		m = au_getclr();
		if (!s)
			s = n = m;
		else {
			n->next_buf = m;
			n = m;
		}
		l = MIN(count, AU_BUFSIZE);
		if (copyin(record, memtod(m, caddr_t), (size_t)l)) {
			/* copyin failed release au_membuf */
			au_free_rec(s);
			return (EFAULT);
		}
		record += l;
		count -= l;
		m->len = (uchar_t)l;
	}

	/* Now attach the entire thing to ad */
	au_write((caddr_t *)&(ad), s);

	/* validate header token type. trust everything following it */
	adr_start(&hadr, memtod(s, char *));
	(void) adr_getchar(&hadr, &c);
	switch (c) {
	case AUT_HEADER32:
		/* size vers+event_ID+event_modifier fields */
		delta = 1 + 2 + 2;
		hdrlen = 1 + 4 + delta + (sizeof (int32_t) * 2);
		size = HEADER_SIZE32;
		break;

#ifdef _LP64
	case AUT_HEADER64:
		/* size vers+event_ID+event_modifier fields */
		delta = 1 + 2 + 2;
		hdrlen = 1 + 4 + delta + (sizeof (int64_t) * 2);
		size = HEADER_SIZE64;
		break;
#endif

	case AUT_HEADER32_EX:
		/*
		 * Skip over the length/version/type/mod fields and
		 * grab the host address type (length), then rewind.
		 * This is safe per the previous minimum length check.
		 */
		hadr.adr_now += 9;
		(void) adr_getint32(&hadr, &host_len);
		hadr.adr_now -= 9 + sizeof (int32_t);

		/* size: vers+event_ID+event_modifier+IP_type+IP_addr_array */
		delta = 1 + 2 + 2 + 4 + host_len;
		hdrlen = 1 + 4 + delta + (sizeof (int32_t) * 2);
		size = HEADER_SIZE32;
		break;

#ifdef _LP64
	case AUT_HEADER64_EX:
		/*
		 * Skip over the length/version/type/mod fields and grab
		 * the host address type (length), then rewind.
		 * This is safe per the previous minimum length check.
		 */
		hadr.adr_now += 9;
		(void) adr_getint32(&hadr, &host_len);
		hadr.adr_now -= 9 + sizeof (int32_t);

		/* size: vers+event_ID+event_modifier+IP_type+IP_addr_array */
		delta = 1 + 2 + 2 + 4 + host_len;
		hdrlen = 1 + 4 + delta + (sizeof (int64_t) * 2);
		size = HEADER_SIZE64;
		break;
#endif

	default:
		/* Header is wrong, reject message */
		au_free_rec(s);
		return (EINVAL);
	}

	if (length < hdrlen) {
		au_free_rec(s);
		return (0);
	}

	/* advance over header token length field */
	hadr.adr_now += 4;

	/* validate version */
	(void) adr_getchar(&hadr, &c);
	if (c != TOKEN_VERSION) {
		/* version is wrong, reject message */
		au_free_rec(s);
		return (EINVAL);
	}

	/* backup to header length field (including version field) */
	hadr.adr_now -= 5;

	/*
	 * add on the zonename token if policy AUDIT_ZONENAME is set
	 */
	if (kctx->auk_policy & AUDIT_ZONENAME) {
		zlen = au_zonename_length(NULL);
		if (zlen > 0) {
			length += zlen;
			m = au_to_zonename(zlen, NULL);
			(void) au_append_rec(ad, m, AU_PACK);
		}
	}
	/* Add an (optional) sequence token. NULL offset if none */
	if (kctx->auk_policy & AUDIT_SEQ) {
		/* get the sequnce token */
		m = au_to_seq();

		/* sequence token 5 bytes long */
		length += 5;

		/* link to audit record (i.e. don't pack the data) */
		(void) au_append_rec(ad, m, AU_LINK);

		/* advance to count field of token */
		adr_start(&sadr, memtod(m, char *));
		sadr.adr_now += 1;
	} else
		sadr.adr_now = (char *)NULL;

	/* add the (optional) trailer token */
	if (kctx->auk_policy & AUDIT_TRAIL) {
		/* trailer token is 7 bytes long */
		length += 7;

		/* append to audit record */
		(void) au_append_rec(ad, au_to_trailer(length), AU_PACK);
	}

	/* audit record completely assembled. set the length */
	adr_int32(&hadr, (int32_t *)&length, 1);

	/* advance to date/time field of header */
	hadr.adr_now += delta;

	/* We are done  put it on the queue */
	AS_INC(as_generated, 1, kctx);
	AS_INC(as_audit, 1, kctx);

	au_enqueue(kctx, s, &hadr, &sadr, size, 0);

	AS_INC(as_totalsize, length, kctx);

	return (0);
}

static void
audit_dont_stop(void *kctx)
{

	if ((((au_kcontext_t *)kctx)->auk_valid != AUK_VALID) ||
	    (((au_kcontext_t *)kctx)->auk_auditstate == AUC_NOAUDIT))
		return;

	mutex_enter(&(((au_kcontext_t *)kctx)->auk_queue.lock));
	cv_broadcast(&(((au_kcontext_t *)kctx)->auk_queue.write_cv));
	mutex_exit(&(((au_kcontext_t *)kctx)->auk_queue.lock));
}

/*
 * auditdoor starts a kernel thread to generate output from the audit
 * queue.  The thread terminates when it detects auditing being turned
 * off, such as when auditd exits with a SIGTERM.  If a subsequent
 * auditdoor arrives while the thread is running, the door descriptor
 * of the last auditdoor in will be used for output.  auditd is responsible
 * for insuring that multiple copies are not running.
 */

static int
auditdoor(int fd)
{
	struct file	*fp;
	struct vnode	*vp;
	int		do_create = 0;
	au_kcontext_t	*kctx;

	if (secpolicy_audit_config(CRED()) != 0)
		return (EPERM);

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	/*
	 * convert file pointer to file descriptor
	 *   Note: fd ref count incremented here.
	 */
	if ((fp = (struct file *)getf(fd)) == NULL) {
		return (EBADF);
	}
	vp = fp->f_vnode;
	if (vp->v_type != VDOOR) {
		cmn_err(CE_WARN,
		    "auditdoor() did not get the expected door descriptor\n");
		releasef(fd);
		return (EINVAL);
	}
	/*
	 * If the output thread is already running, then replace the
	 * door descriptor with the new one and continue; otherwise
	 * create the thread too.  Since au_output_thread makes a call
	 * to au_doorio() which also does
	 * mutex_lock(&(kctx->auk_svc_lock)), the create/dispatch is
	 * done after the unlock...
	 */
	mutex_enter(&(kctx->auk_svc_lock));

	if (kctx->auk_current_vp != NULL)
		VN_RELE(kctx->auk_current_vp);

	kctx->auk_current_vp = vp;
	VN_HOLD(kctx->auk_current_vp);
	releasef(fd);

	if (!kctx->auk_output_active) {
		kctx->auk_output_active = 1;
		do_create = 1;
	}
	mutex_exit(&(kctx->auk_svc_lock));
	if (do_create) {
		kctx->auk_taskq =
		    taskq_create("output_master", 1, minclsyspri, 1, 1, 0);
		(void) taskq_dispatch(kctx->auk_taskq,
		    (task_func_t *)au_output_thread,
		    kctx, TQ_SLEEP);
	}
	return (0);
}

/*
 * au_queue_kick -- wake up the output queue after delay ticks
 */
static void
au_queue_kick(void *kctx)
{
	/*
	 * wakeup reader if its not running and there is something
	 * to do.  It also helps that kctx still be valid...
	 */

	if ((((au_kcontext_t *)kctx)->auk_valid != AUK_VALID) ||
	    (((au_kcontext_t *)kctx)->auk_auditstate == AUC_NOAUDIT))
		return;

	if (((au_kcontext_t *)kctx)->auk_queue.cnt &&
	    ((au_kcontext_t *)kctx)->auk_queue.rd_block)
		cv_broadcast(&((au_kcontext_t *)kctx)->auk_queue.read_cv);

	/* fire off timeout event to kick audit queue awake */
	(void) timeout(au_queue_kick, kctx,
	    ((au_kcontext_t *)kctx)->auk_queue.delay);
}

/*
 * output thread
 *
 * this runs "forever" where "forever" means until either auk_auditstate
 * changes from AUC_AUDITING or if the door descriptor becomes invalid.
 *
 * there is one thread per active zone if AUC_PERZONE is set.  Since
 * there is the possibility that a zone may go down without auditd
 * terminating properly, a zone shutdown kills its au_output_thread()
 * via taskq_destroy().
 */

static void
au_output_thread(au_kcontext_t *kctx)
{
	int		error = 0;

	(void) timeout(au_queue_kick, kctx, kctx->auk_queue.delay);

	/*
	 * Wait for work, until a signal arrives,
	 * or until auditing is disabled.
	 */

	while (!error) {
		if (kctx->auk_auditstate == AUC_AUDITING) {
			mutex_enter(&(kctx->auk_queue.lock));
			while (kctx->auk_queue.head == NULL) {
				/* safety check. kick writer awake */
				if (kctx->auk_queue.wt_block) {
					cv_broadcast(&(kctx->
					    auk_queue.write_cv));
				}

				kctx->auk_queue.rd_block = 1;
				AS_INC(as_rblocked, 1, kctx);

				cv_wait(&(kctx->auk_queue.read_cv),
				    &(kctx->auk_queue.lock));
				kctx->auk_queue.rd_block = 0;

				if (kctx->auk_auditstate != AUC_AUDITING) {
					mutex_exit(&(kctx->auk_queue.lock));
					(void) timeout(audit_dont_stop, kctx,
					    au_resid);
					goto output_exit;
				}
				kctx->auk_queue.rd_block = 0;
			}
			mutex_exit(&(kctx->auk_queue.lock));
			/*
			 * au_doorio() calls au_door_upcall which holds
			 * auk_svc_lock; au_doorio empties the queue before
			 * returning.
			 */

			error = au_doorio(kctx);
		} else {
			/* auditing turned off while we slept */
			break;
		}
	}
output_exit:
	mutex_enter(&(kctx->auk_svc_lock));

	VN_RELE(kctx->auk_current_vp);
	kctx->auk_current_vp = NULL;

	kctx->auk_output_active = 0;

	mutex_exit(&(kctx->auk_svc_lock));
}


/*
 * Get the global policy flag
 */

static int
getpolicy(caddr_t data)
{
	int	policy;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	policy = audit_policy | kctx->auk_policy;

	if (copyout(&policy, data, sizeof (int)))
		return (EFAULT);
	return (0);
}

/*
 * Set the global and local policy flags
 *
 * The global flags only make sense from the global zone;
 * the local flags depend on the AUDIT_PERZONE policy:
 * if the perzone policy is set, then policy is set separately
 * per zone, else held only in the global zone.
 *
 * The initial value of a local zone's policy flag is determined
 * by the value of the global zone's flags at the time the
 * local zone is created.
 *
 * While auditconfig(1M) allows setting and unsetting policies one bit
 * at a time, the mask passed in from auditconfig() is created by a
 * syscall to getpolicy and then modified based on the auditconfig()
 * cmd line, so the input policy value is used to replace the existing
 * policy.
 */


static int
setpolicy(caddr_t data)
{
	int	policy;
	au_kcontext_t	*kctx;

	if (copyin(data, &policy, sizeof (int)))
		return (EFAULT);

	kctx = GET_KCTX_NGZ;

	if (INGLOBALZONE(curproc)) {
		if (policy & ~(AUDIT_GLOBAL | AUDIT_LOCAL))
			return (EINVAL);

		audit_policy = policy & AUDIT_GLOBAL;
	} else {
		if (!(audit_policy & AUDIT_PERZONE))
			return (EINVAL);

		if (policy & ~AUDIT_LOCAL)	/* global bits are a no-no */
			return (EINVAL);
	}
	kctx->auk_policy = policy & AUDIT_LOCAL;

	/*
	 * auk_current_vp is NULL before auditd starts (or during early
	 * auditd starup) or if auditd is halted; in either case,
	 * notification of a policy change is not needed, since auditd
	 * reads policy as it comes up.  The error return from au_doormsg()
	 * is ignored to avoid a race condition -- for example if auditd
	 * segv's, the audit state may be "auditing" but the door may
	 * be closed.  Returning an error if the door is open makes it
	 * impossible for Greenline to restart auditd.
	 */
	if (kctx->auk_current_vp != NULL)
		(void) au_doormsg(kctx, AU_DBUF_POLICY, &policy);

	/*
	 * Wake up anyone who might have blocked on full audit
	 * partitions. audit daemons need to set AUDIT_FULL when no
	 * space so we can tell if we should start dropping records.
	 */
	mutex_enter(&(kctx->auk_queue.lock));

	if ((policy & (AUDIT_CNT | AUDIT_SCNT) &&
	    (kctx->auk_queue.cnt >= kctx->auk_queue.hiwater)))
		cv_broadcast(&(kctx->auk_queue.write_cv));

	mutex_exit(&(kctx->auk_queue.lock));

	return (0);
}

static int
getkmask(caddr_t data)
{
	au_kcontext_t	*kctx;

	kctx = GET_KCTX_PZ;

	if (copyout(&kctx->auk_info.ai_mask, data, sizeof (au_mask_t)))
		return (EFAULT);
	return (0);
}

static int
setkmask(caddr_t data)
{
	au_mask_t	mask;
	au_kcontext_t	*kctx;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	if (copyin(data, &mask, sizeof (au_mask_t)))
		return (EFAULT);

	kctx->auk_info.ai_mask = mask;
	return (0);
}

static int
getkaudit(caddr_t info_p, int len)
{
	STRUCT_DECL(auditinfo_addr, info);
	model_t model;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (len < STRUCT_SIZE(info))
		return (EOVERFLOW);

	STRUCT_FSET(info, ai_auid, kctx->auk_info.ai_auid);
	STRUCT_FSET(info, ai_mask, kctx->auk_info.ai_mask);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, kctx->auk_info.ai_termid.at_port) == 0) {
			return (EOVERFLOW);
		}
		STRUCT_FSET(info, ai_termid.at_port, dev);
	} else {
		STRUCT_FSET(info, ai_termid.at_port,
		    kctx->auk_info.ai_termid.at_port);
	}
#else
	STRUCT_FSET(info, ai_termid.at_port,
	    kctx->auk_info.ai_termid.at_port);
#endif
	STRUCT_FSET(info, ai_termid.at_type,
	    kctx->auk_info.ai_termid.at_type);
	STRUCT_FSET(info, ai_termid.at_addr[0],
	    kctx->auk_info.ai_termid.at_addr[0]);
	STRUCT_FSET(info, ai_termid.at_addr[1],
	    kctx->auk_info.ai_termid.at_addr[1]);
	STRUCT_FSET(info, ai_termid.at_addr[2],
	    kctx->auk_info.ai_termid.at_addr[2]);
	STRUCT_FSET(info, ai_termid.at_addr[3],
	    kctx->auk_info.ai_termid.at_addr[3]);
	STRUCT_FSET(info, ai_asid, kctx->auk_info.ai_asid);

	if (copyout(STRUCT_BUF(info), info_p, STRUCT_SIZE(info)))
		return (EFAULT);

	return (0);
}

/*
 * the host address for AUDIT_PERZONE == 0 is that of the global
 * zone and for local zones it is of the current zone.
 */

static int
setkaudit(caddr_t info_p, int len)
{
	STRUCT_DECL(auditinfo_addr, info);
	model_t model;
	au_kcontext_t	*kctx;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (len < STRUCT_SIZE(info))
		return (EOVERFLOW);

	if (copyin(info_p, STRUCT_BUF(info), STRUCT_SIZE(info)))
		return (EFAULT);

	if ((STRUCT_FGET(info, ai_termid.at_type) != AU_IPv4) &&
	    (STRUCT_FGET(info, ai_termid.at_type) != AU_IPv6))
		return (EINVAL);

	/* Set audit mask, termid and session id as specified */
	kctx->auk_info.ai_auid = STRUCT_FGET(info, ai_auid);
	kctx->auk_info.ai_mask = STRUCT_FGET(info, ai_mask);
#ifdef _LP64
	/* only convert to 64 bit if coming from a 32 bit binary */
	if (model == DATAMODEL_ILP32)
		kctx->auk_info.ai_termid.at_port =
		    DEVEXPL(STRUCT_FGET(info, ai_termid.at_port));
	else
		kctx->auk_info.ai_termid.at_port =
		    STRUCT_FGET(info, ai_termid.at_port);
#else
	kctx->auk_info.ai_termid.at_port = STRUCT_FGET(info, ai_termid.at_port);
#endif
	kctx->auk_info.ai_termid.at_type = STRUCT_FGET(info, ai_termid.at_type);
	bzero(&kctx->auk_info.ai_termid.at_addr[0],
	    sizeof (kctx->auk_info.ai_termid.at_addr));
	kctx->auk_info.ai_termid.at_addr[0] =
	    STRUCT_FGET(info, ai_termid.at_addr[0]);
	kctx->auk_info.ai_termid.at_addr[1] =
	    STRUCT_FGET(info, ai_termid.at_addr[1]);
	kctx->auk_info.ai_termid.at_addr[2] =
	    STRUCT_FGET(info, ai_termid.at_addr[2]);
	kctx->auk_info.ai_termid.at_addr[3] =
	    STRUCT_FGET(info, ai_termid.at_addr[3]);
	kctx->auk_info.ai_asid = STRUCT_FGET(info, ai_asid);

	if (kctx->auk_info.ai_termid.at_type == AU_IPv6 &&
	    IN6_IS_ADDR_V4MAPPED(
	    ((in6_addr_t *)kctx->auk_info.ai_termid.at_addr))) {
		kctx->auk_info.ai_termid.at_type = AU_IPv4;
		kctx->auk_info.ai_termid.at_addr[0] =
		    kctx->auk_info.ai_termid.at_addr[3];
		kctx->auk_info.ai_termid.at_addr[1] = 0;
		kctx->auk_info.ai_termid.at_addr[2] = 0;
		kctx->auk_info.ai_termid.at_addr[3] = 0;
	}
	if (kctx->auk_info.ai_termid.at_type == AU_IPv6)
		kctx->auk_hostaddr_valid = IN6_IS_ADDR_UNSPECIFIED(
		    (in6_addr_t *)kctx->auk_info.ai_termid.at_addr) ? 0 : 1;
	else
		kctx->auk_hostaddr_valid =
		    (kctx->auk_info.ai_termid.at_addr[0] ==
		    htonl(INADDR_ANY)) ? 0 : 1;

	return (0);
}

static int
getqctrl(caddr_t data)
{
	au_kcontext_t	*kctx = GET_KCTX_PZ;
	STRUCT_DECL(au_qctrl, qctrl);
	STRUCT_INIT(qctrl, get_udatamodel());

	mutex_enter(&(kctx->auk_queue.lock));
	STRUCT_FSET(qctrl, aq_hiwater, kctx->auk_queue.hiwater);
	STRUCT_FSET(qctrl, aq_lowater, kctx->auk_queue.lowater);
	STRUCT_FSET(qctrl, aq_bufsz, kctx->auk_queue.bufsz);
	STRUCT_FSET(qctrl, aq_delay, kctx->auk_queue.delay);
	mutex_exit(&(kctx->auk_queue.lock));

	if (copyout(STRUCT_BUF(qctrl), data, STRUCT_SIZE(qctrl)))
		return (EFAULT);

	return (0);
}

static int
setqctrl(caddr_t data)
{
	au_kcontext_t	*kctx;
	struct au_qctrl qctrl_tmp;
	STRUCT_DECL(au_qctrl, qctrl);
	STRUCT_INIT(qctrl, get_udatamodel());

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);
	kctx = GET_KCTX_NGZ;

	if (copyin(data, STRUCT_BUF(qctrl), STRUCT_SIZE(qctrl)))
		return (EFAULT);

	qctrl_tmp.aq_hiwater = (size_t)STRUCT_FGET(qctrl, aq_hiwater);
	qctrl_tmp.aq_lowater = (size_t)STRUCT_FGET(qctrl, aq_lowater);
	qctrl_tmp.aq_bufsz = (size_t)STRUCT_FGET(qctrl, aq_bufsz);
	qctrl_tmp.aq_delay = (clock_t)STRUCT_FGET(qctrl, aq_delay);

	/* enforce sane values */

	if (qctrl_tmp.aq_hiwater <= qctrl_tmp.aq_lowater)
		return (EINVAL);

	if (qctrl_tmp.aq_hiwater < AQ_LOWATER)
		return (EINVAL);

	if (qctrl_tmp.aq_hiwater > AQ_MAXHIGH)
		return (EINVAL);

	if (qctrl_tmp.aq_bufsz < AQ_BUFSZ)
		return (EINVAL);

	if (qctrl_tmp.aq_bufsz > AQ_MAXBUFSZ)
		return (EINVAL);

	if (qctrl_tmp.aq_delay == 0)
		return (EINVAL);

	if (qctrl_tmp.aq_delay > AQ_MAXDELAY)
		return (EINVAL);

	/* update everything at once so things are consistant */
	mutex_enter(&(kctx->auk_queue.lock));
	kctx->auk_queue.hiwater = qctrl_tmp.aq_hiwater;
	kctx->auk_queue.lowater = qctrl_tmp.aq_lowater;
	kctx->auk_queue.bufsz = qctrl_tmp.aq_bufsz;
	kctx->auk_queue.delay = qctrl_tmp.aq_delay;

	if (kctx->auk_queue.rd_block &&
	    kctx->auk_queue.cnt > kctx->auk_queue.lowater)
		cv_broadcast(&(kctx->auk_queue.read_cv));

	if (kctx->auk_queue.wt_block &&
	    kctx->auk_queue.cnt < kctx->auk_queue.hiwater)
		cv_broadcast(&(kctx->auk_queue.write_cv));

	mutex_exit(&(kctx->auk_queue.lock));

	return (0);
}

static int
getcwd(caddr_t data, int length)
{
	struct p_audit_data	*pad;
	struct audit_path	*app;
	int	pathlen;

	pad = P2A(curproc);
	ASSERT(pad != NULL);

	mutex_enter(&(pad->pad_lock));
	app = pad->pad_cwd;
	au_pathhold(app);
	mutex_exit(&(pad->pad_lock));

	pathlen = app->audp_sect[1] - app->audp_sect[0];
	if (pathlen > length) {
		au_pathrele(app);
		return (E2BIG);
	}

	if (copyout(app->audp_sect[0], data, pathlen)) {
		au_pathrele(app);
		return (EFAULT);
	}

	au_pathrele(app);
	return (0);
}

static int
getcar(caddr_t data, int length)
{
	struct p_audit_data	*pad;
	struct audit_path	*app;
	int	pathlen;

	pad = P2A(curproc);
	ASSERT(pad != NULL);

	mutex_enter(&(pad->pad_lock));
	app = pad->pad_root;
	au_pathhold(app);
	mutex_exit(&(pad->pad_lock));

	pathlen = app->audp_sect[1] - app->audp_sect[0];
	if (pathlen > length) {
		au_pathrele(app);
		return (E2BIG);
	}

	if (copyout(app->audp_sect[0], data, pathlen)) {
		au_pathrele(app);
		return (EFAULT);
	}

	au_pathrele(app);
	return (0);
}

static int
getstat(caddr_t data)
{
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	membar_consumer();

	if (copyout((caddr_t)&(kctx->auk_statistics), data, sizeof (au_stat_t)))
		return (EFAULT);
	return (0);
}


static int
setstat(caddr_t data)
{
	au_kcontext_t	*kctx = GET_KCTX_PZ;
	au_stat_t au_stat;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	if (copyin(data, &au_stat, sizeof (au_stat_t)))
		return (EFAULT);

	if (au_stat.as_generated == CLEAR_VAL)
		kctx->auk_statistics.as_generated = 0;
	if (au_stat.as_nonattrib == CLEAR_VAL)
		kctx->auk_statistics.as_nonattrib = 0;
	if (au_stat.as_kernel == CLEAR_VAL)
		kctx->auk_statistics.as_kernel = 0;
	if (au_stat.as_audit == CLEAR_VAL)
		kctx->auk_statistics.as_audit = 0;
	if (au_stat.as_auditctl == CLEAR_VAL)
		kctx->auk_statistics.as_auditctl = 0;
	if (au_stat.as_enqueue == CLEAR_VAL)
		kctx->auk_statistics.as_enqueue = 0;
	if (au_stat.as_written == CLEAR_VAL)
		kctx->auk_statistics.as_written = 0;
	if (au_stat.as_wblocked == CLEAR_VAL)
		kctx->auk_statistics.as_wblocked = 0;
	if (au_stat.as_rblocked == CLEAR_VAL)
		kctx->auk_statistics.as_rblocked = 0;
	if (au_stat.as_dropped == CLEAR_VAL)
		kctx->auk_statistics.as_dropped = 0;
	if (au_stat.as_totalsize == CLEAR_VAL)
		kctx->auk_statistics.as_totalsize = 0;

	membar_producer();

	return (0);

}

static int
setumask(caddr_t data)
{
	STRUCT_DECL(auditinfo, user_info);
	struct proc *p;
	const auditinfo_addr_t	*ainfo;
	model_t	model;

	model = get_udatamodel();
	STRUCT_INIT(user_info, model);

	if (copyin(data, STRUCT_BUF(user_info), STRUCT_SIZE(user_info)))
		return (EFAULT);

	mutex_enter(&pidlock);	/* lock the process queue against updates */
	for (p = practive; p != NULL; p = p->p_next) {
		cred_t	*cr;

		mutex_enter(&p->p_lock);	/* so process doesn't go away */
		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			mutex_exit(&p->p_lock);
			crfree(cr);
			continue;
		}

		if (ainfo->ai_auid == STRUCT_FGET(user_info, ai_auid)) {
			au_mask_t	mask;
			int		err;

			/*
			 * Here's a process which matches the specified auid.
			 * If its mask doesn't already match the new mask,
			 * save the new mask in the pad, to be picked up
			 * next syscall.
			 */
			mask = STRUCT_FGET(user_info, ai_mask);
			err = bcmp(&mask, &ainfo->ai_mask, sizeof (au_mask_t));
			crfree(cr);
			if (err != 0) {
				struct p_audit_data *pad = P2A(p);
				ASSERT(pad != NULL);

				mutex_enter(&(pad->pad_lock));
				pad->pad_flags |= PAD_SETMASK;
				pad->pad_newmask = mask;
				mutex_exit(&(pad->pad_lock));

				/*
				 * No need to call set_proc_pre_sys(), since
				 * t_pre_sys is ALWAYS on when audit is
				 * enabled...due to syscall auditing.
				 */
			}
		} else {
			crfree(cr);
		}
		mutex_exit(&p->p_lock);
	}
	mutex_exit(&pidlock);

	return (0);
}

static int
setsmask(caddr_t data)
{
	STRUCT_DECL(auditinfo, user_info);
	struct proc *p;
	const auditinfo_addr_t	*ainfo;
	model_t	model;

	model = get_udatamodel();
	STRUCT_INIT(user_info, model);

	if (copyin(data, STRUCT_BUF(user_info), STRUCT_SIZE(user_info)))
		return (EFAULT);

	mutex_enter(&pidlock);	/* lock the process queue against updates */
	for (p = practive; p != NULL; p = p->p_next) {
		cred_t	*cr;

		mutex_enter(&p->p_lock);	/* so process doesn't go away */
		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			mutex_exit(&p->p_lock);
			crfree(cr);
			continue;
		}

		if (ainfo->ai_asid == STRUCT_FGET(user_info, ai_asid)) {
			au_mask_t	mask;
			int		err;

			/*
			 * Here's a process which matches the specified asid.
			 * If its mask doesn't already match the new mask,
			 * save the new mask in the pad, to be picked up
			 * next syscall.
			 */
			mask = STRUCT_FGET(user_info, ai_mask);
			err = bcmp(&mask, &ainfo->ai_mask, sizeof (au_mask_t));
			crfree(cr);
			if (err != 0) {
				struct p_audit_data *pad = P2A(p);
				ASSERT(pad != NULL);

				mutex_enter(&(pad->pad_lock));
				pad->pad_flags |= PAD_SETMASK;
				pad->pad_newmask = mask;
				mutex_exit(&(pad->pad_lock));

				/*
				 * No need to call set_proc_pre_sys(), since
				 * t_pre_sys is ALWAYS on when audit is
				 * enabled...due to syscall auditing.
				 */
			}
		} else {
			crfree(cr);
		}
		mutex_exit(&p->p_lock);
	}
	mutex_exit(&pidlock);

	return (0);
}

/*
 * Get the current audit state of the system
 */
static int
getcond(caddr_t data)
{
	au_kcontext_t	*kctx;

	if (au_auditstate == AUC_DISABLED)
		if (copyout(&au_auditstate, data, sizeof (int)))
			return (EFAULT);

	kctx = GET_KCTX_PZ;

	if (copyout(&(kctx->auk_auditstate), data, sizeof (int)))
		return (EFAULT);

	return (0);
}

/*
 * Set the current audit state of the system to on (AUC_AUDITING) or
 * off (AUC_NOAUDIT).
 */
/* ARGSUSED */
static int
setcond(caddr_t data)
{
	int	auditstate;
	au_kcontext_t	*kctx;

	if (!(audit_policy & AUDIT_PERZONE) && (!INGLOBALZONE(curproc)))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	if (copyin(data, &auditstate, sizeof (int)))
		return (EFAULT);

	switch (auditstate) {
	case AUC_AUDITING:		/* Turn auditing on */
		kctx->auk_auditstate = AUC_AUDITING;
		au_auditstate = AUC_ENABLED;
		break;

	case AUC_NOAUDIT:		/* Turn auditing off */
		if (kctx->auk_auditstate == AUC_NOAUDIT)
			break;
		kctx->auk_auditstate = AUC_NOAUDIT;

		/* clear out the audit queue */

		mutex_enter(&(kctx->auk_queue.lock));
		if (kctx->auk_queue.wt_block)
			cv_broadcast(&(kctx->auk_queue.write_cv));

		/* unblock au_output_thread */
		cv_broadcast(&(kctx->auk_queue.read_cv));

		mutex_exit(&(kctx->auk_queue.lock));
		break;

	default:
		return (EINVAL);
	}

	return (0);
}

static int
getclass(caddr_t data)
{
	au_evclass_map_t event;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	if (copyin(data, &event, sizeof (au_evclass_map_t)))
		return (EFAULT);

	if (event.ec_number < 0 || event.ec_number > (au_naevent - 1))
		return (EINVAL);

	event.ec_class = kctx->auk_ets[event.ec_number];

	if (copyout(&event, data, sizeof (au_evclass_map_t)))
		return (EFAULT);

	return (0);
}

static int
setclass(caddr_t data)
{
	au_evclass_map_t event;
	au_kcontext_t	*kctx;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	if (copyin(data, &event, sizeof (au_evclass_map_t)))
		return (EFAULT);

	if (event.ec_number < 0 || event.ec_number > (au_naevent - 1))
		return (EINVAL);

	kctx->auk_ets[event.ec_number] = event.ec_class;

	return (0);
}

static int
getpinfo(caddr_t data)
{
	STRUCT_DECL(auditpinfo, apinfo);
	proc_t *proc;
	const auditinfo_addr_t	*ainfo;
	model_t	model;
	cred_t	*cr, *newcred;

	model = get_udatamodel();
	STRUCT_INIT(apinfo, model);

	if (copyin(data, STRUCT_BUF(apinfo), STRUCT_SIZE(apinfo)))
		return (EFAULT);

	newcred = cralloc();

	mutex_enter(&pidlock);
	if ((proc = prfind(STRUCT_FGET(apinfo, ap_pid))) == NULL) {
		mutex_exit(&pidlock);
		crfree(newcred);
		return (ESRCH);		/* no such process */
	}
	mutex_enter(&proc->p_lock);	/* so process doesn't go away */
	mutex_exit(&pidlock);

	audit_update_context(proc, newcred);	/* make sure it's up-to-date */

	mutex_enter(&proc->p_crlock);
	crhold(cr = proc->p_cred);
	mutex_exit(&proc->p_crlock);
	mutex_exit(&proc->p_lock);

	ainfo = crgetauinfo(cr);
	if (ainfo == NULL) {
		crfree(cr);
		return (EINVAL);
	}

	/* designated process has an ipv6 address? */
	if (ainfo->ai_termid.at_type == AU_IPv6) {
		crfree(cr);
		return (EOVERFLOW);
	}

	STRUCT_FSET(apinfo, ap_auid, ainfo->ai_auid);
	STRUCT_FSET(apinfo, ap_asid, ainfo->ai_asid);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, ainfo->ai_termid.at_port) == 0) {
			crfree(cr);
			return (EOVERFLOW);
		}
		STRUCT_FSET(apinfo, ap_termid.port, dev);
	} else
		STRUCT_FSET(apinfo, ap_termid.port, ainfo->ai_termid.at_port);
#else
	STRUCT_FSET(apinfo, ap_termid.port, ainfo->ai_termid.at_port);
#endif
	STRUCT_FSET(apinfo, ap_termid.machine, ainfo->ai_termid.at_addr[0]);
	STRUCT_FSET(apinfo, ap_mask, ainfo->ai_mask);

	crfree(cr);

	if (copyout(STRUCT_BUF(apinfo), data, STRUCT_SIZE(apinfo)))
		return (EFAULT);

	return (0);
}

static int
getpinfo_addr(caddr_t data, int len)
{
	STRUCT_DECL(auditpinfo_addr, apinfo);
	proc_t *proc;
	const auditinfo_addr_t	*ainfo;
	model_t	model;
	cred_t	*cr, *newcred;

	model = get_udatamodel();
	STRUCT_INIT(apinfo, model);

	if (len < STRUCT_SIZE(apinfo))
		return (EOVERFLOW);

	if (copyin(data, STRUCT_BUF(apinfo), STRUCT_SIZE(apinfo)))
		return (EFAULT);

	newcred = cralloc();

	mutex_enter(&pidlock);
	if ((proc = prfind(STRUCT_FGET(apinfo, ap_pid))) == NULL) {
		mutex_exit(&pidlock);
		crfree(newcred);
		return (ESRCH);
	}
	mutex_enter(&proc->p_lock);	/* so process doesn't go away */
	mutex_exit(&pidlock);

	audit_update_context(proc, newcred);	/* make sure it's up-to-date */

	mutex_enter(&proc->p_crlock);
	crhold(cr = proc->p_cred);
	mutex_exit(&proc->p_crlock);
	mutex_exit(&proc->p_lock);

	ainfo = crgetauinfo(cr);
	if (ainfo == NULL) {
		crfree(cr);
		return (EINVAL);
	}

	STRUCT_FSET(apinfo, ap_auid, ainfo->ai_auid);
	STRUCT_FSET(apinfo, ap_asid, ainfo->ai_asid);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, ainfo->ai_termid.at_port) == 0) {
			crfree(cr);
			return (EOVERFLOW);
		}
		STRUCT_FSET(apinfo, ap_termid.at_port, dev);
	} else
		STRUCT_FSET(apinfo, ap_termid.at_port,
		    ainfo->ai_termid.at_port);
#else
	STRUCT_FSET(apinfo, ap_termid.at_port, ainfo->ai_termid.at_port);
#endif
	STRUCT_FSET(apinfo, ap_termid.at_type, ainfo->ai_termid.at_type);
	STRUCT_FSET(apinfo, ap_termid.at_addr[0], ainfo->ai_termid.at_addr[0]);
	STRUCT_FSET(apinfo, ap_termid.at_addr[1], ainfo->ai_termid.at_addr[1]);
	STRUCT_FSET(apinfo, ap_termid.at_addr[2], ainfo->ai_termid.at_addr[2]);
	STRUCT_FSET(apinfo, ap_termid.at_addr[3], ainfo->ai_termid.at_addr[3]);
	STRUCT_FSET(apinfo, ap_mask, ainfo->ai_mask);

	crfree(cr);

	if (copyout(STRUCT_BUF(apinfo), data, STRUCT_SIZE(apinfo)))
		return (EFAULT);

	return (0);
}

static int
setpmask(caddr_t data)
{
	STRUCT_DECL(auditpinfo, apinfo);
	proc_t *proc;
	cred_t	*newcred;
	auditinfo_addr_t	*ainfo;
	struct p_audit_data	*pad;

	model_t	model;

	model = get_udatamodel();
	STRUCT_INIT(apinfo, model);

	if (copyin(data, STRUCT_BUF(apinfo), STRUCT_SIZE(apinfo)))
		return (EFAULT);

	mutex_enter(&pidlock);
	if ((proc = prfind(STRUCT_FGET(apinfo, ap_pid))) == NULL) {
		mutex_exit(&pidlock);
		return (ESRCH);
	}
	mutex_enter(&proc->p_lock);	/* so process doesn't go away */
	mutex_exit(&pidlock);

	newcred = cralloc();
	if ((ainfo = crgetauinfo_modifiable(newcred)) == NULL) {
		mutex_exit(&proc->p_lock);
		crfree(newcred);
		return (EINVAL);
	}

	mutex_enter(&proc->p_crlock);
	crcopy_to(proc->p_cred, newcred);
	proc->p_cred = newcred;

	ainfo->ai_mask = STRUCT_FGET(apinfo, ap_mask);

	/*
	 * Unlock. No need to broadcast changes via set_proc_pre_sys(),
	 * since t_pre_sys is ALWAYS on when audit is enabled... due to
	 * syscall auditing.
	 */
	crfree(newcred);
	mutex_exit(&proc->p_crlock);

	/* Reset flag for any previous pending mask change; this supercedes */
	pad = P2A(proc);
	ASSERT(pad != NULL);
	mutex_enter(&(pad->pad_lock));
	pad->pad_flags &= ~PAD_SETMASK;
	mutex_exit(&(pad->pad_lock));

	mutex_exit(&proc->p_lock);

	return (0);
}

static int
getfsize(caddr_t data)
{
	au_fstat_t fstat;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	mutex_enter(&(kctx->auk_fstat_lock));
	fstat.af_filesz = kctx->auk_file_stat.af_filesz;
	fstat.af_currsz = kctx->auk_file_stat.af_currsz;
	mutex_exit(&(kctx->auk_fstat_lock));

	if (copyout(&fstat, data, sizeof (au_fstat_t)))
		return (EFAULT);

	return (0);
}

static int
setfsize(caddr_t data)
{
	au_fstat_t fstat;
	au_kcontext_t	*kctx;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	if (copyin(data, &fstat, sizeof (au_fstat_t)))
		return (EFAULT);

	if ((fstat.af_filesz != 0) && (fstat.af_filesz < AU_MIN_FILE_SZ))
		return (EINVAL);

	mutex_enter(&(kctx->auk_fstat_lock));
	kctx->auk_file_stat.af_filesz = fstat.af_filesz;
	mutex_exit(&(kctx->auk_fstat_lock));

	return (0);
}
/*
 * The out of control system call
 * This is audit kitchen sink aka auditadm, aka auditon
 */
static int
auditctl(
	int	cmd,
	caddr_t data,
	int	length)
{
	int result;

	if (!audit_active)
		return (EINVAL);

	switch (cmd) {
	case A_GETCOND:
	case A_GETCAR:
	case A_GETCLASS:
	case A_GETCWD:
	case A_GETFSIZE:
	case A_GETKAUDIT:
	case A_GETKMASK:
	case A_GETPINFO:
	case A_GETPINFO_ADDR:
	case A_GETPOLICY:
	case A_GETQCTRL:
	case A_GETSTAT:
		if (secpolicy_audit_getattr(CRED()) != 0)
			return (EPERM);
		break;
	default:
		if (secpolicy_audit_config(CRED()) != 0)
			return (EPERM);
		break;
	}

	switch (cmd) {
	case A_GETPOLICY:
		result = getpolicy(data);
		break;
	case A_SETPOLICY:
		result = setpolicy(data);
		break;
	case A_GETKMASK:
		result = getkmask(data);
		break;
	case A_SETKMASK:
		result = setkmask(data);
		break;
	case A_GETKAUDIT:
		result = getkaudit(data, length);
		break;
	case A_SETKAUDIT:
		result = setkaudit(data, length);
		break;
	case A_GETQCTRL:
		result = getqctrl(data);
		break;
	case A_SETQCTRL:
		result = setqctrl(data);
		break;
	case A_GETCWD:
		result = getcwd(data, length);
		break;
	case A_GETCAR:
		result = getcar(data, length);
		break;
	case A_GETSTAT:
		result = getstat(data);
		break;
	case A_SETSTAT:
		result = setstat(data);
		break;
	case A_SETUMASK:
		result = setumask(data);
		break;
	case A_SETSMASK:
		result = setsmask(data);
		break;
	case A_GETCOND:
		result = getcond(data);
		break;
	case A_SETCOND:
		result = setcond(data);
		break;
	case A_GETCLASS:
		result = getclass(data);
		break;
	case A_SETCLASS:
		result = setclass(data);
		break;
	case A_GETPINFO:
		result = getpinfo(data);
		break;
	case A_GETPINFO_ADDR:
		result = getpinfo_addr(data, length);
		break;
	case A_SETPMASK:
		result = setpmask(data);
		break;
	case A_SETFSIZE:
		result = setfsize(data);
		break;
	case A_GETFSIZE:
		result = getfsize(data);
		break;
	default:
		result = EINVAL;
		break;
	}
	return (result);
}

static int
audit_modsysent(char *modname, int flags, int (*func)())
{
	struct sysent *sysp;
	int sysnum;
	krwlock_t *kl;

	if ((sysnum = mod_getsysnum(modname)) == -1) {
		cmn_err(CE_WARN, "system call missing from bind file");
		return (-1);
	}

	kl = (krwlock_t *)kobj_zalloc(sizeof (krwlock_t), KM_SLEEP);

	sysp = &sysent[sysnum];
	sysp->sy_narg = auditsysent.sy_narg;
#ifdef _LP64
	sysp->sy_flags = (unsigned short)flags;
#else
	sysp->sy_flags = (unsigned char)flags;
#endif
	sysp->sy_call = func;
	sysp->sy_lock = kl;

#ifdef _SYSCALL32_IMPL
	sysp = &sysent32[sysnum];
	sysp->sy_narg = auditsysent.sy_narg;
	sysp->sy_flags = (unsigned short)flags;
	sysp->sy_call = func;
	sysp->sy_lock = kl;
#endif

	rw_init(sysp->sy_lock, NULL, RW_DEFAULT, NULL);

	return (0);
}
