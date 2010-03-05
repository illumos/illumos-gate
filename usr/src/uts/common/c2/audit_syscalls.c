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

/*
 * This file contains the auditing system call code.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/session.h>	/* for session structure (auditctl(2) */
#include <sys/kmem.h>		/* for KM_SLEEP */
#include <sys/cred.h>
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

#define	HEADER_SIZE64	1;
#define	HEADER_SIZE32	0;
#define	AU_MIN_FILE_SZ	0x80000	/* minumum audit file size */
#define	AUDIT_REC_SIZE	0x8000	/* maximum user audit record size */

extern pri_t	minclsyspri;	/* priority for taskq */

static clock_t	au_resid = 15;	/* wait .15 sec before droping a rec */

static void	au_output_thread();

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "Solaris Auditing (C2)"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, 0
};

int
_init()
{
	return (mod_install(&modlinkage));
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
	uint32_t auditing;

	/* if auditing not enabled, then don't generate an audit record */
	auditing = (U2A(u)->tad_audit != AUC_UNSET) ?
	    U2A(u)->tad_audit : kctx->auk_auditstate;
	if (auditing & ~(AUC_AUDITING | AUC_INIT_AUDIT))
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

/*
 * auditdoor starts a kernel thread to generate output from the audit
 * queue.  The thread terminates when it detects auditing being turned
 * off, such as when auditd exits with a SIGTERM.  If a subsequent
 * auditdoor arrives while the thread is running, the door descriptor
 * of the last auditdoor in will be used for output.  auditd is responsible
 * for insuring that multiple copies are not running.
 */

int
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
