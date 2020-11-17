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
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/proc.h>
#include <c2/audit.h>
#include <sys/procfs.h>
#include <sys/core.h>

/*
 * This function is meant to be a guaranteed abort that generates a core file
 * that allows up to 1k of data to enter into an elfnote in the process. This is
 * meant to insure that even in the face of other problems, this can get out.
 */

void
upanic(void *addr, size_t len)
{
	kthread_t *t = curthread;
	proc_t *p = curproc;
	klwp_t *lwp = ttolwp(t);
	uint32_t auditing = AU_AUDITING();
	uint32_t upflag = P_UPF_PANICKED;
	void *buf;
	int code;

	/*
	 * Before we worry about the data that the user has as a message, go
	 * ahead and make sure we try and get all the other threads stopped.
	 * That'll help us make sure that nothing else is going on and we don't
	 * lose a race.
	 */
	mutex_enter(&p->p_lock);
	lwp->lwp_cursig = SIGABRT;
	mutex_exit(&p->p_lock);

	proc_is_exiting(p);
	if (exitlwps(1) != 0) {
		mutex_enter(&p->p_lock);
		lwp_exit();
	}

	/*
	 * Copy in the user data. We truncate it to PRUPANIC_BUFLEN no matter
	 * what and ensure that the last data was set to zero.
	 */
	if (addr != NULL && len > 0) {
		size_t copylen;

		upflag |= P_UPF_HAVEMSG;

		if (len >= PRUPANIC_BUFLEN) {
			copylen = PRUPANIC_BUFLEN;
			upflag |= P_UPF_TRUNCMSG;
		} else {
			copylen = len;
		}

		buf = kmem_zalloc(PRUPANIC_BUFLEN, KM_SLEEP);
		if (copyin(addr, buf, copylen) != 0) {
			upflag |= P_UPF_INVALMSG;
			upflag &= ~P_UPF_HAVEMSG;
		} else {
			mutex_enter(&p->p_lock);
			ASSERT3P(p->p_upanic, ==, NULL);
			p->p_upanic = buf;
			mutex_exit(&p->p_lock);
		}
	}

	mutex_enter(&p->p_lock);
	p->p_upanicflag = upflag;
	mutex_exit(&p->p_lock);

	if (auditing)		/* audit core dump */
		audit_core_start(SIGABRT);
	code = core(SIGABRT, B_FALSE);
	if (auditing)		/* audit core dump */
		audit_core_finish(code ? CLD_KILLED : CLD_DUMPED);
	exit(code ? CLD_KILLED : CLD_DUMPED, SIGABRT);
}
