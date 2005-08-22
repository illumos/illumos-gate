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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <signal.h>
#include <libintl.h>
#include <dirent.h>
#include <sys/cpc_impl.h>

#include "libcpc.h"
#include "libcpc_impl.h"

/*
 * CPC library handle for use by CPCv1 implementation.
 */
cpc_t *__cpc = NULL;
mutex_t __cpc_lock;		/* protects __cpc handle */
int __cpc_v1_cpuver;		/* CPU version in use by CPCv1 client */

#ifdef __sparc
uint64_t __cpc_v1_pcr;		/* last bound %pcr value */
#else
uint32_t __cpc_v1_pes[2];	/* last bound %pes values */
#endif /* __sparc */

int
__cpc_init(void)
{
	const char *fn = "__cpc_init";
	extern cpc_t *__cpc;	/* CPC handle for obsolete clients to share */

	(void) mutex_lock(&__cpc_lock);
	if (__cpc == NULL && (__cpc = cpc_open(CPC_VER_CURRENT)) == NULL) {
		__cpc_error(fn, dgettext(TEXT_DOMAIN,
		    "Couldn't open CPC library handle\n"));
		(void) mutex_unlock(&__cpc_lock);
		return (-1);
	}
	(void) mutex_unlock(&__cpc_lock);

	return (0);
}

int
cpc_bind_event(cpc_event_t *this, int flags)
{
	cpc_set_t		*set;
	cpc_request_t		*rp;
	int			ret;

	if (this == NULL) {
		(void) cpc_rele();
		return (0);
	}

	if (__cpc_init() != 0) {
		errno = ENXIO;
		return (-1);
	}

	/*
	 * The cpuver and control fields of the cpc_event_t must be saved off
	 * for later. The user may call cpc_take_sample(), expecting these to
	 * be copied into a different cpc_event_t struct by the kernel. We have
	 * to fake that behavior for CPCv1 clients.
	 */
	__cpc_v1_cpuver = this->ce_cpuver;
#ifdef __sparc
	__cpc_v1_pcr = this->ce_pcr;
#else
	__cpc_v1_pes[0] = this->ce_pes[0];
	__cpc_v1_pes[1] = this->ce_pes[1];
#endif /* __sparc */

	if ((set = __cpc_eventtoset(__cpc, this, flags)) == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Convert flags to CPC2.
	 */
	if (flags & CPC_BIND_EMT_OVF) {
		for (rp = set->cs_request; rp != NULL; rp = rp->cr_next)
			rp->cr_flags |= CPC_OVF_NOTIFY_EMT;
		flags &= ~CPC_BIND_EMT_OVF;
	}

	ret = cpc_bind_curlwp(__cpc, set, flags);

	(void) cpc_set_destroy(__cpc, set);

	return (ret);
}

int
cpc_take_sample(cpc_event_t *this)
{
	this->ce_cpuver = __cpc_v1_cpuver;
#ifdef __sparc
	this->ce_pcr = __cpc_v1_pcr;
#else
	this->ce_pes[0] = __cpc_v1_pes[0];
	this->ce_pes[1] = __cpc_v1_pes[1];
#endif /* __sparc */

	return (syscall(SYS_cpc, CPC_SAMPLE, -1, this->ce_pic, &this->ce_hrt,
	    &CPC_TICKREG(this), 0));
}

int
cpc_count_usr_events(int enable)
{
	return (syscall(SYS_cpc, CPC_USR_EVENTS, -1, enable, 0));
}

int
cpc_count_sys_events(int enable)
{
	return (syscall(SYS_cpc, CPC_SYS_EVENTS, -1, enable, 0));
}

int
cpc_rele(void)
{
	return (syscall(SYS_cpc, CPC_RELE, -1, NULL, 0));
}

/*
 * See if the system call is working and installed.
 *
 * We invoke the system call with nonsense arguments - if it's
 * there and working correctly, it will return EINVAL.
 *
 * (This avoids the user getting a SIGSYS core dump when they attempt
 * to bind on older hardware)
 */
int
cpc_access(void)
{
	void (*handler)(int);
	int error = 0;
	const char fn[] = "access";

	handler = signal(SIGSYS, SIG_IGN);
	if (syscall(SYS_cpc, -1, -1, NULL, 0) == -1 &&
	    errno != EINVAL)
		error = errno;
	(void) signal(SIGSYS, handler);

	switch (error) {
	case EAGAIN:
		__cpc_error(fn, dgettext(TEXT_DOMAIN, "Another process may be "
		    "sampling system-wide CPU statistics\n"));
		break;
	case ENOSYS:
		__cpc_error(fn,
		    dgettext(TEXT_DOMAIN, "CPU performance counters "
		    "are inaccessible on this machine\n"));
		break;
	default:
		__cpc_error(fn, "%s\n", strerror(errno));
		break;
	case 0:
		return (0);
	}

	errno = error;
	return (-1);
}

/*
 * To look at the system-wide counters, we have to open the
 * 'shared' device.  Once that device is open, no further contexts
 * can be installed (though one open is needed per CPU)
 */
int
cpc_shared_open(void)
{
	const char driver[] = CPUDRV_SHARED;

	return (open(driver, O_RDWR));
}

void
cpc_shared_close(int fd)
{
	(void) cpc_shared_rele(fd);
	(void) close(fd);
}

int
cpc_shared_bind_event(int fd, cpc_event_t *this, int flags)
{
	extern cpc_t		*__cpc;
	cpc_set_t		*set;
	int			ret;
	char			*packed_set;
	size_t			packsize;
	int			subcode;
	__cpc_args_t		cpc_args;

	if (this == NULL) {
		(void) cpc_shared_rele(fd);
		return (0);
	} else if (flags != 0) {
		errno = EINVAL;
		return (-1);
	}

	if (__cpc_init() != 0) {
		errno = ENXIO;
		return (-1);
	}

	if ((set = __cpc_eventtoset(__cpc, this, flags)) == NULL) {
		errno = EINVAL;
		return (-1);
	}

	__cpc_v1_cpuver = this->ce_cpuver;

	if ((packed_set = __cpc_pack_set(set, flags, &packsize)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	cpc_args.udata1 = packed_set;
	cpc_args.udata2 = (void *)packsize;
	cpc_args.udata3 = (void *)&subcode;

	ret = ioctl(fd, CPCIO_BIND, &cpc_args);

	free(packed_set);
	(void) cpc_set_destroy(__cpc, set);

	return (ret);
}

int
cpc_shared_take_sample(int fd, cpc_event_t *this)
{
	__cpc_args_t args;

	args.udata1 = this->ce_pic;
	args.udata2 = &this->ce_hrt;
	args.udata3 = &CPC_TICKREG(this);

	this->ce_cpuver = __cpc_v1_cpuver;

	return (ioctl(fd, CPCIO_SAMPLE, &args));
}

int
cpc_shared_rele(int fd)
{
	return (ioctl(fd, CPCIO_RELE, 0));
}

int
cpc_pctx_bind_event(pctx_t *pctx, id_t lwpid, cpc_event_t *event, int flags)
{
	cpc_set_t		*set;
	int			ret;

	if (event == NULL)
		return (cpc_pctx_rele(pctx, lwpid));

	if (__cpc_init() != 0) {
		errno = ENXIO;
		return (-1);
	}

	else if (flags != 0) {
		errno = EINVAL;
		return (-1);
	}

	if ((set = __cpc_eventtoset(__cpc, event, flags)) == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * The cpuver and control fields of the cpc_event_t must be saved off
	 * for later. The user may call cpc_take_sample(), expecting these to
	 * be copied into a different cpc_event_t struct by the kernel. We have
	 * to fake that behavior for CPCv1 clients.
	 */
	__cpc_v1_cpuver = event->ce_cpuver;

	ret = cpc_bind_pctx(__cpc, pctx, lwpid, set, 0);

	(void) cpc_set_destroy(__cpc, set);

	return (ret);
}

int
cpc_pctx_take_sample(pctx_t *pctx, id_t lwpid, cpc_event_t *event)
{
	event->ce_cpuver = __cpc_v1_cpuver;

	return (__pctx_cpc(pctx, __cpc, CPC_SAMPLE, lwpid, event->ce_pic,
	    &event->ce_hrt, &CPC_TICKREG(event), CPC1_BUFSIZE));
}

/*
 * Given a process context and an lwpid, mark the CPU performance
 * counter context as invalid.
 */
int
cpc_pctx_invalidate(pctx_t *pctx, id_t lwpid)
{
	return (__pctx_cpc(pctx, __cpc, CPC_INVALIDATE, lwpid, 0, 0, 0, 0));
}

/*
 * Given a process context and an lwpid, remove all our
 * hardware context from it.
 */
int
cpc_pctx_rele(pctx_t *pctx, id_t lwpid)
{
	return (__pctx_cpc(pctx, __cpc, CPC_RELE, lwpid, 0, 0, 0, 0));
}

static cpc_errfn_t *__cpc_uerrfn;

/*PRINTFLIKE2*/
void
__cpc_error(const char *fn, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (__cpc_uerrfn)
		__cpc_uerrfn(fn, fmt, ap);
	else {
		(void) fprintf(stderr, "libcpc: %s: ", fn);
		(void) vfprintf(stderr, fmt, ap);
	}
	va_end(ap);
}

void
cpc_seterrfn(cpc_errfn_t *errfn)
{
	__cpc_uerrfn = errfn;
}

/*
 * cpc_version() is only for CPC1 clients.
 */
uint_t __cpc_workver = CPC_VER_1;

uint_t
cpc_version(uint_t ver)
{
	__cpc_workver = CPC_VER_1;

	switch (ver) {
	case CPC_VER_NONE:
	case CPC_VER_CURRENT:
		return (CPC_VER_CURRENT);
	case CPC_VER_1:
		/*
		 * As long as the client is using cpc_version() at all, it is
		 * a CPCv1 client.  We still allow CPCv1 clients to compile on
		 * CPCv2 systems.
		 */
		return (CPC_VER_1);
	}

	return (CPC_VER_NONE);
}
