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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#ifndef _SYS_PRSYSTM_H
#define	_SYS_PRSYSTM_H

#include <sys/isa_defs.h>
#include <sys/zone.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

extern kmutex_t pr_pidlock;
extern kcondvar_t *pr_pid_cv;

struct prfpregset;
struct pstatus;
struct lwpstatus;
struct psinfo;
struct lwpsinfo;
struct prcred;
struct prpriv;

struct seg;
struct regs;
struct watched_page;

/*
 * These are functions in the procfs module that are
 * called from the kernel proper and from other modules.
 */
extern uint_t pr_getprot(struct seg *, int, void **,
	caddr_t *, caddr_t *, caddr_t);
extern void pr_getprot_done(void **);
extern size_t pr_getsegsize(struct seg *, int);
extern int  pr_isobject(struct vnode *);
extern int  pr_isself(struct vnode *);
extern void prinvalidate(struct user *);
extern void prgetstatus(proc_t *, struct pstatus *, zone_t *);
extern void prgetlwpstatus(kthread_t *, struct lwpstatus *, zone_t *);
extern void prgetpsinfo(proc_t *, struct psinfo *);
extern void prgetlwpsinfo(kthread_t *, struct lwpsinfo *);
extern void prgetprfpregs(klwp_t *, struct prfpregset *);
extern void prgetprxregs(klwp_t *, caddr_t);
extern int  prgetprxregsize(proc_t *);
#if defined(__lint)
/* Work around lint confusion between old and new prcred definitions */
extern void prgetcred();
#else
extern void prgetcred(proc_t *, struct prcred *);
#endif
extern void prgetpriv(proc_t *, struct prpriv *);
extern size_t prgetprivsize(void);
extern int  prnsegs(struct as *, int);
extern void prexit(proc_t *);
extern void prfree(proc_t *);
extern void prlwpexit(kthread_t *);
extern void prlwpfree(proc_t *, lwpent_t *);
extern void prexecstart(void);
extern void prexecend(void);
extern void prrelvm(void);
extern void prbarrier(proc_t *);
extern void prstop(int, int);
extern void prunstop(void);
extern void prnotify(struct vnode *);
extern void prstep(klwp_t *, int);
extern void prnostep(klwp_t *);
extern void prdostep(void);
extern int  prundostep(void);
extern int  prhasfp(void);
extern int  prhasx(proc_t *);
extern caddr_t prmapin(struct as *, caddr_t, int);
extern void prmapout(struct as *, caddr_t, caddr_t, int);
extern int  pr_watch_emul(struct regs *, caddr_t, enum seg_rw);
extern void pr_free_watched_pages(proc_t *);
extern int  pr_allstopped(proc_t *, int);
#if defined(__sparc)
struct gwindows;
extern	int	prnwindows(klwp_t *);
extern	void	prgetwindows(klwp_t *, struct gwindows *);
#if defined(__sparcv9) /* 32-bit adb macros should not see these defs */
extern	void	prgetasregs(klwp_t *, asrset_t);
extern	void	prsetasregs(klwp_t *, asrset_t);
#endif /* __sparcv9 */
#endif	/* __sparc */
#if defined(__x86)
struct	ssd;
extern	int	prnldt(proc_t *);
extern	void	prgetldt(proc_t *, struct ssd *);
#endif	/* __x86 */

#ifdef _SYSCALL32_IMPL
struct prfpregset32;
struct pstatus32;
struct lwpstatus32;
struct psinfo32;
struct lwpsinfo32;
extern void prgetstatus32(proc_t *, struct pstatus32 *, zone_t *);
extern void prgetlwpstatus32(kthread_t *, struct lwpstatus32 *, zone_t *);
extern void prgetpsinfo32(proc_t *, struct psinfo32 *);
extern void prgetlwpsinfo32(kthread_t *, struct lwpsinfo32 *);
extern void lwpsinfo_kto32(const struct lwpsinfo *src, struct lwpsinfo32 *dest);
extern void psinfo_kto32(const struct psinfo *src, struct psinfo32 *dest);
extern void prgetprfpregs32(klwp_t *, struct prfpregset32 *);
#if defined(__sparc)
struct gwindows32;
void		prgetwindows32(klwp_t *, struct gwindows32 *);
#endif /* __sparc */
#endif	/* _SYSCALL32_IMPL */

#endif	/* defined (_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PRSYSTM_H */
