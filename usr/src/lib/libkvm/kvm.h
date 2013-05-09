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
 * Copyright (c) 1987-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#ifndef	_KVM_H
#define	_KVM_H

#include <sys/types.h>
#include <nlist.h>
#include <sys/user.h>
#include <sys/proc.h>


#ifdef __cplusplus
extern "C" {
#endif

/* define a 'cookie' to pass around between user code and the library */
typedef struct _kvmd kvm_t;

/* libkvm routine definitions */

#ifdef __STDC__

extern kvm_t	*kvm_open(const char *, const char *, const char *,
		int, const char *);
extern int	kvm_close(kvm_t *);
extern int	kvm_nlist(kvm_t *, struct nlist []);
extern ssize_t	kvm_read(kvm_t *, uintptr_t, void *, size_t);
extern ssize_t	kvm_kread(kvm_t *, uintptr_t, void *, size_t);
extern ssize_t	kvm_uread(kvm_t *, uintptr_t, void *, size_t);
extern ssize_t	kvm_aread(kvm_t *, uintptr_t, void *, size_t, struct as *);
extern ssize_t	kvm_pread(kvm_t *, uint64_t, void *, size_t);
extern ssize_t	kvm_write(kvm_t *, uintptr_t, const void *, size_t);
extern ssize_t	kvm_kwrite(kvm_t *, uintptr_t, const void *, size_t);
extern ssize_t	kvm_uwrite(kvm_t *, uintptr_t, const void *, size_t);
extern ssize_t	kvm_awrite(kvm_t *, uintptr_t, const void *, size_t,
		struct as *);
extern ssize_t	kvm_pwrite(kvm_t *, uint64_t, const void *, size_t);
extern uint64_t	kvm_physaddr(kvm_t *, struct as *, uintptr_t);
extern proc_t	*kvm_getproc(kvm_t *, pid_t);
extern proc_t	*kvm_nextproc(kvm_t *);
extern int	kvm_setproc(kvm_t *);
extern user_t	*kvm_getu(kvm_t *, struct proc *);
extern int	kvm_getcmd(kvm_t *, proc_t *, user_t *, char ***, char ***);
extern const char *kvm_namelist(kvm_t *);

#else

extern kvm_t	*kvm_open();
extern int	kvm_close();
extern int	kvm_nlist();
extern ssize_t	kvm_read();
extern ssize_t	kvm_kread();
extern ssize_t	kvm_uread();
extern ssize_t	kvm_aread();
extern ssize_t	kvm_pread();
extern ssize_t	kvm_write();
extern ssize_t	kvm_kwrite();
extern ssize_t	kvm_uwrite();
extern ssize_t	kvm_awrite();
extern ssize_t	kvm_pwrite();
extern uint64_t	Kvm_physaddr();
extern proc_t	*kvm_getproc();
extern proc_t	*kvm_nextproc();
extern int	kvm_setproc();
extern user_t	*kvm_getu();
extern int	kvm_getcmd();

#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _KVM_H */
