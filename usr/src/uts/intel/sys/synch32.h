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

#ifndef _SYS_SYNCH32_H
#define	_SYS_SYNCH32_H

#ifdef	__cplusplus
extern "C" {
#endif

/* special defines for LWP mutexes */
#define	mutex_flag		flags.flag1
#define	mutex_ceiling		flags.ceiling
#define	mutex_type		flags.mbcp_type_un.mtype_rcount.count_type1
#define	mutex_rcount		flags.mbcp_type_un.mtype_rcount.count_type2
#define	mutex_magic		flags.magic
#define	mutex_owner		data
/* used to atomically operate on whole word via cas or swap instruction */
#define	mutex_lockword		lock.lock32.lockword
/* this requires atomic_cas_64 */
#define	mutex_lockword64	lock.owner64
/* these are bytes */
#define	mutex_lockw		lock.lock64.pad[7]
#define	mutex_waiters		lock.lock64.pad[6]
#define	mutex_spinners		lock.lock64.pad[5]

/* process-shared lock owner pid */
#define	mutex_ownerpid		lock.lock32.ownerpid

/* Max. recusrion count for recursive mutexes */
#define	RECURSION_MAX		255

/* special defines for LWP condition variables */
#define	cond_type		flags.type
#define	cond_magic		flags.magic
#define	cond_clockid		flags.flag[1]
#define	cond_waiters_user	flags.flag[2]
#define	cond_waiters_kernel	flags.flag[3]

/* special defines for LWP semaphores */
#define	sema_count		count
#define	sema_type		type
#define	sema_waiters		flags[7]

/* special defines for LWP rwlocks */
#define	rwlock_readers		readers
#define	rwlock_type		type
#define	rwlock_magic		magic
#define	rwlock_owner		readercv.data
#define	rwlock_ownerpid		writercv.data

#define	URW_HAS_WAITERS		0x80000000
#define	URW_WRITE_LOCKED	0x40000000
#define	URW_READERS_MASK	0x3fffffff

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SYNCH32_H */
