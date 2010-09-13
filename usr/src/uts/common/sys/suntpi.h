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
 * Copyright (c) 1990-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SUNTPI_H
#define	_SYS_SUNTPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * Persistent information about the capabilities of transport providers.
 * This structure is for the internal use of sockfs and timod.  Because
 * bitfield operations are not atomic, the lock must be used to avoid
 * inconsistencies.
 */
typedef struct tpi_provinfo {
	struct tpi_provinfo	*tpi_next;
	void			*tpi_key;
	size_t			tpi_keylen;
	kmutex_t		tpi_lock;
	uint32_t		tpi_capability : 2,
				tpi_myname : 2,
				tpi_peername : 2,
				_tpi_unused : 26;
} tpi_provinfo_t;

/*
 * Possible values for the above 2-bitfields.  A capability is either
 * supported, unsupported or unknown.
 */
#define	PI_DONTKNOW	0
#define	PI_NO		1
#define	PI_YES		2

extern void		tpi_init(void);
extern tpi_provinfo_t	*tpi_findprov(queue_t *);

#define	PI_PROVLOCK(tp)		mutex_enter(&(tp)->tpi_lock)
#define	PI_PROVUNLOCK(tp)	mutex_exit(&(tp)->tpi_lock)

extern mblk_t	*tpi_ack_alloc(mblk_t *, size_t, uchar_t, t_scalar_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SUNTPI_H */
