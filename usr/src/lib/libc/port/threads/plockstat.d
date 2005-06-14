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

#include <synch.h>

provider plockstat {
	probe mutex__acquire(mutex_t *mp, int rec, int spincount);
	probe mutex__release(mutex_t *mp, int rec);
	probe mutex__spin(mutex_t *mp);
	probe mutex__spun(mutex_t *mp, int successful, int spincount);
	probe mutex__block(mutex_t *mp);
	probe mutex__blocked(mutex_t *mp, int successful);
	probe mutex__error(mutex_t *mp, int err);

	probe rw__acquire(rwlock_t *rwp, int wr);
	probe rw__release(rwlock_t *rwp, int wr);
	probe rw__block(rwlock_t *rwp, int wr);
	probe rw__blocked(rwlock_t *rwp, int wr, int successful);
	probe rw__error(rwlock_t *rwp, int wr, int err);
};

#pragma D attributes Evolving/Evolving/ISA provider plockstat provider
#pragma D attributes Private/Private/Unknown provider plockstat module
#pragma D attributes Private/Private/Unknown provider plockstat function
#pragma D attributes Evolving/Evolving/ISA provider plockstat name
#pragma D attributes Evolving/Evolving/ISA provider plockstat args

