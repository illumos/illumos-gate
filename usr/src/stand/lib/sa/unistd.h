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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SA_UNISTD_H
#define	_SA_UNISTD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Exported interfaces for standalone's subset of libc's <unistd.h>.
 * All standalone code *must* use this header rather than libc's.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NOTE: Some of these are duplicated from <sys/bootvfs.h>; we do this
 *	 rather than just #including it to avoid polluting the namespace.
 */
extern int	open(const char *, int);
extern int	close(int);
extern off_t	lseek(int, off_t, int);
extern ssize_t	read(int, void *, size_t);
extern pid_t	getpid(void);
extern int	gethostname(char *, int);
extern int	sethostname(char *, int);
extern unsigned int sleep(unsigned int);

#ifdef __cplusplus
}
#endif

#endif /* _SA_UNISTD_H */
