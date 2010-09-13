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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SACACHE_H
#define	_SYS_SACACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/filep.h>
#include <sys/dirent.h>

/*
 * there are common cache interface routines
 */

extern	void	*get_icache(int dev, int inum);
extern	void	set_icache(int dev, int inum, void *buf, int len);
extern	int	set_ricache(int dev, int inum, void *buf, int len);
extern	int	get_dcache(int dev, char *name, int pnum);
extern	void	set_dcache(int dev, char *name, int pnum, int inum);
extern	int	set_rdcache(int dev, char *name, int pnum, int inum);
extern  caddr_t	get_bcache(fileid_t *fp);
extern  int	set_bcache(fileid_t *fp);
extern	void	release_cache(int dev);
extern	void	print_cache_data(void);

extern	int	read_opt;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SACACHE_H */
