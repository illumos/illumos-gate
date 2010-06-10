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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SHAREFS_SHARETAB_H
#define	_SHAREFS_SHARETAB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This header defines the glue to keeping a sharetab in memory.
 * It is broken out from sharefs.h in the case that it will be
 * reused in userland.
 */

/*
 * Note:
 * Must include share/share.h before this header.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sh_list {		/* cached share list */
	struct sh_list	*shl_next;
	share_t		*shl_sh;
} sh_list_t;

typedef struct sharefs_hash_head {
	share_t		*ssh_sh;
	uint_t		ssh_count;
} sharefs_hash_head_t;

#define	SHARETAB_HASHES		256

typedef struct sharetab {
	sharefs_hash_head_t	s_buckets[SHARETAB_HASHES];
	char			*s_fstype;
	struct sharetab		*s_next;
	uint_t			s_count;
} sharetab_t;

#define	MOD2(a, pow_of_2)	(a) & ((pow_of_2) - 1)

/*
 * Pearson's string hash
 *
 * See: Communications of the ACM, June 1990 Vol 33 pp 677-680
 * http://www.acm.org/pubs/citations/journals/cacm/1990-33-6/p677-pearson
 */
#define	SHARETAB_HASH_IT(hash, path)					\
{									\
	uint_t		key = 0x12345678;	/* arbitrary value */	\
	int		i, len;						\
									\
	len = strlen((path));						\
									\
	(hash) = MOD2((key + len), SHARETAB_HASHES);			\
									\
	for (i = 0; i < len; i++) {					\
		(hash) = MOD2(((hash) + (path)[i]), SHARETAB_HASHES);	\
		(hash) = pkp_tab[(hash)];				\
	}								\
}

#ifdef __cplusplus
}
#endif

#endif /* !_SHAREFS_SHARETAB_H */
