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

#ifndef	_SIP_HASH_H
#define	_SIP_HASH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <pthread.h>

/* A prime number */
#define	SIP_HASH_SZ	6037

#define	SIP_DIGEST_TO_HASH(digest)					\
	((digest[0] + digest[1] + digest[2] + digest[3] + digest[4] +	\
	digest[5] + digest[6] + digest[7]) % SIP_HASH_SZ)

/* An entry in the hash table, sip_obj is opaque */
typedef struct	sip_hash_obj_s {
	void			*sip_obj;
	struct sip_hash_obj_s	*next_obj;
	struct sip_hash_obj_s	*prev_obj;
} sip_hash_obj_t;


/* A hash list in the table */
typedef struct sip_hash_s {
	sip_hash_obj_t	*hash_head;
	sip_hash_obj_t	*hash_tail;
	int		hash_count;
	pthread_mutex_t sip_hash_mutex;
}sip_hash_t;

int	sip_hash_add(sip_hash_t	*, void *, int);
void	*sip_hash_find(sip_hash_t *, void *, int,
	    boolean_t (*)(void *, void *));
void	sip_walk_hash(sip_hash_t *, void (*)(void *, void *), void *);
void	sip_hash_delete(sip_hash_t *, void *, int,
	    boolean_t (*)(void *, void *, int *));
void	sip_hash_init();

#ifdef	__cplusplus
}
#endif

#endif	/* _SIP_HASH_H */
