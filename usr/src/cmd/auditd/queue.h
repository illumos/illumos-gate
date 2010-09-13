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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#ifndef	_QUEUE_H
#define	_QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <stddef.h>

typedef struct aln audit_link_t;
struct aln {
	audit_link_t	*aln_next;
};

/* one audit_rec_t per audit record */

typedef struct abq audit_rec_t;
struct abq {
	audit_link_t	abq_l;
	int		abq_ref_count;
	size_t		abq_buf_len;	/* space allocated */
	size_t		abq_data_len;	/* space used	   */
	char		abq_buffer[1];	/* variable length */
};
#define	AUDIT_REC_HEADER  offsetof(audit_rec_t, abq_buffer[0])

/* one audit_q_t entry per audit record per plugin */

typedef struct aqq audit_q_t;		/* plugin queued data */
struct aqq {
	audit_link_t	aqq_l;
	audit_rec_t	*aqq_data;
	uint64_t	aqq_sequence;
};

/* queue head */

typedef struct auq au_queue_t;

struct auq {
	void		*auq_head;
	void		*auq_tail;
	int		auq_count;
	pthread_mutex_t	auq_lock;
};

int		audit_dequeue(au_queue_t *, void **);
void		audit_queue_destroy(au_queue_t *);
void		audit_enqueue(au_queue_t *, void *);
int		audit_queue_size(au_queue_t *);
void		audit_queue_init(au_queue_t *);
audit_rec_t	*audit_release(pthread_mutex_t *, audit_rec_t *);
void		audit_incr_ref(pthread_mutex_t *, audit_rec_t *);

#ifdef __cplusplus
}
#endif

#endif	/* _QUEUE_H */
