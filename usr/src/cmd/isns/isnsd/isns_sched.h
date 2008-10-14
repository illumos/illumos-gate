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

#ifndef	_ISNS_SCHED_H
#define	_ISNS_SCHED_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct el_notice {
	uint32_t time;
	void *event;
	int isdummy;
	struct el_key *key;
	struct el_notice *pred;
	struct el_notice *sucd;
} el_notice_t;

typedef struct el_key {
	uint32_t time;
	int count;
	struct el_notice *notice;
	struct el_key *left;
	struct el_key *right;
} el_key_t;

/* function prototypes */
int el_init();
int el_add(void *, uint32_t, void **);
int el_remove(uint32_t, uint32_t, int);
void *el_first(uint32_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_SCHED_H */
