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

#ifndef	_ISNS_ESI_H
#define	_ISNS_ESI_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	EV_ESI = 1,
	EV_REG_EXP
} ev_type_t;

#define	EV_FLAG_INIT	(0x01)
#define	EV_FLAG_AGAIN	(0x02)
#define	EV_FLAG_WAKEUP	(0x04)
#define	EV_FLAG_REMOVE	(0x08)
#define	EV_FLAG_REM_P1	(0x10)
#define	EV_FLAG_REM_P2	(0x20)
#define	EV_FLAG_REM_P3	(0x40)
#define	EV_FLAG_REM_P4	(0x80)

#define	EV_FLAG_REM_P	(0xF0)

typedef struct esi_portal {
	int sz;
	in_addr_t ip4;
	in6_addr_t *ip6;
	uint32_t port;
	uint32_t esip;
	uint32_t ref;
	int so;
	struct esi_portal *next;
} esi_portal_t;

typedef struct ev {
	ev_type_t type;
	uint32_t uid;
	uint32_t intval;
	int flags;
	uchar_t *eid;
	uint32_t eid_len;
	esi_portal_t *portal;
	pthread_mutex_t mtx;
	struct ev *next;
} ev_t;

/* function prototypes */
int esi_load(uint32_t, uchar_t *, uint32_t);
int esi_add(uint32_t, uchar_t *, uint32_t);
int esi_remove(uint32_t);
int esi_remove_obj(const isns_obj_t *, int);
int verify_esi_portal();
uint32_t get_stopwatch(int);
uint32_t ev_intval(void *);
int ev_match(void *, uint32_t);
int ev_remove(void *, uint32_t, int, int);
void ev_free(void *);
int evf_init(void *);
int evf_again(void *);
int evf_wakeup(void *);
int evf_rem(void *);
int evf_rem_pending(void *);
void evf_zero(void *);

void evl_append(void *);
void evl_strip(void *);
int evl_remove(uint32_t, uint32_t, int);

void *esi_proc(void *);

void portal_dies(uint32_t);
void reg_expiring(void *);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_ESI_H */
