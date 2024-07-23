/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _CLOCK_LOCK_H
#define	_CLOCK_LOCK_H

/*
 * Common definitions for the clock_lock test.
 */

#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lock_ops {
	void (*lo_create)(const char *, void **);
	void (*lo_destroy)(void *);
	void (*lo_lock)(void *);
	void (*lo_unlock)(void *);
} lock_ops_t;

typedef struct clock_test {
	const char *ct_desc;
	const lock_ops_t *ct_ops;
	bool ct_enter;
	bool (*ct_test)(const struct clock_test *, void *);
} clock_test_t;

extern const clock_test_t clock_cond_tests[];
extern size_t clock_cond_ntests;
extern const clock_test_t clock_mutex_tests[];
extern size_t clock_mutex_ntests;
extern const clock_test_t clock_rwlock_tests[];
extern size_t clock_rwlock_ntests;
extern const clock_test_t clock_sem_tests[];
extern size_t clock_sem_ntests;

/*
 * Timeouts and functions tests can use.
 */
extern const struct timespec clock_to_100ms;
extern const struct timespec clock_to_invns;
extern const struct timespec clock_to_invnegs;
extern const struct timespec clock_to_invnegns;

extern void clock_rel_to_abs(clockid_t, const struct timespec *restrict,
    struct timespec *restrict);
extern bool clock_abs_after(clockid_t, const struct timespec *);
extern bool clock_rel_after(clockid_t, const struct timespec *,
    const struct timespec *);

#ifdef __cplusplus
}
#endif

#endif /* _CLOCK_LOCK_H */
