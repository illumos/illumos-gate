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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * Common handling for test programs.
 */

#ifndef	_TEST_COMMON_H
#define	_TEST_COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct test *test_t;
typedef void (*test_func_t)(test_t, void *);

extern void test_set_debug(void);
extern void test_set_force(void);
extern test_t test_start(const char *name, ...);
extern void test_failed(test_t, const char *format, ...);
extern void test_passed(test_t);
extern void test_debugf(test_t, const char *format, ...);
extern void test_run(int nthr, test_func_t, void *arg, const char *, ...);

#ifdef	__cplusplus
}
#endif
#endif	/* _TEST_COMMON_H */
