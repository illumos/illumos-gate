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
 * Copyright 2018 Joyent, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "mevent.h"

#define	EXIT_PASS 0
#define	EXIT_FAIL 1

#define VERBOSE(msg)							\
	if (testlib_verbose) {						\
		(void) printf("VERBOSE %s: %s:%d %s: ", testlib_prog,	\
		    __FILE__, __LINE__, __func__);			\
		(void) printf msg;					\
		(void) printf("\n");					\
	}

#define FAIL_PROLOGUE() \
	(void) printf("FAIL %s: %s:%d: ", testlib_prog, __FILE__, __LINE__)

#define	FAIL(msg)							\
	{								\
		FAIL_PROLOGUE();					\
		(void) printf msg;					\
		(void) printf("\n");					\
		exit(EXIT_FAIL);					\
	}

#define FAIL_ERRNO(msg) FAIL((msg ": %s", strerror(errno)))

#define	PASS()								\
	{								\
		(void) printf("PASS %s\n", testlib_prog);		\
		exit(EXIT_PASS);					\
	}

#define	ASSERT_CMP(msg, got, cmp, exp, nfmt)				\
	if (!(got cmp exp)) {						\
		FAIL_PROLOGUE();					\
		(void) printf msg;					\
		(void) printf(": %s=" nfmt " %s %s=" nfmt "\n",		\
		    #got, got, #cmp, #exp, exp);			\
		exit(EXIT_FAIL);					\
	}

#define	ASSERT_CHAR_EQ(msg, got, exp)	ASSERT_CMP(msg, got, ==, exp, "%c")
#define	ASSERT_INT_EQ(msg, got, exp)	ASSERT_CMP(msg, got, ==, exp, "%d")
#define	ASSERT_INT_NEQ(msg, got, exp)	ASSERT_CMP(msg, got, !=, exp, "%d")
#define	ASSERT_INT64_EQ(msg, got, exp)	ASSERT_CMP(msg, got, ==, exp, "%ld")
#define	ASSERT_PTR_EQ(msg, got, exp)	ASSERT_CMP(msg, got, ==, exp, "%p")
#define	ASSERT_PTR_NEQ(msg, got, exp)	ASSERT_CMP(msg, got, !=, exp, "%p")

#define	ASSERT_STR_EQ(msg, got, exp)					\
	if (strcmp(got, exp) != 0) {					\
		FAIL_PROLOGUE();					\
		(void) printf msg;					\
		(void) printf(": %s='%s' != %s='%s'\n",			\
		    #got, got, #exp, exp);				\
		exit(EXIT_FAIL);					\
	}

extern const char	*testlib_prog;
extern boolean_t	testlib_verbose;

extern void start_test(const char *, uint32_t);
extern void start_event_thread(void);
extern void test_mevent_count_lists(int *, int *, int *);
