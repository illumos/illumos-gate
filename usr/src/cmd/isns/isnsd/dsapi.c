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

#include <stdio.h>
#include <stdlib.h>
#ifdef DEBUG
#include <time.h>
#endif

#include "isns_server.h"
#include "isns_cache.h"
#include "isns_obj.h"
#include "isns_log.h"

#ifndef	TARGET_DATA_STORE
#define	TARGET_DATA_STORE	xml
#endif

#define	TARGET_src(TARGET)	XTARGET_src(TARGET)
#define	XTARGET_src(TARGET)	XXTARGET_src(TARGET/data.c)
#define	XXTARGET_src(TARGET)	#TARGET

#include TARGET_src(TARGET_DATA_STORE)

#define	TARGET_func(func)	XTARGET_func(TARGET_DATA_STORE, func)
#define	XTARGET_func(TARGET, func)	XXTARGET_func(TARGET, func)
#define	XXTARGET_func(TARGET, func)	TARGET ## func

#ifdef DEBUG
static time_t total_time = 0;
static clock_t total_clock = 0;
extern int verbose_tc;
#endif

int
target_init_data(
)
{
	return (TARGET_func(_init_data)());
}

int
target_load_obj(
	void **p,
	isns_obj_t **objp,
	uchar_t *phase
)
{
	return (TARGET_func(_load_obj)(p, objp, phase));
}

int
target_add_obj(
	const isns_obj_t *obj
)
{
	int status;
#ifdef DEBUG
	time_t t;
	clock_t c;
	if (verbose_tc != 0) {
		t = time(NULL);
		c = clock();
	}
#endif
	status = TARGET_func(_add_obj)(obj);
#ifdef DEBUG
	if (verbose_tc != 0) {
		t = time(NULL) - t;
		c = clock() - c;
		total_time += t;
		total_clock += c;
		printf("time %d clock %.4lf -adding one object\n",
		    t, c / (double)CLOCKS_PER_SEC);
	}
#endif
	return (status);
}

int
target_modify_obj(
	const isns_obj_t *obj
)
{
	int status;
#ifdef DEBUG
	time_t t;
	clock_t c;
	if (verbose_tc != 0) {
		t = time(NULL);
		c = clock();
	}
#endif
	status = TARGET_func(_modify_obj)(obj);
#ifdef DEBUG
	if (verbose_tc != 0) {
		t = time(NULL) - t;
		c = clock() - c;
		total_time += t;
		total_clock += c;
		printf("time %d clock %.4lf -updating one object\n",
		    t, c / (double)CLOCKS_PER_SEC);
	}
#endif
	return (status);
}

int
target_delete_obj(
	const isns_obj_t *obj
)
{
	int status;
#ifdef DEBUG
	time_t t;
	clock_t c;
	if (verbose_tc != 0) {
		t = time(NULL);
		c = clock();
	}
#endif
	status = TARGET_func(_delete_obj)(obj);
#ifdef DEBUG
	if (verbose_tc != 0) {
		t = time(NULL) - t;
		c = clock() - c;
		total_time += t;
		total_clock += c;
		printf("time %d clock %.4lf -deleting one object\n",
		    t, c / (double)CLOCKS_PER_SEC);
	}
#endif
	return (status);
}

int
target_delete_assoc(
	const isns_obj_t *obj
)
{
	int status;
#ifdef DEBUG
	time_t t;
	clock_t c;
	if (verbose_tc != 0) {
		t = time(NULL);
		c = clock();
	}
#endif
	status = TARGET_func(_delete_assoc)(obj);
#ifdef DEBUG
	if (verbose_tc != 0) {
		t = time(NULL) - t;
		c = clock() - c;
		total_time += t;
		total_clock += c;
		printf("time %d clock %.4lf -deleting one membership\n",
		    t, c / (double)CLOCKS_PER_SEC);
	}
#endif
	return (status);
}

int
target_update_commit(
)
{
	int status;
#ifdef DEBUG
	time_t t;
	clock_t c;
	if (verbose_tc != 0) {
		t = time(NULL);
		c = clock();
	}
#endif
	status = TARGET_func(_update_commit)();
#ifdef DEBUG
	if (verbose_tc != 0) {
		t = time(NULL) - t;
		c = clock() - c;
		total_time += t;
		total_clock += c;
		printf("time %d clock %.4lf -flushing the data\n",
		    t, c / (double)CLOCKS_PER_SEC);
		printf("time %d clock %.4lf -total update\n",
		    total_time, total_clock / (double)CLOCKS_PER_SEC);
		total_time = 0;
		total_clock = 0;
	}
#endif
	return (status);
}

int
target_update_retreat(
)
{
	int status;
#ifdef DEBUG
	time_t t;
	clock_t c;
	if (verbose_tc != 0) {
		t = time(NULL);
		c = clock();
	}
#endif
	status = TARGET_func(_update_retreat)();
#ifdef DEBUG
	if (verbose_tc != 0) {
		t = time(NULL) - t;
		c = clock() - c;
		total_time += t;
		total_clock += c;
		printf("time %d clock %.4lf -flushing the data\n",
		    t, c / (double)CLOCKS_PER_SEC);
		printf("time %d clock %.4lf -total update\n",
		    total_time, total_clock / (double)CLOCKS_PER_SEC);
		total_time = 0;
		total_clock = 0;
	}
#endif
	return (status);
}
