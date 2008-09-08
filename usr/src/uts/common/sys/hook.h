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

/*
 * This file includes definitions of kernel hook framework components
 */

#ifndef _SYS_HOOK_H
#define	_SYS_HOOK_H

#include <sys/queue.h>
#include <sys/netstack.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definition exposed to hook provider and consumer
 */

#define	HOOK_VERSION	1

typedef uintptr_t hook_data_t;

struct hook_event_int;
typedef struct hook_event_int *hook_event_token_t;
struct hook_int;
typedef struct hook_int *hook_token_t;

typedef int (* hook_func_t)(hook_event_token_t, hook_data_t, void *);

/*
 * A hook_notify_cmd_t is given as an argument to functions called as part of
 * the notify callbacks that have been registered firing.
 */
typedef enum hook_notify_cmd_e {
	HN_NONE = 0,
	HN_REGISTER = 1,
	HN_UNREGISTER = 2
} hook_notify_cmd_t;

/*
 *
 */
typedef enum hook_hint_e {
	HH_NONE = 0,
	HH_FIRST,
	HH_LAST,
	HH_BEFORE,
	HH_AFTER
} hook_hint_t;

/*
 * Hook
 */
typedef struct hook_s {
	int		h_version;
	hook_func_t	h_func;		/* callback func */
	char		*h_name;	/* name of this hook */
	uint_t		h_flags;	/* extra hook properties */
	hook_hint_t	h_hint;		/* What type of hint is hintvalue */
	uintptr_t	h_hintvalue;
	void		*h_arg;		/* value to pass back into the hook */
} hook_t;

#define	HOOK_INIT(x, fn, r, a)		\
	do {					\
		(x) = hook_alloc(HOOK_VERSION);	\
		(x)->h_func = (fn);		\
		(x)->h_name = (r);		\
		(x)->h_flags = 0;		\
		(x)->h_hint = HH_NONE;		\
		(x)->h_hintvalue = 0;		\
		(x)->h_arg = (a);		\
		_NOTE(CONSTCOND)		\
	} while (0)

/*
 * Family
 */
typedef struct hook_family_s {
	int		hf_version;	/* version number */
	char		*hf_name;	/* family name */
} hook_family_t;

#define	HOOK_FAMILY_INIT(x, y)			\
	do {					\
		(x)->hf_version = HOOK_VERSION;	\
		(x)->hf_name = (y);		\
		_NOTE(CONSTCOND)		\
	} while (0)

/*
 * Event
 */
typedef struct hook_event_s {
	int		he_version;
	char		*he_name;	/* name of this hook list */
	int		he_flags;	/* 1 = multiple entries allowed */
	boolean_t	he_interested;	/* true if callback exist */
} hook_event_t;

#define	HOOK_RDONLY	0x1		/* Callbacks must not change data */
					/* Multiple callbacks are allowed */

#define	HOOK_EVENT_INIT(x, y)			\
	do {					\
		(x)->he_version = HOOK_VERSION;	\
		(x)->he_name = (y);		\
		(x)->he_flags = 0;		\
		(x)->he_interested = B_FALSE;	\
		_NOTE(CONSTCOND)		\
	} while (0)

typedef int (* hook_notify_fn_t)(hook_notify_cmd_t, void *, const char *,
    const char *, const char *);

extern	hook_t		*hook_alloc(const int version);
extern	void		hook_free(hook_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_HOOK_H */
