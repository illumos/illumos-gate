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

#ifndef _SYS_BEEP_H
#define	_SYS_BEEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mutex.h>

/*
 * Interface to the system beeper.
 *
 * (This is the API, not the hardware interface.)
 */

#ifdef __cplusplus
extern "C" {
#endif

#if	defined(_KERNEL)

/* beep_entry structure */

typedef struct beep_entry {
	unsigned short  frequency;
	unsigned short  duration;
} beep_entry_t;

typedef void (*beep_on_func_t)(void *arg);

typedef void (*beep_off_func_t)(void *arg);

typedef void (*beep_freq_func_t)(void *arg, int freq);

/* beep_state structure */

typedef struct beep_state {

	/* Private data for beep_freq, beep_on, and beep_off functions */
	void		*arg;

	/* Indicates if a beep command is already in progress */
	enum		{BEEP_UNINIT = 0, BEEP_OFF = 1,
			    BEEP_TIMED = 2, BEEP_ON = 3} mode;

	/* Address of the hw-dependent beep_freq function */
	beep_freq_func_t beep_freq;

	/* Address of the hw-dependent beep_on function */
	beep_on_func_t	beep_on;

	/* Address of the hw-dependent beep_off function */
	beep_off_func_t	beep_off;

	/* Timeout id for the beep_timeout() function */
	timeout_id_t	timeout_id;

	/* Mutex protecting mode, timeout_id, queue_head, queue_tail, */
	/* and queue */
	kmutex_t	mutex;

	/* Index of head of queue */
	int		queue_head;

	/* Index of tail of queue */
	int		queue_tail;

	/* Max queue size */
	int		queue_size;

	/* Circular ring buffer */
	beep_entry_t	*queue;
} beep_state_t;

#define	BEEP_QUEUE_SIZE	1000

/* BEEP_DEFAULT is a sentinel for the beep_param table. */
enum beep_type { BEEP_DEFAULT = 0, BEEP_CONSOLE = 1, BEEP_TYPE4 = 2 };

typedef struct beep_params {
	enum beep_type	type;
	int		frequency;	/* Hz */
	int		duration;	/* milliseconds */
} beep_params_t;


extern int beep_init(void *arg,
    beep_on_func_t beep_on_func,
    beep_off_func_t beep_off_func,
    beep_freq_func_t beep_freq_func);

extern int beep_fini(void);

extern int beeper_off(void);

extern int beeper_freq(enum beep_type type, int freq);

extern int beep(enum beep_type type);

extern int beep_polled(enum beep_type type);

extern int beeper_on(enum beep_type type);

extern int beep_mktone(int frequency, int duration);

extern void beep_timeout(void *arg);

extern int beep_busy(void);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BEEP_H */
