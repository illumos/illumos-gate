/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1990-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MULTIMEDIA_SILENCE_DETECT_H
#define	_MULTIMEDIA_SILENCE_DETECT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <audio_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * %M%
 *
 * Description:
 *
 * This file contains definitions of the public structures
 * used by the silence detection function, 'silence_detect()'.
 * There are two structures, one for specifying the start and end
 * points of an interval of silence, and a second for maintaining
 * the state of the silence detection algorithm between calls to
 * 'silence_detect()'.
 */

/* Error returns. */
#define	SILENCE_ERR_BUFFER_TOO_SMALL	-1
#define	SILENCE_ERR_REALLOC_FAILED	-2

/* Algorithm specific defines needed for both silence.h and silence.c. */
/*
 * The interval in milliseconds over which
 * zerocrossings are considered.
 */
#define	ZEROCROSS_RANGE 25

/*
 * The number of blocks needed for threshold
 * determination.
 */
#define	DATA_POINTS	10

/*
 * The END_POINTS structure holds the index of the first point in
 * the silence interval and the first point beyond the end of the
 * silence interval.
 */
typedef struct {
	int ep_start;	/* Index of first point in silence interval. */
	int ep_end;	/* Index of first point beyond silence interval. */
} END_POINTS;

/*
 * The SIL_STATE structure preserves the the state of the silence detection
 * algorithm between calls to 'silence_detect'.  It is allocated by calling
 * 'silence_init_state'; it is initialized by calling 'silence_init_state';
 * and it is deallocated by using 'silence_destroy_state'.
 *
 * The struct should not be directly modified by user programs.
 */
typedef struct {
	unsigned int sampling_rate;	/* The sampling rate. */

/*
 * Length in samples of the algorithms
 * analysis block.  It should be
 * equivalent to 10 msec. of data.
 * It is set by 'silence_init'.
 */
	int block_size;

/*
 * Pointer to leftover data from the
 * previous call.
 */
	short *leftover;

/* Consolidated buffer. */
	short *sbuf;

/*
 * Indicates the position of the end of
 * the current analysis frame (plus 2)
 * relative to the start of the current
 * buffer.
 */
	int m;

/*
 * Keeps track of the number of blocks
 * collected for noise floor statistical
 * characterization.
 */
	int thr_calc_data_pts;

/*
 * Records the algorithm's current place
 * in the finite state machine governing
 * silence interval detection.
 */
	int sil_state;

/*
 * Records how many consecutive analysis
 * blocks have been processed in the
 * current detection state.
 */
	int state_exit_ind[5];

/*
 * Size in samples of the product of
 * ZEROCROSS_RANGE * 10 ms of data.
 */
	int zerocross_range;

/*
 * Stores the indices of the
 * first element of the last ZERO_CROSS_RANGE
 * blocks in the which the zerocrossing rate
 * threshold was exceeded.
 */
	int zerocross_ind[ZEROCROSS_RANGE];

/*
 * Zerocrossing data for threshold
 * calculation.
 */
	int zerocross[DATA_POINTS];

/*
 * Average absolute value data for
 * threshold calculation.
 */
	int abs_val[DATA_POINTS];

/*
 * Zerocrossing threshold determined by
 * 'silence_thrcalc().
 */
	int zerocross_thr;

/*
 * Absolute value threshold determined by
 * 'silence_thrcalc().
 */
	int abs_val_thr[2];

/*
 * The tenative duration of silence.
 * Several decisions made by the algorithm
 * are based on whether or not this quanti-
 * ty is less than the minimum duration
 * of silence.
 */
	int tentative_sil_dur;

/* Minimum duration of silence in samples. */
	int min_sil_dur;

/*
 * Stores the index of the tentative end
 * of the most recent interval of speech
 * relative to the start of the input
 * buffer.
 */
	int end_of_speech;

/*
 * Stores the index of the tentative end
 * of the most recent interval of silence
 * relative to the start of the input
 * buffer.
 */
	int end_of_sil;

/*
 * Pointer to the highest index entry of
 * 'zerocross_cnt' whose value is less than
 * ZEROCROSS_RANGE.  It signifies the
 * number of blocks since the least
 * recent instance when the zerocrossing
 * threshold was exceeded during the last
 * 250 milliseconds.
 */
	int *least_recent;

/*
 * Array of structures containing the
 * endpoints of silence intervals.
 */
	END_POINTS *end_points;

/*
 * Number of entries in the array
 * of END_POINTS structures.
 */
	int end_points_size;

/*
 * Index to simplify the synchronization of
 * silence end point storage.  Whenever the
 * indeterminate region stems from silence,
 * the region's start is moved back 10 msecs
 * to include one block of known silence.
 * This variable stores the index of the
 * start of that block of silence relative
 * to the start of the current input
 * buffer.
 */
	int next_silence_start;

/*
 * default absolute value threshold, used
 * when the first 100ms of speech is loud.
 */
	double noise;

	long	min_abs;	/* minimum of absolute magnitude */
	long	max_abs;	/* maximum of absolute magnitude */
	double	thr_scale;	/* ratio for adaptive threshold adjustment */
	long	block_limit_low;	/* absolute silence level for block */
	long	block_limit_high;	/* absolute voice level for block */
} SIL_STATE;

EXTERN_FUNCTION(SIL_STATE* silence_create_state, (unsigned int, double));
EXTERN_FUNCTION(void silence_destroy_state, (SIL_STATE*));
EXTERN_FUNCTION(int silence_detect,
	(short *, END_POINTS **, unsigned int *, int *, SIL_STATE*));
EXTERN_FUNCTION(void silence_init_state, (SIL_STATE*));
EXTERN_FUNCTION(void silence_set_rate, (unsigned int, SIL_STATE*));
EXTERN_FUNCTION(void silence_set_min_sil_dur, (double, SIL_STATE*));
EXTERN_FUNCTION(void silence_set_thr_scale, (double, SIL_STATE*));
EXTERN_FUNCTION(void silence_set_noise_ratio, (double, SIL_STATE*));
EXTERN_FUNCTION(double silence_get_min_sil_dur, (SIL_STATE*));
EXTERN_FUNCTION(double silence_get_thr_scale, (SIL_STATE*));
EXTERN_FUNCTION(double silence_get_noise_ratio, (SIL_STATE*));

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_SILENCE_DETECT_H */
