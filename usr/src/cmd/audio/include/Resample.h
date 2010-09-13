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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MULTIMEDIA_RESAMPLE_H
#define	_MULTIMEDIA_RESAMPLE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * To convert the sampling rate of fi of input signal to fo of output signal,
 * the least common multiple fm = L * fi = M * fo needs to be derived first.
 * Then the input signal is
 * 1) up-sampled to fm by inserting (L - 1) zero-valued samples after each
 *    input sample,
 * 2) low-pass filtered to half of the lower of fi and fo, and
 * 3) down-sampled to fo by saving one out of every M samples.
 *
 * The low-pass filter is implemented with an FIR filter which is a truncated
 * ideal low pass filter whose order is dependent on its bandwidth.
 *
 * Refer to Fir.h for explanations of filter() and flush().
 *
 */
#include <Fir.h>

#ifdef __cplusplus
extern "C" {
#endif

class ResampleFilter : public Fir {
	int	num_state;		// interpolation requires less states
	int	up;			// upsampling ratio
	int	down;			// down sampling ratio
	int	down_offset;		// 0 <= index in down-sampling < down
	int	up_offset;		// -up < index in up_sampling <= 0

	void updateState(double *in, int size);

	// if fi is a multiple of fo, LP filtering followed by down_sampling
	int decimate_noadjust(short *in, int size, short *out);
	int decimate_flush(short *);
	int decimate(short *in, int size, short *out);

	// if fo is a multiple of fi, up-sampling followed by LP filtering
	int interpolate_noadjust(short *in, int size, short *out);
	int interpolate_flush(short *);
	int interpolate(short *in, int size, short *out);

	int flush(short *out);

public:
	ResampleFilter(int rate_in, int rate_out);
	virtual int	filter_noadjust(short *in, int size, short *out);
	virtual int	filter(short *in, int size, short *out);
	virtual int	getFlushSize(void);
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_RESAMPLE_H */
