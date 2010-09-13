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

#ifndef _MULTIMEDIA_FIR_H
#define	_MULTIMEDIA_FIR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Finite Impulse Response (FIR) filter object
 *
 * For every input sample, the FIR filter generates an output sample:
 * output =	coef[0] * input +
 *		coef[1] * state[order - 1] +
 *		coef[2] * state[order - 2] +
 *		...
 *		coef[order] * state[0]
 *
 * and the filter states are updated:
 *	state[0] = state[1]
 *	state[1] = state[2]
 *	...
 *	state[order - 2] = state[order - 1]
 *	state[order - 1] = input
 */
class Fir {
protected:
	int		order;		// filter order, # taps = order + 1
	double		*coef;		// (order + 1) filter coeffs.
	double		*state;		// "order" filter states
	int		delay;		// actual delay between output & input

	virtual void	updateState(double *data, int size);
	virtual void	update_short(short *data, int size);
	virtual int	flush(short *out);
public:
	virtual void	resetState(void);	// reset states to zero
	Fir(void);
	Fir(int order_in);
	~Fir();
	virtual int	getOrder(void);		// get filter order value
	virtual int	getNumCoefs(void);	// get number of coefficients
	virtual void	putCoef(double *coef_in); // put coef_in in filter coef
	virtual void	getCoef(double *coef_out); // get filter coef
	// filter "size" input samples for "size" output samples
	virtual int	filter_noadjust(short *in, int size, short *out);
	/*
	 * filter "size" input samples. Output sample sequence is offset by
	 * group delay samples to align with the input sample sequence.
	 * the first call of this routine returns "size - group_delay"
	 * output samples. Call this routine with size = 0
	 * to fill the output buffer such that the total number of output
	 * samples is equal to the number of input samples.
	 */
	virtual int	getFlushSize(void); // size of out[] for the last call
	virtual int	filter(short *in, int size, short *out);
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_FIR_H */
