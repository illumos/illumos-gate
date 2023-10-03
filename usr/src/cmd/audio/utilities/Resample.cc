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

/*
 * This is a impementation of sampling rate conversion for low-passed signals.
 *
 * To convert the input signal of sampling rate of fi to another rate of fo,
 * the least common multiple of fi and fo is derived first:
 *	fm = L * fi = M * fo.
 * Then the input signal is up-sampled to fm by inserting (L -1) zero valued
 * samples after each input sample, low-pass filtered, and down-smapled by
 * saving one sample for every M samples. The implementation takes advantages
 * of the (L - 1) zero values in the filter input and the (M - 1) output
 * samples to be disregarded.
 *
 * If L = 1 or M = 1, a simpler decimation or interpolation is used.
 */
#include <memory.h>
#include <math.h>

#include <Resample.h>

extern "C" {
	char *bcopy(char *, char *, int);
	char *memmove(char *, char *, int);
}

#define	BCOPY(src, dest, num) memmove(dest, src, num)

// convolve(), short2double() and double2short() are defined in Fir.cc.
extern double convolve(double *, double *, int);
extern void short2double(double *, short *, int);
extern short double2short(double);

// generate truncated ideal LPF
static void sinc_coef(int	fold,	// sample rate change
	int	order,			// LP FIR filter order
	double  *coef)			// filter coefficients
{
	int	i;
	float   alpha;
	double  bandwidth = M_PI / fold; // digital bandwidth of pass band

	int half = order >> 1;
	if (order & 1) {		// order is odd, center = half + 0.5
		float center = half + 0.5;
		for (i = 0; i <= half; i++) {
			alpha = center - i;
			coef[i] = sin(bandwidth * alpha) / (M_PI * alpha);
		}
	} else {	// order is even, center = half
		for (i = 0; i < half; i++) {
			alpha = half - i;
			coef[i] = sin(bandwidth * alpha) / (M_PI * alpha);
		}
		coef[i++] = bandwidth / M_PI;
	}
	for (; i <= order; i++)		// symmetric FIR
		coef[i] = coef[order - i];
}

/*
 * poly_conv() = coef[0] * data[length - 1] +
 *		 coef[inc_coef] * data[length - 2] +
 *		 ...
 *		 coef[(length - 1) * inc_coef] * data[0] +
 *
 * convolution of coef[order + 1] and data[length] up-sampled by a factor
 * of inc_coef. The terms of coef[1, 2, ... inc_coef - 1] multiplying 0
 * are ignored.
 */
// polyphase filter convolution
double
poly_conv(double	*coef,		// filter coef array
	    int		order,		// filter order
	    int		inc_coef,	// 1-to-L up-sample for data[length]
	    double	*data,		// data array
	    int		length)		// data array length
{
	if ((order < 0) || (inc_coef < 1) || (length < 1))
		return (0.0);
	else {
		double sum = 0.0;
		double *coef_end = coef + order;
		double *data_end = data + length;
		while ((coef <= coef_end) && (data < data_end)) {
			sum += *coef * *--data_end;
			coef += inc_coef;
		}
		return (sum);
	}
}

int
gcf(int a, int b)		// greatest common factor between a and b
{
	int remainder = a % b;
	return (remainder == 0)? b : gcf(b, remainder);
}

void ResampleFilter::
updateState(
	double *in,
	int size)
{
	if (up <= 1)
		Fir::updateState(in, size);
	else if (size >= num_state)
		memcpy(state, in + size - num_state,
		    num_state * sizeof (double));
	else {
		int old = num_state - size;
		BCOPY((char *)(state + size), (char *)state,
		    old * sizeof (double));
		memcpy(state + old, in, size * sizeof (double));
	}
}

ResampleFilter::			// constructor
ResampleFilter(
	int rate_in,			// sampling rate of input signal
	int rate_out)			// sampling rate of output signal
{
	// filter sampling rate = common multiple of rate_in and rate_out
	int commonfactor = gcf(rate_in, rate_out);
	up = rate_out / commonfactor;
	down = rate_in / commonfactor;

	int fold = (up > down)? up : down;	// take the bigger rate change
	order = (fold << 4) - 2;		// filter order = fold * 16 - 2
	coef = new double[order + 1];
	sinc_coef(fold, order, coef);		// required bandwidth = PI/fold

	if (up > 1) {				// need (order/up) states
		num_state = (order + up  - 1) / up;
		state = new double[num_state];
		for (int i = 0; i < num_state; i++)	// reset states
			state[i] = 0.0;
	} else {
		num_state = order;
		state = new double[order];	// need order states
		resetState();
	}
	delay = (order + 1) >> 1;	// assuming symmetric FIR
	down_offset = 0;
	up_offset = 0;
}

// down-to-1 decimation
int ResampleFilter::
decimate_noadjust(short	*in,
		int	size,
		short	*out)
{
	int	i;

	if (size <= 0)
		return (0);
	else if (down <= 1)		// normal filter
		return (Fir::filter_noadjust(in, size, out));
	else if (size <= down_offset) {	// just update states
		update_short(in, size);
		down_offset -= size;
		return (0);
	}

	double *in_buf = new double[size];
	short2double(in_buf, in, size);

	// filter and decimate and output
	short   *out_ptr = out;
	int init_size = (size <= order)? size : order;
	for (i = down_offset; i < init_size; i += down)
		*out_ptr++ = double2short(convolve(coef, in_buf, i + 1) +
		    convolve(coef + i + 1, state + i, order - i));
	for (; i < size; i += down)
		*out_ptr++ = double2short(convolve(coef, in_buf + i - order,
		    order + 1));
	down_offset = i - size;

	updateState(in_buf, size);
	delete[] in_buf;
	return (out_ptr - out);
}

// decimate with group delay adjusted to 0
int ResampleFilter::
decimate(short	*in,
	int	size,
	short	*out)
{
	if (delay <= 0)
		return (decimate_noadjust(in, size, out));
	else if (size <= delay) {
		update_short(in, size);
		delay -= size;
		return (0);
	} else {
		update_short(in, delay);
		in += delay;
		size -= delay;
		delay = 0;
		return (decimate_noadjust(in, size, out));
	}
}

// flush decimate filter
int ResampleFilter::
decimate_flush(short	*out)
{
	int num_in = Fir::getFlushSize();
	short *in = new short[num_in];
	memset(in, 0, num_in * sizeof (short));
	int num_out = decimate_noadjust(in, num_in, out);
	delay += num_in;
	delete[] in;
	return (num_out);
}

// 1-to-up interpolation
int ResampleFilter::
interpolate_noadjust(short	*in,
		    int		size,
		    short	*out)
{
	int	i, j;

	if (size <= 0)
		return (0);
	else if (up <= 1)			// regular filter
		return (Fir::filter_noadjust(in, size, out));

	double *in_buf = new double[size];
	short2double(in_buf, in, size);
	short *out_ptr = out;
	// befor the 1st input sample, generate  "-up_offset" output samples
	int coef_offset = up + up_offset;
	for (j = up_offset; j < 0; j++) {
		*out_ptr++ = double2short(up * poly_conv(coef + coef_offset,
		    order - coef_offset, up, state, num_state));
		coef_offset++;
	}
	// for each of the rest input samples, generate up output samples
	for (i = 1; i < size; i++) {
		for (j = 0; j < up; j++) {
			*out_ptr++ = double2short(up * (poly_conv(coef + j,
			    order - j, up, in_buf, i) + poly_conv(
			    coef + coef_offset, order - coef_offset, up, state,
			    num_state)));
			coef_offset++;
		}
	}

	// for the last input samples, generate "up_offset + up" output samples
	for (j = 0; j < (up_offset + up); j++) {
		*out_ptr++ = double2short(up * (poly_conv(coef + j,
		    order - j, up, in_buf, size) + poly_conv(
		    coef + coef_offset, order - coef_offset, up, state,
		    num_state)));
		coef_offset++;
	}
	updateState(in_buf, size);
	delete[] in_buf;
	return (out_ptr - out);
}

// flush interpolate filter
int ResampleFilter::
interpolate_flush(short	*out)
{
	int num = (Fir::getFlushSize() + up - 1) / up;

	short *in = new short[num];
	memset(in, 0, num * sizeof (short));
	int out_num = interpolate_noadjust(in, num, out);
	delay += num * up;
	delete[] in;
	return (out_num);
}

// interpolate with delay adjusted
int ResampleFilter::
interpolate(short *in,
	    int size,
	    short *out)
{
	if (size <= 0)
		return (interpolate_flush(out));
	else if (delay <= 0)
		return (interpolate_noadjust(in, size, out));
	else {
		int delay_in = (delay + up - 1) / up;
		if (size < delay_in)
			delay_in = size;
		double *in_buf = new double[delay_in];
		short2double(in_buf, in, delay_in);
		updateState(in_buf, delay_in);
		delete[] in_buf;
		delay -= delay_in * up;
		up_offset = delay;
		return (interpolate_noadjust(in + delay_in, size -
		    delay_in, out));
	}
}

int ResampleFilter::
filter_noadjust(short	*in,		// non-integer sampling rate conversion
	int	size,
	short	*out)
{
	int	i, j;

	if (size <= 0)
		return (0);
	else if (up <= 1)
		return (decimate_noadjust(in, size, out));
	else if (down <= 1)
		return (interpolate_noadjust(in, size, out));

	double *in_buf = new double[size];
	short2double(in_buf, in, size);
	short *init_out = out;
	int coef_offset = up_offset + down_offset + up;

	/*
	 * before the 1st input sample,
	 * start from "up_offset + down_offset"th up-sampled sample
	 */
	for (j = up_offset + down_offset; j < 0; j += down) {
		*out++ = double2short(up * poly_conv(coef + coef_offset,
		    order - coef_offset, up, state, num_state));
		coef_offset += down;
	}

	// process the input samples until the last one
	for (i = 1; i < size; i++) {
		for (; j < up; j += down) {
			*out++ = double2short(up * (poly_conv(coef + j,
			    order - j, up, in_buf, i) + poly_conv(
			    coef + coef_offset, order - coef_offset, up, state,
			    num_state)));
			coef_offset += down;
		}
		j -= up;
	}

	// for the last input sample, end at the "up + up_offset"th
	for (; j < (up + up_offset); j += down) {
		*out++ = double2short(up * (poly_conv(coef + j, order - j, up,
		    in_buf, size) + poly_conv(coef + coef_offset,
		    order - coef_offset, up, state, num_state)));
		coef_offset += down;
	}
	down_offset = j - (up + up_offset);

	updateState(in_buf, size);
	delete[] in_buf;
	return (out - init_out);
}

int ResampleFilter::
getFlushSize(void)
{
	int num_in = (Fir::getFlushSize() + up - 1) / up;
	return ((num_in * up + down - 1 - down_offset) / down);
}

int ResampleFilter::
flush(short	*out)		// flush resampling filter

{
	if (down <= 1)
		return (interpolate_flush(out));
	else if (up <= 1)
		return (decimate_flush(out));

	int num = (Fir::getFlushSize() + up - 1) / up;

	short *in = new short[num];
	memset(in, 0, num * sizeof (short));
	int out_num = filter_noadjust(in, num, out);
	delete[] in;
	delay += num * up;
	return (out_num);
}

/*
 * sampling rate conversion with filter delay adjusted
 */
int ResampleFilter::
filter(
	short	*in,
	int	size,
	short	*out)
{
	if (size <= 0)
		return (flush(out));
	else if (up <= 1)
		return (decimate(in, size, out));
	else if (down <= 1)
		return (interpolate(in, size, out));
	else if (delay <= 0)
		return (filter_noadjust(in, size, out));
	else {
		int delay_in = (delay + up - 1) / up;
		if (size < delay_in)
			delay_in = size;
		double *in_buf = new double[delay_in];
		short2double(in_buf, in, delay_in);
		updateState(in_buf, delay_in);
		delete[] in_buf;
		delay -= up * delay_in;
		if (delay <= 0) {
			up_offset = delay;
			down_offset = 0;
		}
		return (filter_noadjust(in + delay_in, size - delay_in, out));
	}
}
