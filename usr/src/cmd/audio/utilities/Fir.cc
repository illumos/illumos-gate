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

#include <memory.h>
#include <stddef.h>
#include <sys/types.h>
#include <Fir.h>

extern "C" {
	char *bcopy(char *, char *, int);
	char *memmove(char *, char *, int);
}

#define	BCOPY(src, dest, num) memmove(dest, src, num)

/*
 * convolve()
 * returns the convolution of coef[length] and in_buf[length]:
 *
 * convolution = coef[0] * in_buf[length - 1] +
 *		 coef[1] * in_buf[length - 2] +
 *		 ...
 *		 coef[length - 1] * in_buf[0]
 */
double
convolve(
	double	*coefs,
	double	*in_buf,
	int	length)
{
	if (length <= 0)
		return (0.0);
	else {
		in_buf += --length;
		double sum = *coefs * *in_buf;
		while (length--)
			sum += *++coefs * *--in_buf;
		return (sum);
	}
}

void				// convert short to double
short2double(
	double *out,
	short *in,
	int size)
{
	while (size-- > 0)
		*out++ = (double)*in++;
}

short
double2short(double in)			// limit double to short
{
	if (in <= -32768.0)
		return (-32768);
	else if (in >= 32767.0)
		return (32767);
	else
		return ((short)in);
}

void Fir::				// update state with data[size]
updateState(
	double	*data,
	int	size)
{
	if (size >= order)
		memcpy(state, data + size - order, order * sizeof (double));
	else {
		int old = order - size;
		BCOPY((char *)(state + size), (char *)state,
		    old * sizeof (double));
		memcpy(state + order - size, data, size * sizeof (double));
	}
}

void Fir::
update_short(
	short	*in,
	int	size)
{
	double *in_buf = new double[size];
	short2double(in_buf, in, size);
	updateState(in_buf, size);
	delete[] in_buf;
}

void Fir::
resetState(void)			// reset state to all zero
{
	for (int i = 0; i < order; i++)
		state[i] = 0.0;
}

Fir::
Fir(void)
{
}

Fir::
Fir(int order_in): order(order_in)	// construct Fir object
{
	state = new double[order];
	resetState();
	coef = new double[order + 1];
	delay = (order + 1) >> 1;	// assuming symmetric FIR
}

Fir::
~Fir()					// destruct Fir object
{
	delete coef;
	delete state;
}

int Fir::
getOrder(void)				// returns filter order
{
	return (order);
}

int Fir::
getNumCoefs(void)			// returns number of filter coefficients
{
	return (order + 1);
}

void Fir::
putCoef(double *coef_in)		// copy coef_in in filter coefficients
{
	memcpy(coef, coef_in, (order + 1) * sizeof (double));
}

void Fir::
getCoef(double *coef_out)		// returns filter coefs in coef_out
{
	memcpy(coef_out, coef, (order + 1) * sizeof (double));
}

int Fir::		// filter in[size], and updates the state.
filter_noadjust(
	short	*in,
	int	size,
	short	*out)
{
	if (size <= 0)
		return (0);

	double *in_buf = new double[size];
	short2double(in_buf, in, size);		// convert short input to double
	int	i;
	int	init_size = (size <= order)? size : order;
	int	init_order = order;
	double	*state_ptr = state;
	short	*out_ptr = out;

	// the first "order" outputs need state in convolution
	for (i = 1; i <= init_size; i++)
		*out_ptr++ = double2short(convolve(coef, in_buf, i) +
		    convolve(coef + i, state_ptr++, init_order--));

	// starting from "order + 1"th output, state is no longer needed
	state_ptr = in_buf;
	while (i++ <= size)
		*out_ptr++ =
		    double2short(convolve(coef, state_ptr++, order + 1));
	updateState(in_buf, size);
	delete[] in_buf;
	return (out_ptr - out);
}

int Fir::
getFlushSize(void)
{
	int group_delay = (order + 1) >> 1;
	return ((delay < group_delay)? group_delay - delay : 0);
}

int Fir::
flush(short *out)		// zero input response of Fir
{
	int num = getFlushSize();
	if (num > 0) {
		short *in = new short[num];
		memset(in, 0, num * sizeof (short));
		num = filter_noadjust(in, num, out);
		delete[] in;
	}
	return (num);
}

/*
 * filter() filters in[size] with filter delay adjusted to 0
 *
 * All FIR filters introduce a delay of "order" samples between input and
 * output sequences. Most FIR filters are symmetric filters to keep the
 * linear phase responses. For those FIR fitlers the group delay is
 * "(order + 1) / 2". So filter_nodelay adjusts the group delay in the
 * output sequence such that the output is aligned with the input and
 * direct comparison between them is possible.
 *
 * The first call of filter returns "size - group_delay" output samples.
 * After all the input samples have been filtered, filter() needs
 * to be called with size = 0 to get the residual output samples to make
 * the output sequence the same length as the input.
 *
 */

int Fir::
filter(
	short	*in,
	int	size,
	short	*out)
{
	if ((size <= 0) || (in == NULL))
		return (flush(out));
	else if (delay <= 0)
		return (filter_noadjust(in, size, out));
	else if (size <= delay) {
		update_short(in, size);
		delay -= size;
		return (0);
	} else {
		update_short(in, delay);
		in += delay;
		size -= delay;
		delay = 0;
		return (filter_noadjust(in, size, out));
	}
}
