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
 * Copyright (C) 4Front Technologies 1996-2008.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Purpose: GRC library version 3.1 internal definitions
 *
 * GRC3 is a high quality sample rate conversion module that uses fixed point
 * arithmetic.
 */

#ifndef AUDIO_GRC3_H
#define	AUDIO_GRC3_H

#define	GRC3_MAXHISTORY 4096

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct grc3state {
	uint32_t srcrate;
	uint32_t dstrate;
	uint32_t ptr;
	uint32_t ptr_incv;

	uint32_t sat;
	uint32_t filtfactor;
	int32_t *historyptr;
	int32_t dummy_pad1;

	int32_t history[GRC3_MAXHISTORY * 2 + 1];

	uint32_t outsz;
} grc3state_t;


/* BEGIN CSTYLED */
/*****************************************************************************

    Tutorial on how to use GRC3 rate conversion

1.  First, you create an instance of grc3state_t for each channel. If you
    are working with stereo files - you will need 2 of such instances,
    for quadro - 4.

    The instances may be allocated in either static or dynamic memory - that
    makes no difference to the convertor. So, if your program has to process
    one stereo stream, there's no reason why should you use malloc/free to
    allocate/deallocate structures. Also, in device drivers, you can
    use static variables as well:

	static grc3state_t grc[2]; // for two channels


2.  Before starting any conversion, grc3state_t instances should be initialized
    properly, and you do this with grc3_setup function. Function itself does
    not allocate additional memory or change anything except grc3state_t
    structure, so this is thread safe, and you don't have to do additional
    "deinitialization".

    If you are doing interleaved audio (stereo/quadro/whatever) conversion,
    you should do setup on each of the channels, and should have separate
    instance of grc3state_t for each channel. As you will understand further,
    such conversion is done separately. And now, the setup function:

	int grc3_setup( grc3state_t *grc,
		    uint32_t	fromRate,
		uint32_t    toRate );

	grc	  - pointer to grc3state_t instance
	fromRate  - source sample rate
	toRate	  - destination sample rate

    Note, that sample rates itself are not important - the important thing
    is ratio between those sample rates. So, for example, if you have to
    convert from 24000Hz to 48000Hz, it's ok to write:

	grc3_setup( &grc[0], 240, 480 );

    Sometimes (in MIDI synths) it would be desired to use fractional sample
    rates. For example, setup for conversion from 33100.78 to 48000 may look
    like this:

	grc3_setup( &grc[0], 3310078, 4800000);

    Note, that on stereo, GRC3 setup will look like this:

	static grc3state_t grc[2];

    // ...

	grc3_setup( &grc[0], 3310078, 4800000)
        grc3_setup( &grc[1], 3310078, 4800000);


    Note, that you should not rely on grc3_setup's fast execution or any
    execution timing. It may contain some massive arithmetic and even huge
    loops, so avoid putting grc3_setup to inner loops and calling in
    latency-dependent code.


3.  Next, before running a stream through grc3_convert function, you should
    reset each of grc3state_t instance used:

	void grc3_reset(grc3state_t *grc);


	grc	- pointer to GRC3 instance variable

    So, for stereo, this appears to be:

	static grc3state_t grc[2];

    // ...

	grc3_reset( &grc[0] );
    grc3_reset( &grc[1] );


4.  Finally, doing conversion is easy:

	void grc3_convert( grc3state_t *grc,
			  int	       domain,
	      int	   quality,
			  const void  *src,
	      void	  *dst,
		  int	       maxInSize,
	      int	   maxOutSize,
	      int	   interleave,
	      int	   offset );


	grc	   - pointer to initialized grc3state_t instance; you
		     can specify NULL to check whether a particular
		 domain/quality pair is supported, check return value

	quality	   - quality to use for conversion, supported values are:

		     0 - D lowest quality (normally equals to low quality)
		 1 - L	low quality    (spline interpolation)
		 2 - M	medium quality (lagrange interpolation)
		 3 - H	high quality
		 4 - HX high quality   (high quality with extra precision)
		 5 - P	production quality

		 6 - PX production quality (prod quality with extra precision)
		     (PX is currently disabled because it causes a crash)

	src	   - source audio buffer

	dst	   - destination audio buffer;

	maxInSize  - size of input buffer (in samples per channel!)

	maxOutSize - size of output buffer (in samples per channel!)
		     (will never overrun this size)

	interleave - interleave factor; for MONO or non-interleaved data
		     it should be equal to 1;

	     2 - STEREO interleaved audio
	     4 - QUADRO interleaved audio

	     So, basically, this parameter should be equal to number
	     of interleaved channels

	offset	   - number of interleaved channel currently processing,
		     starting from 0; for MONO or non-interleaved data
	     it should be equal to 0


	     For unsupported quality values, it will fall back to
	     "D" quality (the lowest one)

		     also on return it sets:

	     grc->outsz	 == number of output samples

	     Note, that if quality is not supported,
	     calling the function with real data will fall back
	     to the worst quality available.

	     Note that this version of GRC3 only supports 24-bit
	     native endian.  (Modified by Sun for performance.)



5.  Interleaved processing of N channels is done like this:


	static grc3state_t grc[N];
    int t;

    //...


    for(t=0; t<N; t++)
    {
	grc3_setup( &grc[t], 22050, 48000 );

	grc3_reset( &grc[t] );
    }


    //...

	while (...) {

	for(t = 0; t < N; t++) {
	    grc3_convert(&grc[t],   // instance pointer
		      4,            // quality
		      in_buffer,    // input buffer
		  out_buffer,       // input buffer
		  in_samples_count, // number of samples
				    // in in_buffer
		  2048,             // size of out_buffer
		  N, t              // num of channels, channel#
		);
	}


	// Normally, for interleaved data, ->outsz of all instances will
	// be the same for the same stream

	put_sound_somewhere(out_buffer,
		     grc[0]->outsz * N * sizeof(out_buffer[0]) );
    }


6.  If you use the same storage and the same setup for processing few separate
    non-related sounds, to prevent the feedback of sound1's tail to sound2's
    beginning - do grc3_reset on the state instances before calling
    grc_convert.

*****************************************************************************
*/
/* END CSTYLED */

void grc3_setup(grc3state_t *, uint32_t fromRate, uint32_t toRate);

void grc3_reset(grc3state_t *);

void grc3_convert(grc3state_t *, int quality,
    const void *src, void *dst, int sz, int bufsz, int inc, int offset);

#ifdef __cplusplus
};
#endif

#endif	/* AUDIO_GRC3_H */
