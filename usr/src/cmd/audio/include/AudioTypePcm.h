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

#ifndef _MULTIMEDIA_AUDIOTYPEPCM_H
#define	_MULTIMEDIA_AUDIOTYPEPCM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioTypeConvert.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is the class for a linear PCM conversion module

class AudioTypePcm : public AudioTypeConvert {
protected:
	typedef unsigned char	ulaw;
	typedef unsigned char	alaw;

	// Conversion routines inline'd in the source file
	double char2dbl(char);
	double short2dbl(short);
	double long2dbl(long);
	long dbl2long(double, long);

	void char2short(char *&, short *&);
	void char2long(char *&, long *&);
	void char2float(char *&, float *&);
	void char2double(char *&, double *&);
	void char2ulaw(char *&, ulaw *&);
	void char2alaw(char *&, alaw *&);

	void short2char(short *&, char *&);
	void short2long(short *&, long *&);
	void short2float(short *&, float *&);
	void short2double(short *&, double *&);
	void short2ulaw(short *&, ulaw *&);
	void short2alaw(short *&, alaw *&);

	void long2char(long *&, char *&);
	void long2short(long *&, short *&);
	void long2float(long *&, float *&);
	void long2double(long *&, double *&);
	void long2ulaw(long *&, ulaw *&);
	void long2alaw(long *&, alaw *&);

	void float2char(float *&, char *&);
	void float2short(float *&, short *&);
	void float2long(float *&, long *&);
	void float2double(float *&, double *&);
	void float2ulaw(float *&, ulaw *&);
	void float2alaw(float *&, alaw *&);

	void double2char(double *&, char *&);
	void double2short(double *&, short *&);
	void double2long(double *&, long *&);
	void double2float(double *&, float *&);
	void double2ulaw(double *&, ulaw *&);
	void double2alaw(double *&, alaw *&);

	void ulaw2char(ulaw *&, char *&);
	void ulaw2short(ulaw*&, short *&);
	void ulaw2long(ulaw*&, long *&);
	void ulaw2float(ulaw *&, float *&);
	void ulaw2double(ulaw *&, double *&);
	void ulaw2alaw(ulaw *&, alaw *&);

	void alaw2ulaw(alaw *&, ulaw *&);
	void alaw2char(alaw *&, char *&);
	void alaw2short(alaw *&, short *&);
	void alaw2long(alaw *&, long *&);
	void alaw2float(alaw *&, float *&);
	void alaw2double(alaw *&, double *&);

public:
	AudioTypePcm();					// Constructor

	// Class AudioTypeConvert methods specialized here

	// TRUE if conversion ok
	virtual Boolean CanConvert(
	    AudioHdr h) const;			// type to check against

	// Convert buffer to the specified type
	// Either the input or output type must be handled by this class

	// Convert to new type
	virtual AudioError Convert(
	    AudioBuffer*& inbuf,		// data buffer to process
	    AudioHdr outhdr);			// target header

	virtual AudioError Flush(AudioBuffer*& buf);
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOTYPEPCM_H */
