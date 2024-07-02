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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <AudioTypePcm.h>
#include <libaudio.h>

#define	irint(d)	((int)d)

// class AudioTypePcm methods


// Constructor
AudioTypePcm::
AudioTypePcm()
{
	// Set up fixed header values; the rest are negotiable
	hdr.Clear();
	hdr.samples_per_unit = 1;
	hdr.encoding = LINEAR;
}

// Test conversion possibilities.
// Return TRUE if conversion to/from the specified type is possible.
Boolean AudioTypePcm::
CanConvert(
	AudioHdr	h) const		// target header
{
	if (h.samples_per_unit != 1)
		return (FALSE);

	switch (h.encoding) {
	case LINEAR:
		switch (h.bytes_per_unit) {
		case 1: case 2: case 4:
			break;
		default:
			return (FALSE);
		}
		break;
	case FLOAT:
		switch (h.bytes_per_unit) {
		case 4: case 8:
			break;
		default:
			return (FALSE);
		}
		break;
	case ULAW:
	case ALAW:
		switch (h.bytes_per_unit) {
		case 1:
			break;
		default:
			return (FALSE);
		}
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

// Clip most negative values and convert to floating-point
inline double AudioTypePcm::
char2dbl(char B)
{
	return ((unsigned char)B == 0x80 ? -1. : (double)B / 127.);
}
inline double AudioTypePcm::
short2dbl(short S)
{
	return ((unsigned short)S == 0x8000 ? -1. : (double)S / 32767.);
}
inline double AudioTypePcm::
long2dbl(long L)
{
	return ((unsigned long)L == 0x80000000 ? -1. : (double)L / 2147483647.);
}
// Convert floating-point to integer, scaled by the appropriate constant
inline long AudioTypePcm::
dbl2long(double D, long C)
{
	return (D >= 1. ? C : D <= -1. ? -C : (long)irint(D * (double)C));
}

// Simple type conversions
inline void AudioTypePcm::
char2short(char *&F, short *&T) { *T++ = ((short)*F++) << 8; }
inline void AudioTypePcm::
char2long(char *&F, long *&T) { *T++ = ((long)*F++) << 24; }
inline void AudioTypePcm::
char2float(char *&F, float *&T) { *T++ = char2dbl(*F++); }
inline void AudioTypePcm::
char2double(char *&F, double *&T) { *T++ = char2dbl(*F++); }
inline void AudioTypePcm::
char2ulaw(char *&F, ulaw *&T) { *T++ = audio_c2u(*F); F++; }
inline void AudioTypePcm::
char2alaw(char *&F, alaw *&T) { *T++ = audio_c2a(*F); F++; }

inline void AudioTypePcm::
short2char(short *&F, char *&T) { *T++ = (char)(*F++ >> 8); }
inline void AudioTypePcm::
short2long(short *&F, long *&T) { *T++ = ((long)*F++) << 16; }
inline void AudioTypePcm::
short2float(short *&F, float *&T) { *T++ = short2dbl(*F++); }
inline void AudioTypePcm::
short2double(short *&F, double *&T) { *T++ = short2dbl(*F++); }
inline void AudioTypePcm::
short2ulaw(short *&F, ulaw *&T) { *T++ = audio_s2u(*F); F++; }
inline void AudioTypePcm::
short2alaw(short *&F, alaw *&T) { *T++ = audio_s2a(*F); F++; }

inline void AudioTypePcm::
long2char(long *&F, char *&T) { *T++ = (char)(*F++ >> 24); }
inline void AudioTypePcm::
long2short(long *&F, short *&T) { *T++ = (short)(*F++ >> 16); }
inline void AudioTypePcm::
long2float(long *&F, float *&T) { *T++ = long2dbl(*F++); }
inline void AudioTypePcm::
long2double(long *&F, double *&T) { *T++ = long2dbl(*F++); }
inline void AudioTypePcm::
long2ulaw(long *&F, ulaw *&T) { *T++ = audio_l2u(*F); F++; }
inline void AudioTypePcm::
long2alaw(long *&F, alaw *&T) { *T++ = audio_l2a(*F); F++; }

inline void AudioTypePcm::
float2char(float *&F, char *&T) { *T++ = (char)dbl2long(*F++, 127); }
inline void AudioTypePcm::
float2short(float *&F, short *&T) { *T++ = (short)dbl2long(*F++, 32767); }
inline void AudioTypePcm::
float2long(float *&F, long *&T) { *T++ = dbl2long(*F++, 2147483647); }
inline void AudioTypePcm::
float2double(float *&F, double *&T) { *T++ = *F++; }
inline void AudioTypePcm::
float2ulaw(float *&F, ulaw *&T) { *T++ = audio_s2u(dbl2long(*F++, 32767)); }
inline void AudioTypePcm::
float2alaw(float *&F, alaw *&T) { *T++ = audio_s2a(dbl2long(*F++, 32767)); }

inline void AudioTypePcm::
double2char(double *&F, char *&T) { *T++ = (char)dbl2long(*F++, 127); }
inline void AudioTypePcm::
double2short(double *&F, short *&T) { *T++ = (short)dbl2long(*F++, 32767); }
inline void AudioTypePcm::
double2long(double *&F, long *&T) { *T++ = dbl2long(*F++, 2147483647); }
inline void AudioTypePcm::
double2float(double *&F, float *&T) { *T++ = *F++; }
inline void AudioTypePcm::
double2ulaw(double *&F, ulaw *&T) { *T++ = audio_s2u(dbl2long(*F++, 32767)); }
inline void AudioTypePcm::
double2alaw(double *&F, alaw *&T) { *T++ = audio_s2a(dbl2long(*F++, 32767)); }

inline void AudioTypePcm::
ulaw2char(ulaw *&F, char *&T) { *T++ = audio_u2c(*F); F++; }
inline void AudioTypePcm::
ulaw2alaw(ulaw *&F, alaw *&T) { *T++ = audio_u2a(*F); F++; }
inline void AudioTypePcm::
ulaw2short(ulaw *&F, short *&T) { *T++ = audio_u2s(*F); F++; }
inline void AudioTypePcm::
ulaw2long(ulaw *&F, long *&T) { *T++ = audio_u2l(*F); F++; }
inline void AudioTypePcm::
ulaw2float(ulaw *&F, float *&T) { *T++ = short2dbl(audio_u2s(*F)); F++; }
inline void AudioTypePcm::
ulaw2double(ulaw *&F, double *&T) { *T++ = short2dbl(audio_u2s(*F)); F++; }

inline void AudioTypePcm::
alaw2char(alaw *&F, char *&T) { *T++ = audio_a2c(*F); F++; }
inline void AudioTypePcm::
alaw2short(alaw *&F, short *&T) { *T++ = audio_a2s(*F); F++; }
inline void AudioTypePcm::
alaw2long(alaw *&F, long *&T) { *T++ = audio_a2l(*F); F++; }
inline void AudioTypePcm::
alaw2float(alaw *&F, float *&T) { *T++ = short2dbl(audio_a2s(*F)); F++; }
inline void AudioTypePcm::
alaw2double(alaw *&F, double *&T) { *T++ = short2dbl(audio_a2s(*F)); F++; }
inline void AudioTypePcm::
alaw2ulaw(alaw*& F, ulaw*& T) { *T++ = audio_a2u(*F); F++; }


// Convert buffer to the specified type
// May replace the buffer with a new one, if necessary
AudioError AudioTypePcm::
Convert(
	AudioBuffer*&	inbuf,			// data buffer to process
	AudioHdr	outhdr)			// target header
{
	AudioBuffer*	outbuf;
	AudioHdr	inhdr;
	Double		length;
	size_t		frames;
	void*		inptr;
	void*		outptr;
	AudioError	err;

	inhdr = inbuf->GetHeader();
	length = inbuf->GetLength();

	if (Undefined(length))
		return (AUDIO_ERR_BADARG);

	// Make sure we're not being asked to do the impossible
	// XXX - how do we deal with multi-channel data??
	// XXX - need a better error code
	if ((err = inhdr.Validate()) || (err = outhdr.Validate()))
		return (err);
	if ((inhdr.sample_rate != outhdr.sample_rate) ||
	    (inhdr.samples_per_unit != outhdr.samples_per_unit) ||
	    (inhdr.samples_per_unit != 1) ||
	    (inhdr.channels != outhdr.channels))
		return (AUDIO_ERR_HDRINVAL);

	// If the buffer is not referenced, and the target size is no bigger
	// than the current size, the conversion can be done in place
	if (!inbuf->isReferenced() &&
	    (outhdr.bytes_per_unit <= inhdr.bytes_per_unit)) {
		outbuf = inbuf;
	} else {
		// Allocate a new buffer
		outbuf = new AudioBuffer(length, "(PCM conversion buffer)");
		if (outbuf == 0)
			return (AUDIO_UNIXERROR);
		err = outbuf->SetHeader(outhdr);
		if (err != AUDIO_SUCCESS) {
			delete outbuf;
			return (err);
		}
	}

	// Convert from the input type to the output type
	inptr = inbuf->GetAddress();
	outptr = outbuf->GetAddress();
	frames = (size_t)inhdr.Time_to_Samples(length)
		* inhdr.channels;

// Define macro to copy with no data conversion
#define	COPY(N)		if (inptr != outptr) memcpy(outptr, inptr, frames * N)
// Define macro to translate a buffer
// XXX - The temporary pointers are necessary to get the updates

// token catenation different for ANSI cpp v.s. old cpp.
#ifdef __STDC__
#define	MOVE(F, T)	{						\
			    F* ip = (F*)inptr; T* op = (T*)outptr;	\
			    while (frames-- > 0) F ## 2 ## T(ip, op);	\
			}
#else
#define	MOVE(F, T)	{						\
			    F* ip = (F*)inptr; T* op = (T*)outptr;	\
			    while (frames-- > 0) F /* */ 2 /* */ T(ip, op);\
			}
#endif
	switch (inhdr.encoding) {
	case LINEAR:
		switch (outhdr.encoding) {
		case LINEAR:		// Convert linear to linear
			switch (inhdr.bytes_per_unit) {
			case 1:
				switch (outhdr.bytes_per_unit) {
				case 1: COPY(1); break;
				case 2: MOVE(char, short); break;
				case 4: MOVE(char, long); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			case 2:
				switch (outhdr.bytes_per_unit) {
				case 1: MOVE(short, char); break;
				case 2: COPY(2); break;
				case 4: MOVE(short, long); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			case 4:
				switch (outhdr.bytes_per_unit) {
				case 1: MOVE(long, char); break;
				case 2: MOVE(long, short); break;
				case 4: COPY(4); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			default:
				err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case FLOAT:		// Convert linear to float
			switch (inhdr.bytes_per_unit) {
			case 1:
				switch (outhdr.bytes_per_unit) {
				case 4: MOVE(char, float); break;
				case 8: MOVE(char, double); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			case 2:
				switch (outhdr.bytes_per_unit) {
				case 4: MOVE(short, float); break;
				case 8: MOVE(short, double); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			case 4:
				switch (outhdr.bytes_per_unit) {
				case 4: MOVE(long, float); break;
				case 8: MOVE(long, double); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			default:
				err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case ULAW:		// Convert linear to u-law
			switch (inhdr.bytes_per_unit) {
			case 1: MOVE(char, ulaw); break;
			case 2: MOVE(short, ulaw); break;
			case 4: MOVE(long, ulaw); break;
			default: err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case ALAW:		// Convert linear to a-law
			switch (inhdr.bytes_per_unit) {
			case 1: MOVE(char, alaw); break;
			case 2: MOVE(short, alaw); break;
			case 4: MOVE(long, alaw); break;
			default: err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		default:
			err = AUDIO_ERR_HDRINVAL; break;
		}
		break;
	case FLOAT:
		switch (outhdr.encoding) {
		case LINEAR:		// Convert float to linear
			switch (inhdr.bytes_per_unit) {
			case 4:
				switch (outhdr.bytes_per_unit) {
				case 1: MOVE(float, char); break;
				case 2: MOVE(float, short); break;
				case 4: MOVE(float, long); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			case 8:
				switch (outhdr.bytes_per_unit) {
				case 1: MOVE(double, char); break;
				case 2: MOVE(double, short); break;
				case 4: MOVE(double, long); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			default:
				err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case FLOAT:		// Convert float to float
			switch (inhdr.bytes_per_unit) {
			case 4:
				switch (outhdr.bytes_per_unit) {
				case 4: COPY(4); break;
				case 8: MOVE(float, double); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			case 8:
				switch (outhdr.bytes_per_unit) {
				case 4: MOVE(double, float); break;
				case 8: COPY(8); break;
				default: err = AUDIO_ERR_HDRINVAL; break;
				}
				break;
			default:
				err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case ULAW:		// Convert float to u-law
			switch (inhdr.bytes_per_unit) {
			case 4: MOVE(float, ulaw); break;
			case 8: MOVE(double, ulaw); break;
			default: err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case ALAW:		// Convert float to a-law
			switch (inhdr.bytes_per_unit) {
			case 4: MOVE(float, alaw); break;
			case 8: MOVE(double, alaw); break;
			default: err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		default:
			err = AUDIO_ERR_HDRINVAL; break;
		}
		break;
	case ULAW:
		switch (outhdr.encoding) {
		case LINEAR:		// Convert ulaw to linear
			switch (outhdr.bytes_per_unit) {
			case 1: MOVE(ulaw, char); break;
			case 2: MOVE(ulaw, short); break;
			case 4: MOVE(ulaw, long); break;
			default: err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case FLOAT:		// Convert ulaw to float
			switch (outhdr.bytes_per_unit) {
			case 4: MOVE(ulaw, float); break;
			case 8: MOVE(ulaw, double); break;
			default: err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case ULAW:		// Convert ulaw to u-law
			COPY(1); break;
		case ALAW:		// Convert ulaw to a-law
			MOVE(ulaw, alaw); break;
		default:
			err = AUDIO_ERR_HDRINVAL; break;
		}
		break;
	case ALAW:
		switch (outhdr.encoding) {
		case LINEAR:		// Convert alaw to linear
			switch (outhdr.bytes_per_unit) {
			case 1: MOVE(alaw, char); break;
			case 2: MOVE(alaw, short); break;
			case 4: MOVE(alaw, long); break;
			default: err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case FLOAT:		// Convert alaw to float
			switch (outhdr.bytes_per_unit) {
			case 4: MOVE(alaw, float); break;
			case 8: MOVE(alaw, double); break;
			default: err = AUDIO_ERR_HDRINVAL; break;
			}
			break;
		case ALAW:		// Convert alaw to a-law
			COPY(1); break;
		case ULAW:		// Convert alaw to u-law
			MOVE(alaw, ulaw); break;
		default:
			err = AUDIO_ERR_HDRINVAL; break;
		}
		break;
	default:
		err = AUDIO_ERR_HDRINVAL; break;
	}
	if (err) {
		if (outbuf != inbuf)
			delete outbuf;
		return (err);
	}

	// Finish up
	if (outbuf == inbuf) {
		// If the conversion was in-place, set the new header
		(void) inbuf->SetHeader(outhdr);
	} else {
		// This will delete the buffer
		inbuf->Reference();
		inbuf->Dereference();

		// Set the valid data length and replace the pointer
		outbuf->SetLength(length);
		inbuf = outbuf;
	}
	return (AUDIO_SUCCESS);
}

AudioError AudioTypePcm::
Flush(
	AudioBuffer*&	/* buf */)
{
	return (AUDIO_SUCCESS);
}
