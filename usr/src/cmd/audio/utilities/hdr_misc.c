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
 * Copyright 1989-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Miscellaneous audio-related operations.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>

#include <libaudio_impl.h>
#include <audio_errno.h>
#include <audio_hdr.h>

/*
 * Convert a byte count into a floating-point time value, in seconds,
 * using the encoding specified in the given audio header structure.
 * Note that the byte count is not the same as the offset in an audio file,
 * since the size of the audio file header is not taken into account.
 */
double
audio_bytes_to_secs(Audio_hdr *hp, unsigned int cnt)
{
	return ((double)cnt /
	    ((double)(hp->channels * hp->bytes_per_unit * hp->sample_rate) /
	    (double)hp->samples_per_unit));
}

/*
 * Convert a floating-point time value, in seconds, to a byte count for
 * the audio encoding in the given audio header.  Note that the byte count
 * is not the same as the offset in an audio file, since the size of the
 * audio file header is not taken into account.
 */
unsigned
audio_secs_to_bytes(Audio_hdr *hp, double sec)
{
	unsigned	offset;

	offset = (unsigned)(0.5 + (sec *
	    ((double)(hp->channels * hp->bytes_per_unit * hp->sample_rate) /
	    (double)hp->samples_per_unit)));

	/* Round down to the start of the nearest sample frame */
	offset -= (offset % (hp->bytes_per_unit * hp->channels));
	return (offset);
}

/*
 * Convert an ASCII time value (hh:mm:ss.dd) into floating-point seconds.
 * Returns value if successfully converted.  Otherwise, returns HUGE_VAL.
 *
 * XXX - currently allows the ridiculous construct:  5.3E3:-47.3E-1:17.3
 */
double
audio_str_to_secs(char *str)
{
	double	val;
	char	*str2;

	val = strtod(str, &str2);	/* get first numeric field */
	if (str2 == str)
		return (HUGE_VAL);

	if (*str2 == ':') {		/* that was hours (or minutes) */
		val *= 60.;
		str = str2 + 1;
		val += strtod(str, &str2);	/* another field is required */
		if (str2 == str)
			return (HUGE_VAL);
	}

	if (*str2 == ':') {		/* converted hours and minutes */
		val *= 60.;
		str = str2 + 1;
		val += strtod(str, &str2);	/* another field is required */
		if (str2 == str)
			return (HUGE_VAL);
	}

	if (*str2 != '\0')
		return (HUGE_VAL);
	return (val);
}

/*
 * Convert floating-point seconds into an ASCII time value (hh:mm:ss.dd).
 *
 * HUGE_VAL is converted to 0:00.  'Precision' specifies the maximum
 * number of digits after the decimal point (-1 allows the max).
 *
 * Store the resulting string in the specified buffer (must be at least
 * AUDIO_MAX_TIMEVAL bytes long).  The string address is returned.
 */
char *
audio_secs_to_str(double sec, char *str, int precision)
{
	char		*p;
	unsigned	ovflow;
	int		hours;
	double		x;
	char		buf[64];

	if (sec == HUGE_VAL) {
		(void) strcpy(str, "0:00");
		return (str);
	}

	/* Limit precision arg to reasonable value */
	if ((precision > 10) || (precision < 0))
		precision = 10;

	/* If negative, write a minus sign and get on with it. */
	p = str;
	if (sec < 0.) {
		sec = -sec;

		/* Round off within precision to avoid -.01 printing as -0:00 */
		(void) sprintf(buf, "%.*f", precision, sec);
		(void) sscanf(buf, "%lf", &sec);
		if (sec > 0.)
			*p++ = '-';
	}

	/* Round off within precision to avoid 1:59.999 printing as 1:60.00 */
	x = fmod(sec, 60.);
	sec -= x;
	(void) sprintf(buf, "%.*f", precision, x);
	(void) sscanf(buf, "%lf", &x);
	sec += x;

	if (sec >= 60.) {
		/* Extract minutes */
		ovflow = ((unsigned)sec) / 60;
		sec -= (double)(ovflow * 60);
		hours = (ovflow >= 60);
		if (hours) {
			/* convert hours */
			(void) sprintf(p, "%d:", ovflow / 60);
			p = &p[strlen(p)];
			ovflow %= 60;
		}
		/* convert minutes (use two digits if hours printed) */
		(void) sprintf(p, "%0*d:", (hours ? 2 : 1), ovflow);
		p = &p[strlen(p)];
	} else {
		*p++ = '0';
		*p++ = ':';
	}

	if (sec < 10.)
		*p++ = '0';
	(void) sprintf(p, "%.*f", precision, sec);
	return (str);
}

/*
 * Compare the encoding fields of two audio headers.
 * Return 0 if they are the same, 1 if they are the same except for
 * sample rate, else -1.
 */
int
audio_cmp_hdr(Audio_hdr *h1, Audio_hdr *h2)
{
	if ((h1->encoding != h2->encoding) ||
	    (h1->bytes_per_unit != h2->bytes_per_unit) ||
	    (h1->channels != h2->channels) ||
	    (h1->samples_per_unit != h2->samples_per_unit))
		return (-1);

	if (h1->sample_rate != h2->sample_rate)
		return (1);

	return (0);
}

/*
 * Interpret the encoding information in the specified header
 * and return an appropriate string in the supplied buffer.
 * The buffer should contain at least AUDIO_MAX_ENCODE_INFO bytes.
 * The returned string is something like:
 *	"stereo 16-bit linear PCM @ 44.1kHz"
 *
 * Returns AUDIO_ERR_BADHDR if the header cannot be interpreted.
 */
int
audio_enc_to_str(Audio_hdr *hdrp, char *str)
{
	char		*chan;
	char		*prec;
	char		*enc;
	char		cbuf[AUDIO_MAX_ENCODE_INFO];
	char		pbuf[AUDIO_MAX_ENCODE_INFO];
	char		sbuf[AUDIO_MAX_ENCODE_INFO];
	int		err;

	err = AUDIO_SUCCESS;

	switch (hdrp->channels) {
	case 0:
		chan = "(zero channels?)";
		err = AUDIO_ERR_BADHDR;
		break;
	case 1:
		chan = "mono"; break;
	case 2:
		chan = "stereo"; break;
	case 4:
		chan = "quad"; break;
	default:
		chan = pbuf;
		(void) sprintf(cbuf, "%u-channel", hdrp->channels); break;
	}

	switch (hdrp->encoding) {
	case AUDIO_ENCODING_ULAW:
		enc = "u-law";
		goto pcm;
	case AUDIO_ENCODING_ALAW:
		enc = "A-law";
		goto pcm;
	case AUDIO_ENCODING_LINEAR:
		enc = "linear PCM";
		goto pcm;
	case AUDIO_ENCODING_FLOAT:
		enc = "floating-point";
pcm:
		if (hdrp->samples_per_unit != 1)
			goto unknown;
		prec = pbuf;
		(void) sprintf(pbuf, "%u-bit", hdrp->bytes_per_unit * 8);
		break;

	default:
unknown:
		err = AUDIO_ERR_ENCODING;
		enc = "(unknown encoding?)";
		if (hdrp->samples_per_unit != 0) {
			prec = pbuf;
			(void) sprintf(pbuf, "%f-bit",
			    (double)(hdrp->bytes_per_unit * 8) /
			    (double)hdrp->samples_per_unit);
		} else {
			prec = "(unknown precision?)";
			err = AUDIO_ERR_BADHDR;
		}
	}

	(void) sprintf(sbuf, "%.3fkHz", ((double)hdrp->sample_rate / 1000.));
	(void) sprintf(str, "%s %s %s @ %s", chan, prec, enc, sbuf);
	return (err);
}
