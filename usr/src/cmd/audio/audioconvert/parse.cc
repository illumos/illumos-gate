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
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include <Audio.h>
#include <AudioHdr.h>

#include <parse.h>
#include <convert.h>

static struct keyword_table Keywords[] = {
	(char *)"encoding",		K_ENCODING,
	(char *)"rate",			K_RATE,
	(char *)"channels",		K_CHANNELS,
	(char *)"offset",		K_OFFSET,
	(char *)"format",		K_FORMAT,
	NULL,				K_NULL,
};

// Lookup the string in a keyword table. return the token associated with it.
keyword_type
do_lookup(
	char			*s,
	struct keyword_table	*kp)
{
	struct keyword_table	*tkp = NULL;

	for (; kp && kp->name; kp++) {
		if (strncmp(s, kp->name, strlen(s)) == 0) {
			// check if exact match
			if (strlen(s) == strlen(kp->name)) {
				return (kp->type);
			} else {
				// already have another partial match, so
				// it's ambiguous
				if (tkp) {
					return (K_AMBIG);
				} else {
					tkp = kp;
				}
			}
		}
	}

	// at end of list. if there was a partial match, return it, if
	// not, there's no match....
	if (tkp) {
		return (tkp->type);
	} else {
		return (K_NULL);
	}
}

// Parse a file format specification
int
fileformat_parse(
	char		*val,
	format_type&	format)
{
	// XXX - other formats later ...
	if (strcasecmp(val, "sun") == 0) {
		format = F_SUN;
	} else if (strcasecmp(val, "raw") == 0) {
		format = F_RAW;
	} else if (strcasecmp(val, "aiff") == 0) {
		Err(MGET("AIFF not yet supported\n"));
		return (-1);
	} else {
		return (-1);
	}
	return (0);
}

// Parse an audio format keyword
int
audioformat_parse(
	char		*val,
	AudioHdr&	hdr)
{
	// check if it's "cd" or "dat" or "voice".
	// these set the precision and encoding, etc.
	if (strcasecmp(val, "dat") == 0) {
		hdr.sample_rate = 48000;
		hdr.channels = 2;
		hdr.encoding = LINEAR;
		hdr.samples_per_unit = 1;
		hdr.bytes_per_unit = 2;
	} else if (strcasecmp(val, "cd") == 0) {
		hdr.sample_rate = 44100;
		hdr.channels = 2;
		hdr.encoding = LINEAR;
		hdr.samples_per_unit = 1;
		hdr.bytes_per_unit = 2;
	} else if (strcasecmp(val, "voice") == 0) {
		hdr.sample_rate = 8000;
		hdr.channels = 1;
		hdr.encoding = ULAW;
		hdr.samples_per_unit = 1;
		hdr.bytes_per_unit = 1;
	} else {
		return (-1);
	}
	return (0);
}

// Parse a format spec and return an audio header that describes it.
// Format is in the form of: [keyword=]value[,[keyword=]value ...].
int
parse_format(
	char		*s,
	AudioHdr&	hdr,
	format_type&	format,
	off_t&		offset)
{
	char		*cp;
	char		*buf;
	char		*key;
	char		*val;
	char		*cp2;

	offset = 0;
	format = F_SUN;

	// if no string provided, just return ...
	if (!(s && *s))
		return (0);

	// First off, try to parse it as a full format string
	// (it would have to have been quoted).
	// If this works, we're done.
	if (hdr.FormatParse(s) == AUDIO_SUCCESS) {
		return (0);
	}

	buf = strdup(s);	// save a copy of the string

	// XXX - bug alert: if someone has info="xxx,yyy", strtok will
	// break unless we snarf properly snarf the info. punt for now,
	// fix later (since no info supported yet)....

	for (cp = strtok(buf, ","); cp; cp = strtok(NULL, ",")) {
		// Check if there's a '='
		// If so, left side is keyword, right side is value.
		// If not, entire string is value.
		if (cp2 = strchr(cp, '=')) {
			*cp2++ = '\0';
			key = cp;
			val = cp2;

			// Look for the keyword
			switch (do_lookup(key, Keywords)) {
			case K_ENCODING:
				if (hdr.EncodingParse(val)) {
					Err(MGET(
					    "invalid encoding option: %s\n"),
					    val);
					goto parse_error;
				}
				break;
			case K_RATE:
				if (hdr.RateParse(val)) {
					Err(MGET("invalid sample rate: %s\n"),
					    val);
					goto parse_error;
				}
				break;
			case K_CHANNELS:
				if (hdr.ChannelParse(val)) {
					Err(MGET(
					    "invalid channels option: %s\n"),
					    val);
					goto parse_error;
				}
				break;
			case K_FORMAT:
				if (fileformat_parse(val, format) < 0) {
					Err(MGET("unknown format: %s\n"), val);
					goto parse_error;
				}
				break;
			case K_OFFSET:
				offset = (off_t)atoi(val);
				break;
			case K_AMBIG:
				Err(MGET("ambiguous keyword: %s\n"), key);
				goto parse_error;
			case K_NULL:
				Err(MGET("null keyword: =%s\n"), val);
				goto parse_error;
			default:
				Err(MGET("invalid keyword: %s\n"), key);
				goto parse_error;
			}
		} else {
			// No keyword, so try to intuit the value
			// First try encoding, audio, and file format.
			// If they fail, try sample rate and channels.
			val = cp;
			if (hdr.EncodingParse(val) &&
			    (audioformat_parse(val, hdr) < 0) &&
			    (fileformat_parse(val, format) < 0)) {
				// If this looks like sample rate, make sure
				// it is not ambiguous with channels
				if (!hdr.RateParse(val)) {
					if (hdr.sample_rate < 1000) {
						int	x;
						char	y[10];

						if (sscanf(val, " %lf %9s",
						    &x, y) != 1) {
							Err(
					MGET("ambiguous numeric option: %s\n"),
							    val);
							goto parse_error;
						}
					}
				} else if (hdr.ChannelParse(val)) {
					Err(MGET("invalid option value: %s\n"),
					    val);
					goto parse_error;
				}
			}
		}
	}
	free(buf);
	return (0);

parse_error:
	free(buf);
	return (-1);
}
