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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2019 RackTop Systems.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <AudioHdr.h>

#define	irint(d)	((int)(d))

// Convert a string to lowercase and return an allocated copy of it.
// XXX - There really should be a string-insensitive 8-bit compare routine.
static char *
to_lowercase(
	char	*str)
{
	unsigned char	*oldstr;
	unsigned char	*newstr;
	int		i;

	oldstr = (unsigned char *) str;
	newstr = new unsigned char [strlen(str) + 1];
	for (i = 0; ; i++) {
		if (isupper(oldstr[i]))
			newstr[i] = tolower(oldstr[i]);
		else
			newstr[i] = oldstr[i];
		if (oldstr[i] == '\0')
			break;
	}
	return ((char *)newstr);
}



// class AudioHdr parsing methods


// Return a string containing the sample rate
char *AudioHdr::
RateString() const
{
	char	*str;
	int	ratek;
	int	rateh;
	int	prec;

	str = new char[32];
	ratek = sample_rate / 1000;
	rateh = sample_rate % 1000;
	if (rateh == 0) {
		(void) sprintf(str, "%dkHz", ratek);
	} else {
		// scale down to print minimum digits after the decimal point
		prec = 3;
		if ((rateh % 10) == 0) {
			prec--;
			rateh /= 10;
		}
		if ((rateh % 10) == 0) {
			prec--;
			rateh /= 10;
		}
		(void) sprintf(str, "%d.%0*dkHz", ratek, prec, rateh);
	}
	return (str);
}

// Return a string containing the number of channels
char *AudioHdr::
ChannelString() const
{
	char	*str;

	str = new char[32];
	switch (channels) {
	case 1:
		(void) sprintf(str, "mono");
		break;
	case 2:
		(void) sprintf(str, "stereo");
		break;
	case 4:
		(void) sprintf(str, "quad");
		break;
	default:
		(void) sprintf(str, "%d-channel", channels);
		break;
	}
	return (str);
}

// Return a string containing the encoding
char *AudioHdr::
EncodingString() const
{
	char	*str;
	Double	prec;
	int	iprec;

	str = new char[64];
	if ((samples_per_unit == 0) || (bytes_per_unit == 0) ||
	    (encoding == NONE)) {
		(void) sprintf(str, "???");
	} else {
		// First encode precision
		iprec = (bytes_per_unit * 8) / samples_per_unit;
		prec = ((Double)bytes_per_unit * 8.) / (Double)samples_per_unit;
		if (prec == (Double) iprec) {
			(void) sprintf(str, "%d-bit ", iprec);
		} else {
			(void) sprintf(str, "%.1f-bit ", double(prec));
		}

		// Then encode format
		switch (encoding) {
		case ULAW:
			// XXX - See bug 1121000
			// XXX - (void) strcat(str, "µ-law");
			(void) strcat(str, "u-law");
			break;
		case ALAW:
			(void) strcat(str, "A-law");
			break;
		case LINEAR:
			(void) strcat(str, "linear");
			break;
		case FLOAT:
			(void) strcat(str, "float");
			break;
		case G721:
			(void) strcat(str, "G.721 ADPCM");
			break;
		case G722:
			(void) strcat(str, "G.722 ADPCM");
			break;
		case G723:
			(void) strcat(str, "G.723 ADPCM");
			break;
		case DVI:
			(void) strcat(str, "DVI ADPCM");
			break;
		default:
			(void) strcat(str, "???");
			break;
		}
	}
	return (str);
}

// Return a string containing the entire audio encoding
char *AudioHdr::
FormatString() const
{
	char	*str;
	char	*rate;
	char	*chan;
	char	*enc;

	str = new char[4 * 32];

	enc = EncodingString();
	rate = RateString();
	chan = ChannelString();
	(void) sprintf(str, "%s, %s, %s", enc, rate, chan);
	delete rate;
	delete chan;
	delete enc;
	return (str);
}

// Parse a string containing the sample rate
AudioError AudioHdr::
RateParse(
	char		*str)
{
static char		*lib_khz = NULL;
static char		*lib_hz = NULL;

	double		r;
	int		rate;
	char		khzbuf[16];
	char		*khz;

	if (str == NULL)
		return (AUDIO_ERR_BADARG);

	// Init i18n string translations
	if (lib_khz == NULL) {
		lib_khz = to_lowercase(_MGET_("khz"));
		lib_hz = to_lowercase(_MGET_("hz"));
	}

	// Scan for a number followed by an optional khz designator
	switch (sscanf(str, " %lf %15s", &r, khzbuf)) {
	case 2:
		// Process 'khz', if present, and fall through
		khz = to_lowercase(khzbuf);
		if ((strcmp(khz, "khz") == 0) ||
		    (strcmp(khz, "khertz") == 0) ||
		    (strcmp(khz, "kilohertz") == 0) ||
		    (strcmp(khz, "k") == 0) ||
		    (strcoll(khz, lib_khz) == 0)) {
			r *= 1000.;
		} else if ((strcmp(khz, "hz") != 0) &&
		    (strcmp(khz, "hertz") != 0) &&
		    (strcoll(khz, lib_hz) != 0)) {
			delete khz;
			return (AUDIO_ERR_BADARG);
		}
		delete khz;
		/* FALLTHROUGH */
	case 1:
		rate = irint(r);
		break;
	default:
		return (AUDIO_ERR_BADARG);
	}
	// Check for reasonable bounds
	if ((rate <= 0) || (rate > 500000)) {
		return (AUDIO_ERR_BADARG);
	}
	sample_rate = (unsigned int) rate;
	return (AUDIO_SUCCESS);
}

// Parse a string containing the number of channels
AudioError AudioHdr::
ChannelParse(
	char		*str)
{
static char		*lib_chan = NULL;
static char		*lib_mono = NULL;
static char		*lib_stereo = NULL;
	char		cstrbuf[16];
	char		*cstr;
	char		xtra[4];
	int		chan;

	// Init i18n string translations
	if (lib_chan == NULL) {
		lib_chan = to_lowercase(_MGET_("channel"));
		lib_mono = to_lowercase(_MGET_("mono"));
		lib_stereo = to_lowercase(_MGET_("stereo"));
	}

	// Parse a number, followed by optional "-channel"
	switch (sscanf(str, " %d %15s", &chan, cstrbuf)) {
	case 2:
		cstr = to_lowercase(cstrbuf);
		if ((strcmp(cstr, "-channel") != 0) &&
		    (strcmp(cstr, "-chan") != 0) &&
		    (strcoll(cstr, lib_chan) != 0)) {
			delete cstr;
			return (AUDIO_ERR_BADARG);
		}
		delete cstr;
	case 1:
		break;
	default:
		// If no number, look for reasonable keywords
		if (sscanf(str, " %15s %1s", cstrbuf, xtra) != 1) {
			return (AUDIO_ERR_BADARG);
		}
		cstr = to_lowercase(cstrbuf);
		if ((strcmp(cstr, "mono") == 0) ||
		    (strcmp(cstr, "monaural") == 0) ||
		    (strcoll(cstr, lib_mono) == 0)) {
			chan = 1;
		} else if ((strcmp(cstr, "stereo") == 0) ||
		    (strcmp(cstr, "dual") == 0) ||
		    (strcoll(cstr, lib_stereo) == 0)) {
			chan = 2;
		} else if ((strcmp(cstr, "quad") == 0) ||
		    (strcmp(cstr, "quadrophonic") == 0)) {
			chan = 4;
		} else {
			delete cstr;
			return (AUDIO_ERR_BADARG);
		}
		delete cstr;
	}
	if ((chan <= 0) || (chan > 256)) {
		return (AUDIO_ERR_BADARG);
	}
	channels = (unsigned int) chan;
	return (AUDIO_SUCCESS);
}

// Parse a string containing the audio encoding
AudioError AudioHdr::
EncodingParse(
	char		*str)
{
static char		*lib_bit = NULL;
static char		*lib_ulaw = NULL;
static char		*lib_Alaw = NULL;
static char		*lib_linear = NULL;
	int		i;
	char		*p;
	char		estrbuf[64];
	char		*estr;
	char		xtrabuf[32];
	char		*xtra;
	char		*xp;
	char		buf[BUFSIZ];
	char		*cp;
	double		prec;

	// Init i18n string translations
	if (lib_bit == NULL) {
		lib_bit = to_lowercase(_MGET_("bit"));
		lib_ulaw = to_lowercase(_MGET_("u-law"));
		lib_Alaw = to_lowercase(_MGET_("A-law"));
		lib_linear = to_lowercase(_MGET_("linear8"));
		lib_linear = to_lowercase(_MGET_("linear"));
	}

	// first copy and remove leading spaces
	(void) strncpy(buf, str, BUFSIZ);
	for (cp = buf; *cp == ' '; cp++)
		continue;

	// Delimit the precision.  If there is one, parse it.
	prec = 0.;
	p = strchr(cp, ' ');
	if (p != NULL) {
		*p++ = '\0';
		i = sscanf(cp, " %lf %15s", &prec, xtrabuf);
		if (i == 0) {
			return (AUDIO_ERR_BADARG);
		}
		if (i == 2) {
			// convert to lowercase and skip leading "-", if any
			xtra = to_lowercase(xtrabuf);
			xp = (xtra[0] == '-') ? &xtra[1] : &xtra[0];

			if ((strcmp(xp, "bit") != 0) &&
			    (strcoll(xp, lib_bit) != 0)) {
				delete xtra;
				return (AUDIO_ERR_BADARG);
			}
			delete xtra;
		}
		if ((prec <= 0.) || (prec > 512.)) {
			return (AUDIO_ERR_BADARG);
		}

		// Don't be fooled by "8 bit"
		i = sscanf(p, " %15s", xtrabuf);
		if (i == 1) {
			// convert to lowercase and skip leading "-", if any
			xtra = to_lowercase(xtrabuf);
			xp = (xtra[0] == '-') ? &xtra[1] : &xtra[0];
			if ((strcmp(xp, "bit") == 0) ||
			    (strcoll(xp, lib_bit) == 0)) {
				    xp = strchr(p, ' ');
				    if (xp != NULL)
					    p = xp;
				    else
					    p += strlen(xtrabuf);
			}
			delete xtra;
		}
	} else {
		p = cp;
	}

	i = sscanf(p, " %31s %31s", estrbuf, xtrabuf);

	// If "adpcm" appended with a space, concatenate it
	if (i == 2) {
		xtra = to_lowercase(xtrabuf);
		if (strcmp(xtra, "adpcm") == 0) {
			(void) strcat(estrbuf, xtra);
			i = 1;
		}
		delete xtra;
	}
	if (i == 1) {
		estr = to_lowercase(estrbuf);
		if ((strcmp(estr, "ulaw") == 0) ||
		    (strcmp(estr, "u-law") == 0) ||
		    (strcmp(estr, "µlaw") == 0) ||
		    (strcmp(estr, "µ-law") == 0) ||
		    (strcmp(estr, "mulaw") == 0) ||
		    (strcmp(estr, "mu-law") == 0) ||
		    (strcoll(estr, lib_ulaw) == 0)) {
			if ((prec != 0.) && (prec != 8.))
				return (AUDIO_ERR_BADARG);
			encoding = ULAW;
			samples_per_unit = 1;
			bytes_per_unit = 1;
		} else if ((strcmp(estr, "alaw") == 0) ||
		    (strcmp(estr, "a-law") == 0) ||
		    (strcoll(estr, lib_Alaw) == 0)) {
			if ((prec != 0.) && (prec != 8.))
				return (AUDIO_ERR_BADARG);
			encoding = ALAW;
			samples_per_unit = 1;
			bytes_per_unit = 1;

		} else if ((strcmp(estr, "linear") == 0) ||
		    (strcmp(estr, "lin") == 0) ||
		    (strcmp(estr, "pcm") == 0) ||
		    (strcoll(estr, lib_linear) == 0)) {
			if ((prec != 0.) && (prec != 8.) && (prec != 16.) &&
			    (prec != 24.) && (prec != 32.))
				return (AUDIO_ERR_BADARG);
			if (prec == 0.)
				prec = 16.;
			encoding = LINEAR;
			samples_per_unit = 1;
			bytes_per_unit = irint(prec / 8.);

		} else if ((strcmp(estr, "linear8") == 0) ||
		    (strcmp(estr, "lin8") == 0) ||
		    (strcmp(estr, "pcm8") == 0)) {
			if ((prec != 0.) && (prec != 8.))
				return (AUDIO_ERR_BADARG);
			prec = 8.;
			encoding = LINEAR;
			samples_per_unit = 1;
			bytes_per_unit = irint(prec / 8.);

		} else if ((strcmp(estr, "linear16") == 0) ||
		    (strcmp(estr, "lin16") == 0) ||
		    (strcmp(estr, "pcm16") == 0)) {
			if ((prec != 0.) && (prec != 16.))
				return (AUDIO_ERR_BADARG);
			prec = 16.;
			encoding = LINEAR;
			samples_per_unit = 1;
			bytes_per_unit = irint(prec / 8.);

		} else if ((strcmp(estr, "linear24") == 0) ||
		    (strcmp(estr, "lin24") == 0) ||
		    (strcmp(estr, "pcm24") == 0)) {
			if ((prec != 0.) && (prec != 24.))
				return (AUDIO_ERR_BADARG);
			prec = 24.;
			encoding = LINEAR;
			samples_per_unit = 1;
			bytes_per_unit = irint(prec / 8.);

		} else if ((strcmp(estr, "linear32") == 0) ||
		    (strcmp(estr, "lin32") == 0) ||
		    (strcmp(estr, "pcm32") == 0)) {
			if ((prec != 0.) && (prec != 32.))
				return (AUDIO_ERR_BADARG);
			prec = 32.;
			encoding = LINEAR;
			samples_per_unit = 1;
			bytes_per_unit = irint(prec / 8.);

		} else if ((strcmp(estr, "float") == 0) ||
		    (strcmp(estr, "floatingpoint") == 0) ||
		    (strcmp(estr, "floating-point") == 0)) {
			if ((prec != 0.) && (prec != 32.) && (prec != 64.))
				return (AUDIO_ERR_BADARG);
			if (prec == 0.)
				prec = 64.;
			encoding = FLOAT;
			samples_per_unit = 1;
			bytes_per_unit = irint(prec / 8.);

		} else if ((strcmp(estr, "float32") == 0) ||
		    (strcmp(estr, "floatingpoint32") == 0) ||
		    (strcmp(estr, "floating-point32") == 0)) {
			if ((prec != 0.) && (prec != 32.))
				return (AUDIO_ERR_BADARG);
			prec = 32.;
			encoding = FLOAT;
			samples_per_unit = 1;
			bytes_per_unit = irint(prec / 8.);

		} else if ((strcmp(estr, "float64") == 0) ||
		    (strcmp(estr, "double") == 0) ||
		    (strcmp(estr, "floatingpoint64") == 0) ||
		    (strcmp(estr, "floating-point64") == 0)) {
			if ((prec != 0.) && (prec != 64.))
				return (AUDIO_ERR_BADARG);
			prec = 64.;
			encoding = FLOAT;
			samples_per_unit = 1;
			bytes_per_unit = irint(prec / 8.);

		} else if ((strcmp(estr, "g.721") == 0) ||
		    (strcmp(estr, "g721") == 0) ||
		    (strcmp(estr, "g.721adpcm") == 0) ||
		    (strcmp(estr, "g721adpcm") == 0)) {
			if ((prec != 0.) && (prec != 4.))
				return (AUDIO_ERR_BADARG);
			encoding = G721;
			samples_per_unit = 2;
			bytes_per_unit = 1;

		} else if ((strcmp(estr, "g.722") == 0) ||
		    (strcmp(estr, "g722") == 0) ||
		    (strcmp(estr, "g.722adpcm") == 0) ||
		    (strcmp(estr, "g722adpcm") == 0)) {
			if ((prec != 0.) && (prec != 8.))
				return (AUDIO_ERR_BADARG);
			encoding = G722;
			samples_per_unit = 1;
			bytes_per_unit = 1;

		} else if ((strcmp(estr, "g.723") == 0) ||
		    (strcmp(estr, "g723") == 0) ||
		    (strcmp(estr, "g.723adpcm") == 0) ||
		    (strcmp(estr, "g723adpcm") == 0)) {
			if ((prec != 0.) && (prec != 3.) && (prec != 5.))
				return (AUDIO_ERR_BADARG);
			if (prec == 0.)
				prec = 3.;
			encoding = G723;
			samples_per_unit = 8;
			bytes_per_unit = irint(prec);

		} else if ((strcmp(estr, "g.723-3") == 0) ||
		    (strcmp(estr, "g.723_3") == 0) ||
		    (strcmp(estr, "g.723.3") == 0) ||
		    (strcmp(estr, "g723-3") == 0) ||
		    (strcmp(estr, "g723_3") == 0) ||
		    (strcmp(estr, "g723.3") == 0)) {
			if ((prec != 0.) && (prec != 3.))
				return (AUDIO_ERR_BADARG);
			prec = 3.;
			encoding = G723;
			samples_per_unit = 8;
			bytes_per_unit = irint(prec);

		} else if ((strcmp(estr, "g.723-5") == 0) ||
		    (strcmp(estr, "g.723_5") == 0) ||
		    (strcmp(estr, "g.723.5") == 0) ||
		    (strcmp(estr, "g723-5") == 0) ||
		    (strcmp(estr, "g723_5") == 0) ||
		    (strcmp(estr, "g723.5") == 0)) {
			if ((prec != 0.) && (prec != 5.))
				return (AUDIO_ERR_BADARG);
			prec = 5.;
			encoding = G723;
			samples_per_unit = 8;
			bytes_per_unit = irint(prec);

		} else if ((strcmp(estr, "dvi") == 0) ||
		    (strcmp(estr, "dviadpcm") == 0)) {
			if ((prec != 0.) && (prec != 4.))
				return (AUDIO_ERR_BADARG);
			encoding = DVI;
			samples_per_unit = 2;
			bytes_per_unit = 1;

		} else {
			delete estr;
			return (AUDIO_ERR_BADARG);
		}
		delete estr;
	} else {
		return (AUDIO_ERR_BADARG);
	}
	return (AUDIO_SUCCESS);
}

// Parse a string containing the comma-separated audio encoding
// Format is: "enc, chan, rate"
//	XXX - some countries use comma instead of decimal point
//	so there may be a problem with "44,1 khz"
AudioError AudioHdr::
FormatParse(
	char		*str)
{
	char		*pstr;
	char		*ptr;
	char		*p;
	AudioHdr	newhdr;
	AudioError	err;

	pstr = new char[strlen(str) + 1];
	(void) strcpy(pstr, str);
	ptr = pstr;

	// Delimit and parse the precision string
	p = strchr(ptr, ',');
	if (p == NULL)
		p = strchr(ptr, ' ');
	if (p == NULL) {
		err = AUDIO_ERR_BADARG;
		goto errret;
	}
	*p++ = '\0';
	err = newhdr.EncodingParse(ptr);

	// Delimit and parse the sample rate string
	if (!err) {
		ptr = p;
		p = strchr(ptr, ',');
		if (p == NULL)
			p = strchr(ptr, ' ');
		if (p == NULL) {
			err = AUDIO_ERR_BADARG;
			goto errret;
		}
		*p++ = '\0';
		err = newhdr.RateParse(ptr);
	}

	// Finally, parse the channels string
	if (!err) {
		err = newhdr.ChannelParse(p);
	}

	// Validate the resulting header
	if (!err)
		err = newhdr.Validate();
	if (!err)
		*this = newhdr;
errret:
	delete pstr;
	return (err);
}
