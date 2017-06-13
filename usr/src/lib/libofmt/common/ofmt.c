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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ofmt.h>
#include <sys/termios.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <libintl.h>

/*
 * functions and structures to internally process a comma-separated string
 * of fields selected for output.
 */
typedef struct {
	char	*s_buf;
	const char **s_fields;	/* array of pointers to the fields in s_buf */
	uint_t	s_nfields;	/* the number of fields in s_buf */
	uint_t	s_currfield;	/* the current field being processed */
} split_t;
static void splitfree(split_t *);
static split_t *split_str(const char *, uint_t);
static split_t *split_fields(const ofmt_field_t *, uint_t, uint_t);

/*
 * The state of the output is tracked in a ofmt_state_t structure.
 * Each os_fields[i] entry points at an ofmt_field_t array for
 * the sub-command whose contents are provided by the caller, with
 * os_nfields set to the number of requested fields.
 */
typedef struct ofmt_state_s {
	ofmt_field_t  	*os_fields;
	uint_t		os_nfields;
	boolean_t	os_lastfield;
	uint_t		os_overflow;
	struct winsize	os_winsize;
	int		os_nrow;
	uint_t		os_flags;
	int		os_nbad;
	char		**os_badfields;
	int		os_maxnamelen;	/* longest name (f. multiline) */
} ofmt_state_t;
/*
 * A B_TRUE return value from the callback function will print out the contents
 * of the output buffer, except when the buffer is returned with the empty
 * string "", in which case the  OFMT_VAL_UNDEF will be printed.
 *
 * If the callback function returns B_FALSE, the "?" string will be emitted.
 */
#define	OFMT_VAL_UNDEF		"--"
#define	OFMT_VAL_UNKNOWN	"?"

/*
 * The maximum number of rows supported by the OFMT_WRAP option.
 */
#define	OFMT_MAX_ROWS		128

static void ofmt_print_header(ofmt_state_t *);
static void ofmt_print_field(ofmt_state_t *, ofmt_field_t *, const char *,
    boolean_t);

/*
 * Split `str' into at most `maxfields' fields, Return a pointer to a
 * split_t containing the split fields, or NULL on failure.
 */
static split_t *
split_str(const char *str, uint_t maxfields)
{
	char	*field, *token, *lasts = NULL;
	split_t	*sp;

	if (*str == '\0' || maxfields == 0)
		return (NULL);

	sp = calloc(sizeof (split_t), 1);
	if (sp == NULL)
		return (NULL);

	sp->s_buf = strdup(str);
	sp->s_fields = malloc(sizeof (char *) * maxfields);
	if (sp->s_buf == NULL || sp->s_fields == NULL)
		goto fail;

	token = sp->s_buf;
	while ((field = strtok_r(token, ",", &lasts)) != NULL) {
		if (sp->s_nfields == maxfields)
			goto fail;
		token = NULL;
		sp->s_fields[sp->s_nfields++] = field;
	}
	return (sp);
fail:
	splitfree(sp);
	return (NULL);
}

/*
 * Split `fields' into at most `maxfields' fields. Return a pointer to
 * a split_t containing the split fields, or NULL on failure. Invoked
 * when all fields are implicitly selected at handle creation by
 * passing in a NULL fields_str
 */
static split_t *
split_fields(const ofmt_field_t *template, uint_t maxfields, uint_t maxcols)
{
	split_t	*sp;
	int i, cols;

	sp = calloc(sizeof (split_t), 1);
	if (sp == NULL)
		return (NULL);

	sp->s_fields = malloc(sizeof (char *) * maxfields);
	if (sp->s_fields == NULL)
		goto fail;
	cols = 0;
	for (i = 0; i < maxfields; i++) {
		cols += template[i].of_width;
		/*
		 * If all fields are implied without explicitly passing
		 * in a fields_str, build a list of field names, stopping
		 * when we run out of columns.
		 */
		if (maxcols > 0 && cols > maxcols)
			break;
		sp->s_fields[sp->s_nfields++] = template[i].of_name;
	}
	return (sp);
fail:
	splitfree(sp);
	return (NULL);
}

/*
 * Free the split_t structure pointed to by `sp'.
 */
static void
splitfree(split_t *sp)
{
	if (sp == NULL)
		return;
	free(sp->s_buf);
	free(sp->s_fields);
	free(sp);
}

/*
 * Open a handle to be used for printing formatted output.
 */
ofmt_status_t
ofmt_open(const char *str, const ofmt_field_t *template, uint_t flags,
    uint_t maxcols, ofmt_handle_t *ofmt)
{
	split_t		*sp;
	uint_t		i, j, of_index;
	const ofmt_field_t *ofp;
	ofmt_field_t	*of;
	ofmt_state_t	*os = NULL;
	int		nfields = 0;
	ofmt_status_t	error = OFMT_SUCCESS;
	boolean_t	parsable = (flags & OFMT_PARSABLE);
	boolean_t	wrap = (flags & OFMT_WRAP);
	boolean_t	multiline = (flags & OFMT_MULTILINE);

	*ofmt = NULL;
	if (parsable) {
		if (multiline)
			return (OFMT_EPARSEMULTI);
		/*
		 * For parsable output mode, the caller always needs
		 * to specify precisely which fields are to be selected,
		 * since the set of fields may change over time.
		 */
		if (str == NULL || str[0] == '\0')
			return (OFMT_EPARSENONE);
		if (strcasecmp(str, "all") == 0)
			return (OFMT_EPARSEALL);
		if (wrap)
			return (OFMT_EPARSEWRAP);
	}
	if (template == NULL)
		return (OFMT_ENOTEMPLATE);
	for (ofp = template; ofp->of_name != NULL; ofp++)
		nfields++;
	/*
	 * split str into the columns selected, or construct the
	 * full set of columns (equivalent to -o all).
	 */
	if (str != NULL && strcasecmp(str, "all") != 0) {
		sp = split_str(str, nfields);
	} else {
		if (parsable || (str != NULL && strcasecmp(str, "all") == 0))
			maxcols = 0;
		sp = split_fields(template, nfields, maxcols);
	}
	if (sp == NULL)
		goto nomem;

	os = calloc(sizeof (ofmt_state_t) +
	    sp->s_nfields * sizeof (ofmt_field_t), 1);
	if (os == NULL)
		goto nomem;
	*ofmt = os;
	os->os_fields = (ofmt_field_t *)&os[1];
	os->os_flags = flags;

	of = os->os_fields;
	of_index = 0;
	/*
	 * sp->s_nfields is the number of fields requested in fields_str.
	 * nfields is the number of fields in template.
	 */
	for (i = 0; i < sp->s_nfields; i++) {
		for (j = 0; j < nfields; j++) {
			if (strcasecmp(sp->s_fields[i],
			    template[j].of_name) == 0) {
				break;
			}
		}
		if (j == nfields) {
			int nbad = os->os_nbad++;

			error = OFMT_EBADFIELDS;
			if (os->os_badfields == NULL) {
				os->os_badfields = malloc(sp->s_nfields *
				    sizeof (char *));
				if (os->os_badfields == NULL)
					goto nomem;
			}
			os->os_badfields[nbad] = strdup(sp->s_fields[i]);
			if (os->os_badfields[nbad] == NULL)
				goto nomem;
			continue;
		}
		of[of_index].of_name = strdup(template[j].of_name);
		if (of[of_index].of_name == NULL)
			goto nomem;
		if (multiline) {
			int n = strlen(of[of_index].of_name);

			os->os_maxnamelen = MAX(n, os->os_maxnamelen);
		}
		of[of_index].of_width = template[j].of_width;
		of[of_index].of_id = template[j].of_id;
		of[of_index].of_cb = template[j].of_cb;
		of_index++;
	}
	splitfree(sp);
	if (of_index == 0) /* all values in str are bogus */
		return (OFMT_ENOFIELDS);
	os->os_nfields = of_index; /* actual number of fields printed */
	ofmt_update_winsize(*ofmt);
	return (error);
nomem:
	error = OFMT_ENOMEM;
	if (os != NULL)
		ofmt_close(os);
	*ofmt = NULL;
	splitfree(sp);
	return (error);
}

/*
 * free resources associated with the ofmt_handle_t
 */
void
ofmt_close(ofmt_handle_t ofmt)
{
	ofmt_state_t *os = ofmt;
	int i;

	if (os == NULL)
		return;
	for (i = 0; i < os->os_nfields; i++)
		free(os->os_fields[i].of_name);
	for (i = 0; i < os->os_nbad; i++)
		free(os->os_badfields[i]);
	free(os->os_badfields);
	free(os);
}

/*
 * Print the value for the selected field by calling the callback-function
 * registered for the field.
 */
static void
ofmt_print_field(ofmt_state_t *os, ofmt_field_t *ofp, const char *value,
    boolean_t escsep)
{
	uint_t	width = ofp->of_width;
	uint_t	valwidth;
	uint_t	compress;
	boolean_t parsable = (os->os_flags & OFMT_PARSABLE);
	boolean_t multiline = (os->os_flags & OFMT_MULTILINE);
	boolean_t rightjust = (os->os_flags & OFMT_RIGHTJUST);
	char	c;

	/*
	 * Parsable fields are separated by ':'. If such a field contains
	 * a ':' or '\', this character is prefixed by a '\'.
	 */
	if (parsable) {
		if (os->os_nfields == 1) {
			(void) printf("%s", value);
			return;
		}
		while ((c = *value++) != '\0') {
			if (escsep && ((c == ':' || c == '\\')))
				(void) putchar('\\');
			(void) putchar(c);
		}
		if (!os->os_lastfield)
			(void) putchar(':');
	} else if (multiline) {
		if (value[0] == '\0')
			value = OFMT_VAL_UNDEF;
		(void) printf("%*.*s: %s", os->os_maxnamelen,
		    os->os_maxnamelen, ofp->of_name, value);
		if (!os->os_lastfield)
			(void) putchar('\n');
	} else {
		if (os->os_lastfield) {
			if (rightjust)
				(void) printf("%*s", width, value);
			else
				(void) printf("%s", value);
			os->os_overflow = 0;
			return;
		}

		valwidth = strlen(value);
		if (valwidth + os->os_overflow >= width) {
			os->os_overflow += valwidth - width + 1;
			if (rightjust)
				(void) printf("%*s ", width, value);
			else
				(void) printf("%s ", value);
			return;
		}

		if (os->os_overflow > 0) {
			compress = MIN(os->os_overflow, width - valwidth);
			os->os_overflow -= compress;
			width -= compress;
		}
		if (rightjust)
			(void) printf("%*s ", width, value);
		else
			(void) printf("%-*s", width, value);
	}
}

/*
 * Print enough to fit the field width.
 */
static void
ofmt_fit_width(split_t **spp, uint_t width, char *value, uint_t bufsize)
{
	split_t		*sp = *spp;
	char		*ptr = value, *lim = ptr + bufsize;
	int		i, nextlen;

	if (sp == NULL) {
		sp = split_str(value, OFMT_MAX_ROWS);
		if (sp == NULL)
			return;

		*spp = sp;
	}
	for (i = sp->s_currfield; i < sp->s_nfields; i++) {
		ptr += snprintf(ptr, lim - ptr, "%s,", sp->s_fields[i]);
		if (i + 1 == sp->s_nfields) {
			nextlen = 0;
			if (ptr > value)
				ptr[-1] = '\0';
		} else {
			nextlen = strlen(sp->s_fields[i + 1]);
		}

		if (strlen(value) + nextlen > width || ptr >= lim) {
			i++;
			break;
		}
	}
	sp->s_currfield = i;
}

/*
 * Print one or more rows of output values for the selected columns.
 */
void
ofmt_print(ofmt_handle_t ofmt, void *arg)
{
	ofmt_state_t *os = ofmt;
	int i;
	char value[1024];
	ofmt_field_t *of;
	boolean_t escsep, more_rows;
	ofmt_arg_t ofarg;
	split_t **sp = NULL;
	boolean_t parsable = (os->os_flags & OFMT_PARSABLE);
	boolean_t multiline = (os->os_flags & OFMT_MULTILINE);
	boolean_t wrap = (os->os_flags & OFMT_WRAP);

	if (wrap) {
		sp = calloc(sizeof (split_t *), os->os_nfields);
		if (sp == NULL)
			return;
	}

	if ((os->os_nrow++ % os->os_winsize.ws_row) == 0 &&
	    !parsable && !multiline) {
		ofmt_print_header(os);
		os->os_nrow++;
	}

	if (multiline && os->os_nrow > 1)
		(void) putchar('\n');

	of = os->os_fields;
	escsep = (os->os_nfields > 1);
	more_rows = B_FALSE;
	for (i = 0; i < os->os_nfields; i++) {
		os->os_lastfield = (i + 1 == os->os_nfields);
		value[0] = '\0';
		ofarg.ofmt_id = of[i].of_id;
		ofarg.ofmt_cbarg = arg;

		if ((*of[i].of_cb)(&ofarg, value, sizeof (value))) {
			if (wrap) {
				/*
				 * 'value' will be split at comma boundaries
				 * and stored into sp[i].
				 */
				ofmt_fit_width(&sp[i], of[i].of_width, value,
				    sizeof (value));
				if (sp[i] != NULL &&
				    sp[i]->s_currfield < sp[i]->s_nfields)
					more_rows = B_TRUE;
			}

			ofmt_print_field(os, &of[i],
			    (*value == '\0' && !parsable) ?
			    OFMT_VAL_UNDEF : value, escsep);
		} else {
			ofmt_print_field(os, &of[i], OFMT_VAL_UNKNOWN, escsep);
		}
	}
	(void) putchar('\n');

	while (more_rows) {
		more_rows = B_FALSE;
		for (i = 0; i < os->os_nfields; i++) {
			os->os_lastfield = (i + 1 == os->os_nfields);
			value[0] = '\0';

			ofmt_fit_width(&sp[i], of[i].of_width,
			    value, sizeof (value));
			if (sp[i] != NULL &&
			    sp[i]->s_currfield < sp[i]->s_nfields)
				more_rows = B_TRUE;

			ofmt_print_field(os, &of[i], value, escsep);
		}
		(void) putchar('\n');
	}
	(void) fflush(stdout);

	if (sp != NULL) {
		for (i = 0; i < os->os_nfields; i++)
			splitfree(sp[i]);
		free(sp);
	}
}

/*
 * Print the field headers
 */
static void
ofmt_print_header(ofmt_state_t *os)
{
	int i;
	ofmt_field_t *of = os->os_fields;
	boolean_t escsep = (os->os_nfields > 1);

	for (i = 0; i < os->os_nfields; i++) {
		os->os_lastfield = (i + 1 == os->os_nfields);
		ofmt_print_field(os, &of[i], of[i].of_name, escsep);
	}
	(void) putchar('\n');
}

/*
 * Update the current window size.
 */
void
ofmt_update_winsize(ofmt_handle_t ofmt)
{
	ofmt_state_t *os = ofmt;
	struct winsize *winsize = &os->os_winsize;

	if (ioctl(1, TIOCGWINSZ, winsize) == -1 ||
	    winsize->ws_col == 0 || winsize->ws_row == 0) {
		winsize->ws_col = 80;
		winsize->ws_row = 24;
	}
}

/*
 * Return error diagnostics using the information in the ofmt_handle_t
 */
char *
ofmt_strerror(ofmt_handle_t ofmt, ofmt_status_t error, char *buf,
    uint_t bufsize)
{
	ofmt_state_t *os = ofmt;
	int i;
	const char *s;
	char ebuf[OFMT_BUFSIZE];
	boolean_t parsable;

	/*
	 * ebuf is intended for optional error-specific data to be appended
	 * after the internationalized error string for an error code.
	 */
	ebuf[0] = '\0';

	switch (error) {
	case OFMT_SUCCESS:
		s = "success";
		break;
	case OFMT_EBADFIELDS:
		/*
		 * Enumerate the singular/plural version of the warning
		 * and error to simplify and improve localization.
		 */
		parsable = (os->os_flags & OFMT_PARSABLE);
		if (!parsable) {
			if (os->os_nbad > 1)
				s = "ignoring unknown output fields:";
			else
				s = "ignoring unknown output field:";
		} else {
			if (os->os_nbad > 1)
				s = "unknown output fields:";
			else
				s = "unknown output field:";
		}
		/* set up the bad fields in ebuf */
		for (i = 0; i < os->os_nbad; i++) {
			(void) strlcat(ebuf, " `", sizeof (ebuf));
			(void) strlcat(ebuf, os->os_badfields[i],
			    sizeof (ebuf));
			(void) strlcat(ebuf, "'", sizeof (ebuf));
		}
		break;
	case OFMT_ENOFIELDS:
		s = "no valid output fields";
		break;
	case OFMT_EPARSEMULTI:
		s = "multiline mode incompatible with parsable mode";
		break;
	case OFMT_EPARSEALL:
		s = "output field `all' invalid in parsable mode";
		break;
	case OFMT_EPARSENONE:
		s = "output fields must be specified in parsable mode";
		break;
	case OFMT_EPARSEWRAP:
		s = "parsable mode is incompatible with wrap mode";
		break;
	case OFMT_ENOTEMPLATE:
		s = "no template provided for fields";
		break;
	case OFMT_ENOMEM:
		s = strerror(ENOMEM);
		break;
	default:
		(void) snprintf(buf, bufsize,
		    dgettext(TEXT_DOMAIN, "unknown ofmt error (%d)"),
		    error);
		return (buf);
	}
	(void) snprintf(buf, bufsize, dgettext(TEXT_DOMAIN, s));
	(void) strlcat(buf, ebuf, bufsize);
	return (buf);
}
