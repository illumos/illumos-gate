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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dirent.h>
#include <locale.h>
#include <libintl.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/file.h>

#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>

#include "praudit.h"
#include "toktable.h"

extern void	init_tokens(void);	/* shared with auditreduce */

static int	check_inputs(int flags, const char *separator);
static void	checkpoint_progress(pr_context_t *context);
static int	print_audit_common(pr_context_t *context, int flags,
    const char *separator);
static int	token_processing(pr_context_t *context);

static int	initdone = 0;

/*
 * This source is shared outside of praudit; the following lint directive
 * is needed to suppress praudit lint warnings about unused functions, for
 * functions which are only invoked outside praudit.
 */

/*LINTLIBRARY*/

/*
 * ----------------------------------------------------------------------
 * check_inputs() - check input flags and delimiter.
 *		Returns:
 *		    0 - successful
 *		   -1 - invalid inputs. errno is set to EINVAL
 * ----------------------------------------------------------------------
 */
static int
check_inputs(int flags, const char *separator)
{
	if ((flags & PRF_RAWM) && (flags & PRF_SHORTM)) {
		errno = EINVAL;
		return (-1);
	}

	/* Ignore the delimiter when XML is specified */
	if (!(flags & PRF_XMLM) && (strlen(separator) >= SEP_SIZE)) {
		errno = EINVAL;
		return (-1);
	}

	return (0);
}

/*
 * ----------------------------------------------------------------------
 * print_audit_xml_prolog_buf() - print the XML prolog.
 *		    0 - successful
 *		   -1 - output buffer too small. errno is set to ENOSPC
 * ----------------------------------------------------------------------
 */
int
print_audit_xml_prolog_buf(char *out_buf, const int out_buf_len)
{
	if (xml_prolog_len > out_buf_len) {
		errno = ENOSPC;
		return (-1);
	}

	(void) snprintf(out_buf, out_buf_len, "%s%s%s%s", prolog1, prolog_xsl,
	    prolog2, xml_start);

	return (0);
}

/*
 * ----------------------------------------------------------------------
 * print_audit_xml_ending_buf() - print the XML ending.
 *		    0 - successful
 *		   -1 - output buffer too small. errno is set to ENOSPC
 * ----------------------------------------------------------------------
 */
int
print_audit_xml_ending_buf(char *out_buf, const int out_buf_len)
{
	if (xml_end_len > out_buf_len) {
		errno = ENOSPC;
		return (-1);
	}

	(void) snprintf(out_buf, out_buf_len, "%s", xml_ending);
	return (0);
}

/*
 * ----------------------------------------------------------------------
 * print_prolog() - print the XML prolog.
 * ----------------------------------------------------------------------
 */
void
print_audit_xml_prolog(void)
{
	(void) printf("%s%s%s%s", prolog1, prolog_xsl, prolog2, xml_start);
}

/*
 * ----------------------------------------------------------------------
 * print_ending() - print the XML ending.
 * ----------------------------------------------------------------------
 */
void
print_audit_xml_ending(void)
{
	(void) printf("%s", xml_ending);
}

/*
 * ----------------------------------------------------------------------
 * checkpoint_progress() - If starting a new file or header token,
 *      checkpoint as needed to mark progress.
 * ----------------------------------------------------------------------
 */
static void
checkpoint_progress(pr_context_t *context)
{
	int	tokenid = context->tokenid;

	if (is_file_token(tokenid) || is_header_token(tokenid)) {
		if (context->data_mode == BUFMODE) {
			context->inbuf_last = context->audit_adr->adr_now - 1;
			context->outbuf_last = context->outbuf_p;
		}
		context->audit_rec_start = context->audit_adr->adr_now - 1;
		if (is_file_token(tokenid)) {
			context->audit_rec_len = 11;
		}
	}
}

/*
 * ----------------------------------------------------------------------
 * print_audit_buf() - display contents of audit trail file
 *
 *		   Parses the binary audit data from the specified input
 *		   buffer, and formats as requested to the specified output
 *		   buffer.
 *
 *	inputs:
 *		   in_buf, -	address and length of binary audit input.
 *		   in_buf_len
 *		   out_buf, -	address and length of output buffer to
 *		   out_buf_len	copy formatted audit data to.
 *		   flags -	formatting flags as defined in praudit.h
 *		   separator -	field delimiter (or NULL if the default
 *				delimiter of comma is to be used).
 *
 * return codes:    0 - success
 *		ENOSPC...
 * ----------------------------------------------------------------------
 */
int
print_audit_buf(char **in_buf, int *in_buf_len, char **out_buf,
    int *out_buf_len, const int flags, const char *separator)
{
	int	retstat = 0;
	pr_context_t	*context;

	if ((retstat = check_inputs(flags, separator)) != 0)
		return (retstat);

	if ((context = (pr_context_t *)malloc(sizeof (pr_context_t))) == NULL) {
		errno = EPERM;
		return (-1);
	}

	/* Init internal pointers and lengths... */
	context->data_mode = BUFMODE;
	context->inbuf_last = context->inbuf_start = *in_buf;
	context->inbuf_totalsize = *in_buf_len;

	context->pending_flag = 0;
	context->current_rec = 0;

	context->outbuf_last = context->outbuf_start =
	    context->outbuf_p = *out_buf;
	context->outbuf_remain_len = *out_buf_len;

	/*
	 * get an adr pointer to the audit input buf
	 */
	context->audit_adr = (adr_t *)malloc(sizeof (adr_t));
	(void) adrm_start(context->audit_adr, *in_buf);
	context->audit_rec_start = NULL;
	context->audit_rec_len = 0;

	retstat = print_audit_common(context, flags, separator);

	/* Check for and handle partial results as needed */
	if (retstat != 0) {
		*in_buf = context->inbuf_last;
		*in_buf_len = context->inbuf_totalsize -
		    (context->inbuf_last - context->inbuf_start);

		/* Return size of output */
		*out_buf_len = context->outbuf_last - context->outbuf_start;
		if (*out_buf_len > 0) {
			/* null-terminate the output */
			*(context->outbuf_last) = '\0';
			*out_buf_len = *out_buf_len + 1;
		}
	} else {
		/* Return size of output */
		*out_buf_len = context->outbuf_p - context->outbuf_start + 1;
		*(context->outbuf_p) = '\0';	/* null-terminate the output */
	}

	(void) free(context->audit_adr);
	(void) free(context);
	return (retstat);
}

/*
 * ----------------------------------------------------------------------
 * print_audit() - display contents of audit trail file
 *
 *		   Parses the binary audit data from the file mapped as stdin,
 *		   and formats as requested to file mapped as stdout.
 *	inputs:
 *		   flags -	formatting flags as defined in praudit.h
 *		   separator -	field delimiter (or NULL if the default
 *				delimiter of comma is to be used).
 *
 * return codes:   -1 - error
 *		    0 - successful
 * ----------------------------------------------------------------------
 */
int
print_audit(const int flags, const char *separator)
{
	int	retstat = 0;
	pr_context_t	*context;

	if ((retstat = check_inputs(flags, separator)) != 0)
		return (retstat);

	if ((context = (pr_context_t *)malloc(sizeof (pr_context_t))) == NULL) {
		errno = EPERM;
		return (-1);
	}

	/*
	 * get an adr pointer to the current audit file (stdin)
	 */
	context->audit_adr = malloc(sizeof (adr_t));
	context->audit_adrf = malloc(sizeof (adrf_t));

	adrf_start(context->audit_adrf, context->audit_adr, stdin);

	context->data_mode = FILEMODE;
	context->audit_rec_start = NULL;
	context->audit_rec_len = 0;

	context->pending_flag = 0;
	context->current_rec = 0;

	retstat = print_audit_common(context, flags, separator);

	(void) free(context->audit_adr);
	(void) free(context->audit_adrf);
	(void) free(context);
	return (retstat);
}

/*
 * ----------------------------------------------------------------------
 * print_audit_common() - common routine for print_audit* functions.
 *
 *		   Parses the binary audit data, and formats as requested.
 *		   The context parameter defines whether the source of the
 *		   audit data is a buffer, or a file mapped to stdin, and
 *		   whether the output is to a buffer or a file mapped to
 *		   stdout.
 *
 *	inputs:
 *		   context -	defines the context of the request, including
 *				info about the source and output.
 *		   flags -	formatting flags as defined in praudit.h
 *		   separator -	field delimiter (or NULL if the default
 *				delimiter of comma is to be used).
 *
 * return codes:   -1 - error
 *		    0 - successful
 * ----------------------------------------------------------------------
 */
static int
print_audit_common(pr_context_t *context, const int flags,
    const char *separator)
{
	int	retstat = 0;

	if (!initdone) {
		init_tokens();
		initdone++;
	}

	context->format = flags;

	/* start with default delimiter of comma */
	(void) strlcpy(context->SEPARATOR, ",", SEP_SIZE);
	if (separator != NULL) {
		if (strlen(separator) < SEP_SIZE) {
			(void) strlcpy(context->SEPARATOR, separator, SEP_SIZE);
		}
	}

	while ((retstat == 0) && pr_input_remaining(context, 1)) {
		if (pr_adr_char(context, (char *)&(context->tokenid), 1) == 0) {
			retstat = token_processing(context);
		} else
			break;
	}

	/*
	 * For buffer processing, if the entire input buffer was processed
	 * successfully, but the last record in the buffer was incomplete
	 * (according to the length from its header), then reflect an
	 * "incomplete input" error (which will cause partial results to be
	 * returned).
	 */
	if ((context->data_mode == BUFMODE) && (retstat == 0) &&
	    (context->audit_adr->adr_now < (context->audit_rec_start +
	    context->audit_rec_len))) {
		retstat = -1;
		errno = EIO;
	}

	/*
	 * If there was a last record that didn't get officially closed
	 * off, do it now.
	 */
	if ((retstat == 0) && (context->format & PRF_XMLM) &&
	    (context->current_rec)) {
		retstat = do_newline(context, 1);
		if (retstat == 0)
			retstat = close_tag(context, context->current_rec);
	}

	return (retstat);
}

/*
 * -----------------------------------------------------------------------
 * token_processing:
 *		  Calls the routine corresponding to the token id
 *		  passed in the parameter from the token table, tokentable
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
static int
token_processing(pr_context_t *context)
{
	uval_t	uval;
	int	retstat;
	int	tokenid = context->tokenid;

	if ((tokenid > 0) && (tokenid <= MAXTOKEN) &&
	    (tokentable[tokenid].func != NOFUNC)) {
		/*
		 * First check if there's a previous record that needs to be
		 * closed off now; then checkpoint our progress as needed.
		 */
		if ((retstat = check_close_rec(context, tokenid)) != 0)
			return (retstat);
		checkpoint_progress(context);

		/* print token name */
		if (context->format & PRF_XMLM) {
			retstat = open_tag(context, tokenid);
		} else {
			if (!(context->format & PRF_RAWM) &&
			    (tokentable[tokenid].t_name != (char *)0)) {
				uval.uvaltype = PRA_STRING;
				uval.string_val =
				    gettext(tokentable[tokenid].t_name);
			} else {
				uval.uvaltype = PRA_BYTE;
				uval.char_val = tokenid;
			}
			retstat = pa_print(context, &uval, 0);
		}
		if (retstat == 0)
			retstat = (*tokentable[tokenid].func)(context);

		/*
		 * For XML, close the token tag. Header tokens wrap the
		 * entire record, so they only get closed later implicitly;
		 * here, just make sure the header open tag gets finished.
		 */
		if ((retstat == 0) && (context->format & PRF_XMLM)) {
			if (!is_header_token(tokenid))
				retstat = close_tag(context, tokenid);
			else
				retstat = finish_open_tag(context);
		}
		return (retstat);
	}
	/* here if token id is not in table */
	(void) fprintf(stderr, gettext("praudit: No code associated with "
	    "token id %d\n"), tokenid);
	return (0);
}
