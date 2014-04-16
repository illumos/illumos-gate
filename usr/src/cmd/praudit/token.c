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


#include <ctype.h>
#include <dirent.h>
#include <grp.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/systm.h>
#include <netinet/in.h>
#include <sys/tiuser.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <nfs/nfs.h>
#include <sys/fs/ufs_quota.h>
#include <sys/time.h>
#include <sys/mkdev.h>
#include <unistd.h>

#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>

#include <tsol/label.h>

#include "praudit.h"
#include "toktable.h"

#include <netdb.h>
#include <arpa/inet.h>

static char *anchor_path(char *);
static char *collapse_path(char *);


/*
 * -----------------------------------------------------------------------
 * is_file_token:
 *		  Tests whether the specified token id represents a type
 *		  of file token.
 * return codes :  1 - tokenid is a file token type
 *		:  0 - otherwise
 * -----------------------------------------------------------------------
 */
int
is_file_token(int tokenid)
{
	if ((tokenid == AUT_OTHER_FILE32) || (tokenid == AUT_OTHER_FILE64))
		return (1);

	return (0);
}

/*
 * -----------------------------------------------------------------------
 * is_header_token:
 *		  Tests whether the specified token id represents a type
 *		  of header token (signifying the start of a record).
 * return codes :  1 - tokenid is a header type
 *		:  0 - otherwise
 * -----------------------------------------------------------------------
 */
int
is_header_token(int tokenid)
{
	if ((tokenid == AUT_OHEADER) || (tokenid == AUT_HEADER32) ||
	    (tokenid == AUT_HEADER32_EX) || (tokenid == AUT_HEADER64) ||
	    (tokenid == AUT_HEADER64_EX))
		return (1);

	return (0);
}

/*
 * -----------------------------------------------------------------------
 * is_token:
 *		  Tests whether the specified token id represents a true
 *		  token, as opposed to a regular tag.
 * return codes :  1 - tokenid is a true token
 *		:  0 - otherwise
 * -----------------------------------------------------------------------
 */
int
is_token(int tokenid)
{
	if ((tokenid > 0) && (tokenid <= MAXTOKEN))
		return (1);

	return (0);
}


/*
 * -----------------------------------------------------------------------
 * exit_token() 	: Process information label token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the label token id has been retrieved
 *
 * Format of exit token:
 *	exit token id		adr_char
 * -----------------------------------------------------------------------
 */
int
exit_token(pr_context_t *context)
{
	int	returnstat;
	int	retval;
	uval_t	uval;

	if ((returnstat = open_tag(context, TAG_ERRVAL)) != 0)
		return (returnstat);

	if ((returnstat = pr_adr_int32(context, (int32_t *)&retval, 1)) == 0) {
		if (!(context->format & PRF_RAWM)) {
			char *emsg = strerror(retval);

			if (emsg == NULL)
				uval.string_val = gettext("Unknown errno");
			else
				uval.string_val = gettext(emsg);
			uval.uvaltype = PRA_STRING;
		} else {
			uval.uvaltype = PRA_INT32;
			uval.int32_val = retval;
		}
		returnstat = pa_print(context, &uval, 0);
	}
	if (returnstat == 0)
		returnstat = close_tag(context, TAG_ERRVAL);

	return (process_tag(context, TAG_RETVAL, returnstat, 1));
}

/*
 * ------------------------------------------------------------------
 * file_token()	: prints out seconds of time and other file name
 * return codes : -1 - error
 *		:  0 - successful, valid file token fields
 * At the time of entry, the file token ID has already been retrieved
 *
 * Format of file token:
 *	file token id		adr_char
 *	seconds of time		adr_u_int
 *	name of other file	adr_string
 * ------------------------------------------------------------------
 */
int
file_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = pa_utime32(context, 0, 0);		/* time from usecs */

	/* other file name */
	returnstat = pa_file_string(context, returnstat, 1);

	return (returnstat);
}

int
file64_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = pa_utime64(context, 0, 0);		/* time from usecs */

	/* other file name */
	returnstat = pa_file_string(context, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * header_token()	: Process record header token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 *			:  1 - warning, password entry not found
 *
 * NOTE: At the time of call, the header token id has been retrieved
 *
 * Format of header token:
 *	header token id 	adr_char
 * 	record byte count	adr_u_int
 *	event type		adr_u_short (printed either ASCII or raw)
 *	event class		adr_u_int   (printed either ASCII or raw)
 *	event action		adr_u_int
 *	if extended:		extended host name (IPv4/IPv6)
 *	seconds of time		adr_u_int   (printed either ASCII or raw)
 *	nanoseconds of time	adr_u_int
 * -----------------------------------------------------------------------
 */
int
header_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = pa_reclen(context, 0);		/* record byte */
	/* version ID */
	returnstat = process_tag(context, TAG_TOKVERS, returnstat, 0);
	/* event type */
	returnstat = process_tag(context, TAG_EVTYPE, returnstat, 0);
	/* event modifier */
	returnstat = pa_event_modifier(context, returnstat, 0);
	/* time from nsec */
	returnstat = pa_ntime32(context, returnstat, 1);

	return (returnstat);
}

int
header64_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = pa_reclen(context, 0);		/* record byte */
	/* version ID */
	returnstat = process_tag(context, TAG_TOKVERS, returnstat, 0);
	/* event type */
	returnstat = process_tag(context, TAG_EVTYPE, returnstat, 0);
	/* event modifier */
	returnstat = pa_event_modifier(context, returnstat, 0);
	/* time from nsec */
	returnstat = pa_ntime64(context, returnstat, 1);

	return (returnstat);
}

int
header32_ex_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = pa_reclen(context, 0);		/* record byte */
	/* version ID */
	returnstat = process_tag(context, TAG_TOKVERS, returnstat, 0);
	/* event type */
	returnstat = process_tag(context, TAG_EVTYPE, returnstat, 0);
	/* event modifier */
	returnstat = pa_event_modifier(context, returnstat, 0);
	/* machine name */
	returnstat = pa_hostname_ex(context, returnstat, 0);
	/* time from nsec */
	returnstat = pa_ntime32(context, returnstat, 1);

	return (returnstat);
}

int
header64_ex_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = pa_reclen(context, 0);		/* record byte */
	/* version ID */
	returnstat = process_tag(context, TAG_TOKVERS, returnstat, 0);
	/* event type */
	returnstat = process_tag(context, TAG_EVTYPE, returnstat, 0);
	/* event modifier */
	returnstat = pa_event_modifier(context, returnstat, 0);
	/* machine name */
	returnstat = pa_hostname_ex(context, returnstat, 0);
	/* time from nsec */
	returnstat = pa_ntime64(context, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * trailer_token()	: Process record trailer token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the trailer token id has already been
 * retrieved
 *
 * Format of trailer token:
 * 	trailer token id	adr_char
 * 	record sequence no	adr_u_short (should be AUT_TRAILER_MAGIC)
 *	record byte count	adr_u_int
 * -----------------------------------------------------------------------
 */
int
trailer_token(pr_context_t *context)
{
	short	magic_number;

	if (pr_adr_u_short(context, (ushort_t *)&magic_number, 1) < 0) {
		(void) fprintf(stderr, gettext(
		    "praudit: Cannot retrieve trailer magic number\n"));
		return (-1);
	} else {
		if (magic_number != AUT_TRAILER_MAGIC) {
			(void) fprintf(stderr, gettext(
			    "praudit: Invalid trailer magic number\n"));
			return (-1);
		} else
			/* Do not display trailer in XML mode */
			if (context->format & PRF_XMLM) {
				uint32_t	junk;
				int		retstat;

				retstat = pr_adr_u_int32(context, &junk, 1);
				return (retstat);
			} else {
				return (pa_adr_u_int32(context, 0, 1));
			}
	}
}

/*
 * -----------------------------------------------------------------------
 * arbitrary_data_token():
 *			  Process arbitrary data token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the arbitrary data token id has already
 * been retrieved
 *
 * Format of arbitrary data token:
 *	arbitrary data token id	adr char
 * 	how to print		adr_char
 *				From audit_record.h, this may be either:
 *				AUP_BINARY	binary
 *				AUP_OCTAL	octal
 *				AUP_DECIMAL	decimal
 *				AUP_HEX		hexadecimal
 *	basic unit		adr_char
 *				From audit_record.h, this may be either:
 *				AUR_BYTE	byte
 *				AUR_CHAR	char
 *				AUR_SHORT	short
 *				AUR_INT32	int32_t
 *				AUR_INT64	int64_t
 *	unit count		adr_char, specifying number of units of
 *				data in the "data items" parameter below
 *	data items		depends on basic unit
 *
 * -----------------------------------------------------------------------
 */
int
arbitrary_data_token(pr_context_t *context)
{
	int	returnstat;
	int	i;
	char	c1;
	short	c2;
	int32_t	c3;
	int64_t c4;
	char	how_to_print, basic_unit, unit_count, fwid;
	char	*p;
	int	index = 0;
	char	*pformat = "%*s";

	uval_t	uval;

	if ((returnstat = pr_adr_char(context, &how_to_print, 1)) != 0)
		return (returnstat);

	if ((returnstat = pr_adr_char(context, &basic_unit, 1)) != 0)
		return (returnstat);

	if ((returnstat = pr_adr_char(context, &unit_count, 1)) != 0)
		return (returnstat);

	if (!(context->format & PRF_RAWM)) {
		uval.uvaltype = PRA_STRING;
		uval.string_val = htp2string(how_to_print);
	} else {
		uval.uvaltype = PRA_INT32;
		uval.int32_val = (int)how_to_print;
	}

	if ((returnstat = open_tag(context, TAG_ARBPRINT)) != 0)
		return (returnstat);
	if ((returnstat = pa_print(context, &uval, 0)) < 0)
		return (returnstat);
	if ((returnstat = close_tag(context, TAG_ARBPRINT)) != 0)
		return (returnstat);

	if (!(context->format & PRF_RAWM)) {
		uval.uvaltype = PRA_STRING;
		uval.string_val = bu2string(basic_unit);
	} else {
		uval.uvaltype = PRA_INT32;
		uval.int32_val = (int32_t)basic_unit;
	}

	if ((returnstat = open_tag(context, TAG_ARBTYPE)) != 0)
		return (returnstat);
	if ((returnstat = pa_print(context, &uval, 0)) < 0)
		return (returnstat);
	if ((returnstat = close_tag(context, TAG_ARBTYPE)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_INT32;
	uval.int32_val = (int32_t)unit_count;

	if ((returnstat = open_tag(context, TAG_ARBCOUNT)) != 0)
		return (returnstat);
	if ((returnstat = pa_print(context, &uval, 1)) < 0)
		return (returnstat);
	if ((returnstat = close_tag(context, TAG_ARBCOUNT)) != 0)
		return (returnstat);

	/* Done with attributes; force end of token open */
	if ((returnstat = finish_open_tag(context)) != 0)
		return (returnstat);

	/* get the field width in case we need to format output */
	fwid = findfieldwidth(basic_unit, how_to_print);
	p = (char *)malloc(80);

	/* now get the data items and print them */
	for (i = 0; (i < unit_count); i++) {
		switch (basic_unit) {
			/* case AUR_BYTE: */
		case AUR_CHAR:
			if (pr_adr_char(context, &c1, 1) == 0)
				(void) convert_char_to_string(how_to_print,
				    c1, p);
			else {
				free(p);
				return (-1);
			}
			break;
		case AUR_SHORT:
			if (pr_adr_short(context, &c2, 1) == 0)
				(void) convert_short_to_string(how_to_print,
				    c2, p);
			else {
				free(p);
				return (-1);
			}
			break;
		case AUR_INT32:
			if (pr_adr_int32(context, &c3, 1) == 0)
				(void) convert_int32_to_string(how_to_print,
				    c3, p);
			else {
				free(p);
				return (-1);
			}
			break;
		case AUR_INT64:
			if (pr_adr_int64(context, &c4, 1) == 0)
				(void) convert_int64_to_string(how_to_print,
				    c4, p);
			else {
				free(p);
				return (-1);
			}
			break;
		default:
			free(p);
			return (-1);
			/*NOTREACHED*/
		}

		/*
		 * At this point, we have successfully retrieved a data
		 * item and converted it into an ASCII string pointed to
		 * by p. If all output is to be printed on one line,
		 * simply separate the data items by a space (or by the
		 * delimiter if this is the last data item), otherwise, we
		 * need to format the output before display.
		 */
		if (context->format & PRF_ONELINE) {
			returnstat = pr_printf(context, "%s", p);
			if ((returnstat >= 0) && (i == (unit_count - 1)))
				returnstat = pr_printf(context, "%s",
				    context->SEPARATOR);
			else
				returnstat = pr_putchar(context, ' ');
		} else {	/* format output */
			returnstat = pr_printf(context, pformat, fwid, p);
			index += fwid;
			if ((returnstat >= 0) &&
			    (((index + fwid) > 75) ||
			    (i == (unit_count - 1)))) {
				returnstat = pr_putchar(context, '\n');
				index = 0;
			}
		} /* else if PRF_ONELINE */
		if (returnstat < 0) {
			free(p);
			return (returnstat);
		}
	}
	free(p);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * opaque_token() 	: Process opaque token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the opaque token id has already been
 * retrieved
 *
 * Format of opaque token:
 *	opaque token id		adr_char
 *	size			adr_short
 *	data			adr_char, size times
 * -----------------------------------------------------------------------
 */
int
opaque_token(pr_context_t *context)
{
	int	returnstat;
	short	size;
	char	*charp;
	uval_t	uval;


	/* print the size of the token */
	if (pr_adr_short(context, &size, 1) == 0) {
		uval.uvaltype = PRA_SHORT;
		uval.short_val = size;
		returnstat = pa_print(context, &uval, 0);
	} else
		returnstat = -1;

	/* now print out the data field in hexadecimal */
	if (returnstat >= 0) {
		/* try to allocate memory for the character string */
		if ((charp = (char *)malloc(size * sizeof (char))) == NULL)
			returnstat = -1;
		else {
			if ((returnstat = pr_adr_char(context, charp,
			    size)) == 0) {
				/* print out in hexadecimal format */
				uval.uvaltype = PRA_STRING;
				uval.string_val = hexconvert(charp, size, size);
				if (uval.string_val) {
					returnstat = pa_print(context,
					    &uval, 1);
					free(uval.string_val);
				}
			}
			free(charp);
		}
	}

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * path_token() 	: Process path token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the path token id has been retrieved
 *
 * Format of path token:
 *	token id	adr_char
 *	path		adr_string
 * -----------------------------------------------------------------------
 */
int
path_token(pr_context_t *context)
{
	char	*path;	/* path */
	char	*apath;	/* anchored path */
	char	*cpath;	/* collapsed path */
	short	length;
	int	returnstat;
	uval_t	uval;

	/*
	 * We need to know how much space to allocate for our string, so
	 * read the length first, then call pr_adr_char to read those bytes.
	 */
	if (pr_adr_short(context, &length, 1) == 0) {
		if ((path = (char *)malloc(length + 1)) == NULL) {
			returnstat = -1;
		} else if (pr_adr_char(context, path, length) == 0) {
			path[length] = '\0';
			uval.uvaltype = PRA_STRING;
			if (*path != '/') {
				apath = anchor_path(path);
				free(path);
			} else
				apath = path;
			cpath = collapse_path(apath);
			uval.string_val = cpath;
			returnstat = pa_print(context, &uval, 1);
			free(cpath);
		} else {
			free(path);
			returnstat = -1;
		}
		return (returnstat);
	} else
		return (-1);
}

/*
 * anchor a path name with a slash
 */
char *
anchor_path(char *sp)
{
	char	*dp; /* destination path */
	char	*tp; /* temporary path */
	size_t	len;

	len = strlen(sp) + 2;
	if ((dp = tp = (char *)calloc(1, len)) == (char *)0)
		return ((char *)0);

	*dp++ = '/';

	(void) strlcpy(dp, sp, len);

	return (tp);
}

/*
 * copy path to collapsed path.
 * collapsed path does not contain:
 *	successive slashes
 *	instances of dot-slash
 *	instances of dot-dot-slash
 * passed path must be anchored with a '/'
 */
char *
collapse_path(char *s)
{
	int	id;	/* index of where we are in destination string */
	int	is;		/* index of where we are in source string */
	int	slashseen;	/* have we seen a slash */
	int	ls;		/* length of source string */

	ls = strlen(s) + 1;

	slashseen = 0;
	for (is = 0, id = 0; is < ls; is++) {
		/* thats all folks, we've reached the end of input */
		if (s[is] == '\0') {
			if (id > 1 && s[id-1] == '/') {
				--id;
			}
			s[id++] = '\0';
			break;
		}
		/* previous character was a / */
		if (slashseen) {
			if (s[is] == '/')
				continue;	/* another slash, ignore it */
		} else if (s[is] == '/') {
			/* we see a /, just copy it and try again */
			slashseen = 1;
			s[id++] = '/';
			continue;
		}
		/* /./ seen */
		if (s[is] == '.' && s[is+1] == '/') {
			is += 1;
			continue;
		}
		/* XXX/. seen */
		if (s[is] == '.' && s[is+1] == '\0') {
			if (id > 1)
				id--;
			continue;
		}
		/* XXX/.. seen */
		if (s[is] == '.' && s[is+1] == '.' && s[is+2] == '\0') {
			is += 1;
			if (id > 0)
				id--;
			while (id > 0 && s[--id] != '/')
				continue;
			id++;
			continue;
		}
		/* XXX/../ seen */
		if (s[is] == '.' && s[is+1] == '.' && s[is+2] == '/') {
			is += 2;
			if (id > 0)
				id--;
			while (id > 0 && s[--id] != '/')
				continue;
			id++;
			continue;
		}
		while (is < ls && (s[id++] = s[is++]) != '/')
			continue;
		is--;
	}
	return (s);
}

/*
 * -----------------------------------------------------------------------
 * cmd_token()		: Process cmd token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the cmd token id has been retrieved
 *
 * Format of command token:
 *	token id	adr_char
 *	argc		adr_short
 *	N*argv[i]	adr_string (short, string)
 *	env cnt		adr_short
 *	N*arge[i]	adr_string (short, string)
 * -----------------------------------------------------------------------
 */
int
cmd_token(pr_context_t *context)
{
	int	returnstat;
	short num;

	returnstat = pr_adr_short(context, &num, 1);
	if (returnstat < 0)
		return (returnstat);

	if (!(context->format & PRF_XMLM)) {
		returnstat = pr_printf(context, "%s%s%d%s",
		    (context->format & PRF_ONELINE) ? "" : gettext("argcnt"),
		    (context->format & PRF_ONELINE) ? "" : context->SEPARATOR,
		    num, context->SEPARATOR);
		if (returnstat < 0)
			return (returnstat);
	}

	for (; num > 0; num--) {
		if ((returnstat = process_tag(context, TAG_ARGV,
		    returnstat, 0)) < 0)
			return (returnstat);
	}

	if ((returnstat = pr_adr_short(context, &num, 1)) < 0)
		return (returnstat);

	if (!(context->format & PRF_XMLM)) {
		returnstat = pr_printf(context, "%s%s%d%s",
		    (context->format & PRF_ONELINE) ? "" : gettext("envcnt"),
		    (context->format & PRF_ONELINE) ? "" : context->SEPARATOR,
		    num, context->SEPARATOR);
		if (returnstat < 0)
			return (returnstat);
	}

	if ((num == 0) && !(context->format & PRF_XMLM)) {
		returnstat = do_newline(context, 1);
		if (returnstat < 0)
			return (returnstat);
	}

	for (; num > 1; num--) {
		if ((returnstat = process_tag(context, TAG_ARGE,
		    returnstat, 0)) < 0)
			return (returnstat);
	}
	if (num)
		returnstat = process_tag(context, TAG_ARGE, returnstat, 1);

	return (returnstat);

}

/*
 * -----------------------------------------------------------------------
 * argument32_token()	: Process argument token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the arg token id has been retrieved
 *
 * Format of argument token:
 *	current directory token id	adr_char
 *	argument number			adr_char
 *	argument value			adr_int32
 *	argument description		adr_string
 * -----------------------------------------------------------------------
 */
int
argument32_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_ARGNUM, 0, 0);
	returnstat = process_tag(context, TAG_ARGVAL32, returnstat, 0);
	returnstat = process_tag(context, TAG_ARGDESC, returnstat, 1);

	return (returnstat);

}

/*
 * -----------------------------------------------------------------------
 * argument64_token()	: Process argument token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the arg token id has been retrieved
 *
 * Format of 64 bit argument token:
 *	current directory token id	adr_char
 *	argument number			adr_char
 *	argument value			adr_int64
 *	argument description		adr_string
 * -----------------------------------------------------------------------
 */
int
argument64_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_ARGNUM, 0, 0);
	returnstat = process_tag(context, TAG_ARGVAL64, returnstat, 0);
	returnstat = process_tag(context, TAG_ARGDESC, returnstat, 1);

	return (returnstat);

}

/*
 * -----------------------------------------------------------------------
 * process_token() 	: Process process token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the process token id has been retrieved
 *
 * Format of process token:
 *	process token id	adr_char
 *	auid			adr_u_int32
 *	euid			adr_u_int32
 *	egid			adr_u_int32
 *	ruid			adr_u_int32
 *	egid			adr_u_int32
 *	pid			adr_u_int32
 *	sid			adr_u_int32
 *	tid			adr_u_int32, adr_u_int32
 * -----------------------------------------------------------------------
 */
int
process32_token(pr_context_t *context)
{
	int	returnstat;

		/* auid */
	returnstat = process_tag(context, TAG_AUID, 0, 0);
		/* uid */
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
		/* gid */
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
		/* ruid */
	returnstat = process_tag(context, TAG_RUID, returnstat, 0);
		/* rgid */
	returnstat = process_tag(context, TAG_RGID, returnstat, 0);
		/* pid */
	returnstat = process_tag(context, TAG_PID, returnstat, 0);
		/* sid */
	returnstat = process_tag(context, TAG_SID, returnstat, 0);
		/* tid */
	returnstat = process_tag(context, TAG_TID32, returnstat, 1);

	return (returnstat);
}

int
process64_token(pr_context_t *context)
{
	int	returnstat;

		/* auid */
	returnstat = process_tag(context, TAG_AUID, 0, 0);
		/* uid */
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
		/* gid */
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
		/* ruid */
	returnstat = process_tag(context, TAG_RUID, returnstat, 0);
		/* rgid */
	returnstat = process_tag(context, TAG_RGID, returnstat, 0);
		/* pid */
	returnstat = process_tag(context, TAG_PID, returnstat, 0);
		/* sid */
	returnstat = process_tag(context, TAG_SID, returnstat, 0);
		/* tid */
	returnstat = process_tag(context, TAG_TID64, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * process_ex_token()	: Process process token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the process token id has been retrieved
 *
 * Format of extended process token:
 *	process token id	adr_char
 *	auid			adr_u_int32
 *	euid			adr_u_int32
 *	egid			adr_u_int32
 *	ruid			adr_u_int32
 *	egid			adr_u_int32
 *	pid			adr_u_int32
 *	sid			adr_u_int32
 *	tid			adr_u_int32, adr_u_int32, 4*adr_u_int32
 * -----------------------------------------------------------------------
 */
int
process32_ex_token(pr_context_t *context)
{
	int	returnstat;

		/* auid */
	returnstat = process_tag(context, TAG_AUID, 0, 0);
		/* uid */
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
		/* gid */
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
		/* ruid */
	returnstat = process_tag(context, TAG_RUID, returnstat, 0);
		/* rgid */
	returnstat = process_tag(context, TAG_RGID, returnstat, 0);
		/* pid */
	returnstat = process_tag(context, TAG_PID, returnstat, 0);
		/* sid */
	returnstat = process_tag(context, TAG_SID, returnstat, 0);
		/* tid */
	returnstat = process_tag(context, TAG_TID32_EX, returnstat, 1);

	return (returnstat);
}

int
process64_ex_token(pr_context_t *context)
{
	int	returnstat;

		/* auid */
	returnstat = process_tag(context, TAG_AUID, 0, 0);
		/* uid */
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
		/* gid */
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
		/* ruid */
	returnstat = process_tag(context, TAG_RUID, returnstat, 0);
		/* rgid */
	returnstat = process_tag(context, TAG_RGID, returnstat, 0);
		/* pid */
	returnstat = process_tag(context, TAG_PID, returnstat, 0);
		/* sid */
	returnstat = process_tag(context, TAG_SID, returnstat, 0);
		/* tid */
	returnstat = process_tag(context, TAG_TID64_EX, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * return_value32_token(): Process return value and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the return value token id has been retrieved
 *
 * Format of return value token:
 * 	return value token id	adr_char
 *	error number		adr_char
 *	return value		adr_int32
 * -----------------------------------------------------------------------
 */
int
return_value32_token(pr_context_t *context)
{
	int		returnstat;
	uchar_t		number;
	int32_t		value;
	char		pb[512];    /* print buffer */
	uval_t		uval;
	bool_t		used_ret_val = 0;

	/*
	 * Every audit record generated contains a return token.
	 *
	 * The return token is a special token. It indicates the success
	 * or failure of the event that contains it.
	 * The return32 token contains two pieces of data:
	 *
	 * 	char	number;
	 * 	int32_t	return_value;
	 *
	 * For audit records generated by the kernel:
	 * The kernel always puts a positive value in "number".
	 * Upon success "number" is 0.
	 * Upon failure "number" is a positive errno value that is less than
	 * sys_nerr.
	 *
	 * For audit records generated at the user level:
	 * Upon success "number" is 0.
	 * Upon failure "number" is -1.
	 *
	 * For both kernel and user land the value of "return_value" is
	 * arbitrary. For the kernel it contains the return value of
	 * the system call. For user land it contains an arbitrary return
	 * value if it is less than ADT_FAIL_VALUE; ADT_FAIL_VALUE
	 * and above are messages defined in adt_event.h.   ADT_FAIL_PAM and
	 * above are messages from pam_strerror().  No interpretation is done
	 * on "return_value" if it is outside the range of ADT_FAIL_VALUE_* or
	 * ADT_FAIL_PAM values.
	 */
	if ((returnstat = open_tag(context, TAG_ERRVAL)) != 0)
		return (returnstat);

	if ((returnstat = pr_adr_u_char(context, &number, 1)) == 0) {
		if (!(context->format & PRF_RAWM)) {
			used_ret_val = 1;
			pa_error(number, pb, sizeof (pb));
			uval.uvaltype = PRA_STRING;
			uval.string_val = pb;
			if ((returnstat = pa_print(context, &uval, 0)) != 0)
				return (returnstat);
			if ((returnstat = close_tag(context, TAG_ERRVAL)) != 0)
				return (returnstat);
			if ((returnstat = open_tag(context, TAG_RETVAL)) != 0)
				return (returnstat);

			if ((returnstat = pr_adr_int32(
			    context, &value, 1)) != 0)
				return (returnstat);

			pa_retval(number, value, pb, sizeof (pb));
		} else {
			uval.uvaltype = PRA_INT32;
			if ((char)number == -1)
				uval.int32_val = -1;
			else
				uval.int32_val = number;
		}
		returnstat = pa_print(context, &uval, used_ret_val);
	}
	if (used_ret_val) {
		if (returnstat == 0)
			returnstat = close_tag(context, TAG_RETVAL);
		return (returnstat);
	}
	if (!returnstat)
		if (returnstat = close_tag(context, TAG_ERRVAL))
			return (returnstat);

	return (process_tag(context, TAG_RETVAL, returnstat, 1));
}

/*
 * -----------------------------------------------------------------------
 * return_value64_token(): Process return value and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the return value token id has been retrieved
 *
 * Format of return value token:
 * 	return value token id	adr_char
 *	error number		adr_char
 *	return value		adr_int64
 *
 * HOWEVER, the 64 bit return value is a concatenation of two
 * 32 bit return values; the first of which is the same as is
 * carried in the return32 token.  The second 32 bits are ignored
 * here so that the displayed return token will have the same
 * number whether the application is 32 or 64 bits.
 * -----------------------------------------------------------------------
 */
int
return_value64_token(pr_context_t *context)
{
	int		returnstat;
	uchar_t		number;
	rval_t		rval;
	char		pb[512];    /* print buffer */
	uval_t		uval;

	/*
	 * Every audit record generated contains a return token.
	 *
	 * The return token is a special token. It indicates the success
	 * or failure of the event that contains it.
	 * The return64 token contains two pieces of data:
	 *
	 * 	char	number;
	 * 	int64_t	return_value;
	 *
	 * For audit records generated by the kernel:
	 * The kernel always puts a positive value in "number".
	 * Upon success "number" is 0.
	 * Upon failure "number" is a positive errno value that is less than
	 * sys_nerr.
	 *
	 * For audit records generated at the user level:
	 * Upon success "number" is 0.
	 * Upon failure "number" is -1.
	 *
	 * For both kernel and user land the value of "return_value" is
	 * arbitrary. For the kernel it contains the return value of
	 * the system call. For user land it contains an arbitrary return
	 * value if it is less than ADT_FAIL_VALUE; ADT_FAIL_VALUE
	 * and above are messages defined in adt_event.h.   ADT_FAIL_PAM and
	 * above are messages from pam_strerror().  No interpretation is done
	 * on "return_value" if it is outside the range of ADT_FAIL_VALUE_* or
	 * ADT_FAIL_PAM values.
	 *
	 * The 64 bit return value consists of two 32bit parts; for
	 * system calls, the first part is the value returned by the
	 * system call and the second part depends on the system call
	 * implementation.  In most cases, the second part is either 0
	 * or garbage; because of that, it is omitted from the praudit
	 * output.
	 */
	if ((returnstat = open_tag(context, TAG_ERRVAL)) != 0)
		return (returnstat);

	if ((returnstat = pr_adr_u_char(context, &number, 1)) == 0) {
		if (!(context->format & PRF_RAWM)) {
			pa_error(number, pb, sizeof (pb));
			uval.uvaltype = PRA_STRING;
			uval.string_val = pb;
			if ((returnstat = pa_print(context, &uval, 0)) != 0)
				return (returnstat);

			if ((returnstat = close_tag(context, TAG_ERRVAL)) != 0)
				return (returnstat);
			if ((returnstat = open_tag(context, TAG_RETVAL)) != 0)
				return (returnstat);

			if ((returnstat = pr_adr_int64(context,
			    &rval.r_vals, 1)) != 0)
				return (returnstat);
			pa_retval(number, rval.r_val1, pb, sizeof (pb));
		} else {
			uval.uvaltype = PRA_INT32;
			if ((char)number == -1)
				uval.int32_val = -1;
			else
				uval.int32_val = number;

			if ((returnstat = pa_print(context, &uval, 0)) != 0)
				return (returnstat);

			if ((returnstat = close_tag(context, TAG_ERRVAL)) != 0)
				return (returnstat);
			if ((returnstat = open_tag(context, TAG_RETVAL)) != 0)
				return (returnstat);

			if ((returnstat = pr_adr_int64(context,
			    &rval.r_vals, 1)) != 0)
				return (returnstat);
			uval.int32_val = rval.r_val1;
		}
		returnstat = pa_print(context, &uval, 1);
	} else {
		return (returnstat);
	}

	if (returnstat == 0)
		returnstat = close_tag(context, TAG_RETVAL);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * subject32_token()	: Process subject token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the subject token id has been retrieved
 *
 * Format of subject token:
 *	subject token id	adr_char
 *	auid			adr_u_int32
 *	euid			adr_u_int32
 *	egid			adr_u_int32
 *	ruid			adr_u_int32
 *	egid			adr_u_int32
 *	pid			adr_u_int32
 *	sid			adr_u_int32
 *	tid			adr_u_int32, adr_u_int32
 * -----------------------------------------------------------------------
 */
int
subject32_token(pr_context_t *context)
{
	int	returnstat;

		/* auid */
	returnstat = process_tag(context, TAG_AUID, 0, 0);
		/* uid */
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
		/* gid */
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
		/* ruid */
	returnstat = process_tag(context, TAG_RUID, returnstat, 0);
		/* rgid */
	returnstat = process_tag(context, TAG_RGID, returnstat, 0);
		/* pid */
	returnstat = process_tag(context, TAG_PID, returnstat, 0);
		/* sid */
	returnstat = process_tag(context, TAG_SID, returnstat, 0);
		/* tid */
	returnstat = process_tag(context, TAG_TID32, returnstat, 1);

	return (returnstat);
}

int
subject64_token(pr_context_t *context)
{
	int	returnstat;

		/* auid */
	returnstat = process_tag(context, TAG_AUID, 0, 0);
		/* uid */
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
		/* gid */
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
		/* ruid */
	returnstat = process_tag(context, TAG_RUID, returnstat, 0);
		/* rgid */
	returnstat = process_tag(context, TAG_RGID, returnstat, 0);
		/* pid */
	returnstat = process_tag(context, TAG_PID, returnstat, 0);
		/* sid */
	returnstat = process_tag(context, TAG_SID, returnstat, 0);
		/* tid */
	returnstat = process_tag(context, TAG_TID64, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * subject_ex_token(): Process subject token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the subject token id has been retrieved
 *
 * Format of extended subject token:
 *	subject token id	adr_char
 *	auid			adr_u_int32
 *	euid			adr_u_int32
 *	egid			adr_u_int32
 *	ruid			adr_u_int32
 *	egid			adr_u_int32
 *	pid			adr_u_int32
 *	sid			adr_u_int32
 *	tid			adr_u_int32, adr_u_int32
 * -----------------------------------------------------------------------
 */
int
subject32_ex_token(pr_context_t *context)
{
	int	returnstat;

		/* auid */
	returnstat = process_tag(context, TAG_AUID, 0, 0);
		/* uid */
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
		/* gid */
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
		/* ruid */
	returnstat = process_tag(context, TAG_RUID, returnstat, 0);
		/* rgid */
	returnstat = process_tag(context, TAG_RGID, returnstat, 0);
		/* pid */
	returnstat = process_tag(context, TAG_PID, returnstat, 0);
		/* sid */
	returnstat = process_tag(context, TAG_SID, returnstat, 0);
		/* tid */
	returnstat = process_tag(context, TAG_TID32_EX, returnstat, 1);

	return (returnstat);
}

int
subject64_ex_token(pr_context_t *context)
{
	int	returnstat;

		/* auid */
	returnstat = process_tag(context, TAG_AUID, 0, 0);
		/* uid */
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
		/* gid */
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
		/* ruid */
	returnstat = process_tag(context, TAG_RUID, returnstat, 0);
		/* rgid */
	returnstat = process_tag(context, TAG_RGID, returnstat, 0);
		/* pid */
	returnstat = process_tag(context, TAG_PID, returnstat, 0);
		/* sid */
	returnstat = process_tag(context, TAG_SID, returnstat, 0);
		/* tid */
	returnstat = process_tag(context, TAG_TID64_EX, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * s5_IPC_token()	: Process System V IPC token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the System V IPC id has been retrieved
 *
 * Format of System V IPC token:
 *	System V IPC token id	adr_char
 *	object id		adr_int32
 * -----------------------------------------------------------------------
 */
int
s5_IPC_token(pr_context_t *context)
{
	int	returnstat;
	uchar_t ipctype;
	uval_t	uval;

	/*
	 * TRANSLATION_NOTE
	 * These names refer to the type of System V IPC object:
	 * message queue, semaphore, shared memory.
	 */

	if (pr_adr_u_char(context, &ipctype, 1) == 0) {
		if ((returnstat = open_tag(context, TAG_IPCTYPE)) != 0)
			return (returnstat);

		if (!(context->format & PRF_RAWM)) {
			/* print in ASCII form */
			uval.uvaltype = PRA_STRING;
			switch (ipctype) {
			case AT_IPC_MSG:
				uval.string_val = gettext("msg");
				break;
			case AT_IPC_SEM:
				uval.string_val = gettext("sem");
				break;
			case AT_IPC_SHM:
				uval.string_val = gettext("shm");
				break;
			}
			returnstat = pa_print(context, &uval, 0);
		}
		/* print in integer form */
		if ((context->format & PRF_RAWM) || (returnstat == 1)) {
			uval.uvaltype = PRA_BYTE;
			uval.char_val = ipctype;
			returnstat = pa_print(context, &uval, 0);
		}
		if ((returnstat = close_tag(context, TAG_IPCTYPE)) != 0)
			return (returnstat);

		/* next get and print ipc id */
		return (process_tag(context, TAG_IPCID, returnstat, 1));
	} else {
		/* cannot retrieve ipc type */
		return (-1);
	}
}

/*
 * -----------------------------------------------------------------------
 * text_token()	: Process text token and display contents
 * return codes	: -1 - error
 *		:  0 - successful
 * NOTE: At the time of call, the text token id has been retrieved
 *
 * Format of text token:
 *	text token id		adr_char
 * 	text			adr_string
 * -----------------------------------------------------------------------
 */
int
text_token(pr_context_t *context)
{
	return (pa_adr_string(context, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * tid_token()		: Process a generic terminal id token / AUT_TID
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the token id has been retrieved
 *
 * Format of tid token:
 *	ip token id	adr_char
 *	terminal type	adr_char
 *  terminal type = AU_IPADR:
 *	remote port:	adr_short
 *	local port:	adr_short
 *	IP type:	adt_int32 -- AU_IPv4 or AU_IPv6
 *	address:	adr_int32 if IPv4, else 4 * adr_int32
 * -----------------------------------------------------------------------
 */
int
tid_token(pr_context_t *context)
{
	int		returnstat;
	uchar_t		type;
	uval_t		uval;

	if ((returnstat = pr_adr_u_char(context, &type, 1)) != 0)
		return (returnstat);
	uval.uvaltype = PRA_STRING;
	if ((returnstat = open_tag(context, TAG_TID_TYPE)) != 0)
		return (returnstat);

	switch (type) {
	default:
		return (-1);	/* other than IP type is not implemented */
	case AU_IPADR:
		uval.string_val = "ip";
		returnstat = pa_print(context, &uval, 0);
		returnstat = close_tag(context, TAG_TID_TYPE);
		returnstat = open_tag(context, TAG_IP);
		returnstat = process_tag(context, TAG_IP_REMOTE, returnstat, 0);
		returnstat = process_tag(context, TAG_IP_LOCAL, returnstat, 0);
		returnstat = process_tag(context, TAG_IP_ADR, returnstat, 1);
		returnstat = close_tag(context, TAG_IP);
		break;
	}
	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * ip_addr_token() 	: Process ip token and display contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the ip token id has been retrieved
 *
 * Format of ip address token:
 *	ip token id	adr_char
 *	address		adr_int32 (printed in hex)
 * -----------------------------------------------------------------------
 */

int
ip_addr_token(pr_context_t *context)
{
	return (pa_hostname(context, 0, 1));
}

int
ip_addr_ex_token(pr_context_t *context)
{
	int	returnstat;
	uint32_t	ip_addr[16];
	uint32_t	ip_type;
	struct in_addr	ia;
	char		*ipstring;
	char		buf[256];
	uval_t		uval;

	/* get address type */
	if ((returnstat = pr_adr_u_int32(context, &ip_type, 1)) != 0)
		return (returnstat);

	/* legal address types are either AU_IPv4 or AU_IPv6 only */
	if ((ip_type != AU_IPv4) && (ip_type != AU_IPv6))
		return (-1);

	/* get address (4/16) */
	if ((returnstat = pr_adr_char(context, (char *)ip_addr, ip_type)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_STRING;
	if (ip_type == AU_IPv4) {
		uval.string_val = buf;

		if (!(context->format & PRF_RAWM)) {
			get_Hname(ip_addr[0], buf, sizeof (buf));
			return (pa_print(context, &uval, 1));
		}

		ia.s_addr = ip_addr[0];
		if ((ipstring = inet_ntoa(ia)) == NULL)
			return (-1);

		(void) snprintf(buf, sizeof (buf), "%s", ipstring);

	} else {
		uval.string_val = buf;

		if (!(context->format & PRF_RAWM)) {
			get_Hname_ex(ip_addr, buf, sizeof (buf));
			return (pa_print(context, &uval, 1));
		}

		(void) inet_ntop(AF_INET6, (void *) ip_addr, buf,
		    sizeof (buf));

	}

	return (pa_print(context, &uval, 1));
}

/*
 * -----------------------------------------------------------------------
 * ip_token()		: Process ip header token and display contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the ip token id has been retrieved
 *
 * Format of ip header token:
 *	ip header token id	adr_char
 *	version			adr_char (printed in hex)
 *	type of service		adr_char (printed in hex)
 *	length			adr_short
 *	id			adr_u_short
 *	offset			adr_u_short
 *	ttl			adr_char (printed in hex)
 *	protocol		adr_char (printed in hex)
 *	checksum		adr_u_short
 *	source address		adr_int32 (printed in hex)
 *	destination address	adr_int32 (printed in hex)
 * -----------------------------------------------------------------------
 */
int
ip_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_IPVERS, 0, 0);
	returnstat = process_tag(context, TAG_IPSERV, returnstat, 0);
	returnstat = process_tag(context, TAG_IPLEN, returnstat, 0);
	returnstat = process_tag(context, TAG_IPID, returnstat, 0);
	returnstat = process_tag(context, TAG_IPOFFS, returnstat, 0);
	returnstat = process_tag(context, TAG_IPTTL, returnstat, 0);
	returnstat = process_tag(context, TAG_IPPROTO, returnstat, 0);
	returnstat = process_tag(context, TAG_IPCKSUM, returnstat, 0);
	returnstat = process_tag(context, TAG_IPSRC, returnstat, 0);
	returnstat = process_tag(context, TAG_IPDEST, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * iport_token() 	: Process ip port address token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At time of call, the ip port address token id has been retrieved
 *
 * Format of ip port token:
 *	ip port address token id	adr_char
 *	port address			adr_short (in_port_t == uint16_t)
 * -----------------------------------------------------------------------
 */
int
iport_token(pr_context_t *context)
{
	return (pa_adr_u_short(context, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * socket_token() 	: Process socket token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At time of call, the socket token id has been retrieved
 *
 * Format of socket token:
 *	ip socket token id		adr_char
 *	socket type			adr_short (in hex)
 *	foreign port			adr_short (in hex)
 *	foreign internet address	adr_hostname/adr_int32 (in ascii/hex)
 * -----------------------------------------------------------------------
 *
 * Note: local port and local internet address have been removed for 5.x
 */
int
socket_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_SOCKTYPE, 0, 0);
	returnstat = process_tag(context, TAG_SOCKPORT, returnstat, 0);
	if (returnstat != 0)
		return (returnstat);

	if ((returnstat = open_tag(context, TAG_SOCKADDR)) != 0)
		return (returnstat);

	if ((returnstat = pa_hostname(context, returnstat, 1)) != 0)
		return (returnstat);

	return (close_tag(context, TAG_SOCKADDR));
}

/*
 * -----------------------------------------------------------------------
 * socket_ex_token()	: Process socket token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At time of call, the extended socket token id has been retrieved
 *
 * Format of extended socket token:
 *	token id			adr_char
 *	socket domain			adr_short (in hex)
 *	socket type			adr_short (in hex)
 *	IP address type			adr_short (in hex) [not displayed]
 *	local port			adr_short (in hex)
 *	local internet address		adr_hostname/adr_int32 (in ascii/hex)
 *	foreign port			adr_short (in hex)
 *	foreign internet address	adr_hostname/adr_int32 (in ascii/hex)
 * -----------------------------------------------------------------------
 *
 * Note: local port and local internet address have been removed for 5.x
 */
int
socket_ex_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_SOCKEXDOM, 0, 0);
	returnstat = process_tag(context, TAG_SOCKEXTYPE, returnstat, 0);
	returnstat = pa_hostname_so(context, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * sequence_token()	: Process sequence token and display contents
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At time of call, the socket token id has been retrieved
 *
 * Format of sequence token:
 *	sequence token id		adr_char
 *	sequence number 		adr_u_int32 (in hex)
 * -----------------------------------------------------------------------
 */
int
sequence_token(pr_context_t *context)
{
	return (process_tag(context, TAG_SEQNUM, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * acl_token()	: Process access control list term
 * return codes	: -1 - error
 *		:  0 - successful
 *
 * Format of acl token:
 *	token id	adr_char
 *	term type	adr_u_int32
 *	term value	adr_u_int32 (depends on type)
 *	file mode	adr_u_int (in octal)
 * -----------------------------------------------------------------------
 */
int
acl_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = pa_pw_uid_gr_gid(context, 0, 0);

	return (process_tag(context, TAG_MODE, returnstat, 1));
}

/*
 * -----------------------------------------------------------------------
 * ace_token()	: Process ZFS/NFSv4 access control list term
 * return codes	: -1 - error
 *		:  0 - successful
 *
 * Format of ace token:
 *	token id	adr_char
 *	term who	adr_u_int32 (uid/gid)
 *	term mask	adr_u_int32
 *	term flags	adr_u_int16
 *	term type	adr_u_int16
 * -----------------------------------------------------------------------
 */
int
ace_token(pr_context_t *context)
{
	return (pa_ace(context, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * attribute_token()	: Process attribute token and display contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the attribute token id has been retrieved
 *
 * Format of attribute token:
 *	attribute token id	adr_char
 * 	mode			adr_u_int (printed in octal)
 *	uid			adr_u_int
 *	gid			adr_u_int
 *	file system id		adr_int
 *
 *	node id			adr_int		(attribute_token
 *						 pre SunOS 5.7)
 *	device			adr_u_int
 * or
 *	node id			adr_int64	(attribute32_token)
 *	device			adr_u_int
 * or
 *	node id			adr_int64	(attribute64_token)
 *	device			adr_u_int64
 * -----------------------------------------------------------------------
 */
int
attribute_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_MODE, 0, 0);
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
	returnstat = process_tag(context, TAG_FSID, returnstat, 0);
	returnstat = process_tag(context, TAG_NODEID32, returnstat, 0);
	returnstat = process_tag(context, TAG_DEVICE32, returnstat, 1);

	return (returnstat);
}

int
attribute32_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_MODE, 0, 0);
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
	returnstat = process_tag(context, TAG_FSID, returnstat, 0);
	returnstat = process_tag(context, TAG_NODEID64, returnstat, 0);
	returnstat = process_tag(context, TAG_DEVICE32, returnstat, 1);

	return (returnstat);
}

int
attribute64_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_MODE, 0, 0);
	returnstat = process_tag(context, TAG_UID, returnstat, 0);
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
	returnstat = process_tag(context, TAG_FSID, returnstat, 0);
	returnstat = process_tag(context, TAG_NODEID64, returnstat, 0);
	returnstat = process_tag(context, TAG_DEVICE64, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * group_token() 	: Process group token and display contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the group token id has been retrieved
 * NOTE: This token is obsolete; it supports exactly NGROUPS_MAX
 * groups.
 *
 * Format of group token:
 *	group token id		adr_char
 *	group list		adr_long, 16 times
 * -----------------------------------------------------------------------
 */
int
group_token(pr_context_t *context)
{
	int	returnstat = 0;
	int	i;

	for (i = 0; i < NGROUPS_MAX - 1; i++) {
		if ((returnstat = process_tag(context, TAG_GROUPID,
		    returnstat, 0)) < 0)
			return (returnstat);
	}

	return (process_tag(context, TAG_GROUPID, returnstat, 1));
}

/*
 * -----------------------------------------------------------------------
 * newgroup_token() 	: Process group token and display contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the group token id has been retrieved
 *
 * Format of new group token:
 *	group token id		adr_char
 *	group number		adr_short
 *	group list		adr_int32, group number times
 * -----------------------------------------------------------------------
 */
int
newgroup_token(pr_context_t *context)
{
	int	returnstat;
	int	i, num;
	short	n_groups;

	returnstat = pr_adr_short(context, &n_groups, 1);
	if (returnstat != 0)
		return (returnstat);

	num = (int)n_groups;
	if (num == 0) {
		if (!(context->format & PRF_XMLM)) {
			returnstat = do_newline(context, 1);
		}
		return (returnstat);
	}
	for (i = 0; i < num - 1; i++) {
		if ((returnstat = process_tag(context, TAG_GROUPID,
		    returnstat, 0)) < 0)
			return (returnstat);
	}

	return (process_tag(context, TAG_GROUPID, returnstat, 1));
}

static int
string_token_common(pr_context_t *context, int tag)
{
	int	returnstat;
	int	num;

	returnstat = pr_adr_int32(context, (int32_t *)&num, 1);
	if (returnstat != 0)
		return (returnstat);

	if (!(context->format & PRF_XMLM)) {
		returnstat = pr_printf(context, "%d%s", num,
		    context->SEPARATOR);
		if (returnstat != 0)
			return (returnstat);
	}

	if (num == 0)
		return (do_newline(context, 1));

	for (; num > 1; num--) {
		if ((returnstat = (process_tag(context, tag,
		    returnstat, 0))) < 0)
			return (returnstat);
	}

	return (process_tag(context, tag, returnstat, 1));
}

int
path_attr_token(pr_context_t *context)
{
	return (string_token_common(context, TAG_XAT));
}

int
exec_args_token(pr_context_t *context)
{
	return (string_token_common(context, TAG_ARG));
}

int
exec_env_token(pr_context_t *context)
{
	return (string_token_common(context, TAG_ENV));
}

/*
 * -----------------------------------------------------------------------
 * s5_IPC_perm_token() : Process System V IPC permission token and display
 *			 contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the System V IPC permission token id
 * has been retrieved
 *
 * Format of System V IPC permission token:
 *	System V IPC permission token id	adr_char
 * 	uid					adr_u_int32
 *	gid					adr_u_int32
 *	cuid					adr_u_int32
 *	cgid					adr_u_int32
 *	mode					adr_u_int32
 *	seq					adr_u_int32
 *	key					adr_int32
 * -----------------------------------------------------------------------
 */
int
s5_IPC_perm_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_UID, 0, 0);
	returnstat = process_tag(context, TAG_GID, returnstat, 0);
	returnstat = process_tag(context, TAG_CUID, returnstat, 0);
	returnstat = process_tag(context, TAG_CGID, returnstat, 0);
	returnstat = process_tag(context, TAG_MODE, returnstat, 0);
	returnstat = process_tag(context, TAG_SEQ, returnstat, 0);
	returnstat = process_tag(context, TAG_KEY, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * host_token()	: Process host token and display contents
 * return codes	: -1 - error
 *		:  0 - successful
 * NOTE: At the time of call, the host token id has been retrieved
 *
 * Format of host token:
 *	host token id		adr_char
 *	hostid			adr_u_int32
 * -----------------------------------------------------------------------
 */
int
host_token(pr_context_t *context)
{
	return (pa_hostname(context, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * liaison_token()	: Process liaison token and display contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the liaison token id has been retrieved
 *
 * Format of liaison token:
 *	liaison token id	adr_char
 *	liaison			adr_u_int32
 * -----------------------------------------------------------------------
 */
int
liaison_token(pr_context_t *context)
{
	return (pa_liaison(context, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * useofauth_token(): Process useofauth token and display contents
 * return codes	: -1 - error
 *		:  0 - successful
 * NOTE: At the time of call, the uauth token id has been retrieved
 *
 * Format of useofauth token:
 *	uauth token id		adr_char
 * 	uauth			adr_string
 * -----------------------------------------------------------------------
 */
int
useofauth_token(pr_context_t *context)
{
	return (pa_adr_string(context, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * user_token(): Process user token and display contents
 * return codes	: -1 - error
 *		:  0 - successful
 * NOTE: At the time of call, the user token id has been retrieved
 *
 * Format of user token:
 *	user token id		adr_char
 *	user id			adr_uid
 * 	user name		adr_string
 * -----------------------------------------------------------------------
 */
int
user_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_UID, 0, 0);
	return (process_tag(context, TAG_USERNAME, returnstat, 1));
}

/*
 * -----------------------------------------------------------------------
 * zonename_token(): Process zonename token and display contents
 * return codes	: -1 - error
 *		:  0 - successful
 * NOTE: At the time of call, the zonename token id has been retrieved
 *
 * Format of zonename token:
 *	zonename token id	adr_char
 * 	zone name		adr_string
 * -----------------------------------------------------------------------
 */
int
zonename_token(pr_context_t *context)
{
	return (process_tag(context, TAG_ZONENAME, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * fmri_token(): Process fmri token and display contents
 * return codes	: -1 - error
 *		:  0 - successful
 * NOTE: At the time of call, the fmri token id has been retrieved
 *
 * Format of fmri token:
 *	fmri token id		adr_char
 * 	service instance name	adr_string
 * -----------------------------------------------------------------------
 */
int
fmri_token(pr_context_t *context)
{
	return (pa_adr_string(context, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * xatom_token()	: Process Xatom token and display contents in hex.
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the xatom token id has been retrieved
 *
 * Format of xatom token:
 *	token id		adr_char
 * 	length			adr_short
 * 	atom			adr_char length times
 * -----------------------------------------------------------------------
 */
int
xatom_token(pr_context_t *context)
{
	return (pa_adr_string(context, 0, 1));
}

int
xcolormap_token(pr_context_t *context)
{
	return (pa_xgeneric(context));
}

int
xcursor_token(pr_context_t *context)
{
	return (pa_xgeneric(context));
}

int
xfont_token(pr_context_t *context)
{
	return (pa_xgeneric(context));
}

int
xgc_token(pr_context_t *context)
{
	return (pa_xgeneric(context));
}

int
xpixmap_token(pr_context_t *context)
{
	return (pa_xgeneric(context));
}

int
xwindow_token(pr_context_t *context)
{
	return (pa_xgeneric(context));
}

/*
 * -----------------------------------------------------------------------
 * xproperty_token(): Process Xproperty token and display contents
 *
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the xproperty token id has been retrieved
 *
 * Format of xproperty token:
 *	token id		adr_char
 *	XID			adr_u_int32
 *	creator UID		adr_u_int32
 *	text			adr_text
 * -----------------------------------------------------------------------
 */
int
xproperty_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_XID, 0, 0);
	returnstat = process_tag(context, TAG_XCUID, returnstat, 0);

	/* Done with attributes; force end of token open */
	if (returnstat == 0)
		returnstat = finish_open_tag(context);

	returnstat = pa_adr_string(context, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * xselect_token(): Process Xselect token and display contents in hex
 *
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the xselect token id has been retrieved
 *
 * Format of xselect token
 *	text token id		adr_char
 * 	property text		adr_string
 * 	property type		adr_string
 * 	property data		adr_string
 * -----------------------------------------------------------------------
 */
int
xselect_token(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_XSELTEXT, 0, 0);
	returnstat = process_tag(context, TAG_XSELTYPE, returnstat, 0);
	returnstat = process_tag(context, TAG_XSELDATA, returnstat, 1);

	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * xclient_token(): Process Xclient token and display contents in hex.
 *
 * return codes		: -1 - error
 *			:  0 - successful
 *
 * Format of xclient token:
 *	token id		adr_char
 * 	client			adr_int32
 * -----------------------------------------------------------------------
 */
int
xclient_token(pr_context_t *context)
{
	return (pa_adr_int32(context, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * label_token() 	: Process label token and display contents
 * return codes 	: -1 - error
 *			: 0 - successful
 * NOTE: At the time of call, the label token id has been retrieved
 *
 * Format of label token:
 *	label token id			adr_char
 *      label ID                	adr_char
 *      label compartment length	adr_char
 *      label classification		adr_short
 *      label compartment words		<compartment length> * 4 adr_char
 * -----------------------------------------------------------------------
 */
/*ARGSUSED*/
int
label_token(pr_context_t *context)
{
	static m_label_t *label = NULL;
	static size32_t l_size;
	int	len;
	int	returnstat;
	uval_t	uval;

	if (label == NULL) {
		if ((label = m_label_alloc(MAC_LABEL)) == NULL) {
			return (-1);
		}
		l_size = blabel_size() - 4;
	}
	if ((returnstat = pr_adr_char(context, (char *)label, 4)) == 0) {
		len = (int)(((char *)label)[1] * 4);
		if ((len > l_size) ||
		    (pr_adr_char(context, &((char *)label)[4], len) != 0)) {
			return (-1);
		}
		uval.uvaltype = PRA_STRING;
		if (!(context->format & PRF_RAWM)) {
			/* print in ASCII form */
			if (label_to_str(label, &uval.string_val, M_LABEL,
			    DEF_NAMES) == 0) {
				returnstat = pa_print(context, &uval, 1);
			} else /* cannot convert to string */
				returnstat = 1;
		}
		/* print in hexadecimal form */
		if ((context->format & PRF_RAWM) || (returnstat == 1)) {
			uval.string_val = hexconvert((char *)label, len, len);
			if (uval.string_val) {
				returnstat = pa_print(context, &uval, 1);
			}
		}
		free(uval.string_val);
	}
	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * useofpriv_token() : Process priv token and display contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the useofpriv token id has been retrieved
 *
 * Format of useofpriv token:
 *	useofpriv token id	adr_char
 *	success/failure flag	adr_char
 *	priv			adr_int32 (Trusted Solaris)
 *	priv_set		'\0' separated privileges.
 * -----------------------------------------------------------------------
 */
/*ARGSUSED*/
int
useofpriv_token(pr_context_t *context)
{
	int	returnstat;
	char	sf;
	uval_t	uval;

	if ((returnstat = pr_adr_char(context, &sf, 1)) != 0) {
		return (returnstat);
	}
	if (!(context->format & PRF_RAWM)) {
		/* print in ASCII form */

		if ((returnstat = open_tag(context, TAG_RESULT)) != 0)
			return (returnstat);

		uval.uvaltype = PRA_STRING;
		if (sf) {
			uval.string_val = gettext("successful use of priv");
			returnstat = pa_print(context, &uval, 0);
		} else {
			uval.string_val = gettext("failed use of priv");
			returnstat = pa_print(context, &uval, 0);
		}
		if (returnstat == 0)
			returnstat = close_tag(context, TAG_RESULT);

		/* Done with attributes; force end of token open */
		if (returnstat == 0)
			returnstat = finish_open_tag(context);
	} else {
		/* print in hexadecimal form */
		if ((returnstat = open_tag(context, TAG_RESULT)) != 0)
			return (returnstat);
		uval.uvaltype = PRA_SHORT;
		uval.short_val = sf;
		returnstat = pa_print(context, &uval, 0);
		if (returnstat == 0)
			returnstat = close_tag(context, TAG_RESULT);

		/* Done with attributes; force end of token open */
		if (returnstat == 0)
			returnstat = finish_open_tag(context);
	}
	return (pa_adr_string(context, 0, 1));
}

/*
 * -----------------------------------------------------------------------
 * privilege_token()	: Process privilege token and display contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the privilege token id has been retrieved
 *
 * Format of privilege token:
 *	privilege token id	adr_char
 *	privilege type		adr_string
 *	privilege		adr_string
 * -----------------------------------------------------------------------
 */
int
privilege_token(pr_context_t *context)
{
	int	returnstat;

	/* privilege type: */
	returnstat = process_tag(context, TAG_SETTYPE, 0, 0);

	/* Done with attributes; force end of token open */
	if (returnstat == 0)
		returnstat = finish_open_tag(context);

	/* privilege: */
	return (pa_adr_string(context, returnstat, 1));
}

/*
 * -----------------------------------------------------------------------
 * secflags_token()	: Process privilege token and display contents
 * return codes 	: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the secflags token id has been retrieved
 *
 * Format of secflags token:
 *	secflags token id	adr_char
 *	secflag set name	adr_string
 *	secflags 		adr_string
 * -----------------------------------------------------------------------
 */
int
secflags_token(pr_context_t *context)
{
	int	returnstat;

	/* Set name */
	returnstat = process_tag(context, TAG_SETTYPE, 0, 0);

	/* Done with attributes; force end of token open */
	if (returnstat == 0)
		returnstat = finish_open_tag(context);

	/* set */
	return (pa_adr_string(context, returnstat, 1));
}
