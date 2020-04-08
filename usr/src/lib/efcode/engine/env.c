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
 */

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <fcode/private.h>
#include <fcode/log.h>


static variable_t verbose_emit;

void
do_verbose_emit(fcode_env_t *env)
{
	verbose_emit ^= 1;
}

/*
 * Internal "emit".
 * Note log_emit gathers up characters and issues a syslog or write to
 * error log file if enabled.
 */
void
do_emit(fcode_env_t *env, uchar_t c)
{
	if (verbose_emit)
		log_message(MSG_ERROR, "emit(%x)\n", c);

	if (c == '\n') {
		env->output_column = 0;
		env->output_line++;
	} else if (c == '\r')
		env->output_column = 0;
	else
		env->output_column++;
	if (isatty(fileno(stdout))) {
		if ((c >= 0x20 && c <= 0x7f) || c == '\n' || c == '\r' ||
		    c == '\b')
			putchar(c);
		else if (c < 0x20)
			printf("@%c", c + '@');
		else
			printf("\\%x", c);
		fflush(stdout);
	}
	log_emit(c);
}

void
system_message(fcode_env_t *env, char *msg)
{
	throw_from_fclib(env, 1, msg);
}

void
emit(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 1, "emit");
	d = POP(DS);
	do_emit(env, d);
}

#include <sys/time.h>

/*
 * 'key?' - abort if stdin is not a tty.
 */
void
keyquestion(fcode_env_t *env)
{
	struct timeval timeval;
	fd_set readfds;
	int ret;

	if (isatty(fileno(stdin))) {
		FD_ZERO(&readfds);
		FD_SET(fileno(stdin), &readfds);
		timeval.tv_sec = 0;
		timeval.tv_usec = 1000;
		ret = select(fileno(stdin) + 1, &readfds, NULL, NULL, &timeval);
		if (FD_ISSET(fileno(stdin), &readfds))
			PUSH(DS, TRUE);
		else
			PUSH(DS, FALSE);
	} else
		forth_abort(env, "'key?' called in non-interactive mode");
}

/*
 * 'key' - abort if stdin is not a tty, will block on read if char not avail.
 */
void
key(fcode_env_t *env)
{
	uchar_t c;

	if (isatty(fileno(stdin))) {
		read(fileno(stdin), &c, 1);
		PUSH(DS, c);
	} else
		forth_abort(env, "'key' called in non-interactive mode");
}

void
type(fcode_env_t *env)
{
	int len;
	char *ptr;

	CHECK_DEPTH(env, 2, "type");
	ptr = pop_a_string(env, &len);
	while (len--)
		do_emit(env, *ptr++);
}

void
paren_cr(fcode_env_t *env)
{
	do_emit(env, '\r');
}

void
fc_crlf(fcode_env_t *env)
{
	do_emit(env, '\n');
}

void
fc_num_out(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)(&env->output_column));
}

void
fc_num_line(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)(&env->output_line));
}

void
expect(fcode_env_t *env)
{
	char *buf, *rbuf;
	int len;

	CHECK_DEPTH(env, 2, "expect");
	buf = pop_a_string(env, &len);
	read_line(env);
	rbuf = pop_a_string(env, NULL);
	if (rbuf) {
		strcpy(buf, rbuf);
		env->span = strlen(buf);
	} else
		env->span = 0;
}

void
span(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)&env->span);
}

void
do_ms(fcode_env_t *env)
{
	fstack_t d;
	timespec_t rqtp;

	CHECK_DEPTH(env, 1, "ms");
	d = POP(DS);
	if (d) {
		rqtp.tv_sec = 0;
		rqtp.tv_nsec = d*1000*1000;
		nanosleep(&rqtp, 0);
	}
}

void
do_get_msecs(fcode_env_t *env)
{
	struct timeval tp;
	long ms;
	timespec_t rqtp;

	gettimeofday(&tp, NULL);
	ms = (tp.tv_usec/1000) + (tp.tv_sec * 1000);
	PUSH(DS, (fstack_t)ms);
	rqtp.tv_sec = 0;
	rqtp.tv_nsec = 1000*1000;
	nanosleep(&rqtp, 0);
}

#define	CMN_MSG_SIZE	256
#define	CMN_MAX_DIGITS	3

typedef struct CMN_MSG_T cmn_msg_t;

struct CMN_MSG_T {
	char		buf[CMN_MSG_SIZE];
	int		level;
	int		len;
	cmn_msg_t	*prev;
	cmn_msg_t	*next;
};

typedef struct CMN_FMT_T cmn_fmt_t;

struct CMN_FMT_T {
	int	fwidth;	/* format field width */
	int	cwidth; /* column width specified in format */
	char	format; /* format type */
};

static cmn_msg_t	*root = NULL;
static int		cmn_msg_level = 0;

/*
 *	validfmt()
 *
 * Called by fmt_str() function to validate and extract formatting
 * information from the supplied input buffer.
 *
 * Supported formats are:
 *	%c - character
 *	%d - signed decimal
 *	%x - unsigned hex
 *	%s - string
 *	%ld - signed 64 bit data
 *	%lx - unsigned 64 bit data
 *	%p - unsigned 64 bit data(pointer)
 *	%% - print as single "%" character
 *
 * Return values are:
 *	0  - valid formatting
 *	1  - invalid formatting found in the input buffer
 *	-1 - NULL pointer passed in for caller's receptacle
 *
 *
 * For valid formatting, caller's supplied cmn_fmt_t elements are
 * filled in:
 *	fwidth:
 *		> 0 - returned value is the field width
 *		< 0 - returned value is negation of field width for
 *			64 bit data formats
 *	cwidth:
 *	  formatted column width(if specified), otherwise 0
 *
 *	format:
 *	  contains the formatting(single) character
 */
static int
validfmt(char *fmt, cmn_fmt_t *cfstr)
{
	int	isll = 0;
	int	*fwidth, *cwidth;
	char	*format;
	char	*dig1, *dig2;
	char	cdigs[CMN_MAX_DIGITS+1];

	if (cfstr == NULL)
		return (-1);

	fwidth = &cfstr->fwidth;
	cwidth = &cfstr->cwidth;
	format = &cfstr->format;
	*fwidth = *cwidth = 0;
	*format = '\0';
	dig1 = dig2 = NULL;

	/* check for left justification character */
	if (*fmt == '-') {
		fmt++;
		(*fwidth)++;

		/* check for column width specification */
		if (isdigit(*fmt))
			dig1 = fmt;	/* save ptr to first digit */
		while (isdigit(*fmt)) {
			fmt++;
			(*fwidth)++;
		}
		/* if ljust specified w/o size, return format error */
		if (*fwidth == 1) {
			return (1);
		}
		dig2 = fmt;		/* save ptr to last digit + 1 */
	} else {
		/* check for column width specification */
		if (isdigit(*fmt)) {
			dig1 = fmt;	/* save ptr to first digit */
			while (isdigit(*fmt)) {
				fmt++;
				(*fwidth)++;
			}
			dig2 = fmt;	/* save ptr to last digit + 1 */
		}
	}

	/* if a column width was specified, save it in caller's struct */
	if (dig1) {
		int nbytes;

		nbytes = dig2 - dig1;
		/* if too many digits in the width return error */
		if (nbytes > CMN_MAX_DIGITS)
			return (1);
		strncpy(cdigs, dig1, nbytes);
		cdigs[nbytes] = 0;
		*cwidth = atoi(cdigs);
	}

	/* check for long format specifier */
	if (*fmt == 'l') {
		fmt++;
		(*fwidth)++;
		isll = 1;
	}

	/* process by specific format type */
	switch (*fmt) {
	case 'c':
	case 's':
	case '%':
		if (isll)
			return (1);
	case 'd':
	case 'x':
		*format = *fmt;
		(*fwidth)++;
		break;
	case 'p':
		isll = 1;		/* uses 64 bit format */
		*format = *fmt;
		(*fwidth)++;
		break;
	default:
		return (1);		/* unknown format type */
	}
	if (isll) {
		*fwidth *= -1;
	}
	return (0);
}

/*
 *	fmt_args()
 *
 * Called by fmt_str() to setup arguments for subsequent snprintf()
 * calls.  For cases not involving column width limitations, processing
 * simply POPs the data stack as required to setup caller's arg(or
 * llarg, as appropriate). When a column width is specified for output,
 * a temporary buffer is constructed to contain snprintf() generated
 * output for the argument. Testing is then performed to determine if
 * the specified column width will require truncation of the output.
 * If so, truncation of least significant digits is performed as
 * necessary, and caller's arg(or llarg) is adjusted to obtain the
 * specified column width.
 *
 */

static void
fmt_args(fcode_env_t *env, int cw, int fw, char format, long *arg,
    long long *llarg)
{
	char	*cbuf;
	char	snf[3];
	int	cbsize;
	int	cnv = 10, ndigits = 0;

	if (fw > 0) {	/* check for normal (not long) formats */

		/* initialize format string for snprintf call */
		snf[0] = '%';
		snf[1] = format;
		snf[2] = 0;

		/* process by format type */
		switch (format) {
		case 'x':
			cnv = 16;
		case 'd':
		case 'c':
		case 'p':
			*arg = POP(DS);
			break;
		case 's':
			POP(DS);
			*arg = POP(DS);
			break;
		case '%':
			return;
		default:
			log_message(MSG_ERROR,
			    "fmt_args:invalid format type! (%s)\n",
			    &format);
			return;
		}

		/* check if a column width was specified */
		if (cw) {
			/* allocate a scratch buffer */
			cbsize = 2*(sizeof (long long)) + 1;
			cbuf = MALLOC(cbsize);

			if (snprintf(cbuf, cbsize, snf, *arg) < 0)
				log_message(MSG_ERROR,
				    "fmt_args: snprintf output error\n");
			while ((cbuf[ndigits] != '\0') &&
			    (ndigits < cbsize))
				ndigits++;

			/* if truncation is necessary, do it */
			if (ndigits > cw) {
				cbuf[cw] = 0;
				if (format == 's') {
					char *str;
					str = (char *)*arg;
					str[cw] = 0;
				} else
					*arg = strtol(cbuf, (char **)NULL, cnv);
			}
			free(cbuf);
		}

	} else {	/* process long formats */

		*llarg = POP(DS);

		/* check if a column width was specified */
		if (cw) {
			/* allocate a scratch buffer */
			cbsize = 2*(sizeof (long long)) + 1;
			cbuf = MALLOC(cbsize);

			switch (format) {
			case 'p':
				cnv = 16;
				if (snprintf(cbuf, cbsize, "%p", *llarg) < 0)
					log_message(MSG_ERROR,
					    "fmt_args: snprintf error\n");
				break;
			case 'x':
				cnv = 16;
				if (snprintf(cbuf, cbsize, "%lx", *llarg) < 0)
					log_message(MSG_ERROR,
					    "fmt_args: snprintf error\n");
				break;
			case 'd':
				if (snprintf(cbuf, cbsize, "%ld", *llarg) < 0)
					log_message(MSG_ERROR,
					    "fmt_args: snprintf error\n");
				break;
			default:
				log_message(MSG_ERROR,
				    "invalid long format type! (l%s)\n",
				    &format);
				free(cbuf);
				return;
			}
			while ((cbuf[ndigits] != '\0') &&
			    (ndigits < cbsize)) {
				ndigits++;
			}
			/* if truncation is necessary, do it */
			if (ndigits > cw) {
				cbuf[cw] = 0;
				*llarg = strtoll(cbuf, (char **)NULL, cnv);
			}
			free(cbuf);
		}
	}
}

/*
 *	fmt_str()
 *
 * Extracts text from caller's input buffer, processes explicit
 * formatting as necessary, and outputs formatted text to caller's
 * receptacle.
 *
 *	env  - pointer to caller's fcode environment
 *	fmt  - pointer to caller's input buffr
 *	fmtbuf - ponter to caller's receptacle buffer
 *	bsize - size of caller's fmtbuf buffer
 *
 * This function performs an initial test to determine if caller's
 * input buffer contains formatting(specified by presence of "%")
 * in the buffer.  If so, validfmt() function is called to verify
 * the formatting, after which the buffer is processed according
 * to the field width specified by validfmt() output.  Special
 * processing is required when caller's buffer contains a double
 * "%" ("%%"), in which case the second "%" is accepted as normal
 * text.
 */

static void
fmt_str(fcode_env_t *env, char *fmt, char *fmtbuf, int bsize)
{
	char	tbuf[CMN_MSG_SIZE];
	char	*fmptr, *pct;
	int	l, cw, fw, bytes;
	long	arg;
	long long llarg;

	*fmtbuf = 0;
	if ((pct = strchr(fmt, '%')) != 0) {
		cmn_fmt_t	cfstr;
		int		vferr;

		l = strlen(pct++);
		vferr = validfmt(pct, &cfstr);
		if (!vferr) {
			fw = cfstr.fwidth;
			cw = cfstr.cwidth;
			fmptr = &cfstr.format;
		} else {
			if (vferr < 0) {
			log_message(MSG_ERROR,
			    "fmt_str: NULL ptr supplied to validfmt()\n");
			return;
			}

			bytes = pct - fmt;
			strncpy(tbuf, fmt, bytes);
			strncpy(tbuf+bytes, "%", 1);
			strncpy(tbuf+bytes+1, fmt+bytes, 1);
			bytes += 2;
			tbuf[bytes] = 0;

			log_message(MSG_ERROR,
			    "fmt_str: invalid format type! (%s)\n",
			    tbuf+bytes-3);

			strncpy(fmtbuf, tbuf, bsize);
			return;
		}

		if (fw > 0) {	/* process normal (not long) formats */
			bytes = pct - fmt + fw;
			strncpy(tbuf, fmt, bytes);
			tbuf[bytes] = 0;
		} else {
			/* if here, fw must be a long format */
			if (*fmptr == 'p') {
				bytes = pct - fmt - fw;
				strncpy(tbuf, fmt, bytes);
				tbuf[bytes] = 0;
			} else {
				bytes = pct - fmt - fw - 2;
				strncpy(tbuf, fmt, bytes);
				tbuf[bytes] = 'l';
				strncpy(tbuf+bytes+1, fmt+bytes, 2);
				tbuf[bytes+1+2] = 0;
			}
		}

		/* if more input buffer to process, recurse */
		if ((l - abs(fw)) != 0) {
			fmt_str(env, pct+abs(fw), (tbuf + strlen(tbuf)),
			    CMN_MSG_SIZE - strlen(tbuf));
		}

		/* call to extract args for snprintf() calls below */
		fmt_args(env, cw, fw, *fmptr, &arg, &llarg);

		if (fw > 0) {	/* process normal (not long) formats */
			switch (*fmptr) {
			case 'd':
			case 'x':
			case 'c':
			case 's':
			case 'p':
				(void) snprintf(fmtbuf, bsize, tbuf, arg);
				break;
			case '%':
				(void) snprintf(fmtbuf, bsize, tbuf);
				break;
			default:
				log_message(MSG_ERROR,
				    "fmt_str: invalid format (%s)\n",
				    fmptr);
				return;
			}

		} else	/* process long formats */
			(void) snprintf(fmtbuf, bsize, tbuf, llarg);

	} else
		strncpy(fmtbuf, fmt, bsize);
}

/*
 *	fc_cmn_append()
 *
 * Pops data stack to obtain message text, and calls fmt_str()
 * function to perform any message formatting necessary.
 *
 * This function is called from fc_cmn_end() or directly in
 * processing a cmn-append token.  Since a pre-existing message
 * context is assumed, initial checking is performed to verify
 * its existence.
 */

void
fc_cmn_append(fcode_env_t *env)
{
	int len;
	char *str;

	if (root == NULL) {
		log_message(MSG_ERROR,
		    "fc_cmn_append: no message context for append\n");
		return;
	}

	len = POP(DS);
	str = (char *)POP(DS);

	if ((root->len + len) < CMN_MSG_SIZE) {
		fmt_str(env, str, root->buf+root->len, CMN_MSG_SIZE -
		    root->len);
		root->len += len;
	} else
		log_message(MSG_ERROR,
		    "fc_cmn_append: append exceeds max msg size\n");
}

/*
 *	fc_cmn_end()
 *
 * Process ]cmn-end token to log the message initiated by a preceeding
 * fc_cmn_start() call.
 *
 * Since nested cmn-xxx[ calls are supported, a test is made to determine
 * if this is the final cmn-end of a nested sequence.  If so, or if
 * there was no nesting, log_message() is called with the appropriate
 * text buffer.  Otherwise, the root variable is adjusted to point to
 * the preceeding message in the sequence and links in the list are
 * updated. No logging is performed until the final ]cmn-end of the
 * sequence is processed; then, messages are logged in FIFO order.
 */
void
fc_cmn_end(fcode_env_t *env)
{
	cmn_msg_t *old;

	if (root == 0) {
		log_message(MSG_ERROR, "]cmn-end call w/o buffer\n");
		return;
	}

	fc_cmn_append(env);

	if (root->prev == 0) {
		cmn_msg_t *next;
		do {
			log_message(root->level, "%s\n", root->buf);
			next  = root->next;
			free(root);
			root = next;
		} while (root);
	} else {
		old = root->prev;
		old->next = root;
		root = old;
	}
}

/*
 *	fc_cmn_start()
 *
 * Generic function to begin a common message.
 *
 * Allocates a new cmn_msg_t to associate with the message, and sets
 * up initial text as specified by callers' inputs:
 *
 *	env  - pointer to caller's fcode environment
 *	head - pointer to initial text portion of the message
 *	path - flag to indicate if a device path is to be generated
 */
static void
fc_cmn_start(fcode_env_t *env, char *head, int path)
{
	cmn_msg_t *new;
	char		*dpath;

	new = MALLOC(sizeof (cmn_msg_t));
	new->prev = root;
	if (root != 0)
		root->next = new;
	strcpy(new->buf, head);
	new->len = strlen(head);
	if (path && env->current_device) {
		dpath = get_path(env, env->current_device);
		strcpy(new->buf+new->len, dpath);
		new->len += strlen(dpath);
		strncpy(new->buf+new->len++, ": ", 2);
		++new->len;
		free(dpath);
	}
	new->level = cmn_msg_level;
	new->next = NULL;
	root = new;
}

/*
 *	fc_cmn_type()
 *
 * Process cmn-type[ token.
 *
 * Invokes fc_cmn_start() to create a message containing blank
 * header and no device path information.
 */
void
fc_cmn_type(fcode_env_t *env)
{
	cmn_msg_level = MSG_INFO;
	fc_cmn_start(env, "", 0);
}

/*
 *	fc_cmn_msg()
 *
 * Process cmn-msg[ token.
 *
 * Invokes fc_cmn_start() to create a message containing blank
 * header but specifying device path information.
 */
void
fc_cmn_msg(fcode_env_t *env)
{

	cmn_msg_level = MSG_INFO;
	fc_cmn_start(env, "", 1);
}

/*
 *	fc_cmn_note()
 *
 * Process cmn-note[ token.
 *
 * Invokes fc_cmn_start() to create a message with NOTICE stamping in
 * the header and specification of device path information.
 */
void
fc_cmn_note(fcode_env_t *env)
{
	cmn_msg_level = MSG_NOTE;
	fc_cmn_start(env, "NOTICE: ", 1);
}

/*
 *	fc_cmn_warn()
 *
 * Process cmn-warn[ token.
 *
 * Invokes fc_cmn_start() to create a message with WARNING stamping in
 * the header and specification of device path information.
 */
void
fc_cmn_warn(fcode_env_t *env)
{
	cmn_msg_level = MSG_WARN;
	fc_cmn_start(env, "WARNING: ", 1);
}

/*
 *	fc_cmn_error()
 *
 * Process cmn-error[ token.
 *
 * Invokes fc_cmn_start() to create a message with ERROR stamping in
 * the header and specification of device path information.
 */
void
fc_cmn_error(fcode_env_t *env)
{
	cmn_msg_level = MSG_ERROR;
	fc_cmn_start(env, "ERROR: ", 1);
}

/*
 *	fc_cmn_fatal()
 *
 * Process cmn-fatal[ token.
 *
 * Invokes fc_cmn_start() to create a message with FATAL stamping in
 * the header and specification of device path information.
 */
void
fc_cmn_fatal(fcode_env_t *env)
{
	cmn_msg_level = MSG_FATAL;
	fc_cmn_start(env, "FATAL: ", 1);
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;
	ASSERT(env);
	NOTICE;

	ANSI(0x088, 0,		"span",			span);
	ANSI(0x08a, 0,		"expect",		expect);

	ANSI(0x08d, 0,		"key?",			keyquestion);
	ANSI(0x08e, 0,		"key",			key);
	ANSI(0x08f, 0,		"emit",			emit);
	ANSI(0x090, 0,		"type",			type);
	ANSI(0x091, 0,		"(cr",			paren_cr);
	ANSI(0x092, 0,		"cr",			fc_crlf);
	ANSI(0x093, 0,		"#out",			fc_num_out);
	ANSI(0x094, 0,		"#line",		fc_num_line);

	FCODE(0x125, 0,		"get-msecs",		do_get_msecs);
	FCODE(0x126, 0,		"ms",			do_ms);

	FORTH(0,		"verbose-emit",		do_verbose_emit);
	FCODE(0x7e9, 0,		"cmn-fatal[",		fc_cmn_fatal);
	FCODE(0x7ea, 0,		"cmn-error[",		fc_cmn_error);
	FCODE(0x7eb, 0,		"cmn-warn[",		fc_cmn_warn);
	FCODE(0x7ec, 0,		"cmn-note[",		fc_cmn_note);
	FCODE(0x7ed, 0,		"cmn-type[",		fc_cmn_type);
	FCODE(0x7ee, 0,		"cmn-append",		fc_cmn_append);
	FCODE(0x7ef, 0,		"]cmn-end",		fc_cmn_end);
	FCODE(0x7f0, 0,		"cmn-msg[",		fc_cmn_msg);
}
