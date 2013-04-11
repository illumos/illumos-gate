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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * MDB uses its own enhanced standard i/o mechanism for all input and output.
 * This file provides the underpinnings of this mechanism, including the
 * printf-style formatting code, the output pager, and APIs for raw input
 * and output.  This mechanism is used throughout the debugger for everything
 * from simple sprintf and printf-style formatting, to input to the lexer
 * and parser, to raw file i/o for reading ELF files.  In general, we divide
 * our i/o implementation into two parts:
 *
 * (1) An i/o buffer (mdb_iob_t) provides buffered read or write capabilities,
 * as well as access to formatting and the ability to invoke a pager.  The
 * buffer is constructed explicitly for use in either reading or writing; it
 * may not be used for both simultaneously.
 *
 * (2) Each i/o buffer is associated with an underlying i/o backend (mdb_io_t).
 * The backend provides, through an ops-vector, equivalents for the standard
 * read, write, lseek, ioctl, and close operations.  In addition, the backend
 * can provide an IOP_NAME entry point for returning a name for the backend,
 * IOP_LINK and IOP_UNLINK entry points that are called when the backend is
 * connected or disconnected from an mdb_iob_t, and an IOP_SETATTR entry point
 * for manipulating terminal attributes.
 *
 * The i/o objects themselves are reference counted so that more than one i/o
 * buffer may make use of the same i/o backend.  In addition, each buffer
 * provides the ability to push or pop backends to interpose on input or output
 * behavior.  We make use of this, for example, to implement interactive
 * session logging.  Normally, the stdout iob has a backend that is either
 * file descriptor 1, or a terminal i/o backend associated with the tty.
 * However, we can push a log i/o backend on top that multiplexes stdout to
 * the original back-end and another backend that writes to a log file.  The
 * use of i/o backends is also used for simplifying tasks such as making
 * lex and yacc read from strings for mdb_eval(), and making our ELF file
 * processing code read executable "files" from a crash dump via kvm_uread.
 *
 * Additionally, the formatting code provides auto-wrap and indent facilities
 * that are necessary for compatibility with adb macro formatting.  In auto-
 * wrap mode, the formatting code examines each new chunk of output to determine
 * if it will fit on the current line.  If not, instead of having the chunk
 * divided between the current line of output and the next, the auto-wrap
 * code will automatically output a newline, auto-indent the next line,
 * and then continue.  Auto-indent is implemented by simply prepending a number
 * of blanks equal to iob_margin to the start of each line.  The margin is
 * inserted when the iob is created, and following each flush of the buffer.
 */

#include <sys/types.h>
#include <sys/termios.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <mdb/mdb_types.h>
#include <mdb/mdb_argvec.h>
#include <mdb/mdb_stdlib.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_signal.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_demangle.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_lex.h>
#include <mdb/mdb.h>

/*
 * Define list of possible integer sizes for conversion routines:
 */
typedef enum {
	SZ_SHORT,		/* format %h? */
	SZ_INT,			/* format %? */
	SZ_LONG,		/* format %l? */
	SZ_LONGLONG		/* format %ll? */
} intsize_t;

/*
 * The iob snprintf family of functions makes use of a special "sprintf
 * buffer" i/o backend in order to provide the appropriate snprintf semantics.
 * This structure is maintained as the backend-specific private storage,
 * and its use is described in more detail below (see spbuf_write()).
 */
typedef struct {
	char *spb_buf;		/* pointer to underlying buffer */
	size_t spb_bufsiz;	/* length of underlying buffer */
	size_t spb_total;	/* total of all bytes passed via IOP_WRITE */
} spbuf_t;

/*
 * Define VA_ARG macro for grabbing the next datum to format for the printf
 * family of functions.  We use VA_ARG so that we can support two kinds of
 * argument lists: the va_list type supplied by <stdarg.h> used for printf and
 * vprintf, and an array of mdb_arg_t structures, which we expect will be
 * either type STRING or IMMEDIATE.  The vec_arg function takes care of
 * handling the mdb_arg_t case.
 */

typedef enum {
	VAT_VARARGS,		/* va_list is a va_list */
	VAT_ARGVEC		/* va_list is a const mdb_arg_t[] in disguise */
} vatype_t;

typedef struct {
	vatype_t val_type;
	union {
		va_list	_val_valist;
		const mdb_arg_t *_val_argv;
	} _val_u;
} varglist_t;

#define	val_valist	_val_u._val_valist
#define	val_argv	_val_u._val_argv

#define	VA_ARG(ap, type) ((ap->val_type == VAT_VARARGS) ? \
	va_arg(ap->val_valist, type) : (type)vec_arg(&ap->val_argv))
#define	VA_PTRARG(ap) ((ap->val_type == VAT_VARARGS) ? \
	(void *)va_arg(ap->val_valist, uintptr_t) : \
	(void *)(uintptr_t)vec_arg(&ap->val_argv))

/*
 * Define macro for converting char constant to Ctrl-char equivalent:
 */
#ifndef CTRL
#define	CTRL(c)	((c) & 0x01f)
#endif

/*
 * Define macro for determining if we should automatically wrap to the next
 * line of output, based on the amount of consumed buffer space and the
 * specified size of the next thing to be inserted (n).
 */
#define	IOB_WRAPNOW(iob, n)	\
	(((iob)->iob_flags & MDB_IOB_AUTOWRAP) && ((iob)->iob_nbytes != 0) && \
	((n) + (iob)->iob_nbytes > (iob)->iob_cols))

/*
 * Define prompt string and string to erase prompt string for iob_pager
 * function, which is invoked if the pager is enabled on an i/o buffer
 * and we're about to print a line which would be the last on the screen.
 */

static const char io_prompt[] = ">> More [<space>, <cr>, q, n, c, a] ? ";
static const char io_perase[] = "                                      ";

static const char io_pbcksp[] =
/*CSTYLED*/
"\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b";

static const size_t io_promptlen = sizeof (io_prompt) - 1;
static const size_t io_peraselen = sizeof (io_perase) - 1;
static const size_t io_pbcksplen = sizeof (io_pbcksp) - 1;

static ssize_t
iob_write(mdb_iob_t *iob, mdb_io_t *io, const void *buf, size_t n)
{
	ssize_t resid = n;
	ssize_t len;

	while (resid != 0) {
		if ((len = IOP_WRITE(io, buf, resid)) <= 0)
			break;

		buf = (char *)buf + len;
		resid -= len;
	}

	/*
	 * Note that if we had a partial write before an error, we still want
	 * to return the fact something was written.  The caller will get an
	 * error next time it tries to write anything.
	 */
	if (resid == n && n != 0) {
		iob->iob_flags |= MDB_IOB_ERR;
		return (-1);
	}

	return (n - resid);
}

static ssize_t
iob_read(mdb_iob_t *iob, mdb_io_t *io)
{
	ssize_t len;

	ASSERT(iob->iob_nbytes == 0);
	len = IOP_READ(io, iob->iob_buf, iob->iob_bufsiz);
	iob->iob_bufp = &iob->iob_buf[0];

	switch (len) {
	case -1:
		iob->iob_flags |= MDB_IOB_ERR;
		break;
	case 0:
		iob->iob_flags |= MDB_IOB_EOF;
		break;
	default:
		iob->iob_nbytes = len;
	}

	return (len);
}

/*ARGSUSED*/
static void
iob_winch(int sig, siginfo_t *sip, ucontext_t *ucp, void *data)
{
	siglongjmp(*((sigjmp_buf *)data), sig);
}

static int
iob_pager(mdb_iob_t *iob)
{
	int status = 0;
	sigjmp_buf env;
	uchar_t c;

	mdb_signal_f *termio_winch;
	void *termio_data;
	size_t old_rows;

	if (iob->iob_pgp == NULL || (iob->iob_flags & MDB_IOB_PGCONT))
		return (0);

	termio_winch = mdb_signal_gethandler(SIGWINCH, &termio_data);
	(void) mdb_signal_sethandler(SIGWINCH, iob_winch, &env);

	if (sigsetjmp(env, 1) != 0) {
		/*
		 * Reset the cursor back to column zero before printing a new
		 * prompt, since its position is unreliable after a SIGWINCH.
		 */
		(void) iob_write(iob, iob->iob_pgp, "\r", sizeof (char));
		old_rows = iob->iob_rows;

		/*
		 * If an existing SIGWINCH handler was present, call it.  We
		 * expect that this will be termio: the handler will read the
		 * new window size, and then resize this iob appropriately.
		 */
		if (termio_winch != (mdb_signal_f *)NULL)
			termio_winch(SIGWINCH, NULL, NULL, termio_data);

		/*
		 * If the window has increased in size, we treat this like a
		 * request to fill out the new remainder of the page.
		 */
		if (iob->iob_rows > old_rows) {
			iob->iob_flags &= ~MDB_IOB_PGSINGLE;
			iob->iob_nlines = old_rows;
			status = 0;
			goto winch;
		}
	}

	(void) iob_write(iob, iob->iob_pgp, io_prompt, io_promptlen);

	for (;;) {
		if (IOP_READ(iob->iob_pgp, &c, sizeof (c)) != sizeof (c)) {
			status = MDB_ERR_PAGER;
			break;
		}

		switch (c) {
		case 'N':
		case 'n':
		case '\n':
		case '\r':
			iob->iob_flags |= MDB_IOB_PGSINGLE;
			goto done;

		case CTRL('c'):
		case CTRL('\\'):
		case 'Q':
		case 'q':
			mdb_iob_discard(iob);
			status = MDB_ERR_PAGER;
			goto done;

		case 'A':
		case 'a':
			mdb_iob_discard(iob);
			status = MDB_ERR_ABORT;
			goto done;

		case 'C':
		case 'c':
			iob->iob_flags |= MDB_IOB_PGCONT;
			/*FALLTHRU*/

		case ' ':
			iob->iob_flags &= ~MDB_IOB_PGSINGLE;
			goto done;
		}
	}

done:
	(void) iob_write(iob, iob->iob_pgp, io_pbcksp, io_pbcksplen);
winch:
	(void) iob_write(iob, iob->iob_pgp, io_perase, io_peraselen);
	(void) iob_write(iob, iob->iob_pgp, io_pbcksp, io_pbcksplen);
	(void) mdb_signal_sethandler(SIGWINCH, termio_winch, termio_data);

	if ((iob->iob_flags & MDB_IOB_ERR) && status == 0)
		status = MDB_ERR_OUTPUT;

	return (status);
}

static void
iob_indent(mdb_iob_t *iob)
{
	if (iob->iob_nbytes == 0 && iob->iob_margin != 0 &&
	    (iob->iob_flags & MDB_IOB_INDENT)) {
		size_t i;

		ASSERT(iob->iob_margin < iob->iob_cols);
		ASSERT(iob->iob_bufp == iob->iob_buf);

		for (i = 0; i < iob->iob_margin; i++)
			*iob->iob_bufp++ = ' ';

		iob->iob_nbytes = iob->iob_margin;
	}
}

static void
iob_unindent(mdb_iob_t *iob)
{
	if (iob->iob_nbytes != 0 && iob->iob_nbytes == iob->iob_margin) {
		const char *p = iob->iob_buf;

		while (p < &iob->iob_buf[iob->iob_margin]) {
			if (*p++ != ' ')
				return;
		}

		iob->iob_bufp = &iob->iob_buf[0];
		iob->iob_nbytes = 0;
	}
}

mdb_iob_t *
mdb_iob_create(mdb_io_t *io, uint_t flags)
{
	mdb_iob_t *iob = mdb_alloc(sizeof (mdb_iob_t), UM_SLEEP);

	iob->iob_buf = mdb_alloc(BUFSIZ, UM_SLEEP);
	iob->iob_bufsiz = BUFSIZ;
	iob->iob_bufp = &iob->iob_buf[0];
	iob->iob_nbytes = 0;
	iob->iob_nlines = 0;
	iob->iob_lineno = 1;
	iob->iob_rows = MDB_IOB_DEFROWS;
	iob->iob_cols = MDB_IOB_DEFCOLS;
	iob->iob_tabstop = MDB_IOB_DEFTAB;
	iob->iob_margin = MDB_IOB_DEFMARGIN;
	iob->iob_flags = flags & ~(MDB_IOB_EOF|MDB_IOB_ERR) | MDB_IOB_AUTOWRAP;
	iob->iob_iop = mdb_io_hold(io);
	iob->iob_pgp = NULL;
	iob->iob_next = NULL;

	IOP_LINK(io, iob);
	iob_indent(iob);
	return (iob);
}

void
mdb_iob_pipe(mdb_iob_t **iobs, mdb_iobsvc_f *rdsvc, mdb_iobsvc_f *wrsvc)
{
	mdb_io_t *pio = mdb_pipeio_create(rdsvc, wrsvc);
	int i;

	iobs[0] = mdb_iob_create(pio, MDB_IOB_RDONLY);
	iobs[1] = mdb_iob_create(pio, MDB_IOB_WRONLY);

	for (i = 0; i < 2; i++) {
		iobs[i]->iob_flags &= ~MDB_IOB_AUTOWRAP;
		iobs[i]->iob_cols = iobs[i]->iob_bufsiz;
	}
}

void
mdb_iob_destroy(mdb_iob_t *iob)
{
	/*
	 * Don't flush a pipe, since it may cause a context swith when the
	 * other side has already been destroyed.
	 */
	if (!mdb_iob_isapipe(iob))
		mdb_iob_flush(iob);

	if (iob->iob_pgp != NULL)
		mdb_io_rele(iob->iob_pgp);

	while (iob->iob_iop != NULL) {
		IOP_UNLINK(iob->iob_iop, iob);
		(void) mdb_iob_pop_io(iob);
	}

	mdb_free(iob->iob_buf, iob->iob_bufsiz);
	mdb_free(iob, sizeof (mdb_iob_t));
}

void
mdb_iob_discard(mdb_iob_t *iob)
{
	iob->iob_bufp = &iob->iob_buf[0];
	iob->iob_nbytes = 0;
}

void
mdb_iob_flush(mdb_iob_t *iob)
{
	int pgerr = 0;

	if (iob->iob_nbytes == 0)
		return; /* Nothing to do if buffer is empty */

	if (iob->iob_flags & MDB_IOB_WRONLY) {
		if (iob->iob_flags & MDB_IOB_PGSINGLE) {
			iob->iob_flags &= ~MDB_IOB_PGSINGLE;
			iob->iob_nlines = 0;
			pgerr = iob_pager(iob);

		} else if (iob->iob_nlines >= iob->iob_rows - 1) {
			iob->iob_nlines = 0;
			if (iob->iob_flags & MDB_IOB_PGENABLE)
				pgerr = iob_pager(iob);
		}

		if (pgerr == 0) {
			/*
			 * We only jump out of the dcmd on error if the iob is
			 * m_out. Presumably, if a dcmd has opened a special
			 * file and is writing to it, it will handle errors
			 * properly.
			 */
			if (iob_write(iob, iob->iob_iop, iob->iob_buf,
			    iob->iob_nbytes) < 0 && iob == mdb.m_out)
				pgerr = MDB_ERR_OUTPUT;
			iob->iob_nlines++;
		}
	}

	iob->iob_bufp = &iob->iob_buf[0];
	iob->iob_nbytes = 0;
	iob_indent(iob);

	if (pgerr)
		longjmp(mdb.m_frame->f_pcb, pgerr);
}

void
mdb_iob_nlflush(mdb_iob_t *iob)
{
	iob_unindent(iob);

	if (iob->iob_nbytes != 0)
		mdb_iob_nl(iob);
	else
		iob_indent(iob);
}

void
mdb_iob_push_io(mdb_iob_t *iob, mdb_io_t *io)
{
	ASSERT(io->io_next == NULL);

	io->io_next = iob->iob_iop;
	iob->iob_iop = mdb_io_hold(io);
}

mdb_io_t *
mdb_iob_pop_io(mdb_iob_t *iob)
{
	mdb_io_t *io = iob->iob_iop;

	if (io != NULL) {
		iob->iob_iop = io->io_next;
		io->io_next = NULL;
		mdb_io_rele(io);
	}

	return (io);
}

void
mdb_iob_resize(mdb_iob_t *iob, size_t rows, size_t cols)
{
	if (cols > iob->iob_bufsiz)
		iob->iob_cols = iob->iob_bufsiz;
	else
		iob->iob_cols = cols != 0 ? cols : MDB_IOB_DEFCOLS;

	iob->iob_rows = rows != 0 ? rows : MDB_IOB_DEFROWS;
}

void
mdb_iob_setpager(mdb_iob_t *iob, mdb_io_t *pgio)
{
	struct winsize winsz;

	if (iob->iob_pgp != NULL) {
		IOP_UNLINK(iob->iob_pgp, iob);
		mdb_io_rele(iob->iob_pgp);
	}

	iob->iob_flags |= MDB_IOB_PGENABLE;
	iob->iob_flags &= ~(MDB_IOB_PGSINGLE | MDB_IOB_PGCONT);
	iob->iob_pgp = mdb_io_hold(pgio);

	IOP_LINK(iob->iob_pgp, iob);

	if (IOP_CTL(pgio, TIOCGWINSZ, &winsz) == 0)
		mdb_iob_resize(iob, (size_t)winsz.ws_row, (size_t)winsz.ws_col);
}

void
mdb_iob_tabstop(mdb_iob_t *iob, size_t tabstop)
{
	iob->iob_tabstop = MIN(tabstop, iob->iob_cols - 1);
}

void
mdb_iob_margin(mdb_iob_t *iob, size_t margin)
{
	iob_unindent(iob);
	iob->iob_margin = MIN(margin, iob->iob_cols - 1);
	iob_indent(iob);
}

void
mdb_iob_setbuf(mdb_iob_t *iob, void *buf, size_t bufsiz)
{
	ASSERT(buf != NULL && bufsiz != 0);

	mdb_free(iob->iob_buf, iob->iob_bufsiz);
	iob->iob_buf = buf;
	iob->iob_bufsiz = bufsiz;

	if (iob->iob_flags & MDB_IOB_WRONLY)
		iob->iob_cols = MIN(iob->iob_cols, iob->iob_bufsiz);
}

void
mdb_iob_clearlines(mdb_iob_t *iob)
{
	iob->iob_flags &= ~(MDB_IOB_PGSINGLE | MDB_IOB_PGCONT);
	iob->iob_nlines = 0;
}

void
mdb_iob_setflags(mdb_iob_t *iob, uint_t flags)
{
	iob->iob_flags |= flags;
	if (flags & MDB_IOB_INDENT)
		iob_indent(iob);
}

void
mdb_iob_clrflags(mdb_iob_t *iob, uint_t flags)
{
	iob->iob_flags &= ~flags;
	if (flags & MDB_IOB_INDENT)
		iob_unindent(iob);
}

uint_t
mdb_iob_getflags(mdb_iob_t *iob)
{
	return (iob->iob_flags);
}

static uintmax_t
vec_arg(const mdb_arg_t **app)
{
	uintmax_t value;

	if ((*app)->a_type == MDB_TYPE_STRING)
		value = (uintmax_t)(uintptr_t)(*app)->a_un.a_str;
	else
		value = (*app)->a_un.a_val;

	(*app)++;
	return (value);
}

static const char *
iob_size2str(intsize_t size)
{
	switch (size) {
	case SZ_SHORT:
		return ("short");
	case SZ_INT:
		return ("int");
	case SZ_LONG:
		return ("long");
	case SZ_LONGLONG:
		return ("long long");
	}
	return ("");
}

/*
 * In order to simplify maintenance of the ::formats display, we provide an
 * unparser for mdb_printf format strings that converts a simple format
 * string with one specifier into a descriptive representation, e.g.
 * mdb_iob_format2str("%llx") returns "hexadecimal long long".
 */
const char *
mdb_iob_format2str(const char *format)
{
	intsize_t size = SZ_INT;
	const char *p;

	static char buf[64];

	buf[0] = '\0';

	if ((p = strchr(format, '%')) == NULL)
		goto done;

fmt_switch:
	switch (*++p) {
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		while (*p >= '0' && *p <= '9')
			p++;
		p--;
		goto fmt_switch;

	case 'a':
	case 'A':
		return ("symbol");

	case 'b':
		(void) strcpy(buf, "unsigned ");
		(void) strcat(buf, iob_size2str(size));
		(void) strcat(buf, " bitfield");
		break;

	case 'c':
		return ("character");

	case 'd':
	case 'i':
		(void) strcpy(buf, "decimal signed ");
		(void) strcat(buf, iob_size2str(size));
		break;

	case 'e':
	case 'E':
	case 'g':
	case 'G':
		return ("double");

	case 'h':
		size = SZ_SHORT;
		goto fmt_switch;

	case 'H':
		return ("human-readable size");

	case 'I':
		return ("IPv4 address");

	case 'l':
		if (size >= SZ_LONG)
			size = SZ_LONGLONG;
		else
			size = SZ_LONG;
		goto fmt_switch;

	case 'm':
		return ("margin");

	case 'N':
		return ("IPv6 address");

	case 'o':
		(void) strcpy(buf, "octal unsigned ");
		(void) strcat(buf, iob_size2str(size));
		break;

	case 'p':
		return ("pointer");

	case 'q':
		(void) strcpy(buf, "octal signed ");
		(void) strcat(buf, iob_size2str(size));
		break;

	case 'r':
		(void) strcpy(buf, "default radix unsigned ");
		(void) strcat(buf, iob_size2str(size));
		break;

	case 'R':
		(void) strcpy(buf, "default radix signed ");
		(void) strcat(buf, iob_size2str(size));
		break;

	case 's':
		return ("string");

	case 't':
	case 'T':
		return ("tab");

	case 'u':
		(void) strcpy(buf, "decimal unsigned ");
		(void) strcat(buf, iob_size2str(size));
		break;

	case 'x':
	case 'X':
		(void) strcat(buf, "hexadecimal ");
		(void) strcat(buf, iob_size2str(size));
		break;

	case 'Y':
		return ("time_t");

	case '<':
		return ("terminal attribute");

	case '?':
	case '#':
	case '+':
	case '-':
		goto fmt_switch;
	}

done:
	if (buf[0] == '\0')
		(void) strcpy(buf, "text");

	return ((const char *)buf);
}

static const char *
iob_int2str(varglist_t *ap, intsize_t size, int base, uint_t flags, int *zero,
    u_longlong_t *value)
{
	uintmax_t i;

	switch (size) {
	case SZ_LONGLONG:
		if (flags & NTOS_UNSIGNED)
			i = (u_longlong_t)VA_ARG(ap, u_longlong_t);
		else
			i = (longlong_t)VA_ARG(ap, longlong_t);
		break;

	case SZ_LONG:
		if (flags & NTOS_UNSIGNED)
			i = (ulong_t)VA_ARG(ap, ulong_t);
		else
			i = (long)VA_ARG(ap, long);
		break;

	case SZ_SHORT:
		if (flags & NTOS_UNSIGNED)
			i = (ushort_t)VA_ARG(ap, uint_t);
		else
			i = (short)VA_ARG(ap, int);
		break;

	default:
		if (flags & NTOS_UNSIGNED)
			i = (uint_t)VA_ARG(ap, uint_t);
		else
			i = (int)VA_ARG(ap, int);
	}

	*zero = i == 0;	/* Return flag indicating if result was zero */
	*value = i;	/* Return value retrieved from va_list */

	return (numtostr(i, base, flags));
}

static const char *
iob_time2str(time_t *tmp)
{
	/*
	 * ctime(3c) returns a string of the form
	 * "Fri Sep 13 00:00:00 1986\n\0".  We turn this into the canonical
	 * adb /y format "1986 Sep 13 00:00:00" below.
	 */
	const char *src = ctime(tmp);
	static char buf[32];
	char *dst = buf;
	int i;

	if (src == NULL)
		return (numtostr((uintmax_t)*tmp, mdb.m_radix, 0));

	for (i = 20; i < 24; i++)
		*dst++ = src[i]; /* Copy the 4-digit year */

	for (i = 3; i < 19; i++)
		*dst++ = src[i]; /* Copy month, day, and h:m:s */

	*dst = '\0';
	return (buf);
}

static const char *
iob_addr2str(uintptr_t addr)
{
	static char buf[MDB_TGT_SYM_NAMLEN];
	char *name = buf;
	longlong_t offset;
	GElf_Sym sym;

	if (mdb_tgt_lookup_by_addr(mdb.m_target, addr,
	    MDB_TGT_SYM_FUZZY, buf, sizeof (buf), &sym, NULL) == -1)
		return (NULL);

	if (mdb.m_demangler != NULL && (mdb.m_flags & MDB_FL_DEMANGLE))
		name = (char *)mdb_dem_convert(mdb.m_demangler, buf);

	/*
	 * Here we provide a little cooperation between the %a formatting code
	 * and the proc target: if the initial address passed to %a is in fact
	 * a PLT address, the proc target's lookup_by_addr code will convert
	 * this to the PLT destination (a different address).  We do not want
	 * to append a "+/-offset" suffix based on comparison with the query
	 * symbol in this case because the proc target has really done a hidden
	 * query for us with a different address.  We detect this case by
	 * comparing the initial characters of buf to the special PLT= string.
	 */
	if (sym.st_value != addr && strncmp(name, "PLT=", 4) != 0) {
		if (sym.st_value > addr)
			offset = -(longlong_t)(sym.st_value - addr);
		else
			offset = (longlong_t)(addr - sym.st_value);

		(void) strcat(name, numtostr(offset, mdb.m_radix,
		    NTOS_SIGNPOS | NTOS_SHOWBASE));
	}

	return (name);
}

/*
 * Produce human-readable size, similar in spirit (and identical in output)
 * to libzfs's zfs_nicenum() -- but made significantly more complicated by
 * the constraint that we cannot use snprintf() as an implementation detail.
 * Recall, floating point is verboten in kmdb.
 */
static const char *
iob_bytes2str(varglist_t *ap, intsize_t size)
{
#ifndef _KMDB
	const int sigfig = 3;
	uint64_t orig;
#endif
	uint64_t n;

	static char buf[68], *c;
	int index = 0;
	char u;

	switch (size) {
	case SZ_LONGLONG:
		n = (u_longlong_t)VA_ARG(ap, u_longlong_t);
		break;

	case SZ_LONG:
		n = (ulong_t)VA_ARG(ap, ulong_t);
		break;

	case SZ_SHORT:
		n = (ushort_t)VA_ARG(ap, uint_t);

	default:
		n = (uint_t)VA_ARG(ap, uint_t);
	}

#ifndef _KMDB
	orig = n;
#endif

	while (n >= 1024) {
		n /= 1024;
		index++;
	}

	u = " KMGTPE"[index];
	buf[0] = '\0';

	if (index == 0) {
		return (numtostr(n, 10, 0));
#ifndef _KMDB
	} else if ((orig & ((1ULL << 10 * index) - 1)) == 0) {
#else
	} else {
#endif
		/*
		 * If this is an even multiple of the base or we are in an
		 * environment where floating point is verboten (i.e., kmdb),
		 * always display without any decimal precision.
		 */
		(void) strcat(buf, numtostr(n, 10, 0));
#ifndef _KMDB
	} else {
		/*
		 * We want to choose a precision that results in the specified
		 * number of significant figures (by default, 3).  This is
		 * similar to the output that one would get specifying the %.*g
		 * format specifier (where the asterisk denotes the number of
		 * significant digits), but (1) we include trailing zeros if
		 * the there are non-zero digits beyond the number of
		 * significant digits (that is, 10241 is '10.0K', not the
		 * '10K' that it would be with %.3g) and (2) we never resort
		 * to %e notation when the number of digits exceeds the
		 * number of significant figures (that is, 1043968 is '1020K',
		 * not '1.02e+03K').  This is also made somewhat complicated
		 * by the fact that we need to deal with rounding (10239 is
		 * '10.0K', not '9.99K'), for which we perform nearest-even
		 * rounding.
		 */
		double val = (double)orig / (1ULL << 10 * index);
		int i, mag = 1, thresh;

		for (i = 0; i < sigfig - 1; i++)
			mag *= 10;

		for (thresh = mag * 10; mag >= 1; mag /= 10, i--) {
			double mult = val * (double)mag;
			uint32_t v;

			/*
			 * Note that we cast mult to a 32-bit value.  We know
			 * that val is less than 1024 due to the logic above,
			 * and that mag is at most 10^(sigfig - 1).  This means
			 * that as long as sigfig is 9 or lower, this will not
			 * overflow.  (We perform this cast because it assures
			 * that we are never converting a double to a uint64_t,
			 * which for some compilers requires a call to a
			 * function not guaranteed to be in libstand.)
			 */
			if (mult - (double)(uint32_t)mult != 0.5) {
				v = (uint32_t)(mult + 0.5);
			} else {
				/*
				 * We are exactly between integer multiples
				 * of units; perform nearest-even rounding
				 * to be consistent with the behavior of
				 * printf().
				 */
				if ((v = (uint32_t)mult) & 1)
					v++;
			}

			if (mag == 1) {
				(void) strcat(buf, numtostr(v, 10, 0));
				break;
			}

			if (v < thresh) {
				(void) strcat(buf, numtostr(v / mag, 10, 0));
				(void) strcat(buf, ".");

				c = (char *)numtostr(v % mag, 10, 0);
				i -= strlen(c);

				/*
				 * We need to zero-fill from the right of the
				 * decimal point to the first significant digit
				 * of the fractional component.
				 */
				while (i--)
					(void) strcat(buf, "0");

				(void) strcat(buf, c);
				break;
			}
		}
#endif
	}

	c = &buf[strlen(buf)];
	*c++ = u;
	*c++ = '\0';

	return (buf);
}

static int
iob_setattr(mdb_iob_t *iob, const char *s, size_t nbytes)
{
	uint_t attr;
	int req;

	if (iob->iob_pgp == NULL)
		return (set_errno(ENOTTY));

	if (nbytes != 0 && *s == '/') {
		req = ATT_OFF;
		nbytes--;
		s++;
	} else
		req = ATT_ON;

	if (nbytes != 1)
		return (set_errno(EINVAL));

	switch (*s) {
	case 's':
		attr = ATT_STANDOUT;
		break;
	case 'u':
		attr = ATT_UNDERLINE;
		break;
	case 'r':
		attr = ATT_REVERSE;
		break;
	case 'b':
		attr = ATT_BOLD;
		break;
	case 'd':
		attr = ATT_DIM;
		break;
	case 'a':
		attr = ATT_ALTCHARSET;
		break;
	default:
		return (set_errno(EINVAL));
	}

	/*
	 * We need to flush the current buffer contents before calling
	 * IOP_SETATTR because IOP_SETATTR may need to synchronously output
	 * terminal escape sequences directly to the underlying device.
	 */
	(void) iob_write(iob, iob->iob_iop, iob->iob_buf, iob->iob_nbytes);
	iob->iob_bufp = &iob->iob_buf[0];
	iob->iob_nbytes = 0;

	return (IOP_SETATTR(iob->iob_pgp, req, attr));
}

static void
iob_bits2str(mdb_iob_t *iob, u_longlong_t value, const mdb_bitmask_t *bmp,
    mdb_bool_t altflag)
{
	mdb_bool_t delim = FALSE;
	const char *str;
	size_t width;

	if (bmp == NULL)
		goto out;

	for (; bmp->bm_name != NULL; bmp++) {
		if ((value & bmp->bm_mask) == bmp->bm_bits) {
			width = strlen(bmp->bm_name) + delim;

			if (IOB_WRAPNOW(iob, width))
				mdb_iob_nl(iob);

			if (delim)
				mdb_iob_putc(iob, ',');
			else
				delim = TRUE;

			mdb_iob_puts(iob, bmp->bm_name);
			value &= ~bmp->bm_bits;
		}
	}

out:
	if (altflag == TRUE && (delim == FALSE || value != 0)) {
		str = numtostr(value, 16, NTOS_UNSIGNED | NTOS_SHOWBASE);
		width = strlen(str) + delim;

		if (IOB_WRAPNOW(iob, width))
			mdb_iob_nl(iob);
		if (delim)
			mdb_iob_putc(iob, ',');
		mdb_iob_puts(iob, str);
	}
}

static const char *
iob_inaddr2str(uint32_t addr)
{
	static char buf[INET_ADDRSTRLEN];

	(void) mdb_inet_ntop(AF_INET, &addr, buf, sizeof (buf));

	return (buf);
}

static const char *
iob_ipv6addr2str(void *addr)
{
	static char buf[INET6_ADDRSTRLEN];

	(void) mdb_inet_ntop(AF_INET6, addr, buf, sizeof (buf));

	return (buf);
}

static const char *
iob_getvar(const char *s, size_t len)
{
	mdb_var_t *val;
	char *var;

	if (len == 0) {
		(void) set_errno(EINVAL);
		return (NULL);
	}

	var = strndup(s, len);
	val = mdb_nv_lookup(&mdb.m_nv, var);
	strfree(var);

	if (val == NULL) {
		(void) set_errno(EINVAL);
		return (NULL);
	}

	return (numtostr(mdb_nv_get_value(val), 10, 0));
}

/*
 * The iob_doprnt function forms the main engine of the debugger's output
 * formatting capabilities.  Note that this is NOT exactly compatible with
 * the printf(3S) family, nor is it intended to be so.  We support some
 * extensions and format characters not supported by printf(3S), and we
 * explicitly do NOT provide support for %C, %S, %ws (wide-character strings),
 * do NOT provide for the complete functionality of %f, %e, %E, %g, %G
 * (alternate double formats), and do NOT support %.x (precision specification).
 * Note that iob_doprnt consumes varargs off the original va_list.
 */
static void
iob_doprnt(mdb_iob_t *iob, const char *format, varglist_t *ap)
{
	char c[2] = { 0, 0 };	/* Buffer for single character output */
	const char *p;		/* Current position in format string */
	size_t len;		/* Length of format string to copy verbatim */
	size_t altlen;		/* Length of alternate print format prefix */
	const char *altstr;	/* Alternate print format prefix */
	const char *symstr;	/* Symbol + offset string */

	u_longlong_t val;	/* Current integer value */
	intsize_t size;		/* Current integer value size */
	uint_t flags;		/* Current flags to pass to iob_int2str */
	size_t width;		/* Current field width */
	int zero;		/* If != 0, then integer value == 0 */

	mdb_bool_t f_alt;	/* Use alternate print format (%#) */
	mdb_bool_t f_altsuff;	/* Alternate print format is a suffix */
	mdb_bool_t f_zfill;	/* Zero-fill field (%0) */
	mdb_bool_t f_left;	/* Left-adjust field (%-) */
	mdb_bool_t f_digits;	/* Explicit digits used to set field width */

	union {
		const char *str;
		uint32_t ui32;
		void *ptr;
		time_t tm;
		char c;
		double d;
		long double ld;
	} u;

	ASSERT(iob->iob_flags & MDB_IOB_WRONLY);

	while ((p = strchr(format, '%')) != NULL) {
		/*
		 * Output the format string verbatim up to the next '%' char
		 */
		if (p != format) {
			len = p - format;
			if (IOB_WRAPNOW(iob, len) && *format != '\n')
				mdb_iob_nl(iob);
			mdb_iob_nputs(iob, format, len);
		}

		/*
		 * Now we need to parse the sequence of format characters
		 * following the % marker and do the appropriate thing.
		 */
		size = SZ_INT;		/* Use normal-sized int by default */
		flags = 0;		/* Clear numtostr() format flags */
		width = 0;		/* No field width limit by default */
		altlen = 0;		/* No alternate format string yet */
		altstr = NULL;		/* No alternate format string yet */

		f_alt = FALSE;		/* Alternate format off by default */
		f_altsuff = FALSE;	/* Alternate format is a prefix */
		f_zfill = FALSE;	/* Zero-fill off by default */
		f_left = FALSE;		/* Left-adjust off by default */
		f_digits = FALSE;	/* No digits for width specified yet */

		fmt_switch:
		switch (*++p) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			if (f_digits == FALSE && *p == '0') {
				f_zfill = TRUE;
				goto fmt_switch;
			}

			if (f_digits == FALSE)
				width = 0; /* clear any other width specifier */

			for (u.c = *p; u.c >= '0' && u.c <= '9'; u.c = *++p)
				width = width * 10 + u.c - '0';

			p--;
			f_digits = TRUE;
			goto fmt_switch;

		case 'a':
			if (size < SZ_LONG)
				size = SZ_LONG;	/* Bump to size of uintptr_t */

			u.str = iob_int2str(ap, size, 16,
			    NTOS_UNSIGNED | NTOS_SHOWBASE, &zero, &val);

			if ((symstr = iob_addr2str(val)) != NULL)
				u.str = symstr;

			if (f_alt == TRUE) {
				f_altsuff = TRUE;
				altstr = ":";
				altlen = 1;
			}
			break;

		case 'A':
			if (size < SZ_LONG)
				size = SZ_LONG;	/* Bump to size of uintptr_t */

			(void) iob_int2str(ap, size, 16,
			    NTOS_UNSIGNED, &zero, &val);

			u.str = iob_addr2str(val);

			if (f_alt == TRUE && u.str == NULL)
				u.str = "?";
			break;

		case 'b':
			u.str = iob_int2str(ap, size, 16,
			    NTOS_UNSIGNED | NTOS_SHOWBASE, &zero, &val);

			iob_bits2str(iob, val, VA_PTRARG(ap), f_alt);

			format = ++p;
			continue;

		case 'c':
			c[0] = (char)VA_ARG(ap, int);
			u.str = c;
			break;

		case 'd':
		case 'i':
			if (f_alt)
				flags |= NTOS_SHOWBASE;
			u.str = iob_int2str(ap, size, 10, flags, &zero, &val);
			break;

		/* No floating point in kmdb */
#ifndef _KMDB
		case 'e':
		case 'E':
			u.d = VA_ARG(ap, double);
			u.str = doubletos(u.d, 7, *p);
			break;

		case 'g':
		case 'G':
			if (size >= SZ_LONG) {
				u.ld = VA_ARG(ap, long double);
				u.str = longdoubletos(&u.ld, 16,
				    (*p == 'g') ? 'e' : 'E');
			} else {
				u.d = VA_ARG(ap, double);
				u.str = doubletos(u.d, 16,
				    (*p == 'g') ? 'e' : 'E');
			}
			break;
#endif

		case 'h':
			size = SZ_SHORT;
			goto fmt_switch;

		case 'H':
			u.str = iob_bytes2str(ap, size);
			break;

		case 'I':
			u.ui32 = VA_ARG(ap, uint32_t);
			u.str = iob_inaddr2str(u.ui32);
			break;

		case 'l':
			if (size >= SZ_LONG)
				size = SZ_LONGLONG;
			else
				size = SZ_LONG;
			goto fmt_switch;

		case 'm':
			if (iob->iob_nbytes == 0) {
				mdb_iob_ws(iob, (width != 0) ? width :
				    iob->iob_margin);
			}
			format = ++p;
			continue;

		case 'N':
			u.ptr = VA_PTRARG(ap);
			u.str = iob_ipv6addr2str(u.ptr);
			break;

		case 'o':
			u.str = iob_int2str(ap, size, 8, NTOS_UNSIGNED,
			    &zero, &val);

			if (f_alt && !zero) {
				altstr = "0";
				altlen = 1;
			}
			break;

		case 'p':
			u.ptr = VA_PTRARG(ap);
			u.str = numtostr((uintptr_t)u.ptr, 16, NTOS_UNSIGNED);
			break;

		case 'q':
			u.str = iob_int2str(ap, size, 8, flags, &zero, &val);

			if (f_alt && !zero) {
				altstr = "0";
				altlen = 1;
			}
			break;

		case 'r':
			if (f_alt)
				flags |= NTOS_SHOWBASE;
			u.str = iob_int2str(ap, size, mdb.m_radix,
			    NTOS_UNSIGNED | flags, &zero, &val);
			break;

		case 'R':
			if (f_alt)
				flags |= NTOS_SHOWBASE;
			u.str = iob_int2str(ap, size, mdb.m_radix, flags,
			    &zero, &val);
			break;

		case 's':
			u.str = VA_PTRARG(ap);
			if (u.str == NULL)
				u.str = "<NULL>"; /* Be forgiving of NULL */
			break;

		case 't':
			if (width != 0) {
				while (width-- > 0)
					mdb_iob_tab(iob);
			} else
				mdb_iob_tab(iob);

			format = ++p;
			continue;

		case 'T':
			if (width != 0 && (iob->iob_nbytes % width) != 0) {
				size_t ots = iob->iob_tabstop;
				iob->iob_tabstop = width;
				mdb_iob_tab(iob);
				iob->iob_tabstop = ots;
			}
			format = ++p;
			continue;

		case 'u':
			if (f_alt)
				flags |= NTOS_SHOWBASE;
			u.str = iob_int2str(ap, size, 10,
			    flags | NTOS_UNSIGNED, &zero, &val);
			break;

		case 'x':
			u.str = iob_int2str(ap, size, 16, NTOS_UNSIGNED,
			    &zero, &val);

			if (f_alt && !zero) {
				altstr = "0x";
				altlen = 2;
			}
			break;

		case 'X':
			u.str = iob_int2str(ap, size, 16,
			    NTOS_UNSIGNED | NTOS_UPCASE, &zero, &val);

			if (f_alt && !zero) {
				altstr = "0X";
				altlen = 2;
			}
			break;

		case 'Y':
			u.tm = VA_ARG(ap, time_t);
			u.str = iob_time2str(&u.tm);
			break;

		case '<':
			/*
			 * Used to turn attributes on (<b>), to turn them
			 * off (</b>), or to print variables (<_var>).
			 */
			for (u.str = ++p; *p != '\0' && *p != '>'; p++)
				continue;

			if (*p == '>') {
				size_t paramlen = p - u.str;

				if (paramlen > 0) {
					if (*u.str == '_') {
						u.str = iob_getvar(u.str + 1,
						    paramlen - 1);
						break;
					} else {
						(void) iob_setattr(iob, u.str,
						    paramlen);
					}
				}

				p++;
			}

			format = p;
			continue;

		case '*':
			width = (size_t)(uint_t)VA_ARG(ap, int);
			goto fmt_switch;

		case '%':
			u.str = "%";
			break;

		case '?':
			width = sizeof (uintptr_t) * 2;
			goto fmt_switch;

		case '#':
			f_alt = TRUE;
			goto fmt_switch;

		case '+':
			flags |= NTOS_SIGNPOS;
			goto fmt_switch;

		case '-':
			f_left = TRUE;
			goto fmt_switch;

		default:
			c[0] = p[0];
			u.str = c;
		}

		len = u.str != NULL ? strlen(u.str) : 0;

		if (len + altlen > width)
			width = len + altlen;

		/*
		 * If the string and the option altstr won't fit on this line
		 * and auto-wrap is set (default), skip to the next line.
		 */
		if (IOB_WRAPNOW(iob, width))
			mdb_iob_nl(iob);

		/*
		 * Optionally add whitespace or zeroes prefixing the value if
		 * we haven't filled the minimum width and we're right-aligned.
		 */
		if (len < (width - altlen) && f_left == FALSE) {
			mdb_iob_fill(iob, f_zfill ? '0' : ' ',
			    width - altlen - len);
		}

		/*
		 * Print the alternate string if it's a prefix, and then
		 * print the value string itself.
		 */
		if (altstr != NULL && f_altsuff == FALSE)
			mdb_iob_nputs(iob, altstr, altlen);
		if (len != 0)
			mdb_iob_nputs(iob, u.str, len);

		/*
		 * If we have an alternate string and it's a suffix, print it.
		 */
		if (altstr != NULL && f_altsuff == TRUE)
			mdb_iob_nputs(iob, altstr, altlen);

		/*
		 * Finally, if we haven't filled the field width and we're
		 * left-aligned, pad out the rest with whitespace.
		 */
		if ((len + altlen) < width && f_left == TRUE)
			mdb_iob_ws(iob, width - altlen - len);

		format = (*p != '\0') ? ++p : p;
	}

	/*
	 * If there's anything left in the format string, output it now
	 */
	if (*format != '\0') {
		len = strlen(format);
		if (IOB_WRAPNOW(iob, len) && *format != '\n')
			mdb_iob_nl(iob);
		mdb_iob_nputs(iob, format, len);
	}
}

void
mdb_iob_vprintf(mdb_iob_t *iob, const char *format, va_list alist)
{
	varglist_t ap = { VAT_VARARGS };
	va_copy(ap.val_valist, alist);
	iob_doprnt(iob, format, &ap);
}

void
mdb_iob_aprintf(mdb_iob_t *iob, const char *format, const mdb_arg_t *argv)
{
	varglist_t ap = { VAT_ARGVEC };
	ap.val_argv = argv;
	iob_doprnt(iob, format, &ap);
}

void
mdb_iob_printf(mdb_iob_t *iob, const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	mdb_iob_vprintf(iob, format, alist);
	va_end(alist);
}

/*
 * In order to handle the sprintf family of functions, we define a special
 * i/o backend known as a "sprintf buf" (or spbuf for short).  This back end
 * provides an IOP_WRITE entry point that concatenates each buffer sent from
 * mdb_iob_flush() onto the caller's buffer until the caller's buffer is
 * exhausted.  We also keep an absolute count of how many bytes were sent to
 * this function during the lifetime of the snprintf call.  This allows us
 * to provide the ability to (1) return the total size required for the given
 * format string and argument list, and (2) support a call to snprintf with a
 * NULL buffer argument with no special case code elsewhere.
 */
static ssize_t
spbuf_write(mdb_io_t *io, const void *buf, size_t buflen)
{
	spbuf_t *spb = io->io_data;

	if (spb->spb_bufsiz != 0) {
		size_t n = MIN(spb->spb_bufsiz, buflen);
		bcopy(buf, spb->spb_buf, n);
		spb->spb_buf += n;
		spb->spb_bufsiz -= n;
	}

	spb->spb_total += buflen;
	return (buflen);
}

static const mdb_io_ops_t spbuf_ops = {
	no_io_read,
	spbuf_write,
	no_io_seek,
	no_io_ctl,
	no_io_close,
	no_io_name,
	no_io_link,
	no_io_unlink,
	no_io_setattr,
	no_io_suspend,
	no_io_resume
};

/*
 * The iob_spb_create function initializes an iob suitable for snprintf calls,
 * a spbuf i/o backend, and the spbuf private data, and then glues these
 * objects together.  The caller (either vsnprintf or asnprintf below) is
 * expected to have allocated the various structures on their stack.
 */
static void
iob_spb_create(mdb_iob_t *iob, char *iob_buf, size_t iob_len,
    mdb_io_t *io, spbuf_t *spb, char *spb_buf, size_t spb_len)
{
	spb->spb_buf = spb_buf;
	spb->spb_bufsiz = spb_len;
	spb->spb_total = 0;

	io->io_ops = &spbuf_ops;
	io->io_data = spb;
	io->io_next = NULL;
	io->io_refcnt = 1;

	iob->iob_buf = iob_buf;
	iob->iob_bufsiz = iob_len;
	iob->iob_bufp = iob_buf;
	iob->iob_nbytes = 0;
	iob->iob_nlines = 0;
	iob->iob_lineno = 1;
	iob->iob_rows = MDB_IOB_DEFROWS;
	iob->iob_cols = iob_len;
	iob->iob_tabstop = MDB_IOB_DEFTAB;
	iob->iob_margin = MDB_IOB_DEFMARGIN;
	iob->iob_flags = MDB_IOB_WRONLY;
	iob->iob_iop = io;
	iob->iob_pgp = NULL;
	iob->iob_next = NULL;
}

/*ARGSUSED*/
ssize_t
null_io_write(mdb_io_t *io, const void *buf, size_t nbytes)
{
	return (nbytes);
}

static const mdb_io_ops_t null_ops = {
	no_io_read,
	null_io_write,
	no_io_seek,
	no_io_ctl,
	no_io_close,
	no_io_name,
	no_io_link,
	no_io_unlink,
	no_io_setattr,
	no_io_suspend,
	no_io_resume
};

mdb_io_t *
mdb_nullio_create(void)
{
	static mdb_io_t null_io = {
		&null_ops,
		NULL,
		NULL,
		1
	};

	return (&null_io);
}

size_t
mdb_iob_vsnprintf(char *buf, size_t nbytes, const char *format, va_list alist)
{
	varglist_t ap = { VAT_VARARGS };
	char iob_buf[64];
	mdb_iob_t iob;
	mdb_io_t io;
	spbuf_t spb;

	ASSERT(buf != NULL || nbytes == 0);
	iob_spb_create(&iob, iob_buf, sizeof (iob_buf), &io, &spb, buf, nbytes);
	va_copy(ap.val_valist, alist);
	iob_doprnt(&iob, format, &ap);
	mdb_iob_flush(&iob);

	if (spb.spb_bufsiz != 0)
		*spb.spb_buf = '\0';
	else if (buf != NULL && nbytes > 0)
		*--spb.spb_buf = '\0';

	return (spb.spb_total);
}

size_t
mdb_iob_asnprintf(char *buf, size_t nbytes, const char *format,
    const mdb_arg_t *argv)
{
	varglist_t ap = { VAT_ARGVEC };
	char iob_buf[64];
	mdb_iob_t iob;
	mdb_io_t io;
	spbuf_t spb;

	ASSERT(buf != NULL || nbytes == 0);
	iob_spb_create(&iob, iob_buf, sizeof (iob_buf), &io, &spb, buf, nbytes);
	ap.val_argv = argv;
	iob_doprnt(&iob, format, &ap);
	mdb_iob_flush(&iob);

	if (spb.spb_bufsiz != 0)
		*spb.spb_buf = '\0';
	else if (buf != NULL && nbytes > 0)
		*--spb.spb_buf = '\0';

	return (spb.spb_total);
}

/*PRINTFLIKE3*/
size_t
mdb_iob_snprintf(char *buf, size_t nbytes, const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	nbytes = mdb_iob_vsnprintf(buf, nbytes, format, alist);
	va_end(alist);

	return (nbytes);
}

void
mdb_iob_nputs(mdb_iob_t *iob, const char *s, size_t nbytes)
{
	size_t m, n, nleft = nbytes;
	const char *p, *q = s;

	ASSERT(iob->iob_flags & MDB_IOB_WRONLY);

	if (nbytes == 0)
		return; /* Return immediately if there is no work to do */

	/*
	 * If the string contains embedded newlines or tabs, invoke ourself
	 * recursively for each string component, followed by a call to the
	 * newline or tab routine.  This insures that strings with these
	 * characters obey our wrapping and indenting rules, and that strings
	 * with embedded newlines are flushed after each newline, allowing
	 * the output pager to take over if it is enabled.
	 */
	while ((p = strnpbrk(q, "\t\n", nleft)) != NULL) {
		if (p > q)
			mdb_iob_nputs(iob, q, (size_t)(p - q));

		if (*p == '\t')
			mdb_iob_tab(iob);
		else
			mdb_iob_nl(iob);

		nleft -= (size_t)(p - q) + 1;	/* Update byte count */
		q = p + 1;			/* Advance past delimiter */
	}

	/*
	 * For a given string component, we determine how many bytes (n) we can
	 * copy into our buffer (limited by either cols or bufsiz depending
	 * on whether AUTOWRAP is on), copy a chunk into the buffer, and
	 * flush the buffer if we reach the end of a line.
	 */
	while (nleft != 0) {
		if (iob->iob_flags & MDB_IOB_AUTOWRAP) {
			ASSERT(iob->iob_cols >= iob->iob_nbytes);
			n = iob->iob_cols - iob->iob_nbytes;
		} else {
			ASSERT(iob->iob_bufsiz >= iob->iob_nbytes);
			n = iob->iob_bufsiz - iob->iob_nbytes;
		}

		m = MIN(nleft, n); /* copy at most n bytes in this pass */

		bcopy(q, iob->iob_bufp, m);
		nleft -= m;
		q += m;

		iob->iob_bufp += m;
		iob->iob_nbytes += m;

		if (m == n && nleft != 0) {
			if (iob->iob_flags & MDB_IOB_AUTOWRAP)
				mdb_iob_nl(iob);
			else
				mdb_iob_flush(iob);
		}
	}
}

void
mdb_iob_puts(mdb_iob_t *iob, const char *s)
{
	mdb_iob_nputs(iob, s, strlen(s));
}

void
mdb_iob_putc(mdb_iob_t *iob, int c)
{
	mdb_iob_fill(iob, c, 1);
}

void
mdb_iob_tab(mdb_iob_t *iob)
{
	ASSERT(iob->iob_flags & MDB_IOB_WRONLY);

	if (iob->iob_tabstop != 0) {
		/*
		 * Round up to the next multiple of the tabstop.  If this puts
		 * us off the end of the line, just insert a newline; otherwise
		 * insert sufficient whitespace to reach position n.
		 */
		size_t n = (iob->iob_nbytes + iob->iob_tabstop) /
		    iob->iob_tabstop * iob->iob_tabstop;

		if (n < iob->iob_cols)
			mdb_iob_fill(iob, ' ', n - iob->iob_nbytes);
		else
			mdb_iob_nl(iob);
	}
}

void
mdb_iob_fill(mdb_iob_t *iob, int c, size_t nfill)
{
	size_t i, m, n;

	ASSERT(iob->iob_flags & MDB_IOB_WRONLY);

	while (nfill != 0) {
		if (iob->iob_flags & MDB_IOB_AUTOWRAP) {
			ASSERT(iob->iob_cols >= iob->iob_nbytes);
			n = iob->iob_cols - iob->iob_nbytes;
		} else {
			ASSERT(iob->iob_bufsiz >= iob->iob_nbytes);
			n = iob->iob_bufsiz - iob->iob_nbytes;
		}

		m = MIN(nfill, n); /* fill at most n bytes in this pass */

		for (i = 0; i < m; i++)
			*iob->iob_bufp++ = (char)c;

		iob->iob_nbytes += m;
		nfill -= m;

		if (m == n && nfill != 0) {
			if (iob->iob_flags & MDB_IOB_AUTOWRAP)
				mdb_iob_nl(iob);
			else
				mdb_iob_flush(iob);
		}
	}
}

void
mdb_iob_ws(mdb_iob_t *iob, size_t n)
{
	if (iob->iob_nbytes + n < iob->iob_cols)
		mdb_iob_fill(iob, ' ', n);
	else
		mdb_iob_nl(iob);
}

void
mdb_iob_nl(mdb_iob_t *iob)
{
	ASSERT(iob->iob_flags & MDB_IOB_WRONLY);

	if (iob->iob_nbytes == iob->iob_bufsiz)
		mdb_iob_flush(iob);

	*iob->iob_bufp++ = '\n';
	iob->iob_nbytes++;

	mdb_iob_flush(iob);
}

ssize_t
mdb_iob_ngets(mdb_iob_t *iob, char *buf, size_t n)
{
	ssize_t resid = n - 1;
	ssize_t len;
	int c;

	if (iob->iob_flags & (MDB_IOB_WRONLY | MDB_IOB_EOF))
		return (EOF); /* can't gets a write buf or a read buf at EOF */

	if (n == 0)
		return (0);   /* we need room for a terminating \0 */

	while (resid != 0) {
		if (iob->iob_nbytes == 0 && iob_read(iob, iob->iob_iop) <= 0)
			goto done; /* failed to refill buffer */

		for (len = MIN(iob->iob_nbytes, resid); len != 0; len--) {
			c = *iob->iob_bufp++;
			iob->iob_nbytes--;

			if (c == EOF || c == '\n')
				goto done;

			*buf++ = (char)c;
			resid--;
		}
	}
done:
	*buf = '\0';
	return (n - resid - 1);
}

int
mdb_iob_getc(mdb_iob_t *iob)
{
	int c;

	if (iob->iob_flags & (MDB_IOB_WRONLY | MDB_IOB_EOF | MDB_IOB_ERR))
		return (EOF); /* can't getc if write-only, EOF, or error bit */

	if (iob->iob_nbytes == 0 && iob_read(iob, iob->iob_iop) <= 0)
		return (EOF); /* failed to refill buffer */

	c = (uchar_t)*iob->iob_bufp++;
	iob->iob_nbytes--;

	return (c);
}

int
mdb_iob_ungetc(mdb_iob_t *iob, int c)
{
	if (iob->iob_flags & (MDB_IOB_WRONLY | MDB_IOB_ERR))
		return (EOF); /* can't ungetc if write-only or error bit set */

	if (c == EOF || iob->iob_nbytes == iob->iob_bufsiz)
		return (EOF); /* can't ungetc EOF, or ungetc if buffer full */

	*--iob->iob_bufp = (char)c;
	iob->iob_nbytes++;
	iob->iob_flags &= ~MDB_IOB_EOF;

	return (c);
}

int
mdb_iob_eof(mdb_iob_t *iob)
{
	return ((iob->iob_flags & (MDB_IOB_RDONLY | MDB_IOB_EOF)) ==
	    (MDB_IOB_RDONLY | MDB_IOB_EOF));
}

int
mdb_iob_err(mdb_iob_t *iob)
{
	return ((iob->iob_flags & MDB_IOB_ERR) == MDB_IOB_ERR);
}

ssize_t
mdb_iob_read(mdb_iob_t *iob, void *buf, size_t n)
{
	ssize_t resid = n;
	ssize_t len;

	if (iob->iob_flags & (MDB_IOB_WRONLY | MDB_IOB_EOF | MDB_IOB_ERR))
		return (0); /* can't read if write-only, eof, or error */

	while (resid != 0) {
		if (iob->iob_nbytes == 0 && iob_read(iob, iob->iob_iop) <= 0)
			break; /* failed to refill buffer */

		len = MIN(resid, iob->iob_nbytes);
		bcopy(iob->iob_bufp, buf, len);

		iob->iob_bufp += len;
		iob->iob_nbytes -= len;

		buf = (char *)buf + len;
		resid -= len;
	}

	return (n - resid);
}

/*
 * For now, all binary writes are performed unbuffered.  This has the
 * side effect that the pager will not be triggered by mdb_iob_write.
 */
ssize_t
mdb_iob_write(mdb_iob_t *iob, const void *buf, size_t n)
{
	ssize_t ret;

	if (iob->iob_flags & MDB_IOB_ERR)
		return (set_errno(EIO));
	if (iob->iob_flags & MDB_IOB_RDONLY)
		return (set_errno(EMDB_IORO));

	mdb_iob_flush(iob);
	ret = iob_write(iob, iob->iob_iop, buf, n);

	if (ret < 0 && iob == mdb.m_out)
		longjmp(mdb.m_frame->f_pcb, MDB_ERR_OUTPUT);

	return (ret);
}

int
mdb_iob_ctl(mdb_iob_t *iob, int req, void *arg)
{
	return (IOP_CTL(iob->iob_iop, req, arg));
}

const char *
mdb_iob_name(mdb_iob_t *iob)
{
	if (iob == NULL)
		return ("<NULL>");

	return (IOP_NAME(iob->iob_iop));
}

size_t
mdb_iob_lineno(mdb_iob_t *iob)
{
	return (iob->iob_lineno);
}

size_t
mdb_iob_gettabstop(mdb_iob_t *iob)
{
	return (iob->iob_tabstop);
}

size_t
mdb_iob_getmargin(mdb_iob_t *iob)
{
	return (iob->iob_margin);
}

mdb_io_t *
mdb_io_hold(mdb_io_t *io)
{
	io->io_refcnt++;
	return (io);
}

void
mdb_io_rele(mdb_io_t *io)
{
	ASSERT(io->io_refcnt != 0);

	if (--io->io_refcnt == 0) {
		IOP_CLOSE(io);
		mdb_free(io, sizeof (mdb_io_t));
	}
}

void
mdb_io_destroy(mdb_io_t *io)
{
	ASSERT(io->io_refcnt == 0);
	IOP_CLOSE(io);
	mdb_free(io, sizeof (mdb_io_t));
}

void
mdb_iob_stack_create(mdb_iob_stack_t *stk)
{
	stk->stk_top = NULL;
	stk->stk_size = 0;
}

void
mdb_iob_stack_destroy(mdb_iob_stack_t *stk)
{
	mdb_iob_t *top, *ntop;

	for (top = stk->stk_top; top != NULL; top = ntop) {
		ntop = top->iob_next;
		mdb_iob_destroy(top);
	}
}

void
mdb_iob_stack_push(mdb_iob_stack_t *stk, mdb_iob_t *iob, size_t lineno)
{
	iob->iob_lineno = lineno;
	iob->iob_next = stk->stk_top;
	stk->stk_top = iob;
	stk->stk_size++;
	yylineno = 1;
}

mdb_iob_t *
mdb_iob_stack_pop(mdb_iob_stack_t *stk)
{
	mdb_iob_t *top = stk->stk_top;

	ASSERT(top != NULL);

	stk->stk_top = top->iob_next;
	top->iob_next = NULL;
	stk->stk_size--;

	return (top);
}

size_t
mdb_iob_stack_size(mdb_iob_stack_t *stk)
{
	return (stk->stk_size);
}

/*
 * Stub functions for i/o backend implementors: these stubs either act as
 * pass-through no-ops or return ENOTSUP as appropriate.
 */
ssize_t
no_io_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	if (io->io_next != NULL)
		return (IOP_READ(io->io_next, buf, nbytes));

	return (set_errno(EMDB_IOWO));
}

ssize_t
no_io_write(mdb_io_t *io, const void *buf, size_t nbytes)
{
	if (io->io_next != NULL)
		return (IOP_WRITE(io->io_next, buf, nbytes));

	return (set_errno(EMDB_IORO));
}

off64_t
no_io_seek(mdb_io_t *io, off64_t offset, int whence)
{
	if (io->io_next != NULL)
		return (IOP_SEEK(io->io_next, offset, whence));

	return (set_errno(ENOTSUP));
}

int
no_io_ctl(mdb_io_t *io, int req, void *arg)
{
	if (io->io_next != NULL)
		return (IOP_CTL(io->io_next, req, arg));

	return (set_errno(ENOTSUP));
}

/*ARGSUSED*/
void
no_io_close(mdb_io_t *io)
{
/*
 * Note that we do not propagate IOP_CLOSE down the io stack.  IOP_CLOSE should
 * only be called by mdb_io_rele when an io's reference count has gone to zero.
 */
}

const char *
no_io_name(mdb_io_t *io)
{
	if (io->io_next != NULL)
		return (IOP_NAME(io->io_next));

	return ("(anonymous)");
}

void
no_io_link(mdb_io_t *io, mdb_iob_t *iob)
{
	if (io->io_next != NULL)
		IOP_LINK(io->io_next, iob);
}

void
no_io_unlink(mdb_io_t *io, mdb_iob_t *iob)
{
	if (io->io_next != NULL)
		IOP_UNLINK(io->io_next, iob);
}

int
no_io_setattr(mdb_io_t *io, int req, uint_t attrs)
{
	if (io->io_next != NULL)
		return (IOP_SETATTR(io->io_next, req, attrs));

	return (set_errno(ENOTSUP));
}

void
no_io_suspend(mdb_io_t *io)
{
	if (io->io_next != NULL)
		IOP_SUSPEND(io->io_next);
}

void
no_io_resume(mdb_io_t *io)
{
	if (io->io_next != NULL)
		IOP_RESUME(io->io_next);
}

/*
 * Iterate over the varargs. The first item indicates the mode:
 * MDB_TBL_PRNT
 * 	pull out the next vararg as a const char * and pass it and the
 * 	remaining varargs to iob_doprnt; if we want to print the column,
 * 	direct the output to mdb.m_out otherwise direct it to mdb.m_null
 *
 * MDB_TBL_FUNC
 * 	pull out the next vararg as type mdb_table_print_f and the
 * 	following one as a void * argument to the function; call the
 * 	function with the given argument if we want to print the column
 *
 * The second item indicates the flag; if the flag is set in the flags
 * argument, then the column is printed. A flag value of 0 indicates
 * that the column should always be printed.
 */
void
mdb_table_print(uint_t flags, const char *delimeter, ...)
{
	va_list alist;
	uint_t flg;
	uint_t type;
	const char *fmt;
	mdb_table_print_f *func;
	void *arg;
	mdb_iob_t *out;
	mdb_bool_t first = TRUE;
	mdb_bool_t print;

	va_start(alist, delimeter);

	while ((type = va_arg(alist, uint_t)) != MDB_TBL_DONE) {
		flg = va_arg(alist, uint_t);

		print = flg == 0 || (flg & flags) != 0;

		if (print) {
			if (first)
				first = FALSE;
			else
				mdb_printf("%s", delimeter);
		}

		switch (type) {
		case MDB_TBL_PRNT: {
			varglist_t ap = { VAT_VARARGS };
			fmt = va_arg(alist, const char *);
			out = print ? mdb.m_out : mdb.m_null;
			va_copy(ap.val_valist, alist);
			iob_doprnt(out, fmt, &ap);
			va_end(alist);
			va_copy(alist, ap.val_valist);
			break;
		}

		case MDB_TBL_FUNC:
			func = va_arg(alist, mdb_table_print_f *);
			arg = va_arg(alist, void *);

			if (print)
				func(arg);

			break;

		default:
			warn("bad format type %x\n", type);
			break;
		}
	}

	va_end(alist);
}
