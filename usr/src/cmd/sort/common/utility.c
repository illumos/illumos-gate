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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "utility.h"

#include "initialize.h"
#include "statistics.h"
#include "streams_common.h"
#include "streams.h"

/*
 * utility
 *
 * Overview
 *   utility.c contains the general purpose routines used in various locations
 *   throughout sort.  It provides a number of interfaces that maintain local
 *   state relevant to this instance of sort.  We discuss the more significant
 *   of these interfaces below.
 *
 * Output guard
 *   sort is one of the few Unix utilities that is capable of working "in
 *   place"; that is, sort can manipulate an input file and place its output in
 *   a file of the same name safely.  This is handled in this implementation by
 *   the output guard facility.  In the case of an interrupt or other fatal
 *   signal, sort essays to restore the original input file.
 *
 * Temporary file cleanup
 *   Similar to the output guard facility, sort cleans up its temporary files in
 *   the case of interruption (or normal exit, for that matter); this is handled
 *   by registering a list of file pointers for later use by the atexit handler.
 *
 * Temporary filename security
 *   sort protects against "open-through-link" security attacks by verifying
 *   that the selected temporary file name is unused.  If the file name is in
 *   use, the pattern is readjusted until an available name pattern is
 *   discovered.
 *
 * Buffered I/O
 *   sort has a simple buffered I/O facility of its own, to facilitate writing
 *   data in large quantities (particularly for multibyte locales).  cxwrite()
 *   is the base routine, while wxwrite(), which handles multibyte buffers, is
 *   built on top of cxwrite().
 */

#define	XBUFFER_SIZE	(32 * KILOBYTE)

#define	EXIT_OK		0
#define	EXIT_FAILURE	1
#define	EXIT_ERROR	2
#define	EXIT_INTERNAL	3

static int held_fd = -1;

static stream_t	**cleanup_chain = NULL;

static char *output_guard_tempname = NULL;
static ssize_t output_guard_size = 0;
static char *output_guard_filename = NULL;
static int output_guard_copy_complete = 0;

static const char *default_tmpdir = "/var/tmp";
static const char *default_template = "/stmAAAXXXXXX";
static const char *default_template_count = ".00000000";
static char *current_tmpdir;
static char *current_template;

static const char PNAME_FMT[] = "%s: ";
static const char ERRNO_FMT[] = ": %s\n";
static const char *pname = "sort";

void
swap(void **a, void **b)
{
	void *t;

	t = *a;
	*a = *b;
	*b = t;

	__S(stats_incr_swaps());
}

/*
 * Temporary file name template handling.
 */
static void
reset_file_template()
{
	struct stat s;

	do {
		(void) strcpy(current_template, current_tmpdir);
		(void) strcat(current_template, default_template);
		(void) mktemp(current_template);
		(void) strcat(current_template, default_template_count);
	} while (lstat(current_template, &s) != -1);
}

int
bump_file_template()
{
	struct stat s;
	int n = strlen(current_template);
	int i;

	for (i = n - 1; isdigit((uchar_t)current_template[i]); i--) {
		current_template[i]++;
		if (current_template[i] > '9')
			current_template[i] = '0';
		else
			break;
	}

	if (!isdigit((uchar_t)current_template[i])) {
		/*
		 * Template has been exhausted, so reset.
		 */
		reset_file_template();
	}

	if (lstat(current_template, &s) == 0) {
		/*
		 * Our newly bumped template has been anticipated; reset to
		 * avoid possible "link-through" attack.
		 */
		reset_file_template();
	}

	return (0);
}

void
set_file_template(char **T)
{
	struct stat s;
	int check_tmpdir = 0;

	if (*T != NULL) {
		current_tmpdir = strdup(*T);
		check_tmpdir = 1;
	} else if ((current_tmpdir = getenv("TMPDIR")) != NULL) {
		check_tmpdir = 1;
	} else {
		current_tmpdir = (char *)default_tmpdir;
	}

	/*
	 * Check that the temporary directory given exists, and is a directory.
	 */
	if (check_tmpdir) {
		if (stat(current_tmpdir, &s) != 0) {
			warn(gettext("cannot stat temporary directory %s"),
			    current_tmpdir);

			current_tmpdir = (char *)default_tmpdir;
		} else if (!S_ISDIR(s.st_mode)) {
			warn(gettext("%s is not a directory; "
			    "using default temporary directory"),
			    current_tmpdir);

			current_tmpdir = (char *)default_tmpdir;
		}
	}

	ASSERT(current_tmpdir != NULL);

	current_template = safe_realloc(NULL, strlen(current_tmpdir)
	    + strlen(default_template) + strlen(default_template_count) + 1);

	reset_file_template();
}

char *
get_file_template()
{
	return (current_template);
}

/*
 * Output guard routines.
 */
void
establish_output_guard(sort_t *S)
{
	struct stat output_stat;

	if (S->m_output_to_stdout)
		return;

	if (stat(S->m_output_filename, &output_stat) == 0) {
		stream_t *strp = S->m_input_streams;

		while (strp != NULL) {
			/*
			 * We needn't protect an empty file.
			 */
			if (!(strp->s_status & STREAM_NOTFILE) &&
			    strp->s_dev == output_stat.st_dev &&
			    strp->s_ino == output_stat.st_ino &&
			    strp->s_filesize > 0) {
				output_guard_filename = S->m_output_filename;
				output_guard_size = strp->s_filesize;

				ASSERT(output_guard_filename != NULL);

				if (bump_file_template() < 0)
					die(EMSG_TEMPORARY);

				if ((strp->s_filename = output_guard_tempname =
				    strdup(get_file_template())) == NULL)
					die(EMSG_ALLOC);

				xcp(output_guard_tempname,
				    output_guard_filename, output_guard_size);

				output_guard_copy_complete = 1;

				return;
			}
			strp = strp->s_next;
		}
	}
}

void
remove_output_guard()
{
	if (output_guard_tempname && unlink(output_guard_tempname) == -1)
		warn(gettext("unable to unlink %s"), output_guard_tempname);

	output_guard_tempname = NULL;
}

void
set_cleanup_chain(stream_t **strp)
{
	ASSERT(strp != NULL);

	cleanup_chain = strp;
}

/*
 * atexit_handler() cleans up any temporary files outstanding after a fatal
 * signal, a call to die() or at exit().  To preserve the input file under low
 * storage conditions (and both the output file and the temporary files are
 * directed at the same filesystem), we remove all temporary files but the
 * output guard first, and then restore the original file.  Of course, this is
 * not foolproof, as another writer may have exhausted storage.
 */
void
atexit_handler()
{
	stream_t *strp;

	if (cleanup_chain && *cleanup_chain)
		for (strp = *cleanup_chain; strp != NULL; strp = strp->s_next)
			stream_unlink_temporary(strp);

	if (output_guard_tempname) {
		if (output_guard_copy_complete)
			xcp(output_guard_filename, output_guard_tempname,
			    output_guard_size);

		remove_output_guard();
	}

	__S(stats_display());
}

size_t
strtomem(char *S)
{
	const char *format_str = "%lf%c";
	double val = 0.0;
	size_t retval;
	char units = 'k';
	size_t phys_total = sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);

	if (sscanf(S, format_str, &val, &units) < 1 || val < 0)
		return (0);

	if (units == '%') {
		if (val < 0 || val > 100)
			return (0);
		val *= phys_total / 100;
	} else
		switch (units) {
			case 't' : /* terabytes */
			case 'T' :
				val *= 1024;
				/*FALLTHROUGH*/
			case 'g' : /* gigabytes */
			case 'G' :
				val *= 1024;
				/*FALLTHROUGH*/
			case 'm' : /* megabytes */
			case 'M' :
				val *= 1024;
				/*FALLTHROUGH*/
			case 'k' : /* kilobytes */
			case 'K' :
				val *= 1024;
				/*FALLTHROUGH*/
			case 'b' : /* bytes */
			case 'B' :
				break;
			default :
				/*
				 * default is kilobytes
				 */
				val *= 1024;
				break;
		}

	if (val > SIZE_MAX)
		return (0);

	retval = (size_t)val;

	return (retval);
}

size_t
available_memory(size_t mem_limit)
{
	size_t phys_avail = sysconf(_SC_AVPHYS_PAGES) * sysconf(_SC_PAGESIZE);
	size_t avail;

	if (mem_limit != 0) {
#ifdef DEBUG
		/*
		 * In the debug case, we want to test the temporary files
		 * handling, so no lower bound on the memory limit is imposed.
		 */
		avail = mem_limit;
#else
		avail = MAX(64 * KILOBYTE, mem_limit);
#endif /* DEBUG */
	} else {
		avail = MAX(64 * KILOBYTE, MIN(AV_MEM_MULTIPLIER * phys_avail /
		    AV_MEM_DIVISOR, 16 * MEGABYTE));
	}

	__S(stats_set_available_memory(avail));

	return (avail);
}

void
set_memory_ratio(sort_t *S, int *numerator, int *denominator)
{
	if (S->m_c_locale) {
		*numerator = CHAR_AVG_LINE;
		*denominator = sizeof (line_rec_t) + sizeof (line_rec_t *) +
		    CHAR_AVG_LINE + CHAR_AVG_LINE;
		return;
	}

	if (S->m_single_byte_locale) {
		*numerator = CHAR_AVG_LINE;
		*denominator = sizeof (line_rec_t) + sizeof (line_rec_t *) +
		    CHAR_AVG_LINE + XFRM_MULTIPLIER * CHAR_AVG_LINE;
		return;
	}

	*numerator = WCHAR_AVG_LINE;
	*denominator = sizeof (line_rec_t) + sizeof (line_rec_t *) +
	    WCHAR_AVG_LINE + WCHAR_AVG_LINE;
}

void *
safe_realloc(void *ptr, size_t sz)
{
	/*
	 * safe_realloc() is not meant as an alternative free() mechanism--we
	 * disallow reallocations to size zero.
	 */
	ASSERT(sz != 0);

	if ((ptr = realloc(ptr, sz)) != NULL)
		return (ptr);

	die(gettext("unable to reallocate buffer"));
	/*NOTREACHED*/
	return (NULL);	/* keep gcc happy */
}

void
safe_free(void *ptr)
{
	if (ptr)
		free(ptr);
}

void *
xzmap(void *addr, size_t len, int prot, int flags, off_t off)
{
	void *pa;

	pa = mmap(addr, len, prot, flags | MAP_ANON, -1, off);
	if (pa == MAP_FAILED)
		die(gettext("can't mmap anonymous memory"));

	return (pa);
}

void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage: %s [-cmu] [-o output] [-T directory] [-S mem]"
	    " [-z recsz]\n\t[-dfiMnr] [-b] [-t char] [-k keydef]"
	    " [+pos1 [-pos2]] files...\n"), CMDNAME);
	exit(E_USAGE);
}

/*
 * hold_file_descriptor() and release_file_descriptor() reserve a single file
 * descriptor entry for later use.  We issue the hold prior to any loop that has
 * an exit condition based on the receipt of EMFILE from an open() call; once we
 * have exited, we can release, typically prior to opening a file for output.
 */
void
hold_file_descriptor()
{
	ASSERT(held_fd == -1);

	if ((held_fd = open("/dev/null", O_RDONLY)) == -1)
		die(gettext("insufficient available file descriptors\n"));
}

void
release_file_descriptor()
{
	ASSERT(held_fd != -1);

	(void) close(held_fd);
	held_fd = -1;
}

void
copy_line_rec(const line_rec_t *a, line_rec_t *b)
{
	(void) memcpy(b, a, sizeof (line_rec_t));
}

void
trip_eof(FILE *f)
{
	if (feof(f))
		return;

	(void) ungetc(fgetc(f), f);
}

/*
 * int cxwrite(int, char *, size_t)
 *
 * Overview
 *   cxwrite() implements a buffered version of fwrite(ptr, nbytes, 1, .) on
 *   file descriptors.  It returns -1 in the case that the write() fails to
 *   write the current buffer contents.  cxwrite() must be flushed before being
 *   applied to a new file descriptor.
 *
 * Return values
 *   0 on success, -1 on error.
 */
int
cxwrite(int fd, char *ptr, size_t nbytes)
{
	static char buffer[XBUFFER_SIZE];
	static size_t offset = 0;
	size_t mbytes;

	if (ptr == NULL) {
		errno = 0;
		while (offset -= write(fd, buffer, offset)) {
			if (errno)
				break;
		}

		if (offset)
			return (-1);

		return (0);
	}

	while (nbytes != 0) {
		if (offset + nbytes > XBUFFER_SIZE)
			mbytes = XBUFFER_SIZE - offset;
		else
			mbytes = nbytes;

		(void) memcpy(buffer + offset, ptr, mbytes);
		nbytes -= mbytes;
		offset += mbytes;
		ptr += mbytes;

		if (nbytes) {
			errno = 0;
			while (offset -= write(fd, buffer, offset)) {
				if (errno)
					break;
			}

			if (offset)
				return (-1);
		}
	}

	return (0);
}

/*
 * int wxwrite(int, wchar_t *)
 *
 * Overview
 *   wxwrite() implements a buffered write() function for null-terminated wide
 *   character buffers with similar calling semantics to cxwrite().  It returns
 *   -1 in the case that it fails to write the current buffer contents.
 *   wxwrite() must be flushed before being applied to a new file descriptor.
 *
 * Return values
 *   0 on success, -1 on error.
 */
int
wxwrite(int fd, wchar_t *ptr)
{
	static char *convert_buffer;
	static size_t convert_bufsize = 1024;
	size_t req_bufsize;

	if (ptr == NULL)
		return (cxwrite(NULL, 0, 1));

	if (convert_buffer == NULL)
		convert_buffer = safe_realloc(NULL, convert_bufsize);
	/*
	 * We use wcstombs(NULL, ., .) to verify that we have an adequate
	 * buffer size for the conversion.  Since this buffer was converted into
	 * wide character format earlier, we can safely assume that the buffer
	 * can be converted back to the external multibyte form.
	 */
	req_bufsize = wcstombs(NULL, ptr, convert_bufsize);
	if (req_bufsize > convert_bufsize) {
		convert_bufsize = req_bufsize + 1;
		convert_buffer = safe_realloc(convert_buffer, convert_bufsize);
	}

	(void) wcstombs(convert_buffer, ptr, convert_bufsize);

	return (cxwrite(fd, convert_buffer, req_bufsize));
}

int
xstreql(const char *a, const char *b)
{
	return (strcmp(a, b) == 0);
}

int
xstrneql(const char *a, const char *b, const size_t l)
{
	return (strncmp(a, b, l) == 0);
}

char *
xstrnchr(const char *S, const int c, const size_t n)
{
	const char	*eS = S + n;

	do {
		if (*S == (char)c)
			return ((char *)S);
	} while (++S < eS);

	return (NULL);
}

void
xstrninv(char *s, ssize_t start, ssize_t length)
{
	ssize_t i;

	for (i = start; i < start + length; i++)
		s[i] = UCHAR_MAX - s[i];
}

int
xwcsneql(const wchar_t *a, const wchar_t *b, const size_t length)
{
	return (wcsncmp(a, b, length) == 0);
}

wchar_t *
xwsnchr(const wchar_t *ws, const wint_t wc, const size_t n)
{
	const wchar_t	*ews = ws + n;

	do {
		if (*ws == (wchar_t)wc)
			return ((wchar_t *)ws);
	} while (++ws < ews);

	return (NULL);
}

void
xwcsninv(wchar_t *s, ssize_t start, ssize_t length)
{
	ssize_t	i;

	for (i = start; i < start + length; i++)
		s[i] = WCHAR_MAX - s[i];
}

#ifdef _LITTLE_ENDIAN
void
xwcsntomsb(wchar_t *s, ssize_t length)
{
	ssize_t i;

	ASSERT(sizeof (wchar_t) == sizeof (uint32_t));

	for (i = 0; i < length; i++, s++) {
		char *t = (char *)s;
		char u;

		u = *t;
		*t = *(t + 3);
		*(t + 3) = u;

		u = *(t + 1);
		*(t + 1) = *(t + 2);
		*(t + 2) = u;
	}
}
#endif /* _LITTLE_ENDIAN */

wchar_t *
xmemwchar(wchar_t *s, wchar_t w, ssize_t length)
{
	ssize_t i = length;

	while (--i > 0) {
		if (*s == w)
			return (s);
		s++;
	}

	return (NULL);
}

void
xcp(char *dst, char *src, off_t size)
{
	int fd_in, fd_out;
	void *mm_in;
	size_t chunksize = 2 * MEGABYTE;
	int i;
	ssize_t nchunks = size / chunksize;
	ssize_t lastchunk = size % chunksize;

	if (dst == NULL || src == NULL)
		return;

	if ((fd_in = open(src, O_RDONLY)) < 0)
		die(EMSG_OPEN, src);
	if ((fd_out = open(dst, O_RDWR | O_CREAT | O_TRUNC, OUTPUT_MODE)) < 0)
		die(EMSG_OPEN, dst);

	for (i = 0; i < nchunks; i++) {
		if ((mm_in = mmap(0, chunksize, PROT_READ, MAP_SHARED, fd_in,
		    i * chunksize)) == MAP_FAILED)
			die(EMSG_MMAP, src);

		if (write(fd_out, mm_in, chunksize) != chunksize)
			die(EMSG_WRITE, dst);

		(void) munmap(mm_in, chunksize);
	}

	if (lastchunk) {
		if ((mm_in = mmap(0, lastchunk, PROT_READ, MAP_SHARED, fd_in,
		    nchunks * chunksize)) == MAP_FAILED)
			die(EMSG_MMAP, src);

		if (write(fd_out, mm_in, lastchunk) != lastchunk)
			die(EMSG_WRITE, dst);

		(void) munmap(mm_in, lastchunk);
	}

	(void) close(fd_in);

	if (close(fd_out) == -1)
		die(EMSG_CLOSE, dst);
}

/*PRINTFLIKE1*/
void
warn(const char *format, ...)
{
	int err = errno;
	va_list alist;

	if (pname != NULL)
		(void) fprintf(stderr, gettext(PNAME_FMT), pname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strrchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERRNO_FMT), strerror(err));
}

/*PRINTFLIKE1*/
void
die(const char *format, ...)
{
	int err = errno;
	va_list alist;

	if (pname != NULL)
		(void) fprintf(stderr, gettext(PNAME_FMT), pname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strrchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERRNO_FMT), strerror(err));

	exit(E_ERROR);
}

#ifdef DEBUG
/*
 * pprintc() is called only by xdump().
 */
#define	BYTES_PER_LINE	16
static void
pprintc(FILE *fp, char c)
{
	if (isspace((uchar_t)c))
		(void) fprintf(fp, " ");
	else if (isprint((uchar_t)c))
		(void) fprintf(fp, "%c", c);
	else
		(void) fprintf(fp, ".");
}

static void
pprintwc(FILE *fp, wchar_t c)
{
	if (iswspace(c))
		(void) fprintf(fp, " ");
	else if (iswprint(c))
		(void) fprintf(fp, "%wc", c);
	else
		(void) fprintf(fp, ".");
}

/*
 * xdump() is used only for debugging purposes.
 */
void
xdump(FILE *fp, uchar_t *buf, size_t bufsize, int wide)
{
	int i;
	size_t nc = 0;
	uchar_t d[BYTES_PER_LINE];

	for (; nc < bufsize; buf++) {
		d[nc % BYTES_PER_LINE] = *buf;
		if (nc % BYTES_PER_LINE == 0) {
			(void) fprintf(fp, "%08x:", nc);
		}
		(void) fprintf(fp, " %02x", *buf);
		nc++;
		if (nc % BYTES_PER_LINE == 0) {
			(void) fprintf(fp, "  ");
			if (wide) {
				for (i = 0; i < BYTES_PER_LINE;
				    i += sizeof (wchar_t))
					pprintwc(fp, *(wchar_t *)(d + i));
			} else {
				for (i = 0; i < BYTES_PER_LINE; i++)
					pprintc(fp, d[i]);
			}
			(void) fprintf(fp, "\n");
		}
	}

	for (i = nc % BYTES_PER_LINE; i < BYTES_PER_LINE; i++)
		(void) fprintf(fp, "   ");

	(void) fprintf(fp, "  ");

	if (wide) {
		for (i = 0; i < nc % BYTES_PER_LINE; i += sizeof (wchar_t))
			pprintwc(fp, *(wchar_t *)(d + i));
	} else {
		for (i = 0; i < nc % BYTES_PER_LINE; i++)
			pprintc(fp, d[i]);
	}

	(void) fprintf(fp, "\n");
}
#endif /* DEBUG */
