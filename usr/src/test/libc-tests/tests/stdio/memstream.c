/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Robert Mustacchi
 */

/*
 * Test memory based streams: opem_memstream(3C), open_wmemstream(3C), and
 * fmemopen(3C).
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <strings.h>
#include <err.h>
#include <errno.h>
#include <wchar.h>
#include <umem.h>
#include <locale.h>

typedef boolean_t (*memstream_test_f)(void);
static char *fmemopen_str1 = "The Road goes ever on and on\n"
	"Down from the door where it began.\n";
const wchar_t *wstream_str = L"いつか終わる夢";
/*
 * smatch doesn't support wide-character constants (wchar_t foo = L'xxx'), so
 * instead use a string which it'll happily accept.
 */
const wchar_t *wstr_const = L"光";

const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}

static boolean_t
fmemopen_badopen(void *buf, size_t size, const char *mode, int err)
{
	FILE *f = fmemopen(buf, size, mode);

	if (f != NULL) {
		warnx("fmemopen() succeeded erroneously");
		(void) fclose(f);
		return (B_FALSE);
	}

	if (errno != err) {
		warnx("fmemopen() open failed with wrong errno, "
		    "found %d (%s), expected %d (%s)", errno, strerror(errno),
		    err, strerror(err));
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
fmemopen_badmode(void)
{
	return (fmemopen_badopen(fmemopen_str1, strlen(fmemopen_str1), "foobar",
	    EINVAL));
}

static boolean_t
fmemopen_zerobuf1(void)
{
	return (fmemopen_badopen(fmemopen_str1, 0, "w", EINVAL));
}

static boolean_t
fmemopen_zerobuf2(void)
{
	return (fmemopen_badopen(NULL, 0, "w+", EINVAL));
}

static boolean_t
fmemopen_nullbuf1(void)
{
	return (fmemopen_badopen(NULL, 10, "r", EINVAL));
}

static boolean_t
fmemopen_nullbuf2(void)
{
	return (fmemopen_badopen(NULL, 10, "w", EINVAL));
}

static boolean_t
fmemopen_nullbuf3(void)
{
	return (fmemopen_badopen(NULL, 10, "a", EINVAL));
}

static boolean_t
fmemopen_nullbuf4(void)
{
	return (fmemopen_badopen(NULL, 10, "ax", EINVAL));
}

static boolean_t
fmemopen_sizemax(void)
{
	return (fmemopen_badopen(NULL, SIZE_MAX, "w+", ENOMEM));
}

static boolean_t
fmemopen_cantalloc(void)
{
	boolean_t ret;

	umem_setmtbf(1);
	ret = fmemopen_badopen(NULL, 10, "w+", ENOMEM);
	umem_setmtbf(0);
	return (ret);
}

static boolean_t
open_memstream_badopen(char **bufp, size_t *sizep, int err)
{
	FILE *f = open_memstream(bufp, sizep);

	if (f != NULL) {
		warnx("open_memstream() succeeded erroneously");
		(void) fclose(f);
		return (B_FALSE);
	}

	if (errno != err) {
		warnx("open_memstream() open failed with wrong errno, "
		    "found %d (%s), expected %d (%s)", errno, strerror(errno),
		    err, strerror(err));
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
open_memstream_badbuf(void)
{
	size_t s, check;
	boolean_t ret;

	arc4random_buf(&s, sizeof (s));
	check = s;
	ret = open_memstream_badopen(NULL, &s, EINVAL);
	if (check != s) {
		warnx("open_memstream() open erroneously wrote to size "
		    "pointer");
		return (B_FALSE);
	}
	return (ret);
}

static boolean_t
open_memstream_badsize(void)
{
	char *c;
	return (open_memstream_badopen(&c, NULL, EINVAL));
}

static boolean_t
open_memstream_allnull(void)
{
	return (open_memstream_badopen(NULL, NULL, EINVAL));
}

static boolean_t
open_memstream_cantalloc(void)
{
	boolean_t ret;
	char *c;
	size_t len;

	umem_setmtbf(1);
	ret = open_memstream_badopen(&c, &len, EAGAIN);
	umem_setmtbf(0);
	return (ret);
}

static boolean_t
open_wmemstream_badopen(wchar_t **bufp, size_t *sizep, int err)
{
	FILE *f = open_wmemstream(bufp, sizep);

	if (f != NULL) {
		warnx("open_wmemstream() succeeded erroneously");
		(void) fclose(f);
		return (B_FALSE);
	}

	if (errno != err) {
		warnx("open_wmemstream() open failed with wrong errno, "
		    "found %d (%s), expected %d (%s)", errno, strerror(errno),
		    err, strerror(err));
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
open_wmemstream_badbuf(void)
{
	size_t s, check;
	boolean_t ret;

	arc4random_buf(&s, sizeof (s));
	check = s;
	ret = open_wmemstream_badopen(NULL, &s, EINVAL);
	if (check != s) {
		warnx("open_wmemstream() open erroneously wrote to size "
		    "pointer");
		return (B_FALSE);
	}
	return (ret);
}

static boolean_t
open_wmemstream_badsize(void)
{
	wchar_t *c;
	return (open_wmemstream_badopen(&c, NULL, EINVAL));
}

static boolean_t
open_wmemstream_allnull(void)
{
	return (open_wmemstream_badopen(NULL, NULL, EINVAL));
}

static boolean_t
open_wmemstream_cantalloc(void)
{
	boolean_t ret;
	wchar_t *c;
	size_t len;

	umem_setmtbf(1);
	ret = open_wmemstream_badopen(&c, &len, EAGAIN);
	umem_setmtbf(0);
	return (ret);
}

static boolean_t
fmemopen_fill_putc(FILE *f, size_t len, boolean_t buffer)
{
	boolean_t ret = B_TRUE;
	size_t i;

	for (i = 0; i < BUFSIZ * 2; i++) {
		if (fputc('a', f) != 'a') {
			break;
		}
	}

	if (buffer) {
		if (i < len) {
			warnx("write mismatch, had %zu bytes, wrote %zu",
			    len, i);
			ret = B_FALSE;
		}

		if (fflush(f) == 0) {
			warnx("somehow flushed overly full stream, expected "
			    "failure");
			ret = B_FALSE;
		}
	} else if (i != len) {
		warnx("write mismatch, had %zu bytes, wrote %zu", len, i);
		ret = B_FALSE;
	}

	if (feof(f) != 0) {
		warn("EOF mistakenly set on write");
		ret = B_FALSE;
	}

	if (ferror(f) == 0) {
		warn("feof not set on write past the end");
		ret = B_FALSE;
	}

	if (fclose(f) != 0) {
		warn("failed to close memory stream");
		return (B_FALSE);
	}

	return (ret);
}

static boolean_t
fmemopen_fill_fwrite(FILE *f, size_t len, boolean_t buffer)
{
	boolean_t ret = B_TRUE;
	size_t i;
	char buf[BUFSIZ];

	(void) memset(buf, 'a', sizeof (buf));
	i = fwrite(buf, sizeof (buf), 1, f);

	if (buffer) {
		if (i != 1) {
			warnx("write mismatch, expected 1 entry, found %zu", i);
			ret = B_FALSE;
		}

		if (fflush(f) == 0) {
			warnx("somehow flushed overly full stream, expected "
			    "failure");
			ret = B_FALSE;
		}
	} else if (i != 0 && i != len) {
		warnx("write mismatch, had %zu bytes, wrote %zu", len, i);
		ret = B_FALSE;
	}

	if (feof(f) != 0) {
		warn("EOF mistakenly set on write");
		ret = B_FALSE;
	}

	if (ferror(f) == 0) {
		warn("feof not set on write past the end");
		ret = B_FALSE;
	}

	if (fclose(f) != 0) {
		warn("failed to close memory stream");
		return (B_FALSE);
	}

	return (ret);
}

static boolean_t
fmemopen_fill_alt_fwrite(FILE *f, size_t len, boolean_t buffer)
{
	boolean_t ret = B_TRUE;
	size_t i;
	char buf[BUFSIZ];

	(void) memset(buf, 'a', sizeof (buf));
	i = fwrite(buf, 1, sizeof (buf), f);

	if (buffer) {
		if (i < len) {
			warnx("write mismatch, had %zu bytes, wrote %zu",
			    len, i);
			ret = B_FALSE;
		}

		if (fflush(f) == 0) {
			warnx("somehow flushed overly full stream, expected "
			    "failure");
			ret = B_FALSE;
		}
	} else if (i != len) {
		warnx("write mismatch, had %zu bytes, wrote %zu", len, i);
		ret = B_FALSE;
	}

	if (feof(f) != 0) {
		warn("EOF mistakenly set on write");
		ret = B_FALSE;
	}

	if (ferror(f) == 0) {
		warn("feof not set on write past the end");
		ret = B_FALSE;
	}

	if (fclose(f) != 0) {
		warn("failed to close memory stream");
		return (B_FALSE);
	}

	return (ret);
}

static boolean_t
fmemopen_fill_fputs(FILE *f, size_t len, boolean_t buffer)
{
	boolean_t ret = B_TRUE;
	size_t i;
	char buf[17];

	(void) memset(buf, 'a', sizeof (buf));
	buf[16] = '\0';
	for (i = 0; i < BUFSIZ * 2; i += 16) {
		if (fputs(buf, f) != 16) {
			break;
		}
	}

	/*
	 * We don't check flushing in the puts case because fputs seems to clear
	 * the buffer as a side effect.
	 */
	if (buffer) {
		if (i < len) {
			warnx("write mismatch, had %zu bytes, wrote %zu",
			    len, i);
			ret = B_FALSE;
		}
	} else if (i != len) {
		warnx("write mismatch, had %zu bytes, wrote %zu", len, i);
		ret = B_FALSE;
	}

	if (feof(f) != 0) {
		warn("EOF mistakenly set on write");
		ret = B_FALSE;
	}

	if (ferror(f) == 0) {
		warn("feof not set on write past the end");
		ret = B_FALSE;
	}

	if (fclose(f) != 0) {
		warn("failed to close memory stream");
		return (B_FALSE);
	}

	return (ret);
}


static boolean_t
fmemopen_fill_default(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	return (fmemopen_fill_putc(f, 128, B_TRUE));
}

static boolean_t
fmemopen_fill_lbuf(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	if (setvbuf(f, NULL, _IOLBF, BUFSIZ) != 0) {
		warn("failed to set buffer to line-buffered mode");
	}

	return (fmemopen_fill_putc(f, 128, B_TRUE));
}

static boolean_t
fmemopen_fill_nobuf(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		warn("failed to set buffer to non-buffered mode");
	}

	return (fmemopen_fill_putc(f, 128, B_FALSE));
}

static boolean_t
fmemopen_fwrite_default(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	return (fmemopen_fill_fwrite(f, 128, B_TRUE));
}

static boolean_t
fmemopen_fwrite_lbuf(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	if (setvbuf(f, NULL, _IOLBF, BUFSIZ) != 0) {
		warn("failed to set buffer to line-buffered mode");
	}

	return (fmemopen_fill_fwrite(f, 128, B_TRUE));
}

static boolean_t
fmemopen_fwrite_nobuf(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		warn("failed to set buffer to non-buffered mode");
	}

	return (fmemopen_fill_fwrite(f, 128, B_FALSE));
}

static boolean_t
fmemopen_alt_fwrite_default(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	return (fmemopen_fill_alt_fwrite(f, 128, B_TRUE));
}

static boolean_t
fmemopen_alt_fwrite_lbuf(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	if (setvbuf(f, NULL, _IOLBF, BUFSIZ) != 0) {
		warn("failed to set buffer to line-buffered mode");
	}

	return (fmemopen_fill_alt_fwrite(f, 128, B_TRUE));
}

static boolean_t
fmemopen_alt_fwrite_nobuf(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		warn("failed to set buffer to non-buffered mode");
	}

	return (fmemopen_fill_alt_fwrite(f, 128, B_FALSE));
}

static boolean_t
fmemopen_fputs_default(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	return (fmemopen_fill_fputs(f, 128, B_TRUE));
}

static boolean_t
fmemopen_fputs_lbuf(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	if (setvbuf(f, NULL, _IOLBF, BUFSIZ) != 0) {
		warn("failed to set buffer to line-buffered mode");
	}

	return (fmemopen_fill_fputs(f, 128, B_TRUE));
}

static boolean_t
fmemopen_fputs_nobuf(void)
{
	FILE *f;

	f = fmemopen(NULL, 128, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		warn("failed to set buffer to non-buffered mode");
	}

	return (fmemopen_fill_fputs(f, 128, B_FALSE));
}

static boolean_t
memstream_check_seek(FILE *f, size_t len, int whence)
{
	off_t o;
	long l;
	boolean_t ret = B_TRUE;

	if (fseeko(f, 0, whence) != 0) {
		warn("failed to seek, whence: %d", whence);
		return (B_FALSE);
	}

	if ((o = ftello(f)) == -1) {
		warn("failed to get offset from ftello");
		ret = B_FALSE;
	} else if (o < 0 || (size_t)o != len) {
		warnx("found bad stream position: expected %zu, found: %zu",
		    len, (size_t)o);
		ret = B_FALSE;
	}

	if ((l = ftell(f)) == -1) {
		warn("failed to get offset from ftell");
		ret = B_FALSE;
	} else if (l < 0 || (size_t)l != len) {
		warnx("found bad stream position: expected %zu, found: %zu",
		    len, (size_t)l);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
fmemopen_defseek_r(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret, ret2;

	f = fmemopen(fmemopen_str1, len, "r");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, 0, SEEK_CUR);
	ret2 = memstream_check_seek(f, len, SEEK_END);
	(void) fclose(f);
	return (ret && ret2);
}

static boolean_t
fmemopen_defseek_rp(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret, ret2;

	f = fmemopen(fmemopen_str1, len, "r+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, 0, SEEK_CUR);
	ret2 = memstream_check_seek(f, len, SEEK_END);
	(void) fclose(f);
	return (ret && ret2);
}

static boolean_t
fmemopen_defseek_w(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret, ret2;
	char *str;

	if ((str = strdup(fmemopen_str1)) == NULL) {
		warn("failed to duplicate string");
		return (B_FALSE);
	}

	f = fmemopen(str, len, "w");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		free(str);
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, 0, SEEK_CUR);
	ret2 = memstream_check_seek(f, 0, SEEK_END);
	(void) fclose(f);
	free(str);
	return (ret && ret2);
}

static boolean_t
fmemopen_defseek_wp(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret, ret2;
	char *str;

	if ((str = strdup(fmemopen_str1)) == NULL) {
		warn("failed to duplicate string");
		return (B_FALSE);
	}

	f = fmemopen(str, len, "w+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		free(str);
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, 0, SEEK_CUR);
	ret2 = memstream_check_seek(f, 0, SEEK_END);
	(void) fclose(f);
	free(str);
	return (ret && ret2);
}

static boolean_t
fmemopen_defseek_a(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret, ret2;
	char *str;

	if ((str = strdup(fmemopen_str1)) == NULL) {
		warn("failed to duplicate string");
		return (B_FALSE);
	}

	f = fmemopen(str, len, "a");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		free(str);
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, len, SEEK_CUR);
	ret2 = memstream_check_seek(f, len, SEEK_END);
	(void) fclose(f);
	free(str);
	return (ret && ret2);
}

static boolean_t
fmemopen_defseek_ap(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret, ret2;
	char *str;

	if ((str = strdup(fmemopen_str1)) == NULL) {
		warn("failed to duplicate string");
		return (B_FALSE);
	}

	f = fmemopen(str, len, "a+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		free(str);
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, len, SEEK_CUR);
	ret2 = memstream_check_seek(f, len, SEEK_END);
	(void) fclose(f);
	free(str);
	return (ret && ret2);
}

static boolean_t
fmemopen_defseek_a_nbyte(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret, ret2;
	char *str;

	if ((str = strdup(fmemopen_str1)) == NULL) {
		warn("failed to duplicate string");
		return (B_FALSE);
	}
	str[8] = '\0';

	f = fmemopen(str, len, "a");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		free(str);
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, 8, SEEK_CUR);
	ret2 = memstream_check_seek(f, 8, SEEK_END);
	(void) fclose(f);
	free(str);
	return (ret && ret2);
}

static boolean_t
fmemopen_defseek_ap_nbyte(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret, ret2;
	char *str;

	if ((str = strdup(fmemopen_str1)) == NULL) {
		warn("failed to duplicate string");
		return (B_FALSE);
	}
	str[12] = '\0';

	f = fmemopen(str, len, "a+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		free(str);
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, 12, SEEK_CUR);
	ret2 = memstream_check_seek(f, 12, SEEK_END);
	(void) fclose(f);
	free(str);
	return (ret && ret2);
}

static boolean_t
fmemopen_defseek_ap_null(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret, ret2;

	f = fmemopen(NULL, len, "a+");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, 0, SEEK_CUR);
	ret2 = memstream_check_seek(f, 0, SEEK_END);
	(void) fclose(f);
	return (ret && ret2);
}

static boolean_t
fmemopen_read_eof_fgetc(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret = B_TRUE, ret2, ret3;

	f = fmemopen(fmemopen_str1, len, "r");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	while (fgetc(f) != EOF) {
		continue;
	}

	if (feof(f) == 0) {
		warnx("stream not at end of EOF");
		ret = B_FALSE;
	}

	ret2 = memstream_check_seek(f, len, SEEK_CUR);
	ret3 = memstream_check_seek(f, len, SEEK_END);
	(void) fclose(f);
	return (ret && ret2 && ret3);
}

static boolean_t
fmemopen_read_eof_fgets(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret = B_TRUE, ret2, ret3;
	char buf[BUFSIZ];

	f = fmemopen(fmemopen_str1, len, "r");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	while (fgets(buf, sizeof (buf), f) != NULL) {
		continue;
	}

	if (feof(f) == 0) {
		warnx("stream not at end of EOF");
		ret = B_FALSE;
	}

	ret2 = memstream_check_seek(f, len, SEEK_CUR);
	ret3 = memstream_check_seek(f, len, SEEK_END);
	(void) fclose(f);
	return (ret && ret2 && ret3);
}

static boolean_t
fmemopen_read_eof_fread(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret = B_TRUE, ret2, ret3;
	char buf[BUFSIZ];

	f = fmemopen(fmemopen_str1, len, "r");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	while (fread(buf, sizeof (buf), 1, f) != 0) {
		continue;
	}

	if (feof(f) == 0) {
		warnx("stream not at end of EOF");
		ret = B_FALSE;
	}

	ret2 = memstream_check_seek(f, len, SEEK_CUR);
	ret3 = memstream_check_seek(f, len, SEEK_END);
	(void) fclose(f);
	return (ret && ret2 && ret3);
}

static boolean_t
fmemopen_read_eof_fread2(void)
{
	FILE *f;
	size_t len = strlen(fmemopen_str1);
	boolean_t ret = B_TRUE, ret2, ret3;
	char buf[BUFSIZ];

	f = fmemopen(fmemopen_str1, len, "r");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	while (fread(buf, 1, sizeof (buf), f) != 0) {
		continue;
	}

	if (feof(f) == 0) {
		warnx("stream not at end of EOF");
		ret = B_FALSE;
	}

	ret2 = memstream_check_seek(f, len, SEEK_CUR);
	ret3 = memstream_check_seek(f, len, SEEK_END);
	(void) fclose(f);
	return (ret && ret2 && ret3);
}

static boolean_t
fmemopen_bad_seeks(void)
{
	FILE *f;
	boolean_t ret = B_TRUE;
	size_t len = strlen(fmemopen_str1);
	uint_t i;
	struct {
		int ret;
		int whence;
		long off;
		long newpos;
	} seeks[] = {
		{ 0, SEEK_CUR, 0, 0 },
		{ -1, SEEK_CUR, -1, 0 },
		{ -1, SEEK_SET, -5, 0 },
		{ -1, SEEK_END, -128, 0 },
		{ -1, SEEK_END, 1, 0 },
		{ -1, SEEK_SET, 128, 0 },
		{ 0, SEEK_SET, 16, 16 },
		{ -1, SEEK_CUR, -20, 16 },
		{ 0, SEEK_CUR, -16, 0 },
	};

	f = fmemopen(fmemopen_str1, len, "r");
	if (f == NULL) {
		warn("failed to open fmemopen stream");
		return (B_FALSE);
	}

	for (i = 0; i < ARRAY_SIZE(seeks); i++) {
		int r;

		r = fseek(f, seeks[i].off, seeks[i].whence);
		if (r != seeks[i].ret) {
			warnx("found bad return value for seek %d/%ld, "
			    "expected %d, found %d", seeks[i].whence,
			    seeks[i].off, seeks[i].ret, r);
			ret = B_FALSE;
		}

		ret &= memstream_check_seek(f, seeks[i].newpos, SEEK_CUR);
	}

	(void) fclose(f);
	return (ret);
}

static boolean_t
fmemopen_open_trunc(void)
{
	char buf[16];
	FILE *f;
	boolean_t ret = B_TRUE;

	(void) memset(buf, 'a', sizeof (buf));
	f = fmemopen(buf, sizeof (buf), "w+");
	if (f == NULL) {
		warn("failed to create fmemopen stream");
		return (B_FALSE);
	}

	if (buf[0] != '\0') {
		warnx("w+ mode didn't truncate the buffer");
		ret = B_FALSE;
	}

	(void) fclose(f);
	return (ret);
}

static boolean_t
fmemopen_write_nul(void)
{
	char buf[BUFSIZ];
	FILE *f;
	boolean_t ret = B_TRUE;
	size_t npos = sizeof (buf) - 32;

	(void) memset(buf, 'a', sizeof (buf));

	f = fmemopen(buf, sizeof (buf), "w");
	if (f == NULL) {
		warn("failed to create fmemopen stream");
		return (B_FALSE);
	}

	if (fputc('b', f) != 'b') {
		warn("failed to write 'b' character to stream");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (buf[0] != 'b' || buf[1] != '\0') {
		warn("stream didn't properly write character and nul");
		ret = B_FALSE;
	}

	if (fseek(f, sizeof (buf) - 32, SEEK_SET)) {
		warn("failed to seek stream");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (buf[npos] != 'a' || buf[npos - 1] != 'a' ||
	    buf[npos + 1] != 'a') {
		warnx("seeking incorrectly inserted a nul");
		ret = B_FALSE;
	}

	(void) fclose(f);

	if (buf[npos] != 'a' || buf[npos - 1] != 'a' ||
	    buf[npos + 1] != 'a') {
		warnx("seeking incorrectly inserted a nul");
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
fmemopen_append_nul(void)
{
	char buf[32], buf2[32];
	FILE *f;
	boolean_t ret = B_TRUE;

	(void) memset(buf, 'a', sizeof (buf));
	buf[8] = '\0';

	f = fmemopen(buf, sizeof (buf), "a");
	if (f == NULL) {
		warn("failed to create fmemopen stream");
		return (B_FALSE);
	}

	if (fputc('b', f) != 'b') {
		warn("failed to write 'b' character to stream");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (buf[8] != 'b' || buf[9] != '\0') {
		warn("stream didn't properly write character and nul");
		ret = B_FALSE;
	}

	/*
	 * Append mode shouldn't insert a NUL if we write the entire buffer.
	 */
	(void) memset(buf2, 'b', sizeof (buf2));
	if (fwrite(buf2, sizeof (buf2) - ftell(f), 1, f) != 1) {
		warn("failed to write buf2");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (buf[sizeof (buf) - 1] != 'b') {
		warnx("found invalid character: %x", buf[sizeof (buf) - 1]);
		ret = B_FALSE;
	}

	(void) fclose(f);

	if (buf[sizeof (buf) - 1] != 'b') {
		warnx("found invalid character: %x", buf[sizeof (buf) - 1]);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
fmemopen_read_nul(void)
{
	char buf[32];
	FILE *f;

	(void) memset(buf, '\0', sizeof (buf));

	f = fmemopen(buf, sizeof (buf), "r+");
	if (f == NULL) {
		warn("failed to create fmemopen stream");
		return (B_FALSE);
	}

	if (fgetc(f) != '\0') {
		warnx("failed to read nul character");
		return (B_FALSE);
	}

	(void) fclose(f);
	return (B_TRUE);
}

static boolean_t
open_memstream_def_seek(void)
{
	char *c;
	size_t s;
	FILE *f;
	boolean_t ret, ret2;

	if ((f = open_memstream(&c, &s)) == NULL) {
		warn("failed to call open_memstream()");
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, 0, SEEK_CUR);
	ret2 = memstream_check_seek(f, 0, SEEK_END);
	(void) fclose(f);
	free(c);
	return (ret && ret2);
}

static boolean_t
open_wmemstream_def_seek(void)
{
	wchar_t *c;
	size_t s;
	FILE *f;
	boolean_t ret, ret2;

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	ret = memstream_check_seek(f, 0, SEEK_CUR);
	ret2 = memstream_check_seek(f, 0, SEEK_END);
	(void) fclose(f);
	free(c);
	return (ret && ret2);
}

static boolean_t
open_memstream_no_read(void)
{
	char *c;
	size_t s;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_memstream(&c, &s)) == NULL) {
		warn("failed to call open_memstream()");
		return (B_FALSE);
	}

	if (fgetc(f) != EOF) {
		warnx("read succeeded when it should have failed");
		ret = B_FALSE;
	}

	if (errno != EBADF) {
		warnx("found wrong errno, expected %d, found %d", EBADF, errno);
		ret = B_FALSE;
	}

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
open_wmemstream_no_read(void)
{
	wchar_t *c;
	size_t s;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	if (fgetc(f) != EOF) {
		warnx("read succeeded when it should have failed");
		ret = B_FALSE;
	}

	if (errno != EBADF) {
		warnx("found wrong errno, expected %d, found %d", EBADF, errno);
		ret = B_FALSE;
	}

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
open_memstream_bad_flush(void)
{
	char *c;
	size_t s;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_memstream(&c, &s)) == NULL) {
		warn("failed to call open_memstream()");
		return (B_FALSE);
	}

	/* Force the buffer to exist */
	if (fputc('a', f) != 'a') {
		warn("failed to write character to buffer");
		ret = B_FALSE;
	}

	if (fseek(f, BUFSIZ * 2 + 1, SEEK_END) != 0) {
		warn("Failed to seek beyond buffer size");
		ret = B_FALSE;
	}

	umem_setmtbf(1);
	if (fputc('a', f) != 'a') {
		warn("failed to write character to buffer");
		ret = B_FALSE;
	}

	if (fflush(f) != EOF) {
		warnx("fflush succeeded when it should have failed");
	}

	if (errno != EAGAIN) {
		warnx("bad errno, found %d, expected %d", errno, EAGAIN);
	}
	umem_setmtbf(0);

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
open_wmemstream_bad_flush(void)
{
	wchar_t *c;
	size_t s;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	/* Force the buffer to exist */
	if (fputwc('a', f) != 'a') {
		warn("failed to write character to buffer");
		ret = B_FALSE;
	}

	if (fseek(f, BUFSIZ * 2 + 1, SEEK_END) != 0) {
		warn("Failed to seek beyond buffer size");
		ret = B_FALSE;
	}

	umem_setmtbf(1);
	if (fputc('a', f) != 'a') {
		warn("failed to write character to buffer");
		ret = B_FALSE;
	}

	if (fflush(f) != EOF) {
		warnx("fflush succeeded when it should have failed");
	}

	if (errno != EAGAIN) {
		warnx("bad errno, found %d, expected %d", errno, EAGAIN);
	}
	umem_setmtbf(0);

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
memstream_bad_seek(void)
{
	FILE *f, *fw;
	boolean_t ret = B_TRUE;
	uint_t i;
	char *c;
	wchar_t *w;
	size_t s1, s2;
	struct {
		int ret;
		int whence;
		long off;
		long newpos;
	} seeks[] = {
		{ 0, SEEK_CUR, 0, 0 },
		{ -1, SEEK_CUR, -1, 0 },
		{ -1, SEEK_SET, -5, 0 },
		{ -1, SEEK_END, -5, 0 },
		{ 0, SEEK_SET, 16, 16 },
		{ -1, SEEK_CUR, -20, 16 },
		{ 0, SEEK_CUR, -16, 0 },
	};

	f = open_memstream(&c, &s1);
	fw = open_wmemstream(&w, &s2);
	if (f == NULL || fw == NULL) {
		warnx("failed to create memory streams");
		return (B_FALSE);
	}

	for (i = 0; i < ARRAY_SIZE(seeks); i++) {
		int r;

		r = fseek(f, seeks[i].off, seeks[i].whence);
		if (r != seeks[i].ret) {
			warnx("found bad return value for seek %d/%ld, "
			    "expected %d, found %d", seeks[i].whence,
			    seeks[i].off, seeks[i].ret, r);
			ret = B_FALSE;
		}

		ret &= memstream_check_seek(f, seeks[i].newpos, SEEK_CUR);

		r = fseek(fw, seeks[i].off, seeks[i].whence);
		if (r != seeks[i].ret) {
			warnx("found bad return value for seek %d/%ld, "
			    "expected %d, found %d", seeks[i].whence,
			    seeks[i].off, seeks[i].ret, r);
			ret = B_FALSE;
		}

		ret &= memstream_check_seek(fw, seeks[i].newpos, SEEK_CUR);
	}

	(void) fclose(f);
	(void) fclose(fw);
	free(c);
	free(w);
	return (ret);
}

static boolean_t
open_memstream_append_nul(void)
{
	char *c;
	size_t s;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_memstream(&c, &s)) == NULL) {
		warn("failed to call open_memstream()");
		return (B_FALSE);
	}

	if (fputc('a', f) != 'a') {
		warn("failed to write 'a' to stream");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (c[s] != '\0') {
		warnx("missing nul character, found %x", c[s]);
		ret = B_FALSE;
	}

	if (fseek(f, arc4random_uniform(2 * BUFSIZ), SEEK_SET) != 0) {
		warn("failed to seek");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (c[s] != '\0') {
		warnx("missing nul character, found %x", c[s]);
		ret = B_FALSE;
	}

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
open_wmemstream_append_nul(void)
{
	wchar_t *c;
	size_t s;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	if (fputwc('a', f) != 'a') {
		warn("failed to write 'a' to stream");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (c[s] != L'\0') {
		warnx("missing nul character, found %" _PRIxWC, c[s]);
		ret = B_FALSE;
	}

	if (fseek(f, arc4random_uniform(2 * BUFSIZ), SEEK_SET) != 0) {
		warn("failed to seek");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (c[s] != L'\0') {
		warnx("missing nul character, found %" _PRIxWC, c[s]);
		ret = B_FALSE;
	}

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
open_wmemstream_embed_nuls(void)
{
	const char str[] = { 'H', 'e', 'l', 'l', 'o', '\0', 'w',
	    'o', 'r', 'd' };
	const wchar_t wstr[] = { L'H', L'e', L'l', L'l', L'o', L'\0', L'w',
	    L'o', L'r', L'd' };
	wchar_t *c;
	size_t s;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	if (fwrite(str, sizeof (char), ARRAY_SIZE(str), f) == 0) {
		warn("failed to write data buffer");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush data buffer");
		ret = B_FALSE;
	}

	if (ARRAY_SIZE(wstr) != s) {
		warnx("size mismatch, wrote %zu chars, found %zu chars",
		    ARRAY_SIZE(wstr), s);
		ret = B_FALSE;
	}

	if (bcmp(wstr, c, sizeof (wstr)) != 0) {
		warnx("data not written in expected format");
		ret = B_FALSE;
	}

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
open_wmemstream_wide_write(void)
{
	size_t slen = wcslen(wstream_str);
	wchar_t *c;
	size_t s;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	if (fputws(wstream_str, f) == -1) {
		warn("failed to write string");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (s != slen) {
		warnx("size mismatch, expected %zu chars, but found %zu",
		    slen, s);
		ret = B_FALSE;
	}

	if (wcscmp(wstream_str, c) != 0) {
		warnx("basic write doesn't match!");
		ret = B_FALSE;
	}

	ret &= memstream_check_seek(f, slen, SEEK_CUR);
	ret &= memstream_check_seek(f, slen, SEEK_END);

	(void) fclose(f);
	free(c);
	return (ret);
}

/*
 * Make sure that if we seek somewhere and flush that it doesn't cause us to
 * grow.
 */
static boolean_t
open_wmemstream_seek_grow(void)
{
	size_t slen = wcslen(wstream_str);
	wchar_t *c;
	size_t s;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (s != 0) {
		warn("bad initial size");
		ret = B_FALSE;
	}

	ret &= memstream_check_seek(f, 0, SEEK_CUR);
	ret &= memstream_check_seek(f, 0, SEEK_END);
	if (fseek(f, 2048, SEEK_SET) != 0) {
		warn("failed to seek");
	}

	ret &= memstream_check_seek(f, 2048, SEEK_CUR);

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (s != 0) {
		warnx("bad size after seek");
		ret = B_FALSE;
	}

	if (fputws(wstream_str, f) == -1) {
		warn("failed to write string");
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (s != slen + 2048) {
		warnx("size is off after seek and write, found %zu", s);
		ret = B_FALSE;
	}

	ret &= memstream_check_seek(f, s, SEEK_CUR);
	ret &= memstream_check_seek(f, s, SEEK_END);

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
open_wmemstream_byte_writes(void)
{
	wchar_t *c;
	size_t s, len, i;
	FILE *f;
	boolean_t ret = B_TRUE;

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	/*
	 * Use non-buffered mode so that way we can make sure to detect mbs
	 * state errors right away.
	 */
	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		warnx("failed to set to non-buffered mode");
		ret = B_FALSE;
	}

	len = wcslen(wstream_str);
	for (i = 0; i < len; i++) {
		char buf[MB_CUR_MAX + 1];
		int mblen, curmb;

		mblen = wctomb(buf, wstream_str[i]);

		if (mblen == -1) {
			warn("failed to convert wc %zu", i);
			ret = B_FALSE;
			continue;
		}
		for (curmb = 0; curmb < mblen; curmb++) {
			if (fputc(buf[curmb], f) == EOF) {
				warn("failed to write byte %d of wc %zu",
				    curmb, i);
				ret = B_FALSE;
			}
		}
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (s != len) {
		warnx("found wrong number of wide characters, expected %zu, "
		    "found %zu", len + 1, s);
		ret = B_FALSE;
	}

	if (wcscmp(c, wstream_str) != 0) {
		warnx("the wide character strings don't compare equally");
		ret = B_FALSE;
	}

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
open_wmemstream_bad_seq(void)
{
	wchar_t *c, test = wstr_const[0];
	size_t s;
	FILE *f;
	char buf[MB_CUR_MAX + 1];
	boolean_t ret = B_TRUE;

	if (wctomb(buf, test) == -1) {
		warn("failed to convert 光 to multi-byte sequence");
		return (B_FALSE);
	}

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	/*
	 * Make sure to use a non-buffered mode so that way writes immediately
	 * get sent to the underlying stream.
	 */
	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		warnx("failed to set to non-buffered mode");
		ret = B_FALSE;
	}

	if (fputc(buf[0], f) == EOF) {
		warn("failed to write 0x%x to buffer", buf[0]);
		ret = B_FALSE;
	}

	if (fputc(buf[0], f) != EOF) {
		warnx("successfully wrote 0x%x to buffer, but should have "
		    "failed", buf[0]);
		ret = B_FALSE;
	}

	if (errno != EIO) {
		warnx("found wrong errno, expected EIO, but found 0x%x", errno);
		ret = B_FALSE;
	}

	(void) fclose(f);
	free(c);
	return (ret);
}

static boolean_t
open_wmemstream_bad_seq_fflush(void)
{
	wchar_t *c, test = wstr_const[0];
	size_t s;
	FILE *f;
	char buf[MB_CUR_MAX + 1];
	boolean_t ret = B_TRUE;

	if (wctomb(buf, test) == -1) {
		warn("failed to convert 光 to multi-byte sequence");
		return (B_FALSE);
	}

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	if (fputc(buf[0], f) == EOF) {
		warn("failed to write 0x%x to buffer", buf[0]);
		ret = B_FALSE;
	}

	if (fputc(buf[0], f) == EOF) {
		warn("failed to write bad byte 0x%x to buffer", buf[0]);
		ret = B_FALSE;
	}

	if (fflush(f) == 0) {
		warn("fflush succeeded, expected failure");
		ret = B_FALSE;
	}

	if (errno != EIO) {
		warn("found wrong errno, expected EIO, but found 0x%x", errno);
		ret = B_FALSE;
	}

	(void) fclose(f);
	free(c);
	return (ret);
}

/*
 * When writing individual bytes out, we need to make sure that we don't
 * incorrectly count buffered data as offsets like we do for other byte oriented
 * consumers of the ftell family.
 */
static boolean_t
open_wmemstream_ftell(void)
{
	wchar_t *c, test = wstr_const[0];
	size_t s, i, wclen;
	FILE *f;
	char buf[MB_CUR_MAX + 1];
	boolean_t ret = B_TRUE;
	long loc;

	if ((wclen = wctomb(buf, test)) == -1) {
		warn("failed to convert 光 to multi-byte sequence");
		return (B_FALSE);
	}

	if ((f = open_wmemstream(&c, &s)) == NULL) {
		warn("failed to call open_wmemstream()");
		return (B_FALSE);
	}

	if ((loc = ftell(f)) != 0) {
		warnx("stream at bad loc after start, found %ld, expected 0",
		    loc);
		ret = B_FALSE;
	}

	if (fputwc(test, f) == WEOF) {
		warn("failed to write wide character to stream");
		ret = B_FALSE;
	}

	if ((loc = ftell(f)) != 1) {
		warnx("stream at bad loc after writing a single wide char, "
		    "found %ld, expected 1", loc);
		ret = B_FALSE;
	}

	for (i = 0; i < wclen - 1; i++) {
		if (fputc(buf[i], f) == EOF) {
			warn("failed to write mb char 0x%x", buf[i]);
			ret = B_FALSE;
		}

		if ((loc = ftell(f)) != 1) {
			warnx("stream at bad loc after putting partial mb seq, "
			    "found %ld, expected 1", loc);
			ret = B_FALSE;
		}
	}

	/*
	 * Only after we advance the final char should it be two.
	 */
	if (fputc(buf[i], f) == EOF) {
		warn("failed to write mb char 0x%x", buf[i]);
		ret = B_FALSE;
	}

	if ((loc = ftell(f)) != 2) {
		warnx("stream at bad loc after writing a mb seq, "
		    "found %ld, expected 2", loc);
		ret = B_FALSE;
	}

	if (fflush(f) != 0) {
		warn("failed to flush stream");
		ret = B_FALSE;
	}

	if (s != 2) {
		warnx("size of stream is wrong, found %zu, expected 2", s);
		ret = B_FALSE;
	}

	if (s != loc) {
		warnx("size of buffer, %zu does not match pre-fflush "
		    "ftell loc: %ld", s, loc);
		ret = B_FALSE;
	}

	loc = ftell(f);
	if (s != loc) {
		warnx("size of buffer, %zu does not match post-fflush "
		    "ftell loc: %ld", s, loc);
		ret = B_FALSE;
	}

	(void) fclose(f);
	free(c);
	return (ret);
}


typedef struct memstream_test {
	memstream_test_f	mt_func;
	const char		*mt_test;
} memstream_test_t;

static const memstream_test_t memstream_tests[] = {
	{ fmemopen_badmode, "fmemopen: bad mode argument" },
	{ fmemopen_zerobuf1, "fmemopen: bad buffer size, valid buf" },
	{ fmemopen_zerobuf2, "fmemopen: bad buffer size, NULL buf" },
	{ fmemopen_nullbuf1, "fmemopen: invalid NULL buf, mode: r" },
	{ fmemopen_nullbuf2, "fmemopen: invalid NULL buf, mode: w" },
	{ fmemopen_nullbuf3, "fmemopen: invalid NULL buf, mode: a" },
	{ fmemopen_nullbuf4, "fmemopen: invalid NULL buf, mode: ax" },
	{ fmemopen_sizemax, "fmemopen: bad open ask for SIZE_MAX bytes" },
	{ fmemopen_cantalloc, "fmemopen: simulate malloc failure at open" },
	{ open_memstream_badbuf, "open_memstream: bad buf" },
	{ open_memstream_badsize, "open_memstream: bad size" },
	{ open_memstream_allnull, "open_memstream: bad buf and size" },
	{ open_memstream_cantalloc, "open_memstream: simulate malloc failure "
	    "at " "open" },
	{ open_wmemstream_badbuf, "open_wmemstream: bad buf" },
	{ open_wmemstream_badsize, "open_wmemstream: bad size" },
	{ open_wmemstream_allnull, "open_wmemstream: bad buf and size" },
	{ open_wmemstream_cantalloc, "open_wmemstream: simulate malloc "
	    "failure at open" },
	{ fmemopen_fill_default, "fmemopen: write beyond end of buffer: putc "
	    "(buf smaller than BUFSIZ)" },
	{ fmemopen_fill_lbuf, "fmemopen: write beyond end of buffer: putc "
	    "(line buffering)" },
	{ fmemopen_fill_nobuf, "fmemopen: write beyond end of buffer: putc "
	    "(no stdio buffering)" },
	{ fmemopen_fwrite_default, "fmemopen: write beyond end of buffer: "
	    "fwrite (buf smaller than BUFSIZ)" },
	{ fmemopen_fwrite_lbuf, "fmemopen: write beyond end of buffer: fwrite "
	    "(line buffering)" },
	{ fmemopen_fwrite_nobuf, "fmemopen: write beyond end of buffer: fwrite "
	    "(no stdio buffering)" },
	{ fmemopen_alt_fwrite_default, "fmemopen: write beyond end of buffer: "
	    "fwrite 2 (buf smaller than BUFSIZ)" },
	{ fmemopen_alt_fwrite_lbuf, "fmemopen: write beyond end of buffer: "
	    "fwrite 2 (line buffering)" },
	{ fmemopen_alt_fwrite_nobuf, "fmemopen: write beyond end of buffer: "
	    "fwrite 2 (no stdio buffering)" },
	{ fmemopen_fputs_default, "fmemopen: write beyond end of buffer: fputs "
	    "(buf smaller than BUFSIZ)" },
	{ fmemopen_fputs_lbuf, "fmemopen: write beyond end of buffer: fputs "
	    "(line buffering)" },
	{ fmemopen_fputs_nobuf, "fmemopen: write beyond end of buffer: fputs "
	    "(no stdio buffering)" },
	{ fmemopen_defseek_r, "fmemopen: default position and log. size, "
	    "mode: r"},
	{ fmemopen_defseek_rp, "fmemopen: default position and log. size, "
	    "mode: r+"},
	{ fmemopen_defseek_w, "fmemopen: default position and log. size, "
	    "mode: w"},
	{ fmemopen_defseek_wp, "fmemopen: default position and log. size, "
	    "mode: w+"},
	{ fmemopen_defseek_a, "fmemopen: default position and log. size, "
	    "mode: a"},
	{ fmemopen_defseek_ap, "fmemopen: default position and log. size, "
	    "mode: a+"},
	{ fmemopen_defseek_a_nbyte, "fmemopen: default position and log. size, "
	    "mode: a, nul byte"},
	{ fmemopen_defseek_ap_nbyte, "fmemopen: default position and log. "
	    "size, mode: a+, nul byte"},
	{ fmemopen_defseek_ap_null, "fmemopen: default position and log. size, "
	    "mode: a+, NULL buf"},
	{ fmemopen_read_eof_fgetc, "fmemopen: read until EOF with fgetc" },
	{ fmemopen_read_eof_fgets, "fmemopen: read until EOF with fgets" },
	{ fmemopen_read_eof_fread, "fmemopen: read until EOF with fread" },
	{ fmemopen_read_eof_fread2, "fmemopen: read until EOF with fread 2" },
	{ fmemopen_bad_seeks, "fmemopen: invalid seeks" },
	{ fmemopen_open_trunc, "fmemopen: w+ mode truncates buffer" },
	{ fmemopen_write_nul, "fmemopen: NULs properly inserted (w)" },
	{ fmemopen_append_nul, "fmemopen: NULs properly inserted (a)" },
	{ fmemopen_read_nul, "fmemopen: read NUL character normally" },
	{ open_memstream_def_seek, "open_memstream: default position and "
	    "logical size" },
	{ open_wmemstream_def_seek, "wopen_memstream: default position and "
	    "logical size" },
	{ open_memstream_no_read, "open_memstream: read doesn't work" },
	{ open_wmemstream_no_read, "open_wmemstream: read doesn't work" },
	{ open_memstream_bad_flush, "open_memstream: flush failure due to "
	    "induced memory failure" },
	{ open_wmemstream_bad_flush, "open_wmemstream: flush failure due to "
	    "induced memory failure" },
	{ memstream_bad_seek, "open_[w]memstream: bad seeks" },
	{ open_memstream_append_nul, "open_memstream: appends NULs" },
	{ open_wmemstream_append_nul, "open_wmemstream: appends NULs" },
	{ open_wmemstream_embed_nuls, "open_wmemstream: handles embedded "
	    "NULs" },
	{ open_wmemstream_wide_write, "open_wmemstream: write wide chars" },
	{ open_wmemstream_seek_grow, "open_wmemstream: seeking doesn't grow" },
	{ open_wmemstream_byte_writes, "open_wmemstream: Write mb sequences" },
	{ open_wmemstream_bad_seq, "open_wmemstream: detect bad utf-8 "
	    "sequence" },
	{ open_wmemstream_bad_seq_fflush, "open_wmemstream: detect bad utf-8 "
	    "sequence 2 (fflush)" },
	{ open_wmemstream_ftell, "open_wmemstream: ftell buffering behavior" }
};

int
main(void)
{
	uint_t i;
	uint_t passes = 0;
	uint_t ntests = ARRAY_SIZE(memstream_tests);

	/*
	 * Set a UTF-8 locale to make sure to exercise open_wmemstream()'s
	 * mbstate logic in a more interesting way than ASCII.
	 */
	(void) setlocale(LC_ALL, "en_US.UTF-8");
	for (i = 0; i < ntests; i++) {
		boolean_t r;

		r = memstream_tests[i].mt_func();
		(void) fprintf(stderr, "TEST %s: %s\n", r ? "PASSED" : "FAILED",
		    memstream_tests[i].mt_test);
		if (r) {
			passes++;
		}
	}

	(void) printf("%d/%d test%s passed\n", passes, ntests,
	    passes > 1 ? "s" : "");
	return (passes == ntests ? EXIT_SUCCESS : EXIT_FAILURE);
}
