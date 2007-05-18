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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <limits.h>
#include <audio/au.h>

#include "bstream.h"
#include "util.h"
#include "audio.h"
#include "byteorder.h"
#include "main.h"

int str_errno;

char *
str_errno_to_string(int serrno)
{
	switch (serrno) {
	case STR_ERR_NO_ERR:
		return (gettext("No error"));
	case STR_ERR_NO_REG_FILE:
		return (gettext("Not a regular file"));
	case STR_ERR_NO_READ_STDIN:
		return (gettext("Stdin not open for reading"));
	case STR_ERR_AU_READ_ERR:
		return (gettext("Unable to read au header"));
	case STR_ERR_AU_UNSUPPORTED_FORMAT:
		return (gettext("Unsupported au format"));
	case STR_ERR_AU_BAD_HEADER:
		return (gettext("Bad au header"));
	case STR_ERR_WAV_READ_ERR:
		return (gettext("Unable to read wav header"));
	case STR_ERR_WAV_UNSUPPORTED_FORMAT:
		return (gettext("Unsupported wav format"));
	case STR_ERR_WAV_BAD_HEADER:
		return (gettext("Bad wav header"));
	case STR_ERR_ISO_READ_ERR:
		return (gettext("Unable to read ISO header"));
	case STR_ERR_ISO_BAD_HEADER:
		return (gettext("Invalid ISO header or not an ISO"));
	default:
		return (gettext("unknown error"));
	}
}

static int
file_stream_size(bstreamhandle h, off_t *size)
{
	struct stat st;

	str_errno = 0;

	if (fstat(h->bstr_fd, &st) < 0)
		return (0);
	if ((st.st_mode & S_IFMT) != S_IFREG) {
		str_errno = STR_ERR_NO_REG_FILE;
		return (0);
	}
	*size = st.st_size;
	return (1);
}

static int
audio_stream_size(bstreamhandle h, off_t *size)
{
	str_errno = 0;
	*size = (off_t)(uintptr_t)(h->bstr_private);
	return (1);
}

static int
file_stream_read(bstreamhandle h, uchar_t *buf, off_t size)
{
	str_errno = 0;
	return (read(h->bstr_fd, buf, size));
}

static int
file_stream_write(bstreamhandle h, uchar_t *buf, off_t size)
{
	str_errno = 0;
	return (write(h->bstr_fd, buf, size));
}

/*
 * with reverse byteorder
 */
static int
file_stream_read_wrbo(bstreamhandle h, uchar_t *buf, off_t size)
{
	int cnt;

	str_errno = 0;
	cnt = read(h->bstr_fd, buf, size);
	if (cnt > 0) {
		int i;
		uchar_t ch;

		for (i = 0; i < cnt; i += 2) {
			ch = buf[i];
			buf[i] = buf[i+1];
			buf[i+1] = ch;
		}
	}
	return (cnt);
}

/*
 * This will change the byteorder in the buffer but that is fine with us.
 */
static int
file_stream_write_wrbo(bstreamhandle h, uchar_t *buf, off_t size)
{
	int i;
	uchar_t ch;

	str_errno = 0;
	if (size > 0) {
		for (i = 0; i < size; i += 2) {
			ch = buf[i];
			buf[i] = buf[i+1];
			buf[i+1] = ch;
		}
	}
	return (write(h->bstr_fd, buf, size));
}

static int
file_stream_close(bstreamhandle h)
{
	int fd;

	str_errno = 0;
	fd = h->bstr_fd;
	free(h);
	return (close(fd));
}

static int
stdin_stream_close(bstreamhandle h)
{
	str_errno = 0;
	free(h);
	return (0);
}

static int
wav_write_stream_close(bstreamhandle h)
{
	uint32_t sz;
	Wave_filehdr wav;

	str_errno = 0;
	(void) memset(&wav, 0, sizeof (wav));
	sz = lseek(h->bstr_fd, 0L, SEEK_END);
	(void) lseek(h->bstr_fd, 0L, SEEK_SET);
	if (read(h->bstr_fd, &wav, sizeof (wav)) != sizeof (wav)) {
		return (1);
	}
	wav.total_chunk_size = CPU_TO_LE32(sz - 8);
	wav.data_size = CPU_TO_LE32(sz - 44);
	(void) lseek(h->bstr_fd, 0L, SEEK_SET);
	if (write(h->bstr_fd, &wav, sizeof (wav)) != sizeof (wav)) {
		return (1);
	}
	(void) close(h->bstr_fd);
	free(h);
	return (0);
}

static int
au_write_stream_close(bstreamhandle h)
{
	uint32_t sz;

	str_errno = 0;
	sz = lseek(h->bstr_fd, 0L, SEEK_END);
	sz -= PRE_DEF_AU_HDR_LEN;
	sz = CPU_TO_BE32(sz);
	if (lseek(h->bstr_fd, 8L, SEEK_SET) < 0)
		return (1);

	if (write(h->bstr_fd, &sz, 4) < 0)
		return (1);

	(void) close(h->bstr_fd);
	free(h);
	return (0);
}

/* ARGSUSED */
static void
stdin_stream_rewind(bstreamhandle h)
{
}

static void
file_stream_rewind(bstreamhandle h)
{
	(void) lseek(h->bstr_fd, 0L, SEEK_SET);
}

static void
au_stream_rewind(bstreamhandle h)
{
	au_filehdr_t au;

	(void) lseek(h->bstr_fd, 0L, SEEK_SET);
	if (read(h->bstr_fd, &au, sizeof (au)) != sizeof (au)) {
		return;
	}

	if (lseek(h->bstr_fd, (long)(BE32_TO_CPU(au.au_offset)),
	    SEEK_SET) < 0) {
		return;
	}
}

static void
wav_stream_rewind(bstreamhandle h)
{
	(void) lseek(h->bstr_fd, (long)(sizeof (Wave_filehdr)), SEEK_SET);
}

bstreamhandle
open_file_read_stream(char *file)
{
	bstreamhandle h;
	int fd;
	struct stat st;

	str_errno = 0;
	if (stat(file, &st) < 0)
		return (NULL);
	if ((st.st_mode & S_IFMT) == S_IFDIR) {
		str_errno = STR_ERR_NO_REG_FILE;
		return (NULL);
	}
	fd = open(file, O_RDONLY);
	if (fd < 0)
		return (NULL);
	h = (bstreamhandle)my_zalloc(sizeof (*h));
	h->bstr_fd = fd;
	h->bstr_read = file_stream_read;
	h->bstr_close = file_stream_close;
	h->bstr_size = file_stream_size;
	h->bstr_rewind = file_stream_rewind;

	return (h);
}

bstreamhandle
open_iso_read_stream(char *fname)
{
	bstreamhandle h;
	off_t iso_size = 0;
	char iso_desc[ISO9660_PRIMARY_DESC_SIZE];

	h = open_file_read_stream(fname);

	/* If we don't have a valid handle immediately return NULL */
	if (h == NULL)
		return (NULL);

	if (debug)
		(void) printf("Checking the ISO 9660 file header\n");

	/* Check to see if we have a valid sized ISO image */
	h->bstr_size(h, &iso_size);
	if (iso_size < ISO9660_HEADER_SIZE) {
		if (debug)
			(void) printf("ISO 9660 header size not sane.\n");
		h->bstr_close(h);
		str_errno = STR_ERR_ISO_BAD_HEADER;
		return (NULL);
	}

	if (debug)
		(void) printf("ISO 9660 header size is sane.\n");

	/* Skip over the boot block sector of the ISO. */
	(void) lseek(h->bstr_fd, ISO9660_BOOT_BLOCK_SIZE, SEEK_SET);

	/*
	 * Try to read in the ISO Descriptor and validate this
	 * is in fact an ISO 9660 image.
	 */
	if (read(h->bstr_fd, iso_desc, ISO9660_PRIMARY_DESC_SIZE) ==
	    ISO9660_PRIMARY_DESC_SIZE) {
		/*
		 * Bytes one through five of a valid ISO 9660 cd image
		 * should contain the string CD001. High Sierra format,
		 * the ISO 9660 predecessor, fills this field with the
		 * string CDROM. If neither is the case then we should
		 * close the stream, set str_errno, and return NULL.
		 */
		if (strncmp(iso_desc + ISO9660_STD_IDENT_OFFSET, "CD001",
		    5) != 0 && strncmp(iso_desc + ISO9660_STD_IDENT_OFFSET,
		    "CDROM", 5) != 0) {
			if (debug)
				(void) printf("Invalid ISO 9660 identifier.\n");
			h->bstr_close(h);
			str_errno = STR_ERR_ISO_BAD_HEADER;
			return (NULL);
		}
	} else {
		h->bstr_close(h);
		str_errno = STR_ERR_ISO_READ_ERR;
		return (NULL);
	}

	/*
	 * Our ISO image is valid rewind the stream
	 * and return the handle.
	 */
	if (debug)
		(void) printf("ISO 9660 header is sane.\n");
	h->bstr_rewind(h);
	return (h);
}

bstreamhandle
open_stdin_read_stream(void)
{
	bstreamhandle h;
	int mode;

	str_errno = 0;
	if ((mode = fcntl(0, F_GETFD, NULL)) < 0) {
		str_errno = STR_ERR_NO_READ_STDIN;
		return (NULL);
	}
	mode &= 3;
	if ((mode != O_RDONLY) && (mode != O_RDWR)) {
		str_errno = STR_ERR_NO_READ_STDIN;
		return (NULL);
	}
	h = (bstreamhandle)my_zalloc(sizeof (*h));
	h->bstr_fd = 0;
	h->bstr_read = file_stream_read;
	h->bstr_close = stdin_stream_close;
	h->bstr_size = file_stream_size;
	h->bstr_rewind = stdin_stream_rewind;

	return (h);
}

bstreamhandle
open_au_read_stream(char *fname)
{
	bstreamhandle h;
	int fd, sav;
	au_filehdr_t *au;
	struct stat st;
	uint32_t data_size;

	au = NULL;
	str_errno = 0;
	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return (NULL);

	if (fstat(fd, &st) < 0) {
		goto au_open_failed;
	}
	if ((st.st_mode & S_IFMT) != S_IFREG) {
		str_errno = STR_ERR_NO_REG_FILE;
		goto au_open_failed;
	}
	au = (au_filehdr_t *)my_zalloc(sizeof (*au));
	if (read(fd, au, sizeof (*au)) != sizeof (*au)) {
		str_errno = STR_ERR_AU_READ_ERR;
		goto au_open_failed;
	}
	au->au_magic = BE32_TO_CPU(au->au_magic);
	au->au_offset = BE32_TO_CPU(au->au_offset);
	au->au_data_size = BE32_TO_CPU(au->au_data_size);
	au->au_encoding = BE32_TO_CPU(au->au_encoding);
	au->au_sample_rate = BE32_TO_CPU(au->au_sample_rate);
	au->au_channels = BE32_TO_CPU(au->au_channels);

	if (au->au_magic != AUDIO_AU_FILE_MAGIC) {
		str_errno = STR_ERR_AU_BAD_HEADER;
		goto au_open_failed;
	}
	if ((au->au_encoding != AUDIO_AU_ENCODING_LINEAR_16) ||
	    (au->au_sample_rate != 44100) || (au->au_channels != 2)) {

		str_errno = STR_ERR_AU_UNSUPPORTED_FORMAT;
		goto au_open_failed;
	}
	if (au->au_data_size != AUDIO_AU_UNKNOWN_SIZE) {
		if ((au->au_offset + au->au_data_size) != st.st_size) {
			str_errno = STR_ERR_AU_BAD_HEADER;
			goto au_open_failed;
		}
		data_size = au->au_data_size;
	} else {
		data_size = st.st_size - au->au_offset;
	}
	if (data_size == 0) {
		str_errno = STR_ERR_AU_UNSUPPORTED_FORMAT;
		goto au_open_failed;
	}
	if (lseek(fd, au->au_offset, SEEK_SET) < 0) {
		goto au_open_failed;
	}

	free(au);
	h = (bstreamhandle)my_zalloc(sizeof (*h));
	h->bstr_fd = fd;
	h->bstr_read = file_stream_read_wrbo;
	h->bstr_close = file_stream_close;
	h->bstr_size = audio_stream_size;
	h->bstr_rewind = au_stream_rewind;
	h->bstr_private = (void *)data_size;

	return (h);

au_open_failed:
	sav = errno;
	(void) close(fd);
	if (au != NULL)
		free(au);
	errno = sav;
	return (NULL);
}

bstreamhandle
open_wav_read_stream(char *fname)
{
	bstreamhandle h;
	int fd, sav;
	Wave_filehdr *wav;
	struct stat st;
	uint32_t data_size;

	wav = NULL;
	str_errno = 0;
	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return (NULL);

	if (fstat(fd, &st) < 0) {
		goto wav_open_failed;
	}
	if ((st.st_mode & S_IFMT) != S_IFREG) {
		str_errno = STR_ERR_NO_REG_FILE;
		goto wav_open_failed;
	}
	wav = (Wave_filehdr *)my_zalloc(sizeof (*wav));
	if (read(fd, wav, sizeof (*wav)) != sizeof (*wav)) {
		str_errno = STR_ERR_WAV_READ_ERR;
		goto wav_open_failed;
	}
	if ((strncmp(wav->riff, "RIFF", 4) != 0) ||
		(strncmp(wav->wave, "WAVE", 4) != 0)) {
		str_errno = STR_ERR_WAV_BAD_HEADER;
		goto wav_open_failed;
	}
	if (((CPU_TO_LE32(wav->total_chunk_size) + 8) != st.st_size) ||
	    (strncmp(wav->fmt, "fmt ", 4) != 0) ||
	    (CPU_TO_LE16(wav->fmt_tag) != 1) ||
	    (CPU_TO_LE16(wav->n_channels) != 2) ||
	    (CPU_TO_LE32(wav->sample_rate) != 44100) ||
	    (CPU_TO_LE16(wav->bits_per_sample) != 16) ||
	    (strncmp(wav->data, "data", 4) != 0) ||
	    ((CPU_TO_LE32(wav->data_size) + 44) != st.st_size)) {

		str_errno = STR_ERR_WAV_UNSUPPORTED_FORMAT;
		goto wav_open_failed;
	}
	data_size = CPU_TO_LE32(wav->data_size);
	if (lseek(fd, sizeof (*wav), SEEK_SET) < 0) {
		goto wav_open_failed;
	}

	free(wav);
	h = (bstreamhandle)my_zalloc(sizeof (*h));
	h->bstr_fd = fd;
	h->bstr_read = file_stream_read;
	h->bstr_close = file_stream_close;
	h->bstr_size = audio_stream_size;
	h->bstr_rewind = wav_stream_rewind;
	h->bstr_private = (void *)data_size;

	return (h);

wav_open_failed:
	sav = errno;
	(void) close(fd);
	if (wav != NULL)
		free(wav);
	errno = sav;
	return (NULL);
}

bstreamhandle
open_aur_read_stream(char *fname)
{
	bstreamhandle h;

	h = open_file_read_stream(fname);
	if (h != NULL) {
		h->bstr_read = file_stream_read_wrbo;
	}
	return (h);
}

bstreamhandle
open_au_write_stream(char *fname)
{
	bstreamhandle h;
	int esav, fd;
	uchar_t head[] = PRE_DEF_AU_HDR;

	str_errno = 0;
	fd = -1;
	/* O_RDWR because we need to read while closing */
	fd = open(fname, O_RDWR|O_CREAT|O_TRUNC, 0666);
	if (fd < 0)
		goto open_au_write_stream_failed;
	if (write(fd, head, PRE_DEF_AU_HDR_LEN) != PRE_DEF_AU_HDR_LEN) {
		goto open_au_write_stream_failed;
	}
	h = (bstreamhandle)my_zalloc(sizeof (*h));
	h->bstr_fd = fd;
	h->bstr_write = file_stream_write_wrbo;
	h->bstr_close = au_write_stream_close;
	return (h);

open_au_write_stream_failed:
	esav = errno;
	if (fd != -1)
		(void) close(fd);
	errno = esav;
	return (NULL);
}

bstreamhandle
open_wav_write_stream(char *fname)
{
	bstreamhandle h;
	int esav, fd;
	uchar_t head[] = PRE_DEF_WAV_HDR;

	str_errno = 0;
	fd = -1;
	fd = open(fname, O_RDWR|O_CREAT|O_TRUNC, 0666);
	if (fd < 0)
		goto open_wav_write_stream_failed;
	if (write(fd, head, PRE_DEF_WAV_HDR_LEN) != PRE_DEF_WAV_HDR_LEN) {
		goto open_wav_write_stream_failed;
	}
	h = (bstreamhandle)my_zalloc(sizeof (*h));
	h->bstr_fd = fd;
	h->bstr_write = file_stream_write;
	h->bstr_close = wav_write_stream_close;
	return (h);

open_wav_write_stream_failed:
	esav = errno;
	if (fd != -1)
		(void) close(fd);
	errno = esav;
	return (NULL);
}

bstreamhandle
open_aur_write_stream(char *fname)
{
	bstreamhandle h;
	int fd;

	str_errno = 0;
	fd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (fd < 0)
		return (NULL);
	h = (bstreamhandle)my_zalloc(sizeof (*h));
	h->bstr_fd = fd;
	h->bstr_write = file_stream_write_wrbo;
	h->bstr_close = file_stream_close;
	return (h);
}

bstreamhandle
open_file_write_stream(char *fname)
{
	bstreamhandle h;
	int fd;

	str_errno = 0;
	fd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (fd < 0)
		return (NULL);
	h = (bstreamhandle)my_zalloc(sizeof (*h));
	h->bstr_fd = fd;
	h->bstr_write = file_stream_write;
	h->bstr_close = file_stream_close;
	return (h);
}

bstreamhandle
open_temp_file_stream(void)
{
	bstreamhandle h;
	char *t;
	int fd;

	str_errno = 0;

	t = (char *)get_tmp_name();

	if (strlcat(t, "/cdXXXXXX", PATH_MAX) >= PATH_MAX)
		return (NULL);

	fd = mkstemp(t);

	if (debug)
		(void) printf("temp is: %s length: %d\n", t, strlen(t));

	if (fd < 0)
		return (NULL);
	(void) unlink(t);

	h = (bstreamhandle)my_zalloc(sizeof (*h));
	h->bstr_fd = fd;
	h->bstr_read = file_stream_read;
	h->bstr_write = file_stream_write;
	h->bstr_close = file_stream_close;
	h->bstr_size = file_stream_size;
	h->bstr_rewind = file_stream_rewind;

	return (h);
}

/*
 * check_avail_temp_space returns 0 if there is adequate space
 * in the temporary directory, or a non-zero error code if
 * something goes wrong
 */
int
check_avail_temp_space(size_t req_size)
{
	struct statvfs buf;
	u_longlong_t free_size = 0;

	if (statvfs(get_tmp_name(), &buf) < 0) {
		return (errno);
	}

	free_size = buf.f_bfree * buf.f_frsize;

	if (free_size <= req_size)
		return (ENOMEM);

	return (0);
}


char *
get_tmp_name(void)
{
	char *t;
	char *envptr;

	t = (char *)my_zalloc(PATH_MAX);

	/*
	 * generate temp directory path based on this order:
	 * user specified (-m option), temp env variable,
	 * and finally /tmp if nothing is found.
	 */

	if (alt_tmp_dir) {

		/* copy and leave room for temp filename */

		(void) strlcpy(t, alt_tmp_dir, PATH_MAX - 10);
	} else {
		envptr = getenv("TMPDIR");
		if (envptr != NULL) {
			(void) strlcpy(t, envptr, PATH_MAX - 10);
		} else {
			(void) strlcpy(t, "/tmp", 5);
		}
	}

	/*
	 * no need to check if path is valid. statvfs will catch
	 * it later and fail with a proper error message.
	 */

	return (t);
}
