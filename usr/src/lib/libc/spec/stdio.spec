#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	clearerr
include		<stdio.h>
declaration	void clearerr(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	ctermid
include		<stdio.h>
declaration	char *ctermid(char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	is_empty_string($return)
end

function	ctermid_r
include		<stdio.h>
declaration	char *ctermid_r(char *s)
version		SUNW_0.7
exception	is_empty_string($return)
end

function	cuserid
include		<stdio.h>
declaration	char *cuserid(char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_cuserid # extends libc/spec/stdio.spec cuserid
weak		cuserid
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	fclose
include		<stdio.h>
declaration	int fclose(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EAGAIN EBADF EFBIG EINTR EIO ENOSPC EPIPE ENXIO
end

function	fdopen
include		<stdio.h>
declaration	FILE *fdopen(int fildes, const char *mode)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINVAL EMFILE ENOMEM
end

function	_fdopen
weak		fdopen
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	feof
include		<stdio.h>
declaration	int feof(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	ferror
include		<stdio.h>
declaration	int ferror(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	fflush
include		<stdio.h>
declaration	int fflush(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EAGAIN EBADF EFBIG EINTR EIO ENOSPC EPIPE ENXIO
end

function	fgetc
include		<stdio.h>
declaration	int fgetc(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EOVERFLOW
end

function	fgetpos
include		<stdio.h>
declaration	int fgetpos(FILE *_RESTRICT_KYWD stream, \
			fpos_t *_RESTRICT_KYWD pos)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EBADF ESPIPE EOVERFLOW
exception	$return == -1
end

function	fgets
include		<stdio.h>
declaration	char *fgets(char *_RESTRICT_KYWD s, int n, \
			FILE *_RESTRICT_KYWD stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EOVERFLOW
end

function	fileno
include		<stdio.h>
declaration	int fileno(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_fileno
weak		fileno
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	flockfile
include		<stdio.h>
declaration	void flockfile(FILE *stream)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	fopen
include		<stdio.h>
declaration	FILE *fopen(const char *_RESTRICT_KYWD filename, \
			const char *_RESTRICT_KYWD mode)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EACCES EINTR EISDIR ELOOP EMFILE ENAMETOOLONG ENFILE ENOENT \
			ENOSPC ENOTDIR ENXIO EOVERFLOW EROFS EINVAL ENOMEM \
			ETXTBSY
end

function	fputc
include		<stdio.h>
declaration	int fputc(int c, FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EFBIG
end

function	fputs
include		<stdio.h>
declaration	int fputs(const char *_RESTRICT_KYWD s, \
			FILE *_RESTRICT_KYWD stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EFBIG
end

function	fread
include		<stdio.h>, <errno.h>
declaration	size_t fread(void *_RESTRICT_KYWD ptr, size_t size, \
			size_t nitems, \
			FILE *_RESTRICT_KYWD stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EOVERFLOW EFBIG
exception	$return == 0 && (errno == EOVERFLOW || errno == EFBIG)
end

function	freopen
include		<stdio.h>
declaration	FILE *freopen(const char *_RESTRICT_KYWD filename, \
			const char *_RESTRICT_KYWD mode, \
			FILE *_RESTRICT_KYWD stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EINTR EISDIR ELOOP EMFILE ENAMETOOLONG ENFILE \
			ENOENT ENOSPC ENOTDIR ENXIO EOVERFLOW EROFS \
			EINVAL ENOMEM ETXTBSY
end

function	fscanf
include		<stdio.h>
declaration	int fscanf(FILE *_RESTRICT_KYWD strm, \
			const char *_RESTRICT_KYWD format, ...)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EOVERFLOW
exception	$return == -1
end

function	fwscanf
include		<stdio.h>, <wchar.h>
declaration	int fwscanf(FILE *_RESTRICT_KYWD stream, \
		const wchar_t *_RESTRICT_KYWD format, ...)
version		SUNW_1.18
end

function	fseek
include		<stdio.h>
declaration	int fseek(FILE *stream, long offset, int whence)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EAGAIN EBADF EFBIG EINTR EINVAL EIO ENOSPC EPIPE ENXIO EOVERFLOW
end

function	fseeko
include		<stdio.h>
declaration	int fseeko(FILE *stream, off_t offset, int whence)
version		SUNW_1.1
errno		EAGAIN EBADF EFBIG EINTR EINVAL EIO ENOSPC EPIPE ENXIO EOVERFLOW
end

function	fsetpos
include		<stdio.h>
declaration	int fsetpos(FILE *stream, const fpos_t *pos)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EBADF ESPIPE
exception	$return == -1
end

function	ftell
include		<stdio.h>
declaration	long ftell(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EBADF ESPIPE EOVERFLOW
end

function	ftello
include		<stdio.h>
declaration	off_t ftello(FILE *stream)
version		SUNW_1.1
errno		EBADF ESPIPE EOVERFLOW
end

function	funlockfile
include		<stdio.h>
declaration	void funlockfile(FILE *stream)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	fwrite
include		<stdio.h>
declaration	size_t fwrite(const void *_RESTRICT_KYWD ptr, size_t size, \
			size_t nitems, \
			FILE *_RESTRICT_KYWD stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EOVERFLOW EFBIG
exception	$return == 0
end

function	getc
include		<stdio.h>
declaration	int getc(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EOVERFLOW
end

function	getc_unlocked
include		<stdio.h>
declaration	int getc_unlocked(FILE *stream)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EOVERFLOW
end

function	getchar
include		<stdio.h>
declaration	int getchar(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EOVERFLOW
end

function	getchar_unlocked
include		<stdio.h>
declaration	int getchar_unlocked(void)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EOVERFLOW
end

function	getpass
include		<unistd.h>
declaration	char *getpass(const char *prompt)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINTR EIO EMFILE ENFILE ENXIO
end

function	_getpass
weak		getpass
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	getpassphrase
include		<unistd.h>
declaration	char *getpassphrase(const char *prompt)
version		SUNW_1.1
errno		EINTR EIO EMFILE ENFILE ENXIO
end

function	gets
include		<stdio.h>
declaration	char *gets(char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EOVERFLOW
end

function	getw
include		<stdio.h>
declaration	int getw(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EOVERFLOW
end

function	_getw
weak		getw
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	pclose
include		<stdio.h>
declaration	int pclose(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == -1
end

function	_pclose
weak		pclose
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	popen
include		<stdio.h>
declaration	FILE *popen(const char *command, const char *mode)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_popen
weak		popen
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	putc
include		<stdio.h>
declaration	int putc(int c, FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EFBIG
end

function	putc_unlocked
include		<stdio.h>
declaration	int putc_unlocked(int c, FILE *stream)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EFBIG
end

function	putchar
include		<stdio.h>
declaration	int putchar(int c)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EFBIG
end

function	putchar_unlocked
include		<stdio.h>
declaration	int putchar_unlocked(int c)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EFBIG
end

function	puts
include		<stdio.h>
declaration	int puts(const char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EFBIG
end

function	putw
include		<stdio.h>
declaration	int putw(int w, FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EFBIG
end

function	_putw
weak		putw
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	scanf
include		<stdio.h>
declaration	int scanf(const char *_RESTRICT_KYWD format, ...)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EOVERFLOW
exception	$return == -1
end

function	setbuf
include		<stdio.h>
declaration	void setbuf(FILE *_RESTRICT_KYWD stream, \
			char *_RESTRICT_KYWD buf)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	setbuffer
include		<stdio.h>
declaration	void setbuffer(FILE *iop, char *abuf, size_t asize)
version		SUNW_0.9
end

function	setlinebuf
include		<stdio.h>
declaration	int setlinebuf(FILE *iop)
version		SUNW_0.9
end

function	setvbuf
include		<stdio.h>
declaration	int setvbuf(FILE *_RESTRICT_KYWD stream, \
			char *_RESTRICT_KYWD buf, int type, size_t size)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	sscanf
include		<stdio.h>
declaration	int sscanf(const char *_RESTRICT_KYWD s, \
			const char *_RESTRICT_KYWD format, ...)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EOVERFLOW
exception	$return == -1
end

function	system
declaration	int system(const char *string )
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	tempnam
include		<stdio.h>
declaration	char *tempnam(const char *dir, const char *pfx)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_tempnam
weak		tempnam
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tmpfile
include		<stdio.h>
declaration	FILE *tmpfile(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EINTR EMFILE ENFILE ENOSPC ENOMEM
end

function	tmpnam
include		<stdio.h>
declaration	char *tmpnam(char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	tmpnam_r
include		<stdio.h>
declaration	char *tmpnam_r(char *s)
version		SUNW_0.7
exception	$return == 0
end

function	ungetc
include		<stdio.h>
declaration	int ungetc(int c, FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	_vfscanf
weak		vfscanf
version		SUNW_1.21
end

function	vfscanf
include		<stdarg.h>, <stdio.h>
declaration	int vfscanf(FILE *_RESTRICT_KYWD strm, \
			const char *_RESTRICT_KYWD format, va_list arg)
version		SUNW_1.21
errno		EOVERFLOW
exception	$return == -1
end

function	vfwscanf
include		<stdarg.h>, <stdio.h>, <wchar.h>
declaration	int vfwscanf(FILE *_RESTRICT_KYWD stream, \
		const wchar_t *_RESTRICT_KYWD format, va_list arg)
version		SUNW_1.21
end

function	_vscanf
weak		vscanf
version		SUNW_1.21
end

function	vscanf
include		<stdarg.h>, <stdio.h>
declaration	int vscanf(const char *_RESTRICT_KYWD format, va_list arg)
version		SUNW_1.21
errno		EOVERFLOW
exception	$return == -1
end

function	_vsscanf
weak		vsscanf
version		SUNW_1.21
end

function	vsscanf
include		<stdarg.h>, <stdio.h>
declaration	int vsscanf(const char *_RESTRICT_KYWD s, \
			const char *_RESTRICT_KYWD format, va_list arg)
version		SUNW_1.21
errno		EOVERFLOW
exception	$return == -1
end

function	vswscanf
include		<stdarg.h>, <stdio.h>, <wchar.h>
declaration	int vswscanf(const wchar_t *_RESTRICT_KYWD ws, \
		const wchar_t *_RESTRICT_KYWD format, va_list arg)
version		SUNW_1.21
end

function	vwscanf
include		<stdarg.h>, <stdio.h>, <wchar.h>
declaration	int vwscanf(const wchar_t *_RESTRICT_KYWD format, va_list arg)
version		SUNW_1.21
end

function	wscanf
include		<stdio.h>, <wchar.h>
declaration	int wscanf(const wchar_t *_RESTRICT_KYWD format, ...)
version		SUNW_1.18
end
