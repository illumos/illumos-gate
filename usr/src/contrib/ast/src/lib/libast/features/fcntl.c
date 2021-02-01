/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * generate POSIX fcntl.h
 */

#include <sys/types.h>

#include "FEATURE/lib"

#define getdtablesize	______getdtablesize
#define getpagesize	______getpagesize
#define ioctl		______ioctl

#if _typ_off64_t
#undef	off_t
#ifdef __STDC__
#define	off_t		off_t
#endif
#endif

#if _hdr_fcntl
#include <fcntl.h>
#endif
#if _hdr_unistd
#include <unistd.h>
#endif

#include <sys/stat.h>

#include "FEATURE/fs"

#undef	getdtablesize   
#undef	getpagesize
#undef	ioctl

#include "FEATURE/tty"

#if _typ_off64_t
#undef	off_t
#define	off_t	off64_t
#endif

int
main()
{
	int		f_local = 0;
	int		f_lck = 0;
	int		o_local = 2;

	printf("#pragma prototyped\n");
	printf("\n");
	printf("#if _typ_off64_t\n");
	printf("#undef	off_t\n");
	printf("#ifdef __STDC__\n");
	printf("#define	off_t		off_t\n");
	printf("#endif\n");
	printf("#endif\n");
	printf("\n");
	printf("#include <ast_fs.h>\n");
	printf("\n");
	printf("#if _typ_off64_t\n");
	printf("#undef	off_t\n");
	printf("#ifdef __STDC__\n");
	printf("#define	off_t		off_t\n");
	printf("#endif\n");
	printf("#endif\n");
	printf("\n");
	printf("#include <fcntl.h>\n");
#if _hdr_mman
	printf("#include <mman.h>\n");
#else
#if _sys_mman
	printf("#include <sys/mman.h>\n");
#endif
#endif
	printf("\n");
#ifndef	FD_CLOEXEC
	printf("#define FD_CLOEXEC	1\n");
	printf("\n");
#endif

#ifndef	F_DUPFD
#define NEED_F	1
#else
	if (F_DUPFD > f_local) f_local = F_DUPFD;
#endif
#ifndef	F_GETFD
#define NEED_F	1
#else
	if (F_GETFD > f_local) f_local = F_GETFD;
#endif
#ifndef	F_GETFL
#define NEED_F	1
#else
	if (F_GETFL > f_local) f_local = F_GETFL;
#endif
#ifndef	F_GETLK
#define NEED_F	1
#else
	if (F_GETLK > f_local) f_local = F_GETLK;
#endif
#ifndef	F_RDLCK
#define NEED_F	1
#define NEED_LCK	1
#else
	if (F_RDLCK > f_lck) f_lck = F_RDLCK;
#endif
#ifndef	F_SETFD
#define NEED_F	1
#else
	if (F_SETFD > f_local) f_local = F_SETFD;
#endif
#ifndef	F_SETFL
#define NEED_F	1
#else
	if (F_SETFL > f_local) f_local = F_SETFL;
#endif
#ifndef	F_SETLK
#define NEED_F	1
#else
	if (F_SETLK > f_local) f_local = F_SETLK;
#endif
#ifndef	F_SETLKW
#define NEED_F	1
#else
	if (F_SETLKW > f_local) f_local = F_SETLKW;
#endif
#ifndef	F_UNLCK
#define NEED_F	1
#define NEED_LCK	1
#else
	if (F_UNLCK > f_lck) f_lck = F_UNLCK;
#endif
#ifndef	F_WRLCK
#define NEED_F	1
#define NEED_LCK	1
#else
	if (F_WRLCK > f_lck) f_lck = F_WRLCK;
#endif

#if	NEED_F
	printf("#define fcntl		_ast_fcntl\n");
#if	_lib_fcntl
	printf("#define _lib_fcntl	1\n");
#endif
	printf("#define _ast_F_LOCAL	%d\n", f_local + 1);
#ifndef	F_DUPFD
	printf("#define F_DUPFD		%d\n", ++f_local);
#endif
#ifndef	F_GETFD
	printf("#define F_GETFD		%d\n", ++f_local);
#endif
#ifndef	F_GETFL
	printf("#define F_GETFL		%d\n", ++f_local);
#endif
#ifndef	F_GETLK
	printf("#define F_GETLK		%d\n", ++f_local);
#endif
#ifndef	F_SETFD
	printf("#define F_SETFD		%d\n", ++f_local);
#endif
#ifndef	F_SETFL
	printf("#define F_SETFL		%d\n", ++f_local);
#endif
#ifndef	F_SETLK
	printf("#define F_SETLK		%d\n", ++f_local);
#endif
#ifndef	F_SETLKW
	printf("#define F_SETLKW	%d\n", ++f_local);
#endif
#if	NEED_LCK
	printf("\n");
#ifndef	F_RDLCK
	printf("#define F_RDLCK		%d\n", f_lck++);
#endif
#ifndef	F_WRLCK
	printf("#define F_WRLCK		%d\n", f_lck++);
#endif
#ifndef	F_UNLCK
	printf("#define F_UNLCK		%d\n", f_lck++);
#endif
#endif
	printf("\n");
	if (f_lck == 3)
	{
		printf("struct flock\n");
		printf("{\n");
		printf("	short	l_type;\n");
		printf("	short	l_whence;\n");
		printf("	off_t	l_start;\n");
		printf("	off_t	l_len;\n");
		printf("	short	l_pid;\n");
		printf("};\n");
		printf("\n");
	}
	printf("\n");
#endif
#ifdef F_DUPFD_CLOEXEC
	printf("#define F_dupfd_cloexec	F_DUPFD_CLOEXEC\n");
#else
	printf("#define F_dupfd_cloexec	F_DUPFD\n");
#endif

#ifndef	O_APPEND
#define NEED_O	1
#else
	if (O_APPEND > o_local) o_local = O_APPEND;
#endif
#ifndef	O_CREAT
#define NEED_O	1
#else
	if (O_CREAT > o_local) o_local = O_CREAT;
#endif
#ifndef	O_EXCL
#define NEED_O	1
#else
	if (O_EXCL > o_local) o_local = O_EXCL;
#endif
#ifndef	O_NOCTTY
#ifdef	TIOCNOTTY
#define NEED_O	1
#endif
#else
	if (O_NOCTTY > o_local) o_local = O_NOCTTY;
#endif
#ifndef	O_NONBLOCK
#ifndef	O_NDELAY
#define NEED_O	1
#endif
#else
	if (O_NONBLOCK > o_local) o_local = O_NONBLOCK;
#endif
#ifndef	O_RDONLY
#define NEED_O	1
#endif
#ifndef	O_RDWR
#define NEED_O	1
#endif
#ifndef	O_TRUNC
#define NEED_O	1
#else
	if (O_TRUNC > o_local) o_local = O_TRUNC;
#endif
#ifndef	O_WRONLY
#define NEED_O	1
#endif

#if	NEED_O
	printf("#define open			_ast_open\n");
	printf("#define _ast_O_LOCAL		0%o\n", o_local<<1);
#ifndef	O_RDONLY
	printf("#define O_RDONLY		0\n");
#endif
#ifndef	O_WRONLY
	printf("#define O_WRONLY		1\n");
#endif
#ifndef	O_RDWR
	printf("#define O_RDWR			2\n");
#endif
#ifndef	O_APPEND
	printf("#define O_APPEND		0%o\n", o_local <<= 1);
#endif
#ifndef	O_CREAT
	printf("#define O_CREAT			0%o\n", o_local <<= 1);
#endif
#ifndef	O_EXCL
	printf("#define O_EXCL			0%o\n", o_local <<= 1);
#endif
#ifndef	O_NOCTTY
#ifdef	TIOCNOTTY
	printf("#define O_NOCTTY		0%o\n", o_local <<= 1);
#endif
#endif
#ifndef	O_NONBLOCK
#ifndef	O_NDELAY
	printf("#define O_NONBLOCK		0%o\n", o_local <<= 1);
#endif
#endif
#ifndef	O_TRUNC
	printf("#define O_TRUNC			0%o\n", o_local <<= 1);
#endif
#endif
#ifndef	O_ACCMODE
	printf("#define O_ACCMODE		(O_RDONLY|O_WRONLY|O_RDWR)\n");
#endif
#ifndef	O_NOCTTY
#ifndef	TIOCNOTTY
	printf("#define O_NOCTTY		0\n");
#endif
#endif
#ifndef	O_NONBLOCK
#ifdef	O_NDELAY
	printf("#define O_NONBLOCK		O_NDELAY\n");
#endif
#endif
#ifndef	O_BINARY
	printf("#define O_BINARY		0\n");
#endif
#ifdef	O_CLOEXEC
	printf("#define O_cloexec		O_CLOEXEC\n");
#else
	printf("#define O_cloexec		0\n");
#endif
#ifndef	O_TEMPORARY
	printf("#define O_TEMPORARY		0\n");
#endif
#ifndef	O_TEXT
	printf("#define O_TEXT			0\n");
#endif
#if	NEED_F || NEED_O
	printf("\n");
#if	NEED_F
	printf("extern int	fcntl(int, int, ...);\n");
#endif
#if	NEED_O
	printf("extern int	open(const char*, int, ...);\n");
#endif
#endif
	printf("\n");
	printf("#include <ast_fs.h>\n");
	printf("#if _typ_off64_t\n");
	printf("#undef	off_t\n");
	printf("#define	off_t		off64_t\n");
	printf("#endif\n");
	printf("#if _lib_fstat64\n");
	printf("#define fstat		fstat64\n");
	printf("#endif\n");
	printf("#if _lib_lstat64\n");
	printf("#define lstat		lstat64\n");
	printf("#endif\n");
	printf("#if _lib_stat64\n");
	printf("#define stat		stat64\n");
	printf("#endif\n");
	printf("#if _lib_creat64\n");
	printf("#define creat		creat64\n");
	printf("#endif\n");
	printf("#if _lib_mmap64\n");
	printf("#define mmap		mmap64\n");
	printf("#endif\n");
	printf("#if _lib_open64\n");
	printf("#undef	open\n");
	printf("#define open		open64\n");
	printf("#endif\n");

	return 0;
}
