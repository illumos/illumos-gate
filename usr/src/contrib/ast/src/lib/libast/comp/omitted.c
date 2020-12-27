#pragma prototyped noticed

/*
 * workarounds to bring the native interface close to posix and x/open
 */

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide utime utimes
#else
#define utime		______utime
#define utimes		______utimes
#endif

#include <ast.h>
#include <error.h>
#include <tm.h>

#include "FEATURE/omitted"

#undef	OMITTED

#if _win32_botch

#define	OMITTED	1

#include <ls.h>
#include <utime.h>

#if __CYGWIN__
#include <ast_windows.h>
#if _win32_botch_execve || _lib_spawn_mode
#define CONVERT		1
#endif
#endif

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide utime utimes
#else
#undef	utime
#undef	utimes
#endif

#ifndef MAX_PATH
#define MAX_PATH	PATH_MAX
#endif

/*
 * these workarounds assume each system call foo() has a _foo() entry
 * which is true for __CYGWIN__ and __EMX__ (both gnu based)
 *
 * the workarounds handle:
 *
 *	(1) .exe suffix inconsistencies
 *	(2) /bin/sh reference in execve() and spawnve()
 *	(3) bogus getpagesize() return values
 *	(4) a fork() bug that screws up shell fork()+script
 *
 * NOTE: Not all workarounds can be handled by unix syscall intercepts.
 *	 In particular, { ksh nmake } have workarounds for case-ignorant
 *	 filesystems and { libast } has workarounds for win32 locale info.
 */

#undef _pathconf
#undef pathconf
#undef stat

extern int		_access(const char*, int);
extern unsigned int	_alarm(unsigned int);
extern int		_chmod(const char*, mode_t);
extern int		_close(int);
extern pid_t		_execve(const char*, char* const*, char* const*);
extern uid_t		_getuid(void);
extern int		_link(const char*, const char*);
extern int		_open(const char*, int, ...);
extern long		_pathconf(const char*, int);
extern ssize_t		_read(int, void*, size_t);
extern int		_rename(const char*, const char*);
extern pid_t		_spawnve(int, const char*, char* const*, char* const*);
extern int		_stat(const char*, struct stat*);
extern int		_unlink(const char*);
extern int		_utime(const char*, const struct utimbuf*);
extern int		_utimes(const char*, const struct timeval*);
extern ssize_t		_write(int, const void*, size_t);

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

#if _win32_botch_access
#define sysaccess		_access
#else
#define sysaccess		access
#endif
#if _win32_botch_alarm
#define sysalarm		_alarm
#else
#define sysalarm		alarm
#endif
#if _win32_botch_chmod
#define syschmod		_chmod
#else
#define syschmod		chmod
#endif
#if _win32_botch_copy
#define sysclose		_close
#else
#define sysclose		close
#endif
#if _win32_botch_execve || _lib_spawn_mode
#define sysexecve		_execve
#else
#define sysexecve		execve
#endif
#if CONVERT
#define sysgetuid		_getuid
#else
#define sysgetuid		getuid
#endif
#if _win32_botch_link
#define syslink			_link
#else
#define syslink			link
#endif
#if _win32_botch_open || _win32_botch_copy
#define sysopen			_open
#else
#define sysopen			open
#endif
#if _win32_botch_pathconf
#define syspathconf		_pathconf
#else
#define syspathconf		pathconf
#endif
#define sysread			_read
#if _win32_botch_rename
#define sysrename		_rename
#else
#define sysrename		rename
#endif
#if _lib_spawn_mode
#define sysspawnve		_spawnve
#else
#define sysspawnve		spawnve
#endif
#if _win32_botch_stat
#define sysstat			_stat
#else
#define sysstat			stat
#endif
#if _win32_botch_truncate
#define systruncate		_truncate
#else
#define systruncate		truncate
#endif
#if _win32_botch_unlink
#define sysunlink		_unlink
#else
#define sysunlink		unlink
#endif
#if _win32_botch_utime
#define sysutime		_utime
#define sysutimes		_utimes
#else
#define sysutime		utime
#define sysutimes		utimes
#endif
#if _win32_botch_copy
#define syswrite		_write
#else
#define syswrite		write
#endif

static char*
suffix(register const char* path)
{
	register const char*	s = path + strlen(path);
	register int		c;

	while (s > path)
		if ((c = *--s) == '.')
			return (char*)s + 1;
		else if (c == '/' || c == '\\')
			break;
	return 0;
}

static int
execrate(const char* path, char* buf, int size, int physical)
{
	char*	s;
	int	n;
	int	oerrno;

	if (suffix(path))
		return 0;
	oerrno = errno;
	if (physical || strlen(path) >= size || !(s = pathcanon(strcpy(buf, path), size, PATH_PHYSICAL|PATH_DOTDOT|PATH_EXISTS)))
		snprintf(buf, size, "%s.exe", path);
	else if (!suffix(buf) && ((buf + size) - s) >= 4)
		strcpy(s, ".exe");
	errno = oerrno;
	return 1;
}

/*
 * return 0 if path is magic, -1 otherwise
 * ux!=0 set to 1 if path is unix executable
 * ux!=0 also retains errno for -1 return
 */

static int
magic(const char* path, int* ux)
{
	int		fd;
	int		r;
	int		n;
	int		m;
	int		oerrno;
#if CONVERT
	unsigned char	buf[512];
#else
	unsigned char	buf[2];
#endif

	oerrno = errno;
	if ((fd = sysopen(path, O_RDONLY, 0)) >= 0)
	{
#if CONVERT
		if (ux)
			n = sizeof(buf);
		else
#endif
			n = 2;
		r = (m = sysread(fd, buf, n)) >= 2 && (buf[1] == 0x5a && (buf[0] == 0x4c || buf[0] == 0x4d) || ux && buf[0] == '#' && buf[1] == '!' && (*ux = 1) && !(ux = 0)) ? 0 : -1;
		sysclose(fd);
		if (ux)
		{
			if (r)
				oerrno = ENOEXEC;
			else if (m > 61 && (n = buf[60] | (buf[61]<<8) + 92) < (m - 1))
				*ux = (buf[n] | (buf[n+1]<<8)) == 3;
			else
				*ux = 0;
		}
	}
	else if (!ux)
		r = -1;
	else if (errno == ENOENT)
	{
		oerrno = errno;
		r = -1;
	}
	else
	{
		r = 0;
		*ux = 0;
	}
	errno = oerrno;
	return r;
}

#if _win32_botch_access

extern int
access(const char* path, int op)
{
	int	r;
	int	oerrno;
	char	buf[PATH_MAX];

	oerrno = errno;
	if ((r = sysaccess(path, op)) && errno == ENOENT && execrate(path, buf, sizeof(buf), 0))
	{
		errno = oerrno;
		r = sysaccess(buf, op);
	}
	return r;
}

#endif

#if _win32_botch_alarm

extern unsigned int
alarm(unsigned int s)
{
	unsigned int		n;
	unsigned int		r;

	static unsigned int	a;

	n = (unsigned int)time(NiL);
	if (a <= n)
		r = 0;
	else
		r = a - n;
	a = n + s - 1;
	(void)sysalarm(s);
	return r;
}

#endif

#if _win32_botch_chmod

extern int
chmod(const char* path, mode_t mode)
{
	int	r;
	int	oerrno;
	char	buf[PATH_MAX];

	if ((r = syschmod(path, mode)) && errno == ENOENT && execrate(path, buf, sizeof(buf), 0))
	{
		errno = oerrno;
		return syschmod(buf, mode);
	}
	if (!(r = syschmod(path, mode)) &&
	    (mode & (S_IXUSR|S_IXGRP|S_IXOTH)) &&
	    !suffix(path) &&
	    (strlen(path) + 4) < sizeof(buf))
	{
		oerrno = errno;
		if (!magic(path, NiL))
		{
			snprintf(buf, sizeof(buf), "%s.exe", path);
			sysrename(path, buf);
		}
		errno = oerrno;
	}
	return r;
}

#endif

#if _win32_botch_execve || _lib_spawn_mode

#if _lib_spawn_mode

/*
 * can anyone get const prototype args straight?
 */

#define execve		______execve
#define spawnve		______spawnve

#include <process.h>

#undef	execve
#undef	spawnve

#endif

#if CONVERT

/*
 * this intercept converts dos env vars to unix
 * we'd rather intercept main but can't twist cc to do it
 * getuid() gets ksh to do the right thing and
 * that's our main concern
 *
 *	DOSPATHVARS='a b c'	convert { a b c }
 */

static int		convertinit;

/*
 * convertvars[0] names the list of env var names
 * convertvars[i] are not converted
 */

static const char*	convertvars[] = { "DOSPATHVARS", "PATH" };

static int
convert(register const char* d, const char* s)
{
	register const char*	t;
	register const char*	v;
	int			i;

	for (i = 0; i < elementsof(convertvars); i++)
	{
		for (v = convertvars[i], t = s; *t && *t == *v; t++, v++);
		if (*t == '=' && *v == 0)
			return 0;
	}
	for (;;)
	{
		while (*d == ' ' || *d == '\t')
			d++;
		if (!*d)
			break;
		for (t = s; *t && *t == *d; d++, t++);
		if (*t == '=' && (*d == ' ' || *d == '\t' || *d == 0))
			return t - s + 1;
		while (*d && *d != ' ' && *d != '\t')
			d++;
	}
	return 0;
}

uid_t
getuid(void)
{
	register char*		d;
	register char*		s;
	register char*		t;
	register char**		e;
	int			n;
	int			m;

	if (!convertinit++ && (d = getenv(convertvars[0])))
		for (e = environ; s = *e; e++)
			if ((n = convert(d, s)) && (m = cygwin_win32_to_posix_path_list_buf_size(s + n)) > 0)
			{
				if (!(t = malloc(n + m + 1)))
					break;
				*e = t;
				memcpy(t, s, n);
				cygwin_win32_to_posix_path_list(s + n, t + n);
			}
	return sysgetuid();
}

#endif

#ifndef _P_OVERLAY
#define _P_OVERLAY	(-1)
#endif

#define DEBUG		1

static pid_t
runve(int mode, const char* path, char* const* argv, char* const* envv)
{
	register char*	s;
	register char**	p;
	register char**	v;

	void*		m1;
	void*		m2;
	pid_t		pid;
	int		oerrno;
	int		ux;
	int		n;
#if defined(_P_DETACH) && defined(_P_NOWAIT)
	int		pgrp;
#endif
#if CONVERT
	char*		d;
	char*		t;
	int		m;
#endif
	struct stat	st;
	char		buf[PATH_MAX];
	char		tmp[PATH_MAX];

#if DEBUG
	static int	trace;
#endif

#if defined(_P_DETACH) && defined(_P_NOWAIT)
	if (mode == _P_DETACH)
	{
		/*
		 * 2004-02-29 cygwin _P_DETACH is useless:
		 *	spawn*() returns 0 instead of the spawned pid
		 *	spawned { pgid sid } are the same as the parent
		 */

		mode = _P_NOWAIT;
		pgrp = 1;
	}
	else
		pgrp = 0;
#endif
	if (!envv)
		envv = (char* const*)environ;
	m1 = m2 = 0;
	oerrno = errno;
#if DEBUG
	if (!trace)
		trace = (s = getenv("_AST_exec_trace")) ? *s : 'n';
#endif
	if (execrate(path, buf, sizeof(buf), 0))
	{
		if (!sysstat(buf, &st))
			path = (const char*)buf;
		else
			errno = oerrno;
	}
	if (path != (const char*)buf && sysstat(path, &st))
		return -1;
	if (!S_ISREG(st.st_mode) || !(st.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)))
	{
		errno = EACCES;
		return -1;
	}
	if (magic(path, &ux))
	{
#if _CYGWIN_fork_works
		errno = ENOEXEC;
		return -1;
#else
		ux = 1;
		p = (char**)argv;
		while (*p++);
		if (!(v = (char**)malloc((p - (char**)argv + 2) * sizeof(char*))))
		{
			errno = EAGAIN;
			return -1;
		}
		m1 = v;
		p = v;
		*p++ = (char*)path;
		*p++ = (char*)path;
		path = (const char*)pathshell();
		if (*argv)
			argv++;
		while (*p++ = (char*)*argv++);
		argv = (char* const*)v;
#endif
	}

	/*
	 * the win32 dll search order is
	 *	(1) the directory of path
	 *	(2) .
	 *	(3) /c/(WINNT|WINDOWS)/system32 /c/(WINNT|WINDOWS)
	 *	(4) the directories on $PATH
	 * there are no cygwin dlls in (3), so if (1) and (2) fail
	 * to produce the required dlls its up to (4)
	 *
	 * the standard allows PATH to be anything once the path
	 * to an executable is determined; this code ensures that PATH
	 * contains /bin so that at least the cygwin dll, required
	 * by all cygwin executables, will be found
	 */

	if (p = (char**)envv)
	{
		n = 1;
		while (s = *p++)
			if (strneq(s, "PATH=", 5))
			{
				s += 5;
				do
				{
					s = pathcat(s, ':', NiL, "", tmp, sizeof(tmp));
					if (streq(tmp, "/usr/bin/") || streq(tmp, "/bin/"))
					{
						n = 0;
						break;
					}
				} while (s);
				if (n)
				{
					n = 0;
					snprintf(tmp, sizeof(tmp), "%s:/bin", *(p - 1));
					*(p - 1) = tmp;
				}
				break;
			}
		if (n)
		{
			n = p - (char**)envv + 1;
			p = (char**)envv;
			if (v = (char**)malloc(n * sizeof(char*)))
			{
				m2 = v;
				envv = (char* const*)v;
				*v++ = strcpy(tmp, "PATH=/bin");
				while (*v++ = *p++);
			}
		}
#if CONVERT
		if (!ux && (d = getenv(convertvars[0])))
			for (p = (char**)envv; s = *p; p++)
				if ((n = convert(d, s)) && (m = cygwin_posix_to_win32_path_list_buf_size(s + n)) > 0)
				{
					if (!(t = malloc(n + m + 1)))
						break;
					*p = t;
					memcpy(t, s, n);
					cygwin_posix_to_win32_path_list(s + n, t + n);
				}
#endif
	}

#if DEBUG
	if (trace == 'a' || trace == 'e')
	{
		sfprintf(sfstderr, "%s %s [", mode == _P_OVERLAY ? "_execve" : "_spawnve", path);
		for (n = 0; argv[n]; n++)
			sfprintf(sfstderr, " '%s'", argv[n]);
		if (trace == 'e')
		{
			sfprintf(sfstderr, " ] [");
			for (n = 0; envv[n]; n++)
				sfprintf(sfstderr, " '%s'", envv[n]);
		}
		sfprintf(sfstderr, " ]\n");
		sfsync(sfstderr);
	}
#endif
#if _lib_spawn_mode
	if (mode != _P_OVERLAY)
	{
		pid = sysspawnve(mode, path, argv, envv);
#if defined(_P_DETACH) && defined(_P_NOWAIT)
		if (pid > 0 && pgrp)
			setpgid(pid, 0);
#endif
	}
	else
#endif
	{
#if defined(_P_DETACH) && defined(_P_NOWAIT)
		if (pgrp)
			setpgid(0, 0);
#endif
		pid = sysexecve(path, argv, envv);
	}
	if (m1)
		free(m1);
	if (m2)
		free(m2);
	return pid;
}

#if _win32_botch_execve

extern pid_t
execve(const char* path, char* const* argv, char* const* envv)
{
	return runve(_P_OVERLAY, path, argv, envv);
}

#endif

#if _lib_spawn_mode

extern pid_t
spawnve(int mode, const char* path, char* const* argv, char* const* envv)
{
	return runve(mode, path, argv, envv);
}

#endif

#endif

#if _win32_botch_getpagesize

extern size_t
getpagesize(void)
{
	return 64 * 1024;
}

#endif

#if _win32_botch_link

extern int
link(const char* fp, const char* tp)
{
	int	r;
	int	oerrno;
	char	fb[PATH_MAX];
	char	tb[PATH_MAX];

	oerrno = errno;
	if ((r = syslink(fp, tp)) && errno == ENOENT && execrate(fp, fb, sizeof(fb), 1))
	{
		if (execrate(tp, tb, sizeof(tb), 1))
			tp = tb;
		errno = oerrno;
		r = syslink(fb, tp);
	}
	return r;
}

#endif

#if _win32_botch_open || _win32_botch_copy

#if _win32_botch_copy

/*
 * this should intercept the important cases
 * dup*() and exec*() fd's will not be intercepted
 */

typedef struct Exe_test_s
{
	int		test;
	ino_t		ino;
	char		path[PATH_MAX];
} Exe_test_t;

static Exe_test_t*	exe[16];

extern int
close(int fd)
{
	int		r;
	int		oerrno;
	struct stat	st;
	char		buf[PATH_MAX];

	if (fd >= 0 && fd < elementsof(exe) && exe[fd])
	{
		r = exe[fd]->test;
		exe[fd]->test = 0;
		if (r > 0 && !fstat(fd, &st) && st.st_ino == exe[fd]->ino)
		{
			if (r = sysclose(fd))
				return r;
			oerrno = errno;
			if (!stat(exe[fd]->path, &st) && st.st_ino == exe[fd]->ino)
			{
				snprintf(buf, sizeof(buf), "%s.exe", exe[fd]->path);
				sysrename(exe[fd]->path, buf);
			}
			errno = oerrno;
			return 0;
		}
	}
	return sysclose(fd);
}

extern ssize_t
write(int fd, const void* buf, size_t n)
{
	if (fd >= 0 && fd < elementsof(exe) && exe[fd] && exe[fd]->test < 0)
		exe[fd]->test = n >= 2 && ((unsigned char*)buf)[1] == 0x5a && (((unsigned char*)buf)[0] == 0x4c || ((unsigned char*)buf)[0] == 0x4d) && !lseek(fd, (off_t)0, SEEK_CUR);
	return syswrite(fd, buf, n);
}

#endif

extern int
open(const char* path, int flags, ...)
{
	int		fd;
	int		mode;
	int		oerrno;
	char		buf[PATH_MAX];
#if _win32_botch_copy
	struct stat	st;
#endif
	va_list		ap;

	va_start(ap, flags);
	mode = (flags & O_CREAT) ? va_arg(ap, int) : 0;
	oerrno = errno;
	fd = sysopen(path, flags, mode);
#if _win32_botch_open
	if (fd < 0 && errno == ENOENT && execrate(path, buf, sizeof(buf), 0))
	{
		errno = oerrno;
		fd = sysopen(buf, flags, mode);
	}
#endif
#if _win32_botch_copy
	if (fd >= 0 && fd < elementsof(exe) && strlen(path) < PATH_MAX &&
	    (flags & (O_CREAT|O_TRUNC)) == (O_CREAT|O_TRUNC) && (mode & 0111))
	{
		if (!suffix(path) && !fstat(fd, &st) && (exe[fd] || (exe[fd] = (Exe_test_t*)malloc(sizeof(Exe_test_t)))))
		{
			exe[fd]->test = -1;
			exe[fd]->ino = st.st_ino;
			strcpy(exe[fd]->path, path);
		}
		errno = oerrno;
	}
#endif
	va_end(ap);
	return fd;
}

#endif

#if _win32_botch_pathconf

extern long
pathconf(const char* path, int op)
{
	if (sysaccess(path, F_OK))
		return -1;
	return syspathconf(path, op);
}

#endif

#if _win32_botch_rename

extern int
rename(const char* fp, const char* tp)
{
	int	r;
	int	oerrno;
	char	fb[PATH_MAX];
	char	tb[PATH_MAX];

	oerrno = errno;
	if ((r = sysrename(fp, tp)) && errno == ENOENT && execrate(fp, fb, sizeof(fb), 1))
	{
		if (execrate(tp, tb, sizeof(tb), 1))
			tp = tb;
		errno = oerrno;
		r = sysrename(fb, tp);
	}
	return r;
}

#endif

#if _win32_botch_stat

extern int
stat(const char* path, struct stat* st)
{
	int	r;
	int	oerrno;
	char	buf[PATH_MAX];

	oerrno = errno;
	if ((r = sysstat(path, st)) && errno == ENOENT && execrate(path, buf, sizeof(buf), 0))
	{
		errno = oerrno;
		r = sysstat(buf, st);
	}
	return r;
}

#endif

#if _win32_botch_truncate

extern int
truncate(const char* path, off_t offset)
{
	int	r;
	int	oerrno;
	char	buf[PATH_MAX];

	oerrno = errno;
	if ((r = systruncate(path, offset)) && errno == ENOENT && execrate(path, buf, sizeof(buf), 0))
	{
		errno = oerrno;
		r = systruncate(buf, offset);
	}
	return r;
}

#endif

#if _win32_botch_unlink

extern int
unlink(const char* path)
{
	int		r;
	int		drive;
	int		mask;
	int		suffix;
	int		stop;
	int		oerrno;
	unsigned long	base;
	char		buf[PATH_MAX];
	char		tmp[MAX_PATH];

#define DELETED_DIR_1	7
#define DELETED_DIR_2	16

	static char	deleted[] = "%c:\\temp\\.deleted\\%08x.%03x";

	static int	count = 0;

#if __CYGWIN__

	DWORD		fattr = FILE_ATTRIBUTE_NORMAL|FILE_FLAG_DELETE_ON_CLOSE;
	DWORD		share = FILE_SHARE_DELETE;
	HANDLE		hp;
	struct stat	st;
	char		nat[MAX_PATH];

	oerrno = errno;
	if (lstat(path, &st) || !S_ISREG(st.st_mode))
		goto try_unlink;
	cygwin_conv_to_full_win32_path(path, nat);
	if (!strncasecmp(nat + 1, ":\\temp\\", 7))
		goto try_unlink;
	drive = nat[0];
	path = (const char*)nat;
	for (;;)
	{
		hp = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_DELETE_ON_CLOSE, NULL);
		if (hp != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hp);
			errno = oerrno;
			return 0;
		}
		if (GetLastError() != ERROR_FILE_NOT_FOUND)
			break;
		if (path == (const char*)buf || !execrate(path, buf, sizeof(buf), 1))
		{
			errno = ENOENT;
			return -1;
		}
		path = (const char*)buf;
	}
#else
	if (sysaccess(path, 0))
#if _win32_botch_access
	{
		if (errno != ENOENT || !execrate(path, buf, sizeof(buf), 1) || sysaccess(buf, 0))
			return -1;
		path = (const char*)buf;
	}
#else
		return -1;
#endif
	drive = 'C':
#endif

	/*
	 * rename to a `deleted' path just in case the file is open
	 * otherwise directory readers may choke on phantom entries
	 */

	base = ((getuid() & 0xffff) << 16) | (time(NiL) & 0xffff);
	suffix = (getpid() & 0xfff) + count++;
	snprintf(tmp, sizeof(tmp), deleted, drive, base, suffix);
	if (!sysrename(path, tmp))
	{
		path = (const char*)tmp;
		goto try_delete;
	}
	if (errno != ENOTDIR && errno != ENOENT)
		goto try_unlink;
	tmp[DELETED_DIR_2] = 0;
	if (sysaccess(tmp, 0))
	{
		mask = umask(0);
		tmp[DELETED_DIR_1] = 0;
		if (sysaccess(tmp, 0) && mkdir(tmp, S_IRWXU|S_IRWXG|S_IRWXO))
		{
			umask(mask);
			goto try_unlink;
		}
		tmp[DELETED_DIR_1] = '\\';
		r = mkdir(tmp, S_IRWXU|S_IRWXG|S_IRWXO);
		umask(mask);
		if (r)
			goto try_unlink;
		errno = 0;
	}
	tmp[DELETED_DIR_2] = '\\';
	if (!errno && !sysrename(path, tmp))
	{
		path = (const char*)tmp;
		goto try_delete;
	}
#if !__CYGWIN__
	if (errno == ENOENT)
	{
#if !_win32_botch_access
		if (execrate(path, buf, sizeof(buf), 1) && !sysrename(buf, tmp))
			path = (const char*)tmp;
#endif
		goto try_unlink;
	}
#endif
	stop = suffix;
	do
	{
		snprintf(tmp, sizeof(tmp), deleted, drive, base, suffix);
		if (!sysrename(path, tmp))
		{
			path = (const char*)tmp;
			goto try_delete;
		}
		if (++suffix > 0xfff)
			suffix = 0;
	} while (suffix != stop);
 try_delete:
#if __CYGWIN__
	hp = CreateFile(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (hp != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hp);
		errno = oerrno;
		return 0;
	}
#endif
 try_unlink:
	errno = oerrno;
	return sysunlink(path);
}

#endif

#if _win32_botch_utime

#if __CYGWIN__

/*
 * cygwin refuses to set st_ctime for some operations
 * this rejects that refusal
 */

static void
ctime_now(const char* path)
{
	HANDLE		hp;
	SYSTEMTIME	st;
	FILETIME	ct;
	WIN32_FIND_DATA	ff;
	struct stat	fs;
	int		oerrno;
	char		tmp[MAX_PATH];

	if (sysstat(path, &fs) || (fs.st_mode & S_IWUSR) || syschmod(path, (fs.st_mode | S_IWUSR) & S_IPERM))
		fs.st_mode = 0;
	cygwin_conv_to_win32_path(path, tmp);
	hp = CreateFile(tmp, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hp && hp != INVALID_HANDLE_VALUE)
	{
		GetSystemTime(&st);
		SystemTimeToFileTime(&st, &ct);
		SetFileTime(hp, &ct, 0, 0);
		CloseHandle(hp);
	}
	if (fs.st_mode)
		syschmod(path, fs.st_mode & S_IPERM);
	errno = oerrno;
}

#else

#define ctime_now(p)

#endif

extern int
utimes(const char* path, const struct timeval* ut)
{
	int	r;
	int	oerrno;
	char	buf[PATH_MAX];

	oerrno = errno;
	if ((r = sysutimes(path, ut)) && errno == ENOENT && execrate(path, buf, sizeof(buf), 0))
	{
		errno = oerrno;
		r = sysutimes(path = buf, ut);
	}
	if (!r)
		ctime_now(path);
	return r;
}

extern int
utime(const char* path, const struct utimbuf* ut)
{
	int	r;
	int	oerrno;
	char	buf[PATH_MAX];

	oerrno = errno;
	if ((r = sysutime(path, ut)) && errno == ENOENT && execrate(path, buf, sizeof(buf), 0))
	{
		errno = oerrno;
		r = sysutime(path = buf, ut);
	}
	if (!r)
		ctime_now(path);
	return r;
}

#endif

#endif

/*
 * some systems (sun) miss a few functions required by their
 * own bsd-like macros
 */

#if !_lib_bzero || defined(bzero)

#undef	bzero

void
bzero(void* b, size_t n)
{
	memset(b, 0, n);
}

#endif

#if !_lib_getpagesize || defined(getpagesize)

#ifndef OMITTED
#define OMITTED	1
#endif

#undef	getpagesize

#ifdef	_SC_PAGESIZE
#undef	_AST_PAGESIZE
#define _AST_PAGESIZE	(int)sysconf(_SC_PAGESIZE)
#else
#ifndef _AST_PAGESIZE
#define _AST_PAGESIZE	4096
#endif
#endif

int
getpagesize()
{
	return _AST_PAGESIZE;
}

#endif

#if __CYGWIN__ && defined(__IMPORT__) && defined(__EXPORT__)

#ifndef OMITTED
#define OMITTED	1
#endif

/*
 * a few _imp__FUNCTION symbols are needed to avoid
 * static link multiple definitions
 */

#ifndef strtod
__EXPORT__ double (*_imp__strtod)(const char*, char**) = strtod;
#endif

#endif

#ifndef OMITTED

NoN(omitted)

#endif
