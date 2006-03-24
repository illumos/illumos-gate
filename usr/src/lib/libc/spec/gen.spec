#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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

function	.div
arch		sparc
version		sparc=SYSVABI_1.3
end

function	.mul
arch		sparc
version		sparc=SYSVABI_1.3
end

function	.rem
arch		sparc
version		sparc=SYSVABI_1.3
end

function	_longjmp
declaration	void _longjmp(jmp_buf env, int val)
version		SUNW_1.1
end

function	_setjmp
declaration	int _setjmp(jmp_buf env)
version		SUNW_1.1
end

function	a64l
include		<stdlib.h>
declaration	long a64l(const char *s)
version		SUNW_0.7
end

function	abort
include		<stdlib.h>
declaration	void abort(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	abs
include		<stdlib.h>
declaration	int abs(int val)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	alphasort
include		<sys/types.h>, <dirent.h>
declaration	int alphasort(const struct dirent **d1, \
			      const struct dirent **d2);
version		SUNW_1.22
end

function	_alphasort
weak		alphasort
version		SUNW_1.22
end

function	ascftime
include		<time.h>
declaration	int ascftime(char *s, const char *format, const struct tm *timeptr)
version		SUNW_0.7
exception	$return == 0
end

function	asctime
include		<time.h>
declaration	char *asctime(const struct tm *tm)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	asctime_r
include		<time.h>
declaration	char *asctime_r(const struct tm *_RESTRICT_KYWD tm, \
			char *_RESTRICT_KYWD buf, int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	_assert
version		SUNW_0.7
end

function	__assert
weak		_assert
version		i386=SYSVABI_1.3 sparc=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_assert_c99
version		SUNWprivate_1.1
end

function	__assert_c99
weak		_assert_c99
version		SUNWprivate_1.1
end

function	atexit
include		<stdlib.h>
declaration	int atexit(void (*func)(void))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return != 0
end

function	atof
include		<stdlib.h>
declaration	double atof(const char *str)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ERANGE EINVAL
exception	errno != 0
end

function	atoi
include		<stdlib.h>
declaration	int atoi(const char *str)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ERANGE EINVAL
exception	errno != 0
end

function	atol
include		<stdlib.h>
declaration	long atol(const char *str)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ERANGE EINVAL
exception	errno != 0
end

function	basename
include		<libgen.h>
declaration	char *basename(char *path)
version		SUNW_1.1
end

function	bcmp
include		<strings.h>
declaration	int bcmp(const void *s1, const void *s2, size_t n)
version		SUNW_0.9
end

function	bcopy
include		<strings.h>
declaration	void bcopy(const void *s1, void *s2, size_t n)
version		SUNW_0.9
end

function	bsearch
include		<stdlib.h>
declaration	void *bsearch(const void *key, const void *base, size_t nel, \
			size_t size, int (*compar)(const void *, const void *))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == NULL
end

function	bzero
include		<strings.h>
declaration	void bzero(void *s, size_t n)
version		SUNW_0.9
end

function	calloc
include		<stdlib.h>, <alloca.h>
declaration	void *calloc(size_t nelem, size_t elsize)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ENOMEM EAGAIN
exception	$return == 0
binding		nodirect
end

function	catclose
include		<nl_types.h>
declaration	int catclose(nl_catd catd)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINTR
exception	$return == -1
end

function	_catclose
weak		catclose
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	catgets
include		<nl_types.h>
declaration	char *catgets(nl_catd catd, int set_num, int msg_num, \
			const char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINTR EINVAL ENOMSG
exception	$return == s
end

function	_catgets
weak		catgets
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	catopen
include		<nl_types.h>
declaration	nl_catd catopen(const char *name, int oflag)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EMFILE ENAMETOOLONG ENFILE ENOENT ENOMEM ENOTDIR
exception	$return == (nl_catd)-1
end

function	_catopen
weak		catopen
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	cfgetispeed
include		<termios.h>
declaration	speed_t cfgetispeed(const struct termios *termios_p)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_cfgetispeed
weak		cfgetispeed
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	cfgetospeed
include		<termios.h>
declaration	speed_t cfgetospeed(const struct termios *termios_p)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_cfgetospeed
weak		cfgetospeed
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	cfree
include		<stdlib.h>
declaration	void cfree(void *ptr, unsigned num, unsigned size);
version		SUNWprivate_1.1
binding		nodirect
end

function	cfsetispeed
include		<termios.h>
declaration	int cfsetispeed(struct termios *termios_p, speed_t speed)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL
exception	($return == -1)
end

function	_cfsetispeed
weak		cfsetispeed
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	cfsetospeed
include		<termios.h>
declaration	int cfsetospeed(struct termios *termios_p, speed_t speed)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL
exception	($return == -1)
end

function	_cfsetospeed
weak		cfsetospeed
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	cftime
include		<time.h>
declaration	int cftime(char *s, char *format, const time_t *clock)
version		SUNW_0.7
exception	$return == 0
end

function	clock
include		<time.h>
declaration	clock_t clock(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == -1
end

function	closedir
include		<sys/types.h>, <dirent.h>
declaration	int closedir(DIR *dirp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINTR
exception	$return == -1
end

function	_closedir
weak		closedir
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	closefrom
include		<stdlib.h>
declaration	void closefrom(int lowfd)
version		SUNW_1.21
end

function	_closefrom
weak		closefrom
version		SUNW_1.21
end

function	closelog
include		<syslog.h>
declaration	void closelog(void)
version		SUNW_0.7
end

function	confstr
include		<unistd.h>
declaration	size_t confstr(int name, char *buf, size_t len)
version		SUNW_0.8
errno		EINVAL
exception	$return == 0 || $return != len
end

function	crypt
include		<unistd.h>
declaration	char *crypt (const char *key, const char *salt)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ENOSYS EINVAL ELIBACC ENOMEM
exception	$return == 0
end

function	_crypt
weak		crypt
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	crypt_gensalt
include		<crypt.h>
declaration	char *crypt_gensalt (const char*, const struct passwd *)
version		SUNW_1.21.1
errno		EINVAL ELIBACC ENOMEM
exception	$return == 0
end

function	csetcol
include		<euc.h>
declaration	int csetcol(int codeset)
version		SUNW_0.7
end

function	csetlen
include		<euc.h>
declaration	int csetlen(int codeset)
version		SUNW_0.7
end

function	ctime
include		<time.h>
declaration	char *ctime(const time_t *clock)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	ctime_r
include		<time.h>
declaration	char *ctime_r(const time_t *clock, char *buf, int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	dbm_clearerr
include		<ndbm.h>
declaration	int dbm_clearerr(DBM *db)
version		SUNW_1.1
end

function	dbm_close
include		<ndbm.h>
declaration	void dbm_close(DBM *db)
version		SUNW_0.7
end

function	dbm_delete
include		<ndbm.h>
declaration	int dbm_delete(DBM *db, datum key)
version		SUNW_0.7
exception	$return < 0
end

function	dbm_error
include		<ndbm.h>
declaration	int dbm_error(DBM *db)
version		SUNW_1.1
end

function	dbm_fetch
include		<ndbm.h>
declaration	datum dbm_fetch(DBM *db, datum key)
version		SUNW_0.7
exception	($return.dptr == 0)
end

function	dbm_firstkey
include		<ndbm.h>
declaration	datum dbm_firstkey(DBM *db)
version		SUNW_0.7
exception	($return.dptr == NULL) && (dbm_error(db) != 0)
end

function	dbm_nextkey
include		<ndbm.h>
declaration	datum dbm_nextkey(DBM *db)
version		SUNW_0.7
exception	($return.dptr == NULL) && (dbm_error(db) != 0)
end

function	dbm_open
include		<ndbm.h>, <fcntl.h>
declaration	DBM *dbm_open(const char *file, int open_flags, \
			mode_t file_mode)
version		SUNW_0.7
exception	$return == NULL
end

function	dbm_store
include		<ndbm.h>
declaration	int dbm_store(DBM *db, datum key, datum content, \
			int store_mode)
version		SUNW_0.7
errno
exception	$return != 0
end

function	difftime
include		<time.h>
declaration	double difftime(time_t time1, time_t time0)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	directio
include		<sys/types.h>, <sys/fcntl.h>
declaration	int directio(int fildes, int advice)
version		SUNW_1.1
errno		EBADF ENOTTY EINVAL
exception	$return == -1
end

function	dirname
include		<libgen.h>
declaration	char *dirname(char *path)
version		SUNW_1.1
end

function	div
declaration	div_t div(int numer, int denom)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	dladdr
version		SUNW_1.22
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	_dladdr
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	dladdr1
version		SUNW_1.22
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	_dladdr1
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	dlamd64getunwind
version		SUNW_1.22
arch		amd64
filter		amd64=/usr/lib/amd64/ld.so.1
end

function	_dlamd64getunwind
version		SUNWprivate_1.1
arch		amd64
filter		amd64=/usr/lib/amd64/ld.so.1
end

function	dlclose
version		SUNW_1.22
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	_dlclose
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	dldump
version		SUNW_1.22
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	_dldump
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	dlerror
version		SUNW_1.22
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	_dlerror
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	dlinfo
version		SUNW_1.22
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	_dlinfo
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	dlmopen
version		SUNW_1.22
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	_dlmopen
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	dlopen
version		SUNW_1.22
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	_dlopen
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	dlsym
version		SUNW_1.22
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	_dlsym
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	drand48
include		<stdlib.h>
declaration	double drand48(void)
version		SUNW_0.7
end

function	dup2
include		<unistd.h>, <sys/resource.h>
declaration	int dup2(int fildes, int fildes2)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINTR EMFILE
exception	$return == -1
end

function	_dup2
weak		dup2
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	econvert
include		<floatingpoint.h>
declaration	char *econvert(double value, int ndigit, int *decpt, \
			int *sign, char *buf)
version		SUNW_0.7
exception	($return == 0)
end

function	ecvt
include		<floatingpoint.h>
declaration	char *ecvt(double value, int ndigit, \
			int *_RESTRICT_KYWD decpt, int *_RESTRICT_KYWD sign)
version		SUNW_0.7
exception	$return == 0
end

function	encrypt
include		<unistd.h>
declaration	void encrypt (char block[64], int edflag)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ENOSYS
end

function	_encrypt
weak		encrypt
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	endgrent
include		<grp.h>
declaration	void endgrent(void)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	endnetgrent
declaration	void endnetgrent(void)
version		SUNW_0.7
errno		ERANGE
end

function	endpwent
include		<pwd.h>
declaration	void endpwent(void)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	endspent
include		<shadow.h>
declaration	void endspent(void)
version		SUNW_0.7
end

function	endusershell
declaration	void endusershell();
version		SUNW_1.1
end

function	endutent
include		<utmp.h>
declaration	void endutent(void)
version		SUNW_0.7
end

function	endutxent
include		<utmpx.h>
declaration	void endutxent(void)
version		SUNW_0.7
end

function	erand48
include		<stdlib.h>
declaration	double erand48(unsigned short xsubi[3])
version		SUNW_0.7
end

function	euccol
include		<euc.h>
declaration	int euccol(const unsigned char *s)
version		SUNW_0.7
end

function	euclen
include		<euc.h>
declaration	int euclen(const unsigned char *s)
version		SUNW_0.7
end

function	eucscol
include		<euc.h>
declaration	int eucscol(const unsigned      char *str)
version		SUNW_0.7
end

function	execl
include		<unistd.h>
declaration	int execl(const char *path, const char *arg0, ...)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EAGAIN EFAULT EINTR ELOOP EMULTIHOP ENAMETOOLONG \
			ENOENT ENOEXEC ENOLINK ENOMEM ENOTDIR
exception	$return == -1
end

function	_execl
weak		execl
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	execle
include		<unistd.h>
declaration	int execle(const char *path,char **const arg0, ...)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EAGAIN EFAULT EINTR ELOOP EMULTIHOP ENAMETOOLONG \
			ENOENT ENOEXEC ENOLINK ENOMEM ENOTDIR
exception	$return == -1
end

function	_execle
weak		execle
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	execlp
include		<unistd.h>
declaration	int execlp(const char *file, const char *arg0, ...)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EAGAIN EFAULT EINTR ELOOP EMULTIHOP ENAMETOOLONG ENOENT \
			ENOEXEC ENOLINK ENOMEM ENOTDIR
exception	$return == -1
end

function	_execlp
weak		execlp
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	execv
include		<unistd.h>
declaration	int execv(const char *path, char *const *argv)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EAGAIN EFAULT EINTR ELOOP EMULTIHOP ENAMETOOLONG ENOENT \
			ENOEXEC ENOLINK ENOMEM ENOTDIR
exception	$return == -1
end

function	_execv
weak		execv
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	execve
include		<unistd.h>
declaration	int execve(const char *path, char *const *argv, \
			char *const *envp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EAGAIN EFAULT EINTR ELOOP EMULTIHOP ENAMETOOLONG ENOENT \
			ENOEXEC ENOLINK ENOMEM ENOTDIR
exception	$return == -1
end

function	_execve
weak		execve
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	execvp
include		<unistd.h>
declaration	int execvp(const char *file, char *const *argv)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EAGAIN EFAULT EINTR ELOOP EMULTIHOP ENAMETOOLONG ENOENT \
			ENOEXEC ENOLINK ENOMEM ENOTDIR
exception	$return == -1
end

function	_execvp
weak		execvp
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	fattach
declaration	int fattach(int fildes, const char *path)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EBADF EBUSY EINVAL ELOOP ENAMETOOLONG ENOENT \
			ENOTDIR EPERM
exception	$return == -1
end

function	_fattach
weak		fattach
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	fconvert
include		<floatingpoint.h>
declaration	char *fconvert(double value, int ndigit, int *decpt, \
			int *sign, char *buf)
version		SUNW_0.7
exception	($return == 0)
end

function	fcvt
include		<floatingpoint.h>
declaration	char *fcvt(double value, int ndigit, \
			int *_RESTRICT_KYWD decpt, int *_RESTRICT_KYWD sign)
version		SUNW_0.7
exception	$return == 0
end

function	fdetach
include		<stropts.h>
declaration	int fdetach(const char *path)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EPERM ENOTDIR ENOENT EINVAL ENAMETOOLONG ELOOP
exception	$return == -1
end

function	_fdetach
weak		fdetach
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	fdwalk
include		<stdlib.h>
declaration	int fdwalk(int (*func)(void *, int), void *cd)
version		SUNW_1.21
end

function	_fdwalk
weak		fdwalk
version		SUNW_1.21
end

function	ffs
include		<strings.h>
declaration	int ffs(const int i)
version		SUNW_0.7
end

function	fgetgrent
include		<grp.h>
declaration	struct group *fgetgrent(FILE *f)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	fgetgrent_r
include		<grp.h>
declaration	struct group *fgetgrent_r(FILE *f, struct group *grp, \
			char *buffer, int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	fgetpwent
include		<pwd.h>
declaration	struct passwd *fgetpwent(FILE *f)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	fgetpwent_r
include		<pwd.h>
declaration	struct passwd *fgetpwent_r(FILE *f, struct passwd *pwd, \
			char *buffer, int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	fgetspent
include		<shadow.h>
declaration	struct spwd *fgetspent(FILE *fp)
version		SUNW_0.7
exception	$return == 0
end

function	fgetspent_r
include		<shadow.h>
declaration	struct spwd *fgetspent_r(FILE *fp, struct spwd *result, \
			char *buffer, int buflen)
version		SUNW_0.7
exception	$return == 0
end

function	free
include		<stdlib.h>, <alloca.h>
declaration	void free(void *ptr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ENOMEM EAGAIN
binding		nodirect
end

function	frexp
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	ftime
include		<sys/timeb.h>
declaration	int ftime(struct timeb *tp)
version		SUNW_0.9
exception	$return == -1
end

function	ftok
include		<sys/ipc.h>
declaration	key_t ftok(const char *path, int id)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES ELOOP ENAMETOOLONG ENOENT ENOTDIR
exception	$return == -1
end

function	_ftok
weak		ftok
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	ftruncate
include		<unistd.h>
declaration	int ftruncate(int fildes, off_t length)
version		SUNW_0.7
errno		EINTR EINVAL EFBIG EIO EACCES EFAULT EISDIR ELOOP EMFILE \
			EMULTIHOP ENAMETOOLONG ENOENT ENFILE ENOTDIR ENOLINK \
			EROFS EAGAIN EBADF
exception	$return == -1
end

function	_ftruncate
weak		ftruncate
version		SUNWprivate_1.1
end

function	ftw
include		<ftw.h>
declaration	int ftw(const char *path, \
			int (*fn)(const char *, const struct stat *, int), \
			int depth)
version		SUNW_0.7
exception	$return == -1
end

function	_ftw
weak		ftw
version		SUNWprivate_1.1
end

function	gconvert
include		<floatingpoint.h>
declaration	char *gconvert(double value, int ndigit, int trailing, \
			char *buf)
version		SUNW_0.7
exception	($return == 0)
end

function	gcvt
include		<floatingpoint.h>
declaration	char *gcvt(double value, int ndigit, char *buf)
version		SUNW_0.7
exception	$return == 0
end

function	getcpuid
include		<sys/processor.h>
declaration	processorid_t getcpuid(void)
version		SUNW_1.21
end

function	_getcpuid
weak		getcpuid
version		SUNW_1.21
end

function	getcwd
include		<unistd.h>
declaration	char *getcwd(char *buf, size_t size)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EACCES EINVAL ERANGE
exception	$return == 0
end

function	_getcwd
weak		getcwd
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	getdate
declaration	struct tm *getdate(const char *string)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_getdate
weak		getdate
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	getdtablesize
include		<unistd.h>
declaration	int getdtablesize(void)
version		SUNW_0.9
end

function	getenv
include		<stdlib.h>
declaration	char *getenv(const char *name)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	getextmntent
include		<stdio.h>, <sys/mnttab.h>
declaration	int getextmntent(FILE *fp, struct extmnttab *mp, size_t len)
version		SUNW_1.20
exception	$return != 0
end

function	getgrent
include		<grp.h>
declaration	struct group *getgrent(void)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getgrent_r
include		<grp.h>
declaration	struct group *getgrent_r(struct group *grp, char *buffer, \
			int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getgrgid
include		<grp.h>
declaration	struct group *getgrgid(gid_t gid)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getgrgid_r
include		<grp.h>
declaration	struct group *getgrgid_r(gid_t gid, struct group *grp, \
			char *buffer, int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getgrnam
include		<grp.h>
declaration	struct group *getgrnam(const char *name)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getgrnam_r
include		<grp.h>
declaration	struct group *getgrnam_r(const char *name, struct group	*grp, \
			char *buffer, int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	gethomelgroup
include		<sys/processor.h>
declaration	lgrpid_t gethomelgroup(void)
version		SUNW_1.21
end

function	_gethomelgroup
weak		gethomelgroup
version		SUNW_1.21
end

function	gethostid
declaration	long gethostid(void)
version		SUNW_0.9
end

function	gethostname
include		<unistd.h>
declaration	int gethostname(char *name, int namelen)
version		SUNW_0.9
errno		EPERM EFAULT
exception	$return == -1
end

function	gethrtime
include		<sys/time.h>
declaration	hrtime_t gethrtime(void)
version		SUNW_0.7
end

function	gethrvtime
include		<sys/time.h>
declaration	hrtime_t gethrvtime(void)
version		SUNW_0.7
end

function	getlogin
include		<unistd.h>, <limits.h>
declaration	char *getlogin(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EMFILE ENFILE ENXIO ERANGE
exception	$return == 0
end

function	getlogin_r
include		<unistd.h>, <limits.h>
declaration	char *getlogin_r(char *name, int namelen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EMFILE ENFILE ENXIO ERANGE
exception	$return == 0
end

function	getmntany
include		<stdio.h>, <sys/mnttab.h>
declaration	int getmntany(FILE *fp, struct mnttab *mp, struct mnttab *mpref)
version		SUNW_0.7
exception	$return != 0
end

function	getmntent
include		<stdio.h>, <sys/mnttab.h>
declaration	int getmntent(FILE *fp, struct mnttab *mp)
version		SUNW_0.7
exception	$return != 0
end

function	getnetgrent
declaration	int getnetgrent(char **machinep, char **userp, char **domainp)
version		SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	getnetgrent_r
declaration	int getnetgrent_r(char **machinep, char **userp, \
			char **domainp, char *buffer, int buflen)
version		SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	getopt
include		<stdlib.h>
declaration	int getopt(int argc, char *const *argv, const char *optstring)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == -1
end

function	_getopt
weak		getopt
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	getopt_clip
include		<getopt.h>
declaration	int getopt_clip(int argc, char *const *argv, \
				const char *optstring, \
				const struct option *long_options, \
				int *long_index)
version		SUNW_1.22
exception	$return == -1
end

function	_getopt_clip
weak		getopt_clip
version		SUNW_1.22
end

function	getopt_long
include		<getopt.h>
declaration	int getopt_long(int argc, char *const *argv, \
				const char *optstring, \
				const struct option *long_options, \
				int *long_index)
version		SUNW_1.22
exception	$return == -1
end

function	_getopt_long
weak		getopt_long
version		SUNW_1.22
end


function	getopt_long_only
include		<getopt.h>
declaration	int getopt_long_only(int argc, char *const *argv, \
				const char *optstring, \
				const struct option *long_options, \
				int *long_index)
version		SUNW_1.22
exception	$return == -1
end

function	_getopt_long_only
weak		getopt_long_only
version		SUNW_1.22
end

function	getpagesize
include		<unistd.h>
declaration	int getpagesize(void)
version		SUNW_0.9
end

function	getpriority
include		<sys/resource.h>
declaration	int getpriority(int which, id_t who)
version		SUNW_0.9
errno		ESRCH EINVAL EPERM EACCES
exception	$return == -1
end

function	getpw
include		<stdlib.h>
declaration	int getpw(uid_t uid, char *buf)
version		SUNW_0.7
exception	$return != 0
end

function	getpwent
include		<pwd.h>
declaration	struct passwd *getpwent(void)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getpwent_r
include		<pwd.h>
declaration	struct passwd *getpwent_r(struct passwd *pwd, \
			char *buffer, int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getpwnam
include		<pwd.h>
declaration	struct passwd *getpwnam(const char *name)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getpwnam_r
include		<pwd.h>
declaration	struct passwd *getpwnam_r(const char *name, \
			struct passwd *pwd, char *buffer, int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getpwuid
include		<pwd.h>
declaration	struct passwd *getpwuid(uid_t uid)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getpwuid_r
include		<pwd.h>
declaration	struct passwd *getpwuid_r(uid_t uid, struct passwd *pwd, \
			char *buffer, int buflen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	getrusage
include		<sys/resource.h>
declaration	int getrusage(int who, struct rusage *r_usage)
version		SUNW_0.9
errno		EFAULT EINVAL
exception	$return == -1
end

function	getspent
include		<shadow.h>
declaration	struct spwd *getspent(void)
version		SUNW_0.7
exception	$return == 0
end

function	getspent_r
include		<shadow.h>
declaration	struct spwd *getspent_r(struct spwd *result, \
			char *buffer, int buflen)
version		SUNW_0.7
exception	$return == 0
end

function	getspnam
include		<shadow.h>
declaration	struct spwd *getspnam(const char *name)
version		SUNW_0.7
exception	$return == 0
end

function	getspnam_r
include		<shadow.h>
declaration	struct spwd *getspnam_r(const char *name, \
			struct spwd *result, char *buffer, int buflen)
version		SUNW_0.7
exception	$return == 0
end

function	getsubopt
include		<stdlib.h>
declaration	int getsubopt(char **optionp, char *const *tokens, char **valuep)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == -1
end

function	_getsubopt
weak		getsubopt
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	gettimeofday
include		<sys/time.h>
declaration	int gettimeofday(struct timeval *tp, void *tzp)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL EPERM
exception	$return == -1
end

function	_gettimeofday
weak		gettimeofday
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	gettxt
include		<nl_types.h>
declaration	char *gettxt(const char *msgid, const char *dflt_str)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	_gettxt
weak		gettxt
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	getusershell
declaration	char *getusershell();
version		SUNW_1.1
exception	$return == 0
end

function	getutent
include		<utmp.h>
declaration	struct utmp *getutent(void)
version		SUNW_0.7
exception	$return == 0
end

function	getutid
include		<utmp.h>
declaration	struct utmp *getutid(const struct utmp *id)
version		SUNW_0.7
exception	$return == 0
end

function	getutline
include		<utmp.h>
declaration	struct utmp *getutline(const struct utmp *line)
version		SUNW_0.7
exception	$return == 0
end

function	getutmp
include		<utmpx.h>
declaration	void getutmp(const struct utmpx *utmpx, struct utmp *utmp)
version		SUNW_0.7
end

function	getutmpx
include		<utmpx.h>
declaration	void getutmpx(const struct utmp *utmp, struct utmpx *utmpx)
version		SUNW_0.7
end

function	getutxent
include		<utmpx.h>
declaration	struct utmpx *getutxent(void)
version		SUNW_0.7
exception	$return == 0
end

function	getutxid
include		<utmpx.h>
declaration	struct utmpx *getutxid(const struct utmpx *id)
version		SUNW_0.7
exception	$return == 0
end

function	getutxline
include		<utmpx.h>
declaration	struct utmpx *getutxline(const struct utmpx *line)
version		SUNW_0.7
exception	$return == 0
end

function	getvfsany
include		<stdio.h>, <sys/vfstab.h>
declaration	int getvfsany(FILE *fp, struct vfstab *vp, struct vfstab *vref)
version		SUNW_0.7
exception	$return != 0
end

function	getvfsent
include		<stdio.h>, <sys/vfstab.h>
declaration	int getvfsent(FILE *fp, struct vfstab *vp)
version		SUNW_0.7
exception	$return != 0
end

function	getvfsfile
include		<stdio.h>, <sys/vfstab.h>
declaration	int getvfsfile(FILE *fp, struct vfstab *vp, char *file)
version		SUNW_0.7
exception	$return != 0
end

function	getvfsspec
include		<stdio.h>, <sys/vfstab.h>
declaration	int getvfsspec(FILE *fp, struct vfstab *vp, char *spec)
version		SUNW_0.7
exception	$return != 0
end

function	getwd
include		<unistd.h>
declaration	char *getwd(char *path_name)
version		SUNW_0.9
exception	$return == 0
end

function	getwidth
include		<euc.h>, <getwidth.h>
declaration	void getwidth(eucwidth_t *ptr)
version		SUNW_0.7
end

function	gmtime
include		<time.h>
declaration	struct tm *gmtime(const time_t *clock)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	gmtime_r
include		<time.h>
declaration	struct tm *gmtime_r(const time_t *_RESTRICT_KYWD clock, \
			struct tm *_RESTRICT_KYWD res)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	grantpt
include		<stdlib.h>
declaration	int grantpt(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINVAL EACCES
exception	$return == 0
end

function	_grantpt
weak		grantpt
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	gsignal
include		<signal.h>
declaration	int gsignal(int sig)
version		SUNW_0.7
end

function	hasmntopt
include		<stdio.h>, <sys/mnttab.h>
declaration	char *hasmntopt(struct mnttab *mnt, char *opt)
version		SUNW_0.7
exception	$return == 0
end

function	hcreate
include		<search.h>
declaration	int hcreate (size_t mekments)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_hcreate
weak		hcreate
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	hdestroy
include		<search.h>
declaration	void hdestroy(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_hdestroy
weak		hdestroy
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	hsearch
include		<search.h>
declaration	ENTRY *hsearch(ENTRY item, ACTION action)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_hsearch
weak		hsearch
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	iconv
include		<iconv.h>
declaration	size_t iconv(iconv_t cd, const char **_RESTRICT_KYWD inbuf, \
			size_t *_RESTRICT_KYWD inbytesleft, \
			char **_RESTRICT_KYWD outbuf, \
			size_t *_RESTRICT_KYWD outbytesleft)
version		SUNW_0.8
errno		EILSEQ EINVAL EBADF E2BIG
exception	($return == -1)
end

function	iconv_close
include		<iconv.h>
declaration	int iconv_close(iconv_t cd)
version		SUNW_0.8
errno		EBADF
exception	($return == -1)
end

function	iconv_open
include		<iconv.h>
declaration	iconv_t iconv_open(const char *tocode, const char *fromcode)
version		SUNW_0.8
errno		EMFILE ENFILE ENOMEM EINVAL
exception	($return == (iconv_t)-1)
end

function	imaxabs
include		<inttypes.h>
declaration	intmax_t imaxabs(intmax_t j)
version		SUNW_1.22
end

function	_imaxabs_c89
include		<inttypes.h>
declaration	int32_t _imaxabs_c89(int32_t j)
arch		sparc i386
version		SUNWprivate_1.1
end

function	imaxdiv
include		<inttypes.h>
declaration	imaxdiv_t imaxdiv(intmax_t numer, intmax_t denom)
version		SUNW_1.22
end

function	_imaxdiv_c89
include		<inttypes.h>
declaration	div_t _imaxdiv_c89(int32_t numer, int32_t denom)
arch		sparc i386
version		SUNWprivate_1.1
end

function	index
include		<strings.h>
declaration	char *index(const char *s, int c)
version		SUNW_0.9
exception	$return == 0
end

function	initgroups
include		<grp.h>, <sys/types.h>
declaration	int initgroups(const char *name, gid_t basegid)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EPERM
exception	$return == -1
end

function	_initgroups
weak		initgroups
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	initstate
include		<stdlib.h>
declaration	char *initstate(unsigned int  seed,  char  *state, size_t size)
version		SUNW_0.9
exception	$return == 0
end

function	innetgr
declaration	int innetgr(const char *netgroup, const char *machine, \
			const char *user, const char *domain)
version		SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	insque
include		<search.h>
#manpage	void insque(struct qelem *elem, struct qelem *pred)
declaration	void insque(void *elem, void *pred)
version		SUNW_0.7
end

function	_insque
weak		insque
version		SUNW_0.7
end

function	isastream
include		<stropts.h>
declaration	int isastream(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF
exception	$return == -1
end

function	_isastream
weak		isastream
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	isatty
include		<unistd.h>
declaration	int isatty(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF ENOTTY
exception	$return == 0 && !unchanged(errno)
end

function	_isatty
weak		isatty
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	jrand48
include		<stdlib.h>
declaration	long jrand48(unsigned short xsubi[3])
version		SUNW_0.7
end

function	killpg
include		<signal.h>
declaration	int killpg(pid_t pgrp, int sig)
version		SUNW_0.9
errno		EINVAL EPERM ESRCH
exception	$return == -1
end

function	l64a
include		<stdlib.h>
declaration	char *l64a(long l)
version		SUNW_0.7
end

function	labs
include		<stdlib.h>
declaration	long labs(long lval)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	lckpwdf
include		<shadow.h>
declaration	int lckpwdf(void)
version		SUNW_0.7
exception	$return == -1
end

function	lcong48
include		<stdlib.h>
declaration	void lcong48(unsigned short param[7])
version		SUNW_0.7
end

function	_ld_libc
version		SUNWprivate_1.1
filter		sparc=/usr/lib/ld.so.1 i386=/usr/lib/ld.so.1 \
		sparcv9=/usr/lib/sparcv9/ld.so.1 amd64=/usr/lib/amd64/ld.so.1
end

function	ldexp
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	ldiv
include		<stdlib.h>
declaration	ldiv_t ldiv(long int numer, long int denom)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	lfind
include		<search.h>
declaration	void *lfind(const void *key, const void *base, size_t *nelp, \
			size_t width, \
			int (*compar)(const void *, const void *))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_lfind
weak		lfind
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	lfmt
include		<pfmt.h>
declaration	int lfmt(FILE *stream, long flags, char *format , ...)
version		SUNW_0.8
exception	$return == -1 || $return == -2
end

function	llabs
include		<stdlib.h>
declaration	long long llabs(long long llval)
version		SUNW_0.7
end

function	lldiv
include		<stdlib.h>
declaration	lldiv_t lldiv(long long numer, long long denom)
version		SUNW_0.7
end

function	localtime
include		<time.h>
declaration	struct tm *localtime(const time_t *clock)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	localtime_r
include		<time.h>
declaration	struct tm *localtime_r(const time_t *_RESTRICT_KYWD clock, \
			struct tm *_RESTRICT_KYWD res)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	longjmp
include		<setjmp.h>
declaration	void longjmp(jmp_buf env, int val)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	lrand48
include		<stdlib.h>
declaration	long lrand48(void)
version		SUNW_0.7
end

function	lsearch
include		<search.h>
declaration	void *lsearch(const void *key, void *base, size_t *nelp, \
			size_t width, \
			int (*compar) (const void *, const void *))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_lsearch
weak		lsearch
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	madvise
include		<sys/types.h>, <sys/mman.h>
declaration	int madvise(caddr_t addr, size_t len, int advice)
version		SUNW_0.7
errno		EINVAL EIO ENOMEM ESTALE
exception	($return == -1)
end

function	makecontext
include		<ucontext.h>
declaration	void makecontext(ucontext_t *ucp, void (*func)(), \
			int argc, ...)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EFAULT ENOMEM
end

function	_makecontext
weak		makecontext
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	__makecontext_v2
include		<ucontext.h>
declaration	void __makecontext_v2(ucontext_t *ucp, void (*func)(), \
			int argc, ...)
arch		sparc sparcv9
version		sparc=SUNW_1.21.2 sparcv9=SUNW_1.21.2
end

function	___makecontext_v2
weak		__makecontext_v2
arch		sparc sparcv9
version		sparc=SUNW_1.21.2 sparcv9=SUNW_1.21.2
end

function	malloc
include		<stdlib.h>, <alloca.h>
declaration	void *malloc(size_t size)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		ENOMEM EAGAIN
binding		nodirect
exception	$return == 0
end

function	memalign
include		<stdlib.h>, <alloca.h>
declaration	void *memalign(size_t alignment, size_t size)
version		SUNW_0.7
errno		ENOMEM EAGAIN
exception	$return == 0
binding		nodirect
end

function	memccpy
include		<string.h>
declaration	void *memccpy(void *_RESTRICT_KYWD s1, \
			const void *_RESTRICT_KYWD s2, int c, size_t n)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_memccpy
weak		memccpy
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	memchr
include		<string.h>
declaration	void *memchr(const void *s, int c, size_t n)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	memcmp
include		<string.h>
declaration	int memcmp(const void *s1, const void *s2, size_t n)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
auxiliary	sparc=/platform/$PLATFORM/lib/libc_psr.so.1 \
		sparcv9=/platform/$PLATFORM/lib/sparcv9/libc_psr.so.1
end

function	memcpy
include		<string.h>
declaration	void *memcpy(void *_RESTRICT_KYWD s1, \
			const void *_RESTRICT_KYWD s2, size_t n)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
auxiliary	sparc=/platform/$PLATFORM/lib/libc_psr.so.1 \
		sparcv9=/platform/$PLATFORM/lib/sparcv9/libc_psr.so.1
end

function	memmove
include		<string.h>
declaration	void *memmove(void *s1, const void *s2, size_t n)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
auxiliary	sparc=/platform/$PLATFORM/lib/libc_psr.so.1 \
		sparcv9=/platform/$PLATFORM/lib/sparcv9/libc_psr.so.1
end

function	memset
include		<string.h>
declaration	void *memset(void *s, int c, size_t n)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
auxiliary	sparc=/platform/$PLATFORM/lib/libc_psr.so.1 \
		sparcv9=/platform/$PLATFORM/lib/sparcv9/libc_psr.so.1
end

function	mkdtemp
include		<stdlib.h>
declaration	char *mkdtemp(char *template)
version		SUNW_1.22.1
exception	$return == 0
end

function	_mkdtemp
weak		mkdtemp
version		SUNW_1.22.1
end

function	mkfifo
include		<sys/types.h>, <sys/stat.h>
declaration	int mkfifo(const char *path, mode_t mode)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == -1
end

function	_mkfifo
weak		mkfifo
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function        mkstemp
include         <stdlib.h>
declaration     int mkstemp(char *template)
version         SUNW_0.7
exception       $return == -1
end

function        _mkstemp
weak            mkstemp
version         SUNW_0.7
end

function        mkstemps
include         <stdlib.h>
declaration     int mkstemps(char *template, int suffixlen)
version         SUNW_1.22.1
exception       $return == -1
end

function        _mkstemps
weak            mkstemps
version         SUNW_1.22.1
end

function	mktemp
include		<stdlib.h>
declaration	char *mktemp(char *template)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_mktemp
weak		mktemp
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	mktime
include		<time.h>
declaration	time_t mktime(struct tm *timeptr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == -1
end

function	mlock
include		<sys/types.h>
declaration	int mlock(caddr_t addr, size_t len)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EAGAIN EINVAL ENOMEM EPERM
exception	$return == -1
end

function	_mlock
weak		mlock
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	mlockall
include		<sys/mman.h>
declaration	int mlockall(int flags)
version		SUNW_0.7
errno		EAGAIN EINVAL EPERM
exception	$return == -1
end

function	modf
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	_modf
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	modff
version		SUNW_0.7
filter		libm.so.2
end

function	monitor
include		<mon.h>
declaration	void monitor(int (*lowpc)(void), int (*highpc)(void), \
			WORD *buffer, size_t bufsize, size_t nfunc)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_monitor
weak		monitor
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	mrand48
include		<stdlib.h>
declaration	long mrand48(void)
version		SUNW_0.7
end

function	msync
include		<sys/mman.h>
declaration	int msync(caddr_t addr, size_t len, int flags)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EBUSY EINVAL EIO ENOMEM EPERM
exception	$return == -1
end

function	_msync
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	munlock
include		<sys/types.h>
declaration	int munlock(caddr_t addr, size_t len)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EAGAIN EINVAL ENOMEM EPERM
exception	$return == -1
end

function	_munlock
weak		munlock
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	munlockall
include		<sys/mman.h>
declaration	int munlockall(void)
version		SUNW_0.7
errno		EAGAIN EINVAL EPERM
exception	$return == -1
end

function	mutex_destroy
include		<synch.h>
declaration	int mutex_destroy(mutex_t *mp)
version		SUNW_0.8
end

function	mutex_init
include		<synch.h>
declaration	int mutex_init(mutex_t *mp, int type, void *arg)
version		SUNW_0.8
end

function	mutex_lock
include		<synch.h>
declaration	int mutex_lock(mutex_t *mp)
version		SUNW_0.8
end

function	mutex_trylock
include		<synch.h>
declaration	int mutex_trylock(mutex_t *mp)
version		SUNW_0.8
end

function	mutex_unlock
include		<synch.h>
declaration	int mutex_unlock(mutex_t *mp)
version		SUNW_0.8
end

function	nftw
include		<ftw.h>
declaration	int nftw(const char *path, \
			int (*fn)(const char *, const struct stat *, \
				int, struct FTW*), \
			int depth, int flags)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == -1
end

function	_nftw
weak		nftw
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	nrand48
include		<stdlib.h>
declaration	long nrand48(unsigned short xsubi[3])
version		SUNW_0.7
end

function	opendir
include		<sys/types.h>, <dirent.h>
declaration	DIR *opendir(const char *dirname)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES ELOOP ENAMETOOLONG ENOENT ENOTDIR EMFILE
exception	$return == 0
end

function	_opendir
weak		opendir
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	fdopendir
include		<sys/types.h>, <dirent.h>
declaration	DIR *fdopendir(int fd)
version		SUNW_1.21
errno		EACCES ELOOP ENAMETOOLONG ENOENT ENOTDIR EMFILE
exception	$return == 0
end

function	_fdopendir
weak		fdopendir
version		SUNW_1.21
end

function	attropen
include		<sys/types.h>, <sys/stat.h>, <fcntl.h>
declaration	int attropen(const char *file, const char *attr, int oflag, ...)
version		SUNW_1.21
errno		EACCES EDQUOT EEXIST EINTR EFAULT EIO EISDIR ELOOP EMFILE \
			EMULTIHOP ENFILE ENOENT ENOLINK ENOSR ENOSPC ENOTDIR \
			ENXIO EOPNOTSUPP EOVERFLOW EROFS EAGAIN EINVAL \
			ENAMETOOLONG ENOMEM ETXTBSY
exception	$return == -1
end

function	_attropen
weak		attropen
version		SUNW_1.21
end

function	openlog
include		<syslog.h>
declaration	void openlog(const char *ident, int logopt, int facility)
version		SUNW_0.7
end

function	perror
include		<stdio.h>, <errno.h>
declaration	void perror(const char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	pfmt
include		<pfmt.h>
declaration	int pfmt(FILE *stream, long flags, char *format, ...)
version		SUNW_0.8
exception	$return == -1
end

function	plock
include		<sys/lock.h>
declaration	int plock(int op)
version		SUNW_0.7
errno		EAGAIN EINVAL EPERM
exception	$return == -1
end

function	posix_openpt
include		<stdlib.h>
include		<fcntl.h>
declaration	int posix_openpt(int oflag)
version		SUNW_1.22
errno		EMFILE ENFILE EINVAL ENOSR
exception	$return == -1
end

function	_posix_openpt
weak		posix_openpt
version		SUNWprivate_1.1
end

function	printstack
include		<ucontext.h>
declaration	int printstack(int fd)
version		SUNW_1.21
exception	$return == -1
end

function	_printstack
weak		printstack
version		SUNWprivate_1.1
end

function	psiginfo
include		<siginfo.h>
declaration	void psiginfo(siginfo_t *pinfo, char *s)
version		SUNW_0.7
end

function	psignal
include		<siginfo.h>
declaration	void psignal(int sig, const char *s)
version		SUNW_0.7
end

function	ptrace
include		<unistd.h>, <sys/types.h>
declaration	int ptrace(int request, pid_t pid, int addr, int data)
arch		sparc i386
version		SYSVABI_1.3
errno		EIO EPERM ESRCH
exception	$return == -1
end

function	_ptrace
weak		ptrace
arch		sparc i386
version 	SYSVABI_1.3
end

function	ptsname
include		<stdlib.h>
declaration	char *ptsname(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_ptsname
weak		ptsname
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	putenv
include		<stdlib.h>
declaration	int putenv(char *string)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ENOMEM
exception	$return != 0
end

function	_putenv
weak		putenv
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	putmsg
include		<stropts.h>
declaration	int putmsg(int fildes, const struct strbuf *ctlptr, \
			const struct strbuf *dataptr, int flags)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EAGAIN EBADF EFAULT EINTR EINVAL ENOSR ENOSTR ENXIO EPIPE ERANGE
exception	$return == -1
end

function	_putmsg
weak		putmsg
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	putpmsg
include		<stropts.h>
declaration	int putpmsg(int fildes, const struct strbuf *ctlptr, \
			const struct strbuf *dataptr, int band, int flags)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EAGAIN EBADF EFAULT EINTR EINVAL ENOSR ENOSTR ENXIO EPIPE ERANGE
exception	$return == -1
end

function	_putpmsg
weak		putpmsg
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	putpwent
include		<pwd.h>
declaration	int putpwent(const struct passwd *p, FILE *f)
version		SUNW_0.7
exception	$return != 0
end

function	putspent
include		<shadow.h>
declaration	int putspent(const struct spwd *p, FILE *fp)
version		SUNW_0.7
exception	$return != 0
end

function	pututline
include		<utmp.h>
declaration	struct utmp *pututline(const struct utmp *utmp)
version		SUNW_0.7
exception	$return == 0
end

function	pututxline
include		<utmpx.h>
declaration	struct utmpx *pututxline(const struct utmpx *utmpx)
version		SUNW_0.7
exception	$return == 0
end

function	qeconvert
include		<floatingpoint.h>
declaration	char *qeconvert(quadruple *value, int ndigit, int *decpt, \
			int *sign, char *buf)
version		SUNW_0.7
exception	($return == 0)
end

function	qfconvert
include		<floatingpoint.h>
declaration	char *qfconvert(quadruple *value, int ndigit, int *decpt, \
			int *sign, char *buf)
version		SUNW_0.7
exception	($return == 0)
end

function	qgconvert
include		<floatingpoint.h>
declaration	char *qgconvert(quadruple *value, int ndigit, int trailing, char *buf)
version		SUNW_0.7
exception	($return == 0)
end

function	qsort
include		<stdlib.h>
declaration	void qsort(void *base, size_t nel, size_t width, \
			int (*compar)(const void *, const void *))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	raise
include		<signal.h>
declaration	int raise(int sig)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == -1
end

function	rand
include		<stdlib.h>
declaration	int rand(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	rand_r
include		<stdlib.h>
declaration	int rand_r(unsigned int *seed)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	random
include		<stdlib.h>
declaration	long random(void)
version		SUNW_0.9
end

function	rctl_walk
include		<rctl.h>
declaration	int rctl_walk(int (*callback)(const char *rctlname, \
		    void *walk_data), void *init_data)
version		SUNW_1.21
end

function	rctlblk_get_global_action
include		<rctl.h>
declaration	uint_t rctlblk_get_global_action(rctlblk_t *);
version		SUNW_1.21
end

function	rctlblk_get_local_action
include		<rctl.h>
declaration	uint_t rctlblk_get_local_action(rctlblk_t *, int *);
version		SUNW_1.21
end

function	rctlblk_get_global_flags
include		<rctl.h>
declaration	uint_t rctlblk_get_global_flags(rctlblk_t *);
version		SUNW_1.21
end

function	rctlblk_get_local_flags
include		<rctl.h>
declaration	uint_t rctlblk_get_local_flags(rctlblk_t *);
version		SUNW_1.21
end

function	rctlblk_get_firing_time
include		<rctl.h>
declaration	hrtime_t rctlblk_get_firing_time(rctlblk_t *);
version		SUNW_1.21
end

function	rctlblk_get_privilege
include		<rctl.h>
declaration	rctl_priv_t rctlblk_get_privilege(rctlblk_t *);
version		SUNW_1.21
end

function	rctlblk_get_recipient_pid
include		<rctl.h>
declaration	id_t rctlblk_get_recipient_pid(rctlblk_t *);
version		SUNW_1.21
end

function	rctlblk_get_value
include		<rctl.h>
declaration	rctl_qty_t rctlblk_get_value(rctlblk_t *);
version		SUNW_1.21
end

function	rctlblk_get_enforced_value
include		<rctl.h>
declaration	rctl_qty_t rctlblk_get_enforced_value(rctlblk_t *);
version		SUNW_1.21
end

function	rctlblk_set_local_action
include		<rctl.h>
declaration	void rctlblk_set_local_action(rctlblk_t *, uint_t, int);
version		SUNW_1.21
end

function	rctlblk_set_local_flags
include		<rctl.h>
declaration	void rctlblk_set_local_flags(rctlblk_t *, uint_t);
version		SUNW_1.21
end

function	rctlblk_set_privilege
include		<rctl.h>
declaration	void rctlblk_set_privilege(rctlblk_t *, rctl_priv_t);
version		SUNW_1.21
end

function	rctlblk_set_recipient_pid
include		<rctl.h>
declaration	void rctlblk_set_recipient_pid(rctlblk_t *, id_t);
version		SUNW_1.22
end

function	rctlblk_set_value
include		<rctl.h>
declaration	void rctlblk_set_value(rctlblk_t *, rctl_qty_t);
version		SUNW_1.21
end

function	rctlblk_size
include		<rctl.h>
declaration	size_t rctlblk_size(void);
version		SUNW_1.21
end

function	readdir
include		<sys/types.h>, <dirent.h>
declaration	struct dirent *readdir(DIR *dirp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EOVERFLOW EBADF ENOENT
exception	$return == 0
end

function	_readdir
weak		readdir
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

# NOTE: The declarations of the various versions of readdir_r()
# in <dirent.h> are hopelessly convoluted, so we can't declare
# its arguments and return value here.
function	readdir_r
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_readdir_r
weak		readdir_r
version		SUNWprivate_1.1
end

function	realloc
include		<stdlib.h>, <alloca.h>
declaration	void *realloc(void *ptr, size_t size)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		ENOMEM EAGAIN
exception	$return == 0
binding		nodirect
end

function	realpath
include		<stdlib.h>
declaration	char *realpath(const char *_RESTRICT_KYWD file_name, \
			char *_RESTRICT_KYWD resolved_name)
version		SUNW_0.7
errno		EACCES EINVAL EIO ELOOP ENAMETOOLONG ENOENT ENOTDIR ENOMEM
exception	$return == 0
end

function	reboot
include		<sys/reboot.h>
declaration	int reboot(int howto, char *bootargs)
version		SUNW_0.9
errno		EPERM
exception	$return == -1
end

function	regcmp
# NOTE: varargs breaks adl
include		<libgen.h>
declaration	char *regcmp(const char *string1, ...)
version		SUNW_1.1
exception	$return == 0
end

function	remove
include		<stdio.h>
declaration	int remove(const char *path)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == -1
end

function	remque
include		<search.h>
#manpage	void remque(struct qelem *elem)
declaration	void remque(void *elem)
version		SUNW_0.7
end

function	_remque
weak		remque
version		SUNW_0.7
end

function	rename
include		<stdio.h>
declaration	int rename(const char *old, const char *new)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EACCES EBUSY EDQUOT EEXIST EINVAL EISDIR ELOOP ENAMETOOLONG \
			EMLINK ENOENT ENOSPC ENOTDIR EROFS EXDEV EIO
exception	$return == -1
end

function	resetmnttab
include		<stdio.h>, <sys/mnttab.h>
declaration	void resetmnttab(FILE *fp)
version		SUNW_1.20
end

function	rewind
include		<stdio.h>
declaration	void rewind(FILE *stream)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	rewinddir
include		<sys/types.h>, <dirent.h>
declaration	void rewinddir(DIR *dirp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_rewinddir
weak		rewinddir
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	rindex
include		<strings.h>
declaration	char *rindex(const char *s, int c)
version		SUNW_0.9
exception	$return == 0
end

function	rw_rdlock
include		<synch.h>
declaration	int rw_rdlock(rwlock_t *rwlp)
version		SUNW_0.8
errno		EINVAL EFAULT EBUSY
end

function	rw_tryrdlock
include		<synch.h>
declaration	int rw_tryrdlock(rwlock_t *rwlp)
version		SUNW_0.8
errno		EINVAL EFAULT EBUSY
end

function	rw_trywrlock
include		<synch.h>
declaration	int rw_trywrlock(rwlock_t *rwlp)
version		SUNW_0.8
errno		EINVAL EFAULT EBUSY
end

function	rw_unlock
include		<synch.h>
declaration	int rw_unlock(rwlock_t *rwlp)
version		SUNW_0.8
errno		EINVAL EFAULT EBUSY
end

function	rw_wrlock
include		<synch.h>
declaration	int rw_wrlock(rwlock_t *rwlp)
version		SUNW_0.8
errno		EINVAL EFAULT EBUSY
end

function	rwlock_destroy
include		<synch.h>
declaration	int rwlock_destroy(rwlock_t *rwlp)
version		SUNW_1.1
errno		EINVAL EFAULT EBUSY
end

function	rwlock_init
include		<synch.h>
declaration	int rwlock_init(rwlock_t *rwlp, int type, void * arg)
version		SUNW_0.8
errno		EINVAL EFAULT EBUSY
end

function	scandir
include		<sys/types.h>, <dirent.h>
declaration	int scandir(const char *dirname, struct dirent *(*namelist[]), \
			int (*select)(const struct dirent *), \
			int (*dcomp)(const struct dirent **, \
				     const struct dirent **));
version		SUNW_1.22
end

function	_scandir
weak		scandir
version		SUNW_1.22
end

function	seconvert
include		<floatingpoint.h>
declaration	char *seconvert(single *value, int ndigit, int *decpt, \
			int *sign, char *buf)
version		SUNW_0.7
exception	($return == 0)
end

function	seed48
include		<stdlib.h>
declaration	unsigned short *seed48(unsigned short seed16v[3])
version		SUNW_0.7
end

function	seekdir
include		<sys/types.h>, <dirent.h>
declaration	void seekdir(DIR *dirp, long int loc)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_seekdir
weak		seekdir
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	select
include		<sys/select.h>
declaration	int select(int nfds, \
			fd_set *_RESTRICT_KYWD readfds, \
			fd_set *_RESTRICT_KYWD writefds, \
			fd_set *_RESTRICT_KYWD errorfds, \
			struct timeval *_RESTRICT_KYWD timeout)
version		SUNW_0.7
errno		EBADF EINTR EINVAL
exception	$return == -1
end

function	pselect
include		<sys/select.h>
declaration	int pselect(int nfds, \
			fd_set *_RESTRICT_KYWD readfds, \
			fd_set *_RESTRICT_KYWD writefds, \
			fd_set *_RESTRICT_KYWD errorfds, \
			const struct timespec *_RESTRICT_KYWD timeout, \
			const sigset_t *_RESTRICT_KYWD sigmask)
version		SUNW_1.22
errno		EBADF EINTR EINVAL
exception	$return == -1
end

function	sema_destroy
include		<synch.h>
declaration	int sema_destroy(sema_t *sp)
version		SUNW_1.1
errno		EINVAL EFAULT EINTR EBUSY
end

function	sema_init
include		<synch.h>
declaration	int sema_init(sema_t *sp, unsigned int count, int type, void * arg)
version		SUNW_0.8
errno		EINVAL EFAULT EINTR EBUSY
end

function	sema_post
include		<synch.h>
declaration	int sema_post(sema_t *sp)
version		SUNW_0.8
errno		EINVAL EFAULT EINTR EBUSY
end

function	sema_trywait
include		<synch.h>
declaration	int sema_trywait(sema_t *sp)
version		SUNW_0.8
errno		EINVAL EFAULT EINTR EBUSY
end

function	sema_wait
include		<synch.h>
declaration	int sema_wait(sema_t *sp)
version		SUNW_0.8
errno		EINVAL EFAULT EINTR EBUSY
end

function	sema_timedwait
include		<synch.h>
declaration	int sema_timedwait(sema_t *sp, const timespec_t *abstime)
version		SUNW_1.22
errno		EINVAL EFAULT EINTR EBUSY ETIME
end

function	sema_reltimedwait
include		<synch.h>
declaration	int sema_reltimedwait(sema_t *sp, const timespec_t *reltime)
version		SUNW_1.22
errno		EINVAL EFAULT EINTR EBUSY ETIME
end

function	setcat
include		<pfmt.h>
declaration	const char *setcat(const char *catalog)
version		SUNW_0.8
exception	$return == 0
end

function	setenv
include		<stdlib.h>
declaration	int setenv(const char *envname, const char *envval, \
			int overwrite)
version		SUNW_1.22
errno		EINVAL ENOMEM
exception	$return != 0
end

function	_setenv # extends libc/spec/gen.spec setenv
weak		setenv
#Declaration	/* Unknown */
version		SUNWprivate_1.1
end

function	setgrent
include		<grp.h>
declaration	void setgrent(void)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sethostname
declaration	int sethostname(char *name, int namelen)
version		SUNW_0.9
errno		EFAULT EPERM
exception	$return == -1
end

function	setjmp
include		<setjmp.h>
declaration	int setjmp(jmp_buf env)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	setkey
include		<stdlib.h>
declaration	void setkey(const char *key)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ENOSYS
end

function	_setkey
weak		setkey
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	setlabel
include		<pfmt.h>
declaration	int setlabel(const char *label)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return != 0
end

function	setlogmask
include		<syslog.h>
declaration	int setlogmask(int maskpri)
version		SUNW_0.7
end

function	setnetgrent
declaration	void setnetgrent(const char *netgroup)
version		SUNW_0.7
errno		ERANGE
end

function	setpgid
include		<sys/types.h>, <unistd.h>
declaration	int setpgid(pid_t pid, pid_t pgid)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EINVAL EPERM ESRCH
exception	$return == -1
end

function	_setpgid
weak		setpgid
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	setpriority
include		<sys/resource.h>
declaration	int setpriority(int which, id_t who, int priority)
version		SUNW_0.9
errno		ESRCH EINVAL EPERM EACCES
exception	$return == -1
end

function	setpwent
include		<pwd.h>
declaration	void setpwent(void)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	setregid
include		<unistd.h>, <limits.h>
declaration	int setregid(gid_t rgid, gid_t egid)
version		SUNW_0.9
errno		EINVAL EPERM
exception	$return == -1
end

function	setreuid
include		<unistd.h>
declaration	int setreuid(uid_t ruid, uid_t euid)
version		SUNW_0.9
errno		EINVAL EPERM
exception	$return == -1
end

function	setspent
include		<shadow.h>
declaration	void setspent(void)
version		SUNW_0.7
end

function	setstate
include		<stdlib.h>
declaration	char *setstate(const char *state)
version		SUNW_0.9
exception	$return == 0
end

function	settimeofday
include		<sys/time.h>
declaration	int settimeofday(struct timeval *tp, void *tzp)
version		SUNW_0.7
errno		EINVAL EPERM
exception	$return == -1
end

function	setusershell
declaration	void setusershell();
version		SUNW_1.1
end

function	setutent
include		<utmp.h>
declaration	void setutent(void)
version		SUNW_0.7
end

function	setutxent
include		<utmpx.h>
declaration	void setutxent(void)
version		SUNW_0.7
end

function	sfconvert
include		<floatingpoint.h>
declaration	char *sfconvert(single *value, int ndigit, int *decpt, \
			int *sign, char *buf)
version		SUNW_0.7
exception	($return == 0)
end

function	sgconvert
include		<floatingpoint.h>
declaration	char *sgconvert(single *value, int ndigit, int trailing, \
			char *buf)
version		SUNW_0.7
exception	($return == 0)
end

function	sig2str
include		<signal.h>
declaration	int sig2str(int signum, char *str)
version		SUNW_0.7
exception	$return == -1
end

function	sigaddset
include		<signal.h>
declaration	int sigaddset(sigset_t *set, int signo)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL EFAULT
exception	$return == -1
end

function	_sigaddset
weak		sigaddset
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigdelset
include		<signal.h>
declaration	int sigdelset(sigset_t *set, int signo)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL EFAULT
exception	$return == -1
end

function	_sigdelset
weak		sigdelset
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigemptyset
include		<signal.h>
declaration	int sigemptyset(sigset_t *set)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL EFAULT
exception	$return == -1
end

function	_sigemptyset
weak		sigemptyset
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigfillset
include		<signal.h>
declaration	int sigfillset(sigset_t *set)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL EFAULT
exception	$return == -1
end

function	_sigfillset
weak		sigfillset
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sighold
include		<signal.h>
declaration	int sighold(int sig)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINTR EINVAL
exception	$return == -1
end

function	_sighold
weak		sighold
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigignore
include		<signal.h>
declaration	int sigignore(int sig)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINTR EINVAL
exception	$return == -1
end

function	_sigignore
weak		sigignore
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigismember
include		<signal.h>
declaration	int sigismember(const sigset_t *set, int signo)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL EFAULT
exception	$return == 0
end

function	_sigismember
weak		sigismember
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	siglongjmp
include		<setjmp.h>
declaration	void siglongjmp(sigjmp_buf env, int val)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	signal
include		<signal.h>
declaration	void (*signal (int sig, void (*disp)(int)))(int)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EINTR EINVAL
exception	$return == SIG_ERR
end

function	sigrelse
include		<signal.h>
declaration	int sigrelse(int sig)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINTR EINVAL
exception	$return == -1
end

function	_sigrelse
weak		sigrelse
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigsend
include		<signal.h>
declaration	int sigsend(idtype_t idtype, id_t id, int sig)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL EPERM ESRCH EFAULT
exception	$return == -1
end

function	_sigsend
weak		sigsend
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigsendset
include		<signal.h>
declaration	int sigsendset(const procset_t *psp, int sig)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL EPERM ESRCH EFAULT
exception	$return == -1
end

function	_sigsendset
weak		sigsendset
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigset
include		<signal.h>
declaration	void (*sigset (int sig, void (*disp)(int)))(int)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINTR EINVAL
exception	$return == SIG_ERR || $return == SIG_HOLD
end

function	_sigset
weak		sigset
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigsetjmp
include		<setjmp.h>
declaration	int sigsetjmp(sigjmp_buf env, int savemask)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_sigsetjmp
weak		sigsetjmp
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	sigstack
include		<signal.h>
declaration	int sigstack(struct sigstack *ss, struct sigstack *oss)
version		SUNW_1.1
errno		EPERM
exception	$return == -1
end

function	sleep
include		<unistd.h>
declaration	unsigned sleep(unsigned seconds)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	srand
include		<stdlib.h>
declaration	void srand(unsigned int seed)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	srand48
include		<stdlib.h>
declaration	void srand48(long seedval)
version		SUNW_0.7
end

function	srandom
include		<stdlib.h>
declaration	void srandom(unsigned int seed)
version		SUNW_0.9
end

function	ssignal
include		<signal.h>
declaration	int (*ssignal(int sig, int (*action)(int)))(int)
version		SUNW_0.7
exception	$return == (int (*)(int)) SIG_DFL
end

function	str2sig
include		<signal.h>
declaration	int str2sig(const char *str, int *signum)
version		SUNW_0.7
exception	$return == -1
end

function	_stack_grow
declaration	void *_stack_grow(void *)
version		SUNW_1.21.2
end

function	stack_getbounds
declaration	int stack_getbounds(stack_t *sp)
version		SUNW_1.21.2
end

function	_stack_getbounds
weak		stack_getbounds
version		SUNW_1.21.2
end

function	stack_setbounds
declaration	int stack_setbounds(const stack_t *sp)
version		SUNW_1.21.2
end

function	_stack_setbounds
weak		stack_setbounds
version		SUNW_1.21.2
end

function	stack_inbounds
declaration	int stack_inbounds(void *addr)
version		SUNW_1.21.2
end

function	_stack_inbounds
weak		stack_inbounds
version		SUNW_1.21.2
end

function	stack_violation
declaration	int stack_violation(int sig, const siginfo_t *sip, \
		const ucontext_t *ucp)
version		SUNW_1.21.2
end

function	_stack_violation
weak		stack_violation
version		SUNW_1.21.2
end

function	strcasecmp
include		<strings.h>
declaration	int strcasecmp(const char *s1, const char *s2)
version		SUNW_0.7
end

function	strcat
include		<string.h>
declaration	char *strcat(char *_RESTRICT_KYWD dst, \
			const char *_RESTRICT_KYWD src)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	strchr
include		<string.h>
declaration	char *strchr(const char *s, int c)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	strcmp
include		<string.h>
declaration	int strcmp(const char *s1, const char *s2)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	strcpy
include		<string.h>
declaration	char *strcpy(char *_RESTRICT_KYWD dst, \
			const char *_RESTRICT_KYWD src)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	strcspn
include		<string.h>
declaration	size_t strcspn(const char *s1, const char *s2)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	strdup
include		<string.h>
declaration	char *strdup(const char *s1)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ENOMEM
exception	$return == 0
end

function	_strdup
weak		strdup
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	strerror
include		<string.h>
declaration	char *strerror(int errnum)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
errno		EINVAL
end

function	strerror_r
include		<string.h>
declaration	int strerror_r(int errnum, char *strerrbuf, size_t buflen)
version		SUNW_1.22
exception	$return != 0
errno		ERANGE EINVAL
end

function	_strerror_r
weak		strerror_r
version		SUNWprivate_1.1
end

function	strftime
include		<time.h>
declaration	size_t strftime(char *_RESTRICT_KYWD s, size_t maxsize, \
			const char *_RESTRICT_KYWD format, \
			const struct tm *_RESTRICT_KYWD timeptr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	strlen
include		<string.h>
declaration	size_t strlen(const char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	strncasecmp
include		<strings.h>
declaration	int strncasecmp(const char *s1, const char *s2, size_t n)
version		SUNW_0.7
end

function	strncat
include		<string.h>
declaration	char *strncat(char *_RESTRICT_KYWD dst, \
			const char *_RESTRICT_KYWD src, size_t n)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	strlcat
include		<string.h>
declaration	size_t strlcat(char *dst, const char *src, size_t dstsize)
version		SUNW_1.19
end

function	strncmp
include		<string.h>
declaration	int strncmp(const char *s1, const char *s2, size_t n)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	strncpy
include		<string.h>
declaration	char *strncpy(char *_RESTRICT_KYWD dst, \
			const char *_RESTRICT_KYWD src, size_t n)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	strlcpy
include		<string.h>
declaration	size_t strlcpy(char *dst, const char *src, size_t dstsize)
version		SUNW_1.19
end

function	strpbrk
include		<string.h>
declaration	char *strpbrk(const char *s1, const char *s2)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	strrchr
include		<string.h>
declaration	char *strrchr(const char *s, int c)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	strsignal
include		<string.h>
declaration	char *strsignal(int sig)
version		SUNW_0.7
exception	$return == 0
end

function	strspn
include		<string.h>
declaration	size_t strspn(const char *s1, const char *s2)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	strstr
include		<string.h>
declaration	char *strstr(const char *s1, const char *s2)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
exception	$return == 0
end

function	strtod
include		<stdlib.h>
declaration	double strtod(const char *_RESTRICT_KYWD str, \
			char **_RESTRICT_KYWD endptr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		ERANGE EINVAL
exception	errno != 0
end

function	strtof
include		<stdlib.h>
declaration	float strtof(const char *_RESTRICT_KYWD str, \
			char **_RESTRICT_KYWD endptr)
version		SUNW_1.22
errno		ERANGE EINVAL
exception	errno != 0
end

function	strtoimax
include		<inttypes.h>
declaration	intmax_t strtoimax(const char *_RESTRICT_KYWD nptr, \
			char **_RESTRICT_KYWD endptr, int base)
version		SUNW_1.22
end

function	_strtoimax_c89
include		<inttypes.h>
declaration	int32_t _strtoimax_c89(const char *nptr, \
			char **endptr, int base)
arch		sparc i386
version		SUNWprivate_1.1
end

function	strtok
include		<string.h>
declaration	char *strtok(char *_RESTRICT_KYWD s1, \
			const char *_RESTRICT_KYWD s2)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	strtok_r
include		<string.h>
declaration	char *strtok_r(char *_RESTRICT_KYWD s1, \
			const char *_RESTRICT_KYWD s2, \
			char **_RESTRICT_KYWD lasts)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	strtol
include		<stdlib.h>
declaration	long strtol(const char *_RESTRICT_KYWD str, \
			char **_RESTRICT_KYWD endptr, int base)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		ERANGE EINVAL
exception	errno != 0
end

function	strtold
include		<stdlib.h>
declaration	long double strtold(const char *_RESTRICT_KYWD str, \
			char **_RESTRICT_KYWD endptr)
version		SUNW_1.22
errno		ERANGE EINVAL
exception	errno != 0
end

function	strtoll
include		<stdlib.h>
declaration	long long strtoll(const char *_RESTRICT_KYWD str, \
			char **_RESTRICT_KYWD endptr, int base)
version		SUNW_0.7
errno		ERANGE EINVAL
exception	errno != 0
end

function	strtoul
include		<stdlib.h>
declaration	unsigned long strtoul(const char *_RESTRICT_KYWD str, \
			char **_RESTRICT_KYWD endptr, int base)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EINVAL ERANGE
exception	errno != 0
end

function	strtoull
include		<stdlib.h>
declaration	unsigned long long strtoull(const char *_RESTRICT_KYWD str, \
			char **_RESTRICT_KYWD endptr, \
			int base)
version		SUNW_0.7
errno		EINVAL ERANGE
exception	errno != 0
end

function	strtoumax
include		<inttypes.h>
declaration	uintmax_t strtoumax(const char *_RESTRICT_KYWD nptr, \
			char **_RESTRICT_KYWD endptr, int base)
version		SUNW_1.22
end

function	_strtoumax_c89
include		<inttypes.h>
declaration	uint32_t _strtoumax_c89(const char *nptr, \
			char **endptr, int base)
arch		sparc i386
version		SUNWprivate_1.1
end

function	swab
include		<unistd.h>
declaration	void swab(const char *_RESTRICT_KYWD src, \
			char *_RESTRICT_KYWD dest, ssize_t nbytes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_swab
weak		swab
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	swapcontext
include		<ucontext.h>
declaration	int swapcontext(ucontext_t *_RESTRICT_KYWD oucp, \
			const ucontext_t *_RESTRICT_KYWD ucp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EFAULT ENOMEM
exception	$return == -1
end

function	_swapcontext
weak		swapcontext
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	swapctl
include		<sys/stat.h>, <sys/swap.h>
declaration	int swapctl(int cmd, void *arg)
version		SUNW_0.7
errno		EEXIST EFAULT EINVAL EISDIR ELOOP ENAMETOOLONG ENOENT ENOMEM \
			ENOSYS ENOTDIR EPERM EROFS
exception	$return == -1
end

function	sync_instruction_memory
declaration	void sync_instruction_memory(caddr_t addr, int len)
version		SUNW_1.1
end

function	sysconf
include		<unistd.h>
declaration	long sysconf(int name)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EINVAL
exception	$return == -1 && errno != 0
end

function	_sysconf
weak		sysconf
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	syslog
include		<syslog.h>
declaration	void syslog(int priority, const char *message, ...)
version		SUNW_0.7
end

function	_syslog
weak		syslog
version		SUNW_0.7
end

function	tcdrain
include		<termios.h>
declaration	int tcdrain(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINTR ENOTTY EIO
exception	($return == -1)
end

function	_tcdrain
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tcflow
include		<termios.h>
declaration	int tcflow(int fildes, int action)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINVAL ENOTTY EIO
exception	($return == -1)
end

function	_tcflow
weak		tcflow
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tcflush
include		<termios.h>
declaration	int tcflush(int fildes, int queue_selector)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINVAL ENOTTY EIO
exception	($return == -1)
end

function	_tcflush
weak		tcflush
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tcgetattr
include		<termios.h>
declaration	int tcgetattr(int fildes, struct termios *termios_p)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF ENOTTY
exception	($return == -1)
end

function	_tcgetattr
weak		tcgetattr
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tcgetpgrp
include		<sys/types.h>, <unistd.h>
declaration	pid_t tcgetpgrp(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF ENOTTY
exception	($return == -1)
end

function	_tcgetpgrp
weak		tcgetpgrp
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tcgetsid
include		<termios.h>
declaration	pid_t tcgetsid(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EACCES EBADF ENOTTY
exception	($return == -1)
end

function	_tcgetsid
weak		tcgetsid
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tcsendbreak
include		<termios.h>
declaration	int tcsendbreak(int fildes, int duration)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF ENOTTY EIO
exception	($return == -1)
end

function	_tcsendbreak
weak		tcsendbreak
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tcsetattr
include		<termios.h>
declaration	int tcsetattr(int fildes, int optional_actions, \
			const struct termios *termios_p)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINTR EINVAL ENOTTY EIO
exception	($return == -1)
end

function	_tcsetattr
weak		tcsetattr
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tcsetpgrp
include		<sys/types.h>, <unistd.h>
declaration	int tcsetpgrp(int fildes, pid_t pgid_id)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINVAL ENOTTY EPERM
exception	($return == -1)
end

function	_tcsetpgrp
weak		tcsetpgrp
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tdelete
include		<search.h>
declaration	void *tdelete(const void *_RESTRICT_KYWD key, \
			void **_RESTRICT_KYWD rootp, \
			int (*compar)(const void *, const void *))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_tdelete
weak		tdelete
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	telldir
include		<dirent.h>
declaration	long int telldir(DIR *dirp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_telldir
weak		telldir
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tfind
include		<search.h>
declaration	void *tfind(const void *key, void *const *rootp, \
			int (*compar)(const void *, const void *))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_tfind
weak		tfind
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	truncate
include		<unistd.h>
declaration	int truncate(const char *path, off_t length)
version		SUNW_0.7
errno		EINTR EINVAL EFBIG EIO EACCES EFAULT EISDIR ELOOP EMFILE \
			EMULTIHOP ENAMETOOLONG ENOENT ENFILE ENOTDIR ENOLINK \
			EROFS EAGAIN EBADF
exception	$return == -1
end

function	_truncate
weak		truncate
version		SUNWprivate_1.1
end

function	tsearch
include		<search.h>
declaration	void *tsearch(const void *key, void **rootp, \
			int (*compar)(const void *, const void *))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == 0
end

function	_tsearch
weak		tsearch
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	ttyname
include		<unistd.h>
declaration	char *ttyname(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		ERANGE EBADF ENOTTY
exception	$return == 0
end

function	ttyname_r
include		<unistd.h>, <limits.h>
declaration	char *ttyname_r(int fildes, char *name, int namelen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ERANGE EBADF ENOTTY
exception	$return == 0
end

function	ttyslot
include		<stdlib.h>
declaration	int ttyslot(void)
version		SUNW_0.7
exception	$return == -1
end

function	twalk
include		<search.h>
declaration	void twalk(const void *root, \
			void (*action)(const void  *, VISIT, int))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_twalk
weak		twalk
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	tzset
include		<time.h>
declaration	void tzset(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	_tzset
weak		tzset
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	ulckpwdf
include		<shadow.h>
declaration	int ulckpwdf(void)
version		SUNW_0.7
exception	$return == -1
end

function	unlockpt
include		<stdlib.h>
declaration	int unlockpt(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EBADF EINVAL
exception	$return == -1
end

function	_unlockpt
weak		unlockpt
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	unsetenv
include		<stdlib.h>
declaration	int unsetenv(const char *name)
version		SUNW_1.22
errno		ENOMEM
exception	$return != 0
end

function	_unsetenv # extends libc/spec/gen.spec unsetenv
weak		unsetenv
#Declaration	/* Unknown */
version		SUNWprivate_1.1
end

function	updwtmp
include		<utmpx.h>
declaration	void updwtmp(const char *wfile, struct utmp *utmp)
version		SUNW_0.7
end

function	updwtmpx
include		<utmpx.h>
declaration	void updwtmpx(const char *wfilex, struct utmpx *utmpx)
version		SUNW_0.7
end

function	usleep
include		<unistd.h>
declaration	int usleep(useconds_t useconds)
version		SUNW_0.9
errno		EINVAL
exception	$return == -1
end

function	_usleep
weak		usleep
version		SUNWprivate_1.1
end

function	utmpname
include		<utmp.h>
declaration	int utmpname(const char *file)
version		SUNW_0.7
exception	$return == 0
end

function	utmpxname
include		<utmpx.h>
declaration	int utmpxname(const char *file)
version		SUNW_0.7
exception	$return == 1
end

function	valloc
include		<stdlib.h>, <alloca.h>
declaration	void *valloc(size_t size)
version		SUNW_0.7
errno		ENOMEM EAGAIN
exception	$return == 0
binding		nodirect
end

function	vlfmt
include		<pfmt.h>, <stdarg.h>
declaration	int vlfmt(FILE *stream, long flags, const char *format, \
			va_list ap)
version		SUNW_0.8
exception	$return == -1 || $return == -2
end

function	vpfmt
include		<pfmt.h>, <stdarg.h>
declaration	int vpfmt(FILE *stream, long flags, const char *format, \
			va_list ap)
version		SUNW_0.8
exception	$return == -1
end

function	vsyslog
include		<syslog.h>
declaration	void vsyslog(int priority, const char *message, va_list ap)
version		SUNW_0.7
end

function	wait3
include		<sys/wait.h>, <sys/time.h>, <sys/resource.h>
declaration	pid_t wait3(int *statusp, int options, struct rusage *rusage)
version		SUNW_0.9
errno		ECHILD EFAULT EINTR EINVAL
exception	$return == -1
end

function	_wait3
weak		wait3
version		SUNWprivate_1.1
end

function	wait4
include		<sys/wait.h>, <sys/time.h>, <sys/resource.h>
declaration	pid_t wait4(pid_t pid, int *statusp, int options, \
			struct rusage *rusage)
version		SUNW_0.9
errno		ECHILD EFAULT EINTR EINVAL
exception	$return == -1
end

function	waitpid
include		<sys/types.h>, <sys/wait.h>
declaration	pid_t waitpid(pid_t pid, int *stat_loc, int options)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		ECHILD EINTR EINVAL
exception	$return == -1
end

function	_waitpid
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	walkcontext
include		<ucontext.h> <sys/types.h>
declaration	int walkcontext(const ucontext_t *uptr, \
			int (*func)(uintptr_t pc, int signo, \
			void * usrarg), void * usrarg);
version		sparc=SUNW_1.21 i386=SUNW_1.21 sparcv9=SUNW_1.22 \
		amd64=SUNW_1.22
exception	$return == -1
end

function	_walkcontext
weak		walkcontext
version		SUNWprivate_1.1
end

function	select_large_fdset
include		<sys/types.h>, <sys/time.h>, <sys/poll.h>, <sys/select.h>
declaration	int select_large_fdset(int nfds, \
			fd_set *_RESTRICT_KYWD readfds, \
			fd_set *_RESTRICT_KYWD writefds, \
			fd_set *_RESTRICT_KYWD errorfds, \
			struct timeval *_RESTRICT_KYWD timeout)
arch		sparc i386
version		SUNW_1.18
errno		EBADF EINTR EINVAL
exception	$return == -1
end

function	pselect_large_fdset
include		<sys/types.h>, <sys/time.h>, <sys/poll.h>, <sys/select.h>
declaration	int pselect_large_fdset(int nfds, \
			fd_set *_RESTRICT_KYWD readfds, \
			fd_set *_RESTRICT_KYWD writefds, \
			fd_set *_RESTRICT_KYWD errorfds, \
			const struct timespec *_RESTRICT_KYWD timeout, \
			const sigset_t *_RESTRICT_KYWD sigmask)
arch		sparc i386
version		SUNW_1.22
errno		EBADF EINTR EINVAL
exception	$return == -1
end

function	atoll
include		<stdlib.h>
declaration	long long atoll(const char *str)
version		SUNW_0.7
end

function	_atoll
weak		atoll
version		SUNWprivate_1.1
end

function	lltostr
include		<stdlib.h>
declaration	char *lltostr(long long value, char *endptr)
version		SUNW_0.7
end

function	_lltostr
weak		lltostr
version		SUNWprivate_1.1
end

function	ulltostr
include		<stdlib.h>
declaration	char *ulltostr(unsigned long long value, char *endptr)
version		SUNW_0.7
end

function	isaexec
include		<unistd.h>
declaration	int isaexec(const char *path, char *const argv[], \
			char *const envp[])
version		SUNW_1.18
end

function	priv_ineffect
include		<priv.h>
declaration	boolean_t priv_ineffect(const char *)
version		SUNW_1.22
exception	$return == B_FALSE
errno		ENOMEM EINVAL
end

function	_priv_ineffect
weak		priv_ineffect
version		SUNW_1.22
end

function	priv_set
include		<priv.h>
declaration	int priv_set(priv_op_t, priv_ptype_t, ...)
version		SUNW_1.22
exception	$return != 0
errno		ENOMEM EPERM EINVAL
end

function	_priv_set
weak		priv_set
version		SUNW_1.22
end

function	priv_str_to_set
include		<priv.h>
declaration	priv_set_t *priv_str_to_set(const char *, const char *, const char **)
version		SUNW_1.22
exception	$return == 0
errno		ENOMEM EINVAL
end

function	_priv_str_to_set
weak		priv_str_to_set
version		SUNW_1.22
end

function	__priv_set_to_str
include		<priv.h>
declaration	char *__priv_set_to_str(void *, const priv_set_t *, char, int)
version		SUNW_1.22
exception	$return == 0
errno		ENOSYS ENOMEM
end

function	priv_set_to_str
include		<priv.h>
declaration	char *priv_set_to_str(const priv_set_t *, char, int)
version		SUNW_1.22
exception	$return == 0
errno		ENOSYS ENOMEM
end

function	_priv_set_to_str
weak		priv_set_to_str
version		SUNW_1.22
end

function	__priv_free_info
include		<priv.h>
declaration	void __priv_free_info(void *)
version		SUNW_1.22
end

function	__priv_parse_info
include		<priv.h>
declaration	void *__priv_parse_info(priv_impl_info_t *)
version		SUNW_1.22
end

function	__priv_getsetbynum
include		<priv.h>
declaration	const char *__priv_getsetbynum(int, void *)
version		SUNW_1.22
exception	$return == 0
errno		EINVAL
end

function	__priv_getdata
version		SUNW_1.22
end

function	__priv_getbynum
include		<priv.h>
declaration	const char *__priv_getbynum(int, void *)
version		SUNW_1.22
exception	$return == 0
errno		EINVAL
end

function	priv_getbynum
include		<priv.h>
declaration	const char *priv_getbynum(int)
version		SUNW_1.22
exception	$return == 0
errno		EINVAL
end

function	_priv_getbynum
weak		priv_getbynum
version		SUNW_1.22
end

function	priv_getsetbynum
include		<priv.h>
declaration	const char *priv_getsetbynum(int)
version		SUNW_1.22
exception	$return == 0
errno		EINVAL
end

function	_priv_getsetbynum
weak		priv_getsetbynum
version		SUNW_1.22
end

function	__priv_getsetbyname
include		<priv.h>
declaration	int __priv_getsetbyname(const char *, void *)
version		SUNW_1.22
exception	$return == -1
errno		EINVAL
end

function	__priv_getbyname
include		<priv.h>
declaration	int __priv_getbyname(const char *, void *)
version		SUNW_1.22
exception	$return == -1
errno		EINVAL
end

function	priv_getbyname
include		<priv.h>
declaration	int priv_getbyname(const char *)
version		SUNW_1.22
exception	$return == -1
errno		EINVAL
end

function	_priv_getbyname
weak		priv_getbyname
version		SUNW_1.22
end

function	priv_getsetbyname
include		<priv.h>
declaration	int priv_getsetbyname(const char *)
version		SUNW_1.22
exception	$return == -1
errno		EINVAL
end

function	_priv_getsetbyname
weak		priv_getsetbyname
version		SUNW_1.22
end

function	priv_gettext
include		<priv.h>
declaration	char *priv_gettext(const char *)
version		SUNW_1.22
exception	$return == 0
end

function	_priv_gettext
weak		priv_gettext
version		SUNW_1.22
end

function	priv_allocset
include		<priv.h>
declaration	priv_set_t *priv_allocset(void)
version		SUNW_1.22
exception	$return == 0
errno		ENOMEM
end

function	_priv_allocset
weak		priv_allocset
version		SUNW_1.22
end

function	priv_freeset
include		<priv.h>
declaration	void priv_freeset(priv_set_t *)
version		SUNW_1.22
end

function	_priv_freeset
weak		priv_freeset
version		SUNW_1.22
end

function	priv_emptyset
include		<priv.h>
declaration	void priv_emptyset(priv_set_t *)
version		SUNW_1.22
end

function	_priv_emptyset
weak		priv_emptyset
version		SUNW_1.22
end

function	priv_fillset
include		<priv.h>
declaration	void priv_fillset(priv_set_t *)
version		SUNW_1.22
end

function	_priv_fillset
weak		priv_fillset
version		SUNW_1.22
end

function	priv_isemptyset
include		<priv.h>
declaration	boolean_t priv_isemptyset(const priv_set_t *)
version		SUNW_1.22
end

function	_priv_isemptyset
weak		priv_isemptyset
version		SUNW_1.22
end

function	priv_isfullset
include		<priv.h>
declaration	boolean_t priv_isfullset(const priv_set_t *)
version		SUNW_1.22
end

function	_priv_isfullset
weak		priv_isfullset
version		SUNW_1.22
end

function	priv_isequalset
include		<priv.h>
declaration	boolean_t priv_isequalset(const priv_set_t *, const priv_set_t *)
version		SUNW_1.22
end

function	_priv_isequalset
weak		priv_isequalset
version		SUNW_1.22
end

function	priv_issubset
include		<priv.h>
declaration	boolean_t priv_issubset(const priv_set_t *, const priv_set_t *)
version		SUNW_1.22
end

function	_priv_issubset
weak		priv_issubset
version		SUNW_1.22
end

function	priv_intersect
include		<priv.h>
declaration	void priv_intersect(const priv_set_t *, priv_set_t *)
version		SUNW_1.22
end

function	_priv_intersect
weak		priv_intersect
version		SUNW_1.22
end

function	priv_union
include		<priv.h>
declaration	void priv_union(const priv_set_t *, priv_set_t *)
version		SUNW_1.22
end

function	_priv_union
weak		priv_union
version		SUNW_1.22
end

function	priv_inverse
include		<priv.h>
declaration	void priv_inverse(priv_set_t *)
version		SUNW_1.22
end

function	_priv_inverse
weak		priv_inverse
version		SUNW_1.22
end

function	priv_addset
include		<priv.h>
declaration	int priv_addset(priv_set_t *, const char *)
version		SUNW_1.22
end

function	_priv_addset
weak		priv_addset
version		SUNW_1.22
end

function	priv_delset
include		<priv.h>
declaration	int priv_delset(priv_set_t *, const char *)
version		SUNW_1.22
end

function	_priv_delset
weak		priv_delset
version		SUNW_1.22
end

function	priv_copyset
include		<priv.h>
declaration	void priv_copyset(const priv_set_t *, priv_set_t *)
version		SUNW_1.22
end

function	_priv_copyset
weak		priv_copyset
version		SUNW_1.22
end

function	priv_ismember
include		<priv.h>
declaration	boolean_t priv_ismember(const priv_set_t *, const char *)
version		SUNW_1.22
end

function	_priv_ismember
weak		priv_ismember
version		SUNW_1.22
end

function	ucred_get
include		<ucred.h>
declaration	ucred_t *ucred_get(pid_t pid)
version		SUNW_1.22
end

function	_ucred_get
weak		ucred_get
version		SUNW_1.22
end

function	_ucred_alloc
include		<ucred.h>
declaration	ucred_t *_ucred_alloc(void)
version		SUNWprivate_1.1
end

function	ucred_free
include		<ucred.h>
declaration	void ucred_free(ucred_t *)
version		SUNW_1.22
end

function	_ucred_free
weak		ucred_free
version		SUNW_1.22
end

function	ucred_geteuid
include		<ucred.h>
declaration	uid_t ucred_geteuid(const ucred_t *)
version		SUNW_1.22
end

function	_ucred_geteuid
weak		ucred_geteuid
version		SUNW_1.22
end

function	ucred_getruid
include		<ucred.h>
declaration	uid_t ucred_getruid(const ucred_t *)
version		SUNW_1.22
end

function	_ucred_getruid
weak		ucred_getruid
version		SUNW_1.22
end

function	ucred_getsuid
include		<ucred.h>
declaration	uid_t ucred_getsuid(const ucred_t *)
version		SUNW_1.22
end

function	_ucred_getsuid
weak		ucred_getsuid
version		SUNW_1.22
end

function	ucred_getegid
include		<ucred.h>
declaration	gid_t ucred_getegid(const ucred_t *)
version		SUNW_1.22
end

function	_ucred_getegid
weak		ucred_getegid
version		SUNW_1.22
end

function	ucred_getrgid
include		<ucred.h>
declaration	gid_t ucred_getrgid(const ucred_t *)
version		SUNW_1.22
end

function	_ucred_getrgid
weak		ucred_getrgid
version		SUNW_1.22
end

function	ucred_getsgid
include		<ucred.h>
declaration	gid_t ucred_getsgid(const ucred_t *)
version		SUNW_1.22
end

function	_ucred_getsgid
weak		ucred_getsgid
version		SUNW_1.22
end

function	ucred_getgroups
include		<ucred.h>
declaration	int ucred_getgroups(const ucred_t *, const gid_t **)
version		SUNW_1.22
end

function	_ucred_getgroups
weak		ucred_getgroups
version		SUNW_1.22
end

function	ucred_getprivset
include		<ucred.h>
declaration	const priv_set_t *ucred_getprivset(const ucred_t *, priv_ptype_t)
version		SUNW_1.22
end

function	_ucred_getprivset
weak		ucred_getprivset
version		SUNW_1.22
end

function	ucred_getpid
include		<ucred.h>
declaration	pid_t ucred_getpid(const ucred_t *)
version		SUNW_1.22
end

function	_ucred_getpid
weak		ucred_getpid
version		SUNW_1.22
end

function	ucred_getprojid
include		<ucred.h>
declaration	projid_t ucred_getprojid(const ucred_t *)
version		SUNW_1.22
end

function	_ucred_getprojid
weak		ucred_getprojid
version		SUNW_1.22
end

function	ucred_getzoneid
include		<ucred.h>
declaration	zoneid_t ucred_getzoneid(const ucred_t *)
version		SUNW_1.22
end

function	_ucred_getzoneid
weak		ucred_getzoneid
version		SUNW_1.22
end

function	ucred_getlabel
include		<ucred.h>
declaration	bslabel_t *ucred_getlabel(const ucred_t *) 
version		SUNW_1.22.2
end

function	_ucred_getlabel
weak		ucred_getlabel
version		SUNW_1.22.2
end

function	ucred_getpflags
include		<ucred.h>
declaration	uint_t ucred_getpflags(const ucred_t *, uint_t)
version		SUNW_1.22
end

function	_ucred_getpflags
weak		ucred_getpflags
version		SUNW_1.22
end

function	zonept
include		<stdlib.h> <sys/zone.h>
declaration	int zonept(int filedes, zoneid_t zoneid)
version		SUNWprivate_1.1
errno		EBADF EINVAL
exception	$return == -1
end

function	getpeerucred
include		<ucred.h>
declaration	int getpeerucred(int, ucred_t **)
version		SUNW_1.22
exception	$return == -1
errno		EINVAL ENOTCONN EBADF EAGAIN ENOTSUP EFAULT
end

function	_getpeerucred
weak		getpeerucred
version		SUNW_1.22
end

function	port_create
include		<port.h>
declaration	int port_create()
version		SUNW_1.22
errno		EAGAIN EMFILE
end

function	_port_create
weak		port_create
version		SUNWprivate_1.1
end

function	port_associate
include		<port.h>
declaration	int port_associate(int port, int source, uintptr_t object, \
		int events, void *user)
version		SUNW_1.22
errno		ENOMEM EINVAL EBADF EBADFD EAGAIN
end

function	_port_associate
weak		port_associate
version		SUNWprivate_1.1
end

function	port_dissociate
include		<port.h>
declaration	int port_dissociate(int port, int type, uintptr_t object)
version		SUNW_1.22
errno		EINVAL EBADF EBADFD EACCES
end

function	_port_dissociate
weak		port_dissociate
version		SUNWprivate_1.1
end


function	port_get
include		<port.h>
declaration	int port_get(int port, port_event_t *pe, \
		struct timespec *timeout)
version		SUNW_1.22
errno		EFAULT EINVAL EBADF EBADFD EINTR ETIME
end

function	_port_get
weak		port_get
version		SUNWprivate_1.1
end

function	port_getn
include		<port.h>
declaration	int port_getn(int port, port_event_t list[], uint_t nent, \
		uint_t *nwait, struct timespec *timeout)
version		SUNW_1.22
errno		EFAULT EINVAL EBADF EBADFD EINTR ETIME
end

function	_port_getn
weak		port_getn
version		SUNWprivate_1.1
end

function	port_send
include		<port.h>
declaration	int port_send(int port, int events, void *user)
version		SUNW_1.22
errno		EAGAIN EBADF EBADFD ENOMEM
end

function	_port_send
weak		port_send
version		SUNWprivate_1.1
end

function	port_sendn
include		<port.h>
declaration	int port_sendn(int ports[], int errors[], uint_t nent, \
		int events, void *user)
version		SUNW_1.22
errno		EAGAIN EBADF EBADFD ENOMEM EINVAL EFAULT EIO
end

function	_port_sendn
weak		port_sendn
version		SUNWprivate_1.1
end

function	port_alert
include		<port.h>
declaration	int port_alert(int port, int flags, int events, void *user)
version		SUNW_1.22
errno		EBADF EBADFD EBUSY EINVAL
end

function	_port_alert
weak		port_alert
version		SUNWprivate_1.1
end

function	port_dispatch
include		<port.h>
declaration	int port_dispatch(int port, int flags, int source, int events, \
		uintptr_t object, void *user)
version		SUNWprivate_1.1
errno		EBADF EBADFD EINTR
end

function	_port_dispatch
weak		port_dispatch
version		SUNWprivate_1.1
end

function	ucred_size
include		<ucred.h>
declaration	size_t ucred_size(void)
version		SUNW_1.22
end

function	_ucred_size
weak		ucred_size
version		SUNW_1.22
end

function	ucred_getauid
include		<ucred.h>, <bsm/audit.h>
declaration	au_id_t ucred_getauid(const ucred_t *)
version		SUNWprivate_1.1
end

function	_ucred_getauid
weak		ucred_getauid
version		SUNWprivate_1.1
end

function	ucred_getasid
include		<ucred.h>, <bsm/audit.h>
declaration	au_asid_t ucred_getasid(const ucred_t *)
version		SUNWprivate_1.1
end

function	_ucred_getasid
weak		ucred_getasid
version		SUNWprivate_1.1
end

function	ucred_getamask
include		<ucred.h>, <bsm/audit.h>
declaration	const au_mask_t *ucred_getamask(const ucred_t *)
version		SUNWprivate_1.1
end

function	_ucred_getamask
weak		ucred_getamask
version		SUNWprivate_1.1
end

function	ucred_getatid
include		<ucred.h>, <bsm/audit.h>
declaration	const au_tid64_addr_t *ucred_getatid(const ucred_t *)
version		SUNWprivate_1.1
end

function	_ucred_getatid
weak		ucred_getatid
version		SUNWprivate_1.1
end
