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

#
# Copyright 2016 Gary Mills
# Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2015, Joyent, Inc.  All rights reserved.
# Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved.
# Copyright 2013 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Nexenta Systems, Inc.
#

LIBCDIR=	$(SRC)/lib/libc
LIB_PIC=	libc_pic.a
VERS=		.1
CPP=		/usr/lib/cpp
TARGET_ARCH=	sparc

# objects are grouped by source directory

# Symbol capabilities objects.
EXTPICS=			\
	$(LIBCDIR)/capabilities/sun4u/sparcv9/pics/symcap.o \
	$(LIBCDIR)/capabilities/sun4u-opl/sparcv9/pics/symcap.o \
	$(LIBCDIR)/capabilities/sun4u-us3-hwcap1/sparcv9/pics/symcap.o \
	$(LIBCDIR)/capabilities/sun4u-us3-hwcap2/sparcv9/pics/symcap.o \
	$(LIBCDIR)/capabilities/sun4v-hwcap1/sparcv9/pics/symcap.o \
	$(LIBCDIR)/capabilities/sun4v-hwcap2/sparcv9/pics/symcap.o

# local objects
STRETS=

CRTOBJS=			\
	__align_cpy_2.o		\
	__align_cpy_4.o		\
	__align_cpy_8.o		\
	_ftou.o			\
	cerror.o

DYNOBJS=

FPOBJS=				\
	_D_cplx_div.o		\
	_D_cplx_div_ix.o	\
	_D_cplx_div_rx.o	\
	_D_cplx_mul.o		\
	_F_cplx_div.o		\
	_F_cplx_div_ix.o	\
	_F_cplx_div_rx.o	\
	_F_cplx_mul.o		\
	_Q_add.o		\
	_Q_cmp.o		\
	_Q_cmpe.o		\
	_Q_cplx_div.o		\
	_Q_cplx_div_ix.o	\
	_Q_cplx_div_rx.o	\
	_Q_cplx_lr_div.o	\
	_Q_cplx_lr_div_ix.o	\
	_Q_cplx_lr_div_rx.o	\
	_Q_cplx_lr_mul.o	\
	_Q_cplx_mul.o		\
	_Q_div.o		\
	_Q_dtoq.o		\
	_Q_fcc.o		\
	_Q_itoq.o		\
	_Q_mul.o		\
	_Q_neg.o		\
	_Q_qtod.o		\
	_Q_qtoi.o		\
	_Q_qtos.o		\
	_Q_qtou.o		\
	_Q_scl.o		\
	_Q_sqrt.o		\
	_Q_stoq.o		\
	_Q_sub.o		\
	_Q_utoq.o

FPOBJS64=			\
	_Qp_qtox.o		\
	_Qp_qtoux.o		\
	_Qp_xtoq.o		\
	_Qp_uxtoq.o		\
	__dtoul.o		\
	__ftoul.o

FPASMOBJS=			\
	_Q_get_rp_rd.o		\
	__quad_mag64.o		\
	fpgetmask.o		\
	fpgetrnd.o		\
	fpgetsticky.o		\
	fpsetmask.o		\
	fpsetrnd.o		\
	fpsetsticky.o

$(__GNUC)FPASMOBJS +=		\
	__quad.o

ATOMICOBJS=			\
	atomic.o

CHACHAOBJS=			\
	chacha.o

XATTROBJS=			\
	xattr_common.o

COMOBJS=			\
	bcmp.o			\
	bcopy.o			\
	bsearch.o		\
	bzero.o			\
	memccpy.o		\
	qsort.o			\
	strtol.o		\
	strtoul.o		\
	strtoll.o		\
	strtoull.o

GENOBJS=			\
	_getsp.o		\
	_xregs_clrptr.o		\
	abs.o			\
	alloca.o		\
	arc4random.o		\
	arc4random_uniform.o	\
	ascii_strcasecmp.o	\
	byteorder.o		\
	cuexit.o		\
	ecvt.o			\
	endian.o		\
	getctxt.o		\
	lock.o			\
	makectxt.o		\
	memchr.o		\
	memcmp.o		\
	new_list.o		\
	setjmp.o		\
	siginfolst.o		\
	siglongjmp.o		\
	smt_pause.o		\
	sparc_data.o		\
	strchr.o		\
	strcmp.o		\
	strlcpy.o		\
	strncmp.o		\
	strncpy.o		\
	strnlen.o		\
	swapctxt.o		\
	sync_instruction_memory.o

# Preserved solely to ease maintenance of 32-bit and 64-bit library builds
# This macro should ALWAYS be empty; native APIs are already 'large file'.
COMSYSOBJS64=

SYSOBJS64=

COMSYSOBJS=			\
	__clock_timer.o		\
	__getloadavg.o		\
	__rusagesys.o		\
	__signotify.o		\
	__sigrt.o		\
	__time.o		\
	_lgrp_home_fast.o	\
	_lgrpsys.o		\
	_nfssys.o		\
	_portfs.o		\
	_pset.o			\
	_rpcsys.o		\
	_sigaction.o		\
	_so_accept.o		\
	_so_bind.o		\
	_so_connect.o		\
	_so_getpeername.o	\
	_so_getsockname.o	\
	_so_getsockopt.o	\
	_so_listen.o		\
	_so_recv.o		\
	_so_recvfrom.o		\
	_so_recvmsg.o		\
	_so_send.o		\
	_so_sendmsg.o		\
	_so_sendto.o		\
	_so_setsockopt.o	\
	_so_shutdown.o		\
	_so_socket.o		\
	_so_socketpair.o	\
	_sockconfig.o		\
	acct.o			\
	acl.o			\
	adjtime.o		\
	alarm.o			\
	brk.o			\
	chdir.o			\
	chroot.o		\
	cladm.o			\
	close.o			\
	execve.o		\
	exit.o			\
	facl.o			\
	fchdir.o		\
	fchroot.o		\
	fdsync.o		\
	fpathconf.o		\
	fstatfs.o		\
	fstatvfs.o		\
	getcpuid.o		\
	getdents.o		\
	getegid.o		\
	geteuid.o		\
	getgid.o		\
	getgroups.o		\
	gethrtime.o		\
	getitimer.o		\
	getmsg.o		\
	getpid.o		\
	getpmsg.o		\
	getppid.o		\
	getrandom.o		\
	getrlimit.o		\
	getuid.o		\
	gtty.o			\
	install_utrap.o		\
	ioctl.o			\
	kaio.o			\
	kill.o			\
	llseek.o		\
	lseek.o			\
	memcntl.o		\
	mincore.o		\
	mmap.o			\
	mmapobjsys.o		\
	modctl.o		\
	mount.o			\
	mprotect.o		\
	munmap.o		\
	nice.o			\
	ntp_adjtime.o		\
	ntp_gettime.o		\
	p_online.o		\
	pathconf.o		\
	pause.o			\
	pcsample.o		\
	pipe2.o			\
	pollsys.o		\
	pread.o			\
	preadv.o		\
	priocntlset.o		\
	processor_bind.o	\
	processor_info.o	\
	profil.o		\
	psecflagsset.o		\
	putmsg.o		\
	putpmsg.o		\
	pwrite.o		\
	pwritev.o		\
	read.o			\
	readv.o			\
	resolvepath.o		\
	seteguid.o		\
	setgid.o		\
	setgroups.o		\
	setitimer.o		\
	setreid.o		\
	setrlimit.o		\
	setuid.o		\
	sigaltstk.o		\
	sigprocmsk.o		\
	sigsendset.o		\
	sigsuspend.o		\
	statfs.o		\
	statvfs.o		\
	stty.o			\
	sync.o			\
	sysconfig.o		\
	sysfs.o			\
	sysinfo.o		\
	syslwp.o		\
	times.o			\
	ulimit.o		\
	umask.o			\
	umount2.o		\
	utssys.o		\
	uucopy.o		\
	vhangup.o		\
	waitid.o		\
	write.o			\
	writev.o		\
	yield.o

SYSOBJS=			\
	__clock_gettime.o	\
	__getcontext.o		\
	__uadmin.o		\
	_lwp_mutex_unlock.o	\
	_stack_grow.o		\
	door.o			\
	forkx.o			\
	forkallx.o		\
	gettimeofday.o		\
	sparc_utrap_install.o	\
	syscall.o		\
	tls_get_addr.o		\
	uadmin.o		\
	umount.o		\
	uname.o			\
	vforkx.o

# Preserved solely to ease maintenance of 32-bit and 64-bit library builds
# This macro should ALWAYS be empty; native APIs are already 'large file'.
PORTGEN64=

# objects from source under $(LIBCDIR)/port
PORTFP=				\
	__flt_decim.o		\
	__flt_rounds.o		\
	__tbl_10_b.o		\
	__tbl_10_h.o		\
	__tbl_10_s.o		\
	__tbl_2_b.o		\
	__tbl_2_h.o		\
	__tbl_2_s.o		\
	__tbl_fdq.o		\
	__tbl_tens.o		\
	__x_power.o		\
	_base_sup.o		\
	aconvert.o		\
	decimal_bin.o		\
	double_decim.o		\
	econvert.o		\
	fconvert.o		\
	file_decim.o		\
	finite.o		\
	fp_data.o		\
	func_decim.o		\
	gconvert.o		\
	hex_bin.o		\
	ieee_globals.o		\
	pack_float.o		\
	sigfpe.o		\
	string_decim.o

PORTGEN=			\
	_env_data.o		\
	_xftw.o			\
	a64l.o			\
	abort.o			\
	addsev.o		\
	ascii_strncasecmp.o	\
	assert.o		\
	atexit.o		\
	atfork.o		\
	atof.o			\
	atoi.o			\
	atol.o			\
	atoll.o			\
	attrat.o		\
	attropen.o		\
	basename.o		\
	calloc.o		\
	catgets.o		\
	catopen.o		\
	cfgetispeed.o		\
	cfgetospeed.o		\
	cfree.o			\
	cfsetispeed.o		\
	cfsetospeed.o		\
	cftime.o		\
	clock.o			\
	closedir.o		\
	closefrom.o		\
	confstr.o		\
	crypt.o			\
	csetlen.o		\
	ctime.o			\
	ctime_r.o		\
	daemon.o		\
	deflt.o			\
	directio.o		\
	dirname.o		\
	div.o			\
	drand48.o		\
	dup.o			\
	env_data.o		\
	err.o			\
	errno.o			\
	euclen.o		\
	event_port.o		\
	execvp.o		\
	explicit_bzero.o	\
	fattach.o		\
	fdetach.o		\
	fdopendir.o		\
	ffs.o			\
	flock.o			\
	fls.o			\
	fmtmsg.o		\
	freezero.o		\
	ftime.o			\
	ftok.o			\
	fts.o			\
	ftw.o			\
	gcvt.o			\
	get_nprocs.o		\
	getauxv.o		\
	getcwd.o		\
	getdate_err.o		\
	getdtblsize.o		\
	getentropy.o		\
	getenv.o		\
	getexecname.o		\
	getgrnam.o		\
	getgrnam_r.o		\
	gethostid.o		\
	gethostname.o		\
	gethz.o			\
	getisax.o		\
	getloadavg.o		\
	getlogin.o		\
	getmntent.o		\
	getnetgrent.o		\
	getopt.o		\
	getopt_long.o		\
	getpagesize.o		\
	getpw.o			\
	getpwnam.o		\
	getpwnam_r.o		\
	getrusage.o		\
	getspent.o		\
	getspent_r.o		\
	getsubopt.o		\
	gettxt.o		\
	getusershell.o		\
	getut.o			\
	getutx.o		\
	getvfsent.o		\
	getwd.o			\
	getwidth.o		\
	getxby_door.o		\
	gtxt.o			\
	hsearch.o		\
	iconv.o			\
	imaxabs.o		\
	imaxdiv.o		\
	index.o			\
	initgroups.o		\
	insque.o		\
	isaexec.o		\
	isastream.o		\
	isatty.o		\
	killpg.o		\
	klpdlib.o		\
	l64a.o			\
	lckpwdf.o		\
	lconstants.o		\
	ldivide.o		\
	lexp10.o		\
	lfind.o			\
	lfmt.o			\
	lfmt_log.o		\
	lldiv.o			\
	llog10.o		\
	lltostr.o		\
	lmath.o			\
	localtime.o		\
	lsearch.o		\
	madvise.o		\
	malloc.o		\
	memalign.o		\
	memmem.o		\
	mkdev.o			\
	mkdtemp.o		\
	mkfifo.o		\
	mkstemp.o		\
	mktemp.o		\
	mlock.o			\
	mlockall.o		\
	mon.o			\
	msync.o			\
	munlock.o		\
	munlockall.o		\
	ndbm.o			\
	nftw.o			\
	nlspath_checks.o	\
	nsparse.o		\
	nss_common.o		\
	nss_dbdefs.o		\
	nss_deffinder.o		\
	opendir.o		\
	opt_data.o		\
	perror.o		\
	pfmt.o			\
	pfmt_data.o		\
	pfmt_print.o		\
	pipe.o			\
	plock.o			\
	poll.o			\
	posix_fadvise.o		\
	posix_fallocate.o	\
	posix_madvise.o		\
	posix_memalign.o	\
	priocntl.o		\
	priv_str_xlate.o	\
	privlib.o		\
	psecflags.o		\
	psiginfo.o		\
	psignal.o		\
	pt.o			\
	putpwent.o		\
	putspent.o		\
	raise.o			\
	rand.o			\
	random.o		\
	rctlops.o		\
	readdir.o		\
	readdir_r.o		\
	reallocarray.o		\
	recallocarray.o		\
	realpath.o		\
	reboot.o		\
	regexpr.o		\
	remove.o		\
	rewinddir.o		\
	rindex.o		\
	scandir.o		\
	seekdir.o		\
	select.o		\
	setlabel.o		\
	setpriority.o		\
	settimeofday.o		\
	sh_locks.o		\
	sigflag.o		\
	siglist.o		\
	sigsend.o		\
	sigsetops.o		\
	ssignal.o		\
	stack.o			\
	stpcpy.o		\
	stpncpy.o		\
	str2sig.o		\
	strcase_charmap.o	\
	strcat.o		\
	strchrnul.o		\
	strcspn.o		\
	strdup.o		\
	strerror.o		\
	strlcat.o		\
	strncat.o		\
	strndup.o		\
	strpbrk.o		\
	strrchr.o		\
	strsep.o		\
	strsignal.o		\
	strspn.o		\
	strstr.o		\
	strtod.o		\
	strtoimax.o		\
	strtok.o		\
	strtok_r.o		\
	strtonum.o		\
	strtoumax.o		\
	swab.o			\
	swapctl.o		\
	sysconf.o		\
	syslog.o		\
	tcdrain.o		\
	tcflow.o		\
	tcflush.o		\
	tcgetattr.o		\
	tcgetpgrp.o		\
	tcgetsid.o		\
	tcsendbreak.o		\
	tcsetattr.o		\
	tcsetpgrp.o		\
	tell.o			\
	telldir.o		\
	tfind.o			\
	time_data.o		\
	time_gdata.o		\
	timespec_get.o		\
	tls_data.o		\
	truncate.o		\
	tsdalloc.o		\
	tsearch.o		\
	ttyname.o		\
	ttyslot.o		\
	ualarm.o		\
	ucred.o			\
	valloc.o		\
	vlfmt.o			\
	vpfmt.o			\
	waitpid.o		\
	walkstack.o		\
	wdata.o			\
	xgetwidth.o		\
	xpg4.o			\
	xpg6.o

PORTPRINT_W=			\
	doprnt_w.o

PORTPRINT=			\
	asprintf.o		\
	doprnt.o		\
	fprintf.o		\
	printf.o		\
	snprintf.o		\
	sprintf.o		\
	vfprintf.o		\
	vprintf.o		\
	vsnprintf.o		\
	vsprintf.o		\
	vwprintf.o		\
	wprintf.o

# Preserved solely to ease maintenance of 32-bit and 64-bit library builds
# This macro should ALWAYS be empty; native APIs are already 'large file'.
PORTSTDIO64=

PORTSTDIO_W=			\
	doscan_w.o

PORTSTDIO=			\
	__extensions.o		\
	_endopen.o		\
	_filbuf.o		\
	_findbuf.o		\
	_flsbuf.o		\
	_wrtchk.o		\
	clearerr.o		\
	ctermid.o		\
	ctermid_r.o		\
	cuserid.o		\
	data.o			\
	doscan.o		\
	fdopen.o		\
	feof.o			\
	ferror.o		\
	fgetc.o			\
	fgets.o			\
	fileno.o		\
	flockf.o		\
	flush.o			\
	fopen.o			\
	fpos.o			\
	fputc.o			\
	fputs.o			\
	fread.o			\
	fseek.o			\
	fseeko.o		\
	ftell.o			\
	ftello.o		\
	fwrite.o		\
	getc.o			\
	getchar.o		\
	getline.o		\
	getpass.o		\
	gets.o			\
	getw.o			\
	popen.o			\
	putc.o			\
	putchar.o		\
	puts.o			\
	putw.o			\
	rewind.o		\
	scanf.o			\
	setbuf.o		\
	setbuffer.o		\
	setvbuf.o		\
	system.o		\
	tempnam.o		\
	tmpfile.o		\
	tmpnam_r.o		\
	ungetc.o		\
	mse.o			\
	vscanf.o		\
	vwscanf.o		\
	wscanf.o

PORTI18N=			\
	getwchar.o		\
	putwchar.o		\
	putws.o			\
	strtows.o		\
	wcsnlen.o		\
	wcstoimax.o		\
	wcstol.o		\
	wcstoul.o		\
	wcswcs.o		\
	wscat.o			\
	wschr.o			\
	wscmp.o			\
	wscpy.o			\
	wscspn.o		\
	wsdup.o			\
	wslen.o			\
	wsncat.o		\
	wsncmp.o		\
	wsncpy.o		\
	wspbrk.o		\
	wsprintf.o		\
	wsrchr.o		\
	wsscanf.o		\
	wsspn.o			\
	wstod.o			\
	wstok.o			\
	wstol.o			\
	wstoll.o		\
	wsxfrm.o		\
	wmemchr.o		\
	wmemcmp.o		\
	wmemcpy.o		\
	wmemmove.o		\
	wmemset.o		\
	wcsstr.o		\
	gettext.o		\
	gettext_real.o		\
	gettext_util.o		\
	gettext_gnu.o		\
	plural_parser.o		\
	wdresolve.o		\
	_ctype.o		\
	isascii.o		\
	toascii.o

PORTI18N_COND=			\
	wcstol_longlong.o	\
	wcstoul_longlong.o

PORTLOCALE=			\
	big5.o			\
	btowc.o			\
	collate.o		\
	collcmp.o		\
	euc.o			\
	fnmatch.o		\
	fgetwc.o		\
	fgetws.o		\
	fix_grouping.o		\
	fputwc.o		\
	fputws.o		\
	fwide.o			\
	gb18030.o		\
	gb2312.o		\
	gbk.o			\
	getdate.o		\
	isdigit.o		\
	iswctype.o		\
	ldpart.o		\
	lmessages.o		\
	lnumeric.o		\
	lmonetary.o		\
	localeconv.o		\
	localeimpl.o		\
	mbftowc.o		\
	mblen.o			\
	mbrlen.o		\
	mbrtowc.o		\
	mbsinit.o		\
	mbsnrtowcs.o		\
	mbsrtowcs.o		\
	mbstowcs.o		\
	mbtowc.o		\
	mskanji.o		\
	nextwctype.o		\
	nl_langinfo.o		\
	none.o			\
	rune.o			\
	runetype.o		\
	setlocale.o		\
	setrunelocale.o		\
	strcasecmp.o		\
	strcasestr.o		\
	strcoll.o		\
	strfmon.o		\
	strftime.o		\
	strncasecmp.o		\
	strptime.o		\
	strxfrm.o		\
	table.o			\
	timelocal.o		\
	tolower.o		\
	towlower.o		\
	ungetwc.o		\
	utf8.o			\
	wcrtomb.o		\
	wcscasecmp.o		\
	wcscoll.o		\
	wcsftime.o		\
	wcsnrtombs.o		\
	wcsrtombs.o		\
	wcstombs.o		\
	wcswidth.o		\
	wcsxfrm.o		\
	wctob.o			\
	wctomb.o		\
	wctrans.o		\
	wctype.o		\
	wcwidth.o		\
	wscol.o

AIOOBJS=			\
	aio.o			\
	aio_alloc.o		\
	posix_aio.o

RTOBJS=				\
	clock_timer.o		\
	mqueue.o		\
	pos4obj.o		\
	sched.o			\
	sem.o			\
	shm.o			\
	sigev_thread.o

SECFLAGSOBJS=			\
	secflags.o

TPOOLOBJS=			\
	thread_pool.o

THREADSOBJS=			\
	alloc.o			\
	assfail.o		\
	c11_thr.o		\
	cancel.o		\
	door_calls.o		\
	tmem.o			\
	pthr_attr.o		\
	pthr_barrier.o		\
	pthr_cond.o		\
	pthr_mutex.o		\
	pthr_rwlock.o		\
	pthread.o		\
	rwlock.o		\
	scalls.o		\
	sema.o			\
	sigaction.o		\
	spawn.o			\
	synch.o			\
	tdb_agent.o		\
	thr.o			\
	thread_interface.o	\
	tls.o			\
	tsd.o

THREADSMACHOBJS=		\
	machdep.o

THREADSASMOBJS=			\
	asm_subr.o

UNICODEOBJS=			\
	u8_textprep.o		\
	uconv.o

UNWINDMACHOBJS=			\
	unwind.o

UNWINDASMOBJS=			\
	unwind_frame.o

# Preserved solely to ease maintenance of 32-bit and 64-bit library builds
# This macro should ALWAYS be empty; native APIs are already 'large file'.
PORTSYS64=

PORTSYS=			\
	_autofssys.o		\
	access.o		\
	acctctl.o		\
	bsd_signal.o		\
	chmod.o			\
	chown.o			\
	corectl.o		\
	eventfd.o		\
	epoll.o			\
	exacctsys.o		\
	execl.o			\
	execle.o		\
	execv.o			\
	fcntl.o			\
	getpagesizes.o		\
	getpeerucred.o		\
	inst_sync.o		\
	issetugid.o		\
	label.o			\
	link.o			\
	lockf.o			\
	lwp.o			\
	lwp_cond.o		\
	lwp_rwlock.o		\
	lwp_sigmask.o		\
	meminfosys.o		\
	mkdir.o			\
	mknod.o			\
	msgsys.o		\
	nfssys.o		\
	open.o			\
	pgrpsys.o		\
	posix_sigwait.o		\
	ppriv.o			\
	psetsys.o		\
	rctlsys.o		\
	readlink.o		\
	rename.o		\
	sbrk.o			\
	semsys.o		\
	set_errno.o		\
	sharefs.o		\
	shmsys.o		\
	sidsys.o		\
	siginterrupt.o		\
	signal.o		\
	signalfd.o		\
	sigpending.o		\
	sigstack.o		\
	stat.o			\
	symlink.o		\
	tasksys.o		\
	time.o			\
	time_util.o		\
	timerfd.o		\
	ucontext.o		\
	unlink.o		\
	ustat.o			\
	utimesys.o		\
	zone.o

PORTREGEX=			\
	glob.o			\
	regcmp.o		\
	regcomp.o		\
	regerror.o		\
	regex.o			\
	regexec.o		\
	regfree.o		\
	wordexp.o

VALUES=	values-Xa.o

MOSTOBJS=			\
	$(STRETS)		\
	$(CRTOBJS)		\
	$(DYNOBJS)		\
	$(FPOBJS)		\
	$(FPOBJS64)		\
	$(FPASMOBJS)		\
	$(ATOMICOBJS)		\
	$(CHACHAOBJS)		\
	$(XATTROBJS)		\
	$(COMOBJS)		\
	$(GENOBJS)		\
	$(PRFOBJS)		\
	$(PORTFP)		\
	$(PORTGEN)		\
	$(PORTGEN64)		\
	$(PORTI18N)		\
	$(PORTI18N_COND)	\
	$(PORTLOCALE)		\
	$(PORTPRINT)		\
	$(PORTPRINT_W)		\
	$(PORTREGEX)		\
	$(PORTSTDIO)		\
	$(PORTSTDIO64)		\
	$(PORTSTDIO_W)		\
	$(PORTSYS)		\
	$(PORTSYS64)		\
	$(AIOOBJS)		\
	$(RTOBJS)		\
	$(SECFLAGSOBJS)		\
	$(TPOOLOBJS)		\
	$(THREADSOBJS)		\
	$(THREADSMACHOBJS)	\
	$(THREADSASMOBJS)	\
	$(UNICODEOBJS)		\
	$(UNWINDMACHOBJS)	\
	$(UNWINDASMOBJS)	\
	$(COMSYSOBJS)		\
	$(SYSOBJS)		\
	$(COMSYSOBJS64)		\
	$(SYSOBJS64)		\
	$(VALUES)

TRACEOBJS=			\
	plockstat.o

# NOTE:	libc.so.1 must be linked with the minimal crti.o and crtn.o
# modules whose source is provided in the $(SRC)/lib/crt directory.
# This must be done because otherwise the Sun C compiler would insert
# its own versions of these modules and those versions contain code
# to call out to C++ initialization functions.  Such C++ initialization
# functions can call back into libc before thread initialization is
# complete and this leads to segmentation violations and other problems.
# Since libc contains no C++ code, linking with the minimal crti.o and
# crtn.o modules is safe and avoids the problems described above.
OBJECTS= $(CRTI) $(MOSTOBJS) $(CRTN)
CRTSRCS= ../../crt/sparc

# include common library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/lib/Makefile.lib.64

# we need to override the default SONAME here because we might
# be building a variant object (still libc.so.1, but different filename)
SONAME = libc.so.1

CFLAGS64 += $(CCVERBOSE)

# This is necessary to avoid problems with calling _ex_unwind().
# We probably don't want any inlining anyway.
CFLAGS64 += -xinline=

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-type-limits
CERRWARN += -_gcc=-Wno-char-subscripts
CERRWARN += -_gcc=-Wno-clobbered
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += -_gcc=-Wno-address

# Setting THREAD_DEBUG = -DTHREAD_DEBUG (make THREAD_DEBUG=-DTHREAD_DEBUG ...)
# enables ASSERT() checking in the threads portion of the library.
# This is automatically enabled for DEBUG builds, not for non-debug builds.
THREAD_DEBUG =
$(NOT_RELEASE_BUILD)THREAD_DEBUG = -DTHREAD_DEBUG

# Make string literals read-only to save memory.
CFLAGS64 += $(XSTRCONST)

ALTPICS= $(TRACEOBJS:%=pics/%)

$(DYNLIB) := BUILD.SO = $(LD) -o $@ -G $(DYNFLAGS) $(PICS) $(ALTPICS) $(EXTPICS)

MAPFILES =	$(LIBCDIR)/port/mapfile-vers

sparcv9_C_PICFLAGS= -K PIC
CFLAGS64 +=	$(EXTN_CFLAGS)
CPPFLAGS=	-D_REENTRANT -Dsparc $(EXTN_CPPFLAGS) $(THREAD_DEBUG) \
		-I$(LIBCBASE)/inc -I$(LIBCDIR)/inc $(CPPFLAGS.master)
ASFLAGS=	$(EXTN_ASFLAGS) -K PIC -P -D__STDC__ -D_ASM -D__sparcv9 $(CPPFLAGS) \
		$(sparcv9_AS_XARCH)

# As a favor to the dtrace syscall provider, libc still calls the
# old syscall traps that have been obsoleted by the *at() interfaces.
# Delete this to compile libc using only the new *at() system call traps
CPPFLAGS += -D_RETAIN_OLD_SYSCALLS

# Inform the run-time linker about libc specialized initialization
RTLDINFO =	-z rtldinfo=tls_rtldinfo
DYNFLAGS +=	$(RTLDINFO)

# Force libc's internal references to be resolved immediately upon loading
# in order to avoid critical region problems.  Since almost all libc symbols
# are marked 'protected' in the mapfiles, this is a minimal set (15 to 20).
DYNFLAGS +=	-znow

DYNFLAGS +=	$(EXTN_DYNFLAGS)

BUILD.s=	$(AS) $(ASFLAGS) $< -o $@

# Override this top level flag so the compiler builds in its native
# C99 mode.  This has been enabled to support the complex arithmetic
# added to libc.
CSTD=	$(CSTD_GNU99)

# libc method of building an archive
# The "$(GREP) -v ' L '" part is necessary only until
# lorder is fixed to ignore thread-local variables.
BUILD.AR= $(RM) $@ ; \
	$(AR) q $@ `$(LORDER) $(MOSTOBJS:%=$(DIR)/%) | $(GREP) -v ' L ' | $(TSORT)`

# extra files for the clean target
CLEANFILES=			\
	$(LIBCDIR)/port/gen/errlst.c	\
	$(LIBCDIR)/port/gen/new_list.c	\
	assym.h			\
	genassym		\
	pics/crti.o		\
	pics/crtn.o		\
	$(ALTPICS)

CLOBBERFILES +=	$(LIB_PIC)

# list of C source for lint
SRCS=							\
	$(ATOMICOBJS:%.o=$(SRC)/common/atomic/%.c)	\
	$(XATTROBJS:%.o=$(SRC)/common/xattr/%.c)	\
	$(COMOBJS:%.o=$(SRC)/common/util/%.c)		\
	$(PORTFP:%.o=$(LIBCDIR)/port/fp/%.c)		\
	$(PORTGEN:%.o=$(LIBCDIR)/port/gen/%.c)		\
	$(PORTI18N:%.o=$(LIBCDIR)/port/i18n/%.c)	\
	$(PORTLOCALE:%.o=$(LIBCDIR)/port/locale/%.c)	\
	$(PORTPRINT:%.o=$(LIBCDIR)/port/print/%.c)	\
	$(PORTREGEX:%.o=$(LIBCDIR)/port/regex/%.c)	\
	$(PORTSTDIO:%.o=$(LIBCDIR)/port/stdio/%.c)	\
	$(PORTSYS:%.o=$(LIBCDIR)/port/sys/%.c)		\
	$(AIOOBJS:%.o=$(LIBCDIR)/port/aio/%.c)		\
	$(RTOBJS:%.o=$(LIBCDIR)/port/rt/%.c)		\
	$(SECFLAGSOBJS:%.o=$(SRC)/common/secflags/%.c)	\
	$(TPOOLOBJS:%.o=$(LIBCDIR)/port/tpool/%.c)	\
	$(THREADSOBJS:%.o=$(LIBCDIR)/port/threads/%.c)	\
	$(THREADSMACHOBJS:%.o=$(LIBCDIR)/$(MACH)/threads/%.c) \
	$(UNICODEOBJS:%.o=$(SRC)/common/unicode/%.c)	\
	$(UNWINDMACHOBJS:%.o=$(LIBCDIR)/port/unwind/%.c) \
	$(FPOBJS:%.o=$(LIBCDIR)/$(MACH)/fp/%.c)		\
	$(FPOBJS64:%.o=$(LIBCBASE)/fp/%.c)		\
	$(LIBCBASE)/crt/_ftou.c				\
	$(LIBCBASE)/gen/_xregs_clrptr.c			\
	$(LIBCBASE)/gen/byteorder.c			\
	$(LIBCBASE)/gen/endian.c			\
	$(LIBCBASE)/gen/ecvt.c				\
	$(LIBCBASE)/gen/getctxt.c			\
	$(LIBCBASE)/gen/makectxt.c			\
	$(LIBCBASE)/gen/siginfolst.c			\
	$(LIBCBASE)/gen/siglongjmp.c			\
	$(LIBCBASE)/gen/swapctxt.c

# conditional assignments
$(DYNLIB) := CRTI = crti.o
$(DYNLIB) := CRTN = crtn.o

# Files which need the threads .il inline template
TIL=				\
	aio.o			\
	alloc.o			\
	assfail.o		\
	atexit.o		\
	atfork.o		\
	cancel.o		\
	door_calls.o		\
	err.o			\
	errno.o			\
	getctxt.o		\
	lwp.o			\
	ma.o			\
	machdep.o		\
	posix_aio.o		\
	pthr_attr.o		\
	pthr_barrier.o		\
	pthr_cond.o		\
	pthr_mutex.o		\
	pthr_rwlock.o		\
	pthread.o		\
	rand.o			\
	rwlock.o		\
	scalls.o		\
	sched.o			\
	sema.o			\
	sigaction.o		\
	sigev_thread.o		\
	spawn.o			\
	stack.o			\
	swapctxt.o		\
	synch.o			\
	tdb_agent.o		\
	thr.o			\
	thread_interface.o	\
	thread_pool.o		\
	tls.o			\
	tsd.o			\
	unwind.o

$(TIL:%=pics/%) := CFLAGS64 += $(LIBCBASE)/threads/sparcv9.il

# Files in fp, port/fp subdirectories that need base.il inline template
IL=				\
	__flt_decim.o		\
	decimal_bin.o

$(IL:%=pics/%) := CFLAGS64 += $(LIBCBASE)/fp/base.il

# Files in fp subdirectory which need __quad.il inline template
QIL=				\
	_Q_add.o		\
	_Q_cmp.o		\
	_Q_cmpe.o		\
	_Q_div.o		\
	_Q_dtoq.o		\
	_Q_fcc.o		\
	_Q_mul.o		\
	_Q_qtod.o		\
	_Q_qtoi.o		\
	_Q_qtos.o		\
	_Q_qtou.o		\
	_Q_sqrt.o		\
	_Q_stoq.o		\
	_Q_sub.o		\
	_Qp_qtox.o		\
	_Qp_qtoux.o

$(QIL:%=pics/%) := CFLAGS64 += $(LIBCDIR)/$(MACH)/fp/__quad.il
pics/_Qp%.o := CFLAGS64 += -I$(LIBCDIR)/$(MACH)/fp
pics/_Q%.o := sparcv9_COPTFLAG = -xO4 -xchip=ultra

# Files in crt subdirectory which need muldiv64.il inline template
#CIL=	mul64.o divrem64.o
#$(CIL:%=pics/%) := CFLAGS += $(LIBCBASE)/crt/mul64.il

# large-file-aware components that should be built large

#$(COMSYSOBJS64:%=pics/%) := \
#	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

#$(SYSOBJS64:%=pics/%) := \
#	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

#$(PORTGEN64:%=pics/%) := \
#	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

#$(PORTSTDIO64:%=pics/%) := \
#	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

#$(PORTSYS64:%=pics/%) := \
#	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

$(PORTSTDIO_W:%=pics/%) := \
	CPPFLAGS += -D_WIDE

$(PORTPRINT_W:%=pics/%) := \
	CPPFLAGS += -D_WIDE

$(PORTI18N_COND:%=pics/%) := \
	CPPFLAGS += -D_WCS_LONGLONG

pics/arc4random.o :=	CPPFLAGS += -I$(SRC)/common/crypto/chacha

# Files which need extra optimization
pics/getenv.o := sparcv9_COPTFLAG = -xO4

.KEEP_STATE:

all: $(LIBS) $(LIB_PIC)

lint	:=	CPPFLAGS += -I$(LIBCDIR)/$(MACH)/fp
lint	:=	CPPFLAGS += -D_MSE_INT_H -D_LCONV_C99
lint	:=	LINTFLAGS64 += -mn

lint:
	@echo $(LINT.c) ... $(LDLIBS)
	@$(LINT.c) $(SRCS) $(LDLIBS)

$(LINTLIB):= SRCS=$(LIBCDIR)/port/llib-lc
$(LINTLIB):= CPPFLAGS += -D_MSE_INT_H
$(LINTLIB):= LINTFLAGS64=-nvx -m64

# object files that depend on inline template
$(TIL:%=pics/%): $(LIBCBASE)/threads/sparcv9.il
$(IL:%=pics/%): $(LIBCBASE)/fp/base.il
$(QIL:%=pics/%): $(LIBCDIR)/$(MACH)/fp/__quad.il
#$(CIL:%=pics/%): $(LIBCBASE)/crt/muldiv64.il

# include common libc targets
include $(LIBCDIR)/Makefile.targ

# We need to strip out all CTF and DOF data from the static library
$(LIB_PIC) := DIR = pics
$(LIB_PIC): pics $$(PICS)
	$(BUILD.AR)
	$(MCS) -d -n .SUNW_ctf $@ > /dev/null 2>&1
	$(MCS) -d -n .SUNW_dof $@ > /dev/null 2>&1
	$(AR) -ts $@ > /dev/null
	$(POST_PROCESS_A)

# special cases
#$(STRETS:%=pics/%): crt/stret.s
#	$(AS) $(ASFLAGS) -DSTRET$(@F:stret%.o=%) crt/stret.s -o $@
#	$(POST_PROCESS_O)

#crt/_rtbootld.s:	crt/_rtboot.s crt/_rtld.c
#	$(CC) $(CPPFLAGS) -O -S -K pic crt/_rtld.c -o crt/_rtld.s
#	$(CAT) crt/_rtboot.s crt/_rtld.s > $@
#	$(RM) crt/_rtld.s

ASSYMDEP_OBJS=			\
	_lwp_mutex_unlock.o	\
	_stack_grow.o		\
	asm_subr.o		\
	setjmp.o		\
	smt_pause.o		\
	tls_get_addr.o		\
	unwind_frame.o		\
	vforkx.o

$(ASSYMDEP_OBJS:%=pics/%)	:=	CPPFLAGS += -I.

$(ASSYMDEP_OBJS:%=pics/%): assym.h

# assym.h build rules

assym.h := CFLAGS64 += -g

GENASSYM_C = $(LIBCDIR)/$(MACH)/genassym.c

genassym: $(GENASSYM_C)
	$(NATIVECC) $(NATIVE_CFLAGS) -I$(LIBCBASE)/inc -I$(LIBCDIR)/inc \
		$(CPPFLAGS.native) -o $@ $(GENASSYM_C)

OFFSETS = $(LIBCDIR)/$(MACH)/offsets.in

assym.h: $(OFFSETS) genassym
	$(OFFSETS_CREATE) <$(OFFSETS) >$@
	./genassym >>$@

# derived C source and related explicit dependencies
$(LIBCDIR)/port/gen/new_list.c: $(LIBCDIR)/port/gen/errlist $(LIBCDIR)/port/gen/errlist.awk
	cd $(LIBCDIR)/port/gen; pwd; $(AWK) -f errlist.awk < errlist

pics/new_list.o: $(LIBCDIR)/port/gen/new_list.c
