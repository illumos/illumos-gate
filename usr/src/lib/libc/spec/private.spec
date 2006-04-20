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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libc/spec/private.spec

function	_QgetRD # used by Sun's old Fortran 77 runtime libraries
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	__charmap_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__class_quadruple # used by Sun's old Fortran 77 runtime libraries
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__clock_getres
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__clock_gettime
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__clock_nanosleep
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__clock_settime
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__collate_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__ctype_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__divrem64
#Declaration	/* Unknown. */
arch		i386
version		i386=SUNWprivate_1.1
end

function	__eucpctowc_gen
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__fdsync
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__fgetwc_dense
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__fgetwc_euc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__fgetwc_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__fltrounds
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	__fnmatch_C
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__fnmatch_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__fnmatch_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__getcontext
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__getdate_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__iswctype_bc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__iswctype_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__iswctype_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__locale_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__localeconv_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_cond_broadcast
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_cond_signal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_cond_timedwait # extends libc/spec/sys.spec _lwp_cond_timedwait
weak		_lwp_cond_timedwait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_cond_reltimedwait # extends libc/spec/sys.spec _lwp_cond_reltimedwait
weak		_lwp_cond_reltimedwait
#Prototype	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_cond_wait # extends libc/spec/sys.spec _lwp_cond_wait
weak		_lwp_cond_wait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_continue
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_info
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_kill
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_mutex_lock # extends libc/spec/sys.spec _lwp_mutex_lock
weak		_lwp_mutex_lock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_mutex_trylock # extends libc/spec/sys.spec _lwp_mutex_trylock
weak		_lwp_mutex_trylock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_mutex_unlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_self
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_sema_init # extends libc/spec/sys.spec _lwp_sema_init
weak		_lwp_sema_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_sema_post
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_sema_trywait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_sema_wait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__lwp_suspend
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mbftowc_dense
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mbftowc_euc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mbftowc_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mblen_gen
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mblen_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mbstowcs_dense
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mbstowcs_euc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mbstowcs_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mbtowc_dense
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mbtowc_euc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mbtowc_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__messages_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__monetary_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__multi_innetgr
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__nanosleep
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__nl_langinfo_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__numeric_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__regcomp_C
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__regcomp_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__regerror_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__regexec_C
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__regexec_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__regfree_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__signotify
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__sigqueue
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__sigtimedwait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__strcoll_C
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__strcoll_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__strcoll_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__strfmon_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__strftime_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__strptime_dontzero
declaration     char *__strptime_dontzero(const char *buf, const char *format, \
                        struct tm *tm)
version		SUNWprivate_1.1
exception       $return == 0
end

function	__strptime_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__strxfrm_C
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__strxfrm_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__strxfrm_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__time_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__timer_create
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__timer_delete
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__timer_getoverrun
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__timer_gettime
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__timer_settime
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__towctrans_bc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__towctrans_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__towlower_bc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__towlower_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__towupper_bc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__towupper_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__trwctype_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__udivrem64
#Declaration	/* Unknown. */
arch		i386
version		i386=SUNWprivate_1.1
end

function	__wcscoll_C
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcscoll_bc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcscoll_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcsftime_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcstombs_dense
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcstombs_euc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcstombs_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcswidth_bc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcswidth_dense
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcswidth_euc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcswidth_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcswidth_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcsxfrm_C
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcsxfrm_bc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcsxfrm_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wctoeucpc_gen
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wctomb_dense
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wctomb_euc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wctomb_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wctrans_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wctype_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcwidth_bc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcwidth_dense
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcwidth_euc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcwidth_sb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__wcwidth_std
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__xgetRD # used by Sun's old Fortran 77 runtime libraries
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	__xtol
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	__xtoll
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	__xtoul
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	__xtoull
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_a64l # extends libc/spec/gen.spec a64l
weak		a64l
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_acl
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_adjtime
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ascftime # extends libc/spec/gen.spec ascftime
weak		ascftime
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_asctime_r # extends libc/spec/gen.spec asctime_r
weak		asctime_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function        _autofssys
#Declaration    /* Unknown. */
version         SUNWprivate_1.1
end

function	_brk # extends libc/spec/sys.spec brk
weak		brk
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_bufsync
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_cerror
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_cerror64
#Declaration	/* Unknown. */
arch		sparc
version		sparc=SUNWprivate_1.1
end

function	_cfree # extends libc/spec/gen.spec cfree
weak		cfree
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_cftime # extends libc/spec/gen.spec cftime
weak		cftime
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_closelog # extends libc/spec/gen.spec closelog
weak		closelog
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_cond_broadcast
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_cond_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_cond_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_cond_signal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_cond_timedwait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_cond_reltimedwait
#Prototype	/* Unknown. */
version		SUNWprivate_1.1
end

function	_cond_wait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ctermid # extends libc/spec/stdio.spec ctermid
weak		ctermid
#Declaration	/* Unknown. */
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 amd64=SYSVABI_1.3 sparcv9=SUNW_0.7
end

function	_ctermid_r # extends libc/spec/stdio.spec ctermid_r
weak		ctermid_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ctime_r # extends libc/spec/gen.spec ctime_r
weak		ctime_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_decimal_to_double # extends libc/spec/fp.spec decimal_to_double
weak		decimal_to_double
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_decimal_to_extended # extends libc/spec/fp.spec decimal_to_extended
weak		decimal_to_extended
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_decimal_to_quadruple # extends libc/spec/fp.spec decimal_to_quadruple
weak		decimal_to_quadruple
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_decimal_to_single # extends libc/spec/fp.spec decimal_to_single
weak		decimal_to_single
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_dgettext # extends libc/spec/i18n.spec dgettext
weak		dgettext
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_doprnt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_doscan
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_double_to_decimal # extends libc/spec/fp.spec double_to_decimal
weak		double_to_decimal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_drand48 # extends libc/spec/gen.spec drand48
weak		drand48
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_econvert # extends libc/spec/gen.spec econvert
weak		econvert
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ecvt # extends libc/spec/gen.spec ecvt
weak		ecvt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_endgrent # extends libc/spec/gen.spec endgrent
weak		endgrent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_endpwent # extends libc/spec/gen.spec endpwent
weak		endpwent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_endspent # extends libc/spec/gen.spec endspent
weak		endspent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_endutent # extends libc/spec/gen.spec endutent
weak		endutent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_endutxent # extends libc/spec/gen.spec endutxent
weak		endutxent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_erand48 # extends libc/spec/gen.spec erand48
weak		erand48
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_exportfs
weak		exportfs
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_extended_to_decimal # extends libc/spec/fp.spec extended_to_decimal
weak		extended_to_decimal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_facl
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fchroot
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fconvert # extends libc/spec/gen.spec fconvert
weak		fconvert
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fcvt # extends libc/spec/gen.spec fcvt
weak		fcvt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ffs # extends libc/spec/gen.spec ffs
weak		ffs
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fgetgrent # extends libc/spec/gen.spec fgetgrent
weak		fgetgrent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fgetgrent_r # extends libc/spec/gen.spec fgetgrent_r
weak		fgetgrent_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fgetpwent # extends libc/spec/gen.spec fgetpwent
weak		fgetpwent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fgetpwent_r # extends libc/spec/gen.spec fgetpwent_r
weak		fgetpwent_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fgetspent # extends libc/spec/gen.spec fgetspent
weak		fgetspent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fgetspent_r # extends libc/spec/gen.spec fgetspent_r
weak		fgetspent_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_file_to_decimal # extends libc/spec/fp.spec file_to_decimal
weak		file_to_decimal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_findbuf
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_findiop
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_finite # extends libc/spec/i18n.spec finite
weak		finite
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_flockfile # extends libc/spec/stdio.spec flockfile
weak		flockfile
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fork1
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fpclass # extends libc/spec/i18n.spec fpclass
weak		fpclass
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fpgetmask
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fpgetround
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fpgetsticky
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fprintf # extends libc/spec/print.spec fprintf
weak		fprintf
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fpsetmask
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fpsetround
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fpsetsticky
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_fstatfs
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_func_to_decimal # extends libc/spec/fp.spec func_to_decimal
weak		func_to_decimal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_funlockfile # extends libc/spec/stdio.spec funlockfile
weak		funlockfile
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_gconvert # extends libc/spec/gen.spec gconvert
weak		gconvert
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_gcvt # extends libc/spec/gen.spec gcvt
weak		gcvt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getarg
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getc_unlocked # extends libc/spec/stdio.spec getc_unlocked
weak		getc_unlocked
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getchar_unlocked # extends libc/spec/stdio.spec getchar_unlocked
weak		getchar_unlocked
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getdents
version		SUNWprivate_1.1
end

function	_getgrent # extends libc/spec/gen.spec getgrent
weak		getgrent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getgrent_r # extends libc/spec/gen.spec getgrent_r
weak		getgrent_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getgrgid # extends libc/spec/gen.spec getgrgid
weak		getgrgid
#Declaration	/* Unknown. */
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 amd64=SYSVABI_1.3 sparcv9=SUNW_0.7
end

function	_getgrgid_r # extends libc/spec/gen.spec getgrgid_r
weak		getgrgid_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getgrnam # extends libc/spec/gen.spec getgrnam
weak		getgrnam
#Declaration	/* Unknown. */
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 amd64=SYSVABI_1.3 sparcv9=SUNW_0.7
end

function	_getgrnam_r # extends libc/spec/gen.spec getgrnam_r
weak		getgrnam_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getgroupsbymember
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getlogin # extends libc/spec/gen.spec getlogin
weak		getlogin
#Declaration	/* Unknown. */
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 amd64=SYSVABI_1.3 sparcv9=SUNW_0.7
end

function	_getlogin_r # extends libc/spec/gen.spec getlogin_r
weak		getlogin_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getmntany # extends libc/spec/gen.spec getmntany
weak		getmntany
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getmntent # extends libc/spec/gen.spec getmntent
weak		getmntent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getpw # extends libc/spec/gen.spec getpw
weak		getpw
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getpwent # extends libc/spec/gen.spec getpwent
weak		getpwent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getpwent_r # extends libc/spec/gen.spec getpwent_r
weak		getpwent_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getpwnam # extends libc/spec/gen.spec getpwnam
weak		getpwnam
#Declaration	/* Unknown. */
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 amd64=SYSVABI_1.3 sparcv9=SUNW_0.7
end

function	_getpwnam_r # extends libc/spec/gen.spec getpwnam_r
weak		getpwnam_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getpwuid # extends libc/spec/gen.spec getpwuid
weak		getpwuid
#Declaration	/* Unknown. */
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 amd64=SYSVABI_1.3 sparcv9=SUNW_0.7
end

function	_getpwuid_r # extends libc/spec/gen.spec getpwuid_r
weak		getpwuid_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getsp
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getfp
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getspent # extends libc/spec/gen.spec getspent
weak		getspent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getspent_r # extends libc/spec/gen.spec getspent_r
weak		getspent_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getspnam # extends libc/spec/gen.spec getspnam
weak		getspnam
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getspnam_r # extends libc/spec/gen.spec getspnam_r
weak		getspnam_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getutent # extends libc/spec/gen.spec getutent
weak		getutent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getutid # extends libc/spec/gen.spec getutid
weak		getutid
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getutline # extends libc/spec/gen.spec getutline
weak		getutline
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getutmp # extends libc/spec/gen.spec getutmp
weak		getutmp
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getutmpx # extends libc/spec/gen.spec getutmpx
weak		getutmpx
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getutxent # extends libc/spec/gen.spec getutxent
weak		getutxent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getutxid # extends libc/spec/gen.spec getutxid
weak		getutxid
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getutxline # extends libc/spec/gen.spec getutxline
weak		getutxline
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getvfsany # extends libc/spec/gen.spec getvfsany
weak		getvfsany
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getvfsent # extends libc/spec/gen.spec getvfsent
weak		getvfsent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getvfsfile # extends libc/spec/gen.spec getvfsfile
weak		getvfsfile
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_getvfsspec # extends libc/spec/gen.spec getvfsspec
weak		getvfsspec
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_gmtime_r # extends libc/spec/gen.spec gmtime_r
weak		gmtime_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_gsignal # extends libc/spec/gen.spec gsignal
weak		gsignal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_gtty
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_hasmntopt # extends libc/spec/gen.spec hasmntopt
weak		hasmntopt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_iconv # extends libc/spec/gen.spec iconv
weak		iconv
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_iconv_close # extends libc/spec/gen.spec iconv_close
weak		iconv_close
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_iconv_open # extends libc/spec/gen.spec iconv_open
weak		iconv_open
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_install_utrap
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_is_euc_fc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_is_euc_pc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_isnanf
version		SUNWprivate_1.1
filter		libm.so.2
end

function	_iswctype
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_jrand48 # extends libc/spec/gen.spec jrand48
weak		jrand48
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_kaio
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_l64a # extends libc/spec/gen.spec l64a
weak		l64a
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ladd
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lckpwdf # extends libc/spec/gen.spec lckpwdf
weak		lckpwdf
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lcong48 # extends libc/spec/gen.spec lcong48
weak		lcong48
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ldivide # extends libc/spec/sys.spec ldivide
weak		ldivide
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lexp10 # extends libc/spec/sys.spec lexp10
weak		lexp10
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lgrp_home_fast
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lgrpsys
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_llabs # extends libc/spec/gen.spec llabs
weak		llabs
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lldiv # extends libc/spec/gen.spec lldiv
weak		lldiv
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_llog10 # extends libc/spec/sys.spec llog10
weak		llog10
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_llseek
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lmul # extends libc/spec/sys.spec lmul
weak		lmul
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_localtime_r # extends libc/spec/gen.spec localtime_r
weak		localtime_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lock_clear
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lock_try
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_logb
version		SUNWprivate_1.1
filter		libm.so.2
end

function	_lrand48 # extends libc/spec/gen.spec lrand48
weak		lrand48
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lshiftl
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_lsub
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ltzset
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_madvise # extends libc/spec/gen.spec madvise
weak		madvise
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_makeut
weak		makeut
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_makeutx
weak		makeutx
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_mbftowc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_memalign # extends libc/spec/gen.spec memalign
weak		memalign
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_memcmp
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
auxiliary	sparc=/platform/$PLATFORM/lib/libc_psr.so.1 \
		sparcv9=/platform/$PLATFORM/lib/sparcv9/libc_psr.so.1
end

function	_memcpy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
auxiliary	sparc=/platform/$PLATFORM/lib/libc_psr.so.1 \
		sparcv9=/platform/$PLATFORM/lib/sparcv9/libc_psr.so.1
end

function	_memmove
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
auxiliary	sparc=/platform/$PLATFORM/lib/libc_psr.so.1 \
		sparcv9=/platform/$PLATFORM/lib/sparcv9/libc_psr.so.1
end

function	_memset
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
auxiliary	sparc=/platform/$PLATFORM/lib/libc_psr.so.1 \
		sparcv9=/platform/$PLATFORM/lib/sparcv9/libc_psr.so.1
end

function	_mincore
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_mkarglst
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_mlockall # extends libc/spec/gen.spec mlockall
weak		mlockall
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_modff
version		SUNWprivate_1.1
filter		libm.so.2
end

function	_mrand48 # extends libc/spec/gen.spec mrand48
weak		mrand48
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_munlockall # extends libc/spec/gen.spec munlockall
weak		munlockall
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_mutex_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_mutex_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_mutex_lock
#Declaration	/* Unknown. */
version		SUNW_0.7
end

function	_mutex_trylock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_mutex_unlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_mutex_held
#Declaration	/* Unknown. */
version		SUNW_0.7
end

function	__mutex_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mutex_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mutex_lock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mutex_trylock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mutex_unlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__mutex_held
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nfs_getfh
weak		nfs_getfh
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nfssvc
weak		nfssvc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nfssys
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nrand48 # extends libc/spec/gen.spec nrand48
weak		nrand48
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nss_delete
weak		nss_delete
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nss_endent
weak		nss_endent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nss_getent
weak		nss_getent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nss_initf_netgroup
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nss_search
weak		nss_search
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_nss_setent
weak		nss_setent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_openlog # extends libc/spec/gen.spec openlog
weak		openlog
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_plock # extends libc/spec/gen.spec plock
weak		plock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pread
version		SUNWprivate_1.1
end

function	pset_assign_forced
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_psiginfo # extends libc/spec/gen.spec psiginfo
weak		psiginfo
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_psignal # extends libc/spec/gen.spec psignal
weak		psignal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_atfork
weak		pthread_atfork
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_getdetachstate
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_getinheritsched
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_getschedparam
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_getschedpolicy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_getscope
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_getstack
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_getstackaddr
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_getstacksize
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_setdetachstate
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_setinheritsched
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_setschedparam
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_setschedpolicy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_setscope
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_setstack
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_setstackaddr
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_attr_setstacksize
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_barrierattr_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_barrierattr_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_barrierattr_setpshared
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_barrierattr_getpshared
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_barrier_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_barrier_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_barrier_wait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_cancel
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_cond_broadcast
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_cond_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_cond_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_cond_signal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_cond_timedwait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_cond_reltimedwait_np
#Prototype	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_cond_wait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_condattr_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_condattr_getclock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_condattr_getpshared
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_condattr_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_condattr_setclock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_condattr_setpshared
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_create
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_detach
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_equal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_exit
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_getschedparam
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_getspecific
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_join
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_key_create
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_key_delete
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_kill
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutex_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutex_getprioceiling
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutex_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutex_lock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutex_setprioceiling
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutex_trylock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutex_unlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutexattr_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutexattr_getprioceiling
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutexattr_getprotocol
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutexattr_getpshared
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutexattr_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutexattr_setprioceiling
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutexattr_setprotocol
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutexattr_setpshared
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_once
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_self
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_setcancelstate
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_setcanceltype
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_setschedparam
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_setschedprio
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_setspecific
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_sigmask
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_testcancel
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutex_timedlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_mutex_reltimedlock_np
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_spin_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_spin_destroy
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_spin_trylock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_spin_lock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pthread_spin_unlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_putc_unlocked # extends libc/spec/stdio.spec putc_unlocked
weak		putc_unlocked
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_putchar_unlocked # extends libc/spec/stdio.spec putchar_unlocked
weak		putchar_unlocked
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_putpwent # extends libc/spec/gen.spec putpwent
weak		putpwent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_putspent # extends libc/spec/gen.spec putspent
weak		putspent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pututline # extends libc/spec/gen.spec pututline
weak		pututline
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pututxline # extends libc/spec/gen.spec pututxline
weak		pututxline
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pwrite
version		SUNWprivate_1.1
end

function	_qeconvert # extends libc/spec/gen.spec qeconvert
weak		qeconvert
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_qecvt # extends libc/spec/sys.spec qecvt
weak		qecvt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_qfconvert # extends libc/spec/gen.spec qfconvert
weak		qfconvert
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_qfcvt # extends libc/spec/sys.spec qfcvt
weak		qfcvt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_qgconvert # extends libc/spec/gen.spec qgconvert
weak		qgconvert
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_qgcvt # extends libc/spec/sys.spec qgcvt
weak		qgcvt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_quadruple_to_decimal # extends libc/spec/fp.spec quadruple_to_decimal
weak		quadruple_to_decimal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_rand_r # extends libc/spec/gen.spec rand_r
weak		rand_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_realbufend
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_realpath # extends libc/spec/gen.spec realpath
weak		realpath
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_rpcsys
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_rw_rdlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_rw_tryrdlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_rw_trywrlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_rw_unlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_rw_wrlock
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_rwlock_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sbrk # extends libc/spec/sys.spec sbrk
weak		sbrk
#Declaration	/* Unknown. */
version		i386=SYSVABI_1.3 amd64=SYSVABI_1.3 sparc=SISCD_2.3 sparcv9=SUNW_0.7
end

function	_sbrk_unlocked
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sbrk_grow_aligned
declaration	void *_sbrk_grow_aligned(size_t size, size_t low_align, \
		    size_t high_align, size_t *actual_size);
version		SUNWprivate_1.1
exception       $return == (void *)-1
end

function	_seconvert # extends libc/spec/gen.spec seconvert
weak		seconvert
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_seed48 # extends libc/spec/gen.spec seed48
weak		seed48
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_select # extends libc/spec/gen.spec select
weak		select
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_pselect # extends libc/spec/gen.spec pselect
weak		pselect
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sema_init
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sema_post
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sema_trywait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sema_wait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sema_timedwait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sema_reltimedwait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setbufend
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setegid
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_seteuid
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setgrent # extends libc/spec/gen.spec setgrent
weak		setgrent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setlogmask # extends libc/spec/gen.spec setlogmask
weak		setlogmask
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setpwent # extends libc/spec/gen.spec setpwent
weak		setpwent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setregid
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setreuid
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setspent # extends libc/spec/gen.spec setspent
weak		setspent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_settimeofday # extends libc/spec/gen.spec settimeofday
weak		settimeofday
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setutent # extends libc/spec/gen.spec setutent
weak		setutent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_setutxent # extends libc/spec/gen.spec setutxent
weak		setutxent
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sfconvert # extends libc/spec/gen.spec sfconvert
weak		sfconvert
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sgconvert # extends libc/spec/gen.spec sgconvert
weak		sgconvert
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sig2str # extends libc/spec/gen.spec sig2str
weak		sig2str
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sigflag
weak		sigflag
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sigfpe # extends libc/spec/sys.spec sigfpe
weak		sigfpe
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_signal # extends libc/spec/gen.spec signal
weak		signal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sigwait
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_single_to_decimal # extends libc/spec/fp.spec single_to_decimal
weak		single_to_decimal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_accept
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_bind
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_connect
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_getpeername
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_getsockname
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_getsockopt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_listen
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_recv
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_recvfrom
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_recvmsg
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_send
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_sendmsg
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_sendto
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_setsockopt
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_shutdown
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_socket
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_so_socketpair
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sockconfig
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_srand48 # extends libc/spec/gen.spec srand48
weak		srand48
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ssignal # extends libc/spec/gen.spec ssignal
weak		ssignal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_statfs
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_str2sig # extends libc/spec/gen.spec str2sig
weak		str2sig
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_strerror # extends libc/spec/gen.spec strerror
weak		strerror
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_string_to_decimal # extends libc/spec/fp.spec string_to_decimal
weak		string_to_decimal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_strsignal # extends libc/spec/gen.spec strsignal
weak		strsignal
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_strtok_r # extends libc/spec/gen.spec strtok_r
weak		strtok_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_strtoll # extends libc/spec/gen.spec strtoll
weak		strtoll
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_strtoull # extends libc/spec/gen.spec strtoull
weak		strtoull
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_stty
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_swapctl # extends libc/spec/gen.spec swapctl
weak		swapctl
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sysconfig
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sysfs
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_sysi86
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_syssun
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_thr_continue
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_create
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_exit
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_get_inf_read
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_get_nan_read
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_getconcurrency
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_getprio
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_getspecific
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_join
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_keycreate
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_kill
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_main
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_min_stack
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_self
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_setconcurrency
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_setprio
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_setspecific
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_sigsetmask
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_stksegment
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_suspend
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_thr_yield
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_tmpnam
weak		tmpnam
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_tmpnam_r
weak		tmpnam_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_trwctype
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ttyname # extends libc/spec/gen.spec ttyname
weak		ttyname
#Declaration	/* Unknown. */
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 amd64=SYSVABI_1.3 sparcv9=SUNW_0.7
end

function	_ttyname_r # extends libc/spec/gen.spec ttyname_r
weak		ttyname_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ttyname_dev
#Declaration      /* Unknown. */
version         SUNWprivate_1.1
end

function	_ttyslot # extends libc/spec/gen.spec ttyslot
weak		ttyslot
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_uadmin # extends libc/spec/sys.spec uadmin
weak		uadmin
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ulckpwdf # extends libc/spec/gen.spec ulckpwdf
weak		ulckpwdf
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ulltostr # # extends libc/spec/gen.spec ulltostr
weak		ulltostr
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_uncached_getgrgid_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_uncached_getgrnam_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_uncached_getpwnam_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_uncached_getpwuid_r
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ungetc_unlocked
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_unordered # extends libc/spec/i18n.spec unordered
weak		unordered
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_updwtmp
weak		updwtmp
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_updwtmpx
weak		updwtmpx
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_ustat
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_utimes
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_utmpname # extends libc/spec/gen.spec utmpname
weak		utmpname
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_utmpxname # extends libc/spec/gen.spec utmpxname
weak		utmpxname
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_utssys
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_valloc # extends libc/spec/gen.spec valloc
weak		valloc
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_vfork
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_vhangup
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_vsyslog # extends libc/spec/gen.spec vsyslog
weak		vsyslog
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_wctomb # extends libc/spec/i18n.spec wctomb
weak		wctomb
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_wrtchk
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_xflsbuf
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_xgetwidth
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_xregs_clrptr
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_yield
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	__nthreads
#Declaration	/* unknown. */
version		SUNWprivate_1.1
end

function	dbm_close_status
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	dbm_do_nextkey
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	dbm_setdefwrite
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	gtty
version		SUNWprivate_1.1
end

function	htonl
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	htons
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	install_utrap
arch		sparc sparcv9
version		SUNWprivate_1.1
end

function	kaio
version		SUNWprivate_1.1
end

function	makeut
version		SUNWprivate_1.1
end

function	mcfiller
version		SUNWprivate_1.1
end

function	mntopt
version		SUNWprivate_1.1
end

function	mutex_held
version		SUNWprivate_1.1
end

function	nfssvc
version		SUNWprivate_1.1
end

function	nop
arch		sparc sparcv9
version		SUNWprivate_1.1
end

function	ntohl
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	ntohs
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	scrwidth
version		SUNWprivate_1.1
end

function	sigflag
version		SUNWprivate_1.1
end

function	str2spwd
version		SUNWprivate_1.1
end

function	stty
version		SUNWprivate_1.1
end

function	sysi86
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	utssys
version		SUNWprivate_1.1
end

function	wdbindf
version		SUNWprivate_1.1
end

function	wdchkind
version		SUNWprivate_1.1
end

function	wddelim
version		SUNWprivate_1.1
end

function	_delete
version		SUNWprivate_1.1
end

function	_insert
version		SUNWprivate_1.1
end

function	_nss_XbyY_fgets
include		<nss_dbdefs.h>
declaration	void _nss_XbyY_fgets(FILE *f, nss_XbyY_args_t *b)
version		SUNWprivate_1.1
end

function	_nss_db_state_destr
include		<nss_common.h>
declaration	void _nss_db_state_destr(struct nss_db_state *s)
version		SUNWprivate_1.1
end

# PSARC/1998/452; Bug 4181371; NSS Lookup Control START

function	__nsw_getconfig_v1
include		"../../inc/nsswitch_priv.h"
declaration	struct __nsw_switchconfig_v1 \
		    *__nsw_getconfig_v1(const char *, enum __nsw_parse_err *)
version		SUNWprivate_1.1
end

function	__nsw_freeconfig_v1
include		"../../inc/nsswitch_priv.h"
declaration	int __nsw_freeconfig_v1(struct __nsw_switchconfig_v1 *)
version		SUNWprivate_1.1
end

function	__nsw_extended_action_v1
include		"../../inc/nsswitch_priv.h"
declaration	action_t __nsw_extended_action_v1(struct __nsw_lookup_v1 *,\
		    int)
version		SUNWprivate_1.1
end

# PSARC/1998/452; Bug 4181371; NSS Lookup Control END

function	_get_exit_frame_monitor
declaration	void * _get_exit_frame_monitor(void)
version		SUNWprivate_1.1
end

# Bugid 4296198, had to move code from libnsl/nis/cache/cache_api.cc

function	__nis_get_environment
declaration	void __nis_get_environment(void)
version		SUNWprivate_1.1
end

# PSARC 2003/266: C99 complex arithmetic support routines

function	_F_cplx_div
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_F_cplx_div_ix
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_F_cplx_div_rx
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_F_cplx_lr_div
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_F_cplx_lr_div_ix
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_F_cplx_lr_div_rx
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_F_cplx_mul
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_D_cplx_div
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_D_cplx_div_ix
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_D_cplx_div_rx
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_D_cplx_lr_div
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_D_cplx_lr_div_ix
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_D_cplx_lr_div_rx
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_D_cplx_mul
#Declaration	/* Unknown. */
version		SUNWprivate_1.1
end

function	_Q_cplx_div
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_Q_cplx_div_ix
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_Q_cplx_div_rx
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_Q_cplx_lr_div
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_Q_cplx_lr_div_ix
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_Q_cplx_lr_div_rx
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_Q_cplx_lr_mul
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_Q_cplx_mul
#Declaration	/* Unknown. */
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end

function	_X_cplx_div
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_X_cplx_div_ix
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_X_cplx_div_rx
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_X_cplx_lr_div
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_X_cplx_lr_div_ix
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_X_cplx_lr_div_rx
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	_X_cplx_mul
#Declaration	/* Unknown. */
arch		i386 amd64
version		i386=SUNWprivate_1.1 amd64=SUNWprivate_1.1
end

function	__udivdi3
#Declaration	/* Unknown. */
arch		sparc i386
version		SUNWprivate_1.1
end

function	__umoddi3
#Declaration	/* Unknown. */
arch		sparc i386
version		SUNWprivate_1.1
end

function	__divdi3
#Declaration	/* Unknown. */
arch		sparc i386
version		SUNWprivate_1.1
end

function	__moddi3
#Declaration	/* Unknown. */
arch		sparc i386
version		SUNWprivate_1.1
end

function	__muldi3
#Declaration	/* Unknown. */
arch		sparc
version		SUNWprivate_1.1
end

function	__cmpdi2
#Declaration	/* Unknown. */
arch		sparc
version		SUNWprivate_1.1
end

function	__ucmpdi2
#Declaration	/* Unknown. */
arch		sparc
version		SUNWprivate_1.1
end

function	__floatdidf
#Declaration	/* Unknown. */
arch		sparc
version		SUNWprivate_1.1
end

function	__floatdisf
#Declaration	/* Unknown. */
arch		sparc
version		SUNWprivate_1.1
end

function	__ashldi3
#Declaration	/* Unknown. */
arch		sparc
version		SUNWprivate_1.1
end

function	__ashrdi3
#Declaration	/* Unknown. */
arch		sparc
version		SUNWprivate_1.1
end

function	__lshrdi3
#Declaration	/* Unknown. */
arch		sparc
version		SUNWprivate_1.1
end

# PSARC/2000/492 UNIX03 project
# Bugid 4850735, functions needed to support printf/scanf variable
# sized u/intmax_t for 32-bit libc

function	_fprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_printf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_snprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_sprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vfprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vsnprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vsprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_fwprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_swprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_wprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vfwprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vswprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vwprintf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_fscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_scanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_sscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vfscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vsscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_fwscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_swscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_wscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vfwscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vswscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	_vwscanf_c89
arch		sparc i386
version		SUNWprivate_1.1
end

function	__fseterror_u
version		SUNWprivate_1.1
end

function	_file_set
arch		sparc i386
version		SUNWprivate_1.1
end
