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

data		___Argv 
version		SUNWprivate_1.1
binding		nodirect
end		

data		__ctype_mask 
version		SUNWprivate_1.1
end		

data		__environ_lock 
version		SUNWprivate_1.1
binding		nodirect
end		

data		__i_size 
version		SUNWprivate_1.1
end		

data		__inf_read 
version		SUNWprivate_1.1
end		

data		__inf_written 
version		SUNWprivate_1.1
end		

data		__lc_charmap 
version		SUNWprivate_1.1
end		

data		__lc_collate 
version		SUNWprivate_1.1
end		

data		__lc_ctype 
version		SUNWprivate_1.1
end		

data		__lc_locale 
version		SUNWprivate_1.1
end		

data		__lc_messages 
version		SUNWprivate_1.1
end		

data		__lc_monetary 
version		SUNWprivate_1.1
end		

data		__lc_numeric 
version		SUNWprivate_1.1
end		

data		__lc_time 
version		SUNWprivate_1.1
end		

data		__libc_threaded
version		SUNWprivate_1.1
end

data		__lyday_to_month 
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end		

data		__malloc_lock 
version		SUNWprivate_1.1
end		

data		__mon_lengths 
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end		

data		__nan_read 
version		SUNWprivate_1.1
end		

data		__nan_written 
version		SUNWprivate_1.1
end		

data		__threaded 
version		SUNWprivate_1.1
end		

data		__trans_lower 
version		SUNWprivate_1.1
end		

data		__trans_upper 
version		SUNWprivate_1.1
end		

data		__xpg6
version		SUNWprivate_1.1
binding		nodirect
end

data		__yday_to_month 
arch		sparc sparcv9
version		sparc=SUNWprivate_1.1 sparcv9=SUNWprivate_1.1
end		

data		_cswidth 
version		SUNWprivate_1.1
end		

data		_lib_version 
version		SUNWprivate_1.1
binding		nodirect
end		

data		_lone extends libc/spec/sys.spec lone
weak		lone 
version		SUNWprivate_1.1 
end		

data		_lten extends libc/spec/sys.spec lten
weak		lten 
version		SUNWprivate_1.1 
end		

data		_lzero extends libc/spec/sys.spec lzero
weak		lzero 
version		SUNWprivate_1.1 
end		

data		_nss_default_finders 
weak		nss_default_finders
version		SUNWprivate_1.1 
end		

data		_smbuf 
version		SUNWprivate_1.1
end		

data		_sp 
version		SUNWprivate_1.1
end		

# this is almost certainly consumed by the fortran run-time
# as well as mdb.

data		_sse_hw
arch		i386
version		SUNWprivate_1.1
end

data		_sys_errlist 
arch		i386 sparc
version		i386=SUNWprivate_1.1 sparc=SUNWprivate_1.1
end		

data		_sys_errs 
arch		i386 sparc
version		i386=SUNWprivate_1.1 sparc=SUNWprivate_1.1
end		

data		_sys_index 
arch		i386 sparc
version		i386=SUNWprivate_1.1 sparc=SUNWprivate_1.1
end		

data		_sys_nerr 
arch		i386 sparc
version		i386=SUNWprivate_1.1 sparc=SUNWprivate_1.1
end		

data		_sys_num_err 
arch		i386 sparc
version		i386=SUNWprivate_1.1 sparc=SUNWprivate_1.1
end		

# tdb_bootstrap and uberdata are consumed by libc_db. Forcing them into the
# dynsym allows debuggers to work with libc's text and no symtab.

data		_tdb_bootstrap
version		SUNWprivate_1.1
end

data		_uberdata
version		SUNWprivate_1.1
end

# Bugid 4296198, had to move these from libnsl/nis/cache/cache_api.cc BEGIN

data		__nis_debug_bind
version		SUNWprivate_1.1
end

data		__nis_debug_calls
version		SUNWprivate_1.1
end

data		__nis_debug_file
version		SUNWprivate_1.1
end

data		__nis_debug_rpc
version		SUNWprivate_1.1
end

data		__nis_prefsrv
version		SUNWprivate_1.1
end

data		__nis_preftype
version		SUNWprivate_1.1
end

data		__nis_server
version		SUNWprivate_1.1
end

# Bugid 4296198, had to move these from libnsl/nis/cache/cache_api.cc END
