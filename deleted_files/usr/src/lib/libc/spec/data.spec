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

data		__ctype extends libc/spec/sys.spec _ctype
weak		_ctype 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

data		__huge_val 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

data		__iob #extends libc/spec/stdio.spec _iob
weak		_iob 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

data		__loc1 
version		SUNW_1.1
end

data		__xpg4 
version		SUNW_0.8
binding		nodirect
end

data		_altzone extends libc/spec/sys.spec altzone
weak		altzone 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

data		_bufendtab 
arch		sparc	i386
version		SUNW_0.7
end

data		_daylight extends libc/spec/sys.spec daylight
weak		daylight 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

data		_environ extends libc/spec/sys.spec environ
weak		environ 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
binding		nodirect
end

data		_iob 
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

data		_lastbuf 
arch		i386 sparc
version		i386=SUNW_0.7 sparc=SUNW_0.7
end

data		_numeric 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

data		_sibuf 
version		SUNW_0.7
end

data		_sobuf 
version		SUNW_0.7
end

data		_sys_buslist 
version		SUNW_0.7
end

data		_sys_cldlist 
version		SUNW_0.7
end

data		_sys_fpelist 
version		SUNW_0.7
end

data		_sys_illlist 
version		SUNW_0.7
end

data		_sys_nsig 
arch		sparc	i386
version		SUNW_0.7
end

data		_sys_segvlist 
version		SUNW_0.7
end

data		_sys_siginfolistp 
version		SUNW_0.7
end

data		_sys_siglist 
version		SUNW_0.7
end

data		_sys_siglistn 
version		SUNW_0.7
end

data		_sys_siglistp 
version		SUNW_0.7
end

data		_sys_traplist 
version		SUNW_0.7
end

data		_timezone extends  libc/spec/sys.spec timezone
weak		timezone 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

data		_tzname extends  libc/spec/sys.spec tzname
weak		tzname 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

data		errno 
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

data		getdate_err 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

function	_getdate_err
weak		getdate_err
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

data		nss_default_finders 
version		SUNW_0.7 
end

data		optarg 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

data		opterr 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

data		optind 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

data		optopt 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
end

data		sys_errlist 
arch		i386 sparc
version		SUNW_0.7 
end

data		sys_nerr 
arch		i386 sparc
version		SUNW_0.7 
end

