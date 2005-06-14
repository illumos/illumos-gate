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

function	setkey
version		SUNW_1.1
filter		libc.so.1
end		

function	encrypt
version		SUNW_1.1
filter		libc.so.1
end		

function	crypt
version		SUNW_1.1
filter		libc.so.1
end		

function	des_setkey
include		<crypt.h>
declaration	void des_setkey(const char *key)
version		SUNWprivate_1.1
end		

function	run_setkey
include		<crypt.h>
declaration	int run_setkey(int *p, const char *keyparam)
version		SUNWprivate_1.1
end		

function	run_crypt
include		<crypt.h>
declaration	int run_crypt(long offset, char *buffer, unsigned int count, int *p)
version		SUNWprivate_1.1
end		

function	makekey
declaration	int makekey(int *b)
version		SUNWprivate_1.1
exception	$return == -1
end		

function	crypt_close_nolock
version		SUNWprivate_1.1
end		

function	crypt_close
declaration	int crypt_close(int *p)
version		SUNWprivate_1.1
end		

function	des_encrypt
declaration	void des_encrypt(char *block, int edflag)
version		SUNWprivate_1.1
end		

function	des_crypt
declaration	char *des_crypt(const char *pw, const char *salt)
version		SUNWprivate_1.1
end		

#
# weak interfaces
#

function	_lib_version
version		SUNWprivate_1.1
end		

function	_setkey
version		SUNWprivate_1.1
filter		libc.so.1
end		

function	_encrypt
version		SUNWprivate_1.1
filter		libc.so.1
end		

function	_crypt
version		SUNWprivate_1.1
filter		libc.so.1
end		

function	_run_setkey
weak		run_setkey
version		SUNWprivate_1.1
end		

function	_run_crypt
weak		run_crypt
version		SUNWprivate_1.1
end		

function	_crypt_close
weak		crypt_close
version		SUNWprivate_1.1
end		

function	_makekey
weak		makekey
version		SUNWprivate_1.1
end		

function	_des_setkey
weak		des_setkey
version		SUNWprivate_1.1
end		

function	_des_encrypt
weak		des_encrypt
version		SUNWprivate_1.1
end		

function	_des_crypt
weak		des_crypt
version		SUNWprivate_1.1
end		

function        des_setparity
version         SUNWprivate_1.1
end

function        ecb_crypt
version         SUNWprivate_1.1
end

function        cbc_crypt
version         SUNWprivate_1.1
end

function	des_encrypt1
version		SUNWprivate_1.1
end		

function	_des_encrypt1
version		SUNWprivate_1.1
end		

function	__des_crypt
version		SUNWprivate_1.1
end		

function	_des_decrypt1
version		SUNWprivate_1.1
end		
