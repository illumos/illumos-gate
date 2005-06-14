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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/sgs/libelf/spec/weak.spec

function	_elf_begin
weak		elf_begin
version		SUNWprivate_1.1
end		

function	_elf_memory
weak		elf_memory
version		SUNWprivate_1.1
end		

function	_elf_cntl
weak		elf_cntl
version		SUNWprivate_1.1
end		

function	_elf_end
weak		elf_end
version		SUNWprivate_1.1
end		

function	_elf_errno
weak		elf_errno
version		SUNWprivate_1.1
end		

function	_elf_errmsg
weak		elf_errmsg
version		SUNWprivate_1.1
end		

function	_elf_fill
weak		elf_fill
version		SUNWprivate_1.1
end		

function	_elf_flagdata
weak		elf_flagdata
version		SUNWprivate_1.1
end		

function	_elf_flagehdr
weak		elf_flagehdr
version		SUNWprivate_1.1
end		

function	_elf_flagelf
weak		elf_flagelf
version		SUNWprivate_1.1
end		

function	_elf_flagphdr
weak		elf_flagphdr
version		SUNWprivate_1.1
end		

function	_elf_flagscn
weak		elf_flagscn
version		SUNWprivate_1.1
end		

function	_elf_flagshdr
weak		elf_flagshdr
version		SUNWprivate_1.1
end		

function	_elf_getarhdr
weak		elf_getarhdr
version		SUNWprivate_1.1
end		

function	_elf_getarsym
weak		elf_getarsym
version		SUNWprivate_1.1
end		

function	_elf_getbase
weak		elf_getbase
version		SUNWprivate_1.1
end		

function	_elf_getdata
weak		elf_getdata
version		SUNWprivate_1.1
end		

function	_elf32_getehdr
weak		elf32_getehdr
version		SUNWprivate_1.1
end		

function	_elf_getident
weak		elf_getident
version		SUNWprivate_1.1
end		

function	_elf32_getphdr
weak		elf32_getphdr
version		SUNWprivate_1.1
end		

function	_elf_getscn
weak		elf_getscn
version		SUNWprivate_1.1
end		

function	_elf32_getshdr
weak		elf32_getshdr
version		SUNWprivate_1.1
end		

function	_elf_hash
weak		elf_hash
version		SUNWprivate_1.1
end		

function	_elf_kind
weak		elf_kind
version		SUNWprivate_1.1
end		

function	_elf_ndxscn
weak		elf_ndxscn
version		SUNWprivate_1.1
end		

function	_elf_newdata
weak		elf_newdata
version		SUNWprivate_1.1
end		

function	_elf32_newehdr
weak		elf32_newehdr
version		SUNWprivate_1.1
end		

function	_elf32_newphdr
weak		elf32_newphdr
version		SUNWprivate_1.1
end		

function	_elf_newscn
weak		elf_newscn
version		SUNWprivate_1.1
end		

function	_elf_next
weak		elf_next
version		SUNWprivate_1.1
end		

function	_elf_nextscn
weak		elf_nextscn
version		SUNWprivate_1.1
end		

function	_elf_rand
weak		elf_rand
version		SUNWprivate_1.1
end		

function	_elf_rawdata
weak		elf_rawdata
version		SUNWprivate_1.1
end		

function	_elf_rawfile
weak		elf_rawfile
version		SUNWprivate_1.1
end		

function	_elf_strptr
weak		elf_strptr
version		SUNWprivate_1.1
end		

function	_elf_update
weak		elf_update
version		SUNWprivate_1.1
end		

function	_elf32_fsize
weak		elf32_fsize
version		SUNWprivate_1.1
end		

function	_elf32_xlatetof
weak		elf32_xlatetof
version		SUNWprivate_1.1
end		

function	_elf32_xlatetom
weak		elf32_xlatetom
version		SUNWprivate_1.1
end		

function	_elf_version
weak		elf_version
version		SUNWprivate_1.1
end		

