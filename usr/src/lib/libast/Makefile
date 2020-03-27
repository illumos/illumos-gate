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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

SHELL=/usr/bin/ksh93

include		../Makefile.lib

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
_msg :=		TARGET= _msg

.KEEP_STATE:

all clean clobber install _msg: $(SUBDIRS)

LIBRARY=	libast.a

HDRS=	\
	align.h \
	ast_botch.h \
	ast_ccode.h \
	ast_common.h \
	ast_dir.h \
	ast_dirent.h \
	ast_fcntl.h \
	ast_float.h \
	ast_fs.h \
	ast_getopt.h \
	ast_iconv.h \
	ast_lib.h \
	ast_limits.h \
	ast_map.h \
	ast_mmap.h \
	ast_mode.h \
	ast_namval.h \
	ast_ndbm.h \
	ast_nl_types.h \
	ast_param.h \
	ast_standards.h \
	ast_std.h \
	ast_stdio.h \
	ast_sys.h \
	ast_time.h \
	ast_tty.h \
	ast_version.h \
	ast_vfork.h \
	ast_wait.h \
	ast_wchar.h \
	ast_windows.h \
	ast.h \
	bytesex.h \
	ccode.h \
	cdt.h \
	debug.h \
	dirent.h \
	dt.h \
	endian.h \
	error.h \
	find.h \
	fnmatch.h \
	fnv.h \
	fs3d.h \
	fts.h \
	ftw.h \
	ftwalk.h \
	getopt.h \
	glob.h \
	hash.h \
	hashkey.h \
	hashpart.h \
	iconv.h \
	ip6.h \
	lc.h \
	ls.h \
	magic.h \
	magicid.h \
	mc.h \
	mime.h \
	mnt.h \
	modecanon.h \
	modex.h \
	namval.h \
	nl_types.h \
	option.h \
	preroot.h \
	proc.h \
	prototyped.h \
	re_comp.h \
	recfmt.h \
	regex.h \
	regexp.h \
	sfdisc.h \
	sfio_s.h \
	sfio_t.h \
	sfio.h \
	shcmd.h \
	sig.h \
	stack.h \
	stak.h \
	stdio.h \
	stk.h \
	swap.h \
	tar.h \
	times.h \
	tm.h \
	tmx.h \
	tok.h \
	tv.h \
	usage.h \
	vdb.h \
	vecargs.h \
	vmalloc.h \
	wait.h \
	wchar.h \
	wordexp.h

HDRDIR32= $(MACH)/include/ast
HDRDIR64= $(MACH64)/include/ast
include ../Makefile.asthdr

install_h: $(ROOTHDRS)

# We don't check these header files because they're owned by AT&T/AST
check:

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
