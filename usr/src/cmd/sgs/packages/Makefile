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
# Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

include		$(SRC)/Makefile.master
include		$(SRC)/cmd/sgs/Makefile.var

BUILDLOG=	package_build.$(MACH).log

MACHS:sh=	if [ "$MACH" = "sparc" ]; \
		then echo "sparc sparcv9"; \
		elif [ "$MACH" = "i386" ]; \
		then echo "i386 amd64"; \
		else echo "unknown"; \
		fi

RDBDIRS=	$(MACHS:%=../librtld_db/demo/%)
LDMAKEDIRS=	$(MACHS:%=../libldmake/%)

SUBDIRS1=	../libconv \
		.WAIT \
		../libdl \
		.WAIT \
		../libelf \
		.WAIT \
		../liblddbg \
		../librtld_db \
		.WAIT \
		../librtld \
		../libcrle

SUBDIRS2 =	../rtld \
		../rtld.4.x \
		../libldstab \
		../lari \
		../ldprof \
		../lddstub \
		$(LDMAKEDIRS) \
		../0@0 \
		../tools \
		$(RDBDIRS)

#
# Package dirs are directories which specifically
# have a 'package' target.  This target is used to key
# off of whether a system build is performed
# or a SUNWonld build.
#
PKGDIRS=	../libcrle \
		../libld \
		../elfdump \
		../elfedit \
		../elfedit/modules \
		../elfwrap \
		../ar \
		../crle \
		../dump \
		../lari \
		../ld \
		../ldd \
		../ldprof \
		../nm \
		../mcs \
		../moe \
		../pvs

$(SUBDIRS1) $(SUBDIRS2) :=	TARGET = install
$(PKGDIRS) :=	TARGET = package

../%:		FRC
		@ cd $@; pwd; $(MAKE) $(TARGET)

.KEEP_STATE_FILE: .make.state.$(MACH)
.KEEP_STATE:
.PARALLEL:	$(SUBDIRS1) $(PKGDIRS) $(SUBDIRS2)

all clean clobber install: FRC
		@ cd $(MACH); pwd; $(MAKE) $@

#
# invoke `package' to build this package from scratch.  It will
# perform make install in the directories that contains components
# that this package is dependent upon
#
package:	FRC
	@/bin/time $(MAKE) package_build 2>&1 | tee $(BUILDLOG)
	@ echo "===BUILD COMPLETED  checking for warnings...==="
	@ grep -i "warning:" $(BUILDLOG) | grep -v PSTAMP | cat
	@ echo "==================done========================="

package_build:	package_dep .WAIT package_chkmsg .WAIT install

package_chkmsg:	FRC
		@ cd ..; pwd; $(MAKE) chkmsg

package_dep:	package_dep_ .WAIT $(SUBDIRS1) .WAIT \
	$(PKGDIRS) .WAIT $(SUBDIRS2)

package_dep_:	FRC
		@ cd ../tools; pwd; $(MAKE) proto && ./proto $(RELEASE)
		@ cd $(SRC)/common/mapfiles/gen ; pwd; $(MAKE) install
		@ cd $(SRC)/head; pwd; $(MAKE) \
			$(ROOT)/usr/include/dlfcn.h \
			$(ROOT)/usr/include/gelf.h \
			$(ROOT)/usr/include/libelf.h \
			$(ROOT)/usr/include/proc_service.h \
			$(ROOT)/usr/include/rtld_db.h \
			$(ROOT)/usr/include/link.h
		@ cd $(SRC)/lib/libproc; pwd; $(MAKE) install_h
		@ cd $(SRC)/uts/common/sys; pwd; $(MAKE) \
			$(ROOT)/usr/include/sys/elf.h \
			$(ROOT)/usr/include/sys/elf_386.h \
			$(ROOT)/usr/include/sys/elf_SPARC.h \
			$(ROOT)/usr/include/sys/elf_notes.h \
			$(ROOT)/usr/include/sys/elf_amd64.h \
			$(ROOT)/usr/include/sys/elftypes.h \
			$(ROOT)/usr/include/sys/auxv.h \
			$(ROOT)/usr/include/sys/auxv_SPARC.h \
			$(ROOT)/usr/include/sys/auxv_386.h \
			$(ROOT)/usr/include/sys/avl.h \
			$(ROOT)/usr/include/sys/link.h \
			$(ROOT)/usr/include/sys/machelf.h \
			$(ROOT)/usr/include/sys/note.h \
			$(ROOT)/usr/include/sys/systeminfo.h
		@ cd ../tools/$(MACH); pwd; $(MAKE) sgsmsg piglatin
		@ cd ..; pwd; $(MAKE) _msg_sgsmsg
		@ cd ..; pwd; $(MAKE) native-add
		@ cd ../libconv; pwd; $(MAKE) all
		@ cd ../link_audit; pwd; $(MAKE) package
		@ cd ../messages/$(MACH); pwd; $(MAKE) test

FRC:
