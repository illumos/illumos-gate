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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2011, 2016 by Delphix. All rights reserved.
#

LIBRARY = libdtrace.a
VERS = .1

LIBSRCS = \
	dt_aggregate.c \
	dt_as.c \
	dt_buf.c \
	dt_cc.c \
	dt_cg.c \
	dt_consume.c \
	dt_decl.c \
	dt_dis.c \
	dt_dof.c \
	dt_error.c \
	dt_errtags.c \
	dt_sugar.c \
	dt_handle.c \
	dt_ident.c \
	dt_inttab.c \
	dt_link.c \
	dt_list.c \
	dt_open.c \
	dt_options.c \
	dt_program.c \
	dt_map.c \
	dt_module.c \
	dt_names.c \
	dt_parser.c \
	dt_pcb.c \
	dt_pid.c \
	dt_pq.c \
	dt_pragma.c \
	dt_print.c \
	dt_printf.c \
	dt_proc.c \
	dt_provider.c \
	dt_regset.c \
        dt_string.c \
	dt_strtab.c \
	dt_subr.c \
	dt_work.c \
	dt_xlator.c

LIBISASRCS = \
	dt_isadep.c

OBJECTS = dt_lex.o dt_grammar.o $(MACHOBJS) $(LIBSRCS:%.c=%.o) $(LIBISASRCS:%.c=%.o)

DRTISRCS = dlink_init.c dlink_common.c
DRTIOBJS = $(DRTISRCS:%.c=pics/%.o)
DRTIOBJ = drti.o

LIBDAUDITSRCS = dlink_audit.c dlink_common.c
LIBDAUDITOBJS = $(LIBDAUDITSRCS:%.c=pics/%.o)
LIBDAUDIT = libdtrace_forceload.so

DLINKSRCS = dlink_common.c dlink_init.c dlink_audit.c

DLIBSRCS += \
	errno.d \
	fc.d \
	io.d \
	ip.d \
	iscsit.d \
	net.d \
	nfs.d \
	nfssrv.d \
	procfs.d \
	regs.d \
	sched.d \
	signal.d \
	scsi.d \
	srp.d \
	sysevent.d \
	tcp.d \
	udp.d \
	unistd.d

include ../../Makefile.lib

SRCS = $(LIBSRCS:%.c=../common/%.c) $(LIBISASRCS:%.c=../$(MACH)/%.c) 
LIBS = $(DYNLIB) $(LINTLIB)

SRCDIR = ../common

CLEANFILES += dt_lex.c dt_grammar.c dt_grammar.h y.output
CLEANFILES += ../common/procfs.sed ../common/procfs.d
CLEANFILES += ../common/io.sed ../common/io.d
CLEANFILES += ../common/ip.sed ../common/ip.d
CLEANFILES += ../common/net.sed ../common/net.d
CLEANFILES += ../common/errno.d ../common/signal.d
CLEANFILES += ../common/dt_errtags.c ../common/dt_names.c
CLEANFILES += ../common/sysevent.sed ../common/sysevent.d
CLEANFILES += ../common/tcp.sed ../common/tcp.d
CLEANFILES += ../common/udp.sed ../common/udp.d
CLEANFILES += $(LIBDAUDITOBJS) $(DRTIOBJS)

CLOBBERFILES += $(LIBDAUDIT) drti.o

CPPFLAGS += -I../common -I.
CFLAGS += $(CCVERBOSE) $(C_BIGPICFLAGS)
CFLAGS64 += $(CCVERBOSE) $(C_BIGPICFLAGS)

CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-switch

YYCFLAGS =
LDLIBS += -lgen -lproc -lrtld_db -lnsl -lsocket -lctf -lelf -lc
DRTILDLIBS = $(LDLIBS.lib) -lc
LIBDAUDITLIBS = $(LDLIBS.lib) -lmapmalloc -lc -lproc

yydebug := YYCFLAGS += -DYYDEBUG

$(LINTLIB) := SRCS = $(SRCDIR)/$(LINTSRC)

LFLAGS = -t -v
YFLAGS = -d -v

ROOTDLIBDIR = $(ROOT)/usr/lib/dtrace
ROOTDLIBDIR64 = $(ROOT)/usr/lib/dtrace/64

ROOTDLIBS = $(DLIBSRCS:%=$(ROOTDLIBDIR)/%)
ROOTDOBJS = $(ROOTDLIBDIR)/$(DRTIOBJ) $(ROOTDLIBDIR)/$(LIBDAUDIT)
ROOTDOBJS64 = $(ROOTDLIBDIR64)/$(DRTIOBJ) $(ROOTDLIBDIR64)/$(LIBDAUDIT)

$(ROOTDLIBDIR)/%.d := FILEMODE=444
$(ROOTDLIBDIR)/%.o := FILEMODE=444
$(ROOTDLIBDIR64)/%.o :=	FILEMODE=444
$(ROOTDLIBDIR)/%.so := FILEMODE=555
$(ROOTDLIBDIR64)/%.so := FILEMODE=555

.KEEP_STATE:

all: $(LIBS) $(DRTIOBJ) $(LIBDAUDIT)

lint: lintdlink lintcheck

lintdlink: $(DLINKSRCS:%.c=../common/%.c)
	$(LINT.c) $(DLINKSRCS:%.c=../common/%.c) $(DRTILDLIBS)

dt_lex.c: $(SRCDIR)/dt_lex.l dt_grammar.h
	$(LEX) $(LFLAGS) $(SRCDIR)/dt_lex.l > $@

dt_grammar.c dt_grammar.h: $(SRCDIR)/dt_grammar.y
	$(YACC) $(YFLAGS) $(SRCDIR)/dt_grammar.y
	@mv y.tab.h dt_grammar.h
	@mv y.tab.c dt_grammar.c

pics/dt_lex.o pics/dt_grammar.o := CFLAGS += $(YYCFLAGS)
pics/dt_lex.o pics/dt_grammar.o := CFLAGS64 += $(YYCFLAGS)

pics/dt_lex.o pics/dt_grammar.o := CERRWARN += -erroff=E_STATEMENT_NOT_REACHED
pics/dt_lex.o pics/dt_grammar.o := CCVERBOSE =

../common/dt_errtags.c: ../common/mkerrtags.sh ../common/dt_errtags.h
	sh ../common/mkerrtags.sh < ../common/dt_errtags.h > $@

../common/dt_names.c: ../common/mknames.sh $(SRC)/uts/common/sys/dtrace.h
	sh ../common/mknames.sh < $(SRC)/uts/common/sys/dtrace.h > $@

../common/errno.d: ../common/mkerrno.sh $(SRC)/uts/common/sys/errno.h
	sh ../common/mkerrno.sh < $(SRC)/uts/common/sys/errno.h > $@

../common/signal.d: ../common/mksignal.sh $(SRC)/uts/common/sys/iso/signal_iso.h
	sh ../common/mksignal.sh < $(SRC)/uts/common/sys/iso/signal_iso.h > $@

../common/%.sed: ../common/%.sed.in
	$(COMPILE.cpp) -D_KERNEL $< | tr -d ' ' | tr '"' '@' | \
	    sed 's/\&/\\\&/g' | grep '^s/' > $@

../common/procfs.d: ../common/procfs.sed ../common/procfs.d.in
	sed -f ../common/procfs.sed < ../common/procfs.d.in > $@

../common/io.d: ../common/io.sed ../common/io.d.in
	sed -f ../common/io.sed < ../common/io.d.in > $@

../common/ip.d: ../common/ip.sed ../common/ip.d.in
	sed -f ../common/ip.sed < ../common/ip.d.in > $@

../common/net.d: ../common/net.sed ../common/net.d.in
	sed -f ../common/net.sed < ../common/net.d.in > $@

../common/sysevent.d: ../common/sysevent.sed ../common/sysevent.d.in
	sed -f ../common/sysevent.sed < ../common/sysevent.d.in > $@

../common/tcp.d: ..//common/tcp.sed ../common/tcp.d.in
	sed -f ../common/tcp.sed < ../common/tcp.d.in > $@

../common/udp.d: ../common/udp.sed ../common/udp.d.in
	sed -f ../common/udp.sed < ../common/udp.d.in > $@

pics/%.o: ../$(MACH)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../$(MACH)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

$(DRTIOBJ): $(DRTIOBJS)
	$(LD) -o $@ -r -Blocal -Breduce $(DRTIOBJS)
	$(POST_PROCESS_O)

$(LIBDAUDIT): $(LIBDAUDITOBJS)
	$(LINK.c) -o $@ $(GSHARED) -h$(LIBDAUDIT) $(ZTEXT) $(ZDEFS) $(BDIRECT) \
	    $(MAPFILE.PGA:%=-M%) $(MAPFILE.NED:%=-M%) $(LIBDAUDITOBJS) \
	    $(LIBDAUDITLIBS)
	$(POST_PROCESS_SO)

$(ROOTDLIBDIR):
	$(INS.dir)

$(ROOTDLIBDIR64): $(ROOTDLIBDIR)
	$(INS.dir)

$(ROOTDLIBDIR)/%.d: ../common/%.d
	$(INS.file)

$(ROOTDLIBDIR)/%.d: ../$(MACH)/%.d
	$(INS.file)

$(ROOTDLIBDIR)/%.d: %.d
	$(INS.file)

$(ROOTDLIBDIR)/%.o: %.o
	$(INS.file)

$(ROOTDLIBDIR64)/%.o: %.o
	$(INS.file)

$(ROOTDLIBDIR)/%.so: %.so
	$(INS.file)

$(ROOTDLIBDIR64)/%.so: %.so
	$(INS.file)

$(ROOTDLIBS): $(ROOTDLIBDIR)

$(ROOTDOBJS): $(ROOTDLIBDIR)

$(ROOTDOBJS64): $(ROOTDLIBDIR64)

include ../../Makefile.targ
