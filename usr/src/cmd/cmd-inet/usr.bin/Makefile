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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2011 Nexenta Systems, Inc. All rights reserved.
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2022 Garrett D'Amore
#

PROG=		finger rdate ruptime rwho whois
SUIDPROG=	rcp rlogin rsh
ALL=		$(PROG) $(SUIDPROG)
SRCS=		$(ALL:%=%.c)
KCMDPROGS=	rcp rlogin rsh

SUBDIRS=	chat dns-sd ftp nc netstat \
		pppd pppdump pppstats rdist talk telnet tftp
SUBDIR1=	talk
MSGSUBDIRS=	talk

# As programs get lint-clean, add them here.  Eventually.
# This hack should go away, and all in PROG should be lint-clean.
# NB: This still applies to enabling compiler warnings and is not lint specific
LINTCLEAN=	rlogin.c rsh.c rcp.c rdate.c rwho.c whois.c

include ../../Makefile.cmd
include ../Makefile.cmd-inet

COMMONOBJS=	kcmd.o
COMMONPOFILES=	$(COMMONOBJS:.o=.po)
COMMONSRCS=	$(CMDINETCOMMONDIR)/$(COMMONOBJS:.o=.c)

POFILES=	rlogin.po rsh.po rcp.po $(COMMONPOFILES)
POFILE=		usr.bin.po

CLOBBERFILES +=	$(ALL)
CLEANFILES +=	kcmd.o rcp.o rlogin.o rsh.o

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
_msg:=		TARGET= _msg

ROOTSUIDPROG=	$(SUIDPROG:%=$(ROOTBIN)/%)
$(ROOTSUIDPROG)	:=	FILEMODE=	04555

CPPFLAGS +=	-DSYSV -DSTRNET -DBSD_COMP -I$(CMDINETCOMMONDIR)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-unused-function

ruptime :=     SMOFF += leaks

# Eventually just plain CFLAGS should be += -v, but not until all in
# PROGS are lint clean.
$(LINTCLEAN)	:=	CFLAGS += $(CCVERBOSE)

finger :=	CFLAGS += $(CCVERBOSE)
# Enable large file support for reading the lastlog file.
finger :=	CPPFLAGS += -D_FILE_OFFSET_BITS=64

finger :=		LDLIBS += -lnsl -lcurses -lsocket
rcp :=		LDLIBS += -lsocket -lsec -lsendfile
rdate:=	LDLIBS += -lsocket
rlogin :=	LDLIBS += -lnsl -lsocket
rsh :=		LDLIBS += -lsocket
whois :=	LDLIBS += -lsocket

include  $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5
$(KCMDPROGS)	:=	LDLIBS += -lnsl -lmech_krb5
$(KCMDPROGS)	:=	LDFLAGS += $(ZIGNORE) $(KRUNPATH) \
				-L$(ROOT)$(KLIBDIR_DO) \
				-L$(ROOT)$(KLIBDIR_GL)

$(COMMONPOFILES) \
rlogin.po rcp.po rsh.po \
$(KCMDPROGS) :=	CPPFLAGS += -DKERBEROS \
			-I$(CMDINETCOMMONDIR) \
			-I$(SRC)/lib/gss_mechs/mech_krb5 \
			-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
			-I$(SRC)/lib/gss_mechs/mech_krb5/include \
			-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5

ROOTSUNWRCP=	$(ROOT)/usr/lib/sunw,rcp
ROOTRSHSYMLINK=	$(ROOT)/usr/ucb/rsh
ROOTREMSHSYMLINK=$(ROOT)/usr/bin/remsh

.KEEP_STATE:

all: $(ALL) $(SUBDIRS)

install: all .WAIT $(ROOTPROG) $(ROOTSUIDPROG) \
	$(SUBDIRS) $(ROOTSUNWRCP) $(ROOTRSHSYMLINK) $(ROOTREMSHSYMLINK)

# Messaging - copy $POFILES to $POFILE to work with the parent directory
# Makefile's '_msg' target.
#
_msg: $(MSGSUBDIRS) $(POFILES)
	$(RM) $(POFILE)
	$(CAT) $(POFILES)	> $(POFILE)

$(COMMONPOFILES): $(COMMONSRCS)
	$(COMPILE.cpp) $(COMMONSRCS) > $(@:.po=.c).i
	$(XGETTEXT) $(XGETFLAGS) $(@:.po=.c).i
	$(RM) $@
	sed "/^domain/d" < messages.po  > $@
	$(RM) messages.po $(@:.po=.c).i

$(COMMONOBJS): $(COMMONSRCS)
	$(COMPILE.c) $(COMMONSRCS)

rlogin: rlogin.o $(COMMONOBJS)
	$(LINK.c) $@.o $(COMMONOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

rcp: rcp.o $(COMMONOBJS)
	$(LINK.c) $@.o $(COMMONOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

rsh: rsh.o $(COMMONOBJS)
	$(LINK.c) $@.o $(COMMONOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTSUNWRCP):
	$(RM) $@; $(SYMLINK) ../bin/rcp $@

$(ROOTRSHSYMLINK):
	$(RM) $@; $(SYMLINK) ../bin/rsh $@

$(ROOTREMSHSYMLINK):
	$(RM) $@; $(SYMLINK) rsh $@

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

clean: $(SUBDIRS) clean_local
clean_local:
	$(RM) $(CLEANFILES)

clobber: $(SUBDIRS) clobber_local
clobber_local: clean_local
	$(RM) $(CLOBBERFILES)

