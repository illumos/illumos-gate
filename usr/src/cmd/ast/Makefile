#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

# Note that these AST components deliver installed headers to /usr/include/ast/
# but nothing else in gate depends on these to build, and serveral of them are
# auto-generated. The install_h target is deliberately not wired into
# 'cmdheaders' in usr/src/Makefile as that would significantly increase the
# time taken to run the 'setup' target. Instead, sub-components automatically
# install header files as part of the 'install' target.

include $(SRC)/Makefile.master

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg
install :=	TARGET= install
install_h :=	TARGET= install_h
# The _feature target is used to initially populate and to update the
# FEATURE files for each component. It is not run as part of a normal
# build.
_feature :=	TARGET= _feature install

SUBDIRS= \
	tools \
	libast \
	libcmd \
	libdll \
	libpp \
	libshell \
	libsum \
	ksh \
	msgcc \
	shcomp

.KEEP_STATE:
.PARALLEL: $(SUBDIRS)

all clean clobber install install_h _msg _feature: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

libast:		tools
libcmd:		libsum libast
libdll:		libast
libpp:		libast
libshell:	libast libcmd libdll
libsum:		libast

shcomp:		libshell
msgcc:		libast libpp
ksh:		libshell shcomp
