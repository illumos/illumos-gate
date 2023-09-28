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

LIBRARY =	libscf.a
VERS =		.1

OBJECTS =		\
	error.o		\
	lowlevel.o	\
	midlevel.o	\
	notify_params.o	\
	highlevel.o	\
	scf_tmpl.o	\
	scf_type.o

include $(SRC)/lib/Makefile.lib

LIBS = $(DYNLIB)

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off
