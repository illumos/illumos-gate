#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# BSD 3 Clause License
#
# Copyright (c) 2007, The Storage Networking Industry Association.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 	- Redistributions of source code must retain the above copyright
#	  notice, this list of conditions and the following disclaimer.
#
# 	- Redistributions in binary form must reproduce the above copyright
#	  notice, this list of conditions and the following disclaimer in
#	  the documentation and/or other materials provided with the
#	  distribution.
#
#	- Neither the name of The Storage Networking Industry Association (SNIA)
#	  nor the names of its contributors may be used to endorse or promote
#	  products derived from this software without specific prior written
#	  permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
LIBRARY= libndmp.a
VERS= .1
OBJECTS= libndmp.o libndmp_error.o libndmp_door_data.o libndmp_prop.o libndmp_base64.o

include ../../Makefile.lib

SRCDIR =	../common
INCS += -I$(SRCDIR)
INCS += -I$(SRC)/cmd/ndmpd/include

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all
LIBS=	$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc -lscf
CPPFLAGS +=	$(INCS) -D_REENTRANT

CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	-_gcc=-Wno-uninitialized

SRCS=	$(OBJECTS:%.o=$(SRCDIR)/%.c)
$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ
