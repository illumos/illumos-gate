#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# include global definitions
include ../../../Makefile.master

#
# Build everything in parallel; use .WAIT for dependencies
.PARALLEL: $(SUBDIRS)

SUBDIRS= clnt srv

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
_msg :=		TARGET= _msg

.KEEP_STATE:

all clean clobber install _msg: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
