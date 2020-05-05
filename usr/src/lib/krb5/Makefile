#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# include global definitions
include ../../Makefile.master

#
# Build everything in parallel; use .WAIT for dependencies
.PARALLEL:

SUBDIRS= \
	dyn	\
	.WAIT	\
	kdb	\
	.WAIT	\
	kadm5	\
	.WAIT	\
	ss	\
	plugins

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

.KEEP_STATE:

all install clean clobber _msg: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
