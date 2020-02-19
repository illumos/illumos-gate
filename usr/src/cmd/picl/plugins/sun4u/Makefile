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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2019 Peter Tribble.
#
# cmd/picl/plugins/sun4u/Makefile
#

include $(SRC)/Makefile.master

SUBDIRS= lib .WAIT envmon .WAIT \
	frudata grover excalibur psvc littleneck daktari \
	cherrystone lw2plus lw8 taco enchilada chicago mpxu ents \
	chalupa silverstone sebring schumacher seattle boston .WAIT

MSGSUBDIRS=	lib frudata grover excalibur psvc littleneck daktari \
	cherrystone lw2plus lw8 taco enchilada chicago envmon mpxu ents \
	silverstone sebring

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg

.KEEP_STATE:

all install clean clobber lint : $(SUBDIRS)

_msg:	$(MSGSUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
