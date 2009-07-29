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

include		../../../../Makefile.cmd

SOLBOOKV2 =	solbook.dtd \
		solbook.dcl

SGMLSHLIB =	$(ROOTSHLIB)/sgml
SGMLSHLIBLOCALE =	$(ROOTSHLIB)/sgml/locale
SGMLSHLIBLOCALEC =	$(ROOTSHLIB)/sgml/locale/C
SGMLDTDDIR = 	$(ROOTSHLIB)/sgml/locale/C/dtds
SOLBOOKV2DIR =  $(SGMLDTDDIR)/solbookv2

ROOTSOLBOOKV2 = $(SOLBOOKV2:%=$(SOLBOOKV2DIR)/%)

FILEMODE = 	0644

.KEEP_STATE :

all :		THIRDPARTYLICENSE

install :	all $(SOLBOOKV2DIR) $(ROOTSOLBOOKV2)

clobber:
	$(RM) THIRDPARTYLICENSE

$(SOLBOOKV2DIR) :
		$(INS.dir) 

$(ROOTSOLBOOKV2):
		$(INS.file) $(@F)

# the license text appears multiple times; just grab the first instance.
THIRDPARTYLICENSE: solbook.dtd
	$(SED) -n -e '/HaL Computer/,/warranty/H' -e '/warranty/{x;p;q;}' \
	    solbook.dtd > $@

