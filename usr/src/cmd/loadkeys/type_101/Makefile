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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# cmd/loadkeys/type_101/Makefile

KEYTABLES = \
	canadian_french2 \
	czech \
	denmark \
	france \
	germany \
	greece \
	hungary \
	italy \
	j3100 \
	japan \
	korea \
	latvia \
	lithuania \
	netherlands \
	norway \
	poland \
	portugal \
	reset \
	russia \
	spain \
	sweden \
	swiss_french \
	swiss_german \
	traditional_chinese \
	turkey \
	uk \
	us

include ../../Makefile.cmd

ROOTKEYTABLESDIR= $(ROOTSHLIB)/keytables
ROOTKEYDIR= $(ROOTKEYTABLESDIR)/type_101
ROOTKEYTABLES= $(KEYTABLES:%=$(ROOTKEYDIR)/%)

# there is an install target for each ROOT layout link
#
LAYOUTS= \
	layout_00 \
	layout_01 \
	layout_22 \
	layout_23 \
	layout_24 \
	layout_25 \
	layout_26 \
	layout_27 \
	layout_28 \
	layout_29 \
	layout_2a \
	layout_2b \
	layout_2c \
	layout_2d \
	layout_2e \
	layout_2f \
	layout_30 \
	layout_31 \
	layout_32 \
	layout_33 \
	layout_34 \
	layout_35 \
	layout_36 \
	layout_37 \
	layout_38 \
	layout_39 \
	layout_3b \
	layout_3e9

ROOTLINKS= $(LAYOUTS:%=$(ROOTKEYDIR)/%)

$(ROOTKEYTABLES) := FILEMODE = 444

# install rule
$(ROOTKEYDIR)/%: %
	$(INS.file)

.KEEP_STATE:

all:  $(KEYTABLES)

install: all $(ROOTKEYTABLESDIR) $(ROOTKEYDIR) $(ROOTKEYTABLES) $(ROOTLINKS)

clean:

neaten:
	for i in $(KEYTABLES); do		\
		sh ./neaten.sh $$i;		\
		if cmp -s $$i $$i.neat; then	\
			echo No change to $$i.;	\
			rm $$i.neat;		\
		fi;				\
	done

$(ROOTKEYTABLESDIR):
	$(INS.dir)

$(ROOTKEYDIR): $(ROOTKEYTABLESDIR)
	$(INS.dir)

# install targets for ROOT layout links
#
$(ROOTKEYDIR)/layout_00: $(ROOTKEYDIR)/us
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us $@

$(ROOTKEYDIR)/layout_01:	$(ROOTKEYDIR)/us
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us $@

$(ROOTKEYDIR)/layout_22:	$(ROOTKEYDIR)/j3100
	$(RM) $@; $(LN) $(ROOTKEYDIR)/j3100 $@

$(ROOTKEYDIR)/layout_23:	$(ROOTKEYDIR)/france
	$(RM) $@; $(LN) $(ROOTKEYDIR)/france $@

$(ROOTKEYDIR)/layout_24:	$(ROOTKEYDIR)/denmark
	$(RM) $@; $(LN) $(ROOTKEYDIR)/denmark $@

$(ROOTKEYDIR)/layout_25:	$(ROOTKEYDIR)/germany
	$(RM) $@; $(LN) $(ROOTKEYDIR)/germany $@

$(ROOTKEYDIR)/layout_26:	$(ROOTKEYDIR)/italy
	$(RM) $@; $(LN) $(ROOTKEYDIR)/italy $@

$(ROOTKEYDIR)/layout_27:	$(ROOTKEYDIR)/netherlands
	$(RM) $@; $(LN) $(ROOTKEYDIR)/netherlands $@

$(ROOTKEYDIR)/layout_28:	$(ROOTKEYDIR)/norway
	$(RM) $@; $(LN) $(ROOTKEYDIR)/norway $@

$(ROOTKEYDIR)/layout_29:	$(ROOTKEYDIR)/portugal
	$(RM) $@; $(LN) $(ROOTKEYDIR)/portugal $@

$(ROOTKEYDIR)/layout_2a:	$(ROOTKEYDIR)/spain
	$(RM) $@; $(LN) $(ROOTKEYDIR)/spain $@

$(ROOTKEYDIR)/layout_2b:	$(ROOTKEYDIR)/sweden
	$(RM) $@; $(LN) $(ROOTKEYDIR)/sweden $@

$(ROOTKEYDIR)/layout_2c:	$(ROOTKEYDIR)/swiss_french
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_french $@

$(ROOTKEYDIR)/layout_2d:	$(ROOTKEYDIR)/swiss_german
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_german $@

$(ROOTKEYDIR)/layout_2e:	$(ROOTKEYDIR)/uk
	$(RM) $@; $(LN) $(ROOTKEYDIR)/uk $@

$(ROOTKEYDIR)/layout_2f:	$(ROOTKEYDIR)/korea
	$(RM) $@; $(LN) $(ROOTKEYDIR)/korea $@

$(ROOTKEYDIR)/layout_30:	$(ROOTKEYDIR)/traditional_chinese
	$(RM) $@; $(LN) $(ROOTKEYDIR)/traditional_chinese $@

$(ROOTKEYDIR)/layout_31:	$(ROOTKEYDIR)/japan
	$(RM) $@; $(LN) $(ROOTKEYDIR)/japan $@

$(ROOTKEYDIR)/layout_32:	$(ROOTKEYDIR)/canadian_french2
	$(RM) $@; $(LN) $(ROOTKEYDIR)/canadian_french2 $@

$(ROOTKEYDIR)/layout_33:	$(ROOTKEYDIR)/hungary
	$(RM) $@; $(LN) $(ROOTKEYDIR)/hungary $@

$(ROOTKEYDIR)/layout_34:	$(ROOTKEYDIR)/poland
	$(RM) $@; $(LN) $(ROOTKEYDIR)/poland $@

$(ROOTKEYDIR)/layout_35:	$(ROOTKEYDIR)/czech
	$(RM) $@; $(LN) $(ROOTKEYDIR)/czech $@

$(ROOTKEYDIR)/layout_36:	$(ROOTKEYDIR)/russia
	$(RM) $@; $(LN) $(ROOTKEYDIR)/russia $@

$(ROOTKEYDIR)/layout_37:	$(ROOTKEYDIR)/latvia
	$(RM) $@; $(LN) $(ROOTKEYDIR)/latvia $@

$(ROOTKEYDIR)/layout_38:	$(ROOTKEYDIR)/turkey
	$(RM) $@; $(LN) $(ROOTKEYDIR)/turkey $@

$(ROOTKEYDIR)/layout_39:	$(ROOTKEYDIR)/greece
	$(RM) $@; $(LN) $(ROOTKEYDIR)/greece $@

$(ROOTKEYDIR)/layout_3b:	$(ROOTKEYDIR)/lithuania
	$(RM) $@; $(LN) $(ROOTKEYDIR)/lithuania $@

$(ROOTKEYDIR)/layout_3e9:	$(ROOTKEYDIR)/us
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us $@

include ../../Makefile.targ
