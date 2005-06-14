#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright (c) 2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME		=> 'Sun::Solaris::BSM::_BSMparse',
    VERSION_FROM	=> '_BSMparse.pm',
    clean		=> {
	FILES	=> '_BSMparse.po'
    }
);

sub MY::postamble {
	'
PO_OBJ		= _BSMparse.po
PO_SRC		= _BSMparse.pm
XGETTEXT	= xgettext

$(PO_OBJ): $(PO_SRC)
	$(XGETTEXT) -d $(PO_OBJ) $(PO_SRC)

_msg: $(MSGDOMAIN) $(PO_OBJ)
	$(RM) $(MSGDOMAIN)/$(PO_OBJ)
	$(CP) $(PO_OBJ) $(MSGDOMAIN)

$(MSGDOMAIN):
	$(INS.dir)

';
}
