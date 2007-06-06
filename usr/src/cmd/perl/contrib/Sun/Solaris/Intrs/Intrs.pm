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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Intrs.pm provides the bootstrap for the private Sun::Solaris::Intrs module.
#

package Sun::Solaris::Intrs;

use strict;
use warnings;
use Exporter;
use DynaLoader;
use vars qw($VERSION @ISA @EXPORT_OK);

our @ISA = qw(Exporter DynaLoader);
our @EXPORT_OK = qw(intrmove is_pcplusmp);
our $VERSION = '0.02';

bootstrap Sun::Solaris::Intrs $VERSION;
1;
