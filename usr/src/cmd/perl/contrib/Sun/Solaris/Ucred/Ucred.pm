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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Ucred.pm provides the bootstrap for the Sun::Solaris::Ucred module.
#

require 5.8.4;
use strict;
use warnings;

package Sun::Solaris::Ucred;

our $VERSION = '1.3';
use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

our (@EXPORT_OK, %EXPORT_TAGS);
my @syscalls = qw(getpeerucred ucred_get);
my @libcalls = qw(ucred_geteuid ucred_getruid ucred_getsuid ucred_getegid
	ucred_getrgid ucred_getsgid ucred_getgroups ucred_getprivset
	ucred_getpflags ucred_getpid ucred_getzoneid ucred_getprojid);

@EXPORT_OK = (@syscalls, @libcalls);
%EXPORT_TAGS = (SYSCALLS => \@syscalls, LIBCALLS => \@libcalls,
		ALL => \@EXPORT_OK);

require Exporter;

use base qw(Exporter Sun::Solaris::Privilege);

use Sun::Solaris::Utils qw(gettext);

1;
__END__
