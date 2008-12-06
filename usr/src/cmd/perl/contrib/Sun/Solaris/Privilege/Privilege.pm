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
# Privilege.pm provides the bootstrap for the Sun::Solaris::Privilege module.
#

require 5.8.4;
use strict;
use warnings;

package Sun::Solaris::Privilege;

our $VERSION = '1.3';

use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

our (@EXPORT_OK, %EXPORT_TAGS);
my @constants = qw(PRIV_STR_SHORT PRIV_STR_LIT PRIV_STR_PORT PRIV_ON PRIV_OFF
	PRIV_SET PRIV_AWARE PRIV_DEBUG);
my @syscalls = qw(setppriv getppriv setpflags getpflags);
my @libcalls = qw(priv_addset priv_copyset priv_delset
    priv_emptyset priv_fillset priv_intersect priv_inverse priv_ineffect
    priv_isemptyset priv_isequalset priv_isfullset priv_ismember
    priv_issubset priv_union priv_set_to_str priv_str_to_set priv_gettext);
my @variables = qw(%PRIVILEGES %PRIVSETS);

my @private = qw(priv_getsetbynum priv_getbynum);

use vars qw(%PRIVILEGES %PRIVSETS);

#
# Dynamically gather all the privilege and privilege set names; they are
# generated in Privileges.xs::BOOT.
#
push @constants, keys %PRIVILEGES, keys %PRIVSETS;

@EXPORT_OK = (@constants, @syscalls, @libcalls, @private, @variables);
%EXPORT_TAGS = (CONSTANTS => \@constants, SYSCALLS => \@syscalls,
    LIBCALLS => \@libcalls, PRIVATE => \@private, VARIABLES => \@variables,
    ALL => \@EXPORT_OK);

our @ISA = qw(Exporter);

1;
__END__
