#
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# Privilege.pm provides the bootstrap for the Sun::Solaris::Privilege module.
#

require 5.8.4;
use strict;
use warnings;

package Sun::Solaris::Privilege;

our $VERSION = '1.4';

use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

our (@EXPORT_OK, %EXPORT_TAGS);
my @constants = qw(PRIV_STR_SHORT PRIV_STR_LIT PRIV_STR_PORT PRIV_ON PRIV_OFF
	PRIV_SET PRIV_AWARE PRIV_AWARE_RESET PRIV_DEBUG PRIV_PFEXEC
	PRIV_XPOLICY NET_MAC_AWARE NET_MAC_AWARE_INHERIT __PROC_PROTECT);
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
