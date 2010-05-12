#
# Copyright (c) 2004, 2008, Oracle and/or its affiliates. All rights reserved.
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
