#
# Copyright (c) 2002, 2008, Oracle and/or its affiliates. All rights reserved.
#

#
# Task.pm provides the bootstrap for the Sun::Solaris::Task module.
#

require 5.8.4;
use strict;
use warnings;

package Sun::Solaris::Task;

our $VERSION = '1.4';
use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

our (@EXPORT_OK, %EXPORT_TAGS);
my @constants = qw(TASK_NORMAL TASK_FINAL TASK_PROJ_PURGE);
my @syscalls = qw(settaskid gettaskid);
@EXPORT_OK = (@constants, @syscalls);
%EXPORT_TAGS = (CONSTANTS => \@constants, SYSCALLS => \@syscalls,
    ALL => \@EXPORT_OK);

use base qw(Exporter);

1;
