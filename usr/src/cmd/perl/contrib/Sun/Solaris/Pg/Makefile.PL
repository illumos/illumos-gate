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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

require 5.8.4;
use strict;
use warnings;
use ExtUtils::MakeMaker;

# #defines.
my @defines = ( DEFINE => exists($ENV{RELEASE_BUILD}) ? '-DNDEBUG' : '' );

# List of POD pages to install.
my @man3pods = ( MAN3PODS => {} );


#
# If not building as part of ON.
#
if (! exists($ENV{CODEMGR_WS})) {

	#
	# Suppress the setting of LD_RUN_PATH.  The ON build environment
	# contains a modified MakeMaker that does this automatically, so we
	# only need to do this if we are building outside of ON.
	#
	package MY;
	no warnings qw(once);

	#
	# Install the POD documentation for non-ON builds.
	#
	my $man3pfx = '$(INST_MAN3DIR)/Sun::Solaris::Pg';
	@man3pods = (
	    MAN3PODS => { 'pod/Pg.pod' => $man3pfx . '.$(MAN3EXT)' }
	);
}

WriteMakefile(
    NAME              => 'Sun::Solaris::Pg',
    VERSION_FROM      => 'Pg.pm',
    @man3pods,
);
