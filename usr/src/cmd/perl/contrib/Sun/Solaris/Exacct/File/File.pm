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
# File.pm contains wrappers for the exacct file manipulation routines.
# 

require 5.8.4;
use strict;
use warnings;

package Sun::Solaris::Exacct::File;

our $VERSION = '1.3';
use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

# @_Constants is set up by the XSUB bootstrap() function.
our (@EXPORT_OK, %EXPORT_TAGS, @_Constants);
@EXPORT_OK = @_Constants;
%EXPORT_TAGS = (CONSTANTS => \@_Constants, ALL => \@EXPORT_OK);

use base qw(Exporter);

#
# Extend the default Exporter::import to do optional inclusion of the
# Fcntl module.
#
sub import
{
	# Do the normal export processing for this module.
	__PACKAGE__->export_to_level(1, @_);

	# Export from Fcntl if the tag is ':ALL'
	if (grep(/^:ALL$/, @_)) {
		require Fcntl;
		Fcntl->export_to_level(1, undef, ':DEFAULT');
	}
}

1;
