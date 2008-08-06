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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Exacct.pm contains wrappers for the exacct error functions and syscalls,
# and some 'shorthand' convenience functions.
# 

require 5.6.1;
use strict;
use warnings;

package Sun::Solaris::Exacct;

our $VERSION = '1.5';
use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

# @_Constants is set up by the XSUB bootstrap() function.
our (@EXPORT_OK, %EXPORT_TAGS, @_Constants);
my @syscalls = qw(getacct putacct wracct);
my @libcalls = qw(ea_error ea_error_str);
my @shorthand = qw(ea_register_catalog ea_new_catalog ea_new_file ea_new_item
    ea_new_group ea_dump_object);
@EXPORT_OK = (@_Constants, @syscalls, @libcalls, @shorthand);
%EXPORT_TAGS = (CONSTANTS => \@_Constants, SYSCALLS => \@syscalls,
    LIBCALLS => \@libcalls, SHORTHAND => \@shorthand, ALL => \@EXPORT_OK);

use base qw(Exporter);

#
# Extend the default Exporter::import to do optional inclusion of all the
# lower-level Exacct modules.  Any export tag prefixed with 'EXACCT_' is
# interpreted as a request to import that tag from all the Exacct modules.
#
sub import
{
	my (@my_tags, %sub_tags);
	shift(@_);
	foreach my $tag (@_) {
		# Note: Modifies @_
		if ($tag =~ /^:EXACCT_(.*)$/) {
			my $new_tag = ":$1";
			push(@my_tags, $new_tag);
			$sub_tags{$new_tag} = 1;
		} else {
			push(@my_tags, $tag);
		}
	}

	# Export the taglist with all "EXACCT_" prefixes removed.
	__PACKAGE__->export_to_level(1, undef, @my_tags);

	# Do sub-module imports if required.
	if (@my_tags = grep(exists($sub_tags{$_}), qw(:ALL :CONSTANTS))) {

		# ::Catalog
		require Sun::Solaris::Exacct::Catalog;
		Sun::Solaris::Exacct::Catalog->export_to_level(1, undef,
		    @my_tags);

		# ::File and Fcntl
		require Sun::Solaris::Exacct::File;
		Sun::Solaris::Exacct::File->export_to_level(1, undef,
		    @my_tags);
		require Fcntl;
		Fcntl->export_to_level(1, undef, ':DEFAULT');

		# ::Object
		require Sun::Solaris::Exacct::Object;
		Sun::Solaris::Exacct::Object->export_to_level(1, undef,
		    @my_tags);
	}
}

#
# Convenience functions - shorthand for fully qualified method names.  Note that
# goto() is used to call the methods so that any errors will appear to come
# from the correct place.  Because goto() does not understand method call syntax
# it is necessary to fake up the class a parameter by unshifting the appropriate
# class name onto the argument lists.
#

sub ea_register_catalog
{
	unshift(@_, 'Sun::Solaris::Exacct::Catalog');
	goto(&Sun::Solaris::Exacct::Catalog::register);
}

sub ea_new_catalog
{
	unshift(@_, 'Sun::Solaris::Exacct::Catalog');
	goto(&Sun::Solaris::Exacct::Catalog::new);
}

sub ea_new_file
{
	unshift(@_, 'Sun::Solaris::Exacct::File');
	goto(&Sun::Solaris::Exacct::File::new);
}

sub ea_new_item
{
	unshift(@_, 'Sun::Solaris::Exacct::Item');
	goto(&Sun::Solaris::Exacct::Object::Item::new);
}

sub ea_new_group
{
	unshift(@_, 'Sun::Solaris::Exacct::Group');
	goto(&Sun::Solaris::Exacct::Object::Group::new);
}

sub ea_dump_object
{
	unshift(@_, 'Sun::Solaris::Exacct::Object');
	goto(&Sun::Solaris::Exacct::Object::dump);
}

1;
