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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Object.pm contains perl code for exacct object manipulation.
#

require 5.8.4;
use strict;
use warnings;

package Sun::Solaris::Exacct::Object;

our $VERSION = '1.3';
use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

our (@EXPORT_OK, %EXPORT_TAGS, @_Constants);
@EXPORT_OK = @_Constants;
%EXPORT_TAGS = (CONSTANTS => \@_Constants, ALL => \@EXPORT_OK);

use base qw(Exporter);
use Sun::Solaris::Exacct::Catalog qw(:CONSTANTS);

#
# Class methods
#

#
# Dump an exacct object to the specified filehandle, or STDOUT by default.
#
sub dump
{
	# Fettle parameters.
	my ($class, $obj, $fh, $indent) = @_;
	$fh ||= \*STDOUT;
	$indent ||= 0;
	my $istr = '  ' x $indent;
	
	# Check for undef values.
	if (! defined($obj)) {
		print $fh ($istr, "UNDEFINED_VALUE\n");
		return;
	}

	# Deal with items.
	my @cat = $obj->catalog()->value();
	if ($obj->type() == &EO_ITEM) {
		printf $fh ("%sITEM\n%s  Catalog = %s|%s|%s\n", 
		   $istr, $istr, @cat);
		$indent++;
		my $val = $obj->value();

		# Recursively dump nested objects.
		if (ref($val)) {
			$class->dump($val, $fh, $indent);

		# Just print out items.
		} else {
			$val = unpack('H*', $val) if ($cat[0] == &EXT_RAW);
			printf $fh ("%s  Value = %s\n", $istr, $val);
		}

	# Deal with groups.
	} else {
		printf $fh ("%sGROUP\n%s  Catalog = %s|%s|%s\n",
		    $istr, $istr, @cat);
		$indent++;
		foreach my $val ($obj->value()) {
			$class->dump($val, $fh, $indent);
		}
		printf $fh ("%sENDGROUP\n", $istr);
	}
}

#
# Item subclass - establish inheritance.
#
package Sun::Solaris::Exacct::Object::Item;
use base qw(Sun::Solaris::Exacct::Object);

#
# Group subclass - establish inheritance.
#
package Sun::Solaris::Exacct::Object::Group;
use base qw(Sun::Solaris::Exacct::Object);

#
# Tied array used for holding a group's items.
#
package Sun::Solaris::Exacct::Object::_Array;
use Carp;

#
# Check the passed list of arguments are derived from ::Object
#
sub check_args
{
	my @duff;
	foreach my $i (@_) {
		push(@duff, $i)
		    if (! UNIVERSAL::isa($i, 'Sun::Solaris::Exacct::Object'));
	}
	if (@duff) {
		local $Carp::CarpLevel = 2;
		croak('"', join('", "', @duff), @duff == 1 ? '" is' : '" are',
		    ' not of type Sun::Solaris::Exacct::Object');
	}
}

#
# Tied hash access methods
#
sub TIEARRAY 
{ 
	return(bless([], $_[0]));
}

sub FETCHSIZE
{
	return(scalar(@{$_[0]}));
}             

sub STORESIZE
{
	$#{$_[0]} = $_[1] - 1;
}  

sub STORE
{
	check_args($_[2]);
	return($_[0]->[$_[1]] = copy_xs_ea_objects($_[2]));
}

sub FETCH
{
	return($_[0]->[$_[1]]);
}

sub CLEAR
{
	@{$_[0]} = ();
}

sub POP
{
	return(pop(@{$_[0]}));
} 

sub PUSH
{
	my $a = shift(@_);
	check_args(@_);
	push(@$a, copy_xs_ea_objects(@_));
}

sub SHIFT
{
	return(shift(@{$_[0]}));
} 

sub UNSHIFT
{
	my $a = shift(@_);
	check_args($_[2]);
	return(unshift(@$a, copy_xs_ea_objects(@_)));
} 

sub EXISTS
{
	return(exists($_[0]->[$_[1]]));
}

sub DELETE
{
	return(delete($_[0]->[$_[1]]));
}

sub EXTEND
{
}

sub SPLICE
{
	my $a = shift(@_);                    
 	my $sz = scalar(@$a);
	my $off = @_ ? shift(@_) : 0;
	$off += $sz if $off < 0;
	my $len = @_ ? shift : $sz - $off;
	check_args(@_);
	return(splice(@$a, $off, $len, copy_xs_ea_objects(@_)));
}

1;
