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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Catalog.pm contains perl code for exacct catalog tag manipulation.
# 

require 5.6.1;
use strict;
use warnings;

package Sun::Solaris::Exacct::Catalog;

our $VERSION = '1.3';
use Carp;
use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

# %_Constants and @_Constants are set up by the XSUB bootstrap() function.
our (@EXPORT_OK, %EXPORT_TAGS, @_Constants, %_Constants);
@EXPORT_OK = @_Constants;
%EXPORT_TAGS = (CONSTANTS => \@_Constants, ALL => \@EXPORT_OK);

use base qw(Exporter);

#
# Class interface.
#

#
# Register a foreign catalog.  Arguments are as follows:
#    <catalog prefix>	Used to uniquely identify the catalog being defined.
#			Must be composed only of uppercase characters.
#    <catalog id>	Numeric identifier for the catalog.
#			Must be between 1 and 15.
#    <export flag>	If true, the constants defined by the register sub will
#			be exported into the caller's namespace.
#    <id list>		List of (name, value) pairs.  These are prefixed with
#			"<catalog_prefix>_" and are used for defining constants
#			that can be used as catalog id field values.
# An example:
#    Sun::Solaris::Exacct::Catalog->register("FROB", 0x01, 1,
#        FLUB => 0x00000001, WURB => 0x00000010)
# results in the definition of the following constants:
#    EXC_FROB	0x01 << 24
#    FROB_FLUB	0x00000001
#    FROB_WURB  0x00000010
#
# Returns 'undef' on success, otherwise an error message.
#
sub register
{
	my ($class, $cat_pfx, $cat_id, $export, %idlist) = @_;

	# Sanity checks.
	my $cat = 'EXC_'. $cat_pfx;
	return ("Invalid catalog prefix \"$cat_pfx\"")
	    if ($cat_pfx !~ /^[A-Z][A-Z0-9]*$/ || $cat_pfx =~ /^EX[TCD]$/);
	return ("Duplicate catalog prefix")
	    if (exists($_Constants{catlg}{name}{$cat}));
	my $id = $cat_id << 24;
	return ("Invalid catalog id \"$cat_id\"")
	    if ($cat_id < 1 || $cat_id > 0xf);   # 4-bit field
	
	# Validate the (name, value) pairs.
	my %seen;
	while (my ($n, $v) = each(%idlist)) {
		return ("Invalid id name \"$n\"")
		    if ($n !~ /^[A-Z][A-Z0-9_]*[A-Z0-9]$/);
		return ("Invalid id value \"$v\"")
		    if ($v < 0 || $v > 0xffffff);   # 24-bit field
		return ("Redefinition of id value \"$v\"")
		    if ($seen{$v}++);
	}
	undef(%seen);

	# Initialise new lookup data members
	$_Constants{catlg}{name}{$cat} = $id;
	$_Constants{catlg}{value}{$id} = $cat;
	my $id_by_name = $_Constants{id}{name}{$cat_pfx}{name}  = {};
	my $id_by_val  = $_Constants{id}{name}{$cat_pfx}{value} = {};
	$_Constants{id}{value}{$id} = $_Constants{id}{name}{$cat_pfx};

	# Put the passed (name, value) pairs into the appropriate hashes.
	my @export_ok = ($cat);
	while (my ($n, $v) = each(%idlist)) {
		my $pn = "${cat_pfx}_${n}";
		$id_by_name->{$pn} = $v;
		$id_by_val->{$v}  = $pn;
		push(@export_ok, $pn);
	}

	# Export the new symbols into the caller's namespace if required.
	if ($export) {
		our (%EXPORT, @EXPORT_OK);
		@EXPORT{@export_ok} = (1) x @export_ok;
		push(@EXPORT_OK, @export_ok);
		__PACKAGE__->export_to_level(1, undef, @export_ok);
	}
}

#
# Create a new Catalog object.  Arguments are either an integer, an existing
# Catalog object or a (type, catalog, id) triplet.
#
sub new
{
	my ($class, @vals) = @_;
	my $value;

	# A single value must be a full catalog tag 
	if (@vals == 1) {
		$value = _catalog_value($vals[0]);

	# A list of 3 values is (type, catalog, id)
	} elsif (@vals == 3) {
		my ($t, $c, $d) = @vals;
		my ($which);

		$which = _is_iv($t) ? 'value' : 'name';
		croak("Invalid data type \"$t\"")
		    if (! exists($_Constants{type}{$which}{$t}));
		$t = $_Constants{type}{name}{$t} if ($which eq 'name');

		$which = _is_iv($c) ? 'value' : 'name';
		croak("Invalid catalog \"$c\"")
		    if (! exists($_Constants{catlg}{$which}{$c}));
		$c = $_Constants{catlg}{name}{$c} if ($which eq 'name');

		$which = _is_iv($d) ? 'value' : 'name';
		croak("Invalid data id \"$d\"")
		    if (! exists($_Constants{id}{value}{$c}{$which}{$d}));
		$d = $_Constants{id}{value}{$c}{name}{$d} if ($which eq 'name');

		$value = $t | $c | $d;

	# Only 1 or 3 arguments are valid
	} else {
		croak("Invalid number of arguments");
	}

	# Create a readonly catalog object.
	return (_new_catalog($value));
}

#
# Object interface.
#

#
# Get the value of a Catalog object.  In a scalar context it returns the 32-bit
# integer representing the tag.  In a list context it returns a
# (type, catalog, id) triplet.  Each of these is a dual-typed SV that in a
# string context returns a representation of the appropriate constant, e.g.
# 'EXD_HOSTNAME', and in a numeric context returns the integer value of the
# associated constant.
#
sub value
{
	my ($self) = @_;

	# In an array context return the split out catalog components
	if (wantarray()) {
		my $t = $$self & &EXT_TYPE_MASK;
		$t = _double_type($t, exists($_Constants{type}{value}{$t})
		    ? $_Constants{type}{value}{$t}
		    : 'UNKNOWN_TYPE');

		my $c = $$self & &EXC_CATALOG_MASK;
		$c = _double_type($c,
		    exists($_Constants{catlg}{value}{$c})
		    ? $_Constants{catlg}{value}{$c}
		    : 'UNKNOWN_CATALOG');

		my $d = $$self & &EXD_DATA_MASK;
		$d = _double_type($d,
		    exists($_Constants{id}{value}{int($c)}{value}{$d})
		    ? $_Constants{id}{value}{int($c)}{value}{$d}
		    : 'UNKNOWN_ID');

		return($t, $c, $d);

	# In a scalar context return the whole thing
	} else {
		return($$self);
	}
}

#
# Fetch the type field of the Catalog object.  The return value is a dual-typed
# SV that in a string context returns a representation of the appropriate
# constant, e.g. 'EXT_STRING', and in a numeric context returns the integer
# value of the associated constant.
#
sub type
{
	my ($self) = @_;

	# Extract the type field and look up the string representation.
	my $t = $$self & &EXT_TYPE_MASK;
	$t = _double_type($t, exists($_Constants{type}{value}{$t})
	    ? $_Constants{type}{value}{$t} : 'UNKNOWN_TYPE');
	return ($t);
}

#
# Fetch the catalog field of the Catalog object.  (see type()).
#
sub catalog
{
	my ($self, $val) = @_;

	# Extract the catalog field and look up the string representation.
	my $c = $$self & &EXC_CATALOG_MASK;
	$c = _double_type($c, exists($_Constants{catlg}{value}{$c})
	    ? $_Constants{catlg}{value}{$c} : 'UNKNOWN_CATALOG');
	return ($c);
}

#
# Fetch the id field of the Catalog object.  (see type()).
#
sub id
{
	my ($self, $val) = @_;

	#
	# Extract the catalog and id field and look up the
	# string representation of the id field.
	#
	my $c = $$self & &EXC_CATALOG_MASK;
	my $d = $$self & &EXD_DATA_MASK;
	$d = _double_type($d, exists($_Constants{id}{value}{$c}{value}{$d})
	    ? $_Constants{id}{value}{$c}{value}{$d} : 'UNKNOWN_ID');
	return ($d);
}

#
# Return a string representation of the type field.
#
sub type_str
{
	my ($self) = @_;

	# Lookup the type and fabricate a string from it.
	my $t = $$self & &EXT_TYPE_MASK;
	if (exists($_Constants{type}{value}{$t})) {
		$t = $_Constants{type}{value}{$t};
		$t =~ s/^EXT_//;
		$t =~ s/_/ /g;
		return(lc($t));
	} else {
		return('UNKNOWN TYPE');
	}
}

#
# Return a string representation of the catalog field.
#
sub catalog_str
{
	my ($self) = @_;

	# Lookup the catalog and fabricate a string from it.
	my $c = $$self & &EXC_CATALOG_MASK;
	if (exists($_Constants{catlg}{value}{$c})) {
		$c = $_Constants{catlg}{value}{$c};
		$c =~ s/^EXC_//;
		$c =~ s/_/ /g;
		return(lc($c));
	} else {
		return('UNKNOWN CATALOG');
	}
}

#
# Return a string representation of the id field.
#
sub id_str
{
	my ($self) = @_;

	# Lookup the id and fabricate a string from it.
	my $c = $$self & &EXC_CATALOG_MASK;
	my $d = $$self & &EXD_DATA_MASK;
	if (exists($_Constants{id}{value}{$c}) &&
	    exists($_Constants{id}{value}{$c}{value}{$d})) {
		$d = $_Constants{id}{value}{$c}{value}{$d};
		$d =~ s/^[A-Z]+_//;
		$d =~ s/_/ /g;
		return(lc($d));
	} else {
		return('UNKNOWN ID');
	}
}

#
# AUTOLOAD for constant definitions.  Values are looked up in the %_Constants
# hash, and then used to create an anonymous sub that will return the correct
# value.  This is then placed into the appropriate symbol table so that future
# calls will bypass the AUTOLOAD and call the sub directly.
#
sub AUTOLOAD
{
	# Extract the name of the constant we are looking for, and its prefix.
	our $AUTOLOAD;
	my $const = $AUTOLOAD;
	$const =~ s/.*:://;
	my ($prefix) = $const =~ /^([^_]+)/;

	# Try to find the appropriate prefix hash.
	my $href;
	if ($prefix eq 'EXT') {
		$href = $_Constants{type}{name};
	} elsif ($prefix eq 'EXC') {
		$href = $_Constants{catlg}{name};
	} elsif (exists($_Constants{id}{name}{$prefix})) {
		$href = $_Constants{id}{name}{$prefix}{name};
	}

	# Look first in the prefix hash, otherwise try the 'other' hash.
	my $val = undef;
	if (exists($href->{$const})) {
		$val = $href->{$const};
	} elsif (exists($_Constants{other}{name}{$const})) {
		$val = $_Constants{other}{name}{$const};
	}

	#
	# Generate the const sub,  place in the appropriate glob
	# and finally goto it to return the value.
	#
	croak("Undefined constant \"$const\"") if (! defined($val));
	my $sub = sub { return $val; };
	no strict qw(refs);
	*{$AUTOLOAD} = $sub;
	goto &$sub;
}

#
# To quieten AUTOLOAD - if this isn't defined AUTLOAD will be called
# unnecessarily during object destruction.
#
sub DESTROY
{
}

1;
