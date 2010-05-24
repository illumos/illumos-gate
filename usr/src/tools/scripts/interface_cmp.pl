#!/usr/bin/perl -w
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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# interface_cmp audits two interface definition files (as created by
# interface_check) against one another, and confirms that:
#
#  o	All versioned libraries that were present in the previous interface
#	are present in the new interface
#
#  o	for each non-private interface in a library confirm that no symbols
#	have been removed and that no symbols have been added to it between
#	the two revisions
#
# Return codes:
#
#  0	All interfaces in the new release are identical in old release.
#  1	Something is different refer to the error messages.


use strict;

use POSIX qw(getenv);
use Getopt::Std;
use File::Basename;

#### Define all global variables (required for strict)
use vars  qw($Prog);
use vars  qw(%opt);
use vars  qw(%old_hash %old_alias %new_hash %new_alias);

# Exception Arrays:
#
# The ADDSYM and DELSYM exceptions are maintained on the @AddSymList
# and @DelSymList arrays, respectively. Each array element is a reference
# to a subarray of triples:
#	(sym_re, ver_re, obj_re)
# where each item in the tripple is a regular expression, used to
# match a particular symbol/version/object combination.
#
# The EMPTY_TOPVERSION exceptions are maintained on the @EmptyTopVerList
# array. Each array element is a reference to a subarray of pairs:
#	(ver_re, obj_re)
# where each item in the pair is a regular expression, used to
# match a particular version/object combination.
#
use vars  qw(@AddSymList @DelSymList @EmptyTopVerList);


## LoadExceptions
#
# Locate the exceptions file and process its contents. We can't use
# onbld_elfmod::LoadExceptionsToEXRE() for this, because our exceptions
# need to support more than a single regular expression.
#
# exit:
#	@AddSymList, @DelSymList, and @EmptyTopVerList have been updated
#
# note:
#	We expand strings of the form MACH(dir) to match the given
#	directory as well as any 64-bit architecture subdirectory that
#	might be present (i.e. amd64, sparcv9).
# 
sub LoadExceptions {
	my $file;
	my $Line;
	my $LineNum = 0;
	my $err = 0;

	# Locate the exception file
	FILE: {
		# If -e is specified, that file must be used
		if ($opt{e}) {
			$file = $opt{e};
			last FILE;
		}

		# If this is an activated workspace, use the exception
		# file found in the exceptions_list directory.
		if (defined($ENV{CODEMGR_WS})) {
			$file = "$ENV{CODEMGR_WS}/exception_lists/interface_cmp";
			last FILE if (-f $file);
		}

		# As a final backstop, the SUNWonbld package provides a
		# copy of the exception file. This can be useful if we
		# are being used with an older workspace.
		#
		# This script is installed in the SUNWonbld bin directory,
		# while the exception file is in etc/exception_lists. Find
		# it relative to the script location given by $0.
		$file = dirname($0) . "/../etc/exception_lists/interface_cmp";
		last FILE if (-f $file);
		
		# No exception file was found.
		return;
	}

	open (EFILE, $file) ||
		die "$Prog: unable to open exceptions file: $file";
	while ($Line = onbld_elfmod::GetLine(\*EFILE, \$LineNum)) {
		
		# Expand MACH()
		$Line =~ s/MACH\(([^)]+)\)/$1(\/amd64|\/sparcv9)?/g;

		if ($Line =~ /^DELSYM\s+/) {
		    my ($item, $sym_re, $ver_re, $obj_re) =
			split(/\s+/, $Line, 4);
		    push @DelSymList, [ $sym_re, $ver_re, $obj_re ];
		    next;
		}

		if ($Line =~ /^ADDSYM\s+/) {
		    my ($item, $sym_re, $ver_re, $obj_re) =
			split(/\s+/, $Line, 4);
		    push @AddSymList, [ $sym_re, $ver_re, $obj_re ];
		    next;
		}

		if ($Line =~ /^EMPTY_TOPVERSION\s+/) {
		    my ($item, $ver_re, $obj_re) = split(/\s+/, $Line, 3);
		    push @EmptyTopVerList, [ $ver_re, $obj_re ];
		    next;
		}

		$err++;
		printf(STDERR "$file: Unrecognized option: ".
		    "line $LineNum: $Line\n");
	}
	close EFILE;

	exit 1 if ($err != 0);
}

## ExSym(SymList, sym, ver, obj)
#
# Compare a given symbol/version/object combination against the
# exceptions found in the given list.
#
# entry:
#	SymList - Reference to @AddSymList, or @DelSymList.
#	sym, ver, obj - Combination to be compared against exception list
#
# exit:
#	Returns True (1) if there is a match, and False (0) otherwise.
#
sub ExSym {
	my ($SymList, $sym, $ver, $obj) = @_;

	foreach my $ex (@$SymList) {
		return 1 if ($obj =~ /$$ex[2]/) && ($ver =~ /$$ex[1]/) &&
		    ($sym =~ /$$ex[0]/);
	}

	return 0;
}

## ExTopVer(ver, obj)
#
# Compare a given version/object combination against the pairs found
# in @EmptyTopVerList.
#
# entry:
#	ver, obj - Combination to be compared against empty top version list
#
# exit:
#	Returns True (1) if there is a match, and False (0) otherwise.
#
sub ExTopVer {
	my ($ver, $obj) = @_;

	foreach my $ex (@EmptyTopVerList) {
		return 1 if ($obj =~ /$$ex[1]/) && ($ver =~ /$$ex[0]/);
	}

	return 0;
}

## ExpandInheritance(objhashref)
#
# For each version contained in the specified object hash reference,
# add the inherited symbols.
#
sub ExpandInheritance {
	my $obj = $_[0];

	# Versions to process. Typically, inheriting versions come before
	# the versions they inherit. Processing the list in reverse order
	# maximizes the odds that a needed sub-version will have already
	# have been processed.
	my @vers = reverse(@{$obj->{'VERSION_NAMES'}});

	# Versions to process in the next pass
	my @next_vers = ();

	# Hash, indexed by version name, that reflects whether the version
	# has been expanded yet or not.
	my %done = ();

	while (scalar(@vers) > 0) {
		foreach my $name (@vers) {
			my $i;
			my $defer = 0;
			my $cur_version = $obj->{'VERSION_INFO'}{$name};
			my ($top, $direct, $total, $symhash, $inheritarr) =
			    @{$cur_version};

			# In order to expand this version, all the inherited
			# versions must already have been done. If not, put
			# this version on @next_vers for the next pass.
			my $num = scalar(@$inheritarr);
			for ($i = 0; $i < $num; $i++) {
			    if (!$done{$inheritarr->[$i]}) {
				$defer = 1;
				push @next_vers, $name;
				last;
			    }
			}
			next if ($defer);

			# Add all the symbols from the inherited versions
			# to this one.
			for ($i = 0; $i < $num; $i++) {
				my $i_version =
				    $obj->{'VERSION_INFO'}{$inheritarr->[$i]};
				my $i_symhash = $i_version->[3];

				foreach my $sym (keys %$i_symhash) {
				    if (!defined($cur_version->[3]{$sym})) {
					    $cur_version->[2]++;
					    $cur_version->[3]{$sym} = 'INHERIT';
				    }
				}
			}

			$done{$name} = 1;
		}

		@vers = @next_vers;
		@next_vers = ();
	}
}

## ReadInterface(file, alias)
#
# Read the interface description file, as produced by interface_check, and
# return a hash describing it.
#
# entry:
#	file - Interface file to read.
#	alias - Refence to hash to be filled in with any aliases
#		that are seen in the file. The alias name is the key,
#		and the object is the value.
#
# exit:
#	The hash referenced by alias has been updated.
#
#	The return value is a hash that encapsulates the interface
#	information. This hash returned uses the object names as the
#	key. Each key references a sub-hash that contains information
#	for that object:
#
#	CLASS		-> ELFCLASS
#	TYPE		-> ELF type
#	VERSION_NAMES	-> Reference to array [1..n] of version names, in the
#			   order they come from the input file.
#	VERSION_INFO	-> Reference to hash indexed by version name, yielding
#			   a reference to an array containing information about
#			   that version.
#
#	The arrays referenced via VERSION_INFO are of the form:
#
#		(top, new, total, symhashref, inheritarrref)
#
#	where:
#		top - 1 if version is a TOP_VERSION, 0 for a regular VERSION
#		new - Number of symbols defined explicitly by version
#		total - Number of symbols included in version, both new,
#			and via inheritance.
#		symhashref - Reference to hash indexed by symbol names, and
#			yielding true (1).
#		inheritarrref - Reference to array of names of versions
#			inherited by this one.
#
sub ReadInterface {
	my ($file, $alias) = @_;
	my %main_hash = ();
	my $Line;
	my $LineNum = 0;
	my $obj_name;
	my $obj_hash;
	my $sym_ok = 0;
	my $cur_version;

	open(FILE, $file) || die "$Prog: Unable to open: $file";

	# Until we see an OBJECT line, nothing else is valid. To
	# simplify the error handling, use a simple initial loop to
	# read the file up to that point
	while ($Line = onbld_elfmod::GetLine(\*FILE, \$LineNum)) {
		if ($Line =~ s/^OBJECT\s+//i) {
		    $obj_name = $Line;
		    $main_hash{$obj_name} = {};
		    $obj_hash = $main_hash{$obj_name};
		    last;
		}
		die "$file: OBJECT expected on line $LineNum: $Line\n";
	}

	# Read the remainder of the file
	while ($Line = onbld_elfmod::GetLine(\*FILE, \$LineNum)) {
		# Items are parsed in order of decreasing frequency

		if ($Line =~
		    /^SYMBOL\s+([^\s]+)$/i) {
			my $sym = $1;

			die "$file: SYMBOL not expected on line $LineNum: $Line\n"
			    if !$sym_ok;
			
			$cur_version->[1]++;
			$cur_version->[2]++;
			$cur_version->[3]{$sym} = 'NEW';
			next;
		}

		if ($Line =~ /^((TOP_)?VERSION)\s+([^\s]+)(\s+\{(.*)\})?\s*$/i) {
			my ($top, $name, $inherit) = ($2, $3, $5);

			$top = defined($top) ? 1 : 0;

			my @inheritarr = defined($inherit) ?
			    split /[,{\s]+/, $inherit : ();

			$cur_version = [ $top, 0, 0, {}, \@inheritarr ];
			$obj_hash->{'VERSION_INFO'}{$name} = $cur_version;

			push @{$obj_hash->{'VERSION_NAMES'}}, $name;
			$sym_ok = 1;
			next;
		}

		if ($Line =~ /^OBJECT\s+([^\s]+)$/i) {
		    my $prev_obj_hash = $obj_hash;
		    $obj_name = $1;
		    $main_hash{$obj_name} = {};
		    $obj_hash = $main_hash{$obj_name};

		    # Expand the versions for the object just processed
		    ExpandInheritance($prev_obj_hash);
		    next;
		}

		if ($Line =~ /^CLASS\s+([^\s]+)$/i) {
			$obj_hash->{'CLASS'} = $1;
			next;
		}

		if ($Line =~ /^TYPE\s+([^\s]+)$/i) {
			$obj_hash->{'TYPE'} = $1;
			next;
		}

		if ($Line =~ /^ALIAS\s+([^\s]+)$/i) {
			$$alias{$1} = $obj_name;
			next;
		}

		die "$file: unrecognized item on line $LineNum: $Line\n";
	}
	close FILE;

	# Expand the versions for the final object from the file
	ExpandInheritance($obj_hash);

	return %main_hash;
}

## PrintInterface(main_hash, alias)
#
# Dump the contents of main_hash and alias to stdout in the same format
# used by interface_check to produce the input interface file. This output
# should diff cleanly against the original (ignoring the header comments).
#
sub PrintInterface {
	my ($main_hash, $alias_hash) = @_;

	foreach my $obj (sort keys %$main_hash) {
		print "OBJECT\t$obj\n";
		print "CLASS\t$main_hash->{$obj}{'CLASS'}\n";
		print "TYPE\t$main_hash->{$obj}{'TYPE'}\n";

		# This is inefficient, but good enough for debugging
		# Look at all the aliases and print those that belong
		# to this object.
		foreach my $alias (sort keys %$alias_hash) {
			print "ALIAS\t$alias\n"
			    if ($obj eq $alias_hash->{$alias});
		}

		next if !defined($main_hash->{$obj}{'VERSION_NAMES'});

		my $num = scalar(@{$main_hash->{$obj}{'VERSION_NAMES'}});
		my $i;
		for ($i = 0; $i < $num; $i++) {
			my $name = $main_hash->{$obj}{'VERSION_NAMES'}[$i];
			my ($top, $direct, $total, $symhash, $inheritarr) =
			    @{$main_hash->{$obj}{'VERSION_INFO'}{$name}};

			$top = $top ? "TOP_" : '';

			my $inherit = (scalar(@$inheritarr) > 0) ?
			    "\t{" . join(', ', @{$inheritarr}) . "}" : '';

			print "${top}VERSION\t$name$inherit\n";

			foreach my $sym (sort keys %$symhash) {
				print "\t$symhash->{$sym}\t$sym\n";
			}
		}
	}
}

## compare()
#
# Compare the old interface definition contained in (%old_hash, %old_alias)
# with the new interface contained in (%new_hash, %new_alias).
#
sub compare {
	foreach my $old_obj (sort keys %old_hash) {
		my $new_obj = $old_obj;
		my $Ttl = 0;

		# If the object does not exist in the new interface,
		# then see if there's an alias for it. Failing that,
		# we simply ignore the object.
		if (!defined($new_hash{$new_obj})) {
			next if !defined($new_alias{$new_obj});
			$new_obj = $new_alias{$new_obj};
		}

		my $old = $old_hash{$old_obj};
		my $new = $new_hash{$new_obj};

		# Every version in the old object must exist in the new object,
		# and there must be exactly the same symbols in each.
		my $num = scalar(@{$old->{'VERSION_NAMES'}});
		for (my $i = 0; $i < $num; $i++) {
			my $name = $old->{'VERSION_NAMES'}[$i];

			# New object must have this version
			if (!defined($new->{'VERSION_INFO'}{$name})) {
				onbld_elfmod::OutMsg2(\*STDOUT, \$Ttl, $old_obj,
				    $new_obj, "$name: deleted version");
				next;
			}

			my ($old_top, $old_direct, $old_total, $old_symhash) =
			    @{$old->{'VERSION_INFO'}{$name}};
			my ($new_top, $new_direct, $new_total, $new_symhash) =
			    @{$new->{'VERSION_INFO'}{$name}};

			# If this is an empty top version, and the old object
			# has the EMPTY_TOPVERSION exception set, then we
			# skip it as if it were not present.
			next if $old_top && ($old_direct == 0) &&
			    ExTopVer($name, $old_obj);

			# We check that every symbol in the old object is
			# in the new one to detect deleted symbols. We then
			# check that every symbol in the new object is also
			# in the old object, to find added symbols. If the
			# "deleted" check is clean, and the two objects have
			# the same number of symbols in their versions, then we
			# can skip the "added" test, because we know that
			# there is no room for an addition to have happened.
			# Since most objects satisfy these constraints, we
			# end up doing roughly half the number of comparisons
			# that would otherwise be needed.
			my $check_added_syms =
			    ($old_total == $new_total) ? 0: 1;

			# Every symbol in the old version must be in the new one
			foreach my $sym (sort keys %$old_symhash) {
				if (!defined($new_symhash->{$sym})) {
					onbld_elfmod::OutMsg2(\*STDOUT,
					   \$Ttl, $old_obj, $new_obj,
					   "$name: deleted interface: $sym")
					    if !ExSym(\@DelSymList,
						      $sym, $name, $new_obj);
					$check_added_syms = 1;
				}
			}

			# Do the "added" check, unless we can optimize it away.
			# Every symbol in the new version must be in the old one.
			if ($check_added_syms) {
				foreach my $sym (sort keys %$new_symhash) {
				    if (!defined($old_symhash->{$sym})) {
					next if ExSym(\@AddSymList,
					    $sym, $name, $new_obj);
					onbld_elfmod::OutMsg2(\*STDOUT,
					       \$Ttl, $old_obj, $new_obj,
					       "$name: added interface: $sym");
				    }
				}
			}

			# We want to ensure that version numbers in an
			# inheritance chain don't go up by more than 1 in
			# any given release. If the version names are in the
			# numbered <PREFIX>x.y[.z] format, we can compare the
			# two top versions and see if this has happened.
			#
			# For a given <PREFIX>x.y[.z], valid sucessors would
			# be <PREFIX>x.(y+1) or <PREFIX>x.y.(z+1), where z is
			# assumed to be 0 if not present.
			#			
			# This check only makes sense when the new interface
			# is a direct decendent of the old one, as specified
			# via the -d option. If the two interfaces are more
			# than one release apart, we should not do this test.
			next if !($opt{d} && $old_top && !$new_top);

			# Known numbered version?
			#
			# Key to @Cat contents:
			# [0]   'NUMBERED'
			# [1]	number of dot separated numeric fields. 2 or 3.
			# [2]   prefix
			# [3]   major #
			# [4]   minor #
			# [5]   micro # (only if [1] is 3)
			my @Cat = onbld_elfmod_vertype::Category($name, '');
			next if ($Cat[0] ne 'NUMBERED');

			my $iname1 = "$Cat[2]$Cat[3]." . ($Cat[4] + 1);
			my $iname2;
			if ($Cat[1] == 3) {
			    $iname2 = "$Cat[2]$Cat[3].$Cat[4]." . ($Cat[5] + 1);
			} else {
			    $iname2 = "$Cat[2]$Cat[3].$Cat[4].1";
			}

			if (defined($new->{'VERSION_INFO'}{$iname1}) ||
			    defined($new->{'VERSION_INFO'}{$iname2})) {
				my $i_top =
				    $new->{'VERSION_INFO'}{$iname1}[0] ||
				    $new->{'VERSION_INFO'}{$iname2}[0];
				if (!$i_top) {
					onbld_elfmod::OutMsg2(\*STDOUT,
					    \$Ttl, $old_obj, $new_obj,
					    "$name: inconsistant " .
					    "version increment: " .
					    "expect $iname1 or $iname2 ".
					    "to replace top version");
				}
			} else {
 				onbld_elfmod::OutMsg2(\*STDOUT,
				    \$Ttl, $old_obj, $new_obj,
			            "$name: expected superseding " .
				    "top version to $name not " .
				    "present: $iname1 or $iname2");
			}
		}


		# Empty versions in the established interface description
		# are usually the result of fixing a versioning mistake
		# at some point in the past. These versions are part of
		# the public record, and cannot be changed now. However, if
		# comparing two interface descriptions from the same gate,
		# flag any empty versions in the new interface description
		# that are not present in the old one. These have yet to
		# become part of the official interface, and should be removed
		# before they do.
		next if !$opt{d};

		$num = scalar(@{$new->{'VERSION_NAMES'}});
		for (my $i = 0; $i < $num; $i++) {
			my $name = $new->{'VERSION_NAMES'}[$i];

			# If old object has this version, skip it
			next if defined($old->{'VERSION_INFO'}{$name});

			# If explicitly whitelisted, skip it
			next if ExTopVer($name, $new_obj);

			my ($new_top, $new_direct, $new_total, $new_symhash) =
			    @{$new->{'VERSION_INFO'}{$name}};

			if ($new_direct == 0) {
				onbld_elfmod::OutMsg2(\*STDOUT,
				    \$Ttl, $old_obj, $new_obj,
				    "$name: invalid empty new version");
			}
		}
	}

}



# -----------------------------------------------------------------------------

# Establish a program name for any error diagnostics.
chomp($Prog = `basename $0`);

# Check that we have arguments. Normally, 2 plain arguments are required,
# but if -t is present, only one is allowed.
if ((getopts('c:de:ot', \%opt) == 0) || (scalar(@ARGV) != ($opt{t} ? 1 : 2))) {
	print "usage: $Prog [-dot] [-c vtype_mod] [-e exfile] old new\n";
	print "\t[-c vtype_mod]\tsupply alternative version category module\n";
	print "\t[-d]\t\tnew is a direct decendent of old\n";
	print "\t[-e exfile]\texceptions file\n";
	print "\t[-o]\t\tproduce one-liner output (prefixed with pathname)\n";
	print "\t[-t]\tParse old, and recreate to stdout\n";
	exit 1;
}

# We depend on the onbld_elfmod and onbld_elfmod_vertype perl modules.
# Both modules are maintained in the same directory as this script,
# and are installed in ../lib/perl. Use the local one if present,
# and the installed one otherwise.
#
# The caller is allowed to supply an alternative implementation for
# onbld_elfmod_vertype via the -c option. In this case, the alternative
# implementation is expected to provide the same interface as the standard
# copy, and is loaded instead.
#
my $moddir = my $vermoddir = dirname($0);
$moddir = "$moddir/../lib/perl" if ! -f "$moddir/onbld_elfmod.pm";
require "$moddir/onbld_elfmod.pm";
if ($opt{c}) {
	require "$opt{c}";
} else {
	$vermoddir = "$vermoddir/../lib/perl"
	    if ! -f "$vermoddir/onbld_elfmod_vertype.pm";
	require "$vermoddir/onbld_elfmod_vertype.pm";
}

# Locate and process the exceptions file
LoadExceptions();

%old_alias = ();
%old_hash = ReadInterface($ARGV[0], \%old_alias);

# If -t is present, only one argument is allowed --- we parse it, and then
# print the same information back to stderr in the same format as the original.
# This is useful for debugging, to verify that the parsing is correct.
if ($opt{t}) {
	PrintInterface(\%old_hash, \%old_alias);
	exit 0;
}

%new_alias = ();
%new_hash = ReadInterface($ARGV[1], \%new_alias);

compare();

exit 0;
