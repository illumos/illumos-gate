#!/usr/perl5/bin/perl -w
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

require 5.005;
use strict;
use locale;
use Errno;
use Fcntl;
use File::Basename;
use Getopt::Std;
use Getopt::Long qw(:config no_ignore_case bundling);
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(textdomain gettext);
use Sun::Solaris::Project qw(:ALL :PRIVATE);
use Sun::Solaris::Task qw(:ALL);

#
# Print a usage message and exit.
#
sub usage
{
	my (@msg) = @_;
	my $prog = basename($0);
	my $space = ' ' x length($prog);
	print(STDERR "$prog: @msg\n") if (@msg);
	printf(STDERR gettext(
	    "Usage: %s [-n] [-f filename]\n"), $prog);
	printf(STDERR gettext(
	    "       %s [-n] [-A|-f filename] [-p projid [-o]] [-c comment]\n".
            "       %s [-a|-s|-r] [-U user[,user...]] [-G group[,group...]]\n".
            "       %s [-K name[=value[,value...]]] [-l new_projectname] ".
	    "project\n"), $prog, $space, $space, $space);
	exit(2);
}

#
# Print a list of error messages and exit.
#
sub error
{
	my $exit = $_[0][0];
	my $prog = basename($0) . ': ';
	foreach my $err (@_) {
		my ($e, $fmt, @args) = @$err;
		printf(STDERR $prog . $fmt . "\n", @args);
	}
	exit($exit);
}

#
# Merge an array of users/groups with an existing array.  The array to merge
# is the first argument, an array ref is the second argument.  The third
# argument is the mode which can be one of:
#     add	add all entries in the first arg to the second
#     remove	remove all entries in the first arg from the second
#     replace	replace the second arg by the first
# The resulting array is returned as a reference.
#
sub merge_lists
{
	my ($new, $old, $mode) = @_;
	my @err;

	if ($mode eq 'add') {
		my @merged = @$old;
		my %look = map { $_ => 1 } @$old;
		my @leftover;
		foreach my $e (@$new) {
			if (! exists($look{$e})) {
				push(@merged, $e);
			} else {
				push(@leftover, $e);
			}
		}
		if (@leftover) {
			push(@err,
			    [6, gettext('Project already contains "%s"'),
			    join(',', @leftover)]);
			return (1, \@err);
		}

		return(0, \@merged);

	} elsif ($mode eq 'remove') {

		my %seen;
		my @dups = grep($seen{$_}++ == 1, @$new);
		if (@dups) {
			push(@err, [6, gettext('Duplicate names "%s"'),
			    join(',', @dups)]);
			return (1, \@err);
		}
		my @merged;
		my %look = map { $_ => 0 } @$new;
		foreach my $e (@$old) {
			if (exists($look{$e})) {
				$look{$e}++;
			} else {
				push(@merged, $e);
			}
		}
		my @leftover = grep(! $look{$_}, keys(%look));
		if (@leftover) {
			push(@err, [6,
		            gettext('Project does not contain "%s"'),
			    join(',', @leftover)]);
			return (1, \@err);
		}
		return (0, \@merged);

	} elsif ($mode eq 'replace' || $mode eq 'substitute') {
		return (0, $new);
	}
}

#
# merge_values(ref to listA, ref to listB, mode
#
# Merges the values in listB with the values in listA.  Dups are not
# merged away, but instead are maintained.
#
# modes:
#	add   :	add values in listB to listA
#	remove:	removes first instance of each value in listB from listA
#	
sub merge_values
{

	my ($new, $old, $mode) = @_;
	my $undefined;
	my @merged;
	my $lastmerged;
	my ($oldval, $newval);
	my $found;
	my @err;

	if (!defined($old) && !defined($new)) {
		return (0, $undefined);
	}
					     
	if ($mode eq 'add') {

		if (defined($old)) {
			push(@merged, @$old);
		}
		if (defined($new)) {
			push(@merged, @$new);
		}
		return (0, \@merged);

	} elsif ($mode eq 'remove') {

		$lastmerged = $old;
		foreach $newval (@$new) {
			$found = 0;
			@merged = ();
			foreach $oldval (@$lastmerged) {
				if (!$found &&
				    projent_values_equal($newval, $oldval)) {
					$found = 1;
				} else {
					push(@merged, $oldval);
				}

			}
			if (!$found) {
				push(@err, [6, gettext(
				    'Value "%s" not found'),
				    projent_values2string($newval)]);
			}
			@$lastmerged = @merged;
		}

		if (@err) {
			return (1, \@err);
		} else {
			return (0, \@merged);
		}
	}
}

#
# merge_attribs(listA ref, listB ref, mode)
#
# Merge listB of attribute/values hash refs with listA
# Each hash ref should have keys "name" and "values"
#
# modes:
#     add	For each attribute in listB, add its values to
#	        the matching attribute in listA.  If listA does not
#		contain this attribute, add it.
#
#     remove	For each attribute in listB, remove its values from
#	        the matching attribute in listA.  If all of an
#		attributes values are removed, the attribute is removed.
#		If the attribute in listB has no values, then the attribute
#		and all of it's values are removed from listA
#
#     substitute For each attribute in listB, replace the values of
#	        the matching attribute in listA with its values.  If
#		listA does not contain this attribute, add it.
#
#     replace	Return listB
#
# The resulting array is returned as a reference.
#
sub merge_attribs
{
	my ($new, $old, $mode) = @_;
	my @merged;
	my @err;
	my $ret;
	my $tmp;
	my $newattrib;
	my $oldattrib;
	my $values;
       
	if ($mode eq 'add') {

		my %oldhash;
		push(@merged, @$old);
		%oldhash = map { $_->{'name'} => $_ } @$old;
		foreach $newattrib (@$new) {

			$oldattrib = $oldhash{$newattrib->{'name'}};
			if (defined($oldattrib)) {
				($ret, $tmp) = merge_values(
				    $newattrib->{'values'},
				    $oldattrib->{'values'},
				    $mode);

				if ($ret != 0) {
					push(@err, @$tmp);
				} else {
					$oldattrib->{'values'} = $tmp;
				}
			} else {
				push(@merged, $newattrib);
			}
		}
		if (@err) {
			return (1, \@err);
		} else {
			return (0, \@merged);
		}

	} elsif ($mode eq 'remove') {

		my %seen;
		my @dups = grep($seen{$_}++ == 1, map { $_->{'name'} } @$new);
		if (@dups) {
			push(@err, [6, gettext(
			    'Duplicate Attributes "%s"'),
			     join(',', @dups)]);
			return (1, \@err);
		}
		my %toremove = map { $_->{'name'} => $_ } @$new;

		foreach $oldattrib (@$old) {
			$newattrib = $toremove{$oldattrib->{'name'}};
			if (!defined($newattrib)) {

				push(@merged, $oldattrib);
				
			} else {
				if (defined($newattrib->{'values'})) {
					($ret, $tmp) = merge_values(
					    $newattrib->{'values'},
					    $oldattrib->{'values'},
					    $mode);

					if ($ret != 0) {
						push(@err, @$tmp);
					} else {
						$oldattrib->{'values'} = $tmp;
					}
					if (defined($tmp) && @$tmp) {
						push(@merged, $oldattrib);
					}
				}
				delete $toremove{$oldattrib->{'name'}};
			}
		}
		foreach $tmp (keys(%toremove)) {
			push(@err, [6,
		            gettext('Project does not contain "%s"'),
			    $tmp]);
		}

		if (@err) {
			return (1, \@err);
		} else {	
			return (0, \@merged);
		}	

	} elsif ($mode eq 'substitute') {

		my %oldhash;
		push(@merged, @$old);
		%oldhash = map { $_->{'name'} => $_ } @$old;
		foreach $newattrib (@$new) {

			$oldattrib = $oldhash{$newattrib->{'name'}};
			if (defined($oldattrib)) {

				$oldattrib->{'values'} =
				    $newattrib->{'values'};

			} else {
				push(@merged, $newattrib);
			}
		}
		if (@err) {
			return (1, \@err);
		} else {
			return (0, \@merged);
		}
	
	} elsif ($mode eq 'replace') {
		return (0, $new);
	}
}

#
# Main routine of script.
#
# Set the message locale.
#
setlocale(LC_ALL, '');
textdomain(TEXT_DOMAIN);


# Process command options and do some initial command-line validity checking.
my ($pname, $flags);
$flags = {};
my $modify = 0;

my $projfile;
my $opt_n;
my $opt_c;
my $opt_o;
my $opt_p;
my $opt_l;
my $opt_a;
my $opt_r;
my $opt_s;
my $opt_U;
my $opt_G;
my @opt_K;
my $opt_A;

GetOptions("f=s" => \$projfile,
	   "n"   => \$opt_n,
	   "c=s" => \$opt_c,
	   "o"	 => \$opt_o,
	   "p=s" => \$opt_p,
	   "l=s" => \$opt_l,
	   "s"	 => \$opt_s,
	   "r"	 => \$opt_r,
	   "a"	 => \$opt_a,
	   "U=s" => \$opt_U,
	   "G=s" => \$opt_G,
	   "K=s" => \@opt_K,
  	   "A"	 => \$opt_A) || usage();

usage(gettext('Invalid command-line arguments')) if (@ARGV > 1);

if ($opt_c || $opt_G || $opt_l || $opt_p || $opt_U || @opt_K || $opt_A) {
	$modify = 1;
	if (! defined($ARGV[0])) {
		usage(gettext('No project name specified'));
	}
}

if (!$modify && defined($ARGV[0])) {
	usage(gettext('missing -c, -G, -l, -p, -U, or -K'));
}

if (defined($opt_A) && defined($projfile)) {
	usage(gettext('-A and -f are mutually exclusive'));
}

if (! defined($projfile)) {
	$projfile = &PROJF_PATH;
}

if ($modify && $projfile eq '-') {
	usage(gettext('Cannot modify standard input'));
}

$pname = $ARGV[0];
usage(gettext('-o requires -p projid to be specified'))
    if (defined($opt_o) && ! defined($opt_p));
usage(gettext('-a, -r, and -s are mutually exclusive'))
    if ((defined($opt_a) && (defined($opt_r) || defined($opt_s))) ||
	(defined($opt_r) && (defined($opt_a) || defined($opt_s))) ||
	(defined($opt_s) && (defined($opt_a) || defined($opt_r))));

usage(gettext('-a and -r require -U users or -G groups to be specified'))
    if ((defined($opt_a) || defined($opt_r) || defined($opt_s)) &&
    ! (defined($opt_U) || defined($opt_G) || (@opt_K)));


if (defined($opt_a)) {
	$flags->{mode} = 'add';
} elsif (defined($opt_r)) {
	$flags->{mode} = 'remove';
} elsif (defined($opt_s)) {
	$flags->{mode} = 'substitute';
} else {
	$flags->{mode} = 'replace';
}

# Fabricate an unique temporary filename.
my $tmpprojf = $projfile . ".tmp.$$";

my $pfh;

#
# Read the project file.  sysopen() is used so we can control the file mode.
# Handle special case for standard input.
if ($projfile eq '-') {
	open($pfh, "<&=STDIN") or error( [10,
	    gettext('Cannot open standard input')]);
} elsif (! sysopen($pfh, $projfile, O_RDONLY)) {
	error([10, gettext('Cannot open %s: %s'), $projfile, $!]);
}
my ($mode, $uid, $gid) = (stat($pfh))[2,4,5];


if ($opt_n) {
	$flags->{'validate'} = 'false';
} else {
	$flags->{'validate'} = 'true';
}

$flags->{'res'} = 'true';
$flags->{'dup'} = 'true';

my ($ret, $pf) = projf_read($pfh, $flags);
if ($ret != 0) {
	error(@$pf);
}
close($pfh);
my $err;
my $tmperr;
my $value;

# Find existing record.
my ($proj, $idx);
$idx = 0;

if (defined($pname)) {
	foreach my $r (@$pf) {	
		if ($r->{'name'} eq $pname) {
			$proj = $r;
			last;
		}	
		$idx++;
	}
	error([6, gettext('Project "%s" does not exist'), $pname])
	    if (! $proj);
}
#
# If there are no modification options, simply reading the file, which
# includes parsing and verifying, is sufficient.
#
if (!$modify) {
	exit(0);
}

foreach my $r (@$pf) {
	if ($r->{'name'} eq $pname) {
		$proj = $r;
		last;
	}	
	$idx++;
}

# Update the record as appropriate.
$err = [];

# Set new project name.
if (defined($opt_l)) {

	($ret, $value) = projent_parse_name($opt_l);
	if ($ret != 0) {
		push(@$err, @$value);
	} else {
		$proj->{'name'} = $value;
		if (!defined($opt_n)) {
			($ret, $tmperr) =
			    projent_validate_unique_name($proj, $pf);
			if ($ret != 0) {
				push(@$err, @$tmperr);
			}
		}
	}
}

# Set new project id.
if (defined($opt_p)) {

	($ret, $value) = projent_parse_projid($opt_p);
	if ($ret != 0) {
		push(@$err, @$value);
	} else {
		$proj->{'projid'} = $value;

		# Check for dupicate.
		if ((!defined($opt_n)) && (!defined($opt_o))) {
			($ret, $tmperr) =
			    projent_validate_unique_id($proj, $pf);
			if ($ret != 0) {
				push(@$err, @$tmperr);
			}
		}
	}	
}

# Set new comment.
if (defined($opt_c)) {

	($ret, $value) = projent_parse_comment($opt_c);
	if ($ret != 0) {
		push(@$err, @$value);
	} else {
		$proj->{'comment'} = $value;
	}
}

# Set new users.
if (defined($opt_U)) {

	my @sortlist;
	my $list;
	($ret, $list) = projent_parse_users($opt_U, {'allowspaces' => 1});
	if ($ret != 0) {
		push(@$err, @$list);
	} else {
		($ret, $list) =
		    merge_lists($list, $proj->{'userlist'}, $flags->{mode});
		if ($ret != 0) {
			push(@$err, @$list);
		} else {
			@sortlist = sort(@$list);
			$proj->{'userlist'} = \@sortlist;
		}
	}	
}

# Set new groups.
if (defined($opt_G)) {

	my @sortlist;
	my $list;
	($ret, $list) = projent_parse_groups($opt_G, {'allowspaces' => 1});
	if ($ret != 0) {
		push(@$err, @$list);
	} else {
		($ret, $list) =
		    merge_lists($list, $proj->{'grouplist'}, $flags->{mode});
		if ($ret != 0) {
			push(@$err, @$list);
		} else {
			@sortlist = sort(@$list);
			$proj->{'grouplist'} = \@sortlist;
		}
	}
}

# Set new attributes.
my $attrib;
my @attriblist;

foreach $attrib (@opt_K) {

	my $list;
	($ret, $list) = projent_parse_attributes($attrib, {'allowunits' => 1});
	if ($ret != 0) {
		push(@$err, @$list);
	} else {
		push(@attriblist, @$list);
	}
}

if (@attriblist) {
	my @sortlist;
	my $list;

	($ret, $list) =
	    merge_attribs(\@attriblist, $proj->{'attributelist'},
	    $flags->{mode});
	if ($ret != 0) {
		push(@$err, @$list);
	} else {
		@sortlist =
		    sort { $a->{'name'} cmp $b->{'name'} } @$list;
		$proj->{'attributelist'} = \@sortlist;
	}
}

# Validate all projent fields.
if (!defined($opt_n)) {
	($ret, $tmperr) = projent_validate($proj, $flags);
	if ($ret != 0) {
		push(@$err, @$tmperr);
	}
}
if (@$err) {
	error(@$err);
}

# Write out the project file.
if ($modify) {

	#
	# Mark projent to write based on new values instead of
	# original line.
	#
	$proj->{'modified'} = 'true';
	umask(0000);
	sysopen($pfh, $tmpprojf, O_WRONLY | O_CREAT | O_EXCL, $mode) ||
	    error([10, gettext('Cannot create %s: %s'), $tmpprojf, $!]);
	projf_write($pfh, $pf);
	close($pfh);

	# Update file attributes.
	if (!chown($uid, $gid, $tmpprojf)) {
		unlink($tmpprojf);
		error([10, gettext('Cannot set ownership of %s: %s'),
		    $tmpprojf, $!]);
	}
	if (! rename($tmpprojf, $projfile)) {
		unlink($tmpprojf);
		error([10, gettext('cannot rename %s to %s: %s'),
	            $tmpprojf, $projfile, $!]);
	}

}

if (defined($opt_A)) {
	my $error;

	if (($error = setproject($pname, "root", TASK_FINAL|TASK_PROJ_PURGE)) != 0) {

		if ($error == SETPROJ_ERR_TASK) {
			if ($!{EAGAIN}) {
				error([5, gettext("resource control limit has ".
				     "been reached\n")]);
			} elsif ($!{ESRCH}) {
				error([5, gettext("user \"%s\" is not a member ".
				     "of project \"%s\"\n"), "root", $pname]);
			} elsif ($!{EACCES}) {
				error([5, gettext("the invoking task is final\n"
				     )]);
			} else {
				error([5, gettext("could not join project \"%s".
				     "\"\n"), $pname]);
			}

		} elsif ($error == SETPROJ_ERR_POOL) {
			if ($!{EACCES}) {
				error([5, gettext("no resource pool accepting ".
				     "default bindings exists for project \"%s".
				     "\"\n"), $pname]);
	        	} elsif ($!{ESRCH}) {
				error([5, gettext("specified resource pool ".
				     "does not exist for project \"%s\"\n"),
				     $pname]);
			} else {
				error([5, gettext("could not bind to default ".
				     "resource pool for project \"%s\"\n"),
				     $pname]);
			}

		} else {
			#
			# $error represents the position - within the semi-colon
			# delimited $attribute - that generated the error
			#
			if ($error <= 0) {
				error([5, gettext("setproject failed for ".
				     "project \"%s\"\n"), $pname]);
			} else {
				my ($name, $projid, $comment, $users_ref,
				     $groups_ref, $attr) = getprojbyname($pname);
				my $attribute = ($attr =~
				     /(\S+?)=\S+?(?:;|\z)/g)[$error - 1];

				if (!$attribute) {
					error([5, gettext("warning, resource ".
					     "control assignment failed for ".
					     "project \"%s\" attribute %d\n"),
					     $pname, $error]);
				} else {
					error([5, gettext("warning, %s ".
					     "resource control assignment ".
					     "failed for project \"%s\"\n"),
					     $attribute, $pname]);
				}
			}
		}
	}
}

exit(0);
