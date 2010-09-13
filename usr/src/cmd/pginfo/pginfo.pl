#! /usr/perl5/bin/perl
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

#
# pginfo - tool for displaying Processor Group information
#

use warnings;
use strict;
use File::Basename;
use Errno;
use POSIX qw(locale_h);
use Getopt::Long qw(:config no_ignore_case bundling auto_version);
use List::Util qw(first max min);
use Sun::Solaris::Utils qw(textdomain gettext);
use Sun::Solaris::Pg;

#
# Constants
#
# It is possible that wnen trying to parse PG information, PG generation changes
# which will cause PG new method to fail with errno set to EAGAIN In this case
# we retry open up to RETRY_COUNT times pausing RETRY_DELAY seconds between each
# retry.
#
# When printing PGs we print them as a little tree with each PG shifted by
# LEVEL_OFFSET from each parent. For example:
#
# PG  RELATIONSHIP                    CPUs
# 0   System                          0-7
# 3    Socket                         0 2 4 6
# 2     Cache                         0 2 4 6
#

use constant {
	VERSION		=> 1.1,
	LEVEL_OFFSET	=> 1,
	RETRY_COUNT	=> 4,
        RETRY_DELAY	=> 0.25,
};

#
# Return codes
#
#     0    Successful completion.
#
#     1    An error occurred.
#
#     2    Invalid command-line options were specified.
#
use constant {
	E_SUCCESS => 0,
	E_ERROR => 1,
	E_USAGE => 2,
};


# Set message locale
setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

# Get script name for error messages
our $cmdname = basename($0, ".pl");

#
# Process options
#
my $do_cpulist;			# -C - Show CPU IDs
my $do_cpus;			# -c - Treat args as CPU IDs
my $do_physical;		# -p - Show physical relationships
my $do_sharing_only;		# -S - Only show sharing relationships
my $do_tree;			# -T - Show ASCII tree
my $do_usage;			# -h - Show usage
my $do_version;			# -V - Show version
my $script_mode;		# -I - Only show IDs
my $verbose = 0;		# -v - Verbose output
my @sharing_filter;		# -r string,...
my @sharing_filter_neg;		# -R string,...

# Exit code
my $rc = E_SUCCESS;

# Parse options from the command line
GetOptions("cpus|c"		=> \$do_cpus,
	   "idlist|I"		=> \$script_mode,
	   "cpulist|C"		=> \$do_cpulist,
	   "physical|p"		=> \$do_physical,
	   "help|h|?"		=> \$do_usage,
	   "sharing|s"		=> \$do_sharing_only,
	   "relationship|r=s"	=> \@sharing_filter,
	   "norelationship|R=s" => \@sharing_filter_neg,
	   "tree|topology|T"	=> \$do_tree,
	   "version|V"		=> \$do_version,
	   "verbose+"		=> \$verbose,
	   "v+"			=> \$verbose,
) || usage(E_USAGE);

# Print usage message when -h is given
usage(E_SUCCESS) if $do_usage;

if ($do_version) {
	#
	# Print version information and exit
	#
	printf gettext("%s version %s\n"), $cmdname, VERSION;
	exit(E_SUCCESS);
}

#
# Verify options compatibility
#
if ($script_mode && $do_cpulist) {
	printf STDERR
	  gettext("%s: options -I and -C can not be used at the same time\n"),
	    $cmdname;
	usage(E_USAGE);
}

if (($script_mode || $do_cpulist) &&
    ($do_physical || $do_sharing_only ||
    $do_tree)) {
	printf STDERR
	  gettext("%s: options -C and -I can not be used with -p -s or -T\n"),
	    $cmdname;
	usage(E_USAGE);
}

if ($do_physical && $do_sharing_only) {
	printf STDERR
	  gettext("%s: option -p can not be used with -s\n"), $cmdname;
	usage(E_USAGE);
}

if ($do_tree && $do_sharing_only) {
	printf STDERR
	  gettext("%s: option -T can not be used with -s\n"),
	    $cmdname;
	usage(E_USAGE);
}

if ($verbose && !($script_mode || $do_cpulist || $do_sharing_only)) {
	$do_tree = 1;
	$do_physical = 1;
}

#
# Get PG information
#
my $p = Sun::Solaris::Pg->new(-tags => $do_physical,
			      -retry => RETRY_COUNT,
			      '-delay' => RETRY_DELAY);

if (!$p) {
	printf STDERR
	  gettext("%s: can not obtain Processor Group information: $!\n"),
	    $cmdname;
	exit(E_ERROR);
}

#
# Convert -[Rr] string1,string2,... into list (string1, string2, ...)
#
@sharing_filter = map { split /,/ } @sharing_filter;
@sharing_filter_neg = map { split /,/ } @sharing_filter_neg;

#
# Get list of all PGs in the system
#
my @all_pgs = $p->all_depth_first();

if (scalar(@all_pgs) == 0) {
	printf STDERR
	  gettext("%s: this system does not have any Processor groups\n"),
	    $cmdname;
	exit(E_ERROR);
}

#
# @pgs is the list of PGs we are going to work with after all the option
# processing
#
my @pgs = @all_pgs;

#
# get list of all CPUs in the system by looking at the root PG cpus
#
my @all_cpus = $p->cpus($p->root());

#
# If there are arguments in the command line, treat them as either PG IDs or as
# CPUs that should be converted to PG IDs.
# Arguments can be specified as x-y x,y,z and use special keyword 'all'
#
if (scalar @ARGV) {
	#
	# Convert 'all' in arguments to all CPUs or all PGs
	#
	my @args;
	my @all = $do_cpus ? @all_cpus : @all_pgs;
	@args = map { $_ eq 'all' ? @all : $_ } @ARGV;

	# Expand any x-y,z ranges
	@args =  $p->expand(@args);

	if ($do_cpus) {
		# @bad_cpus is a list of invalid CPU IDs
		my @bad_cpus =  $p->set_subtract(\@all_cpus, \@args);
		if (scalar @bad_cpus) {
			printf STDERR
			  gettext("%s: Invalid processor IDs %s\n"),
			    $cmdname, $p->id_collapse(@bad_cpus);
			$rc = E_ERROR;
		}
		#
		# List of PGs is the list of any PGs that contain specified CPUs
		#
		@pgs = grep {
			my @cpus = $p->cpus($_);
			scalar($p->intersect(\@cpus, \@args));
		} @all_pgs;
	} else {
		# @pgs is a list of valid CPUs in the arguments
		@pgs = $p->intersect(\@all_pgs, \@args);
		# @bad_pgs is a list of invalid PG IDs
		my @bad_pgs = $p->set_subtract(\@all_pgs, \@args);
		if (scalar @bad_pgs) {
			printf STDERR
			  gettext("%s: Invalid PG IDs %s\n"),
			    $cmdname, $p->id_collapse(@bad_pgs);
			$rc = E_ERROR;
		}
	}
}

#
# Now we have list of PGs to work with. Now apply filtering. First list only
# those matching -R
#
@pgs = grep { list_match($p->sh_name($_), @sharing_filter) } @pgs if
  scalar @sharing_filter;

# Remove any that doesn't match -r
@pgs = grep { !list_match($p->sh_name($_), @sharing_filter_neg) } @pgs if
  scalar @sharing_filter_neg;

# Do we have any PGs left?
if (scalar(@pgs) == 0) {
	printf STDERR
	gettext("%s: no processor groups matching command line arguments %s\n"),
	    $cmdname, "@ARGV";
	exit(E_ERROR);
}

#
# Global list of PGs that should be excluded from the output - it is only used
# when tree mode is specified.
#
my @exclude_pgs;
if ($do_tree) {
	@exclude_pgs = grep {
		list_match($p->sh_name($_), @sharing_filter_neg)
	} @all_pgs;

	#
	# In tree mode add PGs that are in the lineage of given PGs
	#
	@pgs = pg_lineage($p, @pgs)
}

#
# -I is specified, print list of all PGs
#
if ($script_mode) {
	if (scalar(@pgs)) {
		@pgs = sort { $a <=> $b } @pgs;
		print "@pgs\n";
	} else {
		print "none\n";
	}
	exit($rc);
}

#
# -C is specified, print list of all CPUs belonging to PGs
#
if ($do_cpulist) {
	my @cpu_list = $p->uniqsort(map { $p->cpus($_) } @pgs);
	print "@cpu_list\n";
	exit($rc);
}

# Mapping of relationships to list of PGs
my %pgs_by_relationship;

# Maximum length of all sharing names
my $max_sharename_len = length('RELATIONSHIP');

# Maximum length of PG ID
my $max_pg_len = length(max(@pgs)) + 1;

#
# For calculating proper offsets we need to know minimum and maximum level for
# all PGs
#
my @levels = map { $p->level($_) } @pgs;
my $maxlevel = max(@levels);
my $minlevel = min(@levels);

# Calculate maximum string length that should be used to represent PGs
foreach my $pg (@pgs) {
	my $name =  $p->sh_name ($pg) || "unknown";
	my $level = $p->level($pg) || 0;

	if ($do_physical) {
		my $tags = $p->tags($pg);
		$name = "$name [$tags]" if $tags;
	}

	my $length = length($name) + $level - $minlevel;
	$max_sharename_len = $length if $length > $max_sharename_len;
}

if ($do_sharing_only) {
	#
	# -s - only print sharing relationships

	# Get list of sharing relationships
	my @relationships = $p->sharing_relationships(@pgs);

	if ($verbose) {
		printf "%-${max_sharename_len}s %s\n",
		  'RELATIONSHIP', 'PGs';
		foreach my $rel (@relationships) {
			my @pg_rel = grep { $p->sh_name($_) eq $rel }
			  @pgs;
			my $pg_rel = $p->id_collapse (@pg_rel);
			$pgs_by_relationship{$rel} = \@pg_rel;
		}
	}

	foreach my $rel (@relationships) {
		printf "%-${max_sharename_len}s", $rel;
		if ($verbose) {
			my @pgs = @{$pgs_by_relationship{$rel}};
			my $pgs = $p->id_collapse (@pgs);
			print ' ', $pgs;
		}
		print "\n";
	}

	# we are done
	exit($rc);
}

#
# Print PGs either in list form or tree form
#
if (!$do_tree) {
	my $header;

	$header = sprintf "%-${max_pg_len}s %-${max_sharename_len}s" .
	  "   %s\n",
	    'PG', 'RELATIONSHIP', 'CPUs';

	print $header;
	map { pg_print ($p, $_) } @pgs;
} else {
	#
	# Construct a tree from PG hierarchy and prune any PGs that are
	# specified with -R option
	#
	my $pg_tree = pg_make_tree($p);
	map { pg_remove_from_tree($pg_tree, $_) } @exclude_pgs;

	# Find top-level PGs
	my @top_level = grep {
		$pg_tree->{$_} && !defined($pg_tree->{$_}->{parent})
	} @pgs;

	# Print each top-level node as ASCII tree
	foreach my $pg (@top_level) {
		my $children = $pg_tree->{$pg}->{children};
		my @children = $children ? @{$children} : ();
		@children = $p->intersect(\@children, \@pgs);
		pg_print_tree($p, $pg_tree, $pg, '', '', scalar @children);
	}
}

# We are done!
exit($rc);

######################################################################
# Internal functions
#

#
# pg_print(cookie, pg)
# print PG information in list mode
#
sub pg_print
{
	my $p = shift;
	my $pg = shift;
	my $sharing = $p->sh_name($pg);
	if ($do_physical) {
		my $tags = $p->tags($pg);
		$sharing = "$sharing [$tags]" if $tags;
	}
	my $level = $p->level($pg) - $minlevel;
	$sharing = (' ' x (LEVEL_OFFSET * $level)) . $sharing;
	my $cpus = $p->cpus($pg);
	printf "%-${max_pg_len}d %-${max_sharename_len}s", $pg, $sharing;
	print "   $cpus";
	print "\n";
}

#
# pg_showcpus(cookie, pg)
# Print CPUs in the current PG
#
sub pg_showcpus
{
	my $p = shift;
	my $pg = shift;

	my @cpus = $p->cpus($pg);
	my $ncpus = scalar @cpus;
	return 0 unless $ncpus;
	my $cpu_string = $p->cpus($pg);
	return (($ncpus == 1) ?
		"CPU: $cpu_string":
		"CPUs: $cpu_string");
}

#
# pg_print_node(cookie, pg)
# print PG as ASCII tree node
#
sub pg_print_node
{
	my $p = shift;
	my $pg = shift;

	my $sharing = $p->sh_name($pg);
	if ($do_physical) {
		my $tags = $p->tags($pg);
		$sharing = "$sharing [$tags]" if $tags;
	}

	print "$pg ($sharing)";
	my $cpus = pg_showcpus($p, $pg);
	print " $cpus";
	print "\n";
}

#
# pg_print_tree(cookie, tree, pg, prefix, childprefix, npeers)
# print ASCII tree of PGs in the tree
# prefix should be used for the current node, childprefix for children nodes
# npeers is the number of peers of the current node
#
sub pg_print_tree
{
	my $p = shift;
	my $pg_tree = shift;
	my $pg = shift;
	return unless defined ($pg);	# done!
	my $prefix = shift;
	my $childprefix = shift;
	my $npeers = shift;

	# Get list of my children
	my $children = $pg_tree->{$pg}->{children};
	my @children = $children ? @{$children} : ();
	@children = $p->intersect(\@children, \@pgs);
	my $nchildren = scalar @children;

	my $printprefix = "$childprefix";
	my $printpostfix = $npeers ? "|   " : "    ";

	my $bar = $npeers ? "|" : "`";

	print $childprefix ? $childprefix : "";
	print $prefix ? "$bar" . "-- " : "";
	pg_print_node ($p, $pg);

	my $new_prefix = $npeers ? $prefix : "    ";

	# Print the subtree with a new offset, starting from each child
	map {
		pg_print_tree($p, $pg_tree, $_, "|   ",
		      "$childprefix$new_prefix", --$nchildren)
	} @children;
}

#
# list_match(arg, list)
# Return arg if argument matches any of the elements on the list
#
sub list_match
{
	my $arg = shift;

	return first { $arg =~ m/$_/i } @_;
}

#
# Make a version of PG parent-children relationships from cookie
#
sub pg_make_tree
{
	my $p = shift;
	my $pg_tree = ();

	foreach my $pg ($p->all()) {
		my @children = $p->children($pg);
		$pg_tree->{$pg}->{parent} = $p->parent($pg);
		$pg_tree->{$pg}->{children} = \@children;
	}

	return ($pg_tree);
}

#
# pg_remove_from_tree(tree, pg)
# Prune PG from the tree
#
sub pg_remove_from_tree
{
	my $pg_tree = shift;
	my $pg = shift;
	my $node = $pg_tree->{$pg};
	return unless $node;

	my @children = @{$node->{children}};
	my $parent = $node->{parent};
	my $parent_node;

	#
	# Children have a new parent
	#
	map { $pg_tree->{$_}->{parent} = $parent } @children;

	#
	# All children move to the parent (if there is one)
	#
	if (defined($parent) && ($parent_node = $pg_tree->{$parent})) {
		#
		# Merge children from parent and @children list
		#
		my @parent_children = @{$parent_node->{children}};
		#
		# Remove myself from parent children
		#
		@parent_children = grep { $_ != $pg } @parent_children;
		@parent_children = $p->nsort(@parent_children, @children);
		$parent_node->{children} = \@parent_children;
	}

	# Remove current node
	delete $pg_tree->{$pg};
}

#
# For a given list of PGs return the full lineage
#
sub pg_lineage
{
	my $p = shift;
	return unless scalar @_;

	my @parents = grep { defined($_) } map { $p->parent ($_) } @_;

	return ($p->uniq(@_, @parents, pg_lineage ($p, @parents)));
}

#
# Print usage information and exit with the return code specified
#
sub usage
{
	my $rc = shift;
	printf STDERR
	  gettext("Usage:\t%s [-T] [-p] [-v] [-r string] [-R string] [pg ... | -c processor_id ...]\n\n"),
	    $cmdname;
	printf STDERR
	  gettext("\t%s -s [-v] [-r string] [-R string] [pg ... | -c processor_id ...]\n\n"), $cmdname;
	printf STDERR gettext("\t%s -C | -I [-r string] [-R string] [pg ... | -c processor_id ...]\n\n"),
	  $cmdname;
	printf STDERR gettext("\t%s -h\n\n"), $cmdname;

	exit($rc);
}

__END__
