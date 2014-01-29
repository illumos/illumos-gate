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
# Copyright (c) 2014 Racktop Systems.
#

#
# Lgrp.pm provides procedural and object-oriented interface to the Solaris
# liblgrp(3LIB) library.
#


require 5.0010;
use strict;
use warnings;
use Carp;

package Sun::Solaris::Lgrp;

our $VERSION = '1.1';
use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

require Exporter;

our @ISA = qw(Exporter);

our (@EXPORT_OK, %EXPORT_TAGS);

# Things to export
my @lgrp_constants = qw(LGRP_AFF_NONE LGRP_AFF_STRONG LGRP_AFF_WEAK
			LGRP_CONTENT_DIRECT LGRP_CONTENT_HIERARCHY
			LGRP_MEM_SZ_FREE LGRP_MEM_SZ_INSTALLED LGRP_VER_CURRENT
			LGRP_VER_NONE LGRP_VIEW_CALLER
			LGRP_VIEW_OS LGRP_NONE
			LGRP_RSRC_CPU LGRP_RSRC_MEM
			LGRP_CONTENT_ALL LGRP_LAT_CPU_TO_MEM
);

my @proc_constants = qw(P_PID P_LWPID P_MYID);

my @constants = (@lgrp_constants, @proc_constants);

my @functions = qw(lgrp_affinity_get lgrp_affinity_set
		   lgrp_children lgrp_cookie_stale lgrp_cpus lgrp_fini
		   lgrp_home lgrp_init lgrp_latency lgrp_latency_cookie
		   lgrp_mem_size lgrp_nlgrps lgrp_parents
		   lgrp_root lgrp_version lgrp_view lgrp_resources
		   lgrp_isleaf lgrp_lgrps lgrp_leaves);

my @all = (@constants, @functions);

# Define symbolic names for various subsets of export lists
%EXPORT_TAGS = ('CONSTANTS' => \@constants,
		'LGRP_CONSTANTS' => \@lgrp_constants,
		'PROC_CONSTANTS' => \@proc_constants,
		'FUNCTIONS' => \@functions,
		'ALL' => \@all);

# Define things that are ok ot export.
@EXPORT_OK = ( @{ $EXPORT_TAGS{'ALL'} } );

#
# _usage(): print error message and terminate the program.
#
sub _usage
{
	my $msg = shift;
	Carp::croak "Usage: Sun::Solaris::Lgrp::$msg";
}

#
# lgrp_isleaf($cookie, $lgrp)
#   Returns T if lgrp is leaf, F otherwise.
#
sub lgrp_isleaf
{
	scalar @_ == 2 or _usage "lgrp_isleaf(cookie, lgrp)";
	return (!lgrp_children(shift, shift));
}

#
# lgrp_lgrps($cookie, [$lgrp])
#   Returns: list of lgrps in a subtree starting from $lgrp.
# 	     If $root is not specified, use lgrp_root.
# 	     undef on failure.
sub lgrp_lgrps
{
	scalar @_ > 0 or _usage("lgrp_lgrps(cookie, [lgrp])");
	my $cookie = shift;
	my $root = shift;
	$root = lgrp_root($cookie) unless defined $root;
	return unless defined $root;
	my @children = lgrp_children($cookie, $root);
	my @result;

	#
	# Concatenate root with subtrees for every children. Every subtree is
	# obtained by calling lgrp_lgrps recursively with each of the children
	# as the argument.
	#
	@result = @children ?
	  ($root, map {lgrp_lgrps($cookie, $_)} @children) :
	    ($root);
	return (wantarray ? @result : scalar @result);
}

#
# lgrp_leaves($cookie, [$lgrp])
#   Returns: list of leaves in the hierarchy starting from $lgrp.
# 	     If $lgrp is not specified, use lgrp_root.
# 	     undef on failure.
#
sub lgrp_leaves
{
	scalar @_ > 0 or _usage("lgrp_leaves(cookie, [lgrp])");
	my $cookie = shift;
	my $root = shift;
	$root = lgrp_root($cookie) unless defined $root;
	return unless defined $root;
	my @result = grep {
		lgrp_isleaf($cookie, $_)
	} lgrp_lgrps($cookie, $root);
	return (wantarray ? @result : scalar @result);
}

######################################################################
# Object-Oriented interface.
######################################################################

#
# cookie: extract cookie from the argument.
# If the argument is scalar, it is the cookie itself, otherwise it is the
# reference to the object and the cookie value is in $self->{COOKIE}.
#
sub cookie
{
	my $self = shift;
	return ((ref $self) ? $self->{COOKIE} : $self);
}

#
# new: The object constructor
#
sub new
{
	my $class = shift;
	my ($self, $view);
	$view = shift;
	$self->{COOKIE} = ($view ? lgrp_init($view) : lgrp_init()) or
	  croak("lgrp_init: $!\n"), return;
	bless($self, $class) if defined($class);
	bless($self) unless defined($class);
	return ($self);
}

#
# DESTROY: the object destructor.
#
sub DESTROY
{
	lgrp_fini(cookie(shift));
}

############################################################
# Wrapper methods.
#
sub stale
{
	scalar @_ == 1 or _usage("stale(class)");
	return (lgrp_cookie_stale(cookie(shift)));
}

sub view
{
	scalar @_ == 1 or _usage("view(class)");
	return (lgrp_view(cookie(shift)));
}

sub root
{
	scalar @_ == 1 or _usage("root(class)");
	return (lgrp_root(cookie(shift)));
}

sub nlgrps
{
	scalar @_ == 1 or _usage("nlgrps(class)");
	return (lgrp_nlgrps(cookie(shift)));
}

sub lgrps
{
	scalar @_ > 0 or _usage("lgrps(class, [lgrp])");
	return (lgrp_lgrps(cookie(shift), shift));
}

sub leaves
{
	scalar @_ > 0 or _usage("leaves(class, [lgrp])");
	return (lgrp_leaves(cookie(shift), shift));
}

sub version
{
	scalar @_ > 0 or _usage("leaves(class, [version])");
	shift;
	return (lgrp_version(shift || 0));
}

sub children
{
	scalar @_ == 2 or _usage("children(class, lgrp)");
	return (lgrp_children(cookie(shift), shift));
}

sub parents
{
	scalar @_ == 2 or _usage("parents(class, lgrp)");
	return (lgrp_parents(cookie(shift), shift));
}

sub mem_size
{
	scalar @_ == 4 or _usage("mem_size(class, lgrp, type, content)");
	return (lgrp_mem_size(cookie(shift), shift, shift, shift));
}

sub cpus
{
	scalar @_ == 3 or _usage("cpus(class, lgrp, content)");
	return (lgrp_cpus(cookie(shift), shift, shift));
}

sub isleaf
{
	scalar @_ == 2 or _usage("isleaf(class, lgrp)");
	lgrp_isleaf(cookie(shift), shift);
}

sub resources
{
	scalar @_ == 3 or _usage("resources(class, lgrp, resource)");
	return (lgrp_resources(cookie(shift), shift, shift));
}

sub latency
{
	scalar @_ == 3 or _usage("latency(class, from, to)");
	return (lgrp_latency_cookie(cookie(shift), shift, shift));
}

# Methods that do not require cookie
sub home
{
	scalar @_ == 3 or _usage("home(class, idtype, id)");
	shift;
	return (lgrp_home(shift, shift));
}

sub affinity_get
{
	scalar @_ == 4 or _usage("affinity_get(class, idtype, id, lgrp)");
	shift;
	return (lgrp_affinity_get(shift, shift, shift));
}

sub affinity_set
{
	scalar @_ == 5 or
	  _usage("affinity_set(class, idtype, id, lgrp, affinity)");
	shift;
	return (lgrp_affinity_set(shift, shift, shift, shift));
}

1;

__END__
