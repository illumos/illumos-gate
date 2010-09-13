#!/usr/bin/perl

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

use Getopt::Std;
use Cwd;

use strict;

package MDesc;

use constant {
    MDEND  => 0x45,
    MDNODE => 0x4e,
    MDARC  => 0x61,
    MDDATA => 0x64,
    MDSTR  => 0x73,
    MDVAL  => 0x76,
};


sub new {
    my $class = shift;
    my $self = {};
    $self->{FILE} = undef;
    $self->{MAJOR} = undef;
    $self->{MINOR} = undef;
    $self->{NODE_SEC_SZ} = undef;
    $self->{NAME_SEC_SZ} = undef;
    $self->{DATA_SEC_SZ} = undef;
    $self->{NODES} = undef;
    $self->{NAMES} = undef;
    $self->{DATA} = undef;
    bless($self, $class);
    return $self;
}

sub open {
    my $self = shift;
    my ($mdhdr, $size);

    if (@_) {
        $self->{NAME} = shift;
    } else {
        $self->{NAME} = '/dev/mdesc';
    }
    return  unless open(MD, "$self->{NAME}");

    # Read and parse MD header
    unless (read(MD, $mdhdr, 16) == 16) {
        close (MD);
	return;
    }

    ($self->{MAJOR}, $self->{MINOR},
     $self->{NODE_SEC_SZ},
     $self->{NAME_SEC_SZ},
     $self->{DATA_SEC_SZ}) = unpack("nnNNN", $mdhdr);

    $size = read(MD, $self->{NODES}, $self->{NODE_SEC_SZ});
    $size = read(MD, $self->{NAMES}, $self->{NAME_SEC_SZ});
    $size = read(MD, $self->{DATA}, $self->{DATA_SEC_SZ});

    1;
}

#
# return hash of given node's information
#
sub getnode {
    my ($self, $nodeid) = @_;
    my ($tag, $name, $namelen, $nameoff, $datalen, $dataoff, %node);

    ($tag, $namelen, $nameoff, $datalen, $dataoff) =
      unpack("CCx2NNN", substr($self->{NODES}, $nodeid * 16, 16));
    $name = substr($self->{NAMES}, $nameoff, $namelen);
    %node = (tag => $tag, name => $name, nameid => $nameoff);

    if ($tag == MDSTR || $tag == MDDATA) {
        $node{'datalen'} = $datalen;
	$node{'dataoff'} = $dataoff;
    } elsif ($tag == MDVAL) {
        $node{'val'} = ($datalen << 32) | $dataoff;
    } elsif ($tag == MDARC || $tag == MDNODE) {
        $node{'idx'} = ($datalen << 32) | $dataoff;
    }

    return %node;
}


#
# return hash of given property's information
#
sub getprop {
    my ($self, $propid) = @_;
    my (%node, $tag, %prop);

    %node = $self->getnode($propid);
    $tag = $node{'tag'};
    %prop = (name => $node{'name'}, tag => $tag);

    if ($tag == MDSTR) {
        $prop{'string'} =
	  substr($self->{DATA}, $node{'dataoff'}, $node{'datalen'} - 1);
    } elsif ($tag == MDARC) {
	$prop{'arc'} = $node{'idx'};
    } elsif ($tag == MDVAL) {
	$prop{'val'} = $node{'val'};
    } elsif ($tag == MDDATA) {
	$prop{'length'} = $node{'datalen'};
	$prop{'offset'} = $node{'dataoff'};
    } else {
	return undef;
    }

    return %prop;
}
    

#
# find name table index of given name
#
sub findname {
    my ($self, $name) = @_;
    my ($idx, $next, $p);

    for ($idx = 0; $idx < $self->{NAME_SEC_SZ}; $idx = $next + 1) {
        $next = index($self->{NAMES}, "\0", $idx);
	$p = substr($self->{NAMES}, $idx, $next - $idx);
	return $idx  if ($p eq $name);
    }

    return -1;
}


#
# find given property in node
#
sub findprop {
    my ($self, $nodeid, $propname, $type) = @_;
    my (%node, $nameid);

    %node = $self->getnode($nodeid);
    return -1  if ($node{'tag'} != MDNODE);

    $nameid = $self->findname($propname);
    return -1  if ($nameid == -1);

    do {
        $nodeid++;
	%node = $self->getnode($nodeid);
	if ($node{'tag'} == $type && $node{'nameid'} == $nameid) {
	    return $nodeid;
	}
    } while ($node{'tag'} != MDEND);

    return -1;
}


#
# lookup property in node and return its hash
#
sub lookup {
    my ($self, $nodeid, $propname, $type) = @_;
    my ($propid);

    $propid = $self->findprop($nodeid, $propname, $type);
    return undef  if ($propid == -1);

    return $self->getprop($propid);
}


sub scan_node {
    my ($self, $nodeid, $nameid, $arcid, $ret, $seen) = @_;
    my (%node);

    return  if ($seen->[$nodeid] == 1);
    $seen->[$nodeid] = 1;

    %node = $self->getnode($nodeid);
    return                if ($node{'tag'} != MDNODE);
    push(@$ret, $nodeid)  if ($node{'nameid'} == $nameid);

    do {
	$nodeid++;
	%node = $self->getnode($nodeid);
	if ($node{'tag'} == MDARC && $node{'nameid'} == $arcid) {
	    $self->scan_node($node{'idx'}, $nameid, $arcid, $ret, $seen);
	}
    } while ($node{'tag'} != MDEND);
}


#
# scan dag from 'start' via 'arcname'
# return list of nodes named 'nodename'
#
sub scan {
    my ($self, $start, $nodename, $arcname) = @_;
    my ($nameid, $arcid, @ret, @seen);

    $nameid = $self->findname($nodename);
    $arcid = $self->findname($arcname);
    $self->scan_node($start, $nameid, $arcid, \@ret, \@seen);
    return @ret;
}	



package main;


#
# 'find' needs to use globals anyway, 
# so we might as well use the same ones
# everywhere
#
our ($old, $new);
our %opts;


#
# fix path_to_inst
#
sub fixinst {
    use File::Copy;
    my ($oldpat, $newpat);
    my ($in, $out);

    $oldpat = '"' . $old . '/';
    $newpat = '"' . $new . '/';

    $in = "etc/path_to_inst";
    $out = "/tmp/path$$";

    open(IN, "<", $in)     or die "can't open $in\n";
    open(OUT, ">", $out)   or die "can't open $out\n";

    my ($found, $path);
    #
    # first pass
    # see if there are any old paths that need to be re-written
    #
    $found = 0;
    while (<IN>) {
        ($path, undef, undef) = split;
        if ($path =~ /^$oldpat/) {
            $found = 1;
	    last;
	}
    }
    # return if no old paths found
    if ($found == 0) {
        close(IN);
	close(OUT);
        unlink $out;
        return 0;
    }

    print "replacing $old with $new in /etc/path_to_inst\n";
    #
    # 2nd pass
    # substitute new for old
    #
    seek(IN, 0, 0);
    while (<IN>) {
        ($path, undef, undef) = split;
        if ($path =~ /^$oldpat/) {
            s/$oldpat/$newpat/;
	}
        print OUT;
    }
    close(IN);
    close(OUT);

    if ($opts{v}) {
        print "path_to_inst changes:\n";
        system("/usr/bin/diff", $in, $out);
        print "\n";
    }

    move $out, $in        or die "can't modify $in\n";

    return 1;
}


our $oldpat;

sub wanted {
    my $targ;

    -l or return;
    $targ = readlink;
    if ($targ =~ /$oldpat/) {
        $targ =~ s/$old/$new/;
        unlink;
	symlink $targ, $_;
        print "symlink $_ changed to $targ\n"  if ($opts{v});
    }
}

#
# fix symlinks
#
sub fixdev {
    use File::Find;
    $oldpat = "/devices" . $old;

    print "updating /dev symlinks\n";
    find \&wanted, "dev";
}


#
# fixup path_to_inst and /dev symlinks
#
sub fixup {
    # setup globals
    ($old, $new) = @_;

    # if fixinst finds no matches, no need to run fixdev
    return  if (fixinst == 0);
    fixdev;
    print "\n"  if ($opts{v});
}

#
# remove caches
#
sub rmcache {
    unlink "etc/devices/devid_cache";
    unlink "etc/devices/devname_cache";
    unlink <etc/devices/mdi_*_cache>;
    unlink "etc/devices/retire_store";
    unlink "etc/devices/snapshot_cache";
    unlink "dev/.devlink_db";
}


# $< == 0              or die "$0: must be run as root\n";

getopts("vR:", \%opts);

if ($opts{R}) {
    chdir $opts{R}   or die "can't chdir to $opts{R}\n";
}
cwd() ne "/"         or die "can't run on root directory\n";

if ($#ARGV == 1) {
    #
    # manual run (no MD needed)
    #
    fixup @ARGV;
    rmcache;
    exit;
}


my ($md, @nodes, $nodeid, @aliases, $alias);
my (%newpath, %roots);

#
# scan MD for ioaliases
#
$md = MDesc->new;
$md->open;

@nodes = $md->scan(0, "ioaliases", "fwd");
$#nodes == 0    or die "missing ioaliases node\n";

#
# foreach ioalias node, replace any 'alias' paths
# with the 'current' one
#
# complicating this is that the alias paths can be
# substrings of each other, which can cause false
# hits in /etc/path_to_inst, so first gather all
# aliases with the same root into a list, then sort
# it by length so we always fix the longer alias
# paths before the shorter ones
#
@nodes = $md->scan(@nodes[0], "ioalias", "fwd");
foreach $nodeid (@nodes) {
    my (%prop, $current);

    %prop = $md->lookup($nodeid, "aliases", $md->MDSTR);
    @aliases = split(/ /, $prop{'string'});

    %prop = $md->lookup($nodeid, "current", $md->MDSTR);
    $current = $prop{'string'};

    foreach $alias (@aliases) {
        next  if ($alias eq $current);

        my ($slash, $root);
	$newpath{$alias} = $current;
	$slash = index($alias, '/', 1);
	if ($slash == -1) {
	    $root = $alias;
	} else {
	    $root = substr($alias, 0, $slash);
	}
	push(@{ $roots{$root} }, $alias);
    }
}

my $aref;
foreach $aref (values %roots) {
    @aliases = sort { length($b) <=> length($a) } @$aref;
    foreach $alias (@aliases) {
        fixup $alias, $newpath{$alias};
    }
}

rmcache;
