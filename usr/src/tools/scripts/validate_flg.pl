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

# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

use strict;
use File::Find ();
require v5.8.4;

use vars qw/$f_flg *name *dir @execlist $basedir @opt_e @exclude/;
*name   = *File::Find::name;
*dir    = *File::Find::dir;

# Use the same mechanism as def.dir.flp to determine if there are any
# SCCS files matching the pattern supplied for a "find_files"
# statement.
sub sccs_empty {
    my ($pat, $dir) = @_;
    return 0 if $f_flg;
    my $foo = `find $dir -name "$pat" -print | grep /SCCS/s.`;
    $foo eq "";
}

# Not pretty, but simple enough to work for the known cases.
# Does not bother with curly braces or fancy substitutions.
# Returns undef if this pattern is excluded.
sub expand {
    my ($str) = @_;
    while ($str =~ /\$(\w+)/) {
	my $newstr = $ENV{$1};
	$str =~ s/\$$1/$newstr/g;
    }
    foreach my $pat (@exclude) {
	return undef if $str =~ /$pat/;
    }
    $str;
}

# Process a single inc.flg or req.flg file.
sub process_file {
    my ($fname, $incpath) = @_;
    my ($dname, $isincflg);
    my ($expfile, $newpath, $line, $cont, $firstline, $text);

    $dname = $fname;
    $dname =~ s+/[^/]*$++;

    $isincflg = $fname =~ /inc.flg$/;

    if (defined $incpath) {
	$newpath = "$incpath, from $fname:";
    } else {
	$newpath = "from $fname:";
    }

    if (open INC, "<$fname") {
	$line = 0;
	$cont = 0;
	while (<INC>) {
	    chomp;
	    $line++;
	    ( $cont = 0, next ) if /^\s*#/ || /^\s*$/;
	    if ($cont) {
		$text = $text . $_;
	    } else {
		$firstline = $line;
		$text = $_;
	    }
	    if (/\\$/) {
		$cont = 1;
		$text =~ s/\\$//;
		next;
	    }
	    $cont = 0;
	    if ($text =~ /\s*echo_file\s+(\S+)/) {
		next if !defined($expfile = expand($1));
		warn "$fname:$firstline: $1 isn't a file\n" if ! -f $expfile;
	    } elsif ($text =~ /\s*find_files\s+['"]([^'"]+)['"]\s+(.*)/) {
		foreach my $dir (split(/\s+/, "$2")) {
		    next if !defined($expfile = expand($dir));
		    if (! -d $expfile) {
			warn "$fname:$firstline: $dir isn't a directory\n";
		    } elsif ($isincflg && $expfile eq $dname) {
			warn "$fname:$firstline: $dir is unnecessary\n";
		    } elsif (sccs_empty($1, $expfile)) {
			warn "$fname:$firstline: $dir has no SCCS objects ",
				"with '$1'\n";
		    }
		}
	    } elsif ($text =~ /\s*exec_file\s+(\S+)/) {
		next if !defined($expfile = expand($1));
		if (-f $expfile) {
		    push @execlist, $expfile, "$newpath:$firstline";
		} else {
		    warn "$fname:$firstline: $1 isn't a file\n";
		    warn "included $incpath\n" if defined $incpath;
		}
	    } else {
		warn "$0: $fname:$firstline: unknown entry: $text\n";
		warn "included $incpath\n" if defined $incpath;
	    }
	}
	close INC;
    } else {
	warn "$0: $fname: $!\n";
    }
}

sub wanted {
    process_file($_, undef) if /\/(inc|req)\.flg$/ && -f $_;
}

sub next_arg {
    my ($arg) = @_;
    if ($arg eq "") {
	die "$0: missing argument for $_\n" if $#ARGV == -1;
	$arg = shift @ARGV;
    }
    $arg;
}

# I'd like to use Perl's getopts here, but it doesn't handle repeated
# options, and using comma separators is just too ugly.
# This doesn't handle combined options (as in '-rm'), but I don't care.
my $arg;
while ($#ARGV >= 0) {
    $_ = $ARGV[0];
    last if /^[^-]/;
    shift @ARGV;
    last if /^--$/;
    SWITCH: {
	  /^-f/ && do { $f_flg = 1; last SWITCH; };
	  if (/^-e(.*)$/) {
	      $arg = next_arg($1);
	      push @opt_e, $arg;
	      last SWITCH;
	  }
	  print "$0: unknown option $_\n";
	  usage();
    }
}

# compile the 'exclude' regexps
@exclude = map qr/$_/x, @opt_e;

$basedir = "usr";
if ($#ARGV == 0) {
    $basedir = shift @ARGV;
} elsif ($#ARGV > 0) {
    die "$0: unexpected arguments\n";
}

die "$0: \$CODEMGR_WS must be set\n" if $ENV{CODEMGR_WS} eq "";
chdir $ENV{CODEMGR_WS} or die "$0: chdir $ENV{CODEMGR_WS}: $!\n";

File::Find::find({wanted => \&wanted, no_chdir => 1}, $basedir);

# After passing through the tree, process all of the included files.
# There aren't many of these, so don't bother trying to optimize the
# traversal.  Just do them all.
while (@execlist) {
    my $file = shift @execlist;
    my $incpath = shift @execlist;
    process_file($file, $incpath);
}

exit 0;
