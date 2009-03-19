#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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

# WARNING -- this package implements a Sun private interface; it may
# change without notice.

package Sun::Solaris::BSM::_BSMparse;
require 5.005;
use strict;
use Exporter;
use Sun::Solaris::Utils qw(gettext);

use vars qw($VERSION $failedOpen
    %EXPORT_TAGS @ISA @EXPORT_OK @EXPORT_FAIL);

$VERSION = '1.01';

@ISA = qw(Exporter);
my @constants = qw();
@EXPORT_OK = qw(readAttr readEvent readClass filterLabel filterCallName
		readControl getPathList readUser ckAttrEvent);
@EXPORT_FAIL = qw($failedOpen);
%EXPORT_TAGS = (ALL => \@EXPORT_OK);

$failedOpen = gettext("failed to open %s: %s");

sub new {
	my $obj = shift;
	my $debug = shift;	# bool
	my $filters = shift;	# options for filtering

	my $dir = '/etc/security';
	my $attrDir = '/usr/lib/audit';
        my $configDir = $dir;
	$attrDir = shift if (@_);	# override for test
	$configDir = shift if (@_);	# ditto

	my $suffix = '';
	$suffix = shift if (@_);	# test, again

	$obj = ref($obj) || $obj;

	my ($recordf, $classf, $controlf, $eventf, $userf) =
	   ("$attrDir/audit_record_attr$suffix",
	    "$configDir/audit_class$suffix",
	    "$configDir/audit_control$suffix",
	    "$configDir/audit_event$suffix",
	    "$configDir/audit_user$suffix");

	return (bless {
		'attrFile'	=> $recordf,
		'classFile'	=> $classf,
		'classFilter'	=> $filters->{'classFilter'},
		'controlFile'	=> $controlf,
		'debug'		=> $debug,
		'eventFile'	=> $eventf,
		'eventFilter'	=> $filters->{'eventFilter'},
		'idFilter'	=> $filters->{'idFilter'},
		'havePath'	=> 0,
		'kernelDefault'	=> '',
		'userDefault'	=> '',
		'userFile'	=> $userf}, $obj);
}

# readAttr
# read the hand edited attrFile file
#
# return a hash reference

sub readAttr {
	my $obj = shift;

	my $file = $obj->{'attrFile'};
	my $fileHandle = do {local *FileHandle; *FileHandle};
	open($fileHandle, $file) or die sprintf("$failedOpen\n", $file, $!);

	my $count = 0;
	my $lastAttr = '';
	my $lastMacro = '';

	my $attrState = -1;
	my $caseState = 0;
	my $label;
	my $callName = '';
	my $skip = '';
	my $description = 'none';
	my $format = 'none';
	my $comment = '';
	my $title = 'none';
	my $note = '';
	my $case = '';
	my @case = ();
	my %skipClass;
	my %attr = ();
	my %token = ();
	my $classFilter = $obj->{'classFilter'};
	$classFilter = '' unless (defined ($classFilter));

	my %noteAlias = ();
	while (<$fileHandle>) {
		chomp;
		s/#.*//;	 # remove comment
		next if (/^\s*$/);

		if ($attrState < 0) {  # initial state:  header info
			# continue assigning lines to multiline macros 
			# type: message
			if ( $lastMacro ne '' ) {
				my ($mcr, $attr) = split(/\s*:\s*/, $lastMacro);

				if ($mcr eq "message") {
					chomp($noteAlias{$attr}); 
					chop($noteAlias{$attr});

					$_ =~ /^\s*(.*)/i;
					$noteAlias{$attr} .= $1;

					$lastMacro = chkBslash($lastMacro, \$1);
				}
				next;
			}

			$lastMacro = '';
			if (/^\s*skipClass\s*=\s*(.*)/i) {
				my $class = $1;
				# don't skip what you're searching for
				next if (index(lc($classFilter),lc($class)) > -1);
				$skipClass{$1} = 1;
				next;
			}
			elsif (/^\s*token\s*=\s*(.*)/i) {
				my ($attr, $value) = split(/\s*:\s*/, $1);
				$token{$attr} = $value;
				next;
			}
			elsif (/^\s*message\s*=\s*(.*)/i) {
				my ($attr, $value) = split(/\s*:\s*/, $1);
				$noteAlias{$attr} = $value;
				$lastMacro = chkBslash("message:$attr", \$1);
				next;
			}
			elsif (/^\s*kernel\s*=\s*(.*)/i) {
				my ($attr, $value) = split(/\s*:\s*/, $1);
				$obj->{'kernelDefault'} = $1;
				next;
			}
			elsif (/^\s*user\s*=\s*(.*)/i) {
				my ($attr, $value) = split(/\s*:\s*/, $1);
				$obj->{'userDefault'} = $1;
				next;
			}
		}

		# continue assigning lines to multiline attributes 
		# type: case, comment, note, format
		if ( $lastAttr ne '' ) {
			my $curAttrVal = '';

			eval "\$curAttrVal = \$$lastAttr";
			chomp($curAttrVal); 
			chop($curAttrVal);

			$_ =~ /^\s*(.*)/i;
			$curAttrVal .= $1;

			eval "\$$lastAttr = \$curAttrVal";

			$lastAttr = chkBslash($lastAttr, \$1);
			next;
		}

		$lastAttr = '';
		if (/^\s*label\s*=\s*(.*)/i) {
			$attrState = 0 if ($attrState < 0);
			my $newLabel = $1;

			if ($obj->{'debug'}) {
				print STDERR qq{
$newLabel is duplicated in the attribute file (line $.)
				} if ($attr{$newLabel});
			}
			# if $attrState not zero, an unwritten record exists
			if ($attrState) {
				$callName = $obj->filterCallName($label,
				    $callName);
				push(@case, [$case, $format, $comment, $note]);

				if ($obj->filterLabel($label)) {
					$attr{$label} =
					    [$callName, $description, $title,
					    $skip, @case];
					$count++;
				}
				$format = $description = $title = 'none';
				$case = $note = $comment = $skip = $callName
				    = '';
				@case = ();
				$caseState = 0;
			}
			$label = $newLabel;
			$attrState = 1;
		}
		elsif (/^\s*skip\s*=\s*(.*)/i) {
			$skip = $1;
		}
		elsif (/^\s*syscall\s*=\s*(.*)/i) {
			$callName = $1;
		}
		elsif (/^\s*program\s*=\s*(.*)/i) {
			$callName = $1;
		}
		elsif (/^\s*title\s*=\s*(.*)/i) {
			$title = $1;
		}
		elsif (/^\s*see\s*=\s*(.*)/i) {
			$description = $1;
		}
		elsif (/^\s*format\s*=\s*(.*)/i) {
			$format = $1;
			$lastAttr = chkBslash("format", \$1);
		}
		elsif (/^\s*comment\s*=\s*(.*)/i) {
			$comment .= $1;
			$lastAttr = chkBslash("comment", \$1);
		}
		elsif (/^\s*note\s*=\s*(.*)/i) {
			$note .= $1;
			$lastAttr = chkBslash("note", \$1);
		}
		elsif (/^\s*case\s*=\s*(.*)/i) {
			if ($caseState) {
				push(@case, [$case, $format, $comment, $note]);
				$format = 'none';
				$comment = $note = '';
			}
			$case = $1;
			$lastAttr = chkBslash("case", \$1);
			$caseState = 1;
		}
	}
	if ($attrState) {
		$callName = $obj->filterCallName($label, $callName);
		push(@case, [$case, $format, $comment, $note]);
		if ($obj->filterLabel($label)) {
			$attr{$label} = [$callName, $description, $title, $skip,
			    @case];
			$count++;
		}
	}
	close $fileHandle;
	print STDERR "found $count audit attribute entries\n" if ($obj->{'debug'});

	return ($obj->{'attr'} = \%attr, \%token, \%skipClass, \%noteAlias);
}

# readEvent
# read eventFile and extract audit event information, including
# which classes are associated with each event and what call is
# related.

sub readEvent {
	my $obj = shift;

	my %event = ();
	my $file = $obj->{'eventFile'};

	my $fileHandle = do {local *FileHandle; *FileHandle};
	open($fileHandle, $file) or die sprintf("$failedOpen\n", $file, $!);

	my $count = 0;

	unless (defined $obj->{'class'} && (scalar keys %{$obj->{'class'}} > 1)) {
		$obj->readClass();
	}

	my @classFilterMasks = ();
	my $classFilter = $obj->{'classFilter'};
	if ($classFilter) {
		foreach (split(',', $classFilter)) {
			push @classFilterMasks, $obj->{'class'}{$_};
		}
	}
	# ignore customer-supplied audit events (id > 32767)

	while (<$fileHandle>) {
		chomp;
		s/#.*//;	# remove comment
		next if (/^\s*$/);
		if (/^\s*(\d+):(\w+):([^:]+):(.*)/) {
			my $id = $1;
			my $label = $2;
			my $description = $3;
			my $class = $4;

			if ($id !~ /\d+/) {
				print STDERR "$id is not numeric (line $.)\n";
				next;
			}
			next if ($id > 32767);

			$class =~ s/\s*$//;

			if ($obj->{'debug'}) {
				print STDERR qq{
$label is duplicated in the event file (line $.)
				} if ($event{$label});
			}
			next unless ($obj->filterLabel($label));
			my $mask = 0;
			if ($classFilter) {
				foreach (split(/\s*,\s*/, $class)) {
					$mask |= $obj->{'class'}{$_};
				}
				my $skip = 0;
				foreach my $filterMask (@classFilterMasks) {
					unless ($mask & $filterMask) {
						$skip = 1;
						last;
					}
				}
				next if $skip;
			}
			if ($obj->{'idFilter'}) {
				next unless ($obj->{'idFilter'} == $id);
			}
			$event{$label} = [$id, $class, $description];

			$count++;
		}
	}
	close $fileHandle;
	print STDERR "found $count audit events\n" if ($obj->{'debug'});

	return ($obj->{'event'} = \%event);
}

# readClass
# read classFile and extract audit class information

sub readClass {
	my $obj = shift;

	my %class = ();
	my $file = $obj->{'classFile'};

	my $fileHandle = do {local *FileHandle; *FileHandle};
	open($fileHandle, $file) or die sprintf("$failedOpen\n", $file, $!);

	my $count = 0;

	while (<$fileHandle>) {
		chomp;
		s/#.*//;	# remove comment
		next if (/^\s*$/);
		my ($mask1, $class) = split(/:/);  # third field not used
		my $mask2 = hex($mask1);  # integer
		$class{$class} = $mask2;
		$count++;
	}
	close $fileHandle;
	print STDERR "found $count audit classes\n" if ($obj->{'debug'});

	return ($obj->{'class'} = \%class);
}

sub filterLabel {
	my $obj = shift;
	my $label = shift;

	my $eventFilter = $obj->{'eventFilter'};
	my $keepIt = 1;

	$keepIt = 0 if ($eventFilter && ($label !~ /$eventFilter/i));

	return ($keepIt);
}

# Normally, the root of the event label is the system call.  The
# attrFile attribute syscall or program overrides this.

sub filterCallName {
	my $obj = shift;
	my $label = shift;
	my $callName = shift;

	return ($callName) if ($callName);

	$label =~ /AUE_(.*)/;

	my $name = $1;

	return (lc ($name));
}

# readControl
# read controlFile and extract flags and naflags information
# at present, minfree, maxfree and the audit partitions are not
# checked.

sub readControl {
	my $obj = shift;
	my $failMode = shift;

	my $cError = 0;
	my $errors = '';
	my $file = $obj->{'controlFile'};
	my $invalidClass = gettext('invalid class, %s, in audit_control: %s');

	my $fileHandle = do {local *FileHandle; *FileHandle};
	unless (open($fileHandle, $file)) {
		die sprintf("$failedOpen\n", $file, $!)
			unless ($failMode eq 'ignore');
		return (0, '');
	}
	my %class = $obj->{'class'};
	my @paths = $obj->{'paths'};
	while (<$fileHandle>) {
		chomp;
		s/#.*//;	# remove comment
		next if (/^\s*$/);
		if ((/^\s*flags:/i) || (/^\s*naflags:/i)) {
			my ($class) = /flags:\s*(.*)/;
			my @class = split(/\s*,\s*/, $class);

			foreach $class (@class) {
				$class =~ s/^[-+^]+//;
				unless (defined ($class{$class})) {
					$errors .=
					    sprintf("$invalidClass\n",
					    $class, $_);
					$cError++;
				}
			}
		}
		elsif (/^\s*dir:\s*(.*)/) {
			push (@paths, $1);
			$obj->{'havePath'} = 1;
		}
	}
	close $fileHandle;
	return ($cError, $errors);
}

sub getPathList {
	my $obj = shift;

	$obj->readControl() unless ($obj->{'havePath'});

	return ($obj->{'paths'});
}

# readUser
# read userFile and extract audit information for validation

sub readUser {
	my $obj = shift;
	my $failMode = shift;

	my $cError = 0;
	my $error = '';
	my $file = $obj->{'userFile'};

	my $fileHandle = do {local *FileHandle; *FileHandle};
	unless (open($fileHandle, $file)) {
		die sprintf("$failedOpen\n", $file, $!)
			unless ($failMode eq 'ignore');
		return (0, '');
	}
	# these strings are defined here mostly to avoid indentation problems
	my $emptyErr   = gettext('empty audit mask in audit_user: %s');
	my $syntaxErr1 = gettext(
	    'incorrect syntax (exactly two colons req\'d) in audit_user: %s');
	my $syntaxErr2 = gettext('incorrect syntax in audit_user: %s');
	my $invalidErr = gettext('invalid class, %s, in audit_user: %s');
	my $undefined  = gettext('undefined user name in audit_user: %s');

	my %class = $obj->{'class'};
	while (<$fileHandle>) {
		chomp;
		s/#.*//;        # remove comment
		next if (/^\s*$/);
		my $colonCount = tr/:/:/;

		if ($colonCount != 2) {
			$error .= sprintf("$syntaxErr1\n", $_);
			$cError++;
		}
		my ($user, $always, $never) = split(/\s*:\s*/);
		unless (defined($user)) {
			$error .= sprintf("$syntaxErr2\n", $_);
			$cError++;
			next;
		}
		$error .= sprintf("$emptyErr\n", $_) unless ($always);

		my ($name) = getpwnam($user);
		unless (defined($name)) {
			$error .= sprintf("$undefined\n", $user);
			$cError++;
		}
		unless (defined($always) && defined($never)) {
			$error .= sprintf("$emptyErr\n", $_);
			$cError++;
			next;
		}
		my $verify = $always . ',' . $never;
		my @class = split(/\s*,\s*/, $verify);
		my $thisClass;

		foreach $thisClass (@class) {
			$thisClass =~ s/^[-+^]+//;
			unless (defined $class{$thisClass}) {
				$error .= sprintf("$invalidErr\n", $thisClass,
				    $_);
				$cError++;
			}
		}
	}
	close $fileHandle;
	return ($cError, $error);
}

# ckAttrEvent complains if controlFile and attrFile don''t contain the
# same list of events.

sub ckAttrEvent {
	my $obj = shift;

	my $cError = 0;
	my $error = '';
	my $cAttr = 0;
	my $label;
	my $attrErr  = gettext(
	    '%s entry in attribute file but not in event file');
	my $eventErr = gettext(
	    '%s entry in event file but not in attribute file');

	my %attr = %{$obj->{'attr'}};
	my %event = %{$obj->{'event'}};
	foreach $label (keys %attr) {
		$cAttr++;
		unless ($event{$label}) {
			$error .= sprintf("$attrErr\n", $label);
			$cError++;
		}
	}
	my $cEvent = 0;
	foreach $label (keys %event) {
		$cEvent++;
		unless ($attr{$label}) {
			$error .= sprintf("$eventErr\n", $label);
			$cError++;
		}
	}
	# debug only; not I18N'd
	print STDERR
	    "$cAttr audit_record_attr entries and $cEvent audit_event entries\n"
		if ($obj->{'debug'});
	return ($cError, $error);
}

# chkBslash (helper)
# check the given string for backslash character at the end; if found
# return the string sent as a first argument, otherwise return empty
# string.
sub chkBslash ($$) {
	my $retStr = shift;
	my $strPtr = shift;

	if ( $$strPtr !~ /\\$/ ) {
		 $retStr = '';
	}

	return $retStr;
}

1;
