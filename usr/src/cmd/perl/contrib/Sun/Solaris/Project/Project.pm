#
# Copyright (c) 1999, 2008, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2014 Racktop Systems.
#

#
# Project.pm provides the bootstrap for the Sun::Solaris::Project module, and
# also functions for reading, validating and writing out project(4) format
# files.
#
################################################################################
require 5.0010;

use strict;
use warnings;
use locale;
use Errno;
use Fcntl;
use File::Basename;
use POSIX qw(locale_h limits_h);

package Sun::Solaris::Project;

our $VERSION = '1.9';

use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

our (@EXPORT_OK, %EXPORT_TAGS);
my @constants = qw(MAXPROJID PROJNAME_MAX PROJF_PATH PROJECT_BUFSZ
    SETPROJ_ERR_TASK SETPROJ_ERR_POOL);
my @syscalls = qw(getprojid);
my @libcalls = qw(setproject activeprojects getprojent setprojent endprojent
    getprojbyname getprojbyid getdefaultproj fgetprojent inproj
    getprojidbyname);
my @private = qw(projf_read projf_write projf_validate projent_parse
		 projent_parse_name projent_validate_unique_name
		 projent_parse_projid projent_validate_unique_id
		 projent_parse_comment
		 projent_parse_users
		 projent_parse_groups
		 projent_parse_attributes
		 projent_validate projent_validate_projid
		 projent_values_equal projent_values2string);

@EXPORT_OK = (@constants, @syscalls, @libcalls, @private);
%EXPORT_TAGS = (CONSTANTS => \@constants, SYSCALLS => \@syscalls,
    LIBCALLS => \@libcalls, PRIVATE => \@private, ALL => \@EXPORT_OK);

use base qw(Exporter);
use Sun::Solaris::Utils qw(gettext);

#
# Set up default rules for validating rctls.
# These rules are not global-flag specific, but instead
# are the total set of allowable values on all rctls.
#
use Config;
our $MaxNum = &RCTL_MAX_VALUE;
our %RctlRules;

my %rules;
our %SigNo;
my $j;
my $name;
foreach $name (split(' ', $Config{sig_name})) {
	$SigNo{$name} = $j;
	$j++;
}
%rules = (
    'privs' 	=> [ qw(basic privileged priv) ],
    'actions'	=> [ qw(none deny sig) ],
    'signals'	=> [ qw(ABRT XRES HUP STOP TERM KILL XFSZ XCPU),
		     $SigNo{'ABRT'},
		     $SigNo{'XRES'},
		     $SigNo{'HUP'},
		     $SigNo{'STOP'},
		     $SigNo{'TERM'},
		     $SigNo{'KILL'},
		     $SigNo{'XFSZ'},
		     $SigNo{'XCPU'} ],
    'max'	=> $MaxNum
);
	       
$RctlRules{'__DEFAULT__'} = \%rules;

#
# projf_combine_errors(errorA, errorlistB)
#
# Concatenates a single error with a list of errors.  Each error in the new
# list will have a status matching the status of errorA.
#
# Example:
# 
#	projf_combine_errors(
#	    [ 5, "Error on line %d, 10 ],
#	    [ [ 3, "Invalid Value %s", "foo" ],
#	      [ 6, "Duplicate Value %s", "bar" ]
#	    ]);
#
# would return the list ref:
#
#	[ [ 5, "Error on line %d: Invalid Value %s", 10, "foo" ],
#	  [ 5, "Error on line %d: Duplicate Value %s", 10, "bar" ]
#	]
#
# This function is used when a fuction wants to add more information to
# a list of errors returned by another function.
#
sub projf_combine_errors
{

	my ($error1, $errorlist)  = @_;
	my $error2;

	my $newerror;
	my @newerrorlist;

	my ($err1, $fmt1, @args1);
	my ($err2, $fmt2, @args2);

	($err1, $fmt1, @args1) = @$error1;
	foreach $error2 (@$errorlist) {

		($err2, $fmt2, @args2) = @$error2;
		$newerror = [ $err1, $fmt1 . ', ' . $fmt2, @args1, @args2];
		push(@newerrorlist, $newerror);
	}
	return (\@newerrorlist);
}

#
# projf_read(filename, flags)
#
# Reads and parses a project(4) file, and returns a list of projent hashes.
#
# Inputs:
#	filename - file to read
#	flags	 - hash ref of flags
#
# If flags contains key "validate", the project file entries will also be
# validated for run-time correctness  If so, the flags ref is forwarded to
# projf_validate().
#
# Return Value:
#
# Returns a ref to a list of projent hashes.  See projent_parse() for a
# description of a projent hash.
#
sub projf_read
{

	my ($fh, $flags) = @_;
	my @projents;
	my $projent;
	my $linenum = 0;
	my ($projname, $projid, $comment, $users, $groups, $attributes);
	my ($ret, $ref);
	my @errs;

	my ($line, $origline, $next, @projf);
	while (defined($line = <$fh>)) {

		$linenum++;
		$origline = $line;

		# Remove any line continuations and trailing newline.
		$line =~ s/\\\n//g;
		chomp($line);


		if (length($line) > (&PROJECT_BUFSZ - 2)) {
			push(@errs, 
			    [5,
			      gettext('Parse error on line %d, line too long'),
			    $linenum]);

		}

		($ret, $ref) = projent_parse($line, {});
		if ($ret != 0) {
			$ref = projf_combine_errors(
			    [5, gettext('Parse error on line %d'), $linenum],
			    $ref);
			push(@errs, @$ref);
			next;
		}

		$projent = $ref;

		#
		# Cache original line to save original format if it is
		# not changed.
		#
		$projent->{'line'} = $origline;
		$projent->{'modified'} = 'false';
		$projent->{'linenum'} = $linenum;

		push(@projents, $projent);
	}

	if (defined($flags->{'validate'}) && ($flags->{'validate'} eq 'true')) {
		($ret, $ref) = projf_validate(\@projents, $flags);
		if ($ret != 0) {
			push(@errs, @$ref);
		}	
	}	

	if (@errs) {
		return (1, \@errs);
		
	} else {
		return (0, \@projents);
	}
}	

#
# projf_write(filehandle, projent list)
# 
# Write a list of projent hashes to a file handle.
# projent's with key "modified" => false will be
# written using the "line" key.  projent's with
# key "modified" => "true" will be written by
# constructing a new line based on their "name"
# "projid", "comment", "userlist", "grouplist"
# and "attributelist" keys.
#
sub projf_write
{
	my ($fh, $projents) = @_;
	my $projent;
	my $string;

	foreach $projent (@$projents) {

		if ($projent->{'modified'} eq 'false') {
			$string = $projent->{'line'};
		} else {
			$string = projent_2string($projent) . "\n";
		}
		print $fh "$string";
	}
}

#
# projent_parse(line)
#
# Functions for parsing the project file lines into projent hashes.
#
# Returns a number and a ref, one of:
#
# 	(0, ref to projent hash)
#	(non-zero, ref to list of errors)
#
#	Flag can be:
#		allowspaces: allow spaces between user and group names.
#		allowunits : allow units (K, M, etc), on rctl values.
#
# A projent hash contains the keys:
#
#	"name"		- string name of project
#	"projid"	- numeric id of project
#	"comment"	- comment string
#	"users"		- , seperated user list string
#	"userlist"	- list ref to list of user name strings
#	"groups"	- , seperated group list string
#	"grouplist" 	- list ref to liset of group name strings
#	"attributes"	- ; seperated attribute list string
#	"attributelist" - list ref to list of attribute refs
#		          (see projent_parse_attributes() for attribute ref)
#
sub projent_parse
{

	my ($line, $flags) = @_;
	my $projent = {};
	my ($ret, $ref);
	my @errs;
	my ($projname, $projid, $comment, $users, $groups, $attributes);

	#
	# Split fields of project line.  split() is not used because
	# we must enforce that there are 6 fields.
	#
	($projname, $projid, $comment, $users, $groups, $attributes) =
	    $line =~
	    /^([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)$/;

	# If there is not a complete match, nothing will be defined;
	if (!defined($projname)) {
		push(@errs, [5, gettext(
		    'Incorrect number of fields.  Should have 5 ":"\'s.')]);

		# Get as many fields as we can.
		($projname, $projid, $comment, $users, $groups, $attributes) =
		    split(/:/, $line);
	}

	if (defined($projname)) {
		$projent->{'name'} = $projname;
		($ret, $ref) = projent_parse_name($projname);
		if ($ret != 0) {
			push(@errs, @$ref);
		}
	}
	if (defined($projid)) {
		$projent->{'projid'} = $projid;
		($ret, $ref) = projent_parse_projid($projid);
		if ($ret != 0) {
			push(@errs, @$ref);
		}
	}
	if (defined($comment)) {
		$projent->{'comment'} = $comment;
		($ret, $ref) = projent_parse_comment($comment);
		if ($ret != 0) {
			push(@errs, @$ref);
		}
	}
	if (defined($users)) {
		$projent->{'users'} = $users;
		($ret, $ref) = projent_parse_users($users, $flags);
		if ($ret != 0) {
			push(@errs, @$ref);
		} else {
			$projent->{'userlist'} = $ref;
		}
	}
	if (defined($groups)) {
		$projent->{'groups'} = $groups;
		($ret, $ref) = projent_parse_groups($groups, $flags);
		if ($ret != 0) {
			push(@errs, @$ref);
		} else {
			$projent->{'grouplist'} = $ref;
		}
	}
	if (defined($attributes)) {
		$projent->{'attributes'} = $attributes;
		($ret, $ref) = projent_parse_attributes($attributes, $flags);
		if ($ret != 0) {
			push(@errs, @$ref);
		} else {
			$projent->{'attributelist'} = $ref;
		}
	}

	if (@errs) {
		return (1, \@errs);

	} else {
		return (0, $projent);
	}
}

#
# Project name syntax checking.
#
sub projent_parse_name
{
	my @err;
	my ($projname) = @_;

	if (!($projname =~ /^[[:alpha:]][[:alnum:]_.-]*$/)) {
		push(@err, ([3, gettext(
		    'Invalid project name "%s", contains invalid characters'),
		    $projname]));
		return (1, \@err);
	}
	if (length($projname) > &PROJNAME_MAX) {
		push(@err, ([3, gettext(
		    'Invalid project name "%s", name too long'),
		    $projname]));
		return (1, \@err);
	}
	return (0, $projname);
}

#
# Projid syntax checking.
#
sub projent_parse_projid
{
	my @err;
	my ($projid) = @_;

	# verify projid is a positive number, and less than UID_MAX
	if (!($projid =~ /^\d+$/)) {
		push(@err, [3, gettext('Invalid projid "%s"'),
		    $projid]);
		return (1, \@err);

	} elsif ($projid > POSIX::INT_MAX) {
		push(@err, [3, gettext('Invalid projid "%s": must be <= '.
		    POSIX::INT_MAX),
		    $projid]);
		return (1, \@err);

	} else {
		return (0, $projid);
	}
}

#
# Project comment syntax checking.
#
sub projent_parse_comment
{
	my ($comment) = @_;

	# no restrictions on comments
	return (0, $comment);
}

#
# projent_parse_users(string, flags)
#
# Parses "," seperated list of users, and returns list ref to a list of
# user names.  If flags contains key "allowspaces", then spaces are
# allowed between user names and ","'s.
#
sub projent_parse_users
{
	my ($users, $flags) = @_;
	my @err;
	my $user;
	my $pattern;
	my @userlist;

	if (exists($flags->{'allowspaces'})) {
		$pattern = '\s*,\s*';
	} else {
		$pattern = ',';
	}	
	@userlist = split(/$pattern/, $users);

	# Return empty list if there are no users.
	if (!(@userlist)) {
		return (0, \@userlist);
	}

	# Verify each user name is the correct format for a valid user name.
	foreach $user (@userlist) {

		# Allow for wildcards.
		if ($user eq '*' || $user eq '!*') {
			next;
		}

		# Allow for ! operator, usernames must begin with alpha-num,
		# and contain alpha-num, '_', digits, '.', or '-'.
		if (!($user =~ /^!?[[:alpha:]][[:alnum:]_.-]*$/)) {
			push(@err, [3, gettext('Invalid user name "%s"'),
			    $user]);
			next;
		}
	}
	if (@err) {
		return (1,\ @err);
	} else {
		return (0, \@userlist);
	}
}

#
# projent_parse_groups(string, flags)
#
# Parses "," seperated list of groups, and returns list ref to a list of
# groups names.  If flags contains key "allowspaces", then spaces are
# allowed between group names and ","'s.
#
sub projent_parse_groups
{
	my ($groups, $flags) = @_;
	my @err;
	my $group;
	my $pattern;

	my @grouplist; 

	if (exists($flags->{'allowspaces'})) {
		$pattern = '\s*,\s*';
	} else {
		$pattern = ',';
	}	
	@grouplist = split(/$pattern/, $groups);

	# Return empty list if there are no groups.
	if (!(@grouplist)) {
		return (0, \@grouplist);
	}

	# Verify each group is the correct format for a valid group name.
	foreach $group (@grouplist) {

		# Allow for wildcards.
		if ($group eq '*' || $group eq '!*') {
			next;
		}
			
		# Allow for ! operator, groupnames can contain only alpha
		# characters and digits.
		if (!($group =~ /^!?[[:alnum:]]+$/)) {
			push(@err, [3, gettext('Invalid group name "%s"'),
			    $group]);
			next;
		}
	}

	if (@err) {
		return (1,\ @err);
	} else {
		return (0, \@grouplist);
	}
}

#
# projent_tokenize_attribute_values(values)
#
# Values is the right hand side of a name=values attribute/values pair.
# This function splits the values string into a list of tokens.  Tokens are
# valid string values and the characters ( ) , 
#
sub projent_tokenize_attribute_values
{
	#
	# This seperates the attribute string into higher level tokens
	# for parsing.
	#
	my $prev;
	my $cur;
	my $next;
	my $token;
	my @tokens;
	my @newtokens;
	my @err;

	# Seperate tokens delimited by "(", ")", and ",".
	@tokens = split(/([,()])/, $_[0], -1);

	# Get rid of blanks
	@newtokens = grep($_ ne '', @tokens);

	foreach $token (@newtokens) {
		if (!($token =~ /^[(),]$/ ||
		      $token =~ /^[[:alnum:]_.\/=+-]*$/)) {
			push(@err, [3, gettext(
			    'Invalid Character at or near "%s"'), $token]);
		}
	}
	if (@err) {
		return (1, \@err);
	} else {
		return (0, \@newtokens);
	}
}

#
# projent_parse_attribute_values(values)
#
# Values is the right hand side of a name=values attribute/values pair.
# This function parses the values string into a list of values.  Each value
# can be either a scalar value, or a ref to another list of values.
# A ref to the list of values is returned.
# 
sub projent_parse_attribute_values
{
	#
	# For some reason attribute values can be lists of values and
	# sublists, which are scoped using ()'s.  All values and sublists
	# are delimited by ","'s.  Empty values are lists are permitted.
	
	# This function returns a reference to a list of values, each of
	# which can be a scalar value, or a reference to a sublist.  Sublists
	# can contain both scalar values and references to furthur sublists.
	#
	my ($values) = @_;
	my $tokens;
	my @usedtokens;
	my $token;
	my $prev = '';
	my $parendepth = 0;
	my @valuestack;
	my @err;
	my ($ret, $ref);
	my $line;

	push (@valuestack, []);

	($ret, $ref) = projent_tokenize_attribute_values($values);
	if ($ret != 0) {
		return ($ret, $ref);
	}
	$tokens = $ref;

	foreach $token (@$tokens) {
		
		push(@usedtokens, $token);

		if ($token eq ',') {

			if ($prev eq ',' || $prev eq '(' ||
			    $prev eq '') {
				push(@{$valuestack[$#valuestack]}, '');
			}
			$prev = ',';
			next;
		}
		if ($token eq '(') {

			if (!($prev eq '(' || $prev eq ',' ||
			      $prev eq '')) {

				$line = join('', @usedtokens);
				push(@err, [3, gettext(
				    '"%s" <- "(" unexpected'),
				    $line]);

				return (1, \@err);
			}
				    
			$parendepth++;
			my $arrayref = [];
			push(@{$valuestack[$#valuestack]}, $arrayref);
			push(@valuestack, $arrayref);

			$prev = '(';
			next;
		}
		if ($token eq ')') {

			if ($parendepth <= 0) {

				$line = join('', @usedtokens);
				push(@err, [3, gettext(
				    '"%s" <- ")" unexpected'),
				    $line]);

				return (1, \@err);
			}

			if ($prev eq ',' || $prev eq '(') {
				push(@{$valuestack[$#valuestack]}, '');
			}
			$parendepth--;
			pop @valuestack;

			$prev = ')';
			next;
		}

		if (!($prev eq ',' || $prev eq '(' || $prev eq '')) {
			$line = join('', @usedtokens);
			push(@err, [3, gettext(
			    '"%s" <- "%s" unexpected'),
			    $line, $token]);

			return (1, \@err);
		}
				
		push(@{$valuestack[$#valuestack]}, $token);
		$prev = $token;
		next;
	}

	if ($parendepth != 0) {
		push(@err, [3, gettext(
		    '"%s" <- ")" missing'),
		    $values]);
		return (1, \@err);
	}
	
	if ($prev eq ',' || $prev eq '') {
		push(@{$valuestack[$#valuestack]}, '');
	}

	return (0, $valuestack[0]);
}

#
# projent_parse_attribute("name=values", $flags)
#
# $flags is a hash ref.
# Valid flags keys:
#	'allowunits' - allows numeric values to be scaled on certain attributes
#
# Returns a hash ref with keys:
#
#	"name" 		- name of attribute
#	"values"	- ref to list of values.
#			  Each value can be a scalar value, or a ref to
#			  a sub-list of values.
#
sub projent_parse_attribute
{
	my ($string, $flags) = @_;
	my $attribute = {};
	my ($name, $stock, $values);
	my ($ret, $ref);
	my @err;
	my $scale;
	my $num;
	my $modifier;
	my $unit;
	my $tuple;
	my $rules;
	my $rctlmax;
	my $rctlflags;

	# pattern for matching stock symbols.
	my $stockp = '[[:upper:]]{1,5}(?:.[[:upper:]]{1,5})?,';
	# Match attribute with no value.
	($name, $stock) = $string =~
	    /^(($stockp)?[[:alpha:]][[:alnum:]_.-]*)$/;
	if ($name) {
		$attribute->{'name'} = $name;
		return (0, $attribute);
	}

	# Match attribute with value list.
	($name, $stock, $values) = $string =~
	    /^(($stockp)?[[:alpha:]][[:alnum:]_.-]*)=(.*)$/;
	if ($name) {
		$attribute->{'name'} = $name;

		if (!defined($values)) {
			$values = '';
		}

		($ret, $ref) = projent_parse_attribute_values($values);
		if ($ret != 0) {
			$ref = projf_combine_errors(
			    [3,
			    gettext('Invalid value on attribute "%s"'),
			    $name], $ref);
			push(@err, @$ref);
			return ($ret, \@err)
		}

		# Scale attributes than can be scaled.
		if (exists($flags->{"allowunits"})) {

			if ($name eq 'rcap.max-rss' &&
			    defined($ref->[0]) && !ref($ref->[0])) {
				$scale = 'bytes';
				
				($num, $modifier, $unit) =
				    projent_val2num($ref->[0], $scale);
					
				if (!defined($num)) {

					if (defined($unit)) {
						push(@err, [3, gettext(
						    'rcap.max-rss has invalid '.
						    'unit "%s"'), $unit]);
					} else {
						push(@err, [3, gettext(
						    'rcap.max-rss has invalid '.
						    'value "%s"'), $ref->[0]]);
					}
				} elsif ($num eq "OVERFLOW") {
					push(@err, [3, gettext( 'rcap.max-rss value '.
				            '"%s" exceeds maximum value "%s"'),
					    $ref->[0], $MaxNum]);
				} else {
					$ref->[0] = $num;
				} 
			}
			# Check hashed cache of rctl rules.
			$rules = $RctlRules{$name};
			if (!defined($rules)) {
				#
				# See if this is an resource control name, if so
				# cache rules.
				#
				($rctlmax, $rctlflags) = rctl_get_info($name);
				if (defined($rctlmax)) {
					$rules = proj_getrctlrules(
					    $rctlmax, $rctlflags);
					if (defined($rules)) {
						$RctlRules{$name} = $rules;
					} else {
						$RctlRules{$name} =
						    "NOT AN RCTL";
					}
				}	
			}

			# Scale values if this is an rctl.
			if (defined ($rules) && ref($rules)) {
				$flags->{'type'} = $rules->{'type'};
				foreach $tuple (@$ref) {

					# Skip if tuple this is not a list.
					if (!ref($tuple)) {
						next;
					}
					# Skip if second element is not scalar.
					if (!defined($tuple->[1]) ||
					     ref($tuple->[1])) {
						next;
					}
					($num, $modifier, $unit) =
					    projent_val2num($tuple->[1],
					        $flags->{'type'});
					
					if (!defined($num)) {

						if (defined($unit)) {
							push(@err, [3, gettext(
							    'rctl %s has '.
							    'invalid unit '.
							    '"%s"'),$name,
							    $unit]);
						} else {
							push(@err, [3, gettext(
							    'rctl %s has '.
							    'invalid value '.
						            '"%s"'), $name,
							    $tuple->[1]]);
						}
					} elsif ($num eq "OVERFLOW") {
						push(@err, [3, gettext(
					            'rctl %s value "%s" '.
						    'exceeds maximum value "%s"'),
					             $name, $tuple->[1], $MaxNum]);
					} else {
						$tuple->[1] = $num;
					} 
				}
			}
		}
		$attribute->{'values'} = $ref;
		if (@err) {
			return (1, \@err);
		} else {
			return (0, $attribute);
		}

	} else {
		# Attribute did not match name[=value,value...]
		push(@err, [3, gettext('Invalid attribute "%s"'), $string]);
		return (1, \@err);
	}
}

#
# projent_parse_attributes("; seperated list of name=values pairs");
#
# Returns a list of attribute references, as returned by
# projent_parse_attribute().
#
sub projent_parse_attributes
{
	my ($attributes, $flags) = @_;
	my @attributelist;
	my @attributestrings;
	my $attributestring;
	my $attribute;
	my ($ret, $ref);
	my @errs;

	# Split up attributes by ";"'s.
	@attributestrings = split(/;/, $attributes);

	# If no attributes, return empty list.
	if (!@attributestrings) {
		return (0, \@attributelist);
	}

	foreach $attributestring (@attributestrings) {

		($ret, $ref) = projent_parse_attribute($attributestring,
		    $flags);
		if ($ret != 0) {
			push(@errs, @$ref);
		} else {
			push(@attributelist, $ref);
		}
	}

	if (@errs) {
		return (1, \@errs);
	} else {
		return (0, \@attributelist);
	}

}

#
# projent_values_equal(list A, list B)
#
# Given two references to lists of attribute values (as returned by
# projent_parse_attribute_values()), returns 1 if they are identical
# lists or 0 if they are not.
#
# XXX sub projent_values_equal;
sub projent_values_equal
{
	my ($x, $y) = @_;

	my $itema;
	my $itemb;
	my $index = 0;

	if (ref($x) && ref($y)) {

		if (scalar(@$x) != scalar(@$y)) {
			return (0);
		} else {
			foreach $itema (@$x) {
				
				$itemb = $y->[$index++];
				
				if (!projent_values_equal($itema, $itemb)) {
					return (0);
				}
			}
			return (1);
		}
	} elsif ((!ref($x) && (!ref($y)))) {
		return ($x eq $y);
	} else {
		return (0);
	}
}

#
# Converts a list of values to a , seperated string, enclosing sublists
# in ()'s.
#
sub projent_values2string
{
	my ($values) = @_;
	my $string;
	my $value;
	my @valuelist;

	if (!defined($values)) {
		return ('');
	}
	if (!ref($values)) {
		return ($values);
	}
	foreach $value (@$values) {
	    
                if (ref($value)) {
			push(@valuelist,
                            '(' . projent_values2string($value) . ')');
                } else {
			push(@valuelist, $value);
		}
        }

	$string = join(',', @valuelist)	;
	if (!defined($string)) {
		$string = '';
	}	
        return ($string);
}

#
# Converts a ref to an attribute hash with keys "name", and "values" to
# a string in the form "name=value,value...".
#
sub projent_attribute2string
{
	my ($attribute) = @_;
	my $string;

	$string = $attribute->{'name'};

	if (ref($attribute->{'values'}) && @{$attribute->{'values'}}) {
		$string = $string . '=' .
		    projent_values2string(($attribute->{'values'}));
	}	
	return ($string);				 
}

#
# Converts a ref to a projent hash (as returned by projent_parse()) to
# a project(4) database entry line.
#
sub projent_2string
{
	my ($projent) = @_;
	my @attributestrings;
	my $attribute;

	foreach $attribute (@{$projent->{'attributelist'}}) {
		push(@attributestrings, projent_attribute2string($attribute));
	}
	return (join(':', ($projent->{'name'},
			   $projent->{'projid'},
			   $projent->{'comment'},
			   join(',', @{$projent->{'userlist'}}),
			   join(',', @{$projent->{'grouplist'}}),
			   join(';', @attributestrings))));
}

#
# projf_validate(ref to list of projents hashes, flags)
#
# For each projent hash ref in the list, checks that users, groups, and pools
# exists, and that known attributes are valid.  Attributes matching rctl names
# are verified to have valid values given that rctl's global flags and max
# value.
#
# Valid flag keys:
#
#	"res" 	- allow reserved project ids 0-99
#	"dup"   - allow duplicate project ids
#
sub projf_validate
{
	my ($projents, $flags) = @_;
	my $projent;
	my $ret;
	my $ref;
	my @err;
	my %idhash;
	my %namehash;
	my %seenids;
	my %seennames;
	
	# check for unique project names
	foreach $projent (@$projents) {

		my @lineerr;

		$seennames{$projent->{'name'}}++;
		$seenids{$projent->{'projid'}}++;

		if ($seennames{$projent->{'name'}} > 1) {
			push(@lineerr, [4, gettext(
			    'Duplicate project name "%s"'),
			    $projent->{'name'}]);
		}

		if (!defined($flags->{'dup'})) {
			if ($seenids{$projent->{'projid'}} > 1) {
				push(@lineerr, [4, gettext(
				    'Duplicate projid "%s"'),
				    $projent->{'projid'}]);
			}
		}
		($ret, $ref) = projent_validate($projent, $flags);
		if ($ret != 0) {
			push(@lineerr, @$ref);
		}

		if (@lineerr) {
			
			$ref = projf_combine_errors([5, gettext(
			    'Validation error on line %d'),
			    $projent->{'linenum'}], \@lineerr);
			push(@err, @$ref);
		}
	}
	if (@err) {
		return (1, \@err);
	} else {
		return (0, $projents);
	}
}

#
# projent_validate_unique_id(
#     ref to projent hash, ref to list of projent hashes)
#
# Verifies that projid of the projent hash only exists once in the list of
# projent hashes.
#
sub projent_validate_unique_id
{
	my ($projent, $projf, $idhash) = @_;
	my @err;
	my $ret = 0;
	my $projid = $projent->{'projid'};

	if (scalar(grep($_->{'projid'} eq $projid, @$projf)) > 1) {
		$ret = 1;
		push(@err, [4, gettext('Duplicate projid "%s"'),
		    $projid]);
	}

	return ($ret, \@err);
}

#
# projent_validate_unique_id(
#     ref to projent hash, ref to list of projent hashes)
#
# Verifies that project name of the projent hash only exists once in the list
# of projent hashes.
#
# If the seconds argument is a hash ref, it is treated 
#
sub projent_validate_unique_name
{
	my ($projent, $projf, $namehash) = @_;
	my $ret = 0;
	my @err;
	my $pname = $projent->{'name'};

	if (scalar(grep($_->{'name'} eq $pname, @$projf)) > 1) {
		$ret = 1;
		push(@err,
		     [9, gettext('Duplicate project name "%s"'), $pname]);
	}

	return ($ret, \@err);
}

#
# projent_validate(ref to projents hash, flags)
#
# Checks that users, groups, and pools exists, and that known attributes
# are valid.  Attributes matching rctl names are verified to have valid
# values given that rctl's global flags and max value.
#
# Valid flag keys:
#
#	"allowspaces" 	- user and group list are allowed to contain whitespace
#	"res" 		- allow reserved project ids 0-99
#
sub projent_validate
{
	my ($projent, $flags) = @_;
	my $ret = 0;
	my $ref;
	my @err;

	($ret, $ref) =
	    projent_validate_name($projent->{'name'}, $flags);
	if ($ret != 0) {
		push(@err, @$ref);
	} 
	($ret, $ref) =
	    projent_validate_projid($projent->{'projid'}, $flags);
	if ($ret != 0) {
		push(@err, @$ref);
	} 
	($ret, $ref) =
	    projent_validate_comment($projent->{'comment'}, $flags);
	if ($ret != 0) {
		push(@err, @$ref);
	}
	($ret, $ref) =
	    projent_validate_users($projent->{'userlist'}, $flags);
	if ($ret != 0) {
		push(@err, @$ref);
	}
	($ret, $ref) =
	    projent_validate_groups($projent->{'grouplist'}, $flags);
	if ($ret != 0) {
		push(@err, @$ref);
	}
	($ret, $ref) = projent_validate_attributes(
	    $projent->{'attributelist'}, $flags);
	if ($ret != 0) {	
		push(@err, @$ref);
	}	

	my $string = projent_2string($projent);
	if (length($string) > (&PROJECT_BUFSZ - 2)) {
		push(@err, [3, gettext('projent line too long')]);
	}

	if (@err) {
		return (1, \@err);
	} else {
		return (0, $projent);
	}
}

#
# projent_validate_name(name, flags)
#
# does nothing, as any parse-able project name is valid
#
sub projent_validate_name
{
	my ($name, $flags) = @_;
	my @err;

	return (0, \@err);
	
}

#
# projent_validate_projid(projid, flags)
#
# Validates that projid is within the valid range of numbers.
# Valid flag keys:
#	"res"	- allow reserved projid's 0-99
#
sub projent_validate_projid
{
	my ($projid, $flags) = @_;	
	my @err;
	my $ret = 0;
	my $minprojid;

	if (defined($flags->{'res'})) {
		$minprojid = 0;
	} else {
		$minprojid = 100;
	}

	if ($projid < $minprojid) {

		$ret = 1;
		push(@err, [3, gettext('Invalid projid "%s": '.
		    'must be >= 100'),
		    $projid]);

	}

	return ($ret, \@err);
}

#
# projent_validate_comment(name, flags)
#
# Does nothing, as any parse-able comment is valid.
#
sub projent_validate_comment
{
	my ($comment, $flags) = @_;
	my @err;

	return (0, \@err);
}

#
# projent_validate_users(ref to list of user names, flags)
#
# Verifies that each username is either a valid glob, such
# as * or !*, or is an existing user.  flags is unused.
# Also validates that there are no duplicates.
#
sub projent_validate_users
{
	my ($users, $flags) = @_;
	my @err;
	my $ret = 0;
	my $user;
	my $username;

	foreach $user (@$users) {

		if ($user eq '*' || $user eq '!*') {
			next;
		}
		$username = $user;
		$username =~ s/^!//;

		if (!defined(getpwnam($username))) {
			$ret = 1;
			push(@err, [6,
			    gettext('User "%s" does not exist'),
			    $username]);
		}
	}

	my %seen;
        my @dups = grep($seen{$_}++ == 1, @$users);
	if (@dups) {
		$ret = 1;
		push(@err, [3, gettext('Duplicate user names "%s"'),
		    join(',', @dups)]);
	}
	return ($ret, \@err)
}

#
# projent_validate_groups(ref to list of group names, flags)
#
# Verifies that each groupname is either a valid glob, such
# as * or !*, or is an existing group.  flags is unused.
# Also validates that there are no duplicates.
#
sub projent_validate_groups
{
	my ($groups, $flags) = @_;
	my @err;
	my $ret = 0;
	my $group;
	my $groupname;

	foreach $group (@$groups) {

		if ($group eq '*' || $group eq '!*') {
			next;
		}

		$groupname = $group;
		$groupname =~ s/^!//;

		if (!defined(getgrnam($groupname))) {
			$ret = 1;
			push(@err, [6,
			    gettext('Group "%s" does not exist'),
			    $groupname]);
		}
	}

	my %seen;
        my @dups = grep($seen{$_}++ == 1, @$groups);
	if (@dups) {
		$ret = 1;
		push(@err, [3, gettext('Duplicate group names "%s"'),
		    join(',', @dups)]);
	}

	return ($ret, \@err)
}

#
# projent_validate_attribute(attribute hash ref, flags)
#
# Verifies that if the attribute's name is a known attribute or
# resource control, that it contains a valid value.
# flags is unused.
#
sub projent_validate_attribute
{
	my ($attribute, $flags) = @_;
	my $name = $attribute->{'name'};
	my $values = $attribute->{'values'};
	my $value;
	my @errs;
	my $ret = 0;
	my $result;
	my $ref;

	if (defined($values)) {
		$value = $values->[0];
	}
	if ($name eq 'task.final') {

		if (defined($values)) {
			$ret = 1;
			push(@errs, [3, gettext(
			    'task.final should not have value')]);
		}

	# Need to rcap.max-rss needs to be a number
        } elsif ($name eq 'rcap.max-rss') {

		if (!defined($values)) {
			$ret = 1;
			push(@errs, [3, gettext(
			    'rcap.max-rss missing value')]);
		} elsif (scalar(@$values) != 1) {
			$ret = 1;
			push(@errs, [3, gettext(
			    'rcap.max-rss should have single value')]);
		}
		if (!defined($value) || ref($value)) {
			$ret = 1;
			push(@errs, [3, gettext(
			    'rcap.max-rss has invalid value "%s"'),
			    projent_values2string($values)]);;
		} elsif ($value !~ /^\d+$/) {
			$ret = 1;
			push(@errs, [3, gettext(
			    'rcap.max-rss is not an integer value: "%s"'),
			    projent_values2string($values)]);;
                } elsif ($value > $MaxNum) { 
			$ret = 1; 
			push(@errs, [3, gettext( 
			    'rcap.max-rss too large')]); 
                } 
			
	} elsif ($name eq 'project.pool') {
		if (!defined($values)) {
			$ret = 1;
			push(@errs, [3, gettext(
			    'project.pool missing value')]);
		} elsif (scalar(@$values) != 1) {
			$ret = 1;
			push(@errs, [3, gettext(
			    'project.pool should have single value')]);
		} elsif (!defined($value) || ref($value)) {
			$ret = 1;
			push(@errs, [3, gettext(
			    'project.pool has invalid value "%s'),
			    projent_values2string($values)]);;
		} elsif (!($value =~ /^[[:alpha:]][[:alnum:]_.-]*$/)) {
			$ret = 1;
			push(@errs, [3, gettext(
			    'project.pool: invalid pool name "%s"'),
			    $value]);
		# Pool must exist.
		} elsif (pool_exists($value) != 0) {
			$ret = 1;
			push(@errs, [6, gettext(
			    'project.pool: pools not enabled or pool does '.
			    'not exist: "%s"'),
			    $value]);
		}
	} else {
		my $rctlmax;
		my $rctlflags;
		my $rules;

		#
		# See if rctl rules exist for this attribute.  If so, it
		# is an rctl and is checked for valid values.
		#

		# check hashed cache of rctl rules.
		$rules = $RctlRules{$name};
		if (!defined($rules)) {

			#
			# See if this is an resource control name, if so
			# cache rules.
			#
			($rctlmax, $rctlflags) = rctl_get_info($name);
			if (defined($rctlmax)) {
				$rules = proj_getrctlrules(
				    $rctlmax, $rctlflags);
				if (defined($rules)) {
					$RctlRules{$name} = $rules;
				} else {
					$RctlRules{$name} = "NOT AN RCTL";
				}
			}	
		}

		# If rules are defined, this is a resource control.
		if (defined($rules) && ref($rules)) {

			($result, $ref) =
			    projent_validate_rctl($attribute, $flags);
			if ($result != 0) {
				$ret = 1;
				push(@errs, @$ref);
			}
		}
	}
	return ($ret, \@errs);
}

#
# projent_validate_attributes(ref to attribute list, flags)
#
# Validates all attributes in list of attribute references using
# projent_validate_attribute.  flags is unused.
# flags is unused.
#
sub projent_validate_attributes
{
	my ($attributes, $flags) = @_;
	my @err;
	my $ret = 0;
	my $result = 0;
	my $ref;
	my $attribute;

	foreach $attribute (@$attributes) {

		($ret, $ref) = projent_validate_attribute($attribute, $flags);
		if ($ret != 0) {
			$result = $ret;
			push(@err, @$ref);
		}
	}

	my %seen;
        my @dups = grep($seen{$_}++ == 1, map { $_->{'name'} } @$attributes);
	if (@dups) {
		$result = 1;
		push(@err, [3, gettext('Duplicate attributes "%s"'),
		    join(',', @dups)]);
	}

	return ($result, \@err);
}

#
# projent_getrctlrules(max value, global flags)
#
# given an rctls max value and global flags, returns a ref to a hash
# of rctl rules that is used by projent_validate_rctl to validate an
# rctl's values.
# 
sub proj_getrctlrules
{
	my ($max, $flags) = @_;
	my $signals;
	my $rctl;

	$rctl = {};
	$signals = 
	    [ qw(ABRT XRES HUP STOP TERM KILL),
	      $SigNo{'ABRT'},
	      $SigNo{'XRES'},
	      $SigNo{'HUP'},
	      $SigNo{'STOP'},
	      $SigNo{'TERM'},
	      $SigNo{'KILL'} ];
	
	$rctl->{'max'} = $max;

	if ($flags & &RCTL_GLOBAL_BYTES) {
		$rctl->{'type'} = 'bytes';
	} elsif ($flags & &RCTL_GLOBAL_SECONDS) {
		$rctl->{'type'} = 'seconds';
	} elsif ($flags & &RCTL_GLOBAL_COUNT)  {
		$rctl->{'type'} = 'count';
	} else {
		$rctl->{'type'} = 'unknown';
	}
	if ($flags & &RCTL_GLOBAL_NOBASIC) {
		$rctl->{'privs'} = ['privileged', 'priv'];
	} else {
		$rctl->{'privs'} = ['basic', 'privileged', 'priv'];
	}

	if ($flags & &RCTL_GLOBAL_DENY_ALWAYS) {
		$rctl->{'actions'} = ['deny'];

	} elsif ($flags & &RCTL_GLOBAL_DENY_NEVER) {
		$rctl->{'actions'} = ['none'];
	} else {
		$rctl->{'actions'} = ['none', 'deny'];
	}

	if ($flags & &RCTL_GLOBAL_SIGNAL_NEVER) {
		$rctl->{'signals'} = [];

	} else {
		
		push(@{$rctl->{'actions'}}, 'sig');

		if ($flags & &RCTL_GLOBAL_CPU_TIME) {
			push(@$signals, 'XCPU', '30');
		}
		if ($flags & &RCTL_GLOBAL_FILE_SIZE) {
			push(@$signals, 'XFSZ', '31');
		}
		$rctl->{'signals'} = $signals;
	}
	return ($rctl);
}

#
# projent_val2num(scaled value, "seconds" | "count" | "bytes")
#
# converts an integer or scaled value to an integer value.
# returns (integer value, modifier character, unit character.
#
# On failure, integer value is undefined.  If the original
# scaled value is a plain integer, modifier character and
# unit character will be undefined.
#
sub projent_val2num
{
	my ($val, $type) = @_;
	my %scaleM = ( k => 1000,
		       m => 1000000,
		       g => 1000000000,
		       t => 1000000000000,
		       p => 1000000000000000,
		       e => 1000000000000000000);
	my %scaleB = ( k => 1024,
		       m => 1048576,
		       g => 1073741824,
		       t => 1099511627776,
		       p => 1125899906842624,
		       e => 1152921504606846976);

	my $scale;
	my $base;
	my ($num, $modifier, $unit);
	my $mul;
	my $string;
	my $i;
	my $undefined;
	my $exp_unit;

	($num, $modifier, $unit) = $val =~
	    /^(\d+(?:\.\d+)?)(?i:([kmgtpe])?([bs])?)$/;

	# No numeric match.
	if (!defined($num)) {
		return ($undefined, $undefined, $undefined);
	}

	# Decimal number with no scaling modifier.
	if (!defined($modifier) && $num =~ /^\d+\.\d+/) {
		return ($undefined, $undefined, $undefined);
	}	

	if ($type eq 'bytes') {
		$exp_unit = 'b';
		$scale = \%scaleB;
	} elsif ($type eq 'seconds') {
		$exp_unit = 's';
		$scale = \%scaleM;
	} else {
		$scale = \%scaleM;
	}

	if (defined($unit)) {
		$unit = lc($unit);
	}

	# So not succeed if unit is incorrect.
	if (!defined($exp_unit) && defined($unit)) {
		return ($undefined, $modifier, $unit);
	}
	if (defined($unit) && $unit ne $exp_unit) {
		return ($undefined, $modifier, $unit);
	}

	if (defined($modifier)) {

		$modifier = lc($modifier);
		$mul = $scale->{$modifier};
		$num = $num * $mul;
	}

	# check for integer overflow.
	if ($num > $MaxNum) {
		return ("OVERFLOW", $modifier, $unit);
	}
	#
	# Trim numbers that are decimal equivalent to the maximum value
	# to the maximum integer value.
	#
	if ($num == $MaxNum) {
		$num = $MaxNum;;

	} elsif ($num < $MaxNum) {
		# convert any decimal numbers to an integer
		$num = int($num);
	}

	return ($num, $modifier, $unit);
}
#
# projent_validate_rctl(ref to rctl attribute hash, flags)
#
# verifies that the given rctl hash with keys "name" and
# "values" contains valid values for the given name.
# flags is unused.
#
sub projent_validate_rctl
{
	my ($rctl, $flags) = @_;
	my $allrules;
	my $rules;
	my $name;
	my $values;
	my $value;
	my $valuestring;
	my $ret = 0;
	my @err;
	my $priv;
	my $val;
	my @actions;
	my $action;
	my $signal;
	my $sigstring;	# Full signal string on right hand of signal=SIGXXX.
	my $signame;	# Signal number or XXX part of SIGXXX.
	my $siglist;
	my $nonecount;
	my $denycount;
	my $sigcount;

	$name = $rctl->{'name'};
	$values = $rctl->{'values'};

	#
	# Get the default rules for all rctls, and the specific rules for
	# this rctl.
	#
	$allrules = $RctlRules{'__DEFAULT__'};
	$rules = $RctlRules{$name};

	if (!defined($rules) || !ref($rules)) {
		$rules = $allrules;
	}

	# Allow for no rctl values on rctl.
	if (!defined($values)) {
		return (0, \@err);
	}

	# If values exist, make sure it is a list.
	if (!ref($values)) {

		push(@err, [3, gettext(
		    'rctl "%s" missing value'), $name]);
		return (1, \@err);
	}

	foreach $value (@$values) {

		# Each value should be a list.

		if (!ref($value)) {
			$ret = 1;
			push(@err, [3, gettext(
			    'rctl "%s" value "%s" should be in ()\'s'),
				     $name, $value]);
			
			next;
		}

		($priv, $val, @actions) = @$value;
		if (!@actions) {
			$ret = 1;
			$valuestring = projent_values2string([$value]);
			push(@err, [3, gettext(
			    'rctl "%s" value missing action "%s"'),
			    $name, $valuestring]);
		}

		if (!defined($priv)) {
			$ret = 1;
			push(@err, [3, gettext(
			    'rctl "%s" value missing privilege "%s"'),
			    $name, $valuestring]);

		} elsif (ref($priv)) {
			$ret = 1;
			$valuestring = projent_values2string([$priv]);
			push(@err, [3, gettext(
			    'rctl "%s" invalid privilege "%s"'),
				     $name, $valuestring]);

		} else {
			if (!(grep /^$priv$/, @{$allrules->{'privs'}})) {
				
				$ret = 1;
				push(@err, [3, gettext(
			            'rctl "%s" unknown privilege "%s"'),
				    $name, $priv]);

			} elsif (!(grep /^$priv$/, @{$rules->{'privs'}})) {

				$ret = 1;
				push(@err, [3, gettext(
				    'rctl "%s" privilege not allowed '.
				    '"%s"'), $name, $priv]);
			}
		}
		if (!defined($val)) {
			$ret = 1;
			push(@err, [3, gettext(
			    'rctl "%s" missing value'), $name]);

		} elsif (ref($val)) {
			$ret = 1;
			$valuestring = projent_values2string([$val]);
			push(@err, [3, gettext(
			    'rctl "%s" invalid value "%s"'),
				     $name, $valuestring]);
		
		} else {
			if ($val !~ /^\d+$/) {
				$ret = 1;
				push(@err, [3, gettext(
				    'rctl "%s" value "%s" is not '.
				    'an integer'), $name, $val]);

			} elsif ($val > $rules->{'max'}) {
				$ret = 1;
				push(@err, [3, gettext(
				    'rctl "%s" value "%s" exceeds '.
				    'system limit'), $name, $val]);
			}
		}
		$nonecount = 0;
		$denycount = 0;
		$sigcount = 0;

		foreach $action (@actions) {

			if (ref($action)) {
				$ret = 1;
				$valuestring =
				    projent_values2string([$action]);
				push(@err, [3, gettext(
				    'rctl "%s" invalid action "%s"'),
				     $name, $valuestring]);

				next;
			}

			if ($action =~ /^sig(nal)?(=.*)?$/) {
				$signal = $action;
				$action = 'sig';
			}
			if (!(grep /^$action$/, @{$allrules->{'actions'}})) {
			
				$ret = 1;
				push(@err, [3, gettext(
				    'rctl "%s" unknown action "%s"'),
				    $name, $action]);
				next;

			} elsif (!(grep /^$action$/, @{$rules->{'actions'}})) {

				$ret = 1;
				push(@err, [3, gettext(
				    'rctl "%s" action not allowed "%s"'),
				    $name, $action]);
				next;
			}
		
			if ($action eq 'none') {
				if ($nonecount >= 1) {

					$ret = 1;
					push(@err, [3, gettext(
				    	    'rctl "%s" duplicate action '.
					    'none'), $name]);
				}
				$nonecount++;
				next;
			}
			if ($action eq 'deny') {
				if ($denycount >= 1) {

					$ret = 1;
					push(@err, [3, gettext(
				    	    'rctl "%s" duplicate action '.
					    'deny'), $name]);
				}
				$denycount++;
				next;
			}

			# action must be signal
			if ($sigcount >= 1) {

				$ret = 1;
				push(@err, [3, gettext(
			    	    'rctl "%s" duplicate action sig'),
			    	    $name]);
			}	
			$sigcount++;

			#
			# Make sure signal is correct format, one of:
			# sig=##
			# signal=##
			# sig=SIGXXX
			# signal=SIGXXX
			# sig=XXX
			# signal=SIGXXX
			#
			($sigstring) = $signal =~
			    /^
				 (?:signal|sig)=
				     (\d+|
				     (?:SIG)?[[:upper:]]+(?:[+-][123])?
				 )
			     $/x;

			if (!defined($sigstring)) {
				$ret = 1;
				push(@err, [3, gettext(
				    'rctl "%s" invalid signal "%s"'),
				    $name, $signal]);
				next;
			}

			$signame = $sigstring;
			$signame =~ s/SIG//;
			
			# Make sure specific signal is allowed.
			$siglist = $allrules->{'signals'};
			if (!(grep /^$signame$/, @$siglist)) {
				$ret = 1;
				push(@err, [3, gettext(
				    'rctl "%s" invalid signal "%s"'),
				    $name, $signal]);
				next;
			}
			$siglist = $rules->{'signals'};

			if (!(grep /^$signame$/, @$siglist)) {
				$ret = 1;
				push(@err, [3, gettext(
				    'rctl "%s" signal not allowed "%s"'),
				    $name, $signal]);
				next;
			}
		}

		if ($nonecount && ($denycount || $sigcount)) {
			$ret = 1;
			push(@err, [3, gettext(
			    'rctl "%s" action "none" specified with '.
			    'other actions'), $name]);
		}
	}

	if (@err) {
		return ($ret, \@err);
	} else {
	    return ($ret, \@err);
	}
}

1;
