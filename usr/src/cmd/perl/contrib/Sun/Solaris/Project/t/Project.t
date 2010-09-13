#
# Copyright (c) 2000, 2005 Oracle and/or its affiliates. All rights reserved.
#

#
# test script for Sun::Solaris::Project
#

use warnings;
use strict;
use Data::Dumper;
$Data::Dumper::Terse = 1;
$Data::Dumper::Indent = 0;

sub cleanup {
	unlink("/tmp/project.$$.1");
	unlink("/tmp/project.$$.2");
	unlink("/tmp/project.$$.3");
	unlink("/tmp/project.$$.4");
	unlink("/tmp/project.$$.5");
	unlink("/tmp/project.$$.1.w");
	unlink("/tmp/project.$$.2.w");
	unlink("/tmp/project.$$.3.w");
	unlink("/tmp/project.$$.4.w");
	unlink("/tmp/project.$$.5.w");
	unlink("/tmp/projent.$$");
}

# 'use Sun::Solaris::Project;' counts as test 1
our $test = 1;
our $intest = 1;
our $loaded = 0;

#
# Status reporting utils
#
# Expected calling sequence is:
#	start()
#	pass() or fail()
#	start()
#	pass() or fail()
#	...
#	...
#
#	Calling start() twice in a row will fail test.
#	Calling start() and then exiting will fail test.
#
sub start
{
	if ($intest != 0) {
		fatal("Started new test before finishing previous.");
	}
	$test++;
	$intest = 1;
	print "# Starting Test $test: @_\n" if (@_);
}

sub pass
{
	if ($intest == 0) {
		fatal("pass() without start()");
	}
	print("ok $test @_\n");
	$intest = 0;
}

sub fail
{
	if ($intest == 0) {
		fatal("fail() without start()");
	}
	print("not ok $test @_\n");
	$intest = 0;
}

sub fatal
{
	print(STDERR "FATAL!\n");
	print("not ok $test @_\n");
	exit(1);
}

sub comment
{
	print("# @_\n");
}

#
# Read in a project file and build into the same data structure that we will
# get if we do the same with the getXXX functions
#

sub read_pfile
{
	my ($fh) = @_;
	my ($line, @a1, @a2);
	while (defined($line = <$fh>)) {
		chomp($line);
		@a2 = split(/:/, $line, 6);
		$a2[2] = '' if (! defined($a2[2]));
		$a2[3] = defined($a2[3]) ? [ split(/,/, $a2[3]) ] : [];
		$a2[4] = defined($a2[4]) ? [ split(/,/, $a2[4]) ] : [];
		$a2[5] = '' if (! defined($a2[5]));
		push(@a1, [ @a2 ]);
	}
	return(\@a1);
}

#
# Compare two arrays of project structures & check for equivalence.
# Converts each into a string using Data::Dumper and then does a string
# comparison.  Dirty but effective :-)
#

sub cmp_recs
{
	my ($a1, $a2) = @_;
	my $s1 = Dumper($a1);
	my $s2 = Dumper($a2);

	# Make sure numbers and quoted numbers compare the same
	$s1 =~ s/'([+-]?[\d.]+)'/$1/g;
	$s2 =~ s/'([+-]?[\d.]+)'/$1/g;

	return($s1 eq $s2);
}

sub hash2string
{
	my ($key, $value);
	my @strings;
	my $string;
	my $hash = $_[0];
	foreach $key (keys(%$hash)) {
		push(@strings, "$key => $hash->{$key}");
	}
	$string = "{ " . join(", ", @strings) . " }";
	return ($string);
}

#
# Main body of tests starts here.
#

# Check the module loads.
BEGIN {
	$| = 1;
	print "1..548\n";
}

END {
	fail("not ok 1") unless ($loaded);
	fail("Exited during test!") if ($intest == 1);
	cleanup();
}

use Sun::Solaris::Project qw(:ALL :PRIVATE);
$loaded = 1;
pass();

start("Check the constants.");
my ($fh, $line, $n1, $n2, $n3, $s);
open($fh, "</usr/include/project.h") || fatal($!);
while (defined($line = <$fh>)) {
	$n1 = $1 if ($line =~ /#define\s+PROJNAME_MAX\s+(\d+)/);
	$n2 = $1 if ($line =~ /#define\s+PROJECT_BUFSZ\s+(\d+)/);
	$s = $1 if ($line =~ /#define\s+PROJF_PATH\s+"([^"]+)"/);
}
close($fh);
open($fh, "</usr/include/sys/param.h") || fatal($!);
while (defined($line = <$fh>)) {
	$n3 = $1 if ($line =~ /#define\s+MAXUID\s+(\d+)/);
}
close($fh);
if (! defined($s) || ! defined($n1) || ! defined($n2)) {
	fail();
} else {
	if ($n1 == &PROJNAME_MAX && $n2 == &PROJECT_BUFSZ &&
	    $n3 == &MAXPROJID && $s eq &PROJF_PATH) {
		pass();
	} else {
		fail();
	}
}

#
# projf_read on various files with various flags.
#
# This table represents when projf_read should fail given a file
# and flags.
#
# file/flags  # {}	validate	validate,res	validate,dup	
# ###################################################################
# parse error #	no	no		no		no
# dup names   #	yes	no		no		no	
# dup ids     #	yes	no		no		yes
# system ids  #	yes	no		yes		no
# all user    #	yes	yes		yes		yes
#

my $flags1 = {};
my $flags2 = { "validate" => "true" };
my $flags3 = { "validate" => "true", "res" => 1 };
my $flags4 = { "validate" => "true", "dup" => 1 };

# Make a temporary project files.
my ($ret, $file1, $file2, $file3, $file4, $file5, $pass);

# file1, parse error (extra ":") on group.staff project.
open($file1, "+>/tmp/project.$$.1") || fatal($!);
print $file1 <<EOF;
test1:123:project one:root,bin:adm:attr1=a;attr2=b
user.test2:456:project two:adm,uucp:staff:attr1=p;attr2=q
group.test3:678:project three::root,nobody:root,lp:attr1=y;attr2=z
test4:678:project four:root:root:
test5:679:project five::sys:
test6:690::::
EOF

# file2, duplicate project names.
open($file2, "+>/tmp/project.$$.2") || fatal($!);
print $file2 <<EOF;
test1:123:project one:root,bin:adm:attr1=a;attr2=b
user.test2:456:project two:adm,uucp:staff:attr1=p;attr2=q
group.test3:677:project three:root,nobody:root,lp:attr1=y;attr2=z
test1:678:project four:root:root:
test5:679:project five::sys:
test6:690::::
EOF

# file3, duplicate project ids.
open($file3, "+>/tmp/project.$$.3") || fatal($!);
print $file3 <<EOF;
test1:123:project one:root,bin:adm:attr1=a;attr2=b
user.test2:456:project two:adm,uucp:staff:attr1=p;attr2=q
group.test3:677:project three:root,nobody:root,lp:attr1=y;attr2=z
test4:678:project four:root:root:
test5:678:project five::sys:
test6:690::::
EOF

# file4, system project ids.
open($file4, "+>/tmp/project.$$.4") || fatal($!);
print $file4 <<EOF;
system:0::::
user.root:1::::
noproject:2::::
default:3::::
group.staff:10::::
test1:123:project one:root,bin:adm:attr1=a;attr2=b
user.test2:456:project two:adm,uucp:staff:attr1=p;attr2=q
group.test3:677:project three:root,nobody:root,lp:attr1=y;attr2=z
test4:678:project four:root:root:
test5:679:project five::sys:
test6:690::::
EOF

# file5, all unique user projects.
open($file5, "+>/tmp/project.$$.5") || fatal($!);
print $file5 <<EOF;
test1:123:project one:root,bin:adm:attr1=a;attr2=b
user.test2:456:project two:adm,uucp:staff:attr1=p;attr2=q
group.test3:677:project three:root,nobody:root,lp:attr1=y;attr2=z
test4:678:project four:root:root:
test5:679:project five::sys:
test6:690::::
EOF

#
# Each test is the file description, input file, filename, flags, and the expected
# return value.
#
my @read_tests = (
	[ "parse error", $file1, "/tmp/project.$$.1", $flags1, 1 ],
	[ "parse error", $file1, "/tmp/project.$$.1", $flags2, 1 ],
	[ "parse error", $file1, "/tmp/project.$$.1", $flags3, 1 ],
	[ "parse error", $file1, "/tmp/project.$$.1", $flags4, 1 ],
	[ "dup names", $file2, "/tmp/project.$$.2", $flags1, 0 ],
	[ "dup names", $file2, "/tmp/project.$$.2", $flags2, 1 ],
	[ "dup names", $file2, "/tmp/project.$$.2", $flags3, 1 ],
	[ "dup names", $file2, "/tmp/project.$$.2", $flags4, 1 ],
	[ "dup ids", $file3, "/tmp/project.$$.3", $flags1, 0 ],
	[ "dup ids", $file3, "/tmp/project.$$.3", $flags2, 1 ],
	[ "dup ids", $file3, "/tmp/project.$$.3", $flags3, 1 ],
	[ "dup ids", $file3, "/tmp/project.$$.3", $flags4, 0 ],
	[ "sys ids", $file4, "/tmp/project.$$.4", $flags1, 0 ],
	[ "sys ids", $file4, "/tmp/project.$$.4", $flags2, 1 ],
	[ "sys ids", $file4, "/tmp/project.$$.4", $flags3, 0 ],
	[ "sys ids", $file4, "/tmp/project.$$.4", $flags4, 1 ],
	[ "unique users", $file5, "/tmp/project.$$.5", $flags1, 0 ],
	[ "unique users", $file5, "/tmp/project.$$.5", $flags2, 0 ],
	[ "unique users", $file5, "/tmp/project.$$.5", $flags3, 0 ],
	[ "unique users", $file5, "/tmp/project.$$.5", $flags4, 0 ]
);

my $projents;
my @goodprojents;
my $read_test;
my $desc;
my $file;
my $filename;
my $flags;
my $flagstring;
my $exp;
my $error;

# Do projf_read tests.
foreach $read_test (@read_tests) {

	($desc, $file, $filename, $flags, $exp) = @$read_test;
	$flagstring = hash2string($flags);
	start("projf_read(): $desc, flags: $flagstring, file: $filename");

	seek($file, 0, 0);

	($ret, $projents) = projf_read($file, $flags);
	# check return is expected result
	if ($ret != $exp) {
		fail("Expected $exp, Returned $ret");
		if ($ret) {
			foreach $error (@$projents) {
				comment("# " . join(", ", @$error));;
			}
		}
		next;
	}
	# verify either projents or error messages were returned
	if (!(@$projents)) {
		fail("Missing projents or error messages");
		next;
	}
	pass();

	# Save projents from successful reads for testing projf_write.
	if ($ret == 0) {
		push(@goodprojents, [$desc, $flags, $projents, $filename]);
	}
}

close($file1);
close($file2);
close($file3);
close($file4);
close($file5);

# Test projf_write, write each successfully read file.

my @write_tests;
my $write_test;

foreach $write_test (@goodprojents) {

	($desc, $flags, $projents, $filename) = @$write_test;
	$flagstring = hash2string($flags);
	start("projf_write(): $desc, flags: $flagstring, file: $filename");

	open($fh, ">$filename.w") || fatal($!);

	projf_write($fh, $projents);
	close($fh);
	system("cmp -s $filename $filename.w") == 0 ? pass() :
	    fail("Written file $filename.w does not match file $filename");
}

# Tests for projent_parse and projent_validate.

my @projent_tests;
my $projent_test;

#
# Tests, in format:
#
#  [ parse_result_expected, validate_result_expected, flags, project-line ]
#
@projent_tests = (
 
# positive

	[ 0, 0, { "res" => 1 }, "system:0::::" ],
	[ 0, 0, { "res" => 1 }, "user.root:1::::" ],
	[ 0, 0, { "res" => 1 }, "noproject:2::::" ],
	[ 0, 0, { "res" => 1 }, "default:3::::" ],
	[ 0, 0, { "res" => 1 }, "group.staff:10::::" ],
	[ 0, 0, {}, "long:100::::" . "a" x 2048 ],
	[ 0, 0, {}, "Validname:101::::" ],
	[ 0, 0, {}, "Validname2:102::::" ],
	[ 0, 0, {}, "valid3name:103::::" ],
	[ 0, 0, {}, "VALIDNAME:104::::" ],
	[ 0, 0, {}, "VALIDNAME5:105::::" ],
	[ 0, 0, {}, "vAlid5name:106::::" ],
	[ 0, 0, {}, "valid.name:107::::" ],
	[ 0, 0, {}, "valid8.NAME:108::::" ],
	[ 0, 0, {}, "Valid_name9:109::::" ],
	[ 0, 0, {}, "V_alid.name10:110::::" ],
	[ 0, 0, {}, "valid12345678901234567890123456789012345678901234567890123456789:111::::" ],
	[ 0, 0, {}, "projid:2147483647::::" ],
	[ 0, 0, {}, "comment:111: this is ! & my crazy	!@#$%^&*()_+|~`\=-][ 0, 0, {},}{';\"/.,?>< comment:::" ],
	[ 0, 0, {}, "user1:112::*::" ],
	[ 0, 0, {}, "user2:113::!*::" ],
	[ 0, 0, {}, "user3:114::root::" ],
	[ 0, 0, {}, "user4:115::!root::" ],
	[ 0, 0, {}, "user5:116::*,!sys::" ],
	[ 0, 0, {}, "user6:117::!*,daemon::" ],
	[ 0, 0, {}, "user7:118::root,sys,daemon,bin::" ],
	[ 0, 0, {}, "user8:119::root,!sys,daemon,!bin::" ],
	[ 0, 0, { "allowspaces" => 1 }, "user9:116::*, !sys::" ],
	[ 0, 0, { "allowspaces" => 1 }, "user10:117::!* ,daemon::" ],
	[ 0, 0, { "allowspaces" => 1 }, "user11:118::root ,sys ,daemon, bin::" ],
	[ 0, 0, { "allowspaces" => 1 }, "user12:119::root, !sys, daemon ,!bin::" ],
	[ 0, 0, {}, "group1:120:::*:" ],
	[ 0, 0, {}, "group2:121:::!*:" ],
	[ 0, 0, {}, "group3:122:::root:" ],
	[ 0, 0, {}, "group4:123:::!root:" ],
	[ 0, 0, {}, "group5:124:::*,!sys:" ],
	[ 0, 0, {}, "group6:125:::!*,daemon:" ],
	[ 0, 0, {}, "group7:126:::root,sys,daemon,bin:" ],
	[ 0, 0, {}, "group8:127:::root,!sys,daemon,!bin:" ],
	[ 0, 0, { "allowspaces" => 1 }, "group9:124:::*, !sys:" ],
	[ 0, 0, { "allowspaces" => 1 }, "group10:125:::!* ,daemon:" ],
	[ 0, 0, { "allowspaces" => 1 }, "group11:126:::root, sys ,daemon, bin:" ],
	[ 0, 0, { "allowspaces" => 1 }, "group12:127:::root ,!sys, daemon ,!bin:" ],
	[ 0, 0, {}, "group9:128:::sys:" ],
	[ 0, 0, {}, "attrib1:129::::one" ],
	[ 0, 0, {}, "attrib2:130::::One" ],
	[ 0, 0, {}, "attrib3:131::::ONE" ],
	[ 0, 0, {}, "attrib4:132::::attrib10" ],
	[ 0, 0, {}, "attrib5:133::::attrib.attrib=" ],
	[ 0, 0, {}, "attrib6:134::::attib_" ],
	[ 0, 0, {}, "attrib7:135::::a10-._attib" ],
	[ 0, 0, {}, "attrib8:136::::SUNW,attrib" ],
	[ 0, 0, {}, "attrib9:137::::A,A10=" ],
	[ 0, 0, {}, "attrib10:138::::FIVEE,name" ],
	[ 0, 0, {}, "attrib11:139::::one;two" ],
	[ 0, 0, {}, "attrib12:140::::one=1;two=four" ],
	[ 0, 0, {}, "attrib13:141::::one;two=;three=four" ],
	[ 0, 0, {}, "value1:142::::one=foo,bar" ],
	[ 0, 0, {}, "value2:143::::one=,bar," ],
	[ 0, 0, {}, "value3:144::::one=(foo,bar)" ],
	[ 0, 0, {}, "value4:145::::one=(foo,bar,baz),boo" ],
	[ 0, 0, {}, "value5:146::::one;two=bar,(baz),foo,((baz)),(,)" ],
	[ 0, 0, {}, "value6:147::::one=100/200" ],
	[ 0, 0, {}, "value7:148::::two=.-_/=" ],
	[ 0, 0, {}, "value8:149::::name=one=two" ],
	[ 0, 0, { "allowunits" => 1 }, "value9:150::::task.max-lwps=(priv,1000M,deny,signal=SIGHUP),(priv,1000k,deny,signal=SIGKILL)" ],
	[ 0, 0, {}, "comma1:151::,::" ],
	[ 0, 0, {}, "comma2:152::,,::" ],
	[ 0, 0, {}, "comma3:153::root,::" ],
	[ 0, 0, {}, "comma4:154::bin,root,,::" ],
	[ 0, 0, {}, "comma5:155:::,:" ],
	[ 0, 0, {}, "comma6:156:::,,:" ],
	[ 0, 0, {}, "comma7:157:::bin,root,:" ],
	[ 0, 0, {}, "comma8:158:::root,,:" ],
	[ 0, 0, {}, "semi1:159::::;" ],
	[ 0, 0, {}, "semi2:160::::;;" ],
	[ 0, 0, {}, "semi3:161::::foo=(one,two);" ],
	[ 0, 0, {}, "semi4:162::::foo;;" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl1:163::::task.max-lwps=(priv,1000,deny,signal=HUP),(priv,1000k,deny,signal=15)" ],
	[ 0, 0, {}, "rctl1:163::::task.max-lwps=(priv,1000,deny,signal=HUP),(priv,10001,deny,signal=15)" ],
	[ 0, 0, {}, "rctl2:164::::process.max-port-events=(basic,1000,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl3:165::::project.max-crypto-memory=(priv,2.2gb,deny)" ],
	[ 0, 0, {}, "rctl3:165::::project.max-crypto-memory=(priv,10,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl4:166::::project.max-crypto-memory=(privileged,100m,deny)" ],
	[ 0, 0, {}, "rctl4:166::::project.max-crypto-memory=(privileged,100,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl5:167::::project.max-crypto-memory=(priv,1000m,deny)" ],
	[ 0, 0, {}, "rctl5:167::::project.max-crypto-memory=(priv,1000,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl6:168::::project.max-crypto-memory=(priv,1000k,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl6:168::::project.max-crypto-memory=(priv,1000m,deny)" ],
	[ 0, 0, {}, "rctl7:169::::process.max-msg-messages=(priv,10,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl8:170::::process.max-msg-qbytes=(priv,10000kb,deny)" ],
	[ 0, 0, {}, "rctl8:170::::process.max-msg-qbytes=(priv,10000,deny)" ],
	[ 0, 0, {}, "rctl9:171::::process.max-sem-ops=(priv,10000000,deny)" ],
	[ 0, 0, {}, "rctl10:172::::process.max-sem-nsems=(basic,1,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl11:173::::process.max-address-space=(priv,2GB,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl12:174::::process.max-file-descriptor=(basic,1K,deny),(basic,2K,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl13:175::::process.max-core-size=(priv,10Mb,deny),(priv,2GB,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl14:176::::process.max-stack-size=(priv,1.8Gb,deny),(priv,100MB,deny)" ],
	[ 0, 0, {}, "rctl15:177::::process.max-data-size=(priv,1010100101,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl16:178::::process.max-file-size=(priv,100mb,deny,signal=SIGXFSZ),(priv,1000mb,deny,signal=31)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl17:179::::process.max-cpu-time=(priv,1t,signal=XCPU),(priv,100ms,sig=30)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl18:180::::task.max-cpu-time=(priv,1M,sig=SIGKILL)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl19:181::::task.max-lwps=(basic,10,signal=1),(priv,100,deny,signal=KILL)" ],
	[ 0, 0, {}, "rctl20:182::::project.max-device-locked-memory=(priv,1000,deny,sig=TERM)" ],
	[ 0, 0, {}, "rctl21:183::::project.max-port-ids=(priv,100,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl22:184::::project.max-shm-memory=(priv,1000mb,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl23:185::::project.max-shm-ids=(priv,1k,deny,signal=SIGSTOP)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl24:186::::project.max-msg-ids=(priv,1m,deny,signal=XRES)" ],
	[ 0, 0, {}, "rctl25:187::::project.max-sem-ids=(priv,10,deny,signal=ABRT)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl26:188::::project.cpu-shares=(priv,63k,none)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl27:189::::zone.cpu-shares=(priv,20k,none)" ],
	[ 0, 0, {}, "rctl28:190::::zone.cpu-shares=(priv,100,none)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl29:191::::project.max-shm-memory=(priv,200G,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl30:192::::project.max-shm-memory=(priv,200Gb,deny)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl31:193::::project.max-shm-memory=(priv,2000B,deny)" ],
	[ 0, 0, {}, "rctl32:194::::project.max-shm-memory=(priv,2000,deny)" ],
	[ 0, 0, {}, "rctl33:195::::task.max-cpu-time=(priv,2000,none)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl34:196::::task.max-cpu-time=(priv,2000s,none)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl35:197::::task.max-cpu-time=(priv,20.1ps,none)" ],
	[ 0, 0, { "allowunits" => 1 }, "rctl36:198::::task.max-cpu-time=(priv,20T,none)" ],

# negative

	[ 0, 1, {}, "system:0::::" ],
	[ 0, 1, {}, "user.root:1::::" ],
	[ 0, 1, {}, "noproject:2::::" ],
	[ 0, 1, {}, "default:3::::" ],
	[ 0, 1, {}, "group.staff:10::::" ],
	[ 0, 1, {}, "long:100::::" . "a" x 4096 ],
	[ 1, 0, {}, "extrafields:101:::::" ],
	[ 1, 0, {}, "missingfields:102:::" ],
	[ 1, 0, {}, "_invalidname:103::::" ],
	[ 1, 0, {}, "10invlidname:104::::" ],
	[ 1, 0, {}, "invalid%name:105::::" ],
	[ 1, 0, {}, "invalid/name:106::::" ],
	[ 1, 0, {}, ".invalidname:107::::" ],
	[ 1, 0, {}, "=invalidName:108::::" ],
	[ 1, 0, {}, "invalid=name:109::::" ],
	[ 1, 0, {}, "invalid/name:110::::" ],
	[ 1, 0, {}, "/invalidname:111::::" ],
	[ 1, 0, {}, "/invalidname:112::::" ],
	[ 1, 0, {}, "invalidname*:113::::" ],
	[ 1, 0, {}, "invalid?name:114::::" ],
	[ 1, 0, {}, ":115:invalid name comment:::" ],
	[ 1, 0, {}, "invalid!name:116::::" ],
	[ 1, 0, {}, "invalidname!:117::::" ],
	[ 1, 0, {}, "invalid12345678901234567890123456789012345678901234567890123456789:118::::" ],
	[ 1, 0, {}, "projid:-1::::" ],
	[ 1, 0, {}, "projid:abc::::" ],
	[ 1, 0, {}, "projid:2147483648::::" ],
	[ 1, 0, {}, "projid:::::" ],
	[ 1, 0, {}, "user1:118::*!::" ],
	[ 1, 0, {}, "user2:119::10user::" ],
	[ 0, 1, {}, "user3:120::NOLOWER::" ],
	[ 0, 1, {}, "user4:121::toooolong::" ],
	[ 1, 0, {}, "user5:122::root!::" ],
	[ 1, 0, {}, "user6:123::root;sys::" ],
	[ 0, 1, {}, "user7:124::sys,NOLOWER::" ],
	[ 1, 0, {}, "user8:125::sys/bin,root::" ],
	[ 1, 0, {}, "user9:116::*, !sys::" ],
	[ 1, 0, {}, "user10:117::!* ,daemon::" ],
	[ 1, 0, {}, "user11:118::root ,sys ,daemon, bin::" ],
	[ 1, 0, {}, "user12:119::root, !sys, daemon ,!bin::" ],
	[ 1, 0, {}, "group1:126:::*!:" ],
	[ 0, 1, {}, "group2:127:::oneUpper:" ],
	[ 0, 1, {}, "group3:128:::NOLOWER:" ],
	[ 0, 1, {}, "group4:129:::toooolong:" ],
	[ 1, 0, {}, "group5:130:::root!:" ],
	[ 1, 0, {}, "group6:131:::root;sys:" ],
	[ 0, 1, {}, "group7:132:::sys,NOLOWER:" ],
	[ 1, 0, {}, "group8:133:::sys-bin,root:" ],
	[ 1, 0, {}, "group9:124:::*, !sys:" ],
	[ 1, 0, {}, "group10:125:::!* ,daemon:" ],
	[ 1, 0, {}, "group11:126:::root, sys ,daemon, bin:" ],
	[ 1, 0, {}, "group12:127:::root ,!sys, daemon ,!bin:" ],
	[ 1, 0, {}, "attrib1:134::::10" ],
	[ 1, 0, {}, "attrib2:135::::_foo=" ],
	[ 1, 0, {}, "attrib3:136::::,foo" ],
	[ 1, 0, {}, "attrib4:137::::sun,foo" ],
	[ 1, 0, {}, "attrib6:139::::!attrib" ],
	[ 1, 0, {}, "attrib7:140::::_attrib" ],
	[ 1, 0, {}, "attrib8:141::::attib,attrib" ],
	[ 1, 0, {}, "attrib9:142::::attrib/attrib" ],
	[ 1, 0, {}, "attrib10:143::::one;two,three" ],
	[ 1, 0, {}, "attrib11:144::::one=two;three/" ],
	[ 1, 0, {}, "value1:145::::one=foo%" ],
	[ 1, 0, {}, "value2:146::::one= two" ],
	[ 1, 0, {}, "value3:147::::var=foo?" ],
	[ 1, 0, {}, "value4:148::::name=value;name=value2)" ],
	[ 1, 0, {}, "value5:149::::(foo)" ],
	[ 1, 0, {}, "value6:150::::name=(foo,bar" ],
	[ 1, 0, {}, "value7:151::::name=(value)(value)" ],
	[ 1, 0, {}, "value8:152::::name=)" ],
	[ 1, 0, {}, "value9:153::::name=value,(value value)" ],
	[ 1, 0, {}, "value10:154::::name=(value(value))" ],
	[ 1, 0, {}, "value11:155::::name=(value)value" ],
	[ 1, 0, {}, "value11:156::::name=va?lue" ],
	[ 1, 0, {}, "value12:157::::name=(value,value))" ],
	[ 1, 0, {}, "value13:158::::name=(value),value)" ],
	[ 1, 0, {}, "space1 :159::::" ],
	[ 1, 0, {}, " space2:160::::" ],
	[ 1, 0, {}, "space3: 161::::" ],
	[ 1, 0, {}, "space4:162 ::::" ],
	[ 1, 0, {}, "space 5:163::::" ],
	[ 1, 0, {}, "space6:1 64::::" ],
	[ 1, 0, {}, "space7:165:: root::" ],
	[ 1, 0, {}, "space8:166::root ::" ],
	[ 1, 0, {}, "space9:167::daemon, root::" ],
	[ 1, 0, {}, "space10:168::bin root::" ],
	[ 1, 0, {}, "space11:169::daemon ,root::" ],
	[ 1, 0, {}, "space12 :170::::" ],
	[ 1, 0, {}, " space13:171::::" ],
	[ 1, 0, {}, "space14: 172::::" ],
	[ 1, 0, {}, "space15:173 ::::" ],
	[ 1, 0, {}, "space 16:174::::" ],
	[ 1, 0, {}, "space17:1 75::::" ],
	[ 1, 0, {}, "space18:176::: root:" ],
	[ 1, 0, {}, "space19:177:::root :" ],
	[ 1, 0, {}, "space20:178:::daemon, root:" ],
	[ 1, 0, {}, "space21:179:::bin root:" ],
	[ 1, 0, {}, "space22:180:::daemon ,root:" ],
	[ 1, 0, {}, "space23:181:::: foo" ],
	[ 1, 0, {}, "space34:182::::foo =one" ],
	[ 1, 0, {}, "space35:183::::foo= (one)" ],
	[ 1, 0, {}, "space36:184::::foo=(one, two)" ],
	[ 1, 0, {}, "space37:185::::foo=(one ,two)" ],
	[ 1, 0, {}, "space38:186::::foo=( one)" ],
	[ 1, 0, {}, "space39:187::::foo=(one )" ],
	[ 1, 0, {}, "space40:188::::foo=(one) ,two" ],
	[ 1, 0, {}, "space41:189::::foo=one, (two)" ],
	[ 1, 0, {}, "comma1:190::,root,bin::" ],
	[ 1, 0, {}, "comma2:191::root,,bin::" ],
	[ 1, 0, {}, "comma3:192::,,root,bin::" ],
	[ 1, 0, {}, "comma4:193:::,root,bin:" ],
	[ 1, 0, {}, "comma5:194:::root,,bin:" ],
	[ 1, 0, {}, "comma6:195:::,,root,bin:" ],
	[ 1, 0, {}, "semi1:196::::;foo" ],
	[ 1, 0, {}, "semi2:197::::foo;;bar=1" ],
	[ 1, 0, {}, "semi3:198::::;;bar=(10)" ],
	[ 0, 1, {}, "rctl1:199::::task.max-lwps=," ],
	[ 0, 1, {}, "rctl2:200::::task.max-lwps=" ],
	[ 0, 1, {}, "rctl3:201::::task.max-lwps=priv" ],
	[ 0, 1, {}, "rctl4:202::::task.max-lwps=priv,1000" ],
	[ 0, 1, {}, "rctl5:203::::task.max-lwps=priv,1000,deny" ],
	[ 0, 1, {}, "rctl6:204::::task.max-lwps=(priv)" ],
	[ 0, 1, {}, "rctl7:205::::task.max-lwps=(priv,1000)" ],
	[ 0, 1, {}, "rctl8:206::::task.max-lwps=(foo,100,deny)" ],
	[ 0, 1, {}, "rctl9:207::::task.max-lwps=(priv,foo,none)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl9:207::::task.max-lwps=(priv,foo,none)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl10:208::::task.max-lwps=(priv,100foo,none)" ],
	[ 0, 1, {}, "rctl11:209::::task.max-lwps=(priv,1000,foo)" ],
	[ 0, 1, { "allowunits" => 1 }, "rctl12:210::::task.max-lwps=(priv,1000k,deny,signal)" ],
	[ 0, 1, {}, "rctl13:211::::task.max-lwps=(priv,1000,deny,signal=)" ],
	[ 0, 1, {}, "rctl14:212::::task.max-lwps=(priv,1000,deny,signal=foo)" ],
	[ 0, 1, {}, "rctl15:213::::task.max-lwps=(priv,1000,deny,signal=1fo)" ],
	[ 0, 1, {}, "rctl16:214::::task.max-lwps=(priv,1000,deny,signal=100)" ],
	[ 0, 1, {}, "rctl17:215::::task.max-lwps=(priv,1000,deny,signal=SIG)" ],
	[ 0, 1, {}, "rctl18:216::::task.max-lwps=(priv,1000,deny,signal=SIG1)" ],
	[ 0, 1, {}, "rctl19:217::::task.max-lwps=(priv,1000,deny,signal=SIGhup)" ],
	[ 0, 1, {}, "rctl20:218::::task.max-lwps=(priv,1000,deny,signal=SIGHU)" ],
	[ 0, 1, {}, "rctl21:219::::task.max-lwps=(priv,1000,deny,signal=SIGHUPP)" ],
	[ 0, 1, {}, "rctl22:220::::task.max-lwps=(priv,1000,deny,signal=SIGURG)" ],
	[ 0, 1, {}, "rctl23:221::::task.max-lwps=(priv,1000,deny,signal=SIGXCPU)" ],
	[ 0, 1, {}, "rctl24:222::::task.max-lwps=(priv,1000,deny,signal=SIGKILL,10)" ],
	[ 0, 1, {}, "rctl25:223::::task.max-lwps=(priv,1000,deny,signal=SIGKILL,foo)" ],
	[ 0, 1, {}, "rctl26:224::::process.max-port-events=(priv,1000,none)" ],
	[ 0, 1, { "allowunits" => 1 }, "rctl27:225::::process.max-address-space=(basic,1024mb,deny,signal=TERM)" ],
	[ 0, 1, {}, "rctl28:226::::process.max-cpu-time=(basic,3600,deny)" ],
	[ 0, 1, {}, "rctl29:227::::task.max-lwps=()" ],
	[ 0, 1, {}, "rctl30:228::::task.max-lwps=((priv),deny)" ],
	[ 0, 1, {}, "rctl31:229::::task.max-lwps=((priv,1000,deny))" ],
	[ 0, 1, {}, "rctl32:230::::task.max-lwps=(priv,((1000,2000,1000)),deny)" ],
	[ 0, 1, {}, "rctl33:231::::task.max-lwps=(,,,)" ],
	[ 0, 1, {}, "rctl34:232::::task.max-lwps=(priv,1000,(deny))" ],
	[ 0, 1, {}, "rctl35:233::::task.max-lwps=(priv,1000,deny),foo" ],
	[ 0, 1, {}, "rctl36:234::::task.max-lwps=(priv,1000,deny),(priv,1000)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl37:235::::project.max-msg-ids=(priv,15EB,deny)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl38:236::::process.max-address-space=(priv,16.1EB,deny)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl39:237::::process.max-address-space=(priv,18000000000gb,deny)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl40:238::::zone.cpu-shares=(priv,10kb,none)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl41:239::::zone.cpu-shares=(priv,10Ks,none)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl42:240::::zone.cpu-shares=(priv,10s,none)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl43:241::::zone.cpu-shares=(priv,100000b,none)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl44:242::::project.max-shm-memory=(priv,200Ts,deny)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl45:243::::project.max-shm-memory=(priv,200s,deny)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl46:244::::task.max-cpu-time=(priv,20B,none)" ],
	[ 1, 0, { "allowunits" => 1 }, "rctl47:245::::task.max-cpu-time=(priv,20Kb,none)" ],
	[ 0, 1, { "allowunits" => 1 }, "rctl48:246::::project.cpu-shares=(priv,100k,none)" ],
	[ 0, 1, {}, "rctl147:150::::task.max-lwps=(priv,1000M,deny,signal=SIGHUP),(priv,1000k,deny,signal=SIGKILL)" ],
	[ 0, 1, {}, "rctl148:163::::task.max-lwps=(priv,1000,deny,signal=HUP),(priv,1000k,deny,signal=15)" ],
	[ 0, 1, {}, "rctl3:165::::project.max-crypto-memory=(priv,10eb,deny)" ],
	[ 0, 1, {}, "rctl4:166::::project.max-crypto-memory=(privileged,100p,deny)" ],
	[ 0, 1, {}, "rctl5:167::::project.max-crypto-memory=(priv,1000t,deny)" ],
	[ 0, 1, {}, "rctl6:168::::project.max-crypto-memory=(priv,1000g,deny)" ],
	[ 0, 1, {}, "rctl7:169::::process.max-msg-messages=(priv,10m,deny)" ],
	[ 0, 1, {}, "rctl8:170::::process.max-msg-qbytes=(priv,10000kb,deny)" ],
	[ 0, 1, {}, "rctl11:173::::process.max-address-space=(priv,10EB,deny)" ],
	[ 0, 1, {}, "rctl12:174::::process.max-file-descriptor=(basic,1K,deny),(basic,2K,deny)" ],
	[ 0, 1, {}, "rctl13:175::::process.max-core-size=(priv,1Eb,deny),(priv,10PB,deny)" ],
	[ 0, 1, {}, "rctl14:176::::process.max-stack-size=(priv,10Tb,deny),(priv,10TB,deny)" ],
	[ 0, 1, {}, "rctl16:178::::process.max-file-size=(priv,100mb,deny,signal=SIGXFSZ),(priv,1000mb,deny,signal=31)" ],
	[ 0, 1, {}, "rctl17:179::::process.max-cpu-time=(priv,1t,signal=XCPU),(priv,100ms,sig=30)" ],
	[ 0, 1, {}, "rctl18:180::::task.max-cpu-time=(priv,1M,sig=SIGKILL)" ],
	[ 0, 1, {}, "rctl22:184::::project.max-shm-memory=(priv,1000mb,deny)" ],
	[ 0, 1, {}, "rctl23:185::::project.max-shm-ids=(priv,1k,deny,signal=SIGSTOP)" ],
	[ 0, 1, {}, "rctl24:186::::project.max-msg-ids=(priv,1m,deny,signal=XRES)" ],
	[ 0, 1, {}, "rctl26:188::::project.cpu-shares=(priv,63k,none)" ],
	[ 0, 1, {}, "rctl27:189::::zone.cpu-shares=(priv,20k,none)" ],
	[ 0, 1, {}, "rctl29:191::::project.max-shm-memory=(priv,200G,deny)" ],
	[ 0, 1, {}, "rctl30:192::::project.max-shm-memory=(priv,200Gb,deny)" ],
	[ 0, 1, {}, "rctl31:193::::project.max-shm-memory=(priv,2000B,deny)" ],
	[ 0, 1, {}, "rctl34:196::::task.max-cpu-time=(priv,2000s,none)" ],
	[ 0, 1, {}, "rctl35:197::::task.max-cpu-time=(priv,20.1ps,none)" ],
	[ 0, 1, {}, "rctl36:198::::task.max-cpu-time=(priv,20T,none)" ],
);

my $parse_exp;
my $parse_ret;
my $validate_exp;
my $validate_ret;
my $project;
my $projent;
my $errors;

foreach $projent_test ( @projent_tests) {

	($parse_exp, $validate_exp, $flags, $project) = @$projent_test;
	$flagstring = hash2string($flags);	
	start("projent_parse(): flags: $flagstring, project: $project"); 
	($ret, $projent) = projent_parse($project, $flags);
	if ($ret != $parse_exp) {
		fail("Expected $parse_exp, Returned $ret");
		if ($ret) {
			foreach $error (@$projent) {
				comment("# " . join(", ", @$error));
			}	
		}
		next;
	}
	pass();

	# projent_validate() can only be successfully parsed projents
	if ($ret) {
		next;
	}

	start("projent_validate():  flags: $flagstring, project: $project");
	($ret, $errors) = projent_validate($projent, $flags);
	if ($ret != $validate_exp) {
		fail("Expected $validate_exp, Returned $ret");
		if ($ret) {
			foreach $error (@$errors) {
				comment("# " . join(", ", @$error));
			}	
		}
		next;
	}
	pass();
}

my $pf1;
my $pf2;
my $fh1;
my $fh2;
my @lines;

# get projects and make local copy
open($fh1, "/usr/bin/getent project |") || fatal($!);
open($fh2, ">/tmp/projent.$$") || fatal($!);
@lines = <$fh1>;
print $fh2 @lines;
close($fh1);
close($fh2);

open($fh1, "</tmp/projent.$$") || fatal($!);
$pf1 = read_pfile($fh1);
close($fh1);


start("Test getprojid");
($s) = `/usr/xpg4/bin/id -p` =~ /projid=(\d+)/;
defined($s) && $s == getprojid() ? pass() : fail();

start("Test fgetprojent");
$pf2 = [];
open($fh, "</tmp/projent.$$") || fatal($!);
while (my @proj = fgetprojent($fh)) {
	push(@$pf2, [ @proj ]);
}
close($fh);
cmp_recs($pf1, $pf2) ? pass() : fail();

my %pf_byname = map({ $_->[0] => $_} @$pf1);
my %pf_byid = map({ $_->[1] => $_} @$pf1);
my (%h, @a1, @a2, $k, $v);

start("Test getprojent.  Don't assume anything about the order it returns stuff in");
%h = %pf_byname;
$pass = 1;
@a2 = ();
while (@a1 = getprojent()) {
	@a2 = @a1 if (! scalar(@a2));
	if (exists($h{$a1[0]})) {
		$pass = 0 if (! cmp_recs(\@a1, $h{$a1[0]}));
		delete($h{$a1[0]});
	} else {
		$pass = 0;
	}
}
$pass && ! %h ? pass() : fail();

start("Test getprojent when at end");
@a1 = getprojent();
cmp_recs(\@a1, []) ? pass() : fail();


start("Test endprojent/getprojent");
endprojent();
@a1 = getprojent();
cmp_recs(\@a1, \@a2) ? pass() : fail();

start("Test setprojent/getprojent");
setprojent();
@a1 = getprojent();
cmp_recs(\@a1, \@a2) ? pass() : fail();
setprojent();

start("Test getprojbyname");
$pass = 1;
while (($k, $v) = each(%pf_byname)) {
	@a1 = getprojbyname($k);
	$pass = 0 if (! cmp_recs(\@a1, $v));
}
$pass ? pass() : fail();

start("Test getprojbyid");
$pass = 1;
while (($k, $v) = each(%pf_byid)) {
	@a1 = getprojbyid($k);
	$pass = 0 if (! cmp_recs(\@a1, $v));
}
$pass ? pass() : fail();

start("Test getprojidbyname");
$pass = 1;
while (($k, $v) = each(%pf_byname)) {
	$pass = 0 if (getprojidbyname($k) != $v->[1]);
}
$pass ? pass() : fail();

start("Test getdefaultproj");
my $username = getpwuid($>);
my $projid; 
$s = `/usr/bin/id -p` ;
($projid) = $s =~ /projid=\d+\(([^)]+)\)/;
defined($projid) && $projid eq getdefaultproj($username) ? pass() : fail();

start("test inproj");
$s = `/usr/bin/projects`;
($s) = split(/\s+/, $s);
inproj($username, $s) ? pass() : fail();

exit(0);
