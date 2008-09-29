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

use POSIX;
use Socket;

my $MULTI_CLIENT = 0;
my $USE_XANADU = 0;
my $TIMEOUT = 60;
my $EOL = "\n";
my $FILEBENCH = "/usr/benchmarks/filebench";
my $PROG = "/usr/benchmarks/filebench/bin/go_filebench";
my $SHAREDFILEALLOCATOR;
my $TARGETPATH;
my $TARGETDIR;
my $FB_MASTERPATH;
my $STATSBASE;
my $CONFNAME;
my $FSCRIPT;
my $SCRIPT_NO;
my @CLIENTLIST = ();
my %CLIENTHASH = ();
my @CONFLIST;
my %MULTIDATA = ();
my %DEFDATA = ();
my %CONFDATA = ();
my %STATSHASH = ();
@ext_stats=();
@file_stats=();
@arg_stats=();
@pid_arr=();

# The following if test caters for running benchpoint from an alternative path
#if (-r $ENV{"FILEBENCH") {
#	$FILEBENCH = $ENV{"FILEBENCH"};
#}

##############################################################################
## Configuration hash data operations
##############################################################################

# This sub allows a function program to extract the base directory for filebench
sub get_FILEBENCH {
    return ($FILEBENCH);
}

sub get_STATSBASE {
    return ($STATSBASE);
}

sub get_CONFNAME {
    return ($CONFNAME);
}

sub multi_putval {
    my ($key) = shift;
    my ($val) = shift;
    @{MULTIDATA{$key}} = ();
    push(@{ $MULTIDATA{$key} }, $val);
}

sub multi_getval {
    my ($key) = shift;
    return ("@{$MULTIDATA{$key}}");
}

sub multi_exists {
    my ($key) = shift;
    if (exists($MULTIDATA{$key})) {
	return (1);
    }
    return (0);
}

sub conf_getval {
    my ($key) = shift;
    return ("@{$CONFDATA{$key}}");
}

sub conf_reqval {
    my ($key) = shift;
    
    if (exists($CONFDATA{$key})) {
	return ("@{$CONFDATA{$key}}");
    }
    print "ERROR: required key \"$key\" missing from configuration\n";
    exit(1);
}

sub conf_exists {
    my ($key) = shift;
    if (exists($CONFDATA{$key})) {
	return (1);
    }
    return (0);
}

sub conf_hash {
    return(%CONFDATA);
}

##############################################################################
## Filebench Operations
##############################################################################

sub op_init {
}

sub op_load {
    my ($workload) = shift;
    $scriptname = conf_reqval("statsdir") . "/thisrun.f";

    if($workload ne '') {
	print ("Creating Client Script " . $scriptname . "\n");
	open (FSCRIPT, ">$scriptname");
	chmod (0755, $scriptname);
	print FSCRIPT "#!$PROG -f\n\n";
	# Load the df
	print FSCRIPT "load $workload\n";
	# Load the user defined defaults
	op_load_defaults();

	# enable multiclient, if needed
	if ($MULTI_CLIENT == 1) {
	    print FSCRIPT "enable multi master=".multi_getval("masterhost").", client=".conf_getval("myname")."\n";
	}
	# Create the associated files and filesets
	print FSCRIPT "create filesets\n";	

    }
    $SCRIPT_NO = 1;
    return(0);
}

sub op_set {
    my ($var, $val) = @_;
    if($var eq 'debug') {
	    print FSCRIPT "debug $val\n";
    } elsif($var ne '') {
	    print FSCRIPT "set \$$var=$val\n";
    }
    return(0);
}

sub op_eventrate {
    my ($eventrate) = shift;
	if ($eventrate ne '') {
		print FSCRIPT "eventgen rate=$eventrate\n";
		return(0);
	}
}

sub op_run {
    my ($time) = shift;
    print FSCRIPT "run $time\n";
    return(0);
}

sub op_sleep {
    my ($time) = shift;
    print FSCRIPT "sleep $time\n";
    return(0);
}

sub op_msg {
    my ($msg) = shift;
    print FSCRIPT "echo \"$msg\"\n";
    return(0);
}

sub op_quit {
    # Shutdown the appropriate processes
    print FSCRIPT "shutdown processes\n";

    # Quit filebench
    print FSCRIPT "quit\n";
    close(FSCRIPT);
}

sub op_statsdir {
    print FSCRIPT "stats directory ".conf_reqval("statsdir")."\n";
    return(0);
}

sub op_indiv_vars {
    my ($ivar) = shift;
    print FSCRIPT "echo \"\$$ivar\"\n";
    my ($imatch, $ierr, $ibefore, $iafter) = &expect(FSCRIPT,
						 $TIMEOUT, "filebench>");
   
    $ibefore =~ /(.*): (.*): (-*\d+)/;
    $imatch = $3;
    $imatch =~ s/^\s+//;
    chomp($imatch);
    return($imatch);
}

sub op_indiv_stats {
    my ($var) = shift;
    print FSCRIPT "echo \"\${stats.$var}\"\n";
    my ($match, $err, $before, $after) = &expect(FSCRIPT,
						 $TIMEOUT, "filebench>");
   
    $before =~ /(.*): (.*): (-*\d+)/;
    $match = $3;
    $match =~ s/^\s+//;
    chomp($match);
    return($match);
}

sub op_stats {
    my ($time) = shift;
    my ($statsfile) = shift;
    my $mstrstatsdir = $STATSBASE."/".$CONFNAME;

    if ($MULTI_CLIENT == 1) {
	print FSCRIPT "domultisync value=1\n";
    }

    # Create the associated processes and start them running
    print FSCRIPT "create processes\n";

    if (($time ne '') && ($statsfile ne '')) {
	# Clear the current statistics buffers
	print FSCRIPT "stats clear\n";

	# Start external statistics collection (if any)
	# Note all statistics arrays MUST be the same length !
	if (@ext_stats != ()) {
	    if (($#ext_stats == $#file_stats) && ($#ext_stats == $#arg_stats)) {
		$script = $mstrstatsdir . "/stats$SCRIPT_NO.sh";
		open (RUNSCRIPT, ">$script");
		chmod (0755, $script);
		print FSCRIPT "system \"$script\"\n";
		$SCRIPT_NO++;
		$index=0;
		foreach my $ext (@ext_stats) {
		    print RUNSCRIPT "$FILEBENCH/scripts/collect_$ext $ext $file_stats[$index] ";
		    print RUNSCRIPT  $mstrstatsdir;
		    print RUNSCRIPT " $time $FILEBENCH $arg_stats[$index] &\n";
		    $index++;
		}
	    }
	}
	close(RUNSCRIPT);

	# Sleep for the run time
	print FSCRIPT "sleep $time\n";

	# Snap the statistics
	print FSCRIPT "stats snap\n";

	# Dump the statistics to a raw file - out required due to filename constraint
	if ($MULTI_CLIENT == 1) {
	    print FSCRIPT "domultisync value=2\n";
	    print FSCRIPT "stats multidump \"$statsfile.out\"\n";
	} else {
	    print FSCRIPT "stats dump \"$statsfile.out\"\n";
	}

	# Statistics reaping occurs here
	if (@ext_stats != ()) {
	    if (($#ext_stats == $#file_stats) && ($#ext_stats == $#arg_stats)) {
		$script = $mstrstatsdir . "/stats$SCRIPT_NO.sh";
		open (RUNSCRIPT, ">$script");
		chmod (0755, $script);
		print FSCRIPT "system \"$script\"\n";
		$SCRIPT_NO++;
		foreach my $ext (@ext_stats) {
		    print RUNSCRIPT "$FILEBENCH/scripts/kill_stats $ext &\n";
		}
		close(RUNSCRIPT);
	    }
	}

	# Dump the statistics to a Xanadu compatible XML file
	if ($USE_XANADU) {
	    op_xmlstats($statsfile);

	    $script = $mstrstatsdir . "/stats$SCRIPT_NO.pl";
	    open (RUNSCRIPT, ">$script");
	    chmod (0755, $script);
	    print FSCRIPT "system \"$script\"\n";
	    $SCRIPT_NO++;

	    # The following loop adds the benchpoint run parameters and statistics into the filebench XML file
	    # We capture the meta data from the start of the filebench xml file
	    print RUNSCRIPT "#!/usr/bin/perl\n";
	    print RUNSCRIPT "\$phase=1;\n";
	    print RUNSCRIPT "open(STATSFILE,\"<".$mstrstatsdir."/$statsfile.xml\");\n";
	    print RUNSCRIPT "open(OSTATSFILE,\">".$mstrstatsdir."/$statsfile.new.xml\");\n";
	    print RUNSCRIPT "while (<STATSFILE>) {\n";
	    print RUNSCRIPT "\t\$temp=\$_;\n";
	    print RUNSCRIPT "\tif ((!((/.*meta.*/) || (/.*stat_doc.*/))) && (\$phase == 1)) {\n";
	    print RUNSCRIPT "\t\topen(XMLFILE,\"<".$mstrstatsdir."/$statsfile.config.xml\");\n";
	    print RUNSCRIPT "\t\twhile (<XMLFILE>) {\n";
	    print RUNSCRIPT "\t\t\tprint OSTATSFILE \$_;\n";
	    print RUNSCRIPT "\t\t}\n";
	    print RUNSCRIPT "\t\tclose(XMLFILE);\n";
	    print RUNSCRIPT "\t\t\$phase++;\n";
	    print RUNSCRIPT "\t}\n";
	    print RUNSCRIPT "\tprint OSTATSFILE \$temp;\n";
	    print RUNSCRIPT "}\n";
	    print RUNSCRIPT "close(STATSFILE);\n";
	    print RUNSCRIPT "close(OSTATSFILE);\n";
	    print RUNSCRIPT "unlink(\"".$mstrstatsdir."/$statsfile.xml\");\n";
	    print RUNSCRIPT "unlink(\"".$mstrstatsdir."/$statsfile.config.xml\");\n";
	    print RUNSCRIPT "system(\"mv ".$mstrstatsdir."/$statsfile.new.xml ".$mstrstatsdir."/$statsfile.xml\");\n";

	    $script = $mstrstatsdir . "/stats$SCRIPT_NO.sh";
	    open (RUNSCRIPT, ">$script");
	    chmod (0755, $script);
	    print FSCRIPT "system \"$script\"\n";
	    $SCRIPT_NO++;

	    print RUNSCRIPT "mkdir ".$mstrstatsdir."/xml\n";
	    print RUNSCRIPT "mkdir ".$mstrstatsdir."/html\n";

	    print RUNSCRIPT "mv ".$mstrstatsdir."/$statsfile.xml ".$mstrstatsdir."/xml/$statsfile.xml\n";

	    # Process XML file using Xanadu 2
	    print RUNSCRIPT "$FILEBENCH/xanadu/scripts/xanadu import ".$mstrstatsdir." ".$mstrstatsdir."/xml ".conf_reqval("function")."-".$mstrstatsdir."\n";
	    print RUNSCRIPT "$FILEBENCH/xanadu/scripts/xanadu export ".$mstrstatsdir."/xml ".$mstrstatsdir."/html\n";
	    close(RUNSCRIPT);
	}
    }
    return(0);	
}

sub op_xmlstats {
    my ($statsfile) = shift;
    my $mstrstatsdir = $STATSBASE."/".$CONFNAME;
    if($statsfile ne '') {
	print FSCRIPT "stats xmldump \"$statsfile.xml\"\n";	

	# The following loop adds the benchpoint run parameters and statistics into a temporary XML file
	open(OSTATSFILE,">".$mstrstatsdir."/$statsfile.config.xml");
	%CONFHASH = conf_hash();
	# There is no test for whether CONFHASH contains no keys 
	# The following two lines is to obtain the stats run directory name for xanadu meta data
	print OSTATSFILE "<meta name=\"RunId\" value=\"".conf_reqval("function")."-".$mstrstatsdir."\"/>\n";
	print OSTATSFILE "<stat_group name=\"Benchpoint Configuration\">\n";
	print OSTATSFILE "<cell_list>\n";
	foreach $k (keys(%CONFHASH)) {
	    print OSTATSFILE "<cell>@{ $CONFHASH{$k} }</cell>\n";
	}
	print OSTATSFILE "</cell_list>\n";
	print OSTATSFILE "<dim_list>\n";
	print OSTATSFILE "<dim>\n";
	print OSTATSFILE "<dimval>Value</dimval>\n";
	print OSTATSFILE "</dim>\n";
	print OSTATSFILE "<dim>\n";
	foreach $k (keys(%CONFHASH)) {
	    print OSTATSFILE "<dimval>$k</dimval>\n";
	}
	print OSTATSFILE "</dim>\n";
	print OSTATSFILE "</dim_list>\n";
	print OSTATSFILE "</stat_group>\n";
	close(OSTATSFILE);

	return(0);	
    }
    return(1);	
}

sub op_command {
    my ($command) = shift;
	if($command ne '') {
	    print FSCRIPT "$command\n";	
	}
	return(0);	
}

sub op_statshash {
    op_indiv_stats("iocount");	
    $STATSHASH{"iocount"} = op_indiv_stats("iocount");	
    $STATSHASH{"iorate"} = op_indiv_stats("iorate");	
    $STATSHASH{"ioreadrate"} = op_indiv_stats("ioreadrate");	
    $STATSHASH{"iowriterate"} = op_indiv_stats("iowriterate");	
    $STATSHASH{"iobandwidth"} = op_indiv_stats("iobandwidth");	
    $STATSHASH{"iolatency"} = op_indiv_stats("iolatency");	
    $STATSHASH{"iocpu"} = op_indiv_stats("iocpu");	
    $STATSHASH{"oheadcpu"} = op_indiv_stats("oheadcpu");	
    $STATSHASH{"iowait"} = op_indiv_stats("iowait");	
    $STATSHASH{"syscpu"} = op_indiv_stats("syscpu");	
    $STATSHASH{"iocpusys"} = op_indiv_stats("iocpusys");	
    return(%STATSHASH);
}

sub op_load_defaults {
# The following code causes an intermittent bug - may be fixed at a later date
# Prevents the capture of filebench default parameters
#    print FSCRIPT "vars\n";
#    my ($match, $err, $before, $after) = &expect(FSCRIPT,
#						 $TIMEOUT, "filebench>");
#    chomp($before);
#    $before =~ /(.*): (.*): (.*)/;
#    $match = $3;
#    my @vars = split(/ /, $match);
#    my $value = "";
#    # Cater for the default filebench commands
#    foreach my $var (@vars) {
#        if (!conf_exists($var)) {
#            $var =~ s/ //g;
#	    if ($var ne '') {
#		$value = op_indiv_vars($var);
#       	        push(@{ $CONFDATA{$var} }, $value);		   
#	    }
#	}
#    }

    # Cater for the user defined defaults
    foreach $var (keys(%CONFDATA)) {
        if (conf_exists($var)) {
            $var =~ s/ //g;
            my $val = conf_getval($var);

	    if (($SHAREDFILEALLOCATOR) and ($var eq "sharedprealloc")) {
		if (conf_reqval("myname") ne $SHAREDFILEALLOCATOR) {
		    $val = "0";
		}
	    }

            op_set($var, $val);
	}
    }
}

##############################################################################
## Local functions
##############################################################################

sub parse_profile {
    my ($profile) = shift;
    my ($config_section, $default_section, $multi_section);
    
    open(CFILE, "$profile") or 
	die "ERROR: couldn't open profile";
    
    while(<CFILE>) {
	my ($line) = $_;
	chomp($line);
	$line =~ s/^\s+//; # Get rid of spaces
	
	if($line =~ /^#/ or $line eq "") {
	} else {
	    if($line =~ /}/) {
		if($multi_section == 1) {
		    $multi_section = 0;
		}
		if($default_section == 1) {
		    $default_section = 0;
		}
		if($config_section == 1) {
		    $config_section = 0;
		}
	    } elsif($multi_section) {
		$line =~ /(.+) = (.+);/;
		my $opt = $1;
		my $val = $2;
		chomp($opt);
		chomp($val);
		my @vals = ();
		# Check to see if this needs to be a list
		if($val =~ /,/) {
		    push(@vals, $+) while $val =~
			m{"([^\"\\]*(?:\\.[^\"\\]*)*)",? | ([^,]+),? | , }gx;
		    push(@vals, undef) if substr($val, -1,1) eq ',';
		    @{ $MULTIDATA{$opt} } = @vals;
		} else {
		    @{MULTIDATA{$opt}} = ();
		    push(@{ $MULTIDATA{$opt} }, $val);		   
		}	       
	    } elsif($default_section) {
		$line =~ /(.+) = (.+);/;
		my $opt = $1;
		my $val = $2;
		chomp($opt);
		chomp($val);
		my @vals = ();
		# Check to see if this needs to be a list
		if($val =~ /,/) {
		    push(@vals, $+) while $val =~
			m{"([^\"\\]*(?:\\.[^\"\\]*)*)",? | ([^,]+),? | , }gx;
		    push(@vals, undef) if substr($val, -1,1) eq ',';
		    @{ $DEFDATA{$opt} } = @vals;
		} else {
		    @{CONFDATA{$opt}} = ();
		    push(@{ $DEFDATA{$opt} }, $val);		   
		}	       
	    } else {
		if($line =~ /^CONFIG /) {
                    my $config = $line;
	 	    $config =~ s/CONFIG[ 	]+(.+) {/$1/;
		    push(@CONFLIST, $config);
		    $config_section = 1;
		} elsif($line =~ /MULTICLIENT {/) {
		    $multi_section = 1;
		    $MULTI_CLIENT = 1;
		} elsif($line =~ /DEFAULTS {/) {
		    $default_section = 1;
		}
	    }
	}
    }
}


#
# Parse the configuration file
#
sub parse_config {
    my ($config) = shift;

    my $config_section = 0;

    print "parsing profile for config: $config\n";
    
    # Howdy
    seek(CFILE, 0, 0);
    
    while(<CFILE>) {
	# Read in the line and chomp...munch...chomp
	my ($line) = $_;
	chomp($line);
	$line =~ s/^\s+//; # Get rid of spaces

	# look for our stuff
	if ($line =~ /CONFIG $config /) {
	    $config_section = 1;
        }

        if($line =~ /}/) {
	    $config_section = 0;
        }

	# Skip until our config is found
	next if (!$config_section);

	next if ($line =~ /^#/ or $line eq "");

	$line =~ /(.+) = (.+);/;
	my $opt = $1;
	my $val = $2;
	chomp($opt);
	chomp($val);
	my @vals = ();
	# Check to see if this needs to be a list
	if($val =~ /,/) {
	    push(@vals, $+) while $val =~
	        m{"([^\"\\]*(?:\\.[^\"\\]*)*)",? | ([^,]+),? | , }gx;
	    push(@vals, undef) if substr($val, -1,1) eq ',';
		@{ $CONFDATA{$opt} }  = @vals;
	} else {
	    @{CONFDATA{$opt}} = ();
	    push(@{ $CONFDATA{$opt} }, $val);
	}
    }
    
    # Bye, bye
    #close(CFILE) or die "ERROR: config file closing difficulties";
    return \%confdata;
}

sub build_run
{
    # The following function is taken from the user's function file
    pre_run();

    # Set the global statistics directory for this run
    op_statsdir();

    # The following function is taken from the user's function file
    bm_run();

    # Finish and close the .f script
    op_quit();
}

# statistics aggregation section
my %FLOWOPVALS;
my @SUMMARYVALS;

sub init_combined_stats
{
    %FLOWOPVALS = ();
    @SUMMARYVALS = (0,0,0,0,0,0);
}

sub add_2combstats
{
    my ($confname) = shift;
    my ($thisclient) = shift;
    my $clstatdir;
    my $flowopmode = 0;
    my $summarymode = 0;

    print "adding in stats for client: $thisclient, configuration: $confname\n";

    $clstatdir = multi_getval("masterpath")."/".$thisclient;

    print "from: ".$clstatdir."/stats.".$confname.".out\n";
    open (CLSTATS, $clstatdir."/stats.".$confname.".out");
    while(<CLSTATS>) {
	my ($line) = $_;
	chomp($line);
	if (($flowopmode == 0) and ($summarymode == 0)) {
	    if ($line =~ /^Flowop totals:/) {
		$flowopmode = 1;
		next;
	    }
	    if ($line =~ /^IO Summary:/) {
		$summarymode = 1;
		next;
	    }
	}
	if ($line eq "") {
	    $flowopmode = 0;
	    $summarymode = 0;
	    next;
	}

	# get the good stuff
	if ($flowopmode == 1) {
	    my @elementlist;
	    my @valuelist;
	    my $flkey;
	    my $vallistref = [];

	    @elementlist = split('	', $line);
	    $flkey = $elementlist[0];
	    @valuelist = @elementlist[1..$#elementlist];

	    if (exists($FLOWOPVALS{$flkey})) {
		my $numvals;

		$vallistref = $FLOWOPVALS{$flkey};
		$numvals = @{$vallistref};
		for (my $idx = 0; $idx < $numvals; $idx++) {
		    $vallistref->[$idx] += $valuelist[$idx];
		}
	    } else {
		# newly found flowop name
		$vallistref = [@valuelist];
		$FLOWOPVALS{$flkey} = $vallistref;
	    }
	    next;
	}

	# get final totals
	if ($summarymode == 1) {
	    my @valuelist;

	    @valuelist = split('	', $line);

	    for (my $idx = 0; $idx <= $#valuelist; $idx++) {
		$SUMMARYVALS[$idx] += $valuelist[$idx];
	    }
	    next;
	}
    }
    close (CLSTATS);
}

sub print_usage
{
    print "Usage:\n\tfilebench <profile name>\n\tfilebench -c <stat_dir> ...\n";
}

sub dump_combined_stats
{
    my ($confname) = shift;
    my $totvalsref = [];
    my $flkey;
    use FileHandle;

## set up output formating info
format flowoplinefrm =
@<<<<<<<<<<<<<<<<<<< @#######ops/s @###.#mb/s @#####.#ms/op @#######us/op-cpu
$flkey, $totvalsref->[0], $totvalsref->[1], $totvalsref->[2]/$#CLIENTLIST, $totvalsref->[3]/$#CLIENTLIST
.

format summarylinefrm =

IO Summary: @#######ops, @#####.#ops/s, (@####/@#### r/w) @#####.#mb/s, @######us cpu/op, @####.#ms latency
$SUMMARYVALS[0], $SUMMARYVALS[1], $SUMMARYVALS[2], $SUMMARYVALS[3], $SUMMARYVALS[4], $SUMMARYVALS[5], $SUMMARYVALS[6]
.

    open (SUMSTATS, ">$STATSBASE/$confname/stats.$confname.out");
    print "Per-Operation Breakdown:\n";
    print SUMSTATS "Per-Operation Breakdown:\n";

    format_name  STDOUT "flowoplinefrm";
    format_name  SUMSTATS "flowoplinefrm";

    foreach $flkey (keys %FLOWOPVALS) {

	$totvalsref = $FLOWOPVALS{$flkey};

	write STDOUT;
	write SUMSTATS;
    }

    format_name  STDOUT "summarylinefrm";
    format_name  SUMSTATS "summarylinefrm";

    write STDOUT;
    write SUMSTATS;
    close (SUMSTATS);
}

#
# polls the synchronization socket for each client in turn every 5 seconds,
# then sends synch responses once all clients have "checked in". The
# sample number in the received sync requests must match the sequence
# number supplied with the call.
#
sub sync_receive
{
    my $seqnum = shift;
#    my @cl_list;
    my %cl_hash = ();
    %cl_hash = %CLIENTHASH;

    my $count = @CLIENTLIST;
    print "waiting for sync message: $seqnum from $count clients\n";
    while ($count > 0) {
	my $rcv_str = "";

	sleep 5;

	foreach my $client_name (keys %cl_hash)
	{
	    my $clientdata = $CLIENTHASH{$client_name};
	    my $client_hndl = $$clientdata[0];
	    print "recv sync: $client_name undefined handle\n" unless defined($client_hndl);
	    my $client_iaddr = $$clientdata[1];
	    my $sn = $$clientdata[2];
	    my $rtn = 0;

	    do {
		my $tmp_str;
		$rtn = recv($client_hndl, $tmp_str, 80, MSG_DONTWAIT);
		if (defined($rtn)) {
		    $rcv_str = $rcv_str.$tmp_str;
		}   
	    } until (!defined($rtn) || ($rcv_str =~ /$EOL/s ));

	    if (defined($rtn)) {
		my %ophash = ();
		my $ok;

		my @oplist = split /,/,$rcv_str;
		foreach my $opent (@oplist)
		{
		    my ($op, $val) = split /=/,$opent;
		    $ophash{$op} = $val;
		}
		$ok = ($sn == $seqnum);
		$ok &&= defined((my $cmd_val = $ophash{"cmd"}));
		$ok &&= defined((my $samp_val = $ophash{"sample"}));
		if ($ok && ($cmd_val eq "SYNC") && ($samp_val == $seqnum))
		{
		    delete $cl_hash{$client_name};
		    $count--;
		    print "received a sync request from $client_name\n";
		    ${$CLIENTHASH{$client_name}}[2] = ($sn + 1);
		} else {
		    print "received invalid sync request string [".rcv_str."] from client $client_name\n";
		}
	    }
	}
    }
    print "received all sync requests for seq $seqnum, sending responses\n";
    foreach my $client_name (@CLIENTLIST)
    {
	my $clientdata = $CLIENTHASH{$client_name};
	my $client_hndl = $$clientdata[0];
	print "send resp: $client_name undefined handle\n" unless defined($client_hndl);

	send ($client_hndl, "rsp=PASS,sample=$seqnum\n", 0);
    }
}

#
# waits for all known clients to connect, then calls sync_recieve(1) to
# sync_receive(N) to wait for N sync requests for designated sync points
# 1..N.
#
sub sync_server
{
    my $port = shift || 8001;
    my $proto = getprotobyname('tcp');
    my $paddr;
    my $count;

    socket(Server, PF_INET, SOCK_STREAM, $proto)     || die "socket: $!";
    setsockopt(Server, SOL_SOCKET, SO_REUSEADDR,
	       pack("l", 1))			     || die "setsockopt: $1";
    bind(Server, sockaddr_in($port, INADDR_ANY))     || die "bind: $1";
    listen(Server, SOMAXCONN)			     || die "listen: $1";

# wait for connection requests from clients
    print "sync: Waiting for ".@CLIENTLIST." Clients\n";
    for ($count = @CLIENTLIST; $count > 0; $count--) {
	$paddr = accept(my $client_hndl, Server);
	die "bad socket address" unless $paddr;

	my ($port, $iaddr) = sockaddr_in($paddr);
	my $cl_name = gethostbyaddr($iaddr, AF_INET);

	if (!exists($CLIENTHASH{$cl_name})) {
	    die "sync from unknown client $cl_name";
	}

	print "received sync connection from client: $cl_name\n";
	${$CLIENTHASH{$cl_name}}[0] = $client_hndl;
	${$CLIENTHASH{$cl_name}}[1] = $iaddr;
    }

# indicate that all clients have checked in
    sync_receive(1);
    if (conf_exists("runtime") == 1) {
	my $runtime =  conf_getval("runtime");
	sleep $runtime;
    }
    sync_receive(2);
}

##############################################################################
## Main program
##############################################################################

## Make sure arguments are okay
$numargs = $#ARGV + 1;

if($numargs < 1) {
    print_usage();
    exit(2);
} 

if($ARGV[0] eq "-c") {
    if($numargs < 2) {
	print_usage();
	exit(2);
    }
    shift(ARGV);
    exec("$FILEBENCH/scripts/filebench_compare", @ARGV);
}

$PROFILENAME = $ARGV[0];
$PROFILE = $PROFILENAME;
$PROFILE =~ s/.*\/(.+)$/$1/;
parse_profile("$PROFILENAME.prof");

%CONFDATA = ();
%CONFDATA = %DEFDATA;

# get the name of the host this script is running on
my $hostname = `hostname`;
chomp($hostname);

# Check for Multi-Client operation
if ($MULTI_CLIENT == 1) {

    if (multi_exists("targetpath")) {
	$TARGETPATH = multi_getval("targetpath");
    } else {
	print "ERROR: Target pathname required for multi-client operation\n";
	exit(1);
    }

    if (multi_exists("clients")) {
	@CLIENTLIST = split(' ',multi_getval("clients"));
    } else {
	print "ERROR: client list required for multi-client operation\n";
	exit(1);
    }

    if (multi_exists("sharefiles")) {
	$SHAREDFILEALLOCATOR = multi_getval("sharefiles");
    } else {
	$SHAREDFILEALLOCATOR = "";
    }

    $TARGETDIR = $TARGETPATH.conf_getval("dir");

    # Setup the multi client statistics base directory
    $STATSBASE = $TARGETPATH.conf_reqval("stats");

    multi_putval("masterhost", $hostname) unless multi_exists("masterhost");
    multi_putval("masterpath", $STATSBASE) unless multi_exists("masterpath");

    # create a path for filebench.pl to use to access the master directory
    $FB_MASTERPATH = multi_getval("masterpath");

    print "Target PathName = $TARGETPATH, path = ".multi_getval("masterpath")."\n";

} else {
    # Setup the single client statistics base directory
    $STATSBASE = conf_reqval("stats");
}

my $filesystem = conf_reqval("filesystem");
$STATSBASE = $STATSBASE . "/$hostname-$filesystem-$PROFILENAME-";
my $timestamp = strftime "%b_%e_%Y-%Hh_%Mm_%Ss", localtime;
$timestamp =~ s/ //;
$STATSBASE = $STATSBASE . $timestamp;

foreach $config_name (@CONFLIST)
{
    %CONFDATA = ();
    %CONFDATA = %DEFDATA;
    $CONFNAME = $config_name;
    parse_config("$config_name");
    my $function = conf_reqval("function");
    my $statsdir;

    if (-f "$function.func") {
	require "$function.func";
    } else {
	require "$FILEBENCH/config/$function.func";
    }

    # Setup the final statistics directory
    system("mkdir -p $STATSBASE");

    # Leave a log of the run info	
    open (RUNLOG, ">$STATSBASE/thisrun.prof");
    print RUNLOG "# " . conf_reqval("description") . "\n";
    close (RUNLOG);

    system ("cat $PROFILENAME.prof >>".$STATSBASE."/thisrun.prof");

    $statsdir = $STATSBASE . "/" . $config_name;
    system("mkdir -p $statsdir");
    system("chmod a+w $statsdir");

    if ($MULTI_CLIENT == 1) {
	my @pidlist;
	my %multi_confdata;
	my $procpid;
	my $syncclients = "";

	%multi_confdata = %CONFDATA;

	foreach my $thisclient (@CLIENTLIST) {
	    my $tmpdir;
	    my $tmpstatdir;
	    my @clientdata;

	    %CONFDATA = ();
	    %CONFDATA = %multi_confdata;
	    printf "building client: " . $thisclient . "\n";

	    # Setup the statistics directory for each client
	    $tmpstatdir = multi_getval("masterpath")."/".$thisclient;

	    if ($SHAREDFILEALLOCATOR) {
		$tmpdir = $TARGETDIR;
	    } else {
		$tmpdir = $TARGETDIR."/".$thisclient;
	    }

# add info to client hash
	    @clientdata = ();
	    $clientdata[2] = 1;
	    $CLIENTHASH{$thisclient} = \@clientdata;
	    $syncclients = $syncclients." --client ".$thisclient;

	    push(@{ $CONFDATA{"myname"} }, $thisclient);
	    push(@{ $CONFDATA{"statsdir"} }, $tmpstatdir);
	    system("mkdir -p ".$FB_MASTERPATH."/".$thisclient);
	    system("chmod 0777 ".$FB_MASTERPATH."/".$thisclient);

	    # modify dir config variable for multiclient
	    if (conf_exists("dir")) {
		@{$CONFDATA{"dir"}} = ($tmpdir);
	    }
	    build_run();
	}

	# Begin the RUN!!!
	print "Running " . $STATSBASE . "\n";

	#spawn the synchronization server
	print "Starting sync server on host ".$hostname."\n";
	if ($procpid = fork) {
	    push(@pidlist, $procpid);
	} else {
	    sync_server();
	    exit(0);
	}

	sleep(3);

	# remotely execute the run on each client
	foreach $thisclient (@CLIENTLIST) {
	    if($procpid = fork) {
		push(@pidlist, $procpid);
	    } else {
		if ($thisclient eq $hostname) {
		    print "Starting local client: $thisclient\n";
		    system(multi_getval("masterpath")."/".$thisclient."/thisrun.f");
		} else {
		    print "Starting remote client: $thisclient\n";
		    system("ssh ".$thisclient." ".multi_getval("masterpath")."/".$thisclient."/thisrun.f >> ".multi_getval("masterpath")."/".$thisclient."/runs.out");
		}
		exit(0);
	    }
	}

	# wait for all of them to finish
	foreach $procpid (@pidlist) {
	    waitpid($procpid, 0);
	}

	init_combined_stats();

	foreach $thisclient (@CLIENTLIST) {
	    add_2combstats($config_name, $thisclient);
	}

	# dump the combined client stats
	dump_combined_stats($config_name);

    } else {
	push(@{ $CONFDATA{"statsdir"} }, $statsdir);

	build_run();

	# Execute the run
	print "Running " . conf_reqval("statsdir") . "/thisrun.f\n";
	system ($statsdir."/thisrun.f");


    }

}

# The following function is taken from the user's function file
post_run();

print "\n";
