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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

use POSIX;

my $QUIT = 0;
my $USE_XANADU = 0;
my $TIMEOUT = 60;
my $FILEBENCH = "/usr/benchmarks/filebench";
my $PROG = "/usr/benchmarks/filebench/bin/go_filebench";
my $FSCRIPT;
my $SCRIPT_NO;
my @CONFLIST;
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

sub get_CONFNAME {
    return ($CONFNAME);
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
    my $scriptname = conf_reqval("statsdir") . "/thisrun.f";
    if($workload ne '') {
      	   open (FSCRIPT, ">$scriptname");
      	   chmod (0755, $scriptname);
      	   print FSCRIPT "#!$PROG -f\n\n";
           # Load the df
           print FSCRIPT "load $workload\n";
           # Load the user defined defaults
           op_load_defaults();

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
    if($QUIT) {
	# Shutdown the appropriate processes
	print FSCRIPT "shutdown processes\n";

	# Quit filebench
        print FSCRIPT "quit\n";
	close(FSCRIPT);
	print "Running " . conf_reqval("statsdir") . "/thisrun.f\n";
	system (conf_reqval("statsdir") . "/thisrun.f");
    } else {
        print STDOUT "ERROR: pre-mature call to op_quit\n";
    }
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

        # Create the associated processes and start them running
        print FSCRIPT "create processes\n";

	if (($time ne '') && ($statsfile ne '')) {
	    # Clear the current statistics buffers
	    print FSCRIPT "stats clear\n";

	    # Start external statistics collection (if any)
	    # Note all statistics arrays MUST be the same length !
	    if (@ext_stats != ()) {
	    	if (($#ext_stats == $#file_stats) && ($#ext_stats == $#arg_stats)) {
		        $script = conf_reqval("statsdir") . "/stats$SCRIPT_NO.sh";
		        open (RUNSCRIPT, ">$script");
		        chmod (0755, $script);
		        print FSCRIPT "system \"$script\"\n";
  		        $SCRIPT_NO++;
			$index=0;
			foreach my $ext (@ext_stats) {
	    			print RUNSCRIPT "$FILEBENCH/scripts/collect_$ext $ext $file_stats[$index] ";
				print RUNSCRIPT  conf_reqval("statsdir");
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
	    print FSCRIPT "stats dump \"$statsfile.out\"\n";	

	    # Statistics reaping occurs here
	    if (@ext_stats != ()) {
	    	if (($#ext_stats == $#file_stats) && ($#ext_stats == $#arg_stats)) {
		    $script = conf_reqval("statsdir") . "/stats$SCRIPT_NO.sh";
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

	        $script = conf_reqval("statsdir") . "/stats$SCRIPT_NO.pl";
	        open (RUNSCRIPT, ">$script");
	        chmod (0755, $script);
	        print FSCRIPT "system \"$script\"\n";
	        $SCRIPT_NO++;

                # The following loop adds the benchpoint run parameters and statistics into the filebench XML file
                # We capture the meta data from the start of the filebench xml file
                print RUNSCRIPT "#!/usr/bin/perl\n";
		print RUNSCRIPT "\$phase=1;\n";
                print RUNSCRIPT "open(STATSFILE,\"<".conf_reqval("statsdir")."/$statsfile.xml\");\n";
                print RUNSCRIPT "open(OSTATSFILE,\">".conf_reqval("statsdir")."/$statsfile.new.xml\");\n";
                print RUNSCRIPT "while (<STATSFILE>) {\n";
		print RUNSCRIPT "\t\$temp=\$_;\n";
                print RUNSCRIPT "\tif ((!((/.*meta.*/) || (/.*stat_doc.*/))) && (\$phase == 1)) {\n";
                print RUNSCRIPT "\t\topen(XMLFILE,\"<".conf_reqval("statsdir")."/$statsfile.config.xml\");\n";
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
                print RUNSCRIPT "unlink(\"".conf_reqval("statsdir")."/$statsfile.xml\");\n";
                print RUNSCRIPT "unlink(\"".conf_reqval("statsdir")."/$statsfile.config.xml\");\n";
                print RUNSCRIPT "system(\"mv ".conf_reqval("statsdir")."/$statsfile.new.xml ".conf_reqval("statsdir")."/$statsfile.xml\");\n";

	        $script = conf_reqval("statsdir") . "/stats$SCRIPT_NO.sh";
	        open (RUNSCRIPT, ">$script");
	        chmod (0755, $script);
	        print FSCRIPT "system \"$script\"\n";
	        $SCRIPT_NO++;

    	        print RUNSCRIPT "mkdir ".conf_reqval("statsdir")."/xml\n";
    	        print RUNSCRIPT "mkdir ".conf_reqval("statsdir")."/html\n";

    	        print RUNSCRIPT "mv ".conf_reqval("statsdir")."/$statsfile.xml ".conf_reqval("statsdir")."/xml/$statsfile.xml\n";

	        # Process XML file using Xanadu 2
	        print RUNSCRIPT "$FILEBENCH/xanadu/scripts/xanadu import ".conf_reqval("statsdir")." ".conf_reqval("statsdir")."/xml ".conf_reqval("function")."-".conf_reqval("statsdir")."\n";
	        print RUNSCRIPT "$FILEBENCH/xanadu/scripts/xanadu export ".conf_reqval("statsdir")."/xml ".conf_reqval("statsdir")."/html\n";
                close(RUNSCRIPT);
	    }
	}
	return(0);	
}

sub op_xmlstats {
    my ($statsfile) = shift;
	if($statsfile ne '') {
	    	print FSCRIPT "stats xmldump \"$statsfile.xml\"\n";	

		# The following loop adds the benchpoint run parameters and statistics into a temporary XML file
		open(OSTATSFILE,">".conf_reqval("statsdir")."/$statsfile.config.xml");
		%CONFHASH = conf_hash();
		# There is no test for whether CONFHASH contains no keys 
		# The following two lines is to obtain the stats run directory name for xanadu meta data
		print OSTATSFILE "<meta name=\"RunId\" value=\"".conf_reqval("function")."-".conf_reqval("statsdir")."\"/>\n";
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
#    foreach my $var (@vars) {


    # Cater for the user defined defaults
    foreach $var (keys(%CONFDATA)) {
        if (conf_exists($var)) {
            $var =~ s/ //g;
            my $val = conf_getval($var);
            op_set($var, $val);
	}
    }
}

##############################################################################
## Local functions
##############################################################################

sub parse_profile {
    my ($profile) = shift;
    my ($config_section, $default_section);
    
    open(CFILE, "$profile") or 
	die "ERROR: couldn't open profile";
    
    while(<CFILE>) {
	my ($line) = $_;
	chomp($line);
	$line =~ s/^\s+//; # Get rid of spaces
	
	if($line =~ /^#/ or $line eq "") {
	} else {
	    if($line =~ /}/) {
		if($default_section == 1) {
		    $default_section = 0;
		}
		if($config_section == 1) {
		    $config_section = 0;
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
		    @{ $DEFDATA{$opt} }  = @vals;
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
}

sub print_usage
{
    print "Usage:\n\tfilebench <profile name>\n\tfilebench -c <stat_dir> ...\n";
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

# Setup the statistics base directory
$STATSBASE = conf_reqval("stats");
my $filesystem = conf_reqval("filesystem");
my $hostname = `hostname`;
chomp($hostname);
$STATSBASE = $STATSBASE . "/$hostname-$filesystem-$PROFILENAME-";
my $timestamp = strftime "%b_%e_%Y-%Hh_%Mm_%Ss", localtime;
$timestamp =~ s/ //;
$STATSBASE = $STATSBASE . $timestamp;

foreach $CONFNAME (@CONFLIST) {
    %CONFDATA = ();
    %CONFDATA = %DEFDATA;
    parse_config("$CONFNAME");
    my $function = conf_reqval("function");
    if (-f "$function.func") {
	require "$function.func";
    } else {
	require "$FILEBENCH/config/$function.func";
    }
    $QUIT = 0;

    # Setup the statistics directory
    $statsdir = $STATSBASE . "/" . $CONFNAME;
    push(@{ $CONFDATA{"statsdir"} }, $statsdir);		   
    system("mkdir -p $statsdir");

    # The following function is taken from the user's function file
    pre_run();

    # Leave a log of the run info	
    open (RUNLOG, ">$STATSBASE/thisrun.prof");
    print RUNLOG "# " . conf_reqval("description") . "\n";
    close (RUNLOG);
    system ("cat $PROFILENAME.prof >>$STATSBASE/thisrun.prof");

    # Set the global statistics directory for this run
    op_statsdir();

    # The following function is taken from the user's function file
    bm_run();
   
    $QUIT = 1;

    # The following function is taken from the user's function file
    post_run();
    print "\n";
}
