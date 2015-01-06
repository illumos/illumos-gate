#!/usr/perl5/bin/perl -w
#
# nicstat - print network traffic, Kbyte/s read and written. 
#           Solaris 8+, Perl (Sun::Solaris::Kstat).
#
# "netstat -i" only gives a packet count, this program gives Kbytes.
#
# 04-Apr-2011, ver 1.00J
#
# USAGE:    nicstat [-hsz] [-i int[,int...]] | [interval [count]]
#
#           -h              # help
#           -s              # print summary output
#           -z              # skip zero lines
#           -i int[,int...] # print these instances only
#   eg,
#           nicstat         # print summary since boot
#           nicstat 1       # print continually, every 1 second
#           nicstat 1 5     # print 5 times, every 1 second
#           nicstat -i hme0 # only examine hme0
#
# This prints out the KB/s transferred for all the network cards (NICs),
# including packet counts and average sizes. The first line is the summary
# data since boot.
#
# FIELDS:
#           Int         Interface
#           rKB/s       read Kbytes/s
#           wKB/s       write Kbytes/s
#           rPk/s       read Packets/s
#           wPk/s       write Packets/s
#           rAvs        read Average size, bytes
#           wAvs        write Average size, bytes
#           %Util       %Utilisation (r or w/ifspeed)
#           Sat         Saturation (defer, nocanput, norecvbuf, noxmtbuf)
#
# NOTES:
#
# - Some unusual network cards may not provide all the details to Kstat,
#   (or provide different symbols). Check for newer versions of this program,
#   and the @Network array in the code below.
# - Utilisation is based on bytes transferred divided by speed of the interface
#   (if the speed is known). It should be impossible to reach 100% as there
#   are overheads due to bus negotiation and timing.
# - Loopback interfaces may only provide packet counts (if anything), and so
#   bytes and %util will always be zero. Newer versions of Solaris (newer than
#   Solaris 10 6/06) may provide loopback byte stats.
# - Saturation is determined by counting read and write errors caused by the 
#   interface running at saturation. This approach is not ideal, and the value
#   reported is often lower than it should be (eg, 0.0). Reading the rKB/s and
#   wKB/s fields may be more useful.
#
# SEE ALSO:
#           nicstat.c       # the C version, also on my website
#           kstat -n hme0 [interval [count]]       # or qfe0, ...
#           netstat -iI hme0 [interval [count]]
#           se netstat.se [interval]               # SE Toolkit
#           se nx.se [interval]                    # SE Toolkit
#
# COPYRIGHT: Copyright (c) 2013 Brendan Gregg.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at docs/cddl1.txt or
# http://opensource.org/licenses/CDDL-1.0.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at docs/cddl1.txt.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright 2015 Joyent, Inc. All rights reserved.
#
# Author: Brendan Gregg  [Sydney, Australia]
#
# 18-Jul-2004   Brendan Gregg   Created this.
# 07-Jan-2005       "      "    added saturation value.
# 07-Jan-2005       "      "    added summary style (from Peter Tribble).
# 23-Jan-2006       "      "    Tweaked style.
# 11-Aug-2006       "      "    Improved output neatness.
# 30-Sep-2006       "      "    Added loopback, tweaked output.
# 04-Apr-2011	brendan@joyent.com	Updated for smartmachines.

use strict;
use Getopt::Std;
use Sun::Solaris::Kstat;
my $Kstat = Sun::Solaris::Kstat->new();


#
#  Process command line args
#
usage() if defined $ARGV[0] and $ARGV[0] eq "--help";
getopts('hi:sz') or usage();
usage() if defined $main::opt_h;
my $STYLE  = defined $main::opt_s ? $main::opt_s : 0;
my $SKIPZERO  = defined $main::opt_z ? $main::opt_z : 0;

# process [interval [count]],
my ($interval, $loop_max);
if (defined $ARGV[0]) {
    $interval = $ARGV[0];
    $loop_max = defined $ARGV[1] ? $ARGV[1] : 2**32;
    usage() if $interval == 0;
}
else {
    $interval = 1;
    $loop_max = 1; 
}

# check for -i,
my %NetworkOnly;             # network interfaces to print
my $NETWORKONLY = 0;         # match on network interfaces
if (defined $main::opt_i) {
    foreach my $net (split /,/, $main::opt_i) {
        $NetworkOnly{$net} = 1;
    }
    $NETWORKONLY = 1;
}

# globals,
my $loop = 0;                # current loop number
my $PAGESIZE = 20;           # max lines per header
my $line = $PAGESIZE;        # counter for lines printed
my %NetworkNames;            # Kstat network interfaces
my %NetworkData;             # network interface data
my %NetworkDataOld;          # network interface data
$main::opt_h = 0;
$| = 1;                      # autoflush

# kstat "link" module includes:
my @Network = qw(dmfe bge be bnx ce eri eth external ge hme igb ige internal ixgbe le net ppp qfe rtls);
my %Network;
$Network{$_} = 1 foreach (@Network);
my $ZONENAME = `/usr/bin/zonename`;
chomp $ZONENAME;

### Determine network interfaces
unless (find_nets()) {
    if ($NETWORKONLY) {
        print STDERR "ERROR1: $main::opt_i matched no network interfaces.\n";
    }
    else {
        print STDERR "ERROR1: No network interfaces found!\n";
    }
    exit 1;
}


#
#  Main
#
while (1) {

    ### Print Header
    if ($line >= $PAGESIZE) {
        if ($STYLE == 0) {
            printf "%8s %12s %7s %7s %7s %7s %7s %7s %6s %5s\n",
                   "Time", "Int", "rKB/s", "wKB/s", "rPk/s", "wPk/s", "rAvs",
                   "wAvs", "%Util", "Sat";
        }
        elsif ($STYLE == 1) {
            printf "%8s %12s %14s %14s\n", "Time", "Int", "rKB/s", "wKB/s";
        }

        $line = 0;
    }

    ### Get new data
    my (@NetworkData) = fetch_net_data();

    foreach my $network_data (@NetworkData) {

        ### Extract values
        my ($int, $rbytes, $wbytes, $rpackets, $wpackets, $speed, $sat, $time)
            = split /:/, $network_data;

        ### Retrieve old values
        my ($old_rbytes, $old_wbytes, $old_rpackets, $old_wpackets, $old_sat,
            $old_time);
        if (defined $NetworkDataOld{$int}) {
            ($old_rbytes, $old_wbytes, $old_rpackets, $old_wpackets,
             $old_sat, $old_time) = split /:/, $NetworkDataOld{$int};
        }
        else {
            $old_rbytes = $old_wbytes = $old_rpackets = $old_wpackets
                = $old_sat = $old_time = 0;
        }

        #
        #  Calculate statistics
        #

        # delta time
        my $tdiff = $time - $old_time;

        # per second values
        my $rbps = ($rbytes - $old_rbytes) / $tdiff;
        my $wbps = ($wbytes - $old_wbytes) / $tdiff;
        my $rkps = $rbps / 1024;
        my $wkps = $wbps / 1024;
        my $rpps = ($rpackets - $old_rpackets) / $tdiff;
        my $wpps = ($wpackets - $old_wpackets) / $tdiff;
        my $ravs = $rpps > 0 ? $rbps / $rpps : 0;
        my $wavs = $wpps > 0 ? $wbps / $wpps : 0;

        # skip zero lines if asked
        next if $SKIPZERO and ($rbps + $wbps) == 0;
        
        # % utilisation
        my $util;
        if ($speed > 0) {
            # the following has a mysterious "800", it is 100 
            # for the % conversion, and 8 for bytes2bits.
            my $rutil = $rbps * 800 / $speed;
            my $wutil = $wbps * 800 / $speed;
            $util = $rutil > $wutil ? $rutil : $wutil;
            $util = 100 if $util > 100;
        }
        else {
            $util = 0;
        }

        # saturation per sec
        my $sats = ($sat - $old_sat) / $tdiff;

        #
        #  Print statistics
        #
        if ($rbps ne "") {
            my @Time = localtime();

            if ($STYLE == 0) {
                printf "%02d:%02d:%02d %12s ",
                       $Time[2], $Time[1], $Time[0], $int;
                print_neat($rkps);
                print_neat($wkps);
                print_neat($rpps);
                print_neat($wpps);
                print_neat($ravs);
                print_neat($wavs);
                printf "%6.2f %5.2f\n", $util, $sats;
            }
            elsif ($STYLE == 1) {
                printf "%02d:%02d:%02d %12s %14.3f %14.3f\n",
                       $Time[2], $Time[1], $Time[0], $int, $rkps, $wkps;
            }

            $line++;

            # for multiple interfaces, always print the header
            $line += $PAGESIZE if @NetworkData > 1;
        }

        ### Store old values
        $NetworkDataOld{$int}
            = "$rbytes:$wbytes:$rpackets:$wpackets:$sat:$time";
    }

    ### Check for end
    last if ++$loop == $loop_max;

    ### Interval
    sleep $interval;
}


# find_nets - walk Kstat to discover network interfaces.
#
# This walks %Kstat and populates a %NetworkNames with discovered
# network interfaces.
#
sub find_nets {
    my $found = 0;

    ### Loop over all Kstat modules
    foreach my $module (keys %$Kstat) {
        my $Modules = $Kstat->{$module};

        foreach my $instance (keys %$Modules) {
            my $Instances = $Modules->{$instance};

            foreach my $name (keys %$Instances) {

                ### Skip interface if asked
                if ($NETWORKONLY) {
                    next unless $NetworkOnly{$name};
                }

                my $Names = $Instances->{$name};

                # Check this is a network device.
                # Matching on ifspeed has been more reliable than "class"
                # we also match loopback and "link" interfaces.
                if (defined $$Names{ifspeed} || $module eq "lo"
                    || $module eq "link") {
                    next if $name eq "mac";
                    if ($module eq "link") {
                        my $nname = $name;
                        $nname =~ s/\d+$//;
                        next unless defined $Network{$nname}
                                    or $ZONENAME eq $nname
                                    or $ZONENAME eq "global";
                    }
                    ### Save network interface
                    $NetworkNames{$name} = $Names;
                    $found++;
                }
            }
        }
    }

    return $found;
}

# fetch - fetch Kstat data for the network interfaces.
#
# This uses the interfaces in %NetworkNames and returns useful Kstat data.
# The Kstat values used are rbytes64, obytes64, ipackets64, opackets64
# (or the 32 bit versions if the 64 bit values are not there).
#
sub fetch_net_data {
    my ($rbytes, $wbytes, $rpackets, $wpackets, $speed, $time);
    my @NetworkData = ();

    $Kstat->update();

    ### Loop over previously found network interfaces
    foreach my $name (sort keys %NetworkNames) {
        my $Names = $NetworkNames{$name};

        if (defined $$Names{opackets}) {

            ### Fetch write bytes
            if (defined $$Names{obytes64}) {
                $rbytes = $$Names{rbytes64};
                $wbytes = $$Names{obytes64};
            }
            elsif (defined $$Names{obytes}) {
                $rbytes = $$Names{rbytes};
                $wbytes = $$Names{obytes};
            } else {
                $rbytes = $wbytes = 0;
            }

            ### Fetch read bytes
            if (defined $$Names{opackets64}) {
                $rpackets = $$Names{ipackets64};
                $wpackets = $$Names{opackets64};
            }
            else {
                $rpackets = $$Names{ipackets};
                $wpackets = $$Names{opackets};
            }

            ### Fetch interface speed
            if (defined $$Names{ifspeed}) {
                $speed = $$Names{ifspeed};
            }
            else {
                # if we can't fetch the speed, print the
                # %Util as 0.0 . To do this we,
                $speed = 2 ** 48; 
            }

            ### Determine saturation value
            my $sat = 0;
            if (defined $$Names{nocanput} or defined $$Names{norcvbuf}) {
                $sat += defined $$Names{defer} ? $$Names{defer} : 0;
                $sat += defined $$Names{nocanput} ? $$Names{nocanput} : 0;
                $sat += defined $$Names{norcvbuf} ? $$Names{norcvbuf} : 0;
                $sat += defined $$Names{noxmtbuf} ? $$Names{noxmtbuf} : 0;
            }

            ### use the last snaptime value,
            $time = $$Names{snaptime};

            ### store data
            push @NetworkData, "$name:$rbytes:$wbytes:" . 
             "$rpackets:$wpackets:$speed:$sat:$time";
        }
    }

    return @NetworkData;
}

# print_neat - print a float with decimal places if appropriate.
#
# This specifically keeps the width to 7 characters, if possible, plus
# a trailing space.
#
sub print_neat {
    my $num = shift;
    if ($num >= 100000) {
        printf "%7d ", $num;
    } elsif ($num >= 100) {
        printf "%7.1f ", $num;
    } else {
        printf "%7.2f ", $num;
    }
}

# usage - print usage and exit.
#
sub usage {
        print STDERR <<END;
USAGE: nicstat [-hsz] [-i int[,int...]] | [interval [count]]
   eg, nicstat               # print summary since boot
       nicstat 1             # print continually every 1 second
       nicstat 1 5           # print 5 times, every 1 second
       nicstat -s            # summary output
       nicstat -i hme0       # print hme0 only
END
        exit 1;
}
