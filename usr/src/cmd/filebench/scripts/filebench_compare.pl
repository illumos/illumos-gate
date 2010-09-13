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
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Compare filebench results
#
# Usage: filebench_summary <dir1> <dir2> ...
#

use CGI ':standard';

$maxiopsoverall = 0;
$maxiopsrate = 0;
$maxbandwidth = 0;

#
# Create html and text
#
open (HTML, ">index.html");
print HTML start_html(-title=>'Filebench');
print HTML "<body>";
#
# Print aggregate flowop stats
#
foreach $dir (@ARGV) {

    printf ("Generating html for $dir\n");
    open (PROFILE, "<$dir/thisrun.prof");
    $description = <PROFILE>;
    $description =~ s/.*"(.+)".*/$1/;

    $files = `ls $dir/stats.*.out $dir/*/stats.*.out 2>/dev/null`;
    foreach $file (split(/\n/, $files)) {
	print "file = $file\n";

	# Search backwards in-case the hostname is of FQDN or there's a
	# '.' in $dir.
	$rstr = reverse $file;
	($rfstype, $rworkload, $rprefix) = split(/\./, $rstr);
	$prefix = reverse $rprefix;
	$workload = reverse $rworkload;
	$fstype = reverse $rfstype;

	$dataset = $dir;
	$dataset =~ s/.*\/(.+)$/$1/;
	$dataset =~ s/\/$//;
        $desc{$dataset} = "$description";

	open (STATS, $file);
	$tmp = <STATS>;
	while (<STATS>) {
	    ($flowop, $ops, $bandwidth, $latency, $cpu, $wait, $seconds) = split(/[ \t]+/, $_);
	    
	    if (/^$/) {
		$tmp = <STATS>;
	        ($fluff, $opcnt, $ops, $reads, $writes, $bandwidth, 
		    $cpu) = split(/[ \tA-z:\/,]+/, $tmp);
	        $ops{$workload, $dataset} = $ops;
	  	last;
	    }
	    
	    $ops =~ s/ops\/s//;
	    $bandwidth =~ s/mb\/s//;
	    $latency =~ s/ms\/op//;
	    $cpu =~ s/us\/op//;
	    
	    # Collapse shadow reads into single metric
	    if ($flowop =~ /shadowread/) {
		$flowop = "shadow-read";
	    }
	    
	    # Collapse database writes into single metric
	    if ($flowop =~ /db.*write/) {
		$flowop = "db-write";
	    }
	    
	    # Collapse database writes into single metric
	    if ($flowop =~ /db.*write/) {
		$flowop = "db-write";
	    }
	    
	    $datasets{$dataset} = $dataset;
	    $workloads{$workload} = $workload;

	    $flowops{$flowop} = $flowop;
	    $wkl_flowops{$flowop, $workload} = $flowop;
	    $wkl_workload{$flowop, $workload} = $workload;
	    $flow_ops{$flowop, $workload, $dataset} += $ops;
	    $flow_bandwidth{$flowop, $workload, $dataset} += $bandwidth;
	    $flow_latency{$flowop, $workload, $dataset} += $latency;
	    $flow_cpu{$flowop, $workload, $dataset} += $cpu;

	    $bandwidth{$workload, $dataset} += $bandwidth;
	    $latency{$workload, $dataset} += $latency;
	    $cpu{$workload, $dataset} += $cpu;

	    $flowopcnt{$flowop, $workload, $dataset}++;
	    $workloadcnt{$workload, $dataset}++;
	}
	close(STATS);
    }
}

# HTML IOPS
print HTML h1('Throughput breakdown (ops per second)');
print HTML "<table border=1>";
print HTML "<b><td>Workload</td>";
foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
    print HTML "<td>$desc{$dataset}</td>";
}
print HTML "</b></tr>";

foreach $workload (sort (keys %workloads)) {
    print HTML "<b><tr><td>$workload</td>";
    $last = 0;
    foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
	$color = "white";
        $this = $ops{$workload, $dataset};
        if ($last && ($this - $last) < ($last * -0.1)) {
		$color = "red";
        }
        if ($last && ($this - $last) > ($last * 0.1)) {
		$color = "green";
	}
	printf HTML ("<td>%d</td\n", $this);
	$last = $ops{$workload, $dataset};
    }
    print HTML "</b></tr>";
}
print HTML "</table>";

# HTML Bandwidth
print HTML h1('Bandwidth breakdown (MB/s)');
print HTML "<table border=1>";
print HTML "<td>Workload</td>";
foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
    print HTML "<td>$desc{$dataset}</td>";
}
print HTML "</tr>";
foreach $workload (sort (keys %workloads)) {
    $bandwidth = 0;
    foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
	$bandwidth +=  $bandwidth{$workload, $dataset};
    }
    next if ($bandwidth == 0);
    print HTML "<tr><td>$workload</td>";
    foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
	printf HTML ("<td>%d</td>\n", $bandwidth{$workload, $dataset});
    }
    print HTML "</tr>";
}
print HTML "</table>";

# HTML Latency
print HTML h1('Latency breakdown (ms per op)');
print HTML "<table border=1>";
print HTML "<td>Workload</td>";
foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
    print HTML "<td>$desc{$dataset}</td>";
}

print HTML "</tr>";
foreach $workload (sort (keys %workloads)) {
    print HTML "<tr><td>$workload</td>";
    foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
	if ( $workloadcnt{$workload, $dataset}) {
	    printf HTML ("<td>%.1f</td>", $latency{$workload,
		$dataset} / $workloadcnt{$workload, $dataset});
        } else {
             printf HTML ("<td></td>");
        }
    }
    print HTML "</tr>";
    foreach $flowop (keys %wkl_flowops) {
        next if ("$wkl_workload{$flowop}" ne "$workload");
        print HTML "<tr><td><i>__$wkl_flowops{$flowop}</td>";
        foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
	     if ( $flowopcnt{$flowop, $dataset}) {
	         printf HTML ("<td>%.1f</td>\n", $flow_latency{$flowop, 
		    $dataset} / $flowopcnt{$flowop, $dataset});
             } else {
	         printf HTML ("<td></td>");
             }
        }
        print HTML "</i></tr>";
    }
}
print HTML "</table>";

# HTML Efficiency
print HTML h1('Efficiency breakdown (Code path length in uS/op)');
print HTML "<table border=1>";
print HTML "<td>Workload</td>";
foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
    print HTML "<td>$desc{$dataset}</td>";
}
print HTML "</tr>";
foreach $workload (sort (keys %workloads)) {
    print HTML "<tr><td>$workload</td>";
    foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
	if ($workloadcnt{$workload, $dataset}) {
	    printf HTML ("<td>%d</td>", $cpu{$workload, $dataset}
		/ $workloadcnt{$workload, $dataset});
        } else {
             printf HTML ("<td></td>");
        }
    }
    print HTML "</tr>";
    foreach $flowop (keys %wkl_flowops) {
        next if ("$wkl_workload{$flowop}" ne "$workload");
        print HTML "<tr><td><i>__$wkl_flowops{$flowop}</td>";
        foreach $dataset (sort {$a cmp $b}(keys %datasets)) {
	    if ($flowopcnt{$flowop, $dataset}) {
	        printf HTML ("<td>%d</td>\n", $flow_cpu{$flowop, 
		    $dataset} / $flowopcnt{$flowop, $dataset});
            } else {
                 printf HTML ("<td></td>");
            }
        }
        print HTML "</i></tr>";
    }
}
print HTML "</table>";

end_html();
