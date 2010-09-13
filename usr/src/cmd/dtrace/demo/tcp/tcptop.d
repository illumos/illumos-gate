#!/usr/sbin/dtrace -s
/*
 * tcptop: display top TCP network packets by process.
 *	Written using DTrace tcp Provider.
 *
 * Usage: dtrace -s tcptop.d [count] [interval]
 *
 * This analyses TCP network packets and prints the responsible PID plus
 * standard details such as IP address and port. This captures traffic
 * of newly created TCP connections that were established while this program
 * was running along with traffic from existing connections. It can help
 * identify which processes is causing TCP traffic.
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Portions Copyright 2010 Brendan Gregg
 */

#pragma D option quiet
#pragma D option defaultargs
#pragma D option switchrate=10hz

/*
 * Print header
 */
dtrace:::BEGIN
{
	/* starting values */
	counts = $1 ? $1 : 10;
	secs = $2 ? $2 : 5;
	TCP_out = 0;
	TCP_in = 0;

	printf("Sampling... Please wait.\n");
}


tcp:::send
/ args[1]->cs_pid != -1 /
{
	@out[args[1]->cs_zoneid, args[1]->cs_pid, args[2]->ip_saddr, 
	    args[4]->tcp_sport, args[2]->ip_daddr, args[4]->tcp_dport] =
	    sum(args[2]->ip_plength - args[4]->tcp_offset);
}

tcp:::receive
/ args[1]->cs_pid != -1 /
{
	@out[args[1]->cs_zoneid, args[1]->cs_pid, args[2]->ip_daddr, 
	    args[4]->tcp_dport, args[2]->ip_saddr, args[4]->tcp_sport] =
	    sum(args[2]->ip_plength - args[4]->tcp_offset);
}

/*
 * TCP Systemwide Stats
 */
mib:::tcpOutDataBytes       { TCP_out += args[0]; }
mib:::tcpRetransBytes       { TCP_out += args[0]; }
mib:::tcpInDataInorderBytes { TCP_in  += args[0]; }
mib:::tcpInDataDupBytes     { TCP_in  += args[0]; }
mib:::tcpInDataUnorderBytes { TCP_in  += args[0]; }

profile:::tick-1sec
/secs != 0/
{
	secs--;
}

/*
 * Print Report
 */
profile:::tick-1sec
/secs == 0/
{
	/* fetch 1 min load average */
	this->load1a  = `hp_avenrun[0] / 65536;
	this->load1b  = ((`hp_avenrun[0] % 65536) * 100) / 65536;

	/* convert TCP counters to Kb */
	TCP_out /= 1024;
	TCP_in  /= 1024;

	/* print status */
	printf("%Y,  load: %d.%02d,  TCPin: %6d Kb,  TCPout: %6d Kb\n\n",
	    walltimestamp, this->load1a, this->load1b, TCP_in, TCP_out);

	/* print headers */
	printf("%6s %6s %-15s %5s %-15s %5s %9s\n",
	    "ZONE", "PID", "LADDR", "LPORT", "RADDR", "RPORT", "SIZE");

	/* print data */
	printa("%6d %6d %-15s %5d %-15s %5d %@9d\n", @out);
	printf("\n");

	/* clear data */
	trunc(@out);
	TCP_in = 0;
	TCP_out = 0;
	secs = 5;
	counts--;
}

/*
 * End of program
 */
profile:::tick-1sec
/counts == 0/
{
	exit(0);
}

/*
 * Cleanup for Ctrl-C
 */
dtrace:::END
{
	trunc(@out);
}
