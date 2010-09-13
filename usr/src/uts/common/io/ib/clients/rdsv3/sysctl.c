/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file sysctl.c
 * Oracle elects to have and use the contents of sysctl.c under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#define	HZ	100
#define	msecs_to_jiffies(a)	a

static unsigned long rdsv3_sysctl_reconnect_min = 1;

unsigned long rdsv3_sysctl_reconnect_min_jiffies;
unsigned long rdsv3_sysctl_reconnect_max_jiffies = HZ;

unsigned int  rdsv3_sysctl_max_unacked_packets = 8;
unsigned int  rdsv3_sysctl_max_unacked_bytes = (16 << 20);

unsigned int rdsv3_sysctl_ping_enable = 1;

void
rdsv3_sysctl_exit(void)
{
}

int
rdsv3_sysctl_init(void)
{
	rdsv3_sysctl_reconnect_min = msecs_to_jiffies(1);
	rdsv3_sysctl_reconnect_min_jiffies = rdsv3_sysctl_reconnect_min;

	return (0);
}
