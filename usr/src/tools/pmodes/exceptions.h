/*
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * $Id: exceptions.h,v 1.11 2000/01/13 14:12:58 casper Exp $
 *
 * List of files/directories supposed to be group/world writable
 * May need to be updated for each OS release
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	"/etc/dumpdates",
	"/etc/lp",
	"/var/mail/:saved",
	"/var/preserve",
	/*
	 * Lp stuff is chmod'ed back by the lp system; prevent pkgchk errors
	 * later by listing them here.
	 */
	"/etc/lp/Systems",
	"/etc/lp/classes",
	"/etc/lp/forms",
	"/etc/lp/interfaces",
	"/etc/lp/ppd",
	"/etc/lp/printers",
	"/etc/lp/pwheels",
	"/var/lp",
	"/var/lp/logs",
	"/var/spool/lp",
	"/var/spool/lp/admins",
	"/var/spool/lp/fifos",
	"/var/spool/lp/fifos/private",
	"/var/spool/lp/fifos/public",
	"/var/spool/lp/requests",
	"/var/spool/lp/system",

	/* CUPS */
	"/var/cache/cups",

	/* another strange logfile */
	"/usr/oasys/tmp/TERRLOG",

	/* /var/adm stuff added because std cron jobs for sys/adm expect this */
	"/var/adm",
	"/var/adm/acct",
	"/var/adm/acct/fiscal",
	"/var/adm/acct/nite",
	"/var/adm/acct/sum",
	"/var/adm/sa",
	"/var/adm/spellhist",

	/* 5.1, 5.2 */
	"/devices/pseudo/clone:ip",
	"/devices/pseudo/clone:ticlts",
	"/devices/pseudo/clone:ticots",
	"/devices/pseudo/clone:ticotsord",
	"/devices/pseudo/clone:udp",
	"/devices/pseudo/cn:console",
	"/devices/pseudo/cn:syscon",
	"/devices/pseudo/cn:systty",
	"/devices/pseudo/log:conslog",
	"/devices/pseudo/mm:null",
	"/devices/pseudo/mm:zero",
	"/devices/pseudo/sad:user",
	"/devices/pseudo/sy:tty",
	/* 5.3, 5.4, 5.5, ... */
	"/devices/pseudo/clone@0:ip",
	"/devices/pseudo/clone@0:ticlts",
	"/devices/pseudo/clone@0:ticots",
	"/devices/pseudo/clone@0:ticotsord",
	"/devices/pseudo/clone@0:udp",
	"/devices/pseudo/clone@0:tcp",
	"/devices/pseudo/clone@0:rts",
	"/devices/pseudo/cn@0:console",
	"/devices/pseudo/cn@0:syscon",
	"/devices/pseudo/cn@0:systty",
	"/devices/pseudo/ksyms@0:ksyms",
	"/devices/pseudo/log@0:conslog",
	"/devices/pseudo/mm@0:null",
	"/devices/pseudo/mm@0:zero",
	"/devices/pseudo/sad@0:user",
	"/devices/pseudo/sy@0:tty",

	/* 5.6 .... */
	"/devices/pseudo/tl@0:ticlts",
	"/devices/pseudo/tl@0:ticots",
	"/devices/pseudo/tl@0:ticotsord",

	/* 5.8 (ipv6) ... */
	"/devices/pseudo/arp@0:arp",
	"/devices/pseudo/ip6@0:ip6",
	"/devices/pseudo/ip@0:ip",
	"/devices/pseudo/rts@0:rts",
	"/devices/pseudo/tcp6@0:tcp6",
	"/devices/pseudo/tcp@0:tcp",
	"/devices/pseudo/udp6@0:udp6",
	"/devices/pseudo/udp@0:udp",

	/* 5.9 (sendmail 8.12) ... */
	"/var/spool/clientmqueue",
