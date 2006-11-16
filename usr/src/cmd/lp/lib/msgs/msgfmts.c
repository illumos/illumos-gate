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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* LINTLIBRARY */

char	*_lp_msg_fmts[] =
{
    "",           	/* 0 - R_BAD_MESSAGE */
    "HSS",		/* 1 - S_NEW_QUEUE */
    "H",          	/* 2 - R_NEW_QUEUE */
    "H",          	/* 3 - S_ALLOC_FILES */
    "HS",         	/* 4 - R_ALLOC_FILES */
    "S",          	/* 5 - S_PRINT_REQUEST */
    "HSL",         	/* 6 - R_PRINT_REQUEST */
    "S",          	/* 7 - S_START_CHANGE_REQUEST */
    "HS",         	/* 8 - R_START_CHANGE_REQUEST */
    "S",          	/* 9 - S_END_CHANGE_REQUEST */
    "HL",         	/* 10 - R_END_CHANGE_REQUEST */
    "S",          	/* 11 - S_CANCEL_REQUEST */
    "H",          	/* 12 - R_CANCEL_REQUEST */
    "SSSSS",       	/* 13 - S_INQUIRE_REQUEST */
    "HSSSLLHSSSS",     	/* 14 - R_INQUIRE_REQUEST */
    "S",          	/* 15 - S_LOAD_PRINTER */
    "H",          	/* 16 - R_LOAD_PRINTER */
    "S",          	/* 17 - S_UNLOAD_PRINTER */
    "H",          	/* 18 - R_UNLOAD_PRINTER */
    "S",          	/* 19 - S_INQUIRE_PRINTER_STATUS */
    "HSSSSSHSLL", 	/* 20 - R_INQUIRE_PRINTER_STATUS */
    "S",          	/* 21 - S_LOAD_CLASS */
    "H",          	/* 22 - R_LOAD_CLASS */
    "S",          	/* 23 - S_UNLOAD_CLASS */
    "H",          	/* 24 - R_UNLOAD_CLASS */
    "S",          	/* 25 - S_INQUIRE_CLASS */
    "HSHSL",      	/* 26 - R_INQUIRE_CLASS */
    "SSS",        	/* 27 - S_MOUNT */
    "H",          	/* 28 - R_MOUNT */
    "SSS",        	/* 29 - S_UNMOUNT */
    "H",          	/* 30 - R_UNMOUNT */
    "SS",         	/* 31 - S_MOVE_REQUEST */
    "HL",          	/* 32 - R_MOVE_REQUEST */
    "SS",         	/* 33 - S_MOVE_DEST */
    "HSH",          	/* 34 - R_MOVE_DEST */
    "S",          	/* 35 - S_ACCEPT_DEST */
    "H",          	/* 36 - R_ACCEPT_DEST */
    "SS",         	/* 37 - S_REJECT_DEST */
    "H",          	/* 38 - R_REJECT_DEST */
    "S",          	/* 39 - S_ENABLE_DEST */
    "H",          	/* 40 - R_ENABLE_DEST */
    "SSH",         	/* 41 - S_DISABLE_DEST */
    "HS",          	/* 42 - R_DISABLE_DEST */
    "",          	/* 43 - S_LOAD_FILTER_TABLE */
    "H",          	/* 44 - R_LOAD_FILTER_TABLE */
    "",          	/* 45 - S_UNLOAD_FILTER_TABLE */
    "H",          	/* 46 - R_UNLOAD_FILTER_TABLE */
    "S",           	/* 47 - S_LOAD_PRINTWHEEL */
    "H",          	/* 48 - R_LOAD_PRINTWHEEL */
    "S",           	/* 49 - S_UNLOAD_PRINTWHEEL */
    "H",          	/* 50 - R_UNLOAD_PRINTWHEEL */
    "",           	/* 51 - S_LOAD_USER_FILE */
    "H",          	/* 52 - R_LOAD_USER_FILE */
    "",           	/* 53 - S_UNLOAD_USER_FILE */
    "H",          	/* 54 - R_UNLOAD_USER_FILE */
    "S",		/* 55 - S_LOAD_FORM */
    "H",		/* 56 - R_LOAD_FORM */
    "S",		/* 57 - S_UNLOAD_FORM */
    "H",		/* 58 - R_UNLOAD_FORM */
    "S",		/* 59 - S_GETSTATUS */
    "S",		/* 60 - R_GETSTATUS */
    "SH",		/* 61 - S_QUIET_ALERT */
    "H",		/* 62 - R_QUIET_ALERT */
    "SLS",		/* 63 - S_SEND_FAULT */
    "H",		/* 64 - R_SEND_FAULT */
    "H",          	/* 65 - S_SHUTDOWN */
    "H",          	/* 66 - R_SHUTDOWN */
    "",			/* 67 - S_GOODBYE */
    "LHH",		/* 68 - S_CHILD_DONE */
    "",           	/* 69 - I_GET_TYPE */
    "",			/* 70 - I_QUEUE_CHK */
    "SH",		/* 71 - R_CONNECT */
    "SSHH",		/* 72 - S_GET_STATUS */
    "HSHH",		/* 73 - R_GET_STATUS */
    "HSSSSS",		/* 74 - S_INQUIRE_REQUEST_RANK */
    "HSSSLLHSSSHS",	/* 75 - R_INQUIRE_REQUEST_RANK */
    "SSS",		/* 76 - S_CANCEL */
    "HLS",		/* 77 - R_CANCEL */
    "S",		/* 78 - S_NEW_CHILD */
    "SSH",		/* 79 - R_NEW_CHILD */
    "SHSD",		/* 80 - S_SEND_JOB */
    "SHD",		/* 81 - R_SEND_JOB */
    "HSS",		/* 82 - S_JOB_COMPLETED */
    "H",		/* 83 - R_JOB_COMPLETED */
    "S",          	/* 84 - S_INQUIRE_REMOTE_PRINTER */
/*  "",	*/		/*    - the R_INQUIRE_REMOTE_STATUS uses format 20 */
    "H",		/* 85 - S_CHILD_SYNC */
    "S",		/* 86 - S_LOAD_SYSTEM */
    "H",		/* 87 - R_LOAD_SYSTEM */
    "S",		/* 88 - S_UNLOAD_SYSTEM */
    "H",		/* 89 - R_UNLOAD_SYSTEM */
    "SLS",		/* 90 - S_CLEAR_FAULT */
    "H",		/* 91 - R_CLEAR_FAULT */
    "SSSH",        	/* 92 - S_MOUNT_TRAY */
    "H",          	/* 93 - R_MOUNT_TRAY */
    "SSSH",        	/* 94 - S_UNMOUNT_TRAY */
    "H",          	/* 95 - R_UNMOUNT_TRAY */
    "SH",        	/* 96 - S_MAX_TRAYS */
    "H",          	/* 97 - R_MAX_TRAY */
    "SHSHH",        	/* 98 - S_PAPER_CHANGED */
    "H",          	/* 99 - R_PAPER_CHANGED */
    "S",          	/* 100 - S_PAPER_ALLOWED */
    "HSS",          	/* 101 - R_PAPER_ALLOWED */
    "",          	/* 102 - S_PASS_PEER_CONNECTION */
    "H",          	/* 103 - R_PASS_PEER_CONNECTION */
    0,
};
