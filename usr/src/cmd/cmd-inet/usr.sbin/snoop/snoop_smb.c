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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * References used throughout this code:
 *
 * [CIFS/1.0] : A Common Internet File System (CIFS/1.0) Protocol
 *		Internet Engineering Task Force (IETF) draft
 *		Paul J. Leach, Microsoft, Dec. 1997
 *
 * [X/Open-SMB] : X/Open CAE Specification;
 *		Protocols for X/Open PC Interworking: SMB, Version 2
 *		X/Open Document Number: C209
 */

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snoop.h"

/*
 * SMB Format (header)
 * [X/Open-SMB, Sec. 5.1]
 */
struct smb {
	uchar_t idf[4]; /*  identifier, contains 0xff, 'SMB'  */
	uchar_t com;    /*  command code  */
	uchar_t err[4]; /*  NT Status, or error class+code */
	uchar_t flags;
	uchar_t flags2[2];
	uchar_t re[12];
	uchar_t tid[2];
	uchar_t pid[2];
	uchar_t uid[2];
	uchar_t mid[2];
	/*
	 * immediately after the above 32 byte header:
	 *   unsigned char  WordCount;
	 *   unsigned short ParameterWords[ WordCount ];
	 *   unsigned short ByteCount;
	 *   unsigned char  ParameterBytes[ ByteCount ];
	 */
};

/* smb flags */
#define	SERVER_RESPONSE		0x80

/* smb flags2 */
#define	FLAGS2_EXT_SEC		0x0800	/* Extended security */
#define	FLAGS2_NT_STATUS	0x4000	/* NT status codes */
#define	FLAGS2_UNICODE		0x8000	/* String are Unicode */

static void interpret_sesssetupX(int, uchar_t *, int, char *, int);
static void interpret_tconX(int, uchar_t *, int, char *, int);
static void interpret_trans(int, uchar_t *, int, char *, int);
static void interpret_trans2(int, uchar_t *, int, char *, int);
static void interpret_negprot(int, uchar_t *, int, char *, int);
static void interpret_default(int, uchar_t *, int, char *, int);

/*
 * Trans2 subcommand codes
 * [X/Open-SMB, Sec. 16.1.7]
 */
#define	TRANS2_OPEN 0x00
#define	TRANS2_FIND_FIRST 0x01
#define	TRANS2_FIND_NEXT2 0x02
#define	TRANS2_QUERY_FS_INFORMATION 0x03
#define	TRANS2_QUERY_PATH_INFORMATION 0x05
#define	TRANS2_SET_PATH_INFORMATION 0x06
#define	TRANS2_QUERY_FILE_INFORMATION 0x07
#define	TRANS2_SET_FILE_INFORMATION 0x08
#define	TRANS2_CREATE_DIRECTORY 0x0D


struct decode {
	char *name;
	void (*func)(int, uchar_t *, int, char *, int);
	char *callfmt;
	char *replyfmt;
};

/*
 * SMB command codes (function names)
 * [X/Open-SMB, Sec. 5.2]
 */
static struct decode SMBtable[256] = {
	/* 0x00 */
	{ "mkdir", 0, 0, 0 },
	{ "rmdir", 0, 0, 0 },
	{ "open", 0, 0, 0 },
	{ "create", 0, 0, 0 },

	{
		"close", 0,
		/* [X/Open-SMB, Sec. 7.10] */
		"WFileID\0"
		"lLastModTime\0"
		"dByteCount\0\0",
		"dByteCount\0\0"
	},

	{ "flush", 0, 0, 0 },
	{ "unlink", 0, 0, 0 },

	{
		"move", 0,
		/* [X/Open-SMB, Sec. 7.11] */
		"wFileAttributes\0"
		"dByteCount\0r\0"
		"UFileName\0r\0"
		"UNewPath\0\0",
		"dByteCount\0\0"
	},

	{
		"getatr", 0,
		/* [X/Open-SMB, Sec. 8.4] */
		"dBytecount\0r\0"
		"UFileName\0\0",
		"wFileAttributes\0"
		"lTime\0"
		"lSize\0"
		"R\0R\0R\0R\0R\0"
		"dByteCount\0\0"
	},

	{ "setatr", 0, 0, 0 },

	{
		"read", 0,
		/* [X/Open-SMB, Sec. 7.4] */
		"WFileID\0"
		"wI/0 Bytes\0"
		"LFileOffset\0"
		"WBytesLeft\0"
		"dByteCount\0\0",
		"WDataLength\0"
		"R\0R\0R\0R\0"
		"dByteCount\0\0"
	},

	{
		"write", 0,
		/* [X/Open-SMB, Sec. 7.5] */
		"WFileID\0"
		"wI/0 Bytes\0"
		"LFileOffset\0"
		"WBytesLeft\0"
		"dByteCount\0\0",
		"WDataLength\0"
		"dByteCount\0\0"
	},

	{ "lock", 0, 0, 0 },
	{ "unlock", 0, 0, 0 },
	{ "ctemp", 0, 0, 0 },
	{ "mknew", 0, 0, 0 },

	/* 0x10 */
	{
		"chkpth", 0,
		/* [X/Open-SMB, Sec. 8.7] */
		"dByteCount\0r\0"
		"UFile\0\0",
		"dByteCount\0\0"
	},

	{ "exit", 0, 0, 0 },
	{ "lseek", 0, 0, 0 },
	{ "lockread", 0, 0, 0 },
	{ "writeunlock", 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	{
		"readbraw", 0,
		/* [X/Open-SMB, Sec. 10.1] */
		"WFileID\0"
		"LFileOffset\0"
		"wMaxCount\0"
		"wMinCount\0"
		"lTimeout\0R\0"
		"dByteCount\0\0", 0
	},

	{ "readbmpx", 0, 0, 0 },
	{ "readbs", 0, 0, 0 },
	{ "writebraw", 0, 0, 0 },
	{ "writebmpx", 0, 0, 0 },
	{ "writebs", 0, 0, 0 },

	/* 0x20 */
	{ "writec", 0, 0, 0 },
	{ "qrysrv", 0, 0, 0 },
	{ "setattrE", 0, 0, 0 },
	{ "getattrE", 0, 0, 0 },

	{
		"lockingX", 0,
		/* [X/Open-SMB, Sec. 12.2] */
		"wChainedCommand\0"
		"wNextOffset\0"
		"WFileID\0"
		"wLockType\0"
		"lOpenTimeout\0"
		"W#Unlocks\0"
		"W#Locks\0"
		"dByteCount\0\0", 0
	},

	{ "trans", interpret_trans, 0, 0 },
	{ "transs", 0, 0, 0 },
	{ "ioctl", 0, 0, 0 },
	{ "ioctls", 0, 0, 0 },
	{ "copy", 0, 0, 0 },
	{ "move", 0, 0, 0 },
	{ "echo", 0, 0, 0 },
	{ "writeclose", 0, 0, 0 },

	{
		/* [X/Open-SMB, Sec. 12.1] */
		"openX", 0,
		/* call */
		"wChainedCommand\0"
		"wNextOffset\0"
		"wFlags\0"
		"wMode\0"
		"wSearchAttributes\0"
		"wFileAttributes\0"
		"lTime\0"
		"wOpenFunction\0"
		"lFileSize\0"
		"lOpenTimeout\0R\0R\0"
		"dByteCount\0r\0"
		"UFileName\0\0",
		/* reply */
		"wChainedCommand\0"
		"wNextOffset\0"
		"WFileID\0"
		"wAttributes\0"
		"lTime\0"
		"LSize\0"
		"wOpenMode\0"
		"wFileType\0"
		"wDeviceState\0"
		"wActionTaken\0"
		"lUniqueFileID\0R\0"
		"wBytecount\0\0"
	},

	{
		/* [CIFS 4.2.4] */
		"readX", 0,
		/* call */
		"wChainedCommand\0"
		"wNextOffset\0"
		"WFileID\0"
		"LOffset\0"
		"DMaxCount\0"
		"dMinCount\0"
		"dMaxCountHigh\0"
		"R\0"
		"wRemaining\0"
		"lOffsetHigh\0"
		"dByteCount\0\0",
		/* reply */
		"wChainedCommand\0"
		"wNextOffset\0"
		"dRemaining\0R\0R\0"
		"DCount\0"
		"dDataOffset\0"
		"dCountHigh\0"
		"R\0R\0R\0R\0"
		"dByteCount\0\0"
	},

	{
		/* [CIFS 4.2.5] */
		"writeX", 0,
		/* call */
		"wChainedCommand\0"
		"wNextOffset\0"
		"WFileID\0"
		"LOffset\0R\0R\0"
		"wWriteMode\0"
		"wRemaining\0"
		"dDataLenHigh\0"
		"DDataLen\0"
		"dDataOffset\0"
		"lOffsetHigh\0\0",
		/* reply */
		"wChainedCommand\0"
		"wNextOffset\0"
		"DCount\0"
		"wRemaining\0"
		"wCountHigh\0\0"
	},

	/* 0x30 */
	{ 0, 0, 0, 0 },
	{ "closeTD", 0, 0, 0 },
	{ "trans2", interpret_trans2, 0, 0 },
	{ "trans2s", 0, 0, 0 },
	{
		"findclose", 0,
		/* [X/Open-SMB, Sec. 15.4 ] */
		"WFileID\0"
		"dByteCount\0\0",
		"dByteCount\0\0"
	},
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0x40 */
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0x50 */
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0x60 */
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0x70 */
	{ "tcon", 0, 0, 0 },
	{
		"tdis", 0,
		/* [X/Open-SMB, Sec. 6.3] */
		"dByteCount\0\0",
		"dByteCount\0\0"
	},
	{ "negprot", interpret_negprot, 0, 0 },
	{ "sesssetupX", interpret_sesssetupX, 0, 0 },
	{
		"uloggoffX", 0,
		/* [X/Open-SMB, Sec. 15.5] */
		"wChainedCommand\0"
		"wNextOffset\0\0",
		"wChainedCommnad\0"
		"wNextOffset\0\0" },
	{ "tconX", interpret_tconX, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0x80 */
	{ "dskattr", 0, 0, 0 },
	{ "search", 0, 0, 0 },
	{ "ffirst", 0, 0, 0 },
	{ "funique", 0, 0, 0 },
	{ "fclose", 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0x90 */
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0xa0 */
	/*
	 * Command codes 0xa0 to 0xa7 are from
	 * [CIFS/1.0, Sec. 5.1]
	 */
	{ "_NT_Trans", 0, 0, 0 },
	{ "_NT_Trans2", 0, 0, 0 },
	{
		/* [CIFS/1.0, Sec. 4.2.1] */
		"_NT_CreateX", 0,
		/* Call */
		"wChainedCommand\0"
		"wNextOffset\0r\0"
		"dNameLength\0"
		"lCreateFlags\0"
		"lRootDirFID\0"
		"lDesiredAccess\0"
		"lAllocSizeLow\0"
		"lAllocSizeHigh\0"
		"lNTFileAttributes\0"
		"lShareAccess\0"
		"lOpenDisposition\0"
		"lCreateOption\0"
		"lImpersonationLevel\0"
		"bSecurityFlags\0"
		"dByteCount\0r\0"
		"UFileName\0\0",
		/* Reply */
		"wChainedCommand\0"
		"wNextOffset\0"
		"bOplockLevel\0"
		"WFileID\0"
		"lCreateAction\0\0"
	},
	{ 0, 0, 0, 0 },
	{
		"_NT_Cancel", 0,
		/* [CIFS/1.0, Sec. 4.1.8] */
		"dByteCount\0", 0
	},
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0xb0 */
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0xc0 */
	{ "splopen", 0, 0, 0 },
	{ "splwr", 0, 0, 0 },
	{ "splclose", 0, 0, 0 },
	{ "splretq", 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0xd0 */
	{ "sends", 0, 0, 0 },
	{ "sendb", 0, 0, 0 },
	{ "fwdname", 0, 0, 0 },
	{ "cancelf", 0, 0, 0 },
	{ "getmac", 0, 0, 0 },
	{ "sendstrt", 0, 0, 0 },
	{ "sendend", 0, 0, 0 },
	{ "sendtxt", 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0xe0 */
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },

	/* 0xf0 */
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 0, 0, 0 }
};

/* Helpers to get values in Intel order (often mis-aligned). */
static uint16_t
get2(uchar_t *p) {
	return (p[0] + (p[1]<<8));
}
static uint32_t
get4(uchar_t *p) {
	return (p[0] + (p[1]<<8) + (p[2]<<16) + (p[3]<<24));
}
static uint64_t
get8(uchar_t *p) {
	return (get4(p) | ((uint64_t)get4(p+4) << 32));
}

/*
 * Support displaying NT times.
 * Number of seconds between 1970 and 1601 year
 * (134774 days)
 */
static const uint64_t DIFF1970TO1601 = 11644473600ULL;
static const uint32_t TEN_MIL = 10000000UL;
static char *
format_nttime(uint64_t nt_time)
{
	uint64_t nt_sec;	/* seconds */
	uint64_t nt_tus;	/* tenths of uSec. */
	uint32_t ux_nsec;
	int64_t ux_sec;

	/* Optimize time zero. */
	if (nt_time == 0) {
		ux_sec = 0;
		ux_nsec = 0;
		goto out;
	}

	nt_sec = nt_time / TEN_MIL;
	nt_tus = nt_time % TEN_MIL;

	if (nt_sec <= DIFF1970TO1601) {
		ux_sec = 0;
		ux_nsec = 0;
		goto out;
	}
	ux_sec = nt_sec - DIFF1970TO1601;
	ux_nsec = nt_tus * 100;

out:
	return (format_time(ux_sec, ux_nsec));
}

/*
 * This is called by snoop_netbios.c.
 * This is the external entry point.
 */
void
interpret_smb(int flags, uchar_t *data, int len)
{
	struct smb *smb;
	struct decode *decoder;
	char xtra[MAXLINE];
	ushort_t smb_flags2;
	void (*func)(int, uchar_t *, int, char *, int);

	if (len < sizeof (struct smb))
		return;

	smb = (struct smb *)data;
	decoder = &SMBtable[smb->com & 255];
	smb_flags2 = get2(smb->flags2);
	xtra[0] = '\0';

	/*
	 * SMB Header description
	 * [X/Open-SMB, Sec. 5.1]
	 */
	if (flags & F_DTAIL) {
		show_header("SMB:  ", "SMB Header", len);
		show_space();

		if (smb->flags & SERVER_RESPONSE)
			show_line("SERVER RESPONSE");
		else
			show_line("CLIENT REQUEST");

		if (decoder->name)
			show_printf("Command code = 0x%x (SMB%s)",
			    smb->com, decoder->name);
		else
			show_printf("Command code = 0x%x", smb->com);

		/*
		 * NT status or error class/code
		 * [X/Open-SMB, Sec. 5.6]
		 */
		if (smb_flags2 & FLAGS2_NT_STATUS) {
			show_printf("NT Status = %x", get4(smb->err));
		} else {
			/* Error classes [X/Open-SMB, Sec. 5.6] */
			show_printf("Error class/code = %d/%d",
			    smb->err[0], get2(&smb->err[2]));
		}

		show_printf("Flags summary = 0x%.2x", smb->flags);
		show_printf("Flags2 summary = 0x%.4x", smb_flags2);
		show_printf("Tree ID  (TID) = 0x%.4x", get2(smb->tid));
		show_printf("Proc. ID (PID) = 0x%.4x", get2(smb->pid));
		show_printf("User ID  (UID) = 0x%.4x", get2(smb->uid));
		show_printf("Mux. ID  (MID) = 0x%.4x", get2(smb->mid));
		show_space();
	}

	if ((func = decoder->func) == NULL)
		func = interpret_default;
	(*func)(flags, (uchar_t *)data, len, xtra, sizeof (xtra));

	if (flags & F_SUM) {
		char *p;
		int sz, tl;

		/* Will advance p and decr. sz */
		p = get_sum_line();
		sz = MAXLINE;

		/* Call or Reply */
		if (smb->flags & SERVER_RESPONSE)
			tl = snprintf(p, sz, "SMB R");
		else
			tl = snprintf(p, sz, "SMB C");
		p += tl;
		sz -= tl;

		/* The name, if known, else the cmd code */
		if (decoder->name) {
			tl = snprintf(p, sz, " Cmd=SMB%s", decoder->name);
		} else {
			tl = snprintf(p, sz, " Cmd=0x%02X", smb->com);
		}
		p += tl;
		sz -= tl;

		/*
		 * The "extra" (cmd-specific summary).
		 * If non-null, has leading blank.
		 */
		if (xtra[0] != '\0') {
			tl = snprintf(p, sz, "%s", xtra);
			p += tl;
			sz -= tl;
		}

		/*
		 * NT status or error class/code
		 * [X/Open-SMB, Sec. 5.6]
		 *
		 * Only show for response, not call.
		 */
		if (smb->flags & SERVER_RESPONSE) {
			if (smb_flags2 & FLAGS2_NT_STATUS) {
				uint_t status = get4(smb->err);
				snprintf(p, sz, " Status=0x%x", status);
			} else {
				uchar_t errcl = smb->err[0];
				ushort_t code = get2(&smb->err[2]);
				snprintf(p, sz, " Error=%d/%d", errcl, code);
			}
		}
	}

	if (flags & F_DTAIL)
		show_trailer();
}

static void
output_bytes(uchar_t *data, int bytecount)
{
	int i;
	char buff[80];
	char word[10];

	(void) strlcpy(buff, "  ", sizeof (buff));
	for (i = 0; i < bytecount; i++) {
		snprintf(word, sizeof (word), "%.2x ", data[i]);
		(void) strlcat(buff, word, sizeof (buff));
		if ((i+1)%16 == 0 || i == (bytecount-1)) {
			show_line(buff);
			(void) strlcpy(buff, "  ", sizeof (buff));
		}
	}
}

/*
 * Based on the Unicode Standard,  http://www.unicode.org/
 * "The Unicode Standard: A Technical Introduction", June 1998
 */
static int
unicode2ascii(char *outstr, int outlen, uchar_t *instr, int inlen)
{
	int i = 0, j = 0;
	char c;

	while (i < inlen && j < (outlen-1)) {
		/* Show unicode chars >= 256 as '?' */
		if (instr[i+1])
			c = '?';
		else
			c = instr[i];
		if (c == '\0')
			break;
		outstr[j] = c;
		i += 2;
		j++;
	}
	outstr[j] = '\0';
	return (j);
}

/*
 * Convenience macro to copy a string from the data,
 * either in UCS-2 or ASCII as indicated by UCS.
 * OBUF must be an array type (see sizeof) and
 * DP must be an L-value (this increments it).
 */
#define	GET_STRING(OBUF, DP, UCS)				\
{								\
	int _len, _sz = sizeof (OBUF);				\
	if (UCS) {						\
		if (((uintptr_t)DP) & 1)			\
			DP++;					\
		_len = unicode2ascii(OBUF, _sz, DP, 2 * _sz);	\
		DP += 2 * (_len + 1);				\
	} else {						\
		_len = strlcpy(OBUF, (char *)DP, _sz);		\
		DP += (_len + 1);				\
	}							\
}

/*
 * TRANS2 information levels
 * [X/Open-SMB, Sec. 16.1.6]
 */
static void
get_info_level(char *outstr, int outsz, int value)
{

	switch (value) {
	case 1:
		snprintf(outstr, outsz, "Standard");
		break;
	case 2:
		snprintf(outstr, outsz, "Query EA Size");
		break;
	case 3:
		snprintf(outstr, outsz, "Query EAS from List");
		break;
	case 0x101:
		snprintf(outstr, outsz, "Directory Info");
		break;
	case 0x102:
		snprintf(outstr, outsz, "Full Directory Info");
		break;
	case 0x103:
		snprintf(outstr, outsz, "Names Info");
		break;
	case 0x104:
		snprintf(outstr, outsz, "Both Directory Info");
		break;
	default:
		snprintf(outstr, outsz, "Unknown");
		break;
	}
}

/*
 * Interpret TRANS2_QUERY_PATH subcommand
 * [X/Open-SMB, Sec. 16.7]
 */
/* ARGSUSED */
static void
output_trans2_querypath(int flags, uchar_t *data, char *xtra, int xsz)
{
	int length;
	char filename[256];

	if (flags & F_SUM) {
		length = snprintf(xtra, xsz, " QueryPathInfo");
		xtra += length;
		xsz -= length;
		data += 6;
		(void) unicode2ascii(filename, 256, data, 512);
		snprintf(xtra, xsz, " File=%s", filename);
	}

	if (flags & F_DTAIL) {
		show_line("FunctionName = QueryPathInfo");
		show_printf("InfoLevel = 0x%.4x", get2(data));
		data += 6;
		(void) unicode2ascii(filename, 256, data, 512);
		show_printf("FileName = %s", filename);
	}
}

/*
 * Interpret TRANS2_QUERY_FILE subcommand
 * [X/Open-SMB, Sec. 16.9]
 */
/* ARGSUSED */
static void
output_trans2_queryfile(int flags, uchar_t *data, char *xtra, int xsz)
{
	int length;

	if (flags & F_SUM) {
		length = snprintf(xtra, xsz, " QueryFileInfo");
		xtra += length;
		xsz -= length;
		snprintf(xtra, xsz, " FileID=0x%x", get2(data));
	}

	if (flags & F_DTAIL) {
		show_line("FunctionName = QueryFileInfo");
		show_printf("FileID = 0x%.4x", get2(data));
		data += 2;
		show_printf("InfoLevel = 0x%.4x", get2(data));
	}
}

/*
 * Interpret TRANS2_SET_FILE subcommand
 * [X/Open-SMB, Sec. 16.10]
 */
/* ARGSUSED */
static void
output_trans2_setfile(int flags, uchar_t *data, char *xtra, int xsz)
{
	int length;

	if (flags & F_SUM) {
		length = snprintf(xtra, xsz, " SetFileInfo");
		xtra += length;
		xsz -= length;
		snprintf(xtra, xsz, " FileID=0x%x", get2(data));
	}

	if (flags & F_DTAIL) {
		show_line("FunctionName = SetFileInfo");
		show_printf("FileID = 0x%.4x", get2(data));
		data += 2;
		show_printf("InfoLevel = 0x%.4x", get2(data));
	}
}

/*
 * Interpret TRANS2_FIND_FIRST subcommand
 * [X/Open-SMB, Sec. 16.3]
 */
/* ARGSUSED */
static void
output_trans2_findfirst(int flags, uchar_t *data, char *xtra, int xsz)
{
	int length;
	char filename[256];
	char infolevel[100];

	if (flags & F_SUM) {
		length = snprintf(xtra, xsz, " Findfirst");
		xtra += length;
		xsz -= length;
		data += 12;
		(void) unicode2ascii(filename, 256, data, 512);
		snprintf(xtra, xsz, " File=%s", filename);
	}

	if (flags & F_DTAIL) {
		show_line("FunctionName = Findfirst");
		show_printf("SearchAttributes = 0x%.4x", get2(data));
		data += 2;
		show_printf("FindCount = 0x%.4x", get2(data));
		data += 2;
		show_printf("FindFlags = 0x%.4x", get2(data));
		data += 2;
		get_info_level(infolevel, sizeof (infolevel), get2(data));
		show_printf("InfoLevel = %s", infolevel);
		data += 6;
		(void) unicode2ascii(filename, 256, data, 512);
		show_printf("FileName = %s", filename);
	}
}


/*
 * Interpret TRANS2_FIND_NEXT subcommand
 * [X/Open-SMB, Sec. 16.4]
 */
/* ARGSUSED */
static void
output_trans2_findnext(int flags, uchar_t *data, char *xtra, int xsz)
{
	int length;
	char filename[256];
	char infolevel[100];

	if (flags & F_SUM) {
		length = snprintf(xtra, xsz, " Findnext");
		xtra += length;
		xsz -= length;
		data += 12;
		(void) unicode2ascii(filename, 256, data, 512);
		snprintf(xtra, xsz, " File=%s", filename);
	}

	if (flags & F_DTAIL) {
		show_line("FunctionName = Findnext");
		show_printf("FileID = 0x%.4x", get2(data));
		data += 2;
		show_printf("FindCount = 0x%.4x", get2(data));
		data += 2;
		get_info_level(infolevel, sizeof (infolevel), get2(data));
		show_printf("InfoLevel = %s", infolevel);
		data += 2;
		show_printf("FindKey = 0x%.8x", get4(data));
		data += 4;
		show_printf("FindFlags = 0x%.4x", get2(data));
		data += 2;
		(void) unicode2ascii(filename, 256, data, 512);
		show_printf("FileName = %s", filename);
	}
}

/*
 * Interpret a "Negprot" SMB
 * [X/Open-SMB, Sec. 6.1]
 */
/* ARGSUSED */
static void
interpret_negprot(int flags, uchar_t *data, int len, char *xtra, int xsz)
{
	int i, last, length;
	int bytecount;
	int key_len;
	int wordcount;
	char tbuf[256];
	struct smb *smbdata;
	uchar_t *protodata;
	uchar_t *byte0;
	uint64_t nttime;
	uint32_t caps;
	ushort_t smb_flags2;

	smbdata  = (struct smb *)data;
	smb_flags2 = get2(smbdata->flags2);
	protodata = (uchar_t *)data + sizeof (struct smb);
	wordcount = *protodata++;

	if ((smbdata->flags & SERVER_RESPONSE) == 0) {
		/*
		 * request packet:
		 * short bytecount;
		 * struct { char fmt; char name[]; } dialects
		 */
		bytecount = get2(protodata);
		protodata += 2;
		byte0 = protodata;

		if (flags & F_DTAIL)
			show_printf("ByteCount = %d", bytecount);
		if (bytecount > len)
			bytecount = len;

		/* Walk the list of dialects. */
		i = last = 0;
		tbuf[0] = '\0';
		while (protodata < (byte0 + bytecount - 2)) {
			if (*protodata++ != 2)	/* format code */
				break;
			length = strlcpy(tbuf, (char *)protodata,
			    sizeof (tbuf));
			protodata += (length + 1);
			if (flags & F_DTAIL) {
				show_printf("Dialect[%d] = %s",
				    i, tbuf);
			}
			last = i++;
		}
		if (flags & F_SUM) {
			/*
			 * Just print the last dialect, which is
			 * normally the interesting one.
			 */
			snprintf(xtra, xsz, " Dialect[%d]=%s", last, tbuf);
		}
	} else {
		/* Parse reply */
		if (flags & F_SUM) {
			snprintf(xtra, xsz, " Dialect#=%d", protodata[0]);
		}
		if ((flags & F_DTAIL) == 0)
			return;
		if (wordcount < 13)
			return;
		show_printf("WordCount = %d", wordcount);
		show_printf("Dialect Index = %d", protodata[0]);
		protodata += 2;
		show_printf("Security Mode = 0x%x", protodata[0]);
		protodata++;
		show_printf("MaxMPXRequests = %d", get2(protodata));
		protodata += 2;
		show_printf("MaxVCs = %d", get2(protodata));
		protodata += 2;
		show_printf("MaxBufferSize = %d", get4(protodata));
		protodata += 4;
		show_printf("MaxRawBuffer = %d", get4(protodata));
		protodata += 4;
		show_printf("SessionKey = 0x%.8x", get4(protodata));
		protodata += 4;

		caps = get4(protodata);
		protodata += 4;
		show_printf("Capabilities = 0x%.8x", caps);

		/* Server Time */
		nttime = get8(protodata);
		protodata += 8;
		show_printf("Server Time = %s", format_nttime(nttime));

		show_printf("Server TZ = %d", get2(protodata));
		protodata += 2;

		key_len = *protodata++;
		show_printf("KeyLength = %d", key_len);
		bytecount = get2(protodata);
		protodata += 2;
		show_printf("ByteCount = %d", bytecount);

		if (smb_flags2 & FLAGS2_EXT_SEC) {
			show_printf("Server GUID (16)");
			output_bytes(protodata, 16);
			protodata += 16;
			show_printf("Security Blob (SPNEGO)");
			output_bytes(protodata, bytecount - 16);
		} else {
			show_printf("NTLM Challenge: (%d)", key_len);
			output_bytes(protodata, key_len);
			protodata += key_len;
			/*
			 * Get Unicode from capabilities here,
			 * as flags2 typically doesn't have it.
			 * Also, this one is NOT aligned!
			 */
			tbuf[0] = '\0';
			if (caps & 4) {
				(void) unicode2ascii(tbuf, sizeof (tbuf),
				    protodata, 2 * sizeof (tbuf));
			} else {
				(void) strlcpy(tbuf, (char *)protodata,
				    sizeof (tbuf));
			}
			show_printf("Server Domain = %s", tbuf);
		}
	}
}

/*
 * LAN Manager remote admin function names.
 * [X/Open-SMB, Appendix B.8]
 */
static const char *apiname_table[] = {
	"RNetShareEnum",
	"RNetShareGetInfo",
	"NetShareSetInfo",
	"NetShareAdd",
	"NetShareDel",
	"NetShareCheck",
	"NetSessionEnum",
	"NetSessionGetInfo",
	"NetSessionDel",
	"NetConnectionEnum",
	"NetFileEnum",
	"NetFileGetInfo",
	"NetFileClose",
	"RNetServerGetInfo",
	"NetServerSetInfo",
	"NetServerDiskEnum",
	"NetServerAdminCommand",
	"NetAuditOpen",
	"NetAuditClear",
	"NetErrorLogOpen",
	"NetErrorLogClear",
	"NetCharDevEnum",
	"NetCharDevGetInfo",
	"NetCharDevControl",
	"NetCharDevQEnum",
	"NetCharDevQGetInfo",
	"NetCharDevQSetInfo",
	"NetCharDevQPurge",
	"RNetCharDevQPurgeSelf",
	"NetMessageNameEnum",
	"NetMessageNameGetInfo",
	"NetMessageNameAdd",
	"NetMessageNameDel",
	"NetMessageNameFwd",
	"NetMessageNameUnFwd",
	"NetMessageBufferSend",
	"NetMessageFileSend",
	"NetMessageLogFileSet",
	"NetMessageLogFileGet",
	"NetServiceEnum",
	"RNetServiceInstall",
	"RNetServiceControl",
	"RNetAccessEnum",
	"RNetAccessGetInfo",
	"RNetAccessSetInfo",
	"RNetAccessAdd",
	"RNetAccessDel",
	"NetGroupEnum",
	"NetGroupAdd",
	"NetGroupDel",
	"NetGroupAddUser",
	"NetGroupDelUser",
	"NetGroupGetUsers",
	"NetUserEnum",
	"RNetUserAdd",
	"NetUserDel",
	"NetUserGetInfo",
	"RNetUserSetInfo",
	"RNetUserPasswordSet",
	"NetUserGetGroups",
	"NetWkstaLogon",
	"NetWkstaLogoff",
	"NetWkstaSetUID",
	"NetWkstaGetInfo",
	"NetWkstaSetInfo",
	"NetUseEnum",
	"NetUseAdd",
	"NetUseDel",
	"NetUseGetInfo",
	"DosPrintQEnum",
	"DosPrintQGetInfo",
	"DosPrintQSetInfo",
	"DosPrintQAdd",
	"DosPrintQDel",
	"DosPrintQPause",
	"DosPrintQContinue",
	"DosPrintJobEnum",
	"DosPrintJobGetInfo",
	"RDosPrintJobSetInfo",
	"DosPrintJobAdd",
	"DosPrintJobSchedule",
	"RDosPrintJobDel",
	"RDosPrintJobPause",
	"RDosPrintJobContinue",
	"DosPrintDestEnum",
	"DosPrintDestGetInfo",
	"DosPrintDestControl",
	"NetProfileSave",
	"NetProfileLoad",
	"NetStatisticsGet",
	"NetStatisticsClear",
	"NetRemoteTOD",
	"NetBiosEnum",
	"NetBiosGetInfo",
	"NetServerEnum",
	"I_NetServerEnum",
	"NetServiceGetInfo",
	"NetSplQmAbort",
	"NetSplQmClose",
	"NetSplQmEndDoc",
	"NetSplQmOpen",
	"NetSplQmStartDoc",
	"NetSplQmWrite",
	"DosPrintQPurge",
	"NetServerEnum2"
};
static const int apinum_max = (
	sizeof (apiname_table) /
	sizeof (apiname_table[0]));

static const char *
pipeapi_name(int code)
{
	char *name;

	switch (code) {
	case 0x01:
		name = "SetNmPipeState";
		break;
	case 0x11:
		name = "RawReadNmPipe";
		break;
	case 0x21:
		name = "QueryNmPipeState";
		break;
	case 0x22:
		name = "QueryNmPipeInfo";
		break;
	case 0x23:
		name = "PeekNmPipe";
		break;
	case 0x26:
		name = "XactNmPipe";
		break;
	case 0x31:
		name = "RawWriteNmPipe";
		break;
	case 0x36:
		name = "ReadNmPipe";
		break;
	case 0x37:
		name = "WriteNmPipe";
		break;
	case 0x53:
		name = "WaitNmPipe";
		break;
	case 0x54:
		name = "CallNmPipe";
		break;
	default:
		name = "?";
		break;
	}
	return (name);
}

/*
 * Interpret a "trans" SMB
 * [X/Open-SMB, Appendix B]
 *
 * This is very much like "trans2" below.
 */
/* ARGSUSED */
static void
interpret_trans(int flags, uchar_t *data, int len, char *xtra, int xsz)
{
	struct smb *smb;
	uchar_t *vwv; /* word parameters */
	int wordcount;
	uchar_t *byteparms;
	int bytecount;
	int parambytes;
	int paramoffset;
	int setupcount;
	int subcode;
	uchar_t *setupdata;
	uchar_t *params;
	int apinum;
	int isunicode;
	char filename[256];
	const char *apiname;
	const char *subcname;
	ushort_t smb_flags2;

	smb = (struct smb *)data;
	smb_flags2 = get2(smb->flags2);
	vwv = (uchar_t *)data + sizeof (struct smb);
	wordcount = *vwv++;

	/* Is the pathname in unicode? */
	isunicode = smb_flags2 & FLAGS2_UNICODE;

	byteparms = vwv + (2 * wordcount);
	bytecount = get2(byteparms);
	byteparms += 2;

	/*
	 * Print the lengths before we (potentially) bail out
	 * due to lack of data (so the user knows why we did).
	 */
	if (flags & F_DTAIL)
		show_printf("WordCount = %d", wordcount);

	/* Get length and location of params and setup data. */
	if (!(smb->flags & SERVER_RESPONSE)) {
		/* CALL */
		if (wordcount < 14)
			return;
		parambytes  = get2(vwv + (2 *  9));
		paramoffset = get2(vwv + (2 * 10));
		setupcount = *(vwv + (2 * 13));
		setupdata  =   vwv + (2 * 14);
	} else {
		/* REPLY */
		if (wordcount < 10)
			return;
		parambytes  = get2(vwv + (2 * 3));
		paramoffset = get2(vwv + (2 * 4));
		setupcount = *(vwv + (2 *  9));
		setupdata  =   vwv + (2 * 10);
	}

	/* The parameters are offset from the SMB header. */
	params = data + paramoffset;

	if ((smb->flags & SERVER_RESPONSE) == 0) {
		/* This is a CALL. */

		if (setupcount > 0)
			subcode = get2(setupdata);
		else
			subcode = -1; /* invalid */
		subcname = pipeapi_name(subcode);

		if (parambytes > 0)
			apinum = params[0];
		else
			apinum = -1; /* invalid */
		if (0 <= apinum && apinum < apinum_max)
			apiname = apiname_table[apinum];
		else
			apiname = "?";

		if (flags & F_SUM) {
			int tl;
			/* Only get one or the other */
			if (*subcname != '?') {
				tl = snprintf(xtra, xsz,
				    " Func=%s", subcname);
				xtra += tl;
				xsz -= tl;
			}
			if (*apiname != '?')
				snprintf(xtra, xsz,
				    " Func=%s", apiname);
			return;
		}
		if ((flags & F_DTAIL) == 0)
			return;

		/* print the word parameters */
		show_printf("TotalParamBytes = %d", get2(vwv));
		show_printf("TotalDataBytes = %d", get2(vwv+2));
		show_printf("MaxParamBytes = %d", get2(vwv+4));
		show_printf("MaxDataBytes = %d", get2(vwv+6));
		show_printf("MaxSetupWords = %d", vwv[8]);
		show_printf("TransFlags = 0x%.4x", get2(vwv+10));
		show_printf("Timeout = 0x%.8x", get4(vwv+12));
		/* skip Reserved2 */
		show_printf("ParamBytes = %d", parambytes);
		show_printf("ParamOffset = %d", paramoffset);
		show_printf("DataBytes = %d", get2(vwv+22));
		show_printf("DataOffset = %d", get2(vwv+24));
		show_printf("SetupWords = %d", setupcount);
		show_printf("ByteCount = %d", bytecount);

		/* That finishes the VWV, now the misc. stuff. */
		if (setupcount > 0)
			show_printf("NmPipeFunc = 0x%x (%s)",
			    subcode, subcname);
		if (parambytes > 0)
			show_printf("RAP_Func = %d (%s)",
			    apinum, apiname);

		/* Finally, print the byte parameters. */
		GET_STRING(filename, byteparms, isunicode);
		show_printf("FileName = %s", filename);
	} else {
		/* This is a REPLY. */
		if (flags & F_SUM)
			return;
		if ((flags & F_DTAIL) == 0)
			return;
		/* print the word parameters */
		show_printf("TotalParamBytes = %d", get2(vwv));
		show_printf("TotalDataBytes = %d", get2(vwv+2));
		/* skip Reserved */
		show_printf("ParamBytes = 0x%.4x", parambytes);
		show_printf("ParamOffset = 0x%.4x", paramoffset);
		show_printf("ParamDispl. = 0x%.4x", get2(vwv+10));
		show_printf("DataBytes = 0x%.4x", get2(vwv+12));
		show_printf("DataOffset = 0x%.4x", get2(vwv+14));
		show_printf("DataDispl. = 0x%.4x", get2(vwv+16));
		show_printf("SetupWords = %d", setupcount);
		show_printf("ByteCount = %d", bytecount);

		show_printf("ParamVec (%d)", parambytes);
		output_bytes(params, parambytes);
	}
}

/*
 * Interpret a "TconX" SMB
 * [X/Open-SMB, Sec. 11.4]
 */
/* ARGSUSED */
static void
interpret_tconX(int flags, uchar_t *data, int len, char *xtra, int xsz)
{
	int length;
	int isunicode;
	int bytecount;
	int wordcount;
	int andxcmd;
	int andxoffset;
	int tconflags;
	int pw_len;
	char path[256];
	char tbuf[256];
	char svc[8];
	struct smb *smbdata;
	uchar_t *tcondata;
	ushort_t smb_flags2;

	smbdata = (struct smb *)data;
	smb_flags2 = get2(smbdata->flags2);
	tcondata = (uchar_t *)data + sizeof (struct smb);
	wordcount = *tcondata++;

	isunicode = smb_flags2 & FLAGS2_UNICODE;

	if ((smbdata->flags & SERVER_RESPONSE) == 0) {
		/* Request */
		if (wordcount < 4)
			return;
		andxcmd = get2(tcondata);
		tcondata += 2;
		andxoffset = get2(tcondata);
		tcondata += 2;
		tconflags = get2(tcondata);
		tcondata += 2;
		pw_len = get2(tcondata);
		tcondata += 2;
		bytecount = get2(tcondata);
		tcondata += 2;

		/* skip password */
		if (pw_len > len)
			pw_len = len;
		tcondata += pw_len;

		GET_STRING(path, tcondata, isunicode);
		(void) strlcpy(svc, (char *)tcondata, sizeof (svc));

		if (flags & F_SUM) {
			snprintf(xtra, xsz, " Share=%s", path);
			return;
		}

		if ((flags & F_DTAIL) == 0)
			return;

		show_printf("WordCount = %d", wordcount);
		show_printf("ChainedCommand = 0x%.2x", andxcmd);
		show_printf("NextOffset = 0x%.4x", andxoffset);
		show_printf("TconFlags = 0x%.4x", tconflags);
		show_printf("PasswordLength = 0x%.4x", pw_len);
		show_printf("ByteCount = %d", bytecount);
		show_printf("SharePath = %s", path);
		show_printf("ServiceType = %s", svc);
	} else {
		/* response */
		if (wordcount < 3)
			return;
		andxcmd = get2(tcondata);
		tcondata += 2;
		andxoffset = get2(tcondata);
		tcondata += 2;
		tconflags = get2(tcondata);
		tcondata += 2;
		bytecount = get2(tcondata);
		tcondata += 2;

		length = strlcpy(svc, (char *)tcondata, sizeof (svc));
		tcondata += (length + 1);

		if (flags & F_SUM) {
			snprintf(xtra, xsz, " Type=%s", svc);
			return;
		}
		if ((flags & F_DTAIL) == 0)
			return;

		show_printf("WordCount = %d", wordcount);
		show_printf("ChainedCommand = 0x%.2x", andxcmd);
		show_printf("NextOffset = 0x%.4x", andxoffset);
		show_printf("OptionalSupport = 0x%.4x", tconflags);
		show_printf("ByteCount = %d", bytecount);
		show_printf("ServiceType = %s", svc);
		GET_STRING(tbuf, tcondata, isunicode);
		show_printf("NativeFS = %s", tbuf);
	}
}

/*
 * Interpret a "SesssetupX" SMB
 * [X/Open-SMB, Sec. 11.3]
 */
/* ARGSUSED */
static void
interpret_sesssetupX(int flags, uchar_t *data, int len, char *xtra, int xsz)
{
	int bytecount;
	int lm_pw_len;
	int ext_security;
	int sec_blob_len;
	int isunicode;
	int nt_pw_len;
	int wordcount;
	int cap;
	char tbuf[256];
	struct smb *smbdata;
	uchar_t *setupdata;
	ushort_t smb_flags2;

	smbdata  = (struct smb *)data;
	smb_flags2 = get2(smbdata->flags2);
	setupdata = (uchar_t *)data + sizeof (struct smb);
	wordcount = *setupdata++;

	isunicode = smb_flags2 & FLAGS2_UNICODE;
	ext_security = smb_flags2 & FLAGS2_EXT_SEC;

	if ((smbdata->flags & SERVER_RESPONSE) == 0) {
		/* request summary */
		if (flags & F_SUM) {
			if (ext_security) {
				/* No decoder for SPNEGO */
				snprintf(xtra, xsz, " (SPNEGO)");
				return;
			}
			if (wordcount != 13)
				return;
			setupdata += 14;
			lm_pw_len = get2(setupdata);
			setupdata += 2;
			nt_pw_len = get2(setupdata);
			setupdata += 6;
			cap = get4(setupdata);
			setupdata += 6 + lm_pw_len + nt_pw_len;

			GET_STRING(tbuf, setupdata, isunicode);
			snprintf(xtra, xsz, " Username=%s", tbuf);
		}

		if ((flags & F_DTAIL) == 0)
			return;

		/* request detail */
		show_printf("WordCount = %d", wordcount);
		if (wordcount < 7)
			return;
		/* words 0 - 6 */
		show_printf("ChainedCommand = 0x%.2x", setupdata[0]);
		setupdata += 2;
		show_printf("NextOffset = 0x%.4x", get2(setupdata));
		setupdata += 2;
		show_printf("MaxBufferSize = %d", get2(setupdata));
		setupdata += 2;
		show_printf("MaxMPXRequests = %d", get2(setupdata));
		setupdata += 2;
		show_printf("VCNumber = %d", get2(setupdata));
		setupdata += 2;
		show_printf("SessionKey = 0x%.8x", get4(setupdata));
		setupdata += 4;

		if (ext_security) {
			if (wordcount != 12)
				return;
			/* word 7 */
			sec_blob_len = get2(setupdata);
			setupdata += 2;
			show_printf("Sec. blob len = %d", sec_blob_len);
			/* words 8, 9 (reserved) */
			setupdata += 4;
		} else {
			if (wordcount != 13)
				return;
			/* word 7 */
			lm_pw_len = get2(setupdata);
			setupdata += 2;
			show_printf("LM_Hash_Len = %d", lm_pw_len);
			/* word 8 */
			nt_pw_len = get2(setupdata);
			setupdata += 2;
			show_printf("NT_Hash_Len = %d", nt_pw_len);
			/* words 9, 10 (reserved) */
			setupdata += 4;
		}

		cap = get4(setupdata);
		show_printf("Capabilities = 0x%.8x", cap);
		setupdata += 4;

		bytecount = get2(setupdata);
		setupdata += 2;
		show_printf("ByteCount = %d", bytecount);

		if (ext_security) {
			/* No decoder for SPNEGO.  Just dump hex. */
			show_printf("Security blob: (SPNEGO)");
			output_bytes(setupdata, sec_blob_len);
			setupdata += sec_blob_len;
		} else {
			/* Dump password hashes */
			if (lm_pw_len > 0) {
				show_printf("LM Hash (%d bytes)", lm_pw_len);
				output_bytes(setupdata, lm_pw_len);
				setupdata += lm_pw_len;
			}
			if (nt_pw_len > 0) {
				show_printf("NT Hash (%d bytes)", nt_pw_len);
				output_bytes(setupdata, nt_pw_len);
				setupdata += nt_pw_len;
			}

			/* User */
			GET_STRING(tbuf, setupdata, isunicode);
			show_printf("AccountName = %s", tbuf);

			/* Domain */
			GET_STRING(tbuf, setupdata, isunicode);
			show_printf("DomainName = %s", tbuf);
		}

		/*
		 * Remainder is the same for etc. sec. or not
		 * Native OS, Native LanMan
		 */
		GET_STRING(tbuf, setupdata, isunicode);
		show_printf("NativeOS = %s", tbuf);

		GET_STRING(tbuf, setupdata, isunicode);
		show_printf("NativeLanman = %s", tbuf);
	} else {
		/* response summary */
		if (flags & F_SUM) {
			if (ext_security) {
				/* No decoder for SPNEGO */
				snprintf(xtra, xsz, " (SPNEGO)");
			}
			return;
		}

		if ((flags & F_DTAIL) == 0)
			return;

		/* response detail */
		show_printf("WordCount = %d", wordcount);
		if (wordcount < 3)
			return;

		show_printf("ChainedCommand = 0x%.2x", setupdata[0]);
		setupdata += 2;
		show_printf("NextOffset = 0x%.4x", get2(setupdata));
		setupdata += 2;
		show_printf("SetupAction = 0x%.4x", get2(setupdata));
		setupdata += 2;

		if (ext_security) {
			if (wordcount != 4)
				return;
			sec_blob_len = get2(setupdata);
			setupdata += 2;
			show_printf("Sec. blob len = %d", sec_blob_len);
		} else {
			if (wordcount != 3)
				return;
		}

		bytecount = get2(setupdata);
		setupdata += 2;
		show_printf("ByteCount = %d", bytecount);

		if (ext_security) {
			/* No decoder for SPNEGO.  Just dump hex. */
			show_line("Security blob: (SPNEGO)");
			output_bytes(setupdata, sec_blob_len);
			setupdata += sec_blob_len;
		}

		/*
		 * Native OS, Native LanMan
		 */
		GET_STRING(tbuf, setupdata, isunicode);
		show_printf("NativeOS = %s", tbuf);

		GET_STRING(tbuf, setupdata, isunicode);
		show_printf("NativeLanman = %s", tbuf);

		if (ext_security == 0) {
			GET_STRING(tbuf, setupdata, isunicode);
			show_printf("DomainName = %s", tbuf);
		}
	}
}

/*
 * Interpret "Trans2" SMB
 * [X/Open-SMB, Sec. 16]
 *
 * This is very much like "trans" above.
 */
/* ARGSUSED */
static void
interpret_trans2(int flags, uchar_t *data, int len, char *xtra, int xsz)
{
	struct smb *smb;
	uchar_t *vwv; /* word parameters */
	int wordcount;
	uchar_t *byteparms;
	int bytecount;
	int parambytes;
	int paramoffset;
	int setupcount;
	int subcode;
	uchar_t *setupdata;
	uchar_t *params;
	char *name;

	smb  = (struct smb *)data;
	vwv = (uchar_t *)data + sizeof (struct smb);
	wordcount = *vwv++;

	byteparms = vwv + (2 * wordcount);
	bytecount = get2(byteparms);
	byteparms += 2;

	/*
	 * Print the lengths before we (potentially) bail out
	 * due to lack of data (so the user knows why we did).
	 */
	if (flags & F_DTAIL) {
		show_printf("WordCount = %d", wordcount);
		show_printf("ByteCount = %d", bytecount);
	}

	/* Get length and location of params and setup data. */
	if (!(smb->flags & SERVER_RESPONSE)) {
		/* CALL */
		if (wordcount < 14)
			return;
		parambytes  = get2(vwv + (2 *  9));
		paramoffset = get2(vwv + (2 * 10));
		setupcount = *(vwv + (2 * 13));
		setupdata  =   vwv + (2 * 14);
	} else {
		/* REPLY */
		if (wordcount < 10)
			return;
		parambytes  = get2(vwv + (2 * 3));
		paramoffset = get2(vwv + (2 * 4));
		setupcount = *(vwv + (2 *  9));
		setupdata  =   vwv + (2 * 10);
	}
	if (setupcount > 0)
		subcode = get2(setupdata);
	else
		subcode = -1; /* invalid */

	/* The parameters are offset from the SMB header. */
	params = data + paramoffset;

	if (flags & F_DTAIL && !(smb->flags & SERVER_RESPONSE)) {
		/* This is a CALL. */
		/* print the word parameters */
		show_printf("TotalParamBytes = %d", get2(vwv));
		show_printf("TotalDataBytes = %d", get2(vwv+2));
		show_printf("MaxParamBytes = %d", get2(vwv+4));
		show_printf("MaxDataBytes = %d", get2(vwv+6));
		show_printf("MaxSetupWords = %d", vwv[8]);
		show_printf("TransFlags = 0x%.4x", get2(vwv+10));
		show_printf("Timeout = 0x%.8x", get4(vwv+12));
		/* skip Reserved2 */
		show_printf("ParamBytes = 0x%.4x", parambytes);
		show_printf("ParamOffset = 0x%.4x", paramoffset);
		show_printf("DataBytes = 0x%.4x", get2(vwv+22));
		show_printf("DataOffset = 0x%.4x", get2(vwv+24));
		show_printf("SetupWords = %d", setupcount);

		/* That finishes the VWV, now the misc. stuff. */
		show_printf("FunctionCode = %d", subcode);
	}

	if (!(smb->flags & SERVER_RESPONSE)) {
		/* This is a CALL.  Do sub-function. */
		switch (subcode) {
		case TRANS2_OPEN:
			name = "Open";
			goto name_only;
		case TRANS2_FIND_FIRST:
			output_trans2_findfirst(flags, params, xtra, xsz);
			break;
		case TRANS2_FIND_NEXT2:
			output_trans2_findnext(flags, params, xtra, xsz);
			break;
		case TRANS2_QUERY_FS_INFORMATION:
			name = "QueryFSInfo";
			goto name_only;
		case TRANS2_QUERY_PATH_INFORMATION:
			output_trans2_querypath(flags, params, xtra, xsz);
			break;
		case TRANS2_SET_PATH_INFORMATION:
			name = "SetPathInfo";
			goto name_only;
		case TRANS2_QUERY_FILE_INFORMATION:
			output_trans2_queryfile(flags, params, xtra, xsz);
			break;
		case TRANS2_SET_FILE_INFORMATION:
			output_trans2_setfile(flags, params, xtra, xsz);
			break;
		case TRANS2_CREATE_DIRECTORY:
			name = "CreateDir";
			goto name_only;

		default:
			name = "Unknown";
			/* fall through */
		name_only:
			if (flags & F_SUM)
				snprintf(xtra, xsz, " %s", name);
			if (flags & F_DTAIL)
				show_printf("FunctionName = %s", name);
			break;
		}
	}

	if (flags & F_DTAIL && smb->flags & SERVER_RESPONSE) {
		/* This is a REPLY. */
		/* print the word parameters */
		show_printf("TotalParamBytes = %d", get2(vwv));
		show_printf("TotalDataBytes = %d",  get2(vwv+2));
		/* skip Reserved */
		show_printf("ParamBytes = 0x%.4x", parambytes);
		show_printf("ParamOffset = 0x%.4x", paramoffset);
		show_printf("ParamDispl. = 0x%.4x", get2(vwv+10));
		show_printf("DataBytes = 0x%.4x", get2(vwv+12));
		show_printf("DataOffset = 0x%.4x", get2(vwv+14));
		show_printf("DataDispl. = 0x%.4x", get2(vwv+16));
		show_printf("SetupWords = %d", setupcount);

		output_bytes(byteparms, bytecount);
	}
}


static void
interpret_default(int flags, uchar_t *data, int len, char *xtra, int xsz)
{
	int slength;
	int i, tl;
	int isunicode;
	int printit;
	int wordcount;
	int outsz;
	char *outstr;
	char *format;
	char valuetype;
	char word[10];
	char *label;
	char tempstr[256];
	uchar_t *comdata, *limit;
	char buff[80];
	struct smb *smbdata;
	struct decode *decoder;
	uchar_t bval;
	ushort_t wval;
	ushort_t smb_flags2;
	uint_t lval;

	smbdata  = (struct smb *)data;
	smb_flags2 = get2(smbdata->flags2);
	comdata = (uchar_t *)data + sizeof (struct smb);
	wordcount = *comdata++;
	limit = data + len;

	isunicode = smb_flags2 & FLAGS2_UNICODE;
	decoder = &SMBtable[smbdata->com & 255];

	if (smbdata->flags & SERVER_RESPONSE)
		format = decoder->replyfmt;
	else
		format = decoder->callfmt;

	if (!format || strlen(format) == 0) {
		if (flags & F_SUM)
			return;
		show_printf("WordCount = %d", wordcount);
		if (wordcount == 0)
			return;
		show_line("Word values (in hex):");
		buff[0] = '\0';
		for (i = 0; i < wordcount; i++) {
			snprintf(word, sizeof (word), "%.4x ", get2(comdata));
			comdata += 2;
			if (comdata >= limit)
				wordcount = i+1; /* terminate */
			(void) strlcat(buff, word, sizeof (buff));
			if (((i+1) & 7) == 0 || i == (wordcount-1)) {
				show_line(buff);
				strcpy(buff, "");
			}
		}
		return;
	}

	if (flags & F_DTAIL)
		show_printf("WordCount = %d", wordcount);

	outstr = xtra;
	outsz = xsz;

	valuetype = format[0];
	while (valuetype != '\0') {
		if (comdata >= limit)
			break;
		label = format+1;
		printit = (flags & F_DTAIL) || (valuetype <= 'Z');

		switch (valuetype) {
		case 'W':
		case 'w':
			wval = get2(comdata);
			comdata += 2;
			if (!printit)
				break;
			if (flags & F_DTAIL)
				show_printf(
				    "%s = 0x%.4x", label, wval);
			else {
				tl = snprintf(outstr, outsz,
				    " %s=0x%x", label, wval);
				outstr += tl;
				outsz -= tl;
			}
			break;

		case 'D':
		case 'd':
			wval = get2(comdata);
			comdata += 2;
			if (!printit)
				break;
			if (flags & F_DTAIL)
				show_printf(
				    "%s = %d", label, wval);
			else {
				tl = snprintf(outstr, outsz,
				    " %s=%d", label, wval);
				outstr += tl;
				outsz -= tl;
			}
			break;

		case 'L':
		case 'l':
			lval = get4(comdata);
			comdata += 4;
			if (!printit)
				break;
			if (flags & F_DTAIL)
				show_printf(
				    "%s = 0x%.8x", label, lval);
			else {
				tl = snprintf(outstr, outsz,
				    " %s=0x%x", label, lval);
				outstr += tl;
				outsz -= tl;
			}
			break;

		case 'B':
		case 'b':
			bval = comdata[0];
			comdata += 1;
			if (!printit)
				break;
			if (flags & F_DTAIL)
				show_printf(
				    "%s = 0x%.2x", label, bval);
			else {
				tl = snprintf(outstr, outsz,
				    " %s=0x%x", label, bval);
				outstr += tl;
				outsz -= tl;
			}
			break;

		case 'r':
			comdata++;
			break;

		case 'R':
			comdata += 2;
			break;

		case 'U':
		case 'u':
			/* Unicode or ASCII string. */
			GET_STRING(tempstr, comdata, isunicode);
			if (!printit)
				break;
			if (flags & F_DTAIL)
				show_printf(
				    "%s = %s", label, tempstr);
			else {
				tl = snprintf(outstr, outsz,
				    " %s=%s", label, tempstr);
				outstr += tl;
				outsz -= tl;
			}
			break;

		case 'S':
		case 's':
			slength = strlcpy(tempstr, (char *)comdata,
			    sizeof (tempstr));
			comdata += (slength+1);
			if (!printit)
				break;
			if (flags & F_DTAIL)
				show_printf(
				    "%s = %s", label, tempstr);
			else {
				tl = snprintf(outstr, outsz,
				    " %s=%s", label, tempstr);
				outstr += tl;
				outsz -= tl;
			}
			break;
		}
		format += (strlen(format) + 1);
		valuetype = format[0];
	}
}
