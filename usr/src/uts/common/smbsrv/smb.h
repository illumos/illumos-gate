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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_SMB_H
#define	_SMBSRV_SMB_H

/*
 * SMB definitions and interfaces, mostly defined in the CIFS spec.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SMB definitions and interfaces, mostly defined in the CIFS spec.
 */

#ifdef _KERNEL
#include <sys/types.h>
#endif
#include <smbsrv/smb_i18n.h>
#include <smbsrv/msgbuf.h>


#ifdef __cplusplus
extern "C" {
#endif


/*
 * Typedefs from CIFS section 3.2
 */
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef uint32_t ULONG;
typedef int32_t LONG;


/*
 * The msgbuf format and length of an SMB header.
 */
#define	SMB_HEADER_DOS_FMT	"Mbbbwbww10.wwww"
#define	SMB_HEADER_NT_FMT	"Mblbww#c2.wwww"
#define	SMB_HEADER_LEN		32
#define	SMB_SIG_SIZE		8	/* SMB signature size */

/*
 * CIFS definition for the SMB header (CIFS Section 3.2). Note that the
 * pid_high field is not documented in the 1997 CIFS specificaction. This
 * is a decoded or memory-based definition, which may be padded to align
 * its elements on word boundaries. See smb_hdrbuf_t for the network
 * ready structure.
 */
typedef struct smb_hdr {
	UCHAR protocol[4];
	UCHAR command;

	union {
		struct {
			UCHAR error_class;
			UCHAR reserved;
			USHORT error;
		} dos_error;
		ULONG ntstatus;
	}status;

	UCHAR flags;
	USHORT flags2;
	USHORT pid_high;

	union {
		USHORT pad[5];
		struct {
			USHORT reserved;
			UCHAR security_sig[SMB_SIG_SIZE];
		} extra;
	} extra;

	USHORT tid;
	USHORT pid;
	USHORT uid;
	USHORT mid;
} smb_hdr_t;


/*
 * Encoded or packed SMB header in network ready format.
 */
typedef struct smb_hdrbuf {
	unsigned char hdr[SMB_HEADER_LEN];
} smb_hdrbuf_t;

typedef struct smb_nethdr {
	uint8_t sh_protocol[4];
	uint8_t sh_command;

	union {
		struct {
			uint8_t sh_error_class;
			uint8_t sh_reserved;
			uint8_t sh_error[2];
		} dos_error;
		uint8_t sh_ntstatus[4];
	} status;

	uint8_t sh_flags;
	uint8_t sh_flags2[2];
	uint8_t sh_pid_high[2];

	union {
		uint8_t sh_pad[10];
		struct {
			uint8_t sh_reserved[2];
			uint8_t sh_security_sig[SMB_SIG_SIZE];
		} extra;
	} extra;

	uint8_t sh_tid[2];
	uint8_t sh_pid[2];
	uint8_t sh_uid[2];
	uint8_t sh_mid[2];
} smb_nethdr_t;

/*
 * Protocol magic value as a 32-bit.  This will be 0xff 0x53 0x4d 0x42 on
 * the wire.
 */

#define	SMB_PROTOCOL_MAGIC	0x424d53ff

/*
 * Time and date encoding (CIFS Section 3.6). The date is encoded such
 * that the year has a range of 0-119, which represents 1980-2099. The
 * month range is 1-12, and the day range is 1-31.
 */
typedef struct smb_date {
	USHORT day   : 5;
	USHORT month : 4;
	USHORT year  : 7;
} smb_date_t;


/*
 * The hours range is 0-23, the minutes range is 0-59 and the two_sec
 * range is 0-29.
 */
typedef struct smb_time {
	USHORT two_sec : 5;
	USHORT minutes : 6;
	USHORT hours    : 5;
} smb_time_t;


/*
 * This is a 64-bit signed absolute time representing 100ns increments.
 * A positive value represents the absolute time since 1601AD. A
 * negative value represents a context specific relative time.
 */
typedef struct smb_time2 {
	ULONG low_time;
	LONG high_time;
} smb_time2_t;


/*
 * The number of seconds since Jan 1, 1970, 00:00:00.0.
 */
typedef uint32_t smb_utime_t;


#define	SMB_LM_NEGOTIATE_WORDCNT		13
#define	SMB_NT_NEGOTIATE_WORDCNT		17


typedef struct smb_nt_negotiate_rsp {
	UCHAR word_count;
	USHORT dialect_index;
	UCHAR security_mode;
	USHORT max_mpx;
	USHORT max_vc;
	ULONG max_buffer_size;
	ULONG max_raw_size;
	ULONG session_key;
	ULONG capabilities;
	ULONG time_low;
	ULONG time_high;
	USHORT server_tz;
	UCHAR security_len;
	USHORT byte_count;
	UCHAR *guid;
	UCHAR *challenge;
	UCHAR *oem_domain;
} smb_nt_negotiate_rsp_t;

/*
 * SMB_COM_TRANSACTION
 */
typedef struct smb_transact_rsp {
	UCHAR  WordCount;		/* Count of data bytes */
					/* value = 10 + SetupCount */
	USHORT TotalParamCount;		/* Total parameter bytes being sent */
	USHORT TotalDataCount;		/* Total data bytes being sent */
	USHORT Reserved;
	USHORT ParamCount;		/* Parameter bytes sent this buffer */
	USHORT ParamOffset;		/* Offset (from hdr start) to params */
	USHORT ParamDisplacement;	/* Displacement of these param bytes */
	USHORT DataCount;		/* Data bytes sent this buffer */
	USHORT DataOffset;		/* Offset (from hdr start) to data */
	USHORT DataDisplacement;	/* Displacement of these data bytes */
	UCHAR  SetupCount;		/* Count of setup words */
	USHORT BCC;
#if 0
	UCHAR Reserved2;		/* Reserved (pad above to word) */
	UCHAR Buffer[1];		/* Buffer containing: */
	USHORT Setup[];			/*  Setup words (# = SetupWordCount) */
	USHORT ByteCount;		/*  Count of data bytes */
	UCHAR Pad[];			/*  Pad to SHORT or LONG */
	UCHAR Params[];			/*  Param. bytes (# = ParamCount) */
	UCHAR Pad1[];			/*  Pad to SHORT or LONG */
	UCHAR Data[];			/*  Data bytes (# = DataCount) */
#endif
} smb_transact_rsp_t;

/*
 * SMBreadX
 */
typedef struct smb_read_andx_rsp {
	UCHAR WordCount;
	UCHAR AndXCmd;
	UCHAR AndXReserved;
	USHORT AndXOffset;
	USHORT Remaining;
	USHORT DataCompactionMode;
	USHORT Reserved;
	USHORT DataLength;
	USHORT DataOffset;
	ULONG  DataLengthHigh;
	USHORT Reserved2[3];
	USHORT ByteCount;
#if 0
	UCHAR Pad[];
	UCHAR Data[];
#endif
} smb_read_andx_rsp_t;

#ifdef __cplusplus
}
#endif


#endif /* _SMBSRV_SMB_H */
