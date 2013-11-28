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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SMB requests.
 *
 * Request
 *   Header
 *	Magic		0xFF 'S' 'M' 'B'
 *	smb_com 	a byte, the "first" command
 *	Error		a 4-byte union, ignored in a request
 *	smb_flg		a one byte set of eight flags
 *	smb_flg2	a two byte set of 16 flags
 *	.		twelve reserved bytes, have a role
 *			in connectionless transports (IPX, UDP?)
 *	smb_tid		a 16-bit tree ID, a mount point sorta,
 *			0xFFFF is this command does not have
 *			or require a tree context
 *	smb_pid		a 16-bit process ID
 *	smb_uid		a 16-bit user ID, specific to this "session"
 *			and mapped to a system (bona-fide) UID
 *	smb_mid		a 16-bit multiplex ID, used to differentiate
 *			multiple simultaneous requests from the same
 *			process (pid) (ref RPC "xid")
 *
 *   Chained (AndX) commands (0 or more)
 *	smb_wct		a byte, number of 16-bit words containing
 *			command parameters, min 2 for chained command
 *	andx_com	a byte, the "next" command, 0xFF for none
 *	.		an unused byte
 *	andx_off	a 16-bit offset, byte displacement from &Magic
 *			to the smb_wct field of the "next" command,
 *			ignore if andx_com is 0xFF, s/b 0 if no next
 *	smb_vwv[]	0 or more 16-bit (sorta) parameters for
 *			"this" command (i.e. smb_com if this is the
 *			first parameters, or the andx_com of the just
 *			previous block.
 *	smb_bcc		a 16-bit count of smb_data[] bytes
 *	smb_data[]	0 or more bytes, format specific to commands
 *	padding[]	Optional padding
 *
 *   Last command
 *	smb_wct		a byte, number of 16-bit words containing
 *			command parameters, min 0 for chained command
 *	smb_vwv[]	0 or more 16-bit (sorta) parameters for
 *			"this" command (i.e. smb_com if this is the
 *			first parameters, or the andx_com of the just
 *			previous block.
 *	smb_bcc		a 16-bit count of smb_data[] bytes
 *	smb_data[]	0 or more bytes, format specific to commands
 *
 * Reply
 *   Header
 *	Magic		0xFF 'S' 'M' 'B'
 *	smb_com 	a byte, the "first" command, corresponds
 *			to request
 *	Error		a 4-byte union, coding depends on dialect in use
 *			for "DOS" errors
 *				a byte for error class
 *				an unused byte
 *				a 16-bit word for error code
 *			for "NT" errors
 *				a 32-bit error code which
 *				is a packed class and specifier
 *			for "OS/2" errors
 *				I don't know
 *			The error information is specific to the
 *			last command in the reply chain.
 *	smb_flg		a one byte set of eight flags, 0x80 bit set
 *			indicating this message is a reply
 *	smb_flg2	a two byte set of 16 flags
 *	.		twelve reserved bytes, have a role
 *			in connectionless transports (IPX, UDP?)
 *	smb_tid		a 16-bit tree ID, a mount point sorta,
 *			should be the same as the request
 *	smb_pid		a 16-bit process ID, MUST BE the same as request
 *	smb_uid		a 16-bit user ID, specific to this "session"
 *			and mapped to a system (bona-fide) UID,
 *			should be the same as request
 *	smb_mid		a 16-bit multiplex ID, used to differentiate
 *			multiple simultaneous requests from the same
 *			process (pid) (ref RPC "xid"), MUST BE the
 *			same as request
 *	padding[]	Optional padding
 *
 *   Chained (AndX) commands (0 or more)
 *	smb_wct		a byte, number of 16-bit words containing
 *			command parameters, min 2 for chained command,
 *	andx_com	a byte, the "next" command, 0xFF for none,
 *			corresponds to request, if this is the chained
 *			command that had an error set to 0xFF
 *	.		an unused byte
 *	andx_off	a 16-bit offset, byte displacement from &Magic
 *			to the smb_wct field of the "next" command,
 *			ignore if andx_com is 0xFF, s/b 0 if no next
 *	smb_vwv[]	0 or more 16-bit (sorta) parameters for
 *			"this" command (i.e. smb_com if this is the
 *			first parameters, or the andx_com of the just
 *			previous block. Empty if an error.
 *	smb_bcc		a 16-bit count of smb_data[] bytes
 *	smb_data[]	0 or more bytes, format specific to commands
 *			empty if an error.
 *
 *   Last command
 *	smb_wct		a byte, number of 16-bit words containing
 *			command parameters, min 0 for chained command
 *	smb_vwv[]	0 or more 16-bit (sorta) parameters for
 *			"this" command (i.e. smb_com if this is the
 *			first parameters, or the andx_com of the just
 *			previous block, empty if an error.
 *	smb_bcc		a 16-bit count of smb_data[] bytes
 *	smb_data[]	0 or more bytes, format specific to commands,
 *			empty if an error.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kstat.h>
#include <sys/sdt.h>
#include <sys/spl.h>

static int is_andx_com(unsigned char);
static int smbsr_check_result(struct smb_request *, int, int);

static const smb_disp_entry_t const
smb_disp_table[SMB_COM_NUM] = {
	{ "SmbCreateDirectory", SMB_SDT_OPS(create_directory),  /* 0x00 000 */
	    0x00, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbDeleteDirectory", SMB_SDT_OPS(delete_directory),	/* 0x01 001 */
	    0x01, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbOpen", SMB_SDT_OPS(open),				/* 0x02 002 */
	    0x02, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbCreate", SMB_SDT_OPS(create),			/* 0x03 003 */
	    0x03, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbClose", SMB_SDT_OPS(close),			/* 0x04 004 */
	    0x04, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbFlush", SMB_SDT_OPS(flush),			/* 0x05 005 */
	    0x05, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbDelete", SMB_SDT_OPS(delete),			/* 0x06 006 */
	    0x06, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbRename", SMB_SDT_OPS(rename),			/* 0x07 007 */
	    0x07, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbQueryInformation", SMB_SDT_OPS(query_information), /* 0x08 008 */
	    0x08, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbSetInformation", SMB_SDT_OPS(set_information),	/* 0x09 009 */
	    0x09, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbRead", SMB_SDT_OPS(read),				/* 0x0A 010 */
	    0x0A, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbWrite", SMB_SDT_OPS(write),			/* 0x0B 011 */
	    0x0B, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbLockByteRange", SMB_SDT_OPS(lock_byte_range),	/* 0x0C 012 */
	    0x0C, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbUnlockByteRange", SMB_SDT_OPS(unlock_byte_range),	/* 0x0D 013 */
	    0x0D, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbCreateTemporary", SMB_SDT_OPS(create_temporary),	/* 0x0E 014 */
	    0x0E, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbCreateNew", SMB_SDT_OPS(create_new),		/* 0x0F 015 */
	    0x0F, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbCheckDirectory", SMB_SDT_OPS(check_directory),	/* 0x10 016 */
	    0x10, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbProcessExit", SMB_SDT_OPS(process_exit),		/* 0x11 017 */
	    0x11, PC_NETWORK_PROGRAM_1_0,
	    SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID },
	{ "SmbSeek", SMB_SDT_OPS(seek),				/* 0x12 018 */
	    0x12, PC_NETWORK_PROGRAM_1_0 },
	{ "SmbLockAndRead", SMB_SDT_OPS(lock_and_read),		/* 0x13 019 */
	    0x13, LANMAN1_0 },
	{ "SmbWriteAndUnlock", SMB_SDT_OPS(write_and_unlock),	/* 0x14 020 */
	    0x14, LANMAN1_0 },
	{ "Invalid", SMB_SDT_OPS(invalid), 0x15, 0 },		/* 0x15	021 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x16, 0 },		/* 0x16 022 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x17, 0 },		/* 0x17 023 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x18, 0 },		/* 0x18 024 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x19, 0 },		/* 0x19 025 */
	{ "SmbReadRaw", SMB_SDT_OPS(invalid), 0x1A, 0 },	/* 0x1A 026 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x1B, 0 },		/* 0x1B 027 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x1C, 0 },		/* 0x1C 028 */
	{ "SmbWriteRaw", SMB_SDT_OPS(invalid), 0x1D, 0 },	/* 0x1D 029 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x1E, 0 },		/* 0x1E 030 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x1F, 0 },		/* 0x1F 031 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x20, 0 },		/* 0x20 032 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x21, 0 },		/* 0x21 033 */
	{ "SmbSetInformation2", SMB_SDT_OPS(set_information2),	/* 0x22 034 */
	    0x22, LANMAN1_0 },
	{ "SmbQueryInformation2",
	    SMB_SDT_OPS(query_information2),			/* 0x23 035 */
	    0x23, LANMAN1_0 },
	{ "SmbLockingX", SMB_SDT_OPS(locking_andx),		/* 0x24 036 */
	    0x24, LANMAN1_0 },
	{ "SmbTransaction", SMB_SDT_OPS(transaction),		/* 0x25 037 */
	    0x25, LANMAN1_0 },
	{ "SmbTransactionSecondary",
	    SMB_SDT_OPS(transaction_secondary),			/* 0x26 038 */
	    0x26, LANMAN1_0 },
	{ "SmbIoctl", SMB_SDT_OPS(ioctl),			/* 0x27 039 */
	    0x27, LANMAN1_0 },
	{ "Invalid", SMB_SDT_OPS(invalid), 0x28, 0 },	/* 0x28 040 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x29, 0 },	/* 0x29 041 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x2A, 0 },	/* 0x2A 042 */
	{ "SmbEcho", SMB_SDT_OPS(echo),				/* 0x2B 043 */
	    0x2B, LANMAN1_0, SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID },
	{ "SmbWriteAndClose", SMB_SDT_OPS(write_and_close),	/* 0x2C 044 */
	    0x2C, LANMAN1_0 },
	{ "SmbOpenX", SMB_SDT_OPS(open_andx),			/* 0x2D 045 */
	    0x2D, LANMAN1_0 },
	{ "SmbReadX", SMB_SDT_OPS(read_andx),			/* 0x2E 046 */
	    0x2E, LANMAN1_0 },
	{ "SmbWriteX", SMB_SDT_OPS(write_andx),			/* 0x2F 047 */
	    0x2F, LANMAN1_0 },
	{ "Invalid", SMB_SDT_OPS(invalid), 0x30, 0 },	/* 0x30 048 */
	{ "SmbCloseAndTreeDisconnect",
	    SMB_SDT_OPS(close_and_tree_disconnect),		/* 0x31 049 */
	    0x31, LANMAN1_0 },
	{ "SmbTransaction2", SMB_SDT_OPS(transaction2),		/* 0x32 050 */
	    0x32, LM1_2X002 },
	{ "SmbTransaction2Secondary",
	    SMB_SDT_OPS(transaction2_secondary),		/* 0x33 051 */
	    0x33, LM1_2X002 },
	{ "SmbFindClose2", SMB_SDT_OPS(find_close2),		/* 0x34 052 */
	    0x34, LM1_2X002 },
	{ "Invalid", SMB_SDT_OPS(invalid), 0x35, 0 },	/* 0x35 053 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x36, 0 },	/* 0x36 054 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x37, 0 },	/* 0x37 055 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x38, 0 },	/* 0x38 056 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x39, 0 },	/* 0x39 057 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x3A, 0 },	/* 0x3A 058 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x3B, 0 },	/* 0x3B 059 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x3C, 0 },	/* 0x3C 060 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x3D, 0 },	/* 0x3D 061 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x3E, 0 },	/* 0x3E 062 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x3F, 0 },	/* 0x3F 063 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x40, 0 },	/* 0x40 064 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x47, 0 },	/* 0x47 065 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x48, 0 },	/* 0x48 066 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x49, 0 },	/* 0x49 067 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x44, 0 },	/* 0x44 068 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x45, 0 },	/* 0x45 069 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x46, 0 },	/* 0x46 070 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x47, 0 },	/* 0x47 071 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x48, 0 },	/* 0x48 072 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x49, 0 },	/* 0x49 073 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x4A, 0 },	/* 0x4A 074 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x4B, 0 },	/* 0x4B 075 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x4C, 0 },	/* 0x4C 076 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x4D, 0 },	/* 0x4D 077 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x4E, 0 },	/* 0x4E 078 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x4F, 0 },	/* 0x4F 079 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x50, 0 },	/* 0x50 080 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x51, 0 },	/* 0x51 081 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x52, 0 },	/* 0x52 082 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x53, 0 },	/* 0x53 083 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x54, 0 },	/* 0x54 084 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x55, 0 },	/* 0x55 085 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x56, 0 },	/* 0x56 086 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x57, 0 },	/* 0x57 087 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x58, 0 },	/* 0x58 088 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x59, 0 },	/* 0x59 089 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x5A, 0 },	/* 0x5A 090 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x5B, 0 },	/* 0x5B 091 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x5C, 0 },	/* 0x5C 092 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x5D, 0 },	/* 0x5D 093 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x5E, 0 },	/* 0x5E 094 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x5F, 0 },	/* 0x5F 095 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x60, 0 },	/* 0x60 096 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x61, 0 },	/* 0x61 097 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x62, 0 },	/* 0x62 098 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x63, 0 },	/* 0x63 099 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x64, 0 },	/* 0x64 100 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x65, 0 },	/* 0x65 101 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x66, 0 },	/* 0x66 102 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x67, 0 },	/* 0x67 103 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x68, 0 },	/* 0x68 104 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x69, 0 },	/* 0x69 105 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x6A, 0 },	/* 0x6A 106 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x6B, 0 },	/* 0x6B 107 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x6C, 0 },	/* 0x6C 108 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x6D, 0 },	/* 0x6D 109 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x6E, 0 },	/* 0x6E 110 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x6F, 0 },	/* 0x6F 111 */
	{ "SmbTreeConnect", SMB_SDT_OPS(tree_connect),		/* 0x70 112 */
	    0x70, PC_NETWORK_PROGRAM_1_0, SDDF_SUPPRESS_TID },
	{ "SmbTreeDisconnect", SMB_SDT_OPS(tree_disconnect),	/* 0x71 113 */
	    0x71, PC_NETWORK_PROGRAM_1_0,
	    SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID },
	{ "SmbNegotiate", SMB_SDT_OPS(negotiate),		/* 0x72 114 */
	    0x72, PC_NETWORK_PROGRAM_1_0,
	    SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID },
	{ "SmbSessionSetupX", SMB_SDT_OPS(session_setup_andx),	/* 0x73 115 */
	    0x73, LANMAN1_0, SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID },
	{ "SmbLogoffX", SMB_SDT_OPS(logoff_andx),		/* 0x74 116 */
	    0x74, LM1_2X002, SDDF_SUPPRESS_TID },
	{ "SmbTreeConnectX", SMB_SDT_OPS(tree_connect_andx),	/* 0x75 117 */
	    0x75, LANMAN1_0, SDDF_SUPPRESS_TID },
	{ "Invalid", SMB_SDT_OPS(invalid), 0x76, 0, 0 },	/* 0x76 118 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x77, 0, 0 },	/* 0x77 119 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x78, 0, 0 },	/* 0x78 120 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x79, 0, 0 },	/* 0x79 121 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x7A, 0, 0 },	/* 0x7A 122 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x7B, 0, 0 },	/* 0x7B 123 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x7C, 0, 0 },	/* 0x7C 124 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x7D, 0, 0 },	/* 0x7D 125 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x7E, 0, 0 },	/* 0x7E 126 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x7F, 0, 0 },	/* 0x7F 127 */
	{ "SmbQueryInformationDisk",
	    SMB_SDT_OPS(query_information_disk),		/* 0x80 128 */
	    0x80, PC_NETWORK_PROGRAM_1_0, 0 },
	{ "SmbSearch", SMB_SDT_OPS(search),			/* 0x81 129 */
	    0x81, PC_NETWORK_PROGRAM_1_0, 0 },
	{ "SmbFind", SMB_SDT_OPS(find),				/* 0x82 130 */
	    0x82, LANMAN1_0, 0 },
	{ "SmbFindUnique", SMB_SDT_OPS(find_unique),		/* 0x83 131 */
	    0x83, LANMAN1_0, 0 },
	{ "SmbFindClose", SMB_SDT_OPS(find_close),		/* 0x84 132 */
	    0x84, LANMAN1_0, 0 },
	{ "Invalid", SMB_SDT_OPS(invalid), 0x85, 0, 0 },	/* 0x85 133 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x86, 0, 0 },	/* 0x86 134 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x87, 0, 0 },	/* 0x87 135 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x88, 0, 0 },	/* 0x88 136 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x89, 0, 0 },	/* 0x89 137 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x8A, 0, 0 },	/* 0x8A 138 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x8B, 0, 0 },	/* 0x8B 139 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x8C, 0, 0 },	/* 0x8C 140 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x8D, 0, 0 },	/* 0x8D 141 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x8E, 0, 0 },	/* 0x8E 142 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x8F, 0, 0 },	/* 0x8F 143 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x90, 0, 0 },	/* 0x90 144 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x91, 0, 0 },	/* 0x91 145 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x92, 0, 0 },	/* 0x92 146 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x93, 0, 0 },	/* 0x93 147 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x94, 0, 0 },	/* 0x94 148 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x95, 0, 0 },	/* 0x95 149 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x96, 0, 0 },	/* 0x96 150 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x97, 0, 0 },	/* 0x97 151 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x98, 0, 0 },	/* 0x98 152 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x99, 0, 0 },	/* 0x99 153 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x9A, 0, 0 },	/* 0x9A 154 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x9B, 0, 0 },	/* 0x9B 155 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x9C, 0, 0 },	/* 0x9C 156 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x9D, 0, 0 },	/* 0x9D 157 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x9E, 0, 0 },	/* 0x9E 158 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0x9F, 0, 0 },	/* 0x9F 159 */
	{ "SmbNtTransact", SMB_SDT_OPS(nt_transact),	/* 0xA0 160 */
	    0xA0, NT_LM_0_12, 0 },
	{ "SmbNtTransactSecondary",
	    SMB_SDT_OPS(nt_transact_secondary),			/* 0xA1 161 */
	    0xA1, NT_LM_0_12, 0 },
	{ "SmbNtCreateX", SMB_SDT_OPS(nt_create_andx),		/* 0xA2 162 */
	    0xA2, NT_LM_0_12, 0 },
	{ "Invalid", SMB_SDT_OPS(invalid), 0xA3, 0, 0 },	/* 0xA3 163 */
	{ "SmbNtCancel", SMB_SDT_OPS(nt_cancel),		/* 0xA4 164 */
	    0xA4, NT_LM_0_12, 0 },
	{ "SmbNtRename", SMB_SDT_OPS(nt_rename),		/* 0xA5 165 */
	    0xA5, NT_LM_0_12, 0 },
	{ "Invalid", SMB_SDT_OPS(invalid), 0xA6, 0, 0 },	/* 0xA6 166 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xA7, 0, 0 },	/* 0xA7 167 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xA8, 0, 0 },	/* 0xA8 168 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xA9, 0, 0 },	/* 0xA9 169 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xAA, 0, 0 },	/* 0xAA 170 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xAB, 0, 0 },	/* 0xAB 171 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xAC, 0, 0 },	/* 0xAC 172 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xAD, 0, 0 },	/* 0xAD 173 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xAE, 0, 0 },	/* 0xAE 174 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xAF, 0, 0 },	/* 0xAF 175 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB0, 0, 0 },	/* 0xB0 176 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB1, 0, 0 },	/* 0xB1 177 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB2, 0, 0 },	/* 0xB2 178 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB3, 0, 0 },	/* 0xB3 179 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB4, 0, 0 },	/* 0xB4 180 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB5, 0, 0 },	/* 0xB5 181 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB6, 0, 0 },	/* 0xB6 182 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB7, 0, 0 },	/* 0xB7 183 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB8, 0, 0 },	/* 0xB8 184 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xB9, 0, 0 },	/* 0xB9 185 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xBA, 0, 0 },	/* 0xBA 186 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xBB, 0, 0 },	/* 0xBB 187 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xBC, 0, 0 },	/* 0xBC 188 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xBD, 0, 0 },	/* 0xBD 189 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xBE, 0, 0 },	/* 0xBE 190 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xBF, 0, 0 },	/* 0xBF 191 */
	{ "SmbOpenPrintFile", SMB_SDT_OPS(open_print_file),	/* 0xC0 192 */
	    0xC0, PC_NETWORK_PROGRAM_1_0, 0 },
	{ "SmbWritePrintFile", SMB_SDT_OPS(write_print_file),	/* 0xC1 193 */
	    0xC1, PC_NETWORK_PROGRAM_1_0, 0 },
	{ "SmbClosePrintFile", SMB_SDT_OPS(close_print_file),	/* 0xC2 194 */
	    0xC2, PC_NETWORK_PROGRAM_1_0, 0 },
	{ "SmbGetPrintQueue", SMB_SDT_OPS(get_print_queue),	/* 0xC3 195 */
	    0xC3, PC_NETWORK_PROGRAM_1_0, 0 },
	{ "Invalid", SMB_SDT_OPS(invalid), 0xC4, 0, 0 },	/* 0xC4 196 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xC5, 0, 0 },	/* 0xC5 197 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xC6, 0, 0 },	/* 0xC6 198 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xC7, 0, 0 },	/* 0xC7 199 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xC8, 0, 0 },	/* 0xC8 200 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xC9, 0, 0 },	/* 0xC9 201 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xCA, 0, 0 },	/* 0xCA 202 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xCB, 0, 0 },	/* 0xCB 203 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xCC, 0, 0 },	/* 0xCC 204 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xCD, 0, 0 },	/* 0xCD 205 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xCE, 0, 0 },	/* 0xCE 206 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xCF, 0, 0 },	/* 0xCF 207 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD0, 0, 0 },	/* 0xD0 208 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD1, 0, 0 },	/* 0xD1 209 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD2, 0, 0 },	/* 0xD2 210 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD3, 0, 0 },	/* 0xD3 211 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD4, 0, 0 },	/* 0xD4 212 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD5, 0, 0 },	/* 0xD5 213 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD6, 0, 0 },	/* 0xD6 214 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD7, 0, 0 },	/* 0xD7 215 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD8, 0, 0 },	/* 0xD8 216 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xD9, 0, 0 },	/* 0xD9 217 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xDA, 0, 0 },	/* 0xDA 218 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xDB, 0, 0 },	/* 0xDB 219 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xDC, 0, 0 },	/* 0xDC 220 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xDD, 0, 0 },	/* 0xDD 221 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xDE, 0, 0 },	/* 0xDE 222 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xDF, 0, 0 },	/* 0xDF 223 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE0, 0, 0 },	/* 0xE0 224 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE1, 0, 0 },	/* 0xE1 225 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE2, 0, 0 },	/* 0xE2 226 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE3, 0, 0 },	/* 0xE3 227 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE4, 0, 0 },	/* 0xE4 228 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE5, 0, 0 },	/* 0xE5 229 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE6, 0, 0 },	/* 0xE6 230 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE7, 0, 0 },	/* 0xE7 231 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE8, 0, 0 },	/* 0xE8 232 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xE9, 0, 0 },	/* 0xE9 233 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xEA, 0, 0 },	/* 0xEA 234 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xEB, 0, 0 },	/* 0xEB 235 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xEC, 0, 0 },	/* 0xEC 236 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xED, 0, 0 },	/* 0xED 237 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xEE, 0, 0 },	/* 0xEE 238 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xEF, 0, 0 },	/* 0xEF 239 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF0, 0, 0 },	/* 0xF0 240 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF1, 0, 0 },	/* 0xF1 241 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF2, 0, 0 },	/* 0xF2 242 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF3, 0, 0 },	/* 0xF3 243 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF4, 0, 0 },	/* 0xF4 244 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF5, 0, 0 },	/* 0xF5 245 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF6, 0, 0 },	/* 0xF6 246 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF7, 0, 0 },	/* 0xF7 247 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF8, 0, 0 },	/* 0xF8 248 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xF9, 0, 0 },	/* 0xF9 249 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xFA, 0, 0 },	/* 0xFA 250 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xFB, 0, 0 },	/* 0xFB 251 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xFC, 0, 0 },	/* 0xFC 252 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xFD, 0, 0 },	/* 0xFD 253 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xFE, 0, 0 },	/* 0xFE 254 */
	{ "Invalid", SMB_SDT_OPS(invalid), 0xFF, 0, 0 }	/* 0xFF	255 */
};

/*
 * smbsr_cleanup
 *
 * If any user/tree/file is used by given request then
 * the reference count for that resource has been incremented.
 * This function decrements the reference count and close
 * the resource if it's needed.
 */

void
smbsr_cleanup(smb_request_t *sr)
{
	ASSERT((sr->sr_state != SMB_REQ_STATE_CLEANED_UP) &&
	    (sr->sr_state != SMB_REQ_STATE_COMPLETED));

	if (sr->r_xa) {
		if (sr->r_xa->xa_flags & SMB_XA_FLAG_COMPLETE)
			smb_xa_close(sr->r_xa);
		smb_xa_rele(sr->session, sr->r_xa);
		sr->r_xa = NULL;
	}

	/*
	 * Mark this request so we know that we've already cleaned it up.
	 * A request should only get cleaned up once so multiple calls to
	 * smbsr_cleanup for the same request indicate a bug.
	 */
	mutex_enter(&sr->sr_mutex);
	if (sr->sr_state != SMB_REQ_STATE_CANCELED)
		sr->sr_state = SMB_REQ_STATE_CLEANED_UP;
	mutex_exit(&sr->sr_mutex);
}
/*
 * smb_dispatch_request
 *
 * Returns:
 *
 *    B_TRUE	The caller must free the smb request passed in.
 *    B_FALSE	The caller must not access the smb request passed in. It has
 *		been kept in an internal queue and may have already been freed.
 */
boolean_t
smb_dispatch_request(struct smb_request *sr)
{
	smb_sdrc_t		sdrc;
	const smb_disp_entry_t	*sdd;
	smb_disp_stats_t	*sds;
	boolean_t		disconnect = B_FALSE;
	smb_session_t		*session;
	smb_server_t		*server;
	uint32_t		capabilities;
	uint32_t		byte_count;
	uint32_t		max_bytes;

	session = sr->session;
	server = session->s_server;
	capabilities = session->capabilities;

	ASSERT(sr->tid_tree == 0);
	ASSERT(sr->uid_user == 0);
	ASSERT(sr->fid_ofile == 0);
	sr->smb_fid = (uint16_t)-1;

	/* temporary until we identify a user */
	sr->user_cr = zone_kcred();
	sr->orig_request_hdr = sr->command.chain_offset;

	/* If this connection is shutting down just kill request */
	if (smb_mbc_decodef(&sr->command, SMB_HEADER_ED_FMT,
	    &sr->smb_com,
	    &sr->smb_rcls,
	    &sr->smb_reh,
	    &sr->smb_err,
	    &sr->smb_flg,
	    &sr->smb_flg2,
	    &sr->smb_pid_high,
	    sr->smb_sig,
	    &sr->smb_tid,
	    &sr->smb_pid,
	    &sr->smb_uid,
	    &sr->smb_mid) != 0) {
		disconnect = B_TRUE;
		goto drop_connection;
	}

	/*
	 * The reply "header" is filled in now even though it will,
	 * most likely, be rewritten under reply_ready below.  We
	 * could reserve the space but this is convenient in case
	 * the dialect dispatcher has to send a special reply (like
	 * TRANSACT).
	 *
	 * Ensure that the 32-bit error code flag is turned off.
	 * Clients seem to set it in transact requests and they may
	 * get confused if we return success or a 16-bit SMB code.
	 */
	sr->smb_rcls = 0;
	sr->smb_reh = 0;
	sr->smb_err = 0;
	sr->smb_flg2 &= ~SMB_FLAGS2_NT_STATUS;

	(void) smb_mbc_encodef(&sr->reply, SMB_HEADER_ED_FMT,
	    sr->smb_com,
	    sr->smb_rcls,
	    sr->smb_reh,
	    sr->smb_err,
	    sr->smb_flg,
	    sr->smb_flg2,
	    sr->smb_pid_high,
	    sr->smb_sig,
	    sr->smb_tid,
	    sr->smb_pid,
	    sr->smb_uid,
	    sr->smb_mid);
	sr->first_smb_com = sr->smb_com;

	/*
	 * Verify SMB signature if signing is enabled, dialect is NT LM 0.12,
	 * signing was negotiated and authentication has occurred.
	 */
	if (session->signing.flags & SMB_SIGNING_ENABLED) {
		if (smb_sign_check_request(sr) != 0) {
			smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
			    ERRDOS, ERROR_ACCESS_DENIED);
			disconnect = B_TRUE;
			goto report_error;
		}
	}

andx_more:
	sdd = &smb_disp_table[sr->smb_com];
	ASSERT(sdd->sdt_function);
	sds = &server->sv_disp_stats[sr->smb_com];

	if (smb_mbc_decodef(&sr->command, "b", &sr->smb_wct) != 0) {
		disconnect = B_TRUE;
		goto report_error;
	}

	(void) MBC_SHADOW_CHAIN(&sr->smb_vwv, &sr->command,
	    sr->command.chain_offset, sr->smb_wct * 2);

	if (smb_mbc_decodef(&sr->command, "#.w", sr->smb_wct*2, &sr->smb_bcc)) {
		disconnect = B_TRUE;
		goto report_error;
	}

	atomic_add_64(&sds->sdt_rxb,
	    (int64_t)(sr->smb_wct * 2 + sr->smb_bcc + 1));
	sr->sr_txb = sr->reply.chain_offset;

	/*
	 * Ignore smb_bcc if CAP_LARGE_READX/CAP_LARGE_WRITEX
	 * and this is SmbReadX/SmbWriteX since this enables
	 * large reads/write and bcc is only 16-bits.
	 */
	max_bytes = sr->command.max_bytes - sr->command.chain_offset;
	if (((sr->smb_com == SMB_COM_READ_ANDX) &&
	    (capabilities & CAP_LARGE_READX)) ||
	    ((sr->smb_com == SMB_COM_WRITE_ANDX) &&
	    (capabilities & CAP_LARGE_WRITEX))) {
		/* May be > BCC */
		byte_count = max_bytes;
	} else if (max_bytes < (uint32_t)sr->smb_bcc) {
		/* BCC is bogus.  Will fail later. */
		byte_count = max_bytes;
	} else {
		/* ordinary case */
		byte_count = (uint32_t)sr->smb_bcc;
	}

	(void) MBC_SHADOW_CHAIN(&sr->smb_data, &sr->command,
	    sr->command.chain_offset, byte_count);

	sr->command.chain_offset += byte_count;
	if (sr->command.chain_offset > sr->command.max_bytes) {
		disconnect = B_TRUE;
		goto report_error;
	}

	/* Store pointers for later */
	sr->cur_reply_offset = sr->reply.chain_offset;

	if (is_andx_com(sr->smb_com)) {
		/* Peek ahead and don't disturb vwv */
		if (smb_mbc_peek(&sr->smb_vwv, sr->smb_vwv.chain_offset, "b.w",
		    &sr->andx_com, &sr->andx_off) < 0) {
			disconnect = B_TRUE;
			goto report_error;
		}
	} else {
		sr->andx_com = (unsigned char)-1;
	}

	mutex_enter(&sr->sr_mutex);
	switch (sr->sr_state) {
	case SMB_REQ_STATE_SUBMITTED:
	case SMB_REQ_STATE_CLEANED_UP:
		sr->sr_state = SMB_REQ_STATE_ACTIVE;
		break;
	case SMB_REQ_STATE_CANCELED:
		break;
	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&sr->sr_mutex);

	/*
	 * Setup UID and TID information (if required). Both functions
	 * will set the sr credentials. In domain mode, the user and
	 * tree credentials should be the same. In share mode, the
	 * tree credentials (defined in the share definition) should
	 * override the user credentials.
	 */
	if (!(sdd->sdt_flags & SDDF_SUPPRESS_UID) && (sr->uid_user == NULL)) {
		sr->uid_user = smb_session_lookup_uid(session, sr->smb_uid);
		if (sr->uid_user == NULL) {
			smbsr_error(sr, 0, ERRSRV, ERRbaduid);
			smbsr_cleanup(sr);
			goto report_error;
		}

		sr->user_cr = smb_user_getcred(sr->uid_user);
	}
	if (!(sdd->sdt_flags & SDDF_SUPPRESS_TID) && (sr->tid_tree == NULL)) {
		sr->tid_tree = smb_session_lookup_tree(session, sr->smb_tid);
		if (sr->tid_tree == NULL) {
			smbsr_error(sr, 0, ERRSRV, ERRinvnid);
			smbsr_cleanup(sr);
			goto report_error;
		}
	}

	/*
	 * If the command is not a read raw request we can set the
	 * state of the session back to SMB_SESSION_STATE_NEGOTIATED
	 * (if the current state is SMB_SESSION_STATE_OPLOCK_BREAKING).
	 * Otherwise we let the read raw handler to deal with it.
	 */
	smb_rwx_rwenter(&session->s_lock, RW_READER);
	if (session->s_state == SMB_SESSION_STATE_OPLOCK_BREAKING) {
		(void) smb_rwx_rwupgrade(&session->s_lock);
		if (session->s_state == SMB_SESSION_STATE_OPLOCK_BREAKING)
			session->s_state = SMB_SESSION_STATE_NEGOTIATED;
	}
	smb_rwx_rwexit(&session->s_lock);

	sr->sr_time_start = gethrtime();
	if ((sdrc = (*sdd->sdt_pre_op)(sr)) == SDRC_SUCCESS)
		sdrc = (*sdd->sdt_function)(sr);

	if (sdrc != SDRC_SR_KEPT) {
		(*sdd->sdt_post_op)(sr);
		smbsr_cleanup(sr);
	}
	smb_latency_add_sample(&sds->sdt_lat, gethrtime() - sr->sr_time_start);

	atomic_add_64(&sds->sdt_txb,
	    (int64_t)(sr->reply.chain_offset - sr->sr_txb));

	switch (sdrc) {
	case SDRC_SUCCESS:
		break;

	case SDRC_DROP_VC:
		disconnect = B_TRUE;
		goto drop_connection;

	case SDRC_NO_REPLY:
		return (B_TRUE);

	case SDRC_SR_KEPT:
		return (B_FALSE);

	case SDRC_ERROR:
		goto report_error;

	case SDRC_NOT_IMPLEMENTED:
	default:
		smbsr_error(sr, 0, ERRDOS, ERRbadfunc);
		goto report_error;
	}

	/*
	 * If there's no AndX command, we're done.
	 */
	if (sr->andx_com == 0xff)
		goto reply_ready;

	/*
	 * Otherwise, we have to back-patch the AndXCommand and AndXOffset
	 * and continue processing.
	 */
	sr->andx_prev_wct = sr->cur_reply_offset;
	(void) smb_mbc_poke(&sr->reply, sr->andx_prev_wct + 1, "b.w",
	    sr->andx_com, MBC_LENGTH(&sr->reply));

	sr->command.chain_offset = sr->orig_request_hdr + sr->andx_off;
	sr->smb_com = sr->andx_com;
	goto andx_more;

report_error:
	sr->reply.chain_offset = sr->cur_reply_offset;
	(void) smb_mbc_encodef(&sr->reply, "bw", 0, 0);

	sr->smb_wct = 0;
	sr->smb_bcc = 0;

	if (sr->smb_rcls == 0 && sr->smb_reh == 0 && sr->smb_err == 0)
		smbsr_error(sr, 0, ERRSRV, ERRerror);

reply_ready:
	smbsr_send_reply(sr);

drop_connection:
	if (disconnect) {
		smb_rwx_rwenter(&session->s_lock, RW_WRITER);
		switch (session->s_state) {
		case SMB_SESSION_STATE_DISCONNECTED:
		case SMB_SESSION_STATE_TERMINATED:
			break;
		default:
			smb_soshutdown(session->sock);
			session->s_state = SMB_SESSION_STATE_DISCONNECTED;
			break;
		}
		smb_rwx_rwexit(&session->s_lock);
	}

	return (B_TRUE);
}

int
smbsr_encode_empty_result(struct smb_request *sr)
{
	return (smbsr_encode_result(sr, 0, 0, "bw", 0, 0));
}

int
smbsr_encode_result(struct smb_request *sr, int wct, int bcc, char *fmt, ...)
{
	va_list ap;

	if (MBC_LENGTH(&sr->reply) != sr->cur_reply_offset)
		return (-1);

	va_start(ap, fmt);
	(void) smb_mbc_vencodef(&sr->reply, fmt, ap);
	va_end(ap);

	sr->smb_wct = (unsigned char)wct;
	sr->smb_bcc = (uint16_t)bcc;

	if (smbsr_check_result(sr, wct, bcc) != 0)
		return (-1);

	return (0);
}

static int
smbsr_check_result(struct smb_request *sr, int wct, int bcc)
{
	int		offset = sr->cur_reply_offset;
	int		total_bytes;
	unsigned char	temp, temp1;
	struct mbuf	*m;

	total_bytes = 0;
	m = sr->reply.chain;
	while (m != 0) {
		total_bytes += m->m_len;
		m = m->m_next;
	}

	if ((offset + 3) > total_bytes)
		return (-1);

	(void) smb_mbc_peek(&sr->reply, offset, "b", &temp);
	if (temp != wct)
		return (-1);

	if ((offset + (wct * 2 + 1)) > total_bytes)
		return (-1);

	/* reply wct & vwv seem ok, consider data now */
	offset += wct * 2 + 1;

	if ((offset + 2) > total_bytes)
		return (-1);

	(void) smb_mbc_peek(&sr->reply, offset, "bb", &temp, &temp1);
	if (bcc == VAR_BCC) {
		if ((temp != 0xFF) || (temp1 != 0xFF)) {
			return (-1);
		} else {
			bcc = (total_bytes - offset) - 2;
			(void) smb_mbc_poke(&sr->reply, offset, "bb",
			    bcc, bcc >> 8);
		}
	} else {
		if ((temp != (bcc&0xFF)) || (temp1 != ((bcc>>8)&0xFF)))
			return (-1);
	}

	offset += bcc + 2;

	if (offset != total_bytes)
		return (-1);

	sr->smb_wct = (unsigned char)wct;
	sr->smb_bcc = (uint16_t)bcc;
	return (0);
}

int
smbsr_decode_vwv(struct smb_request *sr, char *fmt, ...)
{
	int rc;
	va_list ap;

	va_start(ap, fmt);
	rc = smb_mbc_vdecodef(&sr->smb_vwv, fmt, ap);
	va_end(ap);

	if (rc)
		smbsr_error(sr, 0, ERRSRV, ERRerror);
	return (rc);
}

int
smbsr_decode_data(struct smb_request *sr, char *fmt, ...)
{
	int rc;
	va_list ap;

	va_start(ap, fmt);
	rc = smb_mbc_vdecodef(&sr->smb_data, fmt, ap);
	va_end(ap);

	if (rc)
		smbsr_error(sr, 0, ERRSRV, ERRerror);
	return (rc);
}

boolean_t
smbsr_decode_data_avail(smb_request_t *sr)
{
	return (sr->smb_data.chain_offset < sr->smb_data.max_bytes);
}

void
smbsr_send_reply(smb_request_t *sr)
{
	if (SMB_TREE_IS_CASEINSENSITIVE(sr))
		sr->smb_flg |= SMB_FLAGS_CASE_INSENSITIVE;
	else
		sr->smb_flg &= ~SMB_FLAGS_CASE_INSENSITIVE;

	(void) smb_mbc_poke(&sr->reply, 0, SMB_HEADER_ED_FMT,
	    sr->first_smb_com,
	    sr->smb_rcls,
	    sr->smb_reh,
	    sr->smb_err,
	    sr->smb_flg | SMB_FLAGS_REPLY,
	    sr->smb_flg2,
	    sr->smb_pid_high,
	    sr->smb_sig,
	    sr->smb_tid,
	    sr->smb_pid,
	    sr->smb_uid,
	    sr->smb_mid);

	if (sr->session->signing.flags & SMB_SIGNING_ENABLED)
		smb_sign_reply(sr, NULL);

	smb_server_inc_req(sr->session->s_server);
	if (smb_session_send(sr->session, 0, &sr->reply) == 0)
		sr->reply.chain = 0;
}

/*
 * Map errno values to SMB and NT status values.
 * Note: ESRCH is a special case to handle a streams lookup failure.
 */
static const struct {
	int errnum;
	int errcls;
	int errcode;
	DWORD status32;
} const smb_errno_map[] = {
	{ ENOSPC,	ERRDOS, ERROR_DISK_FULL, NT_STATUS_DISK_FULL },
	{ EDQUOT,	ERRDOS, ERROR_DISK_FULL, NT_STATUS_DISK_FULL },
	{ EPERM,	ERRSRV, ERRaccess, NT_STATUS_ACCESS_DENIED },
	{ ENOTDIR,	ERRDOS, ERRbadpath, NT_STATUS_OBJECT_PATH_NOT_FOUND },
	{ EISDIR,	ERRDOS, ERRbadpath, NT_STATUS_FILE_IS_A_DIRECTORY },
	{ ENOENT,	ERRDOS, ERRbadfile, NT_STATUS_NO_SUCH_FILE },
	{ ENOTEMPTY,	ERRDOS, ERROR_DIR_NOT_EMPTY,
	    NT_STATUS_DIRECTORY_NOT_EMPTY },
	{ EILSEQ,	ERRDOS, ERROR_INVALID_NAME,
	    NT_STATUS_OBJECT_NAME_INVALID },
	{ EACCES,	ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ ENOMEM,	ERRDOS, ERRnomem, NT_STATUS_NO_MEMORY },
	{ EIO,		ERRHRD, ERRgeneral, NT_STATUS_IO_DEVICE_ERROR },
	{ EXDEV, 	ERRSRV, ERRdiffdevice, NT_STATUS_NOT_SAME_DEVICE },
	{ EREMOTE, 	ERRSRV, ERRbadpath, NT_STATUS_PATH_NOT_COVERED},
	{ EROFS,	ERRHRD, ERRnowrite, NT_STATUS_ACCESS_DENIED },
	{ ESTALE,	ERRDOS, ERRbadfid, NT_STATUS_INVALID_HANDLE },
	{ EBADF,	ERRDOS, ERRbadfid, NT_STATUS_INVALID_HANDLE },
	{ EEXIST,	ERRDOS, ERRfilexists, NT_STATUS_OBJECT_NAME_COLLISION },
	{ ENXIO,	ERRSRV, ERRinvdevice, NT_STATUS_BAD_DEVICE_TYPE },
	{ ESRCH,	ERRDOS, ERROR_FILE_NOT_FOUND,
	    NT_STATUS_OBJECT_NAME_NOT_FOUND },
	/*
	 * It's not clear why smb_read_common effectively returns
	 * ERRnoaccess if a range lock prevents access and smb_write_common
	 * effectively returns ERRaccess.  This table entry is used by
	 * smb_read_common and preserves the behavior that was there before.
	 */
	{ ERANGE,	ERRDOS, ERRnoaccess, NT_STATUS_FILE_LOCK_CONFLICT }
};

void
smbsr_map_errno(int errnum, smb_error_t *err)
{
	int i;

	for (i = 0; i < sizeof (smb_errno_map)/sizeof (smb_errno_map[0]); ++i) {
		if (smb_errno_map[i].errnum == errnum) {
			err->status   = smb_errno_map[i].status32;
			err->errcls   = smb_errno_map[i].errcls;
			err->errcode  = smb_errno_map[i].errcode;
			return;
		}
	}

	err->status   = NT_STATUS_INTERNAL_ERROR;
	err->errcls   = ERRDOS;
	err->errcode  = ERROR_INTERNAL_ERROR;
}

void
smbsr_errno(struct smb_request *sr, int errnum)
{
	smbsr_map_errno(errnum, &sr->smb_error);
	smbsr_set_error(sr, &sr->smb_error);
}

/*
 * Report a request processing status (error or warning).
 */
void
smbsr_status(smb_request_t *sr, DWORD status, uint16_t errcls, uint16_t errcode)
{
	sr->smb_error.status   = status;
	sr->smb_error.errcls   = errcls;
	sr->smb_error.errcode  = errcode;

	smbsr_set_error(sr, &sr->smb_error);
}

/*
 * Setup a request processing error.  This function can be used to
 * report 32-bit status codes or DOS errors.  Set the status code
 * to 0 (NT_STATUS_SUCCESS) to explicitly report a DOS error,
 * regardless of the client capabilities.
 *
 * If status is non-zero and the client supports 32-bit status
 * codes, report the status.  Otherwise, report the DOS error.
 */
void
smbsr_set_error(smb_request_t *sr, smb_error_t *err)
{
	uint32_t status;
	uint32_t capabilities;

	ASSERT(sr);
	ASSERT(err);

	status = err->status;
	capabilities = sr->session->capabilities;

	if ((err->errcls == 0) && (err->errcode == 0)) {
		capabilities |= CAP_STATUS32;
		if (status == 0)
			status = NT_STATUS_INTERNAL_ERROR;
	}

	if ((capabilities & CAP_STATUS32) && (status != 0)) {
		sr->smb_rcls = status & 0xff;
		sr->smb_reh = (status >> 8) & 0xff;
		sr->smb_err  = status >> 16;
		sr->smb_flg2 |= SMB_FLAGS2_NT_STATUS;
	} else {
		if ((err->errcls == 0) || (err->errcode == 0)) {
			sr->smb_rcls = ERRSRV;
			sr->smb_err  = ERRerror;
		} else {
			sr->smb_rcls = (uint8_t)err->errcls;
			sr->smb_err  = (uint16_t)err->errcode;
		}
	}
}

smb_xa_t *
smbsr_lookup_xa(smb_request_t *sr)
{
	ASSERT(sr->r_xa == 0);

	sr->r_xa = smb_xa_find(sr->session, sr->smb_pid, sr->smb_mid);
	return (sr->r_xa);
}

void
smbsr_release_file(smb_request_t *sr)
{
	smb_ofile_t	*of = sr->fid_ofile;

	sr->fid_ofile = NULL;
	(void) smb_ofile_release(of);
}

void
smbsr_lookup_file(smb_request_t *sr)
{
	if (sr->fid_ofile == NULL)
		sr->fid_ofile = smb_ofile_lookup_by_fid(sr, sr->smb_fid);
}

static int
is_andx_com(unsigned char com)
{
	switch (com) {
	case SMB_COM_LOCKING_ANDX:
	case SMB_COM_OPEN_ANDX:
	case SMB_COM_READ_ANDX:
	case SMB_COM_WRITE_ANDX:
	case SMB_COM_SESSION_SETUP_ANDX:
	case SMB_COM_LOGOFF_ANDX:
	case SMB_COM_TREE_CONNECT_ANDX:
	case SMB_COM_NT_CREATE_ANDX:
		return (1);
	}
	return (0);
}

/*
 * Invalid command stubs.
 *
 * SmbWriteComplete is sent to acknowledge completion of raw write requests.
 * We never send raw write commands to other servers so, if we receive
 * SmbWriteComplete, we treat it as an error.
 *
 * The Read/Write Block Multiplexed (mpx) protocol is used to maximize
 * performance when reading/writing a large block of data: it can be
 * used in parallel with other client/server operations.  The mpx sub-
 * protocol is not supported because we support only connection oriented
 * transports and NT supports mpx only over connectionless transports.
 */
smb_sdrc_t
smb_pre_invalid(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Invalid__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_invalid(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Invalid__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_invalid(smb_request_t *sr)
{
	smb_sdrc_t sdrc;

	switch (sr->smb_com) {
	case SMB_COM_WRITE_COMPLETE:
		smbsr_error(sr, 0, ERRSRV, ERRerror);
		sdrc = SDRC_ERROR;
		break;

	default:
		smbsr_error(sr, NT_STATUS_NOT_IMPLEMENTED,
		    ERRDOS, ERROR_INVALID_FUNCTION);
		sdrc = SDRC_NOT_IMPLEMENTED;
		break;
	}

	return (sdrc);
}

/*
 * smb_dispatch_stats_init
 *
 * Initializes dispatch statistics.
 */
void
smb_dispatch_stats_init(smb_server_t *sv)
{
	smb_disp_stats_t *sds = sv->sv_disp_stats;
	smb_kstat_req_t *ksr;
	int		ks_ndata;
	int		i;

	ksr = ((smbsrv_kstats_t *)sv->sv_ksp->ks_data)->ks_reqs;

	for (i = 0; i < SMB_COM_NUM; i++, ksr++) {
		smb_latency_init(&sds[i].sdt_lat);
		(void) strlcpy(ksr->kr_name, smb_disp_table[i].sdt_name,
		    sizeof (ksr->kr_name));
	}
	/* Legacy Statistics */
	for (i = 0, ks_ndata = 0; i < SMB_COM_NUM; i++) {
		if (smb_disp_table[i].sdt_function != smb_com_invalid)
			ks_ndata++;
	}
}

/*
 * smb_dispatch_stats_fini
 *
 * Frees and destroyes the resources used for statistics.
 */
void
smb_dispatch_stats_fini(smb_server_t *sv)
{
	smb_disp_stats_t *sds = sv->sv_disp_stats;
	int	i;

	for (i = 0; i < SMB_COM_NUM; i++)
		smb_latency_destroy(&sds[i].sdt_lat);
}

void
smb_dispatch_stats_update(smb_server_t *sv,
    smb_kstat_req_t *ksr, int first, int nreq)
{
	smb_disp_stats_t *sds = sv->sv_disp_stats;
	int	i;
	int	last;

	last = first + nreq - 1;

	if ((first < SMB_COM_NUM) && (last < SMB_COM_NUM))  {
		for (i = first; i <= last; i++, ksr++) {
			ksr->kr_rxb = sds[i].sdt_rxb;
			ksr->kr_txb = sds[i].sdt_txb;
			mutex_enter(&sds[i].sdt_lat.ly_mutex);
			ksr->kr_nreq = sds[i].sdt_lat.ly_a_nreq;
			ksr->kr_sum = sds[i].sdt_lat.ly_a_sum;
			ksr->kr_a_mean = sds[i].sdt_lat.ly_a_mean;
			ksr->kr_a_stddev =
			    sds[i].sdt_lat.ly_a_stddev;
			ksr->kr_d_mean = sds[i].sdt_lat.ly_d_mean;
			ksr->kr_d_stddev =
			    sds[i].sdt_lat.ly_d_stddev;
			sds[i].sdt_lat.ly_d_mean = 0;
			sds[i].sdt_lat.ly_d_nreq = 0;
			sds[i].sdt_lat.ly_d_stddev = 0;
			sds[i].sdt_lat.ly_d_sum = 0;
			mutex_exit(&sds[i].sdt_lat.ly_mutex);
		}
	}
}
