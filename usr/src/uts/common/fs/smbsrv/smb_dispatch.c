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
 *
 * Dispatching SMB requests.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ALMOST EVERYTHING YOU NEED TO KNOW ABOUT A SERVER MESSAGE BLOCK
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

#include <smbsrv/smb_incl.h>
#include <sys/sdt.h>

#define	SMB_ALL_DISPATCH_STAT_INCR(stat)	atomic_inc_64(&stat);

static kstat_t *smb_dispatch_ksp = NULL;
static kstat_named_t *smb_dispatch_kstat_data = NULL;
static int smb_dispatch_kstat_size = 0;

static int 	is_andx_com(unsigned char);

extern void	smbsr_decode_error(struct smb_request *sr);
extern void	smbsr_encode_error(struct smb_request *sr);
extern void	smbsr_check_result(struct smb_request *sr, int wct, int bcc);

extern int	smb_com_cancel_forward(struct smb_request *);
extern int	smb_com_check_directory(struct smb_request *);
extern int	smb_com_close(struct smb_request *);
extern int	smb_com_close_and_tree_disconnect(struct smb_request *);
extern int	smb_com_close_print_file(struct smb_request *);
extern int	smb_com_copy(struct smb_request *);
extern int	smb_com_create(struct smb_request *);
extern int	smb_com_create_directory(struct smb_request *);
extern int	smb_com_create_new(struct smb_request *);
extern int	smb_com_create_temporary(struct smb_request *);
extern int	smb_com_delete(struct smb_request *);
extern int	smb_com_delete_directory(struct smb_request *);
extern int	smb_com_echo(struct smb_request *);
extern int	smb_com_find(struct smb_request *);
extern int	smb_com_find_close(struct smb_request *);
extern int	smb_com_find_close2(struct smb_request *);
extern int	smb_com_find_notify_close(struct smb_request *);
extern int	smb_com_find_unique(struct smb_request *);
extern int	smb_com_flush(struct smb_request *);
extern int	smb_com_forward_user_name(struct smb_request *);
extern int	smb_com_get_machine_name(struct smb_request *);
extern int	smb_com_get_print_queue(struct smb_request *);
extern int	smb_com_invalid_command(struct smb_request *);
extern int	smb_com_ioctl(struct smb_request *);
extern int	smb_com_ioctl_secondary(struct smb_request *);
extern int	smb_com_lock_and_read(struct smb_request *);
extern int	smb_com_lock_byte_range(struct smb_request *);
extern int	smb_com_locking_andx(struct smb_request *);
extern int	smb_com_logoff_andx(struct smb_request *);
extern int	smb_com_move(struct smb_request *);
extern int	smb_com_negotiate(struct smb_request *);
extern int	smb_com_nt_cancel(struct smb_request *);
extern int	smb_com_nt_create_andx(struct smb_request *);
extern int	smb_com_nt_transact(struct smb_request *);
extern int	smb_com_nt_transact_secondary(struct smb_request *);
extern int	smb_com_open(struct smb_request *);
extern int	smb_com_open_andx(struct smb_request *);
extern int	smb_com_open_print_file(struct smb_request *);
extern int	smb_com_process_exit(struct smb_request *);
extern int	smb_com_query_information(struct smb_request *);
extern int	smb_com_query_information2(struct smb_request *);
extern int	smb_com_query_information_disk(struct smb_request *);
extern int	smb_com_read(struct smb_request *);
extern int	smb_com_read_andx(struct smb_request *);
extern int	smb_com_read_mpx(struct smb_request *);
extern int	smb_com_read_mpx_secondary(struct smb_request *);
extern int	smb_com_read_raw(struct smb_request *);
extern int	smb_com_rename(struct smb_request *);
extern int	smb_com_search(struct smb_request *);
extern int	smb_com_seek(struct smb_request *);
extern int	smb_com_send_broadcast_message(struct smb_request *);
extern int	smb_com_send_end_mb_message(struct smb_request *);
extern int	smb_com_send_single_message(struct smb_request *);
extern int	smb_com_send_start_mb_message(struct smb_request *);
extern int	smb_com_send_text_mb_message(struct smb_request *);
extern int	smb_com_session_setup_andx(struct smb_request *);
extern int	smb_com_set_information(struct smb_request *);
extern int	smb_com_set_information2(struct smb_request *);
extern int	smb_com_transaction(struct smb_request *);
extern int	smb_com_transaction2(struct smb_request *);
extern int	smb_com_transaction2_secondary(struct smb_request *);
extern int	smb_com_transaction_secondary(struct smb_request *);
extern int	smb_com_tree_connect(struct smb_request *);
extern int	smb_com_tree_connect_andx(struct smb_request *);
extern int	smb_com_tree_disconnect(struct smb_request *);
extern int	smb_com_unlock_byte_range(struct smb_request *);
extern int	smb_com_write(struct smb_request *);
extern int	smb_com_write_and_close(struct smb_request *);
extern int	smb_com_write_and_unlock(struct smb_request *);
extern int	smb_com_write_andx(struct smb_request *);
extern int	smb_com_write_complete(struct smb_request *);
extern int	smb_com_write_mpx(struct smb_request *);
extern int	smb_com_write_mpx_secondary(struct smb_request *);
extern int	smb_com_write_print_file(struct smb_request *);
extern int	smb_com_write_raw(struct smb_request *);

static smb_dispatch_table_t	dispatch[256] = {
	{ smb_com_create_directory,				/* 0x00 000 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbCreateDirectory", KSTAT_DATA_UINT64 } },
	{ smb_com_delete_directory,				/* 0x01 001 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbDeleteDirectory", KSTAT_DATA_UINT64 } },
	{ smb_com_open,						/* 0x02 002 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbOpen", KSTAT_DATA_UINT64 } },
	{ smb_com_create,					/* 0x03 003 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbCreate", KSTAT_DATA_UINT64 } },
	{ smb_com_close,					/* 0x04 004 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbClose", KSTAT_DATA_UINT64 } },
	{ smb_com_flush,					/* 0x05 005 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbFlush", KSTAT_DATA_UINT64 } },
	{ smb_com_delete,					/* 0x06 006 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbDelete", KSTAT_DATA_UINT64 } },
	{ smb_com_rename,					/* 0x07 007 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbRename", KSTAT_DATA_UINT64 } },
	{ smb_com_query_information,				/* 0x08 008 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbQueryInformation", KSTAT_DATA_UINT64 } },
	{ smb_com_set_information,				/* 0x09 009 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbSetInformation", KSTAT_DATA_UINT64 } },
	{ smb_com_read,						/* 0x0A 010 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbRead", KSTAT_DATA_UINT64 } },
	{ smb_com_write,					/* 0x0B 011 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbWrite", KSTAT_DATA_UINT64 } },
	{ smb_com_lock_byte_range,				/* 0x0C 012 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbLockByteRange", KSTAT_DATA_UINT64 } },
	{ smb_com_unlock_byte_range,				/* 0x0D 013 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbUnlockByteRange", KSTAT_DATA_UINT64 } },
	{ smb_com_create_temporary,				/* 0x0E 014 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbCreateTemporary", KSTAT_DATA_UINT64 } },
	{ smb_com_create_new,					/* 0x0F 015 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbCreateNew",	KSTAT_DATA_UINT64 } },
	{ smb_com_check_directory,				/* 0x10 016 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbCheckDirectory", KSTAT_DATA_UINT64 } },
	{ smb_com_process_exit,					/* 0x11 017 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID,
	    RW_READER,
	    { "SmbProcessExit", KSTAT_DATA_UINT64 } },
	{ smb_com_seek,						/* 0x12 018 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbSeek", KSTAT_DATA_UINT64 } },
	{ smb_com_lock_and_read,				/* 0x13 019 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbLockAndRead", KSTAT_DATA_UINT64 } },
	{ smb_com_write_and_unlock,				/* 0x14 020 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbWriteAndUnlock", KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, RW_READER, 0 },				/* 0x15 021 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x16 022 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x17 023 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x18 024 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x19 025 */
	{ smb_com_read_raw,					/* 0x1A 026 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_WRITER,
	    { "SmbReadRaw", KSTAT_DATA_UINT64 } },
	{ smb_com_read_mpx,					/* 0x1B 027 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbReadMpx", KSTAT_DATA_UINT64 } },
	{ smb_com_read_mpx_secondary,				/* 0x1C 028 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbReadMpxSecondary",	KSTAT_DATA_UINT64 } },
	{ smb_com_write_raw,					/* 0x1D 029 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW | SDDF_SUPPRESS_UNLEASH,
	    RW_WRITER,
	    { "SmbWriteRaw", KSTAT_DATA_UINT64 } },
	{ smb_com_write_mpx,					/* 0x1E 030 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbWriteMpx", KSTAT_DATA_UINT64 } },
	{ smb_com_write_mpx_secondary,				/* 0x1F 031 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbWriteMpxSecondary", KSTAT_DATA_UINT64 } },
	{ smb_com_write_complete,				/* 0x20 032 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbWriteComplete", KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, 0, 0 },					/* 0x21 033 */
	{ smb_com_set_information2,				/* 0x22 034 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbSetInformation2", KSTAT_DATA_UINT64 } },
	{ smb_com_query_information2,				/* 0x23 035 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbQueryInformation2",	KSTAT_DATA_UINT64 } },
	{ smb_com_locking_andx,					/* 0x24 036 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbLockingX", KSTAT_DATA_UINT64 } },
	{ smb_com_transaction,					/* 0x25 037 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbTransaction", KSTAT_DATA_UINT64 } },
	{ smb_com_transaction_secondary,			/* 0x26 038 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbTransactionSecondary", KSTAT_DATA_UINT64 } },
	{ smb_com_ioctl,					/* 0x27 039 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbIoctl", KSTAT_DATA_UINT64 } },
	{ smb_com_ioctl_secondary,				/* 0x28 040 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbIoctlSecondary", KSTAT_DATA_UINT64 } },
	{ smb_com_copy,						/* 0x29 041 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbCopy", KSTAT_DATA_UINT64 } },
	{ smb_com_move,						/* 0x2A 042 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbMove", KSTAT_DATA_UINT64 } },
	{ smb_com_echo,						/* 0x2B 043 */
	    LANMAN1_0, SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID,
	    RW_READER,
	    { "SmbEcho", KSTAT_DATA_UINT64 } },
	{ smb_com_write_and_close,				/* 0x2C 044 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbWriteAndClose", KSTAT_DATA_UINT64 } },
	{ smb_com_open_andx,					/* 0x2D 045 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbOpenX", KSTAT_DATA_UINT64 } },
	{ smb_com_read_andx,					/* 0x2E 046 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbReadX", KSTAT_DATA_UINT64 } },
	{ smb_com_write_andx,					/* 0x2F 047 */
	    LANMAN1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbWriteX",	KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, 0, 0 },					/* 0x30 048 */
	{ smb_com_close_and_tree_disconnect,			/* 0x31 049 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbCloseAndTreeDisconnect", KSTAT_DATA_UINT64 } },
	{ smb_com_transaction2,					/* 0x32 050 */
	    LM1_2X002, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbTransaction2", KSTAT_DATA_UINT64 } },
	{ smb_com_transaction2_secondary,			/* 0x33 051 */
	    LM1_2X002, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbTransaction2Secondary", KSTAT_DATA_UINT64 } },
	{ smb_com_find_close2,					/* 0x34 052 */
	    LM1_2X002, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbFindClose2", KSTAT_DATA_UINT64 } },
	{ smb_com_find_notify_close,				/* 0x35 053 */
	    LM1_2X002, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbFindNotifyClose", KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, RW_READER, 0 },				/* 0x36 054 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x37 055 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x38 056 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x39 057 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x3A 058 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x3B 059 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x3C 060 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x3D 061 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x3E 062 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x3F 063 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x40 064 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x41 065 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x42 066 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x43 067 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x44 068 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x45 069 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x46 070 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x47 071 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x48 072 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x49 073 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x4A 074 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x4B 075 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x4C 076 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x4D 077 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x4E 078 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x4F 079 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x50 080 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x51 081 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x52 082 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x53 083 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x54 084 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x55 085 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x56 086 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x57 087 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x58 088 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x59 089 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x5A 090 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x5B 091 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x5C 092 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x5D 093 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x5E 094 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x5F 095 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x60 096 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x61 097 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x62 098 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x63 099 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x64 100 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x65 101 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x66 102 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x67 103 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x68 104 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x69 105 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x6A 106 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x6B 107 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x6C 108 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x6D 109 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x6E 110 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x6F 111 */
	{ smb_com_tree_connect,					/* 0x70 112 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_SUPPRESS_TID,
	    RW_READER,
	    { "SmbTreeConnect", KSTAT_DATA_UINT64 } },
	{ smb_com_tree_disconnect,				/* 0x71 113 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID,
	    RW_READER,
	    { "SmbTreeDisconnect", KSTAT_DATA_UINT64 } },
	{ smb_com_negotiate,					/* 0x72 114 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID,
	    RW_WRITER,
	    { "SmbNegotiate", KSTAT_DATA_UINT64 } },
	{ smb_com_session_setup_andx,				/* 0x73 115 */
	    LANMAN1_0, SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID,
	    RW_READER,
	    { "SmbSessionSetupX",	KSTAT_DATA_UINT64 } },
	{ smb_com_logoff_andx,					/* 0x74 116 */
	    LM1_2X002, SDDF_SUPPRESS_TID,
	    RW_READER,
	    { "SmbLogoffX", KSTAT_DATA_UINT64 } },
	{ smb_com_tree_connect_andx,				/* 0x75 117 */
	    LANMAN1_0, SDDF_SUPPRESS_TID,
	    RW_READER,
	    { "SmbTreeConnectX", KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, RW_READER, 0 },				/* 0x76 118 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x77 119 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x78 120 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x79 121 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x7A 122 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x7B 123 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x7C 124 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x7D 125 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x7E 126 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x7F 127 */
	{ smb_com_query_information_disk,			/* 0x80 128 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbQueryInformationDisk", KSTAT_DATA_UINT64 } },
	{ smb_com_search,					/* 0x81 129 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbSearch", KSTAT_DATA_UINT64 } },
	{ smb_com_find,						/* 0x82 130 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbFind", KSTAT_DATA_UINT64 } },
	{ smb_com_find_unique,					/* 0x83 131 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbFindUnique", KSTAT_DATA_UINT64 } },
	{ smb_com_find_close,					/* 0x84 132 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbFindClose", KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, RW_READER, 0 },				/* 0x85 133 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x86 134 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x87 135 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x88 136 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x89 137 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x8A 138 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x8B 139 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x8C 140 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x8D 141 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x8E 142 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x8F 143 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x90 144 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x91 145 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x92 146 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x93 147 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x94 148 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x95 149 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x96 150 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x97 151 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x98 152 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x99 153 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x9A 154 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x9B 155 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x9C 156 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x9D 157 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x9E 158 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0x9F 159 */
	{ smb_com_nt_transact,					/* 0xA0 160 */
	    NT_LM_0_12, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbNtTransact",	KSTAT_DATA_UINT64 } },
	{ smb_com_nt_transact_secondary,			/* 0xA1 161 */
	    NT_LM_0_12, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbNtTransactSecondary",	KSTAT_DATA_UINT64 } },
	{ smb_com_nt_create_andx,				/* 0xA2 162 */
	    NT_LM_0_12, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbNtCreateX",	KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, 0, 0 },					/* 0xA3 163 */
	{ smb_com_nt_cancel,					/* 0xA4 164 */
	    NT_LM_0_12, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbNtCancel",	KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, RW_READER, 0 },				/* 0xA5 165 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xA6 166 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xA7 167 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xA8 168 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xA9 169 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xAA 170 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xAB 171 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xAC 172 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xAD 173 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xAE 174 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xAF 175 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB0 176 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB1 177 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB2 178 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB3 179 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB4 180 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB5 181 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB6 182 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB7 183 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB8 184 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xB9 185 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xBA 186 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xBB 187 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xBC 188 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xBD 189 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xBE 190 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xBF 191 */
	{ smb_com_open_print_file,				/* 0xC0 192 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbOpenPrintFile", KSTAT_DATA_UINT64 } },
	{ smb_com_write_print_file,				/* 0xC1 193 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_SUPPRESS_SHOW,
	    RW_READER,
	    { "SmbWritePrintFile", KSTAT_DATA_UINT64 } },
	{ smb_com_close_print_file,				/* 0xC2 194 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbClosePrintFile", KSTAT_DATA_UINT64 } },
	{ smb_com_get_print_queue,				/* 0xC3 195 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbGetPrintQueue", KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, RW_READER, 0 },				/* 0xC4 196 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xC5 197 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xC6 198 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xC7 199 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xC8 200 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xC9 201 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xCA 202 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xCB 203 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xCC 204 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xCD 205 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xCE 206 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xCF 207 */
	{ smb_com_send_single_message,				/* 0xD0 208 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
		RW_READER,
	    { "SmbSendSingleMessage", KSTAT_DATA_UINT64 } },
	{ smb_com_send_broadcast_message,			/* 0xD1 209 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbSendBroadcastMessage", KSTAT_DATA_UINT64 } },
	{ smb_com_forward_user_name,				/* 0xD2 210 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbForwardUserName", KSTAT_DATA_UINT64 } },
	{ smb_com_cancel_forward,				/* 0xD3 211 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbCancelForward", KSTAT_DATA_UINT64 } },
	{ smb_com_get_machine_name,				/* 0xD4 212 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbGetMachineName", KSTAT_DATA_UINT64 } },
	{ smb_com_send_start_mb_message,			/* 0xD5 213 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbSendStartMbMessage", KSTAT_DATA_UINT64 } },
	{ smb_com_send_end_mb_message,				/* 0xD6 214 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbSendEndMbMessage", KSTAT_DATA_UINT64 } },
	{ smb_com_send_text_mb_message,				/* 0xD7 215 */
	    PC_NETWORK_PROGRAM_1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbSendTextMbMessage", KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, RW_READER, 0 },				/* 0xD8 216 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xD9 217 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xDA 218 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xDB 219 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xDC 220 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xDD 221 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xDE 222 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xDF 223 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE0 224 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE1 225 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE2 226 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE3 227 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE4 228 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE5 229 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE6 230 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE7 231 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE8 232 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xE9 233 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xEA 234 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xEB 235 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xEC 236 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xED 237 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xEE 238 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xEF 239 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF0 240 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF1 241 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF2 242 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF3 243 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF4 244 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF5 245 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF6 246 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF7 247 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF8 248 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xF9 249 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xFA 250 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xFB 251 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xFC 252 */
	{ 0, 0, 0, RW_READER, 0 },				/* 0xFD 253 */
	{ smb_com_invalid_command,				/* 0xFE 254 */
	    LANMAN1_0, SDDF_NO_FLAGS,
	    RW_READER,
	    { "SmbInvalidCommand", KSTAT_DATA_UINT64 } },
	{ 0, 0, 0, RW_READER, 0 }				/* 0xFF 255 */
};

int smb_watch = -1;
int smb_emit_sending = 0;

/*
 * smbsr_cleanup
 *
 * If any user/tree/file is used by given request then
 * the reference count for that resource has been incremented.
 * This function decrements the reference count and close
 * the resource if it's needed.
 */

void
smbsr_cleanup(struct smb_request *sr)
{
	ASSERT((sr->sr_state != SMB_REQ_STATE_CLEANED_UP) &&
	    (sr->sr_state != SMB_REQ_STATE_COMPLETED));

	if (sr->fid_ofile)
		smbsr_disconnect_file(sr);

	if (sr->sid_odir)
		smbsr_disconnect_dir(sr);

	if (sr->tid_tree) {
		smb_tree_release(sr->tid_tree);
		sr->tid_tree = NULL;
	}

	if (sr->uid_user) {
		smb_user_release(sr->uid_user);
		sr->uid_user = NULL;
	}

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

int
smb_dispatch_request(struct smb_request *sr)
{
	int			rc;
	smb_dispatch_table_t	*sdd;
	smb_error_t		err;

	ASSERT(sr->tid_tree == 0);
	ASSERT(sr->uid_user == 0);
	ASSERT(sr->fid_ofile == 0);
	ASSERT(sr->sid_odir == 0);
	sr->smb_fid = (uint16_t)-1;
	sr->smb_sid = (uint16_t)-1;

	/* temporary until we identify a user */
	sr->user_cr = kcred;
	sr->orig_request_hdr = sr->command.chain_offset;

	/* If this connection is shutting down just kill request */
	if (smb_decode_mbc(&sr->command, SMB_HEADER_ED_FMT,
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
		return (-1);
	}

	/*
	 * The reply "header" is filled in now even though
	 * it most likely will be rewritten under reply_ready:
	 * below. Could just reserve the space. But this
	 * (for now) is convenient incase the dialect dispatcher
	 * has to send a special reply (like TRANSACT).
	 *
	 * Ensure that the 32-bit error code flag is turned off.
	 * Clients seem to set it in transact requests and they may
	 * get confused if we return success or a 16-bit SMB code.
	 */
	sr->smb_rcls = 0;
	sr->smb_reh = 0;
	sr->smb_err = 0;
	sr->smb_flg2 &= ~SMB_FLAGS2_NT_STATUS;

	(void) smb_encode_mbc(&sr->reply, SMB_HEADER_ED_FMT,
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
	if (sr->session->signing.flags & SMB_SIGNING_ENABLED) {
		if (smb_sign_check_request(sr) != 0) {
			err.severity = ERROR_SEVERITY_ERROR;
			err.status = NT_STATUS_ACCESS_DENIED;
			err.errcls = ERRDOS;
			err.errcode = ERROR_ACCESS_DENIED;
			smbsr_set_error(sr, &err);
			rc = -1;
			smb_rwx_rwenter(&sr->session->s_lock, RW_READER);
			goto reply_error;
		}
	}

andx_more:
	sdd = &dispatch[sr->smb_com];

	smb_rwx_rwenter(&sr->session->s_lock, sdd->sdt_slock_mode);

	if (smb_decode_mbc(&sr->command, "b", &sr->smb_wct) != 0) {
		rc = -3;
		goto cant_decode;
	}

	(void) MBC_SHADOW_CHAIN(&sr->smb_vwv, &sr->command,
	    sr->command.chain_offset, sr->smb_wct * 2);

	if (smb_decode_mbc(&sr->command, "#.w",
	    sr->smb_wct*2, &sr->smb_bcc) != 0) {
		rc = -5;
		goto cant_decode;
	}

	(void) MBC_SHADOW_CHAIN(&sr->smb_data, &sr->command,
	    sr->command.chain_offset, sr->smb_bcc);

	sr->command.chain_offset += sr->smb_bcc;
	if (sr->command.chain_offset > sr->command.max_bytes) {
		rc = -6;
		goto cant_decode;
	}

	/* Store pointers for later */
	sr->cur_reply_offset = sr->reply.chain_offset;

	if (is_andx_com(sr->smb_com)) {
		/* Peek ahead and don't disturb vwv */
		if (smb_peek_mbc(&sr->smb_vwv, sr->smb_vwv.chain_offset, "b.w",
		    &sr->andx_com, &sr->andx_off) < 0) {
			rc = -7;
			goto cant_decode;
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

	if (sdd->sdt_function) {

		if ((rc = setjmp(&sr->exjb))) {
			/*
			 * Handle any errors from raw write.
			 */
			if (sr->session->s_state ==
			    SMB_SESSION_STATE_WRITE_RAW_ACTIVE) {
				/*
				 * Set state so that the netbios session
				 * daemon will start accepting data again.
				 */
				sr->session->s_write_raw_status = 0;
				sr->session->s_state =
				    SMB_SESSION_STATE_NEGOTIATED;
			}

			/*
			 * We should never have sr->sr_keep set here
			 * since this is the error path.
			 */
			ASSERT(sr->sr_keep == 0);

			smbsr_cleanup(sr);

			if (sr->smb_com == smb_watch) {
				smb_emit_sending = 1;
			}
			if (rc < 0) {
				rc -= 1000;
				goto cant_decode;
			}
			goto reply_error;
		}

		/*
		 * Setup UID and TID information (if required). Both functions
		 * will set the sr credentials. In domain mode, the user and
		 * tree credentials should be the same. In share mode, the
		 * tree credentials (defined in the share definition) should
		 * override the user credentials.
		 */
		if (!(sdd->sdt_flags & SDDF_SUPPRESS_UID)) {
			sr->uid_user = smb_user_lookup_by_uid(sr->session,
			    &sr->user_cr, sr->smb_uid);
			if (sr->uid_user == NULL) {
				smbsr_error(sr, 0, ERRSRV, ERRbaduid);
				/* NOTREACHED */
			}
			if (!(sdd->sdt_flags & SDDF_SUPPRESS_TID)) {
				sr->tid_tree = smb_tree_lookup_by_tid(
				    sr->uid_user, sr->smb_tid);
				if (sr->tid_tree == NULL) {
					smbsr_error(sr, 0, ERRSRV, ERRinvnid);
					/* NOTREACHED */
				}
			}
		}

		/*
		 * If the command is not a read raw request we can set the
		 * state of the session back to SMB_SESSION_STATE_NEGOTIATED
		 * (if the current state is SMB_SESSION_STATE_OPLOCK_BREAKING).
		 * Otherwise we let the read raw handler to deal with it.
		 */
		if ((sr->session->s_state ==
		    SMB_SESSION_STATE_OPLOCK_BREAKING) &&
		    (sr->smb_com != SMB_COM_READ_RAW)) {
			krw_t	mode;
			/*
			 * The lock may have to be upgraded because, at this
			 * point, we don't know how it was entered. We just
			 * know that it has to be entered in writer mode here.
			 * Whatever mode was used to enter the lock, it will
			 * be restored.
			 */
			mode = smb_rwx_rwupgrade(&sr->session->s_lock);
			if (sr->session->s_state ==
			    SMB_SESSION_STATE_OPLOCK_BREAKING) {
				sr->session->s_state =
				    SMB_SESSION_STATE_NEGOTIATED;
			}
			smb_rwx_rwdowngrade(&sr->session->s_lock, mode);
		}

		DTRACE_PROBE1(smb__dispatch__com, struct smb_request_t *, sr);

		/*
		 * Increment method invocation count. This value is exposed
		 * via kstats, and it represents a count of all the dispatched
		 * requests, including the ones that have a return value, other
		 * than SDRC_NORMAL_REPLY.
		 */
		SMB_ALL_DISPATCH_STAT_INCR(sdd->sdt_dispatch_stats.value.ui64);

		rc = (*sdd->sdt_function)(sr);

		/*
		 * Only call smbsr_cleanup if smb->sr_keep is not set.  The
		 * smb_nt_transact_notify_change function will set
		 * smb->sr_keep if it retains control of the request when
		 * it returns.  In that case the notify change code
		 * will call smbsr_cleanup later when the request is finally
		 * completed.
		 */
		if (sr->sr_keep == 0)
			smbsr_cleanup(sr);
	} else {
		rc = SDRC_UNIMPLEMENTED;	/* Unknown? */
	}

	if (rc != SDRC_NORMAL_REPLY) {	/* normal case special & fast */
		switch (rc) {
		case SDRC_NORMAL_REPLY:
			break;

		case SDRC_ERROR_REPLY:
			goto reply_error;

		case SDRC_DROP_VC:
			switch (sr->session->s_state) {
			case SMB_SESSION_STATE_DISCONNECTED:
			case SMB_SESSION_STATE_TERMINATED:
				break;
			default:
				smb_soshutdown(sr->session->sock);
				break;
			}
			goto reply_error;

		case SDRC_NO_REPLY:
			/* tricky. */
			smb_rwx_rwexit(&sr->session->s_lock);
			return (0);

		case SDRC_UNIMPLEMENTED:
			sr->smb_rcls = ERRDOS;
			sr->smb_err = ERRbadfunc;
			goto reply_error;

		default:
			sr->smb_rcls = ERRDOS;
			sr->smb_err = ERRerror;	/* need better */
			goto reply_error;
		}
	}

	if (sr->andx_com == 0xff)
		goto reply_ready;

	/* have to back-patch the AndXCommand and AndXOffset */
	sr->andx_prev_wct = sr->cur_reply_offset;
	(void) smb_poke_mbc(&sr->reply, sr->andx_prev_wct + 1, "b.w",
	    sr->andx_com, MBC_LENGTH(&sr->reply));

	smb_rwx_rwexit(&sr->session->s_lock);

	/* now it gets interesting */
	sr->command.chain_offset = sr->orig_request_hdr + sr->andx_off;

	sr->smb_com = sr->andx_com;

	goto andx_more;

reply_ready:

	if (SMB_TREE_CASE_INSENSITIVE(sr)) {
		sr->smb_flg |= SMB_FLAGS_CASE_INSENSITIVE;
	} else {
		sr->smb_flg &= ~SMB_FLAGS_CASE_INSENSITIVE;
	}

	(void) smb_poke_mbc(&sr->reply, 0, SMB_HEADER_ED_FMT,
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

	if ((rc = smb_session_send(sr->session, 0, &sr->reply)) == 0)
		sr->reply.chain = 0;

	smb_rwx_rwexit(&sr->session->s_lock);

	return (rc);

cant_decode:
reply_error:
	sr->reply.chain_offset = sr->cur_reply_offset;
	(void) smb_encode_mbc(&sr->reply, "bw", 0, 0);

	sr->smb_wct = 0;
	sr->smb_bcc = 0;

	if (sr->smb_rcls == 0) {
		sr->smb_rcls = ERRSRV;
		sr->smb_err  = ERRerror;
	}
	goto reply_ready;
}


void
smbsr_encode_result(struct smb_request *sr, int wct,
    int bcc, char *fmt, ...)
{
	va_list ap;

	if (MBC_LENGTH(&sr->reply) != sr->cur_reply_offset) {
		smbsr_encode_error(sr);
	}

	va_start(ap, fmt);
	(void) smb_mbc_encode(&sr->reply, fmt, ap);
	va_end(ap);

	sr->smb_wct = (unsigned char)wct;
	sr->smb_bcc = (uint16_t)bcc;

	smbsr_check_result(sr, wct, bcc);
}

void
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

	if ((offset + 3) > total_bytes) {
		smbsr_encode_error(sr);
		/* NOTREACHED */
	}

	(void) smb_peek_mbc(&sr->reply, offset, "b", &temp);
	if (temp != wct) {
		smbsr_encode_error(sr);
		/* NOTREACHED */
	}

	if ((offset + (wct * 2 + 1)) > total_bytes) {
		smbsr_encode_error(sr);
		/* NOTREACHED */
	}

	/* reply wct & vwv seem ok, consider data now */
	offset += wct * 2 + 1;

	if ((offset + 2) > total_bytes) {
		smbsr_encode_error(sr);
	}

	(void) smb_peek_mbc(&sr->reply, offset, "bb", &temp, &temp1);
	if (bcc == VAR_BCC) {
		if ((temp != 0xFF) || (temp1 != 0xFF)) {
			smbsr_encode_error(sr);
			/* NOTREACHED */
		} else {
			bcc = (total_bytes - offset) - 2;
			(void) smb_poke_mbc(&sr->reply, offset, "bb",
			    bcc, bcc >> 8);
		}
	} else {
		if ((temp != (bcc&0xFF)) || (temp1 != ((bcc>>8)&0xFF))) {
			smbsr_encode_error(sr);
		}
	}

	offset += bcc + 2;

	if (offset != total_bytes) {
		smbsr_encode_error(sr);
	}

	sr->smb_wct = (unsigned char)wct;
	sr->smb_bcc = (uint16_t)bcc;
}

int
smbsr_decode_vwv(struct smb_request *sr, char *fmt, ...)
{
	int rc;
	va_list ap;

	va_start(ap, fmt);
	rc = smb_mbc_decode(&sr->smb_vwv, fmt, ap);
	va_end(ap);

	return (rc);
}

int
smbsr_decode_data(struct smb_request *sr, char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = smb_mbc_decode(&sr->smb_data, fmt, ap);
	va_end(ap);
	return (r);
}

void
smbsr_send_reply(struct smb_request *sr)
{
	(void) smb_poke_mbc(&sr->reply, 0, SMB_HEADER_ED_FMT,
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

	(void) smb_session_send(sr->session, 0, &sr->reply);
}


void
smbsr_decode_error(struct smb_request *sr)
{
	longjmp(&sr->exjb);
}

void
smbsr_encode_error(struct smb_request *sr)
{
	longjmp(&sr->exjb);
}

void
smbsr_encode_empty_result(struct smb_request *sr)
{
	smbsr_encode_result(sr, 0, 0, "bw", 0, 0);
}

/*
 * Map errno values to SMB and NT status values.
 * Note: ESRCH is a special case to handle a streams lookup failure.
 */
static struct {
	int errnum;
	int errcls;
	int errcode;
	DWORD status32;
} smb_errno_map[] = {
	{ ENOSPC,	ERRDOS, ERROR_DISK_FULL, NT_STATUS_DISK_FULL },
	{ EDQUOT,	ERRDOS, ERROR_DISK_FULL, NT_STATUS_DISK_FULL },
	{ EPERM,	ERRSRV, ERRaccess, NT_STATUS_ACCESS_DENIED },
	{ ENOTDIR,	ERRDOS, ERRbadpath, NT_STATUS_OBJECT_PATH_NOT_FOUND },
	{ EISDIR,	ERRDOS, ERRbadpath, NT_STATUS_FILE_IS_A_DIRECTORY },
	{ ENOENT,	ERRDOS, ERRbadfile, NT_STATUS_NO_SUCH_FILE },
	{ ENOTEMPTY,	ERRDOS, ERROR_DIR_NOT_EMPTY,
	    NT_STATUS_DIRECTORY_NOT_EMPTY },
	{ EACCES,	ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ ENOMEM,	ERRDOS, ERRnomem, NT_STATUS_NO_MEMORY },
	{ EIO,		ERRHRD, ERRgeneral, NT_STATUS_IO_DEVICE_ERROR },
	{ EXDEV, 	ERRSRV, ERRdiffdevice, NT_STATUS_NOT_SAME_DEVICE },
	{ EROFS,	ERRHRD, ERRnowrite, NT_STATUS_ACCESS_DENIED },
	{ ESTALE,	ERRDOS, ERRbadfid, NT_STATUS_INVALID_HANDLE},
	{ EBADF,	ERRDOS, ERRbadfid, NT_STATUS_INVALID_HANDLE},
	{ EEXIST,	ERRDOS, ERRfilexists, NT_STATUS_OBJECT_NAME_COLLISION},
	{ ENXIO,	ERRSRV, ERRinvdevice, NT_STATUS_BAD_DEVICE_TYPE},
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
			err->severity = ERROR_SEVERITY_ERROR;
			err->status   = smb_errno_map[i].status32;
			err->errcls   = smb_errno_map[i].errcls;
			err->errcode  = smb_errno_map[i].errcode;
			return;
		}
	}

	err->severity = ERROR_SEVERITY_ERROR;
	err->status   = NT_STATUS_INTERNAL_ERROR;
	err->errcls   = ERRDOS;
	err->errcode  = ERROR_INTERNAL_ERROR;
}

void
smbsr_errno(struct smb_request *sr, int errnum)
{
	smb_error_t err;

	smbsr_map_errno(errnum, &err);
	smbsr_set_error(sr, &err);
	longjmp(&sr->exjb);
	/* NOTREACHED */
}

/*
 * Report a request processing warning.
 */
void
smbsr_warn(smb_request_t *sr, DWORD status, uint16_t errcls, uint16_t errcode)
{
	smb_error_t err;

	err.severity = ERROR_SEVERITY_WARNING;
	err.status   = status;
	err.errcls   = errcls;
	err.errcode  = errcode;

	smbsr_set_error(sr, &err);
}

/*
 * Report a request processing error.  This function will not return.
 */
void
smbsr_error(smb_request_t *sr, DWORD status, uint16_t errcls, uint16_t errcode)
{
	smb_error_t err;

	err.severity = ERROR_SEVERITY_ERROR;
	err.status   = status;
	err.errcls   = errcls;
	err.errcode  = errcode;

	smbsr_set_error(sr, &err);
	longjmp(&sr->exjb);
	/* NOTREACHED */
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
	uint32_t severity;
	uint32_t capabilities;

	ASSERT(sr);
	ASSERT(err);

	status = err->status;
	severity = (err->severity == 0) ? ERROR_SEVERITY_ERROR : err->severity;
	capabilities = sr->session->capabilities;

	if ((err->errcls == 0) && (err->errcode == 0)) {
		capabilities |= CAP_STATUS32;
		if (status == 0)
			status = NT_STATUS_INTERNAL_ERROR;
	}

	if ((capabilities & CAP_STATUS32) && (status != 0)) {
		status |= severity;
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
smbsr_disconnect_file(smb_request_t *sr)
{
	smb_ofile_t	*of = sr->fid_ofile;

	sr->fid_ofile = NULL;
	(void) smb_ofile_release(of);
}

void
smbsr_disconnect_dir(smb_request_t *sr)
{
	smb_odir_t	*od = sr->sid_odir;

	sr->sid_odir = NULL;
	smb_odir_release(od);
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
 * Invalid command stub.
 */
/*ARGSUSED*/
int
smb_com_invalid_command(struct smb_request *sr)
{
	return (SDRC_UNIMPLEMENTED);
}

/*
 * smb_kstat_update_dispatch
 *
 * This callback function updates the smb_dispatch_kstat_data when kstat
 * command is invoked.
 */
/*ARGSUSED*/
static int
smb_kstat_update_dispatch(kstat_t *ksp, int rw)
{
	int i = 0, j = 0;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		for (i = 0; i < 256; i++) {
			if (dispatch[i].sdt_function) {
				(void) memcpy(&smb_dispatch_kstat_data[j],
				    &(dispatch[i].sdt_dispatch_stats),
				    sizeof (kstat_named_t));
				j++;
			}
		}
	}
	return (0);
}

/*
 * smb_initialize_dispatch_kstat
 *
 * Initialize dispatch kstats.
 */
void
smb_initialize_dispatch_kstat()
{
	int i = 0, alloc_size = 0;

	for (i = 0; i < 256; i++) {
		if (dispatch[i].sdt_function)
			smb_dispatch_kstat_size++;
	}

	alloc_size = smb_dispatch_kstat_size * sizeof (kstat_named_t);
	smb_dispatch_kstat_data = (kstat_named_t *)
	    kmem_zalloc(alloc_size, KM_SLEEP);

	smb_dispatch_ksp = kstat_create("smb", 0, "smb_dispatch_all", "misc",
	    KSTAT_TYPE_NAMED, alloc_size/sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);
	if (smb_dispatch_ksp) {
		smb_dispatch_ksp->ks_data = smb_dispatch_kstat_data;
		smb_dispatch_ksp->ks_update = smb_kstat_update_dispatch;
		kstat_install(smb_dispatch_ksp);
	}
}

/*
 * smb_remove_dispatch_kstat
 *
 * Remove dispatch kstats.
 */
void
smb_remove_dispatch_kstat()
{
	if (smb_dispatch_kstat_data != NULL)
		kmem_free(smb_dispatch_kstat_data,
		    smb_dispatch_kstat_size * sizeof (kstat_named_t));

	if (smb_dispatch_ksp != NULL) {
		kstat_delete(smb_dispatch_ksp);
		smb_dispatch_ksp = NULL;
	}
}
