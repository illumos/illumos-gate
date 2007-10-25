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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_incl.h>

struct xlate_table {
	int		code;
	char		*str;
};

struct xlate_table smb_xlate_com[] = {
	{	SMB_COM_CREATE_DIRECTORY,	"CREATE_DIRECTORY" },
	{	SMB_COM_DELETE_DIRECTORY,	"DELETE_DIRECTORY" },
	{	SMB_COM_OPEN,			"OPEN" },
	{	SMB_COM_CREATE,			"COM_CREATE" },
	{	SMB_COM_CLOSE,			"CLOSE" },
	{	SMB_COM_FLUSH,			"FLUSH" },
	{	SMB_COM_DELETE,			"DELETE" },
	{	SMB_COM_RENAME,			"RENAME" },
	{	SMB_COM_QUERY_INFORMATION,	"QUERY_INFORMATION" },
	{	SMB_COM_SET_INFORMATION,	"SET_INFORMATION" },
	{	SMB_COM_READ,			"READ" },
	{	SMB_COM_WRITE,			"WRITE" },
	{	SMB_COM_LOCK_BYTE_RANGE,	"LOCK_BYTE_RANGE" },
	{	SMB_COM_UNLOCK_BYTE_RANGE,	"UNLOCK_BYTE_RANGE" },
	{	SMB_COM_CREATE_TEMPORARY,	"CREATE_TEMPORARY" },
	{	SMB_COM_CREATE_NEW,		"CREATE_NEW" },
	{	SMB_COM_CHECK_DIRECTORY,	"CHECK_DIRECTORY" },
	{	SMB_COM_PROCESS_EXIT,		"PROCESS_EXIT" },
	{	SMB_COM_SEEK,			"SEEK" },
	{	SMB_COM_LOCK_AND_READ,		"LOCK_AND_READ" },
	{	SMB_COM_WRITE_AND_UNLOCK,	"WRITE_AND_UNLOCK" },
	{	SMB_COM_READ_RAW,		"READ_RAW" },
	{	SMB_COM_READ_MPX,		"READ_MPX" },
	{	SMB_COM_READ_MPX_SECONDARY,	"READ_MPX_SECONDARY" },
	{	SMB_COM_WRITE_RAW,		"WRITE_RAW" },
	{	SMB_COM_WRITE_MPX,		"WRITE_MPX" },
	{	SMB_COM_WRITE_COMPLETE,		"WRITE_COMPLETE" },
	{	SMB_COM_SET_INFORMATION2,	"SET_INFORMATION2" },
	{	SMB_COM_QUERY_INFORMATION2,	"QUERY_INFORMATION2" },
	{	SMB_COM_LOCKING_ANDX,		"LOCKING_ANDX" },
	{	SMB_COM_TRANSACTION,		"TRANSACTION" },
	{	SMB_COM_TRANSACTION_SECONDARY,	"TRANSACTION_SECONDARY" },
	{	SMB_COM_IOCTL,			"IOCTL" },
	{	SMB_COM_IOCTL_SECONDARY,	"IOCTL_SECONDARY" },
	{	SMB_COM_COPY,			"COPY" },
	{	SMB_COM_MOVE,			"MOVE" },
	{	SMB_COM_ECHO,			"ECHO" },
	{	SMB_COM_WRITE_AND_CLOSE,	"WRITE_AND_CLOSE" },
	{	SMB_COM_OPEN_ANDX,		"OPEN_ANDX" },
	{	SMB_COM_READ_ANDX,		"READ_ANDX" },
	{	SMB_COM_WRITE_ANDX,		"WRITE_ANDX" },
	{	SMB_COM_CLOSE_AND_TREE_DISC,	"CLOSE_AND_TREE_DISC" },
	{	SMB_COM_TRANSACTION2,		"TRANSACTION2" },
	{	SMB_COM_TRANSACTION2_SECONDARY,	"TRANSACTION2_SECONDARY" },
	{	SMB_COM_FIND_CLOSE2,		"FIND_CLOSE2" },
	{	SMB_COM_FIND_NOTIFY_CLOSE,	"FIND_NOTIFY_CLOSE" },
	{	SMB_COM_TREE_CONNECT,		"TREE_CONNECT" },
	{	SMB_COM_TREE_DISCONNECT,	"TREE_DISCONNECT" },
	{	SMB_COM_NEGOTIATE,		"NEGOTIATE" },
	{	SMB_COM_SESSION_SETUP_ANDX,	"SESSION_SETUP_ANDX" },
	{	SMB_COM_LOGOFF_ANDX,		"LOGOFF_ANDX" },
	{	SMB_COM_TREE_CONNECT_ANDX,	"TREE_CONNECT_ANDX" },
	{	SMB_COM_QUERY_INFORMATION_DISK,	"QUERY_INFORMATION_DISK" },
	{	SMB_COM_SEARCH,			"SEARCH" },
	{	SMB_COM_FIND,			"FIND" },
	{	SMB_COM_FIND_UNIQUE,		"FIND_UNIQUE" },
	{	SMB_COM_NT_TRANSACT,		"NT_TRANSACT" },
	{	SMB_COM_NT_TRANSACT_SECONDARY,	"NT_TRANSACT_SECONDARY" },
	{	SMB_COM_NT_CREATE_ANDX,		"NT_CREATE_ANDX" },
	{	SMB_COM_NT_CANCEL,		"NT_CANCEL" },
	{	SMB_COM_OPEN_PRINT_FILE,	"OPEN_PRINT_FILE" },
	{	SMB_COM_WRITE_PRINT_FILE,	"WRITE_PRINT_FILE" },
	{	SMB_COM_CLOSE_PRINT_FILE,	"CLOSE_PRINT_FILE" },
	{	SMB_COM_GET_PRINT_QUEUE,	"GET_PRINT_QUEUE" },
	{ 0 }
};

struct xlate_table smb_xlate_rcls[] = {
	{	SUCCESS,		"SUCCESS" },
	{	ERRDOS,			"ERRDOS" },
	{	ERRSRV,			"ERRSRV" },
	{	ERRHRD,			"ERRHRD" },
	{	ERRCMD,			"ERRCMD" },
	{ 0 }
};

struct xlate_table smb_xlate_errdos[] = {
	{	ERRbadfunc,			"ERRbadfunc" },
	{	ERRbadfile,			"ERRbadfile" },
	{	ERRbadpath,			"ERRbadpath" },
	{	ERRnofids,			"ERRnofids" },
	{	ERRnoaccess,			"ERRnoaccess" },
	{	ERRbadfid,			"ERRbadfid" },
	{	ERRbadmcb,			"ERRbadmcb" },
	{	ERRnomem,			"ERRnomem" },
	{	ERRbadmem,			"ERRbadmem" },
	{	ERRbadenv,			"ERRbadenv" },
	{	ERRbadformat,			"ERRbadformat" },
	{	ERRbadaccess,			"ERRbadaccess" },
	{	ERRbaddata,			"ERRbaddata" },
	{	ERRbaddrive,			"ERRbaddrive" },
	{	ERRremcd,			"ERRremcd" },
	{	ERRdiffdevice,			"ERRdiffdevice" },
	{	ERRnofiles,			"ERRnofiles" },
	{	ERRbadshare,			"ERRbadshare" },
	{	ERRlock,			"ERRlock" },
	{	ERRfilexists,			"ERRfilexists" },
	{	ERRbadpipe,			"ERRbadpipe" },
	{	ERRpipebusy,			"ERRpipebusy" },
	{	ERRpipeclosing,			"ERRpipeclosing" },
	{	ERRnotconnected,		"ERRnotconnected" },
	{	ERRmoredata,			"ERRmoredata" },
	{ 0 }
};

struct xlate_table smb_xlate_errsrv[] = {
	{	ERRerror,			"ERRerror" },
	{	ERRbadpw,			"ERRbadpw" },
	{	ERRaccess,			"ERRaccess" },
	{	ERRinvnid,			"ERRinvnid" },
	{	ERRinvnetname,			"ERRinvnetname" },
	{	ERRinvdevice,			"ERRinvdevice" },
	{	ERRqfull,			"ERRqfull" },
	{	ERRqtoobig,			"ERRqtoobig" },
	{	ERRqeof,			"ERRqeof" },
	{	ERRinvpfid,			"ERRinvpfid" },
	{	ERRsmbcmd,			"ERRsmbcmd" },
	{	ERRsrverror,			"ERRsrverror" },
	{	ERRfilespecs,			"ERRfilespecs" },
	{	ERRbadpermits,			"ERRbadpermits" },
	{	ERRsetattrmode,			"ERRsetattrmode" },
	{	ERRpaused,			"ERRpaused" },
	{	ERRmsgoff,			"ERRmsgoff" },
	{	ERRnoroom,			"ERRnoroom" },
	{	ERRrmuns,			"ERRrmuns" },
	{	ERRtimeout,			"ERRtimeout" },
	{	ERRnoresource,			"ERRnoresource" },
	{	ERRtoomanyuids,			"ERRtoomanyuids" },
	{	ERRbaduid,			"ERRbaduid" },
	{	ERRusempx,			"ERRusempx" },
	{	ERRusestd,			"ERRusestd" },
	{	ERRcontmpx,			"ERRcontmpx" },
	{	ERRnosupport,			"ERRnosupport" },
	{ 0 }
};

struct xlate_table smb_xlate_errhrd[] = {
	{	ERRnowrite,			"ERRnowrite" },
	{	ERRbadunit,			"ERRbadunit" },
	{	ERRnotready,			"ERRnotready" },
	{	ERRbadcmd,			"ERRbadcmd" },
	{	ERRdata,			"ERRdata" },
	{	ERRbadreq,			"ERRbadreq" },
	{	ERRseek,			"ERRseek" },
	{	ERRbadmedia,			"ERRbadmedia" },
	{	ERRbadsector,			"ERRbadsector" },
	{	ERRnopaper,			"ERRnopaper" },
	{	ERRwrite,			"ERRwrite" },
	{	ERRread,			"ERRread" },
	{	ERRgeneral,			"ERRgeneral" },
	{	ERRbadshare,			"ERRbadshare" },
	{	ERRlock,			"ERRlock" },
	{	ERRwrongdisk,			"ERRwrongdisk" },
	{	ERRFCBUnavail,			"ERRFCBUnavail" },
	{	ERRsharebufexc,			"ERRsharebufexc" },
	{ 0 }
};

struct xlate_table smb_xlate_dialect[] = {
	{	DIALECT_UNKNOWN,		"DIALECT_UNKNOWN" },
	{	PC_NETWORK_PROGRAM_1_0,		"PC NETWORK PROGRAM 1.0" },
	{	PCLAN1_0,			"PCLAN1.0" },
	{	MICROSOFT_NETWORKS_1_03,	"MICROSOFT NETWORKS 1.03" },
	{	MICROSOFT_NETWORKS_3_0,		"MICROSOFT NETWORKS 3.0" },
	{	LANMAN1_0,			"LANMAN1.0" },
	{	LM1_2X002,			"LM1.2X002" },
	{	DOS_LM1_2X002,			"DOS LM1.2X002" },
	{	DOS_LANMAN2_1,			"DOS LANMAN2.1" },
	{	LANMAN2_1,			"LANMAN2.1" },
	{   Windows_for_Workgroups_3_1a,	"Windows for Workgroups 3.1a" },
	{	NT_LM_0_12,			"NT LM 0.12" },
	{ 0 }
};

static char *
smb_xlate_cd_to_str(struct xlate_table *xl, int cd)
{
	static char	no_answer[32];

	for (; xl->str; xl++)
		if (xl->code == cd)
			return (xl->str);

	(void) sprintf(no_answer, "-%x-", cd);

	return (no_answer);
}

static int
smb_xlate_str_to_cd(struct xlate_table *xl, char *str)
{
	for (; xl->str; xl++)
		if (strcmp(xl->str, str) == 0)
			return (xl->code);
	return (-1);
}


char *
smb_xlate_com_cd_to_str(int com)
{
	return (smb_xlate_cd_to_str(smb_xlate_com, com));
}

char *
smb_xlate_dialect_cd_to_str(int dialect)
{
	return (smb_xlate_cd_to_str(smb_xlate_dialect, dialect));
}

int
smb_xlate_dialect_str_to_cd(char *str)
{
	return (smb_xlate_str_to_cd(smb_xlate_dialect, str));
}
