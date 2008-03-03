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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SMB print interface.
 */

#include <smbsrv/smb_incl.h>


/*
 * smb_com_open_print_file
 *
 * This message is sent to create a new printer file which will be deleted
 * once it has been closed and printed.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 2
 * USHORT SetupLength;                Length of printer setup data
 * USHORT Mode;                       0 = Text mode (DOS expands TABs)
 *                                     1 = Graphics mode
 * USHORT ByteCount;                  Count of data bytes;  min = 2
 * UCHAR BufferFormat;                0x04
 * STRING IdentifierString[];         Identifier string
 *
 * Tid in the SMB header must refer to a printer resource type.
 *
 * SetupLength is the number of bytes in the first part of the resulting
 * print spool file which contains printer-specific control strings.
 *
 * Mode can have the following values:
 *
 *      0     Text mode.  The server may optionally
 *            expand tabs to a series of spaces.
 *      1     Graphics mode.  No conversion of data
 *            should be done by the server.
 *
 * IdentifierString can be used by the server to provide some sort of per-
 * client identifying component to the print file.
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 1
 * USHORT Fid;                        File handle
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * Fid is the returned handle which may be used by subsequent write and
 * close operations.  When the file is finally closed, it will be sent to
 * the spooler and printed.
 *
 * 4.5.1.1   Errors
 *
 * ERRDOS/ERRnoaccess
 * ERRDOS/ERRnofids
 * ERRSRV/ERRinvdevice
 * ERRSRV/ERRbaduid
 * ERRSRV/ERRqfull
 * ERRSRV/ERRqtoobig
 */
smb_sdrc_t
smb_pre_open_print_file(smb_request_t *sr)
{
	DTRACE_SMB_1(op__OpenPrintFile__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_open_print_file(smb_request_t *sr)
{
	DTRACE_SMB_1(op__OpenPrintFile__done, smb_request_t *, sr);
}

smb_sdrc_t /*ARGSUSED*/
smb_com_open_print_file(smb_request_t *sr)
{
	return (SDRC_NOT_IMPLEMENTED);
}


/*
 * smb_com_close_print_file
 *
 *
 * This message invalidates the specified file handle and queues the file
 * for printing.
 *
 *   Client Request                     Description
 *   ================================== =================================
 *
 *   UCHAR WordCount;                   Count of parameter words = 1
 *   USHORT Fid;                        File handle
 *   USHORT ByteCount;                  Count of data bytes = 0
 *
 * Fid refers to a file previously created with SMB_COM_OPEN_PRINT_FILE.
 * On successful completion of this request, the file is queued for
 * printing by the server.
 *
 *   Server Response                    Description
 *   ================================== =================================
 *
 *   UCHAR WordCount;                   Count of parameter words = 0
 *   USHORT ByteCount;                  Count of data bytes = 0
 *
 * Servers which negotiate dialects of LANMAN1.0 and newer allow all the
 * other types of Fid closing requests to invalidate the Fid and begin
 * spooling.
 */
smb_sdrc_t
smb_pre_close_print_file(smb_request_t *sr)
{
	DTRACE_SMB_1(op__ClosePrintFile__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_close_print_file(smb_request_t *sr)
{
	DTRACE_SMB_1(op__ClosePrintFile__done, smb_request_t *, sr);
}

smb_sdrc_t /*ARGSUSED*/
smb_com_close_print_file(smb_request_t *sr)
{
	return (SDRC_NOT_IMPLEMENTED);
}


/*
 * smb_com_get_print_queue
 *
 * This message obtains a list of the elements currently in the print queue
 * on the server.
 *
 *   Client Request                     Description
 *   ================================== =================================
 *
 *   UCHAR WordCount;                   Count of parameter words = 2
 *   USHORT MaxCount;                   Max number of entries to return
 *   USHORT StartIndex;                 First queue entry to return
 *   USHORT ByteCount;                  Count of data bytes = 0
 *
 * StartIndex specifies the first entry in the queue to return.
 *
 * MaxCount specifies the maximum number of entries to return, this may be
 * a positive or negative number.  A positive number requests a forward
 * search, a negative number indicates a backward search.
 *
 *   Server Response                    Description
 *   ================================== =================================
 *
 *   UCHAR WordCount;                   Count of parameter words = 2
 *   USHORT Count;                      Number of entries returned
 *   USHORT RestartIndex;               Index of entry after last
 *                                       returned
 *   USHORT ByteCount;                  Count of data bytes;  min = 3
 *   UCHAR BufferFormat;                0x01 -- Data block
 *   USHORT DataLength;                 Length of data
 *   UCHAR Data[];                      Queue elements
 *
 * Count indicates how many entries were actually returned.  RestartIndex
 * is the index of the entry following the last entry returned; it may be
 * used as the StartIndex in a subsequent request to resume the queue
 * listing.
 *
 * The format of each returned queue element is:
 *
 *   Queue Element Member             Description
 *   ================================ ===================================
 *
 *   SMB_DATE FileDate;               Date file was queued
 *   SMB_TIME FileTime;               Time file was queued
 *   UCHAR Status;                    Entry status.  One of:
 *                                     01 = held or stopped
 *                                     02 = printing
 *                                     03 = awaiting print
 *                                     04 = in intercept
 *                                     05 = file had error
 *                                     06 = printer error
 *                                     07-FF = reserved
 *   USHORT SpoolFileNumber;          Assigned by the spooler
 *   ULONG SpoolFileSize;             Number of bytes in spool file
 *   UCHAR Reserved;
 *   UCHAR SpoolFileName[16];         Client which created the spool file
 *
 * SMB_COM_GET_PRINT_QUEUE will return less than the requested number of
 * elements only when the top or end of the queue is encountered.
 *
 * Support for this SMB is server optional.  In particular, no current
 * Microsoft client software issues this request.
 *
 * 4.5.2.1   Errors
 *
 * ERRHRD/ERRnotready
 * ERRHRD/ERRerror
 * ERRSRV/ERRbaduid
 */
smb_sdrc_t
smb_pre_get_print_queue(smb_request_t *sr)
{
	DTRACE_SMB_1(op__GetPrintQueue__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_get_print_queue(smb_request_t *sr)
{
	DTRACE_SMB_1(op__GetPrintQueue__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_get_print_queue(smb_request_t *sr)
{
	unsigned short max_count, start_ix;

	if (smbsr_decode_vwv(sr, "ww", &max_count, &start_ix) != 0)
		return (SDRC_ERROR);

	if (smbsr_encode_result(sr, 2, 3, "bwwwbw", 2, 0, 0, 3, 1, 0))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}


/*
 * smb_com_write_print_file
 *
 * This message is sent to write bytes into a print spool file.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 1
 * USHORT Fid;                        File handle
 * USHORT ByteCount;                  Count of data bytes;  min = 4
 * UCHAR BufferFormat;                0x01 -- Data block
 * USHORT DataLength;                 Length of data
 * UCHAR Data[];                      Data
 *
 * Fid indicates the print spool file to be written, it must refer to a
 * print spool file.
 *
 * ByteCount specifies the number of bytes to be written, and must be less
 * than MaxBufferSize for the Tid specified.
 *
 * Data contains the bytes to append to the print spool file.  The first
 * SetupLength bytes in the resulting print spool file contain printer
 * setup data.  SetupLength is specified in the SMB_COM_OPEN_PRINT_FILE SMB
 * request.
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * Servers which negotiate a protocol dialect of LANMAN1.0 or later also
 * support the application of normal write requests to print spool files.
 *
 */
smb_sdrc_t
smb_pre_write_print_file(smb_request_t *sr)
{
	DTRACE_SMB_1(op__WritePrintFile__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_write_print_file(smb_request_t *sr)
{
	DTRACE_SMB_1(op__WritePrintFile__done, smb_request_t *, sr);
}

smb_sdrc_t /*ARGSUSED*/
smb_com_write_print_file(smb_request_t *sr)
{
	return (SDRC_NOT_IMPLEMENTED);
}
