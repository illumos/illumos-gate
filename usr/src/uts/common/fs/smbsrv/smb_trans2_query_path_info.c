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
 * SMB: trans2_query_path_information
 *
 * This request is used to get information about a specific file or
 * subdirectory.
 *
 *  Client Request             Value
 *  ========================== =========================================
 *
 *  WordCount                  15
 *  MaxSetupCount              0
 *  SetupCount                 1
 *  Setup[0]                   TRANS2_QUERY_PATH_INFORMATION
 *
 *  Parameter Block Encoding   Description
 *  ========================== =========================================
 *
 *  USHORT InformationLevel;   Level of information requested
 *  ULONG Reserved;            Must be zero
 *  STRING FileName;           File or directory name
 *
 * The following InformationLevels may be requested:
 *
 *  Information Level                Value
 *
 *  ================================ =====
 *
 *  SMB_INFO_STANDARD                1
 *  SMB_INFO_QUERY_EA_SIZE           2
 *  SMB_INFO_QUERY_EAS_FROM_LIST     3
 *  SMB_INFO_QUERY_ALL_EAS           4
 *  SMB_INFO_IS_NAME_VALID           6
 *  SMB_QUERY_FILE_BASIC_INFO        0x101
 *  SMB_QUERY_FILE_STANDARD_INFO     0x102
 *  SMB_QUERY_FILE_EA_INFO           0x103
 *  SMB_QUERY_FILE_NAME_INFO         0x104
 *  SMB_QUERY_FILE_ALL_INFO          0x107
 *  SMB_QUERY_FILE_ALT_NAME_INFO     0x108
 *  SMB_QUERY_FILE_STREAM_INFO       0x109
 *  SMB_QUERY_FILE_COMPRESSION_INFO  0x10B
 *
 * The requested information is placed in the Data portion of the
 * transaction response.  For the information levels greater than 0x100,
 * the transaction response has 1 parameter word which should be ignored by
 * the client.
 *
 * The following sections describe the InformationLevel dependent encoding
 * of the data part of the transaction response.
 *
 * 4.2.14.1  SMB_INFO_STANDARD & SMB_INFO_QUERY_EA_SIZE
 *
 *  Data Block Encoding              Description
 *  ===============================  ====================================
 *
 *  SMB_DATE CreationDate;           Date when file was created
 *  SMB_TIME CreationTime;           Time when file was created
 *  SMB_DATE LastAccessDate;         Date of last file access
 *  SMB_TIME LastAccessTime;         Time of last file access
 *  SMB_DATE LastWriteDate;          Date of last write to the file
 *  SMB_TIME LastWriteTime;          Time of last write to the file
 *  ULONG  DataSize;                 File Size
 *  ULONG AllocationSize;            Size of filesystem allocation unit
 *  USHORT Attributes;               File Attributes
 *  ULONG EaSize;                    Size of file's EA information
 *                                   (SMB_INFO_QUERY_EA_SIZE)
 *
 * 4.2.14.2  SMB_INFO_QUERY_EAS_FROM_LIST & SMB_INFO_QUERY_ALL_EAS
 *
 *  Response Field       Value
 *  ==================== ===============================================
 *
 *  MaxDataCount         Length of EAlist found (minimum value is 4)
 *
 *  Parameter Block      Description
 *  Encoding             ===============================================
 *  ====================
 *
 *  USHORT EaErrorOffset Offset into EAList of EA error
 *
 *  Data Block Encoding  Description
 *  ==================== ===============================================
 *
 *  ULONG ListLength;    Length of the remaining data
 *  UCHAR EaList[]       The extended attributes list
 *
 * 4.2.14.3  SMB_INFO_IS_NAME_VALID
 *
 * This requests checks to see if the name of the file contained in the
 * request's Data field has a valid path syntax.  No parameters or data are
 * returned on this information request. An error is returned if the syntax
 * of the name is incorrect.  Success indicates the server accepts the path
 * syntax, but it does not ensure the file or directory actually exists.
 *
 * 4.2.14.4  SMB_QUERY_FILE_BASIC_INFO
 *
 *  Data Block Encoding              Description
 *  ===============================  ====================================
 *
 *  LARGE_INTEGER CreationTime;      Time when file was created
 *  LARGE_INTEGER LastAccessTime;    Time of last file access
 *  LARGE_INTEGER LastWriteTime;     Time of last write to the file
 *  LARGE_INTEGER ChangeTime         Time when file was last changed
 *  USHORT Attributes;               File Attributes
 *
 * 4.2.14.5  SMB_QUERY_FILE_STANDARD_INFO
 *
 *  Data Block Encoding              Description
 *  ===============================  ====================================
 *
 *  LARGE_INTEGER AllocationSize     Allocated size of the file in number
 *                                   of bytes
 *  LARGE_INTEGER EndofFile;         Offset to the first free byte in the
 *                                   file
 *  ULONG NumberOfLinks              Number of hard links to the file
 *  BOOLEAN DeletePending            Indicates whether the file is marked
 *                                   for deletion
 *  BOOLEAN Directory                Indicates whether the file is a
 *                                   directory
 *
 * 4.2.14.6  SMB_QUERY_FILE_EA_INFO
 *
 *  Data Block Encoding              Description
 *  ===============================  ====================================
 *
 *  ULONG EASize                     Size of the file's extended
 *                                   attributes in number of bytes
 *
 * 4.2.14.7  SMB_QUERY_FILE_NAME_INFO
 *
 *  Data Block Encoding              Description
 *  ===============================  ====================================
 *
 *  ULONG FileNameLength             Length of the file name in number of
 *                                   bytes
 *  STRING FileName                  Name of the file
 *
 * 4.2.14.8  SMB_QUERY_FILE_ALL_INFO
 *
 *  Data Block Encoding              Description
 *  ===============================  ====================================
 *
 *  LARGE_INTEGER CreationTime;      Time when file was created
 *  LARGE_INTEGER LastAccessTime;    Time of last file access
 *  LARGE_INTEGER LastWriteTime;     Time of last write to the file
 *  LARGE_INTEGER ChangeTime         Time when file was last changed
 *  USHORT Attributes;               File Attributes
 *  LARGE_INTEGER AllocationSize     Allocated size of the file in number
 *                                   of bytes
 *  LARGE_INTEGER EndofFile;         Offset to the first free byte in the
 *                                   file
 *  ULONG NumberOfLinks              Number of hard links to the file
 *  BOOLEAN DeletePending            Indicates whether the file is marked
 *                                   for deletion
 *  BOOLEAN Directory                Indicates whether the file is a
 *                                   directory
 *  LARGE_INTEGER Index Number       A file system unique identifier
 *  ULONG EASize                     Size of the file's extended
 *                                   attributes in number of bytes
 *  ULONG AccessFlags                Access that a caller has to the
 *                                   file; Possible values and meanings
 *                                   are specified below
 *  LARGE_INTEGER Index Number       A file system unique identifier
 *  LARGE_INTEGER CurrentByteOffset  Current byte offset within the file
 *  ULONG Mode                       Current Open mode of the file handle
 *                                   to the file; possible values and
 *                                   meanings are detailed below
 *  ULONG AlignmentRequirement       Buffer Alignment required by device;
 *                                   possible values detailed below
 *  ULONG FileNameLength             Length of the file name in number of
 *                                   bytes
 *  STRING FileName                  Name of the file
 *
 * The AccessFlags specifies the access permissions a caller has to the
 * file and can have any suitable combination of the following values:
 *
 *  Value                           Meaning
 *
 * ILE_READ_DATA        0x00000001 Data can be read from the file
 * ILE_WRITE_DATA       0x00000002 Data can be written to the file
 * ILE_APPEND_DATA      0x00000004 Data can be appended to the file
 * ILE_READ_EA          0x00000008 Extended attributes associated
 *                                  with the file can be read
 * ILE_WRITE_EA         0x00000010 Extended attributes associated
 *                                  with the file can be written
 * ILE_EXECUTE          0x00000020 Data can be read into memory from
 *                                  the file using system paging I/O
 * ILE_READ_ATTRIBUTES  0x00000080 Attributes associated with the
 *                                  file can be read
 * ILE_WRITE_ATTRIBUTES 0x00000100 Attributes associated with the
 *                                  file can be written
 * ELETE                0x00010000 The file can be deleted
 * EAD_CONTROL          0x00020000 The access control list and
 *                                  ownership associated with the
 *                                  file can be read
 * RITE_DAC             0x00040000 The access control list and
 *                                  ownership associated with the
 *                                  file can be written.
 * RITE_OWNER           0x00080000 Ownership information associated
 *                                  with the file can be written
 * YNCHRONIZE           0x00100000 The file handle can waited on to
 *                                  synchronize with the completion
 *                                  of an input/output request
 *
 * The Mode field specifies the mode in which the file is currently opened.
 * The possible values may be a suitable and logical combination of the
 * following:
 *
 * Value                                       Meaning
 *
 * FILE_WRITE_THROUGH           0x00000002     File is opened in mode
 *                                             where data is written to
 *                                             file before the driver
 *                                             completes a write request
 * FILE_SEQUENTIAL_ONLY         0x00000004     All access to the file is
 *                                             sequential
 * FILE_SYNCHRONOUS_IO_ALERT    0x00000010     All operations on the
 *                                             file are performed
 *                                             synchronously
 * FILE_SYNCHRONOUS_IO_NONALER  0x00000020     All operations on the
 * T                                           file are to be performed
 *                                             synchronously. Waits  in
 *                                             the system to synchronize
 *                                             I/O queuing and
 *                                             completion are not
 *                                             subject to alerts.
 *
 * The AlignmentRequirement field specifies buffer alignment required by
 * the device and can have any one of the following values:
 *
 *   Value                              Meaning
 *
 * FILE_BYTE_ALIGNMENT      0x00000000  The buffer needs to be aligned
 *                                      on a byte boundary
 * FILE_WORD_ALIGNMENT      0x00000001  The buffer needs to be aligned
 *                                      on a word boundary
 * FILE_LONG_ALIGNMENT      0x00000003  The buffer needs to be aligned
 *                                      on a 4 byte boundary
 * FILE_QUAD_ALIGNMENT      0x00000007  The buffer needs to be aligned
 *                                      on an 8 byte boundary
 * FILE_OCTA_ALIGNMENT      0x0000000f  The buffer needs to be aligned
 *                                      on a 16 byte boundary
 * FILE_32_BYTE_ALIGNMENT   0x0000001f  The buffer needs to be aligned
 *                                      on a 32 byte boundary
 * FILE_64_BYTE_ALIGNMENT   0x0000003f  The buffer needs to be aligned
 *                                      on a 64 byte boundary
 * FILE_128_BYTE_ALIGNMENT  0x0000007f  The buffer needs to be aligned
 *                                      on a 128 byte boundary
 * FILE_256_BYTE_ALIGNMENT  0x000000ff  The buffer needs to be aligned
 *                                      on a 256 byte boundary
 * FILE_512_BYTE_ALIGNMENT  0x000001ff  The buffer needs to be aligned
 *                                      on a 512 byte boundary
 *
 * 4.2.14.9  SMB_QUERY_FILE_ALT_NAME_INFO
 *
 *  Data Block Encoding   Description
 *  ===================== =================================
 *  ULONG FileNameLength  Length of the file name in number of bytes
 *  STRING FileName       Name of the file
 *
 * 4.2.14.10 SMB_QUERY_FILE_STREAM_INFO
 *
 *  Data Block Encoding              Description
 *  ===============================  ====================================
 *  ULONG NextEntryOffset            Offset to the next entry (in bytes)
 *  ULONG StreamNameLength           Length of the stream name in # of bytes
 *  LARGE_INTEGER StreamSize         Size of the stream in number of bytes
 *  LARGE_INTEGER AllocationSize     Allocated size of stream in bytes
 *  STRING FileName                  Name of the stream
 *
 * 4.2.14.11 SMB_QUERY_FILE_COMPRESSION_INFO
 *
 *  Data Block Encoding              Description
 *  ===============================  ====================================
 *  LARGE_INTEGER                    Size of the compressed file in
 *  CompressedFileSize               number of bytes
 *  USHORT CompressionFormat         compression algorithm used
 *  UCHAR CompressionUnitShift       Size of the stream in number of bytes
 *  UCHAR ChunkShift                 Allocated size of the stream in # of bytes
 *  UCHAR ClusterShift               Allocated size of the stream in # of bytes
 *  UCHAR Reserved[3]                Name of the stream
 *
 * typedef struct {
 *     LARGE_INTEGER CompressedFileSize;
 *     USHORT CompressionFormat;
 *     UCHAR CompressionUnitShift;
 *     UCHAR ChunkShift;
 *     UCHAR ClusterShift;
 *     UCHAR Reserved[3];
 * } FILE_COMPRESSION_INFORMATION;
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/msgbuf.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_fsops.h>

/*
 * Function: int smb_com_trans2_query_path_information(struct smb_request *)
 */
int
smb_com_trans2_query_path_information(struct smb_request *sr, struct smb_xa *xa)
{
	char			*path, *alt_nm_ptr;
	int			rc;
	u_offset_t		dsize, dused;
	unsigned short		infolev, dattr;
	smb_attr_t		*ap, ret_attr;
	struct smb_node		*dir_node;
	struct smb_node		*node;
	char			*name;
	char			*short_name;
	char			*name83;
	unsigned char		is_dir;
	int			len;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
		    ERROR_ACCESS_DENIED);
		/* NOTREACHED */
	}

	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	short_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	name83 = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	if (smb_decode_mbc(&xa->req_param_mb, "%w4.u", sr,
	    &infolev, &path) != 0) {
		kmem_free(name, MAXNAMELEN);
		kmem_free(short_name, MAXNAMELEN);
		kmem_free(name83, MAXNAMELEN);
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	/*
	 * Some MS clients pass NULL file names
	 * NT interprets this as "\"
	 */
	if ((len = strlen(path)) == 0)
		path = "\\";
	else {
		if ((len > 1) && (path[len - 1] == '\\')) {
			/*
			 * Remove the terminating slash to prevent
			 * sending back '.' instead of path name.
			 */
			path[len - 1] = 0;
		}
	}

	ap = &ret_attr;
	if ((rc = smb_pathname_reduce(sr, sr->user_cr, path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode, &dir_node, name))
	    != 0) {
		kmem_free(name, MAXNAMELEN);
		kmem_free(short_name, MAXNAMELEN);
		kmem_free(name83, MAXNAMELEN);
		smbsr_errno(sr, rc);
		/* NOTREACHED */
	}

	if ((rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    sr->tid_tree->t_snode, dir_node, name, &node, ap, short_name,
	    name83)) != 0) {
		smb_node_release(dir_node);
		kmem_free(name, MAXNAMELEN);
		kmem_free(short_name, MAXNAMELEN);
		kmem_free(name83, MAXNAMELEN);
		smbsr_errno(sr, rc);
		/* NOTREACHED */
	}
	smb_node_release(dir_node);
	(void) strcpy(name, node->od_name);

	dattr = smb_node_get_dosattr(node);
	if (ap->sa_vattr.va_type == VDIR) {
		is_dir = 1;
		/*
		 * Win2K and NT reply with the size of directory
		 * file.
		 */
		dsize = dused = 0;
	} else {
		is_dir = 0;
		dsize = ap->sa_vattr.va_size;
		dused = ap->sa_vattr.va_blksize * ap->sa_vattr.va_nblocks;
	}

	switch (infolev) {
	case SMB_INFO_STANDARD:
		if (dsize > UINT_MAX)
			dsize = UINT_MAX;
		if (dused > UINT_MAX)
			dused = UINT_MAX;

		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb,
		    ((sr->session->native_os == NATIVE_OS_WIN95)
		    ? "YYYllw" : "yyyllw"),
		    smb_gmt_to_local_time(ap->sa_crtime.tv_sec),
		    smb_gmt_to_local_time(ap->sa_vattr.va_atime.tv_sec),
		    smb_gmt_to_local_time(ap->sa_vattr.va_mtime.tv_sec),
		    (uint32_t)dsize,
		    (uint32_t)dused,
		    dattr);
		break;

	case SMB_INFO_QUERY_EA_SIZE:
		if (dsize > UINT_MAX)
			dsize = UINT_MAX;
		if (dused > UINT_MAX)
			dused = UINT_MAX;

		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb,
		    ((sr->session->native_os == NATIVE_OS_WIN95)
		    ? "YYYllwl" : "yyyllwl"),
		    smb_gmt_to_local_time(ap->sa_crtime.tv_sec),
		    smb_gmt_to_local_time(ap->sa_vattr.va_atime.tv_sec),
		    smb_gmt_to_local_time(ap->sa_vattr.va_mtime.tv_sec),
		    (uint32_t)dsize,
		    (uint32_t)dused,
		    dattr, 0);
		break;

	case SMB_INFO_QUERY_EAS_FROM_LIST:
	case SMB_INFO_QUERY_ALL_EAS:
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", 0);
		break;

	case SMB_INFO_IS_NAME_VALID:
		break;

	case SMB_QUERY_FILE_BASIC_INFO:
		/*
		 * NT includes 6 undocumented bytes at the end of this
		 * response, which are required by NetBench 5.01.
		 * Similar change in smb_trans2_query_file_information.c.
		 */
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "TTTTw6.",
		    &ap->sa_crtime,
		    &ap->sa_vattr.va_atime,
		    &ap->sa_vattr.va_mtime,
		    &ap->sa_vattr.va_ctime,
		    dattr);
		break;

	case SMB_QUERY_FILE_STANDARD_INFO:
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		/*
		 * Add 2 bytes to pad data to long. It is
		 * necessary because Win2k expects the padded bytes.
		 */
		(void) smb_encode_mbc(&xa->rep_data_mb, "qqlbb2.",
		    dused,
		    dsize,
		    ap->sa_vattr.va_nlink,
		    (node && (node->flags & NODE_FLAGS_DELETE_ON_CLOSE) != 0),
		    (char)(ap->sa_vattr.va_type == VDIR));
		break;

	case SMB_QUERY_FILE_EA_INFO:
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", 0);
		break;

	case SMB_QUERY_FILE_NAME_INFO:
		/*
		 * If you have problems here, see the changes
		 * in smb_trans2_query_file_information.c.
		 */
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "%lu", sr,
		    smb_ascii_or_unicode_strlen(sr, name), name);
		break;

	case SMB_QUERY_FILE_ALL_INFO:
		/*
		 * The reply of this information level on the
		 * wire doesn't match with protocol specification.
		 * This is what spec. needs: "TTTTwqqlbbqllqqll"
		 * But this is actually is sent on the wire:
		 * "TTTTw6.qqlbb2.l"
		 * So, there is a 6-byte pad between Attributes and
		 * AllocationSize. Also there is a 2-byte pad After
		 * Directory field. Between Directory and FileNameLength
		 * there is just 4 bytes that it seems is AlignmentRequirement.
		 * There are 6 other fields between Directory and
		 * AlignmentRequirement in spec. that aren't sent
		 * on the wire.
		 */
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "TTTTw6.qqlbb2.l",
		    &ap->sa_crtime,
		    &ap->sa_vattr.va_atime,
		    &ap->sa_vattr.va_mtime,
		    &ap->sa_vattr.va_ctime,
		    dattr,
		    dused,
		    dsize,
		    ap->sa_vattr.va_nlink,
		    0,
		    is_dir,
		    0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "%lu", sr,
		    smb_ascii_or_unicode_strlen(sr, name), name);
		break;

	case SMB_QUERY_FILE_ALT_NAME_INFO:
		/*
		 * Conform to the rule used by Windows NT/2003 servers.
		 * Shortname is created only if either the filename or
		 * extension portion of a file is made up of mixed case.
		 *
		 * If the shortname is generated, it will be returned as
		 * the alternative name.  Otherwise, converts the original
		 * name to all upper-case and returns it as the alternative
		 * name.  This is how Windows NT/2003 servers behave.  However,
		 * Windows 2000 seems to preserve the case of the original
		 * name, and returns it as the alternative name.
		 *
		 * Note: The shortname is returned by smb_fsop_lookup(), above.
		 * In the case that the name used by the client was originally
		 * generated in response to a case-insensitive collision, the
		 * short_name and the 8.3 name will reflect this.
		 */
		alt_nm_ptr = ((*short_name == 0) ?
		    utf8_strupr(name) : short_name);
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "%lu", sr,
		    smb_ascii_or_unicode_strlen(sr, alt_nm_ptr), alt_nm_ptr);
		break;

	case SMB_QUERY_FILE_STREAM_INFO:
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		smb_encode_stream_info(sr, xa, node, ap);
		break;

	case SMB_QUERY_FILE_COMPRESSION_INFO:
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb,
		    "qwbbb3.", dsize, 0, 0, 0, 0);
		break;

	default:
		smb_node_release(node);
		kmem_free(name, MAXNAMELEN);
		kmem_free(short_name, MAXNAMELEN);
		kmem_free(name83, MAXNAMELEN);
		smbsr_error(sr, 0, ERRDOS, ERRunknownlevel);
		/* NOTREACHED */
		break;
	}
	smb_node_release(node);
	kmem_free(name, MAXNAMELEN);
	kmem_free(short_name, MAXNAMELEN);
	kmem_free(name83, MAXNAMELEN);
	return (SDRC_NORMAL_REPLY);
}
