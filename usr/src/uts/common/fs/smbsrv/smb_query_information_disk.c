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
 * SMB: query_information_disk
 *
 * The SMB_COM_QUERY_INFORMATION_DISK command is used to determine the
 * capacity and remaining free space on the drive hosting the directory
 * structure indicated by Tid in the SMB header.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 5
 * USHORT TotalUnits;                 Total allocation units per server
 * USHORT BlocksPerUnit;              Blocks per allocation unit
 * USHORT BlockSize;                  Block size (in bytes)
 * USHORT FreeUnits;                  Number of free units
 * USHORT Reserved;                   Reserved (client should ignore)
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * The blocking/allocation units used in this response may be independent
 * of the actual physical or logical blocking/allocation algorithm(s) used
 * internally by the server.  However, they must accurately reflect the
 * amount of space on the server.
 *
 * This SMB only returns 16 bits of information for each field, which may
 * not be large enough for some disk systems.  In particular TotalUnits is
 * commonly > 64K.  Fortunately, it turns out the all the client cares
 * about is the total disk size, in bytes, and the free space, in bytes.
 * So,  it is reasonable for a server to adjust the relative values of
 * BlocksPerUnit and BlockSize to accommodate.  If after all adjustment,
 * the numbers are still too high, the largest possible values for
 * TotalUnit or FreeUnits (i.e. 0xFFFF) should be returned.
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

smb_sdrc_t
smb_com_query_information_disk(struct smb_request *sr)
{
	int			rc;
	struct statvfs64	df;
	fsblkcnt64_t		total_blocks, free_blocks;
	unsigned long		block_size, unit_size;
	unsigned short		blocks_per_unit, bytes_per_block;
	unsigned short		total_units, free_units;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS, ERRnoaccess);
		return (SDRC_ERROR_REPLY);
	}

	rc = smb_fsop_statfs(sr->user_cr, sr->tid_tree->t_snode, &df);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR_REPLY);
	}

	unit_size = 1;
	block_size = df.f_frsize;
	total_blocks = df.f_blocks;
	free_blocks = df.f_bavail;

	/*
	 * It seems that DOS clients cannot handle block sizes
	 * bigger than 512 KB. So we have to set the block size at
	 * most to 512
	 */

	while (block_size > 512) {
		block_size >>= 1;
		unit_size <<= 1;
	}

	/* adjust blocks and sizes until they fit into a word */

	while (total_blocks >= 0xFFFF) {
		total_blocks >>= 1;
		free_blocks >>= 1;
		if ((unit_size <<= 1) > 0xFFFF) {
			unit_size >>= 1;
			total_blocks = 0xFFFF;
			free_blocks <<= 1;
			break;
		}
	}

	total_units = (total_blocks >= 0xFFFF) ?
	    0xFFFF : (unsigned short)total_blocks;
	free_units = (free_blocks >= 0xFFFF) ?
	    0xFFFF : (unsigned short)free_blocks;
	bytes_per_block = (unsigned short)block_size;
	blocks_per_unit = (unsigned short)unit_size;

	rc = smbsr_encode_result(sr, 5, 0, "bwwww2.w",
	    5,
	    total_units,	/* total_units */
	    blocks_per_unit,	/* blocks_per_unit */
	    bytes_per_block,	/* blocksize */
	    free_units,		/* free_units */
	    0);			/* bcc */

	return ((rc == 0) ? SDRC_NORMAL_REPLY : SDRC_ERROR_REPLY);
}
