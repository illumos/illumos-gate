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

#ifndef _T10_SBC_H
#define	_T10_SBC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SBC-2 specific structures and defines
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	SBC_CAPACITY_PMI	0x01

#define	SBC_SYNC_CACHE_IMMED	0x02
#define	SBC_SYNC_CACHE_NV	0x04

/*
 * SBC-2 revision 16, section 5.20 - VERIFY command.
 * Bits found in the CDB.
 */
/* --- Bits found in byte 1 --- */
#define	SBC_VRPROTECT_MASK	0xe0
#define	SBC_DPO			0x10
#define	SBC_BYTCHK		0x02
/* --- Bits found in byte 6 --- */
#define	SBC_GROUP_MASK		0x1f

/*
 * SBC-2 revision 16, section 5.17 START_STOP
 * Table 49 -- POWER CONDITION field
 */
#define	SBC_PWR_MASK		0xf0
#define	SBC_PWR_SHFT		4
#define	SBC_PWR_START_VALID	0x00
#define	SBC_PWR_ACTIVE		0x01
#define	SBC_PWR_IDLE		0x02
#define	SBC_PWR_STANDBY		0x03
#define	SBC_PWR_OBSOLETE	0x05	/* JIST checks this one */
#define	SBC_PWR_LU_CONTROL	0x07
#define	SBC_PWR_FORCE_IDLE_0	0x0a
#define	SBC_PWR_FORCE_STANDBY_0	0x0b
#define	SBC_PWR_LOEJ		0x02
#define	SBC_PWR_START		0x01

typedef struct disk_params {
	/*
	 * Size of LUN in blocks
	 */
	diskaddr_t	d_size;

	/*
	 * Number of bytes per section. This will probably
	 * Become vary important for the T10 Data Integrity
	 * Stuff.
	 */
	uint32_t	d_bytes_sect;
	uint32_t	d_heads,
			d_spt,
			d_cyl;
	/*
	 * Another bogus values.
	 */
	uint32_t	d_rpm,
			d_interleave;

	/*
	 * This lock protects access to both the d_mmap_overlaps AVL tree
	 * and use of the reserved disk_io buffer when memory is exhausted.
	 */
	pthread_mutex_t	d_mutex;

	/*
	 * When using mmap backing store it's possible for an application
	 * to issue a read and a write command of the same block without
	 * first waiting for the read to complete. Since we pass the address
	 * to the mmap area back to the transport and continue it's possible
	 * to start processing the write command which will change the data
	 * before the read has completed. To prevent this condition read
	 * commands store their data address and length into the avl tree.
	 * The write command will see if it's potential address is the same
	 * as one of the read commands. If so, the write command will pause
	 * until the read completes.
	 */
	avl_tree_t	d_mmap_overlaps;
	pthread_cond_t	d_mmap_cond;
	Boolean_t	d_mmap_paused;

	pthread_cond_t	d_io_cond;
	Boolean_t	d_io_need;
	Boolean_t	d_io_used;
	struct disk_io	*d_io_reserved;

	Boolean_t	d_fast_write;
	t10_lu_state_t	d_state;
	sbc_reserve_t	d_sbc_reserve;
} disk_params_t;

typedef struct disk_io {
	/*
	 * This structure needs to be the first member. The first member
	 * of this structure is an aio_result_t. If we need to issue
	 * an aio request a generic handler is called for all aio requests.
	 * To allow this generic handler a means to callback to the appropriate
	 * emulation routines a generic header is used. The generic handler
	 * can cast the pointer returned from aiowait to a t10_aio_t structure.
	 * From there it can determine the call back routine and pass it
	 * a specific pointer.
	 */
	t10_aio_t	da_aio;

	/*
	 * Communication with the SAM-3 layer requires us to send back this
	 * pointer which was passed in at the command start.
	 */
	t10_cmd_t	*da_cmd;

	/*
	 * (1) During AIO operations we need to allocate space to hold the
	 *    data. This pointer represents that data which will be freed
	 *    from our callback (argument to trans_send_datain) after the
	 *    transport has finished with it.
	 * (2) During mmap ops the memory address of the requested data block
	 *    will be stored here along with the transfer size. This will
	 *    be used by the overlap protection to see if we must hold
	 *    off a write op.
	 */
	char		*da_data;
	size_t		da_data_len;

	/*
	 * True if da_data has been malloc'd verses mmap and therefore
	 * we need to free it when the free routine is called.
	 */
	Boolean_t	da_data_alloc;

	/*
	 * True if an overlap value was stored which needs to be cleared.
	 */
	Boolean_t	da_clear_overlap;

	/*
	 * If we're breaking up the transfer to comply with max_out
	 * then da_offset indicates where in the transfer we're currently
	 * at.
	 */
	uint64_t	da_offset;

	/*
	 * This is the LBA of a SCSI READ or WRITE command. Once decoded
	 * from the cdb we don't want to recompute it each time it's needed
	 * in the different phases.
	 */
	diskaddr_t	da_lba;
	size_t		da_lba_cnt;

	disk_params_t	*da_params;

	/*
	 * Normal command overlap protection is done by the SAM-3 layer.
	 * This overlap is to prevent a write op from changing data before
	 * an existing read op has transmitted the data.
	 */
	avl_node_t	da_mmap_overlap;
} disk_io_t;

#ifdef __cplusplus
}
#endif

#endif /* _T10_SBC_H */
