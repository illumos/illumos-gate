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

#ifndef	_STMF_SBD_H
#define	_STMF_SBD_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	SBD_FAILURE		STMF_LU_FAILURE
#define	SBD_FILEIO_FAILURE	(SBD_FAILURE | STMF_FSC(1))

/*
 * if the function pointers to write metadata are NULL, then sbd assumes that
 * metadata and LU data share the same store. In that case sbd sets aside
 * some space for metadata and adjusts the LU size reported to initiators
 * accordingly.
 */
typedef	struct sbd_store {
	void		*sst_sbd_private;
	void		*sst_store_private;
	char		*sst_alias;

	stmf_status_t	(*sst_online)(struct sbd_store *sst);
	stmf_status_t	(*sst_offline)(struct sbd_store *sst);
	stmf_status_t	(*sst_deregister_lu)(struct sbd_store *sst);

	stmf_status_t	(*sst_data_read)(struct sbd_store *sst,
				uint64_t offset, uint64_t size, uint8_t *buf);
	stmf_status_t	(*sst_data_write)(struct sbd_store *sst,
				uint64_t offset, uint64_t size, uint8_t *buf);
	stmf_status_t	(*sst_data_flush)(struct sbd_store *sst);

	stmf_status_t	(*sst_meta_read)(struct sbd_store *sst,
				uint64_t offset, uint64_t size, uint8_t *buf);
	stmf_status_t	(*sst_meta_write)(struct sbd_store *sst,
				uint64_t offset, uint64_t size, uint8_t *buf);
} sbd_store_t;

typedef struct sst_init_data {
	uint64_t	sst_store_size;		/* Total size of the store */

	/*
	 * This is the metadat for the store implementation itself
	 * that needs to be persisted.
	 */
	uint64_t	sst_store_meta_data_size;

	/* This is returned to the caller */
	uint8_t		sst_guid[16];

	uint32_t	sst_flags;
	uint16_t	sst_blocksize;		/* To expose to initiators */
} sst_init_data_t;

/*
 * sst_flags.
 */
#define	SST_NOT_PERSISTENT	0x0001
#define	SST_READONLY_DATA	0x0002

sbd_store_t *sbd_sst_alloc(uint32_t additional_size, uint32_t flags);
void sbd_sst_free(sbd_store_t *sst);
stmf_status_t sbd_create_meta(sbd_store_t *sst, sst_init_data_t *sst_idata);
stmf_status_t sbd_modify_meta(sbd_store_t *sst, sst_init_data_t *sst_idata);
stmf_status_t sbd_register_sst(sbd_store_t *sst, sst_init_data_t *sst_idata);
stmf_status_t sbd_deregister_sst(sbd_store_t *sst);

#ifdef	__cplusplus
}
#endif

#endif /* _STMF_SBD_H */
