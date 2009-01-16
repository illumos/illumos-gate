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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PX_MSI_H
#define	_SYS_PX_MSI_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * MSI data structure.
 */
typedef struct px_msi {
	dev_info_t	*msi_dip;	/* MSI consumer dip */
	int		msi_inum;	/* INUM for this device */
	uint_t		msi_state;	/* MSI alloc state */
	msinum_t	msi_msinum;	/* MSI number */
	msiqid_t	msi_msiq_id;	/* MSIQ used */
} px_msi_t;

#define	MSI_STATE_FREE		0x1
#define	MSI_STATE_INUSE		0x2

/*
 * MSI soft state structure.
 */
typedef struct px_msi_state {
	uint_t		msi_cnt;	/* No of MSIs */
	msinum_t	msi_1st_msinum;	/* First MSI number */
	uint_t		msi_data_mask;	/* MSI data mask */
	uint_t		msi_data_width; /* MSI data width */
	uint64_t	msi_addr32;	/* MSI 32 address */
	uint64_t	msi_addr32_len; /* MSI 32 length */
	uint64_t	msi_addr64;	/* MSI 64 address */
	uint64_t	msi_addr64_len; /* MSI 64 length */

	px_msi_t	*msi_p;		/* Pointer to MSIs array */
	kmutex_t	msi_mutex;	/* Mutex for MSI alloc/free */
	uint_t		msi_type;	/* MSI or MSI-X */
	boolean_t	msi_mem_flg;	/* TRUE if driver allocates memory */

	ddi_irm_pool_t	*msi_pool_p;	/* IRM Pool */
} px_msi_state_t;

/*
 * px_msi_ranges
 */
typedef struct px_msi_ranges {
	int	msi_no;
	int	no_msis;
} px_msi_ranges_t;

/*
 * px_msi_address_ranges
 */
typedef struct px_msi_address_ranges {
	uint32_t	msi_addr32_hi;
	uint32_t	msi_addr32_lo;
	uint32_t	msi_addr32_len;
	uint32_t	msi_addr64_hi;
	uint32_t	msi_addr64_lo;
	uint32_t	msi_addr64_len;
} px_msi_address_ranges_t;

#define	PX_MSI_WIDTH			16
#define	PX_MSIX_WIDTH			32

/*
 * Default MSI configurations
 */
#define	PX_DEFAULT_MSI_CNT		256
#define	PX_DEFAULT_MSI_1ST_MSINUM	0
#define	PX_DEFAULT_MSI_DATA_MASK	0xff
#define	PX_DEFAULT_MSI_DATA_WIDTH	PX_MSIX_WIDTH

#define	PX_MSI_4GIG_LIMIT		0xFFFFFFFFUL
#define	PX_MSI_ADDR_LEN			0x10000	/* 64K bytes */

extern	int	px_msi_attach(px_t *px_p);
extern	void	px_msi_detach(px_t *px_p);

extern	int	px_msi_alloc(px_t *px_p, dev_info_t *rdip, int type, int inum,
		    int msi_count, int flag, int *actual_msi_count_p);
extern	int	px_msi_free(px_t *px_p, dev_info_t *rdip, int inum,
		    int msi_count);

extern	int	px_msi_get_msinum(px_t *px_p, dev_info_t *rdip,
		    int inum, msinum_t *msi_num_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_MSI_H */
