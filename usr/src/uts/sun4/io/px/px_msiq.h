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

#ifndef	_SYS_PX_MSIQ_H
#define	_SYS_PX_MSIQ_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * MSIQ data structure.
 */
struct px_msiq {
	msiqid_t	msiq_id;	/* MSIQ ID */
	ushort_t	msiq_state;	/* MSIQ alloc state */
	ushort_t	msiq_refcnt;	/* # of MSIQ users */
	msiqhead_t	*msiq_base_p;	/* MSIQ base pointer */

	/* Fields accessed under interrupt context */
	msiqhead_t	msiq_curr_head_index; /* MSIQ Curr head index */
	msiqhead_t	msiq_new_head_index; /* MSIQ new head index */
	ushort_t	msiq_recs2process; /* # of MSIQ records to process */
};

#define	MSIQ_STATE_FREE		0x1
#define	MSIQ_STATE_INUSE	0x2

/*
 * MSIQ soft state structure.
 */
typedef struct px_msiq_state {
	/* Available MSIQs */
	uint_t		msiq_cnt;	/* # of MSIQs */
	uint_t		msiq_rec_cnt;	/* # of records per MSIQ */
	msiqid_t	msiq_1st_msiq_id; /* First MSIQ ID */
	devino_t	msiq_1st_devino; /* First devino */
	boolean_t	msiq_redist_flag; /* Flag to redist MSIQs */

	/* MSIQs specific reserved for MSI/Xs */
	uint_t		msiq_msi_qcnt;	/* # of MSIQs for MSI/Xs */
	msiqid_t	msiq_1st_msi_qid; /* First MSIQ ID for MSI/Xs */

	/* MSIQs specific reserved for PCIe messages */
	uint_t		msiq_msg_qcnt;	/* # of MSIQs for PCIe msgs */
	msiqid_t	msiq_1st_msg_qid; /* First MSIQ ID for PCIe msgs */

	px_msiq_t	*msiq_p;	/* Pointer to MSIQs array */
	void		*msiq_buf_p; /* Pointer to MSIQs array */
	kmutex_t	msiq_mutex;	/* Mutex for MSIQ alloc/free */
} px_msiq_state_t;

/*
 * px_msi_eq_to_devino
 */
typedef struct px_msi_eq_to_devino {
	int	msi_eq_no;
	int	no_msi_eqs;
	int	devino_no;
} px_msi_eq_to_devino_t;

/*
 * Default MSIQ Configurations
 */
#define	PX_DEFAULT_MSIQ_CNT		36
#define	PX_DEFAULT_MSIQ_REC_CNT		128
#define	PX_DEFAULT_MSIQ_1ST_MSIQ_ID	0
#define	PX_DEFAULT_MSIQ_1ST_DEVINO	24

extern	int	px_msiq_attach(px_t *px_p);
extern	void	px_msiq_detach(px_t *px_p);
extern	void	px_msiq_resume(px_t *px_p);

extern	int	px_msiq_alloc(px_t *px_p, msiq_rec_type_t rec_type,
		    msgcode_t msg_code, msiqid_t *msiq_id_p);
extern	int	px_msiq_alloc_based_on_cpuid(px_t *px_p,
		    msiq_rec_type_t rec_type, cpuid_t cpuid,
		    msiqid_t *msiq_id_p);
extern	int	px_msiq_free(px_t *px_p, msiqid_t msiq_id);
extern	void	px_msiq_redist(px_t *px_p);

extern  devino_t px_msiqid_to_devino(px_t *px_p, msiqid_t msiq_id);
extern  msiqid_t px_devino_to_msiqid(px_t *px_p, devino_t devino);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_MSIQ_H */
