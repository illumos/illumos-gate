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

/*
 * SES State definitions
 */

/*
 * I18N message number ranges
 *  This file: 16500 - 16999
 *  Shared common messages: 1 - 1999
 */

#ifndef	_A_STATE_H
#define	_A_STATE_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Include any headers you depend on.
 */
#include	<sys/fibre-channel/fcio.h>
#define	_SYS_FC4_FCAL_LINKAPP_H
#include	<sys/fc4/fcio.h>
#include <gfc.h>
#include <g_state.h>
#include <a5k.h>

/*
 * Definitions for send/receive diagnostic command
 */
#define	HEADER_LEN		4
#define	MAX_REC_DIAG_LENGTH	0xfffe



typedef struct	rec_diag_hdr {
	uchar_t		page_code;
	uchar_t		sub_enclosures;
	ushort_t	page_len;
} Rec_diag_hdr;

/* struct for list of gfc_map_t */
typedef struct gfc_map_mp {
	gfc_map_t   map;
	struct gfc_map_mp *map_next;
} gfc_map_mp_t;

/*
 * We should use the scsi_capacity structure in impl/commands.h
 * but it uses u_long's to define 32 bit values.
 */
typedef	struct	capacity_data_struct {
	uint_t	last_block_addr;
	uint_t	block_size;
} Read_capacity_data;

/* Function prototypes defined for liba5k modules */
/* diag.c */
extern int	l_dev_bypass_enable(struct  path_struct *, int, int,
		int, int);
extern int	l_bp_bypass_enable(char *, int, int, int, int, int);
extern int	d_p_enable(char *, int);
extern int	d_p_bypass(char *, int);

/* lhot.c */
extern int	is_null_wwn(uchar_t *);

/* mon.c */
extern int	l_ex_open_test(struct dlist *, char *, int);
extern int	l_get_conflict(char *, char **, int);
extern int	l_new_password(char *, char *);
extern int	l_get_mode_pg(char *, uchar_t **, int);
extern void	l_element_msg_string(uchar_t, char *);
extern int	l_check_file(char *, int);
extern int	l_get_pid_from_path(const char *, const gfc_map_t *, int *);

#ifdef	__cplusplus
}
#endif

#endif	/* _A_STATE_H */
