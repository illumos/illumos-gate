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

#ifndef	_ISNS_DD_H
#define	_ISNS_DD_H

#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t bmp_t;

/*
 * dd matrix
 */
typedef struct matrix {
	uint32_t x, y;
	/* uint32_t *z; */ /* obsoleted- map between uid & mid */
	/* rwlock_t l; */ /* obsoleted */
	bmp_t *m;
	struct cache *c;
} matrix_t;

#define	MATRIX_X_HEADER		(1)
#define	MATRIX_X_INFO(X)	(X[0])

#define	SIZEOF_X_UNIT(M)	(((M)->x + MATRIX_X_HEADER) * sizeof (bmp_t))
#define	MATRIX_X_UNIT(M, N)	&(M)->m[(N) * ((M)->x + MATRIX_X_HEADER)]

#define	NUM_OF_MEMBER(M)	((M)->x * sizeof (bmp_t) * 8)
#define	UID2MID(M, UID)		get_mid(M, UID)
#define	NEW_MID(M, UID)		new_mid(M, UID)

#define	GET_PRIMARY(UID)	(UID) / (sizeof (bmp_t) * 8)
#define	GET_SECOND(UID)		(UID) % (sizeof (bmp_t) * 8)
#define	COMP_UID(PRI, SND)	((PRI) * sizeof (bmp_t) * 8 + (SND))

#define	SET_MEMBERSHIP(BMP, PRI, SND)	\
	(BMP)[(PRI) + MATRIX_X_HEADER] |= (0x1 << (SND))
#define	CLEAR_MEMBERSHIP(BMP, PRI, SND)	\
	(BMP)[(PRI) + MATRIX_X_HEADER] &= ~(0x1 << (SND))

#define	TEST_MEMBERSHIP(BMP, PRI, SEC) \
	((BMP)[(PRI) + MATRIX_X_HEADER] & (0x1 << (SEC)))

#define	FOR_EACH_MEMBER(BMP, NUM, UID, STMT) \
{\
	int i1624 = 0;\
	while (i1624 < (NUM)) {\
		int j1624 = 0;\
		while (j1624 < 8 * sizeof ((BMP)[0])) {\
			if (((BMP)[i1624] & (1 << j1624)) != 0) {\
				UID = COMP_UID(i1624, j1624);\
				STMT\
			}\
			j1624 ++;\
		}\
		i1624 ++;\
	}\
}

/* functions */
int dd_matrix_init(struct cache *);
int create_dd_object(isns_tlv_t *, uint16_t, isns_obj_t **);
int create_dds_object(isns_tlv_t *, uint16_t, isns_obj_t **);
int adm_create_dd(isns_obj_t **, uchar_t *, uint32_t, uint32_t);
int adm_create_dds(isns_obj_t **, uchar_t *, uint32_t, uint32_t);
int update_dd_name(uint32_t, uint32_t, uchar_t *);
int update_dds_name(uint32_t, uint32_t, uchar_t *);
int update_dd_features(uint32_t, uint32_t);
int update_dds_status(uint32_t, uint32_t);
uint32_t get_dd_id(uint32_t, uint32_t);
uint32_t get_dds_id(uint32_t, uint32_t);
uint32_t get_common_dd(uint32_t, uint32_t, uint32_t);
int remove_dd_object(uint32_t);
int remove_dds_object(uint32_t);
int add_dd_member(isns_obj_t *);
int add_dds_member(isns_obj_t *);
int remove_dd_member(isns_obj_t *);
int remove_dds_member(uint32_t, uint32_t);
int get_dd_matrix(const uint32_t, bmp_t **, uint32_t *);
int get_dds_matrix(const uint32_t, bmp_t **, uint32_t *);
int get_scope(uchar_t *, bmp_t **, uint32_t *);
int cb_clone_attrs(void *, void *);
int is_dd_active(uint32_t);
int update_ddd(void *, const uchar_t);
int verify_ddd(void);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_DD_H */
