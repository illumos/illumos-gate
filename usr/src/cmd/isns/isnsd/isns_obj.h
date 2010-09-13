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

#ifndef	_ISNS_OBJ_H
#define	_ISNS_OBJ_H

#ifdef __cplusplus
extern "C" {
#endif

#define	ENTITY_KEY		ISNS_EID_ATTR_ID
#define	ISCSI_KEY		ISNS_ISCSI_NAME_ATTR_ID
#define	PORTAL_KEY1		ISNS_PORTAL_IP_ADDR_ATTR_ID
#define	PORTAL_KEY2		ISNS_PORTAL_PORT_ATTR_ID
#define	PG_KEY1			ISNS_PG_ISCSI_NAME_ATTR_ID
#define	PG_KEY2			ISNS_PG_PORTAL_IP_ADDR_ATTR_ID
#define	PG_KEY3			ISNS_PG_PORTAL_PORT_ATTR_ID
#define	PG_PGT			ISNS_PG_TAG_ATTR_ID
#define	DD_KEY			ISNS_DD_ID_ATTR_ID
#define	DDS_KEY			ISNS_DD_SET_ID_ATTR_ID

#define	ENTITY_END		ISNS_ENTITY_CERT_ATTR_ID
#define	ISCSI_END		ISNS_ISCSI_AUTH_METHOD_ATTR_ID
#define	PORTAL_END		ISNS_PORTAL_CERT_ATTR_ID
#define	PG_END			ISNS_PG_NEXT_ID_ATTR_ID
#define	DD_END			ISNS_DD_FEATURES_ATTR_ID
#define	DDS_END			ISNS_DD_SET_STATUS_ATTR_ID

#define	IS_ENTITY_KEY(ID)	((ID) == ENTITY_KEY)
#define	IS_ISCSI_KEY(ID)	((ID) == ISCSI_KEY)
#define	IS_PORTAL_KEY1(ID)	((ID) == PORTAL_KEY1)
#define	IS_PORTAL_KEY2(ID)	((ID) == PORTAL_KEY2)
#define	IS_PG_KEY1(ID)		((ID) == PG_KEY1)
#define	IS_PG_KEY2(ID)		((ID) == PG_KEY2)
#define	IS_PG_KEY3(ID)		((ID) == PG_KEY3)
#define	IS_PG_PGT(ID)		((ID) == PG_PGT)

#define	IS_ENTITY_ATTR(ID) \
	((ID) > ENTITY_KEY && (ID) <= ENTITY_END)
#define	IS_ISCSI_ATTR(ID) \
	((ID) > ISCSI_KEY && (ID) <= ISCSI_END)
#define	IS_PORTAL_ATTR(ID) \
	((ID) > PORTAL_KEY2 && (ID) <= PORTAL_END)
#define	IS_PG_ATTR(ID) \
	((ID) > PG_KEY1 && (ID) <= PG_END)

/* functions */
int obj_tab_init(struct cache *);

uint32_t set_obj_uid(void *, uint32_t);
int extract_attr(isns_attr_t *, const isns_tlv_t *, int);
int assign_attr(isns_attr_t *, const isns_attr_t *);
void free_one_object(isns_obj_t *);
void free_object(isns_obj_t *);
isns_obj_t *obj_calloc(int);
isns_obj_t *make_default_entity();
int reg_get_entity(
	isns_obj_t **,
	isns_tlv_t **,
	uint16_t *
);
int reg_get_obj(
	isns_obj_t **,
	isns_attr_t *,
	isns_tlv_t **,
	uint16_t *
);
int reg_auth_src(isns_type_t, uint32_t, uchar_t *);
int set_parent_obj(isns_obj_t *, uint32_t);
int buff_child_obj(const isns_type_t, const isns_type_t,
	const void *, void const***);
int update_child_obj(const isns_type_t, const uint32_t,
	void const***, int);
int update_ref_obj(const isns_obj_t *);
int verify_ref_obj(const isns_type_t, const uint32_t,
	void const***);
int update_deref_obj(isns_obj_t *);
uint32_t set_child_number(isns_obj_t *, int, uint16_t);

int key_cmp(lookup_ctrl_t *, isns_obj_t *);
int register_object(isns_obj_t *, uint32_t *, int *);
int register_assoc(isns_obj_t *, uint32_t *);
int dereg_assoc(lookup_ctrl_t *);
int dereg_object(lookup_ctrl_t *, int);
int dereg_downwards(isns_obj_t *);
int data_sync(int);

uint32_t obj_hval(void *, uint16_t, uint32_t *);
int is_obj_equal(isns_obj_t *, isns_obj_t *);
uint32_t get_obj_uid(const void *);
uint32_t is_obj_there(lookup_ctrl_t *);
uint32_t is_parent_there(uchar_t *);
void *assoc_clone(void *, int);
int obj_cmp(void *, void *, int);
int add_object(void *);
int replace_object(void *, void *, uint32_t *, int);
#ifdef DEBUG
void obj_dump(void *);
uint32_t *get_child_n(isns_obj_t *, int);
uint32_t get_ref_n(isns_obj_t *, int);
#endif
uint32_t get_ref_t(isns_obj_t *, isns_type_t);

uint32_t *const get_parent_p(const isns_obj_t *);
uint32_t get_parent_uid(const isns_obj_t *);
uint32_t *get_child_t(isns_obj_t *, int);
int is_obj_online(const isns_obj_t *);

uint32_t get_timestamp(void);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_OBJ_H */
