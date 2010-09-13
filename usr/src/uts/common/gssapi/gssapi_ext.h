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
 *
 * Private extensions and utilities to the GSS-API.
 * These are not part of the GSS-API specification
 * but may be useful to GSS-API users.
 */

#ifndef _GSSAPI_EXT_H
#define	_GSSAPI_EXT_H

#include <gssapi/gssapi.h>
#ifdef	_KERNEL
#include <sys/systm.h>
#else
#include <strings.h>
#endif


#ifdef	__cplusplus
extern "C" {
#endif

/* MACRO for comparison of gss_OID's */
#define	g_OID_equal(o1, o2) \
	(((o1)->length == (o2)->length) && \
	(memcmp((o1)->elements, (o2)->elements, (int)(o1)->length) == 0))


/*
 * MACRO for copying of OIDs - memory must already be allocated
 * o2 is copied to o1
 */
#define	g_OID_copy(o1, o2) \
	bcopy((o2)->elements, (o1)->elements, (o2)->length);\
	(o1)->length = (o2)->length;


/* MACRO to check if input buffer is valid */
#define	GSS_EMPTY_BUFFER(buf)	((buf) == NULL ||\
	(buf)->value == NULL || (buf)->length == 0)


/*
 * GSSAPI Extension functions -- these functions aren't
 * in the GSSAPI specification, but are provided in our
 * GSS library.
 */

#ifndef	_KERNEL

/*
 * qop configuration file handling.
 */
#define	MAX_QOP_NUM_PAIRS	128
#define	MAX_QOPS_PER_MECH	128

typedef struct _qop_num {
	char *qop;
	OM_uint32 num;
	char *mech;
} qop_num;

OM_uint32
__gss_qop_to_num(
	char		*qop,		/* input qop string */
	char		*mech,		/* input mech string */
	OM_uint32	*num		/* output qop num */
);

OM_uint32
__gss_num_to_qop(
	char		*mech,		/* input mech string */
	OM_uint32	num,		/* input qop num */
	char		**qop		/* output qop name */
);

OM_uint32
__gss_get_mech_info(
	char		*mech,		/* input mech string */
	char		**qops		/* buffer for return qops */
);

OM_uint32
__gss_mech_qops(
	char *mech,			/* input mech */
	qop_num *mech_qops,		/* mech qops buffer */
	int *numqops			/* buffer to return numqops */
);

OM_uint32
__gss_mech_to_oid(
	const char *mech,		/* mechanism string name */
	gss_OID *oid			/* mechanism oid */
);

const char *
__gss_oid_to_mech(
	const gss_OID oid		/* mechanism oid */
);

OM_uint32
__gss_get_mechanisms(
	char *mechArray[],		/* array to populate with mechs */
	int arrayLen			/* length of passed in array */
);

OM_uint32
__gss_get_mech_type(
	gss_OID oid,			/* mechanism oid */
	const gss_buffer_t token	/* token */
);

OM_uint32
__gss_userok(
	OM_uint32 *,		/* minor status */
	const gss_name_t,	/* remote user principal name */
	const char *,		/* local unix user name */
	int *);			/* remote principal ok to login w/out pw? */

OM_uint32
gsscred_expname_to_unix_cred(
	const gss_buffer_t,	/* export name */
	uid_t *,		/* uid out */
	gid_t *,		/* gid out */
	gid_t *[],		/* gid array out */
	int *);			/* gid array length */

OM_uint32
gsscred_name_to_unix_cred(
	const gss_name_t,	/* gss name */
	const gss_OID,		/* mechanim type */
	uid_t *,		/* uid out */
	gid_t *,		/* gid out */
	gid_t *[],		/* gid array out */
	int *);			/* gid array length */


/*
 * The following function will be used to resolve group
 * ids from a UNIX uid.
 */
OM_uint32
gss_get_group_info(
	const uid_t,		/* entity UNIX uid */
	gid_t *,		/* gid out */
	gid_t *[],		/* gid array */
	int *);			/* length of the gid array */



OM_uint32
gss_acquire_cred_with_password(
	OM_uint32 *		minor_status,
	const gss_name_t	desired_name,
	const gss_buffer_t	password,
	OM_uint32		time_req,
	const gss_OID_set	desired_mechs,
	int			cred_usage,
	gss_cred_id_t 		*output_cred_handle,
	gss_OID_set *		actual_mechs,
	OM_uint32 *		time_rec);

OM_uint32
gss_add_cred_with_password(
	OM_uint32		*minor_status,
	const gss_cred_id_t	input_cred_handle,
	const gss_name_t	desired_name,
	const gss_OID		desired_mech,
	const gss_buffer_t	password,
	gss_cred_usage_t	cred_usage,
	OM_uint32		initiator_time_req,
	OM_uint32		acceptor_time_req,
	gss_cred_id_t		*output_cred_handle,
	gss_OID_set		*actual_mechs,
	OM_uint32		*initiator_time_rec,
	OM_uint32		*acceptor_time_rec);

/*
 * Returns a buffer set with the first member containing the
 * session key for SSPI compatibility. The optional second
 * member contains an OID identifying the session key type.
 */
extern const gss_OID GSS_C_INQ_SSPI_SESSION_KEY;

#else	/*	_KERNEL	*/

OM_uint32
kgsscred_expname_to_unix_cred(
	const gss_buffer_t expName,
	uid_t *uidOut,
	gid_t *gidOut,
	gid_t *gids[],
	int *gidsLen,
	uid_t uid);

OM_uint32
kgsscred_name_to_unix_cred(
	const gss_name_t intName,
	const gss_OID mechType,
	uid_t *uidOut,
	gid_t *gidOut,
	gid_t *gids[],
	int *gidsLen,
	uid_t uid);

OM_uint32
kgss_get_group_info(
	const uid_t puid,
	gid_t *gidOut,
	gid_t *gids[],
	int *gidsLen,
	uid_t uid);
#endif

/*
 * GGF extensions
 */
typedef struct gss_buffer_set_desc_struct {
    size_t count;
    gss_buffer_desc *elements;
} gss_buffer_set_desc, *gss_buffer_set_t;

#define	GSS_C_NO_BUFFER_SET ((gss_buffer_set_t)0)

OM_uint32 gss_create_empty_buffer_set
	(OM_uint32 *, /* minor_status */
	gss_buffer_set_t *); /* buffer_set */

OM_uint32 gss_add_buffer_set_member
	(OM_uint32 *, /* minor_status */
	const gss_buffer_t, /* member_buffer */
	gss_buffer_set_t *); /* buffer_set */

OM_uint32  gss_release_buffer_set
	(OM_uint32 *, /* minor_status */
	gss_buffer_set_t *); /* buffer_set */

OM_uint32 gss_inquire_sec_context_by_oid
	(OM_uint32 *, /* minor_status */
	const gss_ctx_id_t, /* context_handle */
	const gss_OID, /* desired_object */
	gss_buffer_set_t *); /* data_set */

#ifdef	__cplusplus
}
#endif

#endif	/* _GSSAPI_EXT_H */
