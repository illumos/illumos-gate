/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1998, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _IMPL_H
#define	_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/* Exported Constants */

#ifndef	NULL
#define	NULL 0
#endif

#ifndef	TRUE
#define	TRUE	1
#endif
#ifndef	FALSE
#define	FALSE	0
#endif

#ifndef	True
#define	True	1
#endif
#ifndef	False
#define	False	0
#endif

#ifndef	MIN
#define	MIN(x, y)	((x) < (y)? (x) : (y))
#endif
#ifndef	MAX
#define	MAX(x, y)	((x) > (y)? (x) : (y))
#endif

#define	NOT_IMPLEMENTED		-1
#define	END_OF_TABLE		-2
#define	OTHER_ERROR		-3

#define	EXACT_ENTRY		1
#define	FIRST_ENTRY		2
#define	NEXT_ENTRY		3

#define	FIRST_PASS		1
#define	SECOND_PASS		2


/* Exported Types */

typedef int32_t Integer;


typedef struct _String {
	uchar_t *chars;
	int len;
} String;


typedef uint32_t Subid;

typedef struct _Oid {
	Subid *subids;
	int len;
} Oid;

typedef struct _IndexType {
	int type;
	int len;
	int *value;
} IndexType;

typedef struct in_addr IPAddress;
typedef struct sockaddr_in Address;


/* Exported Functions */

extern char *pdu_type_string(uchar_t type);
extern char *asn1_type_string(uchar_t type);
extern char *error_status_string(int status);
extern char *generic_trap_string(int generic);
extern char *SSAOidString(Oid *oid);
extern char *timeval_string(struct timeval *tv);
extern char *ip_address_string(IPAddress *ip_address);
extern char *address_string(Address *address);

/* Conversion Routines */
extern char *SSAStringToChar(String str);
extern Oid *SSAOidStrToOid(char *name, char *error_label);

extern void SSAStringZero(String *string);
extern int SSAStringInit(String *string, uchar_t *chars, int len,
    char *error_label);
extern int SSAStringCpy(String *string1, String *string2, char *error_label);

extern Oid *SSAOidNew(void);
extern void SSAOidZero(Oid *oid);
extern void SSAOidFree(Oid *oid);
extern int SSAOidInit(Oid *oid, Subid *subids, int len, char *error_label);
extern int SSAOidCpy(Oid *oid1, Oid *oid2, char *error_label);
extern Oid *SSAOidDup(Oid *oid, char *error_label);
extern int SSAOidCmp(Oid *oid1, Oid *oid2);

extern int name_to_ip_address(char *name, IPAddress *ip_address,
    char *error_label);
extern int get_my_ip_address(IPAddress *my_ip_address, char *error_label);

#ifdef	__cplusplus
}
#endif

#endif	/* _IMPL_H */
