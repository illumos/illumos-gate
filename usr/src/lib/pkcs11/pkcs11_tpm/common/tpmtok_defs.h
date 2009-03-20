/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TPMTOK_DEFS_H
#define	_TPMTOK_DEFS_H

/* TSS key type helper */
#define	TPMTOK_TSS_KEY_TYPE_MASK	0x000000F0
#define	TPMTOK_TSS_KEY_TYPE(x)		(x & TPMTOK_TSS_KEY_TYPE_MASK)
#define	TPMTOK_TSS_KEY_MIG_TYPE(x)	(x & TSS_KEY_MIGRATABLE)

#define	TPMTOK_TSS_MAX_ERROR		0x00000FFF
#define	TPMTOK_TSS_ERROR_CODE(x)	(x & TPMTOK_TSS_MAX_ERROR)

/* key types in the TPM token */
#define	TPMTOK_PRIVATE_ROOT_KEY	1
#define	TPMTOK_PRIVATE_LEAF_KEY	2
#define	TPMTOK_PUBLIC_ROOT_KEY	3
#define	TPMTOK_PUBLIC_LEAF_KEY	4

/* key identifiers for the PKCS#11 objects */
#define	TPMTOK_PRIVATE_ROOT_KEY_ID	"PRIVATE_ROOT_KEY"
#define	TPMTOK_PRIVATE_LEAF_KEY_ID	"PRIVATE_LEAF_KEY"
#define	TPMTOK_PUBLIC_ROOT_KEY_ID	"PUBLIC_ROOT_KEY"
#define	TPMTOK_PUBLIC_LEAF_KEY_ID	"PUBLIC_LEAF_KEY"

#define	NULL_HKEY	0
#define	NULL_HENCDATA	0
#define	NULL_HPOLICY	0
#define	NULL_HCONTEXT	0
#define	NULL_HPCRS	0

#define	LOG(priority, fmt, ...) \
{\
	openlog("tpmtoken", LOG_NDELAY|LOG_PID, LOG_USER);\
	syslog(priority, "%s " fmt, __FILE__, ##__VA_ARGS__);\
}

#endif /* _TPMTOK_DEFS_H */
