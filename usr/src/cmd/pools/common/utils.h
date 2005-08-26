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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_UTILS_H
#define	_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Error messages for pool commands */
#define	ERR_SET_TERM		"cleanup installation failed: %s\n"
#define	ERR_CONF_LOAD		"cannot load configuration from %s: %s\n"
#define	ERR_CMD_FILE_INIT	"cannot initialise command sequence: %s\n"
#define	ERR_PROP_TO_LIST	"cannot add property %s to property list\n"
#define	ERR_UNKNOWN_ENTITY	"unrecognised entity %lld\n"
#define	ERR_ASSOC_TO_LIST	"cannot add association %s to association " \
	"list\n"
#define	ERR_GET_ELEMENT_DETAILS	"cannot get the %s details for %s: %s\n"
#define	ERR_LOCATE_ELEMENT	"cannot locate the %s, %s: %s\n"
#define	ERR_CREATE_ELEMENT	"cannot create the %s, %s: %s\n"
#define	ERR_DESTROY_ELEMENT	"cannot destroy the %s, %s: %s\n"
#define	ERR_ALLOC_ELEMENT	"cannot allocate %s: %s\n"
#define	ERR_PUT_PROPERTY	"put property %s failed: %s\n"
#define	ERR_REMOVE_PROPERTY	"remove property %s failed: %s\n"
#define	ERR_GET_PROPERTY	"get property %s failed: %s\n"
#define	ERR_UNKNOWN_RESOURCE	"unrecognized resource type: %d\n"
#define	ERR_ASSOC_RESOURCE	"cannot associate resource %s to pool: %s\n"
#define	ERR_VALIDATION_FAILED	"configuration failed strict validation: %s\n"
#define	ERR_CONFIG_OPEN_FAILED	"cannot open the configuration: %s\n"
#define	ERR_CONFIG_SAVE_FAILED	"cannot save the configuration: %s\n"
#define	ERR_WRONG_SYSTEM_NAME	"incorrect system name supplied: %s\n"
#define	ERR_CMD_LINE_ALLOC	"cannot create command, not enough memory\n"
#define	ERR_PROP_ALLOC		"cannot create property, not enough memory\n"
#define	ERR_ASSOC_ALLOC		"cannot create association, not enough memory\n"

#define	ERR_DISABLE		"cannot disable pools"
#define	ERR_ENABLE		"cannot enable pools"
#define	ERR_NOMEM		"not enough memory\n"
#define	ERR_PERMISSIONS		"insufficient privileges\n"
#define	ERR_PRIVILEGE		"cannot access %s privileges"
#define	ERR_OPEN_DYNAMIC	"couldn't open pools state file: %s\n"
#define	ERR_OPEN_STATIC		"couldn't open configuration at '%s': %s\n"
#define	ERR_VALIDATE_RUNTIME	"configuration at '%s' cannot be instantiated "\
	"on current system\n"
#define	ERR_COMMIT_DYNAMIC	"couldn't commit configuration changes at '%s'"\
	": %s\n"
#define	ERR_REMOVE_DYNAMIC	"couldn't remove dynamic configuration: %s\n"
#define	ERR_COMMIT_STATIC	"couldn't commit configuration changes at '%s'"\
	": %s\n"
#define	ERR_EXPORT_DYNAMIC	"couldn't export pools state file to '%s': %s\n"
#define	ERR_NO_POOLS		"no pools defined\n"
#define	ERR_XFER_COMPONENT	"cannot transfer %s %s to %s: %s\n"
#define	ERR_XFER_QUANTITY	"cannot transfer %llu from %s to %s: %s\n"
#define	ERR_CMDPARSE_FAILED	"command parsing failed, terminating...\n"

#define	CONFIGURATION		"configuration"
#define	RESOURCE		"resource"
#define	POOL			"pool"
#define	PSET			"pset"
#define	COMPONENT		"component"
#define	CPU			"cpu"
#define	SYSTEM_NAME		"system.name"
#define	POOL_NAME		"pool.name"
#define	PSET_NAME		"pset.name"
#define	CPU_SYSID		"cpu.sys_id"

#define	E_PO_SUCCESS	0		/* Exit status for success */
#define	E_ERROR		1		/* Exit status for error */
#define	E_USAGE		2		/* Exit status for usage error */

extern const char *get_errstr(void);
extern const char *get_errstr_err(int, int);
extern void warn(const char *, ...);
extern void die(const char *, ...) __NORETURN;
extern const char *getpname(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTILS_H */
