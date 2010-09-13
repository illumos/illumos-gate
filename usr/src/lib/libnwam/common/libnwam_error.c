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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libnwam.h>
#include <libintl.h>

static struct nwam_error_info {
	nwam_error_t error_code;
	const char *error_desc;
} nwam_errors[] = {
	{NWAM_SUCCESS,			"no error"},
	{NWAM_LIST_END,			"end of list reached"},
	{NWAM_INVALID_HANDLE,		"entity handle is invalid"},
	{NWAM_HANDLE_UNBOUND,		"handle not bound to entity"},
	{NWAM_INVALID_ARG,		"argument is invalid"},
	{NWAM_PERMISSION_DENIED,	"Insufficient permissions for action"},
	{NWAM_NO_MEMORY,		"out of memory"},
	{NWAM_ENTITY_EXISTS,		"entity exists"},
	{NWAM_ENTITY_IN_USE,		"entity in use"},
	{NWAM_ENTITY_COMMITTED,		"entity already committed"},
	{NWAM_ENTITY_NOT_FOUND,		"entity not found"},
	{NWAM_ENTITY_TYPE_MISMATCH,	"entity type mismatch"},
	{NWAM_ENTITY_INVALID,		"validation of entity failed"},
	{NWAM_ENTITY_INVALID_MEMBER,	"entity has invalid member"},
	{NWAM_ENTITY_INVALID_STATE,	"entity is in incorrect state"},
	{NWAM_ENTITY_INVALID_VALUE,	"validation of entity value failed"},
	{NWAM_ENTITY_MISSING_MEMBER,	"entity is missing required member"},
	{NWAM_ENTITY_NO_VALUE,		"no value associated with entity"},
	{NWAM_ENTITY_MULTIPLE_VALUES,	"multiple values for entity"},
	{NWAM_ENTITY_READ_ONLY,		"entity is read only"},
	{NWAM_ENTITY_NOT_DESTROYABLE,	"entity cannot be destroyed"},
	{NWAM_ENTITY_NOT_MANUAL, "entity cannot be manually enabled/disabled"},
	{NWAM_WALK_HALTED,		"callback function returned nonzero"},
	{NWAM_ERROR_BIND,		"could not bind to backend server"},
	{NWAM_ERROR_BACKEND_INIT,	"could not initialize backend"},
	{NWAM_ERROR_INTERNAL,		"internal error"}
};

#define	NWAM_NUM_ERRORS	(sizeof (nwam_errors) / sizeof (*nwam_errors))

const char *
nwam_strerror(nwam_error_t code)
{
	struct nwam_error_info *cur, *end;

	cur = nwam_errors;
	end = cur + NWAM_NUM_ERRORS;

	for (; cur < end; cur++) {
		if (code == cur->error_code)
			return (dgettext(TEXT_DOMAIN, cur->error_desc));
	}

	return (dgettext(TEXT_DOMAIN, "unknown error"));
}
