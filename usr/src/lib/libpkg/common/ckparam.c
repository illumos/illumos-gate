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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkglocale.h"

#define	MAXLEN 256
#define	TOKLEN 16

static int	proc_name(char *param, char *value);
static int	proc_arch(char *param, char *value);
static int	proc_version(char *param, char *value);
static int	proc_category(char *param, char *value);
static int	bad_first_char(char *param, char *value);
static int	not_alnum(char *param, char *pt);
static int	not_ascii(char *param, char *pt);
static int	too_long(char *param, char *pt, int len);
static int	isnull(char *param, char *pt);

int
ckparam(char *param, char *val)
{
	char *value = strdup(val);
	int ret_val = 0;	/* return value */

	if (strcmp(param, "NAME") == 0)
		ret_val = proc_name(param, value);

	else if (strcmp(param, "ARCH") == 0)
		ret_val = proc_arch(param, value);

	else if (strcmp(param, "VERSION") == 0)
		ret_val = proc_version(param, value);

	else if (strcmp(param, "CATEGORY") == 0)
		ret_val = proc_category(param, value);

	/* param does not match existing parameters */
	free(value);
	return (ret_val);
}

static int
proc_name(char *param, char *value)
{
	int ret_val;

	if (!(ret_val = isnull(param, value))) {
		ret_val += too_long(param, value, MAXLEN);
		ret_val += not_ascii(param, value);
	}

	return (ret_val);
}

static int
proc_arch(char *param, char *value)
{
	int ret_val;
	char *token;

	if (!(ret_val = isnull(param, value))) {
		token = strtok(value, ", ");

		while (token) {
			ret_val += too_long(param, token, TOKLEN);
			ret_val += not_ascii(param, token);
			token = strtok(NULL, ", ");
		}
	}

	return (ret_val);
}

static int
proc_version(char *param, char *value)
{
	int ret_val;

	if (!(ret_val = isnull(param, value))) {
		ret_val += bad_first_char(param, value);
		ret_val += too_long(param, value, MAXLEN);
		ret_val += not_ascii(param, value);
	}

	return (ret_val);
}

static int
proc_category(char *param, char *value)
{
	int ret_val;
	char *token;

	if (!(ret_val = isnull(param, value))) {
		token = strtok(value, ", ");

		while (token) {
			ret_val += too_long(param, token, TOKLEN);
			ret_val += not_alnum(param, token);
			token = strtok(NULL, ", ");
		}
	}

	return (ret_val);
}

static int
bad_first_char(char *param, char *value)
{
	if (*value == '(') {
		progerr(pkg_gt(ERR_CHAR), param);
		return (1);
	}

	return (0);
}

static int
isnull(char *param, char *pt)
{
	if (!pt || *pt == '\0') {
		progerr(pkg_gt(ERR_UNDEF), param);
		return (1);
	}
	return (0);
}

static int
too_long(char *param, char *pt, int len)
{
	if (strlen(pt) > (size_t)len) {
		progerr(pkg_gt(ERR_LEN), param);
		return (1);
	}
	return (0);
}

static int
not_ascii(char *param, char *pt)
{
	while (*pt) {
		if (!(isascii(*pt))) {
			progerr(pkg_gt(ERR_ASCII), param);
			return (1);
		}
		pt++;
	}
	return (0);
}

static int
not_alnum(char *param, char *pt)
{
	while (*pt) {
		if (!(isalnum(*pt))) {
			progerr(pkg_gt(ERR_ALNUM), param);
			return (1);
		}
		pt++;
	}

	return (0);
}
