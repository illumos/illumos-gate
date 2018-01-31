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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2015 by Delphix. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 * Copyright 2017 RackTop Systems.
 */

#include <sys/sid.h>

#include <umem.h>
#include <strings.h>

static char *
ksid_strdup(const char *s)
{
	size_t len;
	char *new;

	len = strlen(s);
	new = umem_alloc(len + 1, KM_SLEEP);
	bcopy(s, new, len);
	new[len] = '\0';

	return (new);
}

static void
ksid_strfree(char *s)
{
	umem_free(s, strlen(s) + 1);
}

ksiddomain_t *
ksid_lookupdomain(const char *dom)
{
	ksiddomain_t *kd;

	kd = umem_zalloc(sizeof (ksiddomain_t), UMEM_NOFAIL);
	kd->kd_name = ksid_strdup(dom);
	return (kd);
}

void
ksiddomain_rele(ksiddomain_t *ksid)
{
	ksid_strfree(ksid->kd_name);
	umem_free(ksid, sizeof (ksiddomain_t));
}
