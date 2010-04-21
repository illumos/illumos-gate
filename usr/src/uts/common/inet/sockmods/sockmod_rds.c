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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sunldi.h>
#include <inet/common.h>
#include <sys/strsubr.h>
#include <sys/socketvar.h>

extern sock_lower_handle_t rdsv3_create(int, int, int, sock_downcalls_t **,
    uint_t *, int *, int, cred_t *);

#define	INET_NAME	"sockrds"
#define	INET_DEVMINOR	0
#define	INET_MODMTFLAGS	D_MP
#define	INET_SOCKDESC	"RDSv3 socket module"
#define	INET_SOCK_PROTO_CREATE_FUNC	(*rdsv3_create)

#include "../inetddi.c"

ldi_ident_t	sockrds_li;
ldi_handle_t    rdsv3_transport_handle = NULL;

#define	RDSV3_DEVICE_NAME	"/devices/ib/rdsv3@0:rdsv3"

int
_init(void)
{
	int	ret;

	ret = ldi_ident_from_mod(&modlinkage, &sockrds_li);
	if (ret != 0) {
		sockrds_li = NULL;
		goto done;
	}

	ret = ldi_open_by_name(RDSV3_DEVICE_NAME, FREAD | FWRITE, kcred,
	    &rdsv3_transport_handle, sockrds_li);
	if (ret != 0) {
		ldi_ident_release(sockrds_li);
		sockrds_li = NULL;
		rdsv3_transport_handle = NULL;
		goto done;
	}

	ret = mod_install(&modlinkage);
	if (ret != 0) {
		(void) ldi_close(rdsv3_transport_handle, FNDELAY, kcred);
		ldi_ident_release(sockrds_li);
		sockrds_li = NULL;
		rdsv3_transport_handle = NULL;
	}

done:
	return (ret);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret != 0) {
		return (ret);
	}

	if (rdsv3_transport_handle != NULL) {
		(void) ldi_close(rdsv3_transport_handle, FNDELAY, kcred);
		rdsv3_transport_handle = NULL;
	}

	if (sockrds_li != NULL)
		ldi_ident_release(sockrds_li);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
