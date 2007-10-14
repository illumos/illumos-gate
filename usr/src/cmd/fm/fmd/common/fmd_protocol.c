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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fm/protocol.h>
#include <strings.h>
#include <alloca.h>
#include <stdio.h>

#include <fmd_protocol.h>
#include <fmd_module.h>
#include <fmd_conf.h>
#include <fmd_subr.h>
#include <fmd_error.h>
#include <fmd_time.h>
#include <fmd.h>

/*
 * Create an FMRI authority element for the environment in which this instance
 * of fmd is deployed.  This function is called once and the result is cached.
 */
nvlist_t *
fmd_protocol_authority(void)
{
	const char *str;
	nvlist_t *nvl;
	int err = 0;

	if (nvlist_xalloc(&nvl, NV_UNIQUE_NAME, &fmd.d_nva) != 0)
		fmd_panic("failed to xalloc authority nvlist");

	err |= nvlist_add_uint8(nvl, FM_VERSION, FM_FMRI_AUTH_VERSION);

	if ((str = fmd_conf_getnzstr(fmd.d_conf, "product")) == NULL)
		str = fmd_conf_getnzstr(fmd.d_conf, "platform");

	if (str != NULL)
		err |= nvlist_add_string(nvl, FM_FMRI_AUTH_PRODUCT, str);

	if ((str = fmd_conf_getnzstr(fmd.d_conf, "chassis")) != NULL)
		err |= nvlist_add_string(nvl, FM_FMRI_AUTH_CHASSIS, str);

	if ((str = fmd_conf_getnzstr(fmd.d_conf, "domain")) != NULL)
		err |= nvlist_add_string(nvl, FM_FMRI_AUTH_DOMAIN, str);

	if ((str = fmd_conf_getnzstr(fmd.d_conf, "server")) != NULL)
		err |= nvlist_add_string(nvl, FM_FMRI_AUTH_SERVER, str);

	if (err != 0)
		fmd_panic("failed to populate nvlist: %s\n", fmd_strerror(err));

	return (nvl);
}

/*
 * Create an FMRI for the specified module.  We use the cached authority
 * nvlist saved in fmd.d_auth to fill in the authority member.
 */
nvlist_t *
fmd_protocol_fmri_module(fmd_module_t *mp)
{
	nvlist_t *nvl;
	int err = 0;

	if (nvlist_xalloc(&nvl, NV_UNIQUE_NAME, &fmd.d_nva) != 0)
		fmd_panic("failed to xalloc diag-engine fmri nvlist");

	err |= nvlist_add_uint8(nvl, FM_VERSION, FM_FMD_SCHEME_VERSION);
	err |= nvlist_add_string(nvl, FM_FMRI_SCHEME, FM_FMRI_SCHEME_FMD);
	err |= nvlist_add_nvlist(nvl, FM_FMRI_AUTHORITY, fmd.d_auth);
	err |= nvlist_add_string(nvl, FM_FMRI_FMD_NAME, mp->mod_name);

	if (mp->mod_info != NULL) {
		err |= nvlist_add_string(nvl,
		    FM_FMRI_FMD_VERSION, mp->mod_info->fmdi_vers);
	} else if (mp == fmd.d_rmod) {
		err |= nvlist_add_string(nvl,
		    FM_FMRI_FMD_VERSION, fmd.d_version);
	}

	if (err != 0)
		fmd_panic("failed to populate nvlist: %s\n", fmd_strerror(err));

	return (nvl);
}

nvlist_t *
fmd_protocol_fault(const char *class, uint8_t certainty,
    nvlist_t *asru, nvlist_t *fru, nvlist_t *resource, const char *location)
{
	nvlist_t *nvl;
	int err = 0;

	if (nvlist_xalloc(&nvl, NV_UNIQUE_NAME, &fmd.d_nva) != 0)
		fmd_panic("failed to xalloc fault nvlist");

	err |= nvlist_add_uint8(nvl, FM_VERSION, FM_FAULT_VERSION);
	err |= nvlist_add_string(nvl, FM_CLASS, class);
	err |= nvlist_add_uint8(nvl, FM_FAULT_CERTAINTY, certainty);

	if (asru != NULL)
		err |= nvlist_add_nvlist(nvl, FM_FAULT_ASRU, asru);
	if (fru != NULL)
		err |= nvlist_add_nvlist(nvl, FM_FAULT_FRU, fru);
	if (resource != NULL)
		err |= nvlist_add_nvlist(nvl, FM_FAULT_RESOURCE, resource);
	if (location != NULL)
		err |= nvlist_add_string(nvl, FM_FAULT_LOCATION, location);

	if (err != 0)
		fmd_panic("failed to populate nvlist: %s\n", fmd_strerror(err));

	return (nvl);
}

nvlist_t *
fmd_protocol_list(const char *class, nvlist_t *de_fmri, const char *uuid,
    const char *code, uint_t argc, nvlist_t **argv, uint8_t *flagv, int domsg,
    struct timeval *tvp)
{
	int64_t tod[2];
	nvlist_t *nvl;
	int err = 0;

	tod[0] = tvp->tv_sec;
	tod[1] = tvp->tv_usec;

	if (nvlist_xalloc(&nvl, NV_UNIQUE_NAME, &fmd.d_nva) != 0)
		fmd_panic("failed to xalloc suspect list nvlist");

	err |= nvlist_add_uint8(nvl, FM_VERSION, FM_SUSPECT_VERSION);
	err |= nvlist_add_string(nvl, FM_CLASS, class);
	err |= nvlist_add_string(nvl, FM_SUSPECT_UUID, uuid);
	err |= nvlist_add_string(nvl, FM_SUSPECT_DIAG_CODE, code);
	err |= nvlist_add_int64_array(nvl, FM_SUSPECT_DIAG_TIME, tod, 2);
	err |= nvlist_add_nvlist(nvl, FM_SUSPECT_DE, de_fmri);
	err |= nvlist_add_uint32(nvl, FM_SUSPECT_FAULT_SZ, argc);

	if (!domsg) {
		err |= nvlist_add_boolean_value(nvl,
		    FM_SUSPECT_MESSAGE, B_FALSE);
	}

	if (argc != 0) {
		err |= nvlist_add_nvlist_array(nvl,
		    FM_SUSPECT_FAULT_LIST, argv, argc);
		err |= nvlist_add_uint8_array(nvl,
		    FM_SUSPECT_FAULT_STATUS, flagv, argc);
	}

	if (err != 0)
		fmd_panic("failed to populate nvlist: %s\n", fmd_strerror(err));

	return (nvl);
}

nvlist_t *
fmd_protocol_rsrc_asru(const char *class,
    nvlist_t *fmri, const char *uuid, const char *code,
    boolean_t faulty, boolean_t unusable, boolean_t message, nvlist_t *event,
    struct timeval *tvp)
{
	nvlist_t *nvl;
	int64_t tod[2];
	int err = 0;

	tod[0] = tvp->tv_sec;
	tod[1] = tvp->tv_usec;

	if (nvlist_xalloc(&nvl, NV_UNIQUE_NAME, &fmd.d_nva) != 0)
		fmd_panic("failed to xalloc resource nvlist");

	err |= nvlist_add_uint8(nvl, FM_VERSION, FM_RSRC_VERSION);
	err |= nvlist_add_string(nvl, FM_CLASS, class);
	err |= nvlist_add_nvlist(nvl, FM_RSRC_RESOURCE, fmri);

	if (uuid != NULL)
		err |= nvlist_add_string(nvl, FM_RSRC_ASRU_UUID, uuid);

	if (code != NULL)
		err |= nvlist_add_string(nvl, FM_RSRC_ASRU_CODE, code);

	err |= nvlist_add_boolean_value(nvl, FM_RSRC_ASRU_FAULTY, faulty);
	err |= nvlist_add_boolean_value(nvl, FM_RSRC_ASRU_UNUSABLE, unusable);
	err |= nvlist_add_boolean_value(nvl, FM_SUSPECT_MESSAGE, message);
	err |= nvlist_add_int64_array(nvl, FM_SUSPECT_DIAG_TIME, tod, 2);

	if (event != NULL)
		err |= nvlist_add_nvlist(nvl, FM_RSRC_ASRU_EVENT, event);

	if (err != 0)
		fmd_panic("failed to populate nvlist: %s\n", fmd_strerror(err));

	return (nvl);
}

nvlist_t *
fmd_protocol_fmderror(int errnum, const char *format, va_list ap)
{
	uint64_t ena = fmd_ena();
	nvlist_t *nvl;
	int err = 0;
	char c, *msg;
	size_t len;

	if (nvlist_xalloc(&nvl, NV_UNIQUE_NAME, &fmd.d_nva) != 0)
		return (NULL);

	len = vsnprintf(&c, 1, format, ap);
	msg = alloca(len + 1);
	(void) vsnprintf(msg, len + 1, format, ap);

	if (msg[len] == '\n')
		msg[len] = '\0';

	err |= nvlist_add_uint8(nvl, FM_VERSION, FM_EREPORT_VERSION);
	err |= nvlist_add_string(nvl, FM_CLASS, fmd_errclass(errnum));
	err |= nvlist_add_uint64(nvl, FM_EREPORT_ENA, ena);
	err |= nvlist_add_string(nvl, FMD_ERR_MOD_MSG, msg);

	if (err != 0) {
		nvlist_free(nvl);
		return (NULL);
	}

	return (nvl);
}

nvlist_t *
fmd_protocol_moderror(fmd_module_t *mp, int oserr, const char *msg)
{
	uint64_t ena = fmd_ena();
	nvlist_t *nvl, *fmri;
	int err = 0;

	if (nvlist_xalloc(&nvl, NV_UNIQUE_NAME, &fmd.d_nva) != 0)
		fmd_panic("failed to xalloc module error nvlist");

	if (mp->mod_fmri == NULL)
		fmri = fmd_protocol_fmri_module(mp);
	else
		fmri = mp->mod_fmri;

	err |= nvlist_add_uint8(nvl, FM_VERSION, FM_EREPORT_VERSION);
	err |= nvlist_add_string(nvl, FM_CLASS, fmd_errclass(EFMD_MODULE));
	err |= nvlist_add_nvlist(nvl, FM_EREPORT_DETECTOR, fmri);
	err |= nvlist_add_uint64(nvl, FM_EREPORT_ENA, ena);
	err |= nvlist_add_string(nvl, FMD_ERR_MOD_MSG, msg);

	if (mp->mod_fmri == NULL)
		nvlist_free(fmri);

	if (oserr != 0) {
		err |= nvlist_add_int32(nvl, FMD_ERR_MOD_ERRNO, oserr);
		err |= nvlist_add_string(nvl, FMD_ERR_MOD_ERRCLASS,
		    fmd_errclass(oserr));
	}

	if (err != 0)
		fmd_panic("failed to populate nvlist: %s\n", fmd_strerror(err));

	return (nvl);
}

nvlist_t *
fmd_protocol_xprt_ctl(fmd_module_t *mp, const char *class, uint8_t version)
{
	nvlist_t *nvl;
	int err = 0;

	if (nvlist_xalloc(&nvl, NV_UNIQUE_NAME, &fmd.d_nva) != 0)
		fmd_panic("failed to xalloc rsrc xprt nvlist");

	err |= nvlist_add_uint8(nvl, FM_VERSION, version);
	err |= nvlist_add_string(nvl, FM_CLASS, class);
	err |= nvlist_add_nvlist(nvl, FM_RSRC_RESOURCE, mp->mod_fmri);

	if (err != 0)
		fmd_panic("failed to populate nvlist: %s\n", fmd_strerror(err));

	return (nvl);
}

nvlist_t *
fmd_protocol_xprt_sub(fmd_module_t *mp,
    const char *class, uint8_t version, const char *subclass)
{
	nvlist_t *nvl = fmd_protocol_xprt_ctl(mp, class, version);
	int err = nvlist_add_string(nvl, FM_RSRC_XPRT_SUBCLASS, subclass);

	if (err != 0)
		fmd_panic("failed to populate nvlist: %s\n", fmd_strerror(err));

	return (nvl);
}

nvlist_t *
fmd_protocol_xprt_uuclose(fmd_module_t *mp, const char *class, uint8_t version,
    const char *uuid)
{
	nvlist_t *nvl = fmd_protocol_xprt_ctl(mp, class, version);
	int err = nvlist_add_string(nvl, FM_RSRC_XPRT_UUID, uuid);

	if (err != 0)
		fmd_panic("failed to populate nvlist: %s\n", fmd_strerror(err));

	return (nvl);
}
