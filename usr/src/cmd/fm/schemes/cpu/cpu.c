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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/processor.h>
#include <fm/fmd_fmri.h>

#include <string.h>
#include <strings.h>
#include <errno.h>
#include <kstat.h>
#ifdef	sparc
#include <sys/mdesc.h>
#include <cpu.h>
#endif	/* sparc */

/*
 * The scheme plugin for cpu FMRIs.
 */

#ifdef	sparc
cpu_t cpu;
#endif	/* sparc */

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	uint8_t version;
	uint32_t cpuid;
	uint64_t serialid;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_CPU_SCHEME_VERSION ||
	    nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID, &cpuid) != 0 ||
	    nvlist_lookup_uint64(nvl, FM_FMRI_CPU_SERIAL_ID, &serialid) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	return (snprintf(buf, buflen, "cpu:///%s=%u/%s=%llX", FM_FMRI_CPU_ID,
	    cpuid, FM_FMRI_CPU_SERIAL_ID, (u_longlong_t)serialid));
}

static int
cpu_get_serialid_kstat(uint32_t cpuid, uint64_t *serialidp)
{
	kstat_named_t *kn;
	kstat_ctl_t *kc;
	kstat_t *ksp;
	int i;

	if ((kc = kstat_open()) == NULL) /* XXX commonify */
		return (-1); /* errno is set for us */

	if ((ksp = kstat_lookup(kc, "cpu_info", cpuid, NULL)) == NULL) {
		(void) kstat_close(kc);
		return (fmd_fmri_set_errno(ENOENT));
	}

	if (kstat_read(kc, ksp, NULL) == -1) {
		int oserr = errno;
		(void) kstat_close(kc);
		return (fmd_fmri_set_errno(oserr));
	}

	for (kn = ksp->ks_data, i = 0; i < ksp->ks_ndata; i++, kn++) {
		if (strcmp(kn->name, "device_ID") == 0) {
			*serialidp = kn->value.ui64;
			(void) kstat_close(kc);
			return (0);
		}
	}

	(void) kstat_close(kc);

	return (fmd_fmri_set_errno(ENOENT));
}

static int
cpu_get_serialid(uint32_t cpuid, uint64_t *serialidp)
{
#ifdef	sparc
	if (cpu.cpu_mdesc_cpus != NULL)
	    return (cpu_get_serialid_mdesc(cpuid, serialidp));
	else
#endif	/* sparc */
	    return (cpu_get_serialid_kstat(cpuid, serialidp));
}

int
fmd_fmri_expand(nvlist_t *nvl)
{
	uint8_t version;
	uint32_t cpuid;
	uint64_t serialid;
	int rc;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_CPU_SCHEME_VERSION ||
	    nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID, &cpuid) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if ((rc = nvlist_lookup_uint64(nvl, FM_FMRI_CPU_SERIAL_ID,
	    &serialid)) == 0)
		return (0); /* fmri is already expanded */
	else if (rc != ENOENT)
		return (fmd_fmri_set_errno(rc));

	if (cpu_get_serialid(cpuid, &serialid) != 0)
		return (-1); /* errno is set for us */

	if ((rc = nvlist_add_uint64(nvl, FM_FMRI_CPU_SERIAL_ID, serialid)) != 0)
		return (fmd_fmri_set_errno(rc));

	return (0);
}

int
fmd_fmri_present(nvlist_t *nvl)
{
	uint8_t version;
	uint32_t cpuid;
	uint64_t nvlserid, curserid;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_CPU_SCHEME_VERSION ||
	    nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID, &cpuid) != 0 ||
	    nvlist_lookup_uint64(nvl, FM_FMRI_CPU_SERIAL_ID, &nvlserid) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if (cpu_get_serialid(cpuid, &curserid) != 0)
		return (errno == ENOENT ? 0 : -1);

	return (curserid == nvlserid);
}

int
fmd_fmri_unusable(nvlist_t *nvl)
{
	uint8_t version;
	uint32_t cpuid;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_CPU_SCHEME_VERSION ||
	    nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID, &cpuid) != 0)
		return (fmd_fmri_set_errno(EINVAL));
	else
		return (p_online(cpuid, P_STATUS) == P_FAULTED);
}

#ifdef	sparc
int
fmd_fmri_init(void)
{
	bzero(&cpu, sizeof (cpu_t));
	return (cpu_mdesc_init());
}

void
fmd_fmri_fini(void)
{
	cpu_mdesc_fini();
}
#endif	/* sparc */
