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

#include <sys/types.h>
#include <sys/cpr.h>
#include <sys/pte.h>
#include <sys/promimpl.h>
#include <sys/prom_plat.h>
#include "cprboot.h"

extern void	prom_unmap(caddr_t, uint_t);

extern int cpr_debug;
static int cpr_show_props = 0;


/*
 * Read the config file and pass back the file path, filesystem
 * device path.
 */
int
cpr_read_cprinfo(int fd, char *file_path, char *fs_path)
{
	struct cprconfig cf;

	if (cpr_fs_read(fd, (char *)&cf, sizeof (cf)) != sizeof (cf) ||
	    cf.cf_magic != CPR_CONFIG_MAGIC)
		return (-1);

	(void) prom_strcpy(file_path, cf.cf_path);
	(void) prom_strcpy(fs_path, cf.cf_dev_prom);

	return (0);
}


/*
 * Read the location of the state file from the root filesystem.
 * Pass back to the caller the full device path of the filesystem
 * and the filename relative to that fs.
 */
int
cpr_locate_statefile(char *file_path, char *fs_path)
{
	int fd;
	int rc;

	if ((fd = cpr_fs_open(CPR_CONFIG)) != -1) {
		rc = cpr_read_cprinfo(fd, file_path, fs_path);
		(void) cpr_fs_close(fd);
	} else
		rc = -1;

	return (rc);
}


/*
 * Open the "defaults" file in the root fs and read the values of the
 * properties saved during the checkpoint.  Restore the values to nvram.
 *
 * Note: an invalid magic number in the "defaults" file means that the
 * state file is bad or obsolete so our caller should not proceed with
 * the resume.
 */
int
cpr_reset_properties(void)
{
	char *str, *default_path;
	int fd, len, rc, prop_errors;
	cprop_t *prop, *tail;
	cdef_t cdef;
	pnode_t node;

	str = "cpr_reset_properties";
	default_path = CPR_DEFAULT;

	if ((fd = cpr_fs_open(default_path)) == -1) {
		prom_printf("%s: unable to open %s\n",
		    str, default_path);
		return (-1);
	}

	rc = 0;
	len = cpr_fs_read(fd, (char *)&cdef, sizeof (cdef));
	if (len != sizeof (cdef)) {
		prom_printf("%s: error reading %s\n", str, default_path);
		rc = -1;
	} else if (cdef.mini.magic != CPR_DEFAULT_MAGIC) {
		prom_printf("%s: bad magic number in %s\n", str, default_path);
		rc = -1;
	}

	(void) cpr_fs_close(fd);
	if (rc)
		return (rc);

	node = prom_optionsnode();
	if (node == OBP_NONODE || node == OBP_BADNODE) {
		prom_printf("%s: cannot find \"options\" node\n", str);
		return (-1);
	}

	/*
	 * reset nvram to the original property values
	 */
	if (cpr_show_props)
		prom_printf("\n\ncpr_show_props:\n");
	for (prop_errors = 0, prop = cdef.props, tail = prop + CPR_MAXPROP;
	    prop < tail; prop++) {
		if (cpr_show_props) {
			prom_printf("mod=%c, name=\"%s\",\tvalue=\"%s\"\n",
			    prop->mod, prop->name, prop->value);
		}
		if (prop->mod != PROP_MOD)
			continue;

		len = prom_strlen(prop->value);
		if (prom_setprop(node, prop->name, prop->value, len + 1) < 0 ||
		    prom_getproplen(node, prop->name) != len) {
			prom_printf("%s: error setting \"%s\" to \"%s\"\n",
			    str, prop->name, prop->value);
			prop_errors++;
		}
	}

	return (prop_errors ? -1 : 0);
}


/*
 * Read and verify cpr dump descriptor
 */
int
cpr_read_cdump(int fd, cdd_t *cdp, ushort_t mach_type)
{
	char *str;
	int nread;

	str = "\ncpr_read_cdump:";
	nread = cpr_read(fd, (caddr_t)cdp, sizeof (*cdp));
	if (nread != sizeof (*cdp)) {
		prom_printf("%s Error reading cpr dump descriptor\n", str);
		return (-1);
	}

	if (cdp->cdd_magic != CPR_DUMP_MAGIC) {
		prom_printf("%s bad dump magic 0x%x, expected 0x%x\n",
		    str, cdp->cdd_magic, CPR_DUMP_MAGIC);
		return (-1);
	}

	if (cdp->cdd_version != CPR_VERSION) {
		prom_printf("%s bad cpr version %d, expected %d\n",
		    str, cdp->cdd_version, CPR_VERSION);
		return (-1);
	}

	if (cdp->cdd_machine != mach_type) {
		prom_printf("%s bad machine type 0x%x, expected 0x%x\n",
		    str, cdp->cdd_machine, mach_type);
		return (-1);
	}

	if (cdp->cdd_bitmaprec <= 0) {
		prom_printf("%s bad bitmap %d\n", str, cdp->cdd_bitmaprec);
		return (-1);
	}

	if (cdp->cdd_dumppgsize <= 0) {
		prom_printf("%s Bad pg tot %d\n", str, cdp->cdd_dumppgsize);
		return (-1);
	}

	cpr_debug = cdp->cdd_debug;

	return (0);
}


/*
 * update cpr dump terminator
 */
void
cpr_update_terminator(ctrm_t *file_term, caddr_t mapva)
{
	ctrm_t *mem_term;

	/*
	 * Add the offset to reach the terminator in the kernel so that we
	 * can directly change the restored kernel image.
	 */
	mem_term = (ctrm_t *)(mapva + (file_term->va & MMU_PAGEOFFSET));

	mem_term->real_statef_size = file_term->real_statef_size;
	mem_term->tm_shutdown = file_term->tm_shutdown;
	mem_term->tm_cprboot_start.tv_sec = file_term->tm_cprboot_start.tv_sec;
	mem_term->tm_cprboot_end.tv_sec = prom_gettime() / 1000;
}


/*
 * simple bcopy for cprboot
 */
void
bcopy(const void *s, void *d, size_t count)
{
	const char *src = s;
	char *dst = d;

	while (count--)
		*dst++ = *src++;
}
