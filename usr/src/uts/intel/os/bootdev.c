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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/modctl.h>
#include <sys/sunddi.h>

/* internal global data */
static struct modlmisc modlmisc = {
	&mod_miscops, "bootdev misc module"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * convert a prom device path to an equivalent path in /devices
 * Does not deal with aliases.  Does deal with pathnames which
 * are not fully qualified.  This routine is generalized
 * to work across several flavors of OBP
 */
int
i_promname_to_devname(char *prom_name, char *ret_buf)
{
	if (prom_name == NULL || ret_buf == NULL ||
	    (strlen(prom_name) >= MAXPATHLEN)) {
		return (EINVAL);
	}
	if (i_ddi_prompath_to_devfspath(prom_name, ret_buf) != DDI_SUCCESS)
		return (EINVAL);

	return (0);
}

/*
 * If bootstring contains a device path, we need to convert to a format
 * the prom will understand.  To do so, we convert the existing path to
 * a prom-compatible path and return the value of new_path.  If the
 * caller specifies new_path as NULL, we allocate an appropriately
 * sized new_path on behalf of the caller.  If the caller invokes this
 * function with new_path = NULL, they must do so from a context in
 * which it is safe to perform a sleeping memory allocation.
 *
 * NOTE: Intel does not have a real PROM, so the implementation
 *       simply returns a copy of the string passed in.
 */
char *
i_convert_boot_device_name(char *cur_path, char *new_path, size_t *len)
{
	if (new_path != NULL) {
		(void) snprintf(new_path, *len, "%s", cur_path);
		return (new_path);
	} else {
		*len = strlen(cur_path) + 1;
		new_path = kmem_alloc(*len, KM_SLEEP);
		(void) snprintf(new_path, *len, "%s", cur_path);
		return (new_path);
	}
}
