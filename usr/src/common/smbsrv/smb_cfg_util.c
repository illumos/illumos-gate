/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#include <string.h>
#else
#include <sys/sunddi.h>
#endif
#include <smbsrv/smbinfo.h>

void
smb_cfg_set_require(const char *value, smb_cfg_val_t *cfg)
{
	if (value == NULL) {
		*cfg = SMB_CONFIG_DISABLED;
		return;
	}

	if (strcmp(value, "required") == 0)
		*cfg = SMB_CONFIG_REQUIRED;
	else if (strcmp(value, "enabled") == 0)
		*cfg = SMB_CONFIG_ENABLED;
	else
		*cfg = SMB_CONFIG_DISABLED;
}
