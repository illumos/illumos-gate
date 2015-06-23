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
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This module defines generic functions to map Native OS and Native
 * LanMan names to values.
 */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <string.h>
#endif
#include <smbsrv/string.h>
#include <smbsrv/smbinfo.h>

typedef struct smb_native {
	int sn_value;
	const char *sn_name;
} smb_native_t;

/*
 * smbnative_os_value
 *
 * Return the appropriate native OS value for the specified native OS name.
 *
 * Example OS values used by Windows:
 *
 *	Windows 4.0, Windows NT, Windows NT 4.0
 *	Windows 5.0, Windows 5.1
 *	Windows 2000, Windows 2000 5.0, Windows 2000 5.1
 *	Windows 2002
 *	Windows .NET
 *	Windows Server 2003
 *	Windows XP
 *
 * Windows 2000 server:            "Windows 2000 2195"
 * Windows XP Professional client: "Windows 2002 2543"
 * Windows XP PDC server:          "Windows 5.1"
 * Windows .Net:                   "Windows .NET 3621"
 * Windows .Net:                   "Windows .NET 3718"
 *
 * DAVE (Thursby Software: CIFS for MacOS) uses "MacOS", sometimes with a
 * version number appended, i.e. "MacOS 8.5.1". We treat DAVE like NT 4.0
 * except for the cases that DAVE clients set 'watch tree' flag in notify
 * change requests.
 *
 * Samba reports UNIX as its Native OS, which we can map to NT 4.0.
 */
int
smbnative_os_value(const char *native_os)
{
	static smb_native_t os_table[] = {
		{ NATIVE_OS_WINNT,	"Windows NT 4.0"	},
		{ NATIVE_OS_WINNT,	"Windows NT"		},
		{ NATIVE_OS_WIN95,	"Windows 4.0"		},
		{ NATIVE_OS_WIN2000,	"Windows 5.0"		},
		{ NATIVE_OS_WIN2000,	"Windows 5.1"		},
		{ NATIVE_OS_WIN2000,	"Windows 2000"		},
		{ NATIVE_OS_WIN2000,	"Windows 2002"		},
		{ NATIVE_OS_WIN2000,	"Windows .NET"		},
		{ NATIVE_OS_WIN2000,	"Windows Server"	},
		{ NATIVE_OS_WIN2000,	"Windows XP"		},
		{ NATIVE_OS_WINNT,	"UNIX"			},
		{ NATIVE_OS_MACOS,	"MacOS" 		}
	};

	int i;
	int len;
	const char *name;

	if (native_os == NULL)
		return (NATIVE_OS_UNKNOWN);

	/*
	 * Windows Vista sends an empty native OS string.
	 */
	if (*native_os == '\0')
		return (NATIVE_OS_WIN2000);

	for (i = 0; i < sizeof (os_table)/sizeof (os_table[0]); ++i) {
		name = os_table[i].sn_name;
		len = strlen(name);

		if (smb_strcasecmp(name, native_os, len) == 0)
			return (os_table[i].sn_value);
	}

	return (NATIVE_OS_UNKNOWN);
}

/*
 * smbnative_lm_value
 *
 * Return the appropriate native LanMan value for the specified native
 * LanMan name. There's an alignment problem in some packets from some
 * clients that means we can miss the first character, so we do an
 * additional check starting from the second character.
 *
 * Example LanMan values:
 *
 *	NT LAN Manager 4.0
 *	Windows 4.0
 *	Windows NT, Windows NT 4.0
 *	Windows 2000 LAN Manager
 *	Windows 2000, Windows 2000 5.0, Windows 2000 5.1
 *	Windows 2002, Windows 2002 5.1
 *	Windows .NET, Windows .NET 5.2
 *	Windows Server 2003
 *	Windows XP
 *	NETSMB		(Solaris CIFS client)
 *	DAVE		(Thursby Software: CIFS for MacOS)
 *	Samba
 */
int
smbnative_lm_value(const char *native_lm)
{
	static smb_native_t lm_table[] = {
		{ NATIVE_LM_NT,		"NT LAN Manager 4.0"		},
		{ NATIVE_LM_NT,		"Windows NT"			},
		{ NATIVE_LM_NT,		"Windows 4.0"			},
		{ NATIVE_LM_NT,		"DAVE"				}
	};

	int i;
	int len;
	const char *name;

	/*
	 * Windows Vista sends an empty native LM string.
	 */
	if (native_lm == NULL || *native_lm == '\0')
		return (NATIVE_LM_WIN2000);

	for (i = 0; i < sizeof (lm_table)/sizeof (lm_table[0]); ++i) {
		name = lm_table[i].sn_name;
		len = strlen(name);

		if ((smb_strcasecmp(name, native_lm, len) == 0) ||
		    (smb_strcasecmp(&name[1], native_lm, len - 1) == 0)) {
			return (lm_table[i].sn_value);
		}
	}

	return (NATIVE_LM_WIN2000);
}

/*
 * smbnative_pdc_value
 *
 * This function is called when libsmbrdr connects to a PDC.
 * The PDC type is derived from the Native LanMan string.
 * The PDC value will default to PDC_WIN2000.
 *
 * Example strings:
 *
 *	NT LAN Manager 4.0
 *	Windows 4.0, Windows NT, Windows NT 4.0
 *	Windows 2000 LAN Manager
 *	Windows 2000, Windows 2000 5.0, Windows 2000 5.1
 *	Windows 2002, Windows 2002 5.1
 *	Windows .NET, Windows .NET 5.2
 *	Samba
 *	DAVE
 */
int
smbnative_pdc_value(const char *native_lm)
{
	static smb_native_t pdc_table[] = {
		{ PDC_WINNT,	"NT LAN Manager 4.0"		},
		{ PDC_WINNT,	"Windows NT 4.0"		},
		{ PDC_WINNT,	"Windows NT"			},
		{ PDC_WINNT,	"Windows 4.0"			},
		{ PDC_WINNT,	"DAVE"				},
		{ PDC_SAMBA,	"Samba"				}
	};

	int i;
	int len;
	const char *name;

	if (native_lm == NULL || *native_lm == '\0')
		return (PDC_WIN2000);

	for (i = 0; i < sizeof (pdc_table)/sizeof (pdc_table[0]); ++i) {
		name = pdc_table[i].sn_name;
		len = strlen(name);

		if ((smb_strcasecmp(name, native_lm, len) == 0) ||
		    (smb_strcasecmp(&name[1], native_lm, len - 1) == 0)) {
			return (pdc_table[i].sn_value);
		}
	}

	return (PDC_WIN2000);
}

/*
 * Returns the native OS string for the given OS version.
 * If no match is found the string for Windows 2000 is returned.
 */
const char *
smbnative_os_str(smb_version_t *version)
{
	int i;

	static smb_native_t osstr_table[] = {
		{ SMB_MAJOR_NT,		"Windows NT"		},
		{ SMB_MAJOR_2000,	"Windows 2000"		},
		{ SMB_MAJOR_XP,		"Windows XP"		},
		{ SMB_MAJOR_2003,	"Windows Server 2003"	},
		{ SMB_MAJOR_VISTA,	""			},
		{ SMB_MAJOR_2008,	""			},
		{ SMB_MAJOR_2008R2,	""			}
	};

	for (i = 0; i < sizeof (osstr_table)/sizeof (osstr_table[0]); ++i) {
		if (version->sv_major == osstr_table[i].sn_value)
			return (osstr_table[i].sn_name);
	}

	return (osstr_table[1].sn_name);
}

/*
 * Returns the native Lanman string for the given OS version.
 * If no match is found the string for Windows 2000 is returned.
 */
const char *
smbnative_lm_str(smb_version_t *version)
{
	int i;

	static smb_native_t lmstr_table[] = {
		{ SMB_MAJOR_NT,		"NT LAN Manager 4.0"		},
		{ SMB_MAJOR_2000,	"Windows 2000 LAN Manager"	},
		{ SMB_MAJOR_XP,		"Windows 2002 5.1"		},
		{ SMB_MAJOR_2003,	"Windows Server 2003 5.2"	},
		{ SMB_MAJOR_VISTA,	""				},
		{ SMB_MAJOR_2008,	""				},
		{ SMB_MAJOR_2008R2,	""				}
	};

	for (i = 0; i < sizeof (lmstr_table)/sizeof (lmstr_table[0]); ++i) {
		if (version->sv_major == lmstr_table[i].sn_value)
			return (lmstr_table[i].sn_name);
	}

	return (lmstr_table[1].sn_name);
}
