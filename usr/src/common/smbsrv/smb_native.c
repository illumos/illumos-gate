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

/*
 * This module defines generic functions to map Native OS and Native
 * LanMan names to values.
 */

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <string.h>
#endif
#include <smbsrv/string.h>
#include <smbsrv/smbinfo.h>

/*
 * smbnative_os_value
 *
 * Return the appropriate native OS value for the specified native OS name.
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
smbnative_os_value(char *native_os)
{
	typedef struct native_os_table {
		int os_value;
		char *os_name;
	} native_os_table_t;

	static native_os_table_t os_table[] = {
		{ NATIVE_OS_WINNT,	"Windows NT 4.0"	},
		{ NATIVE_OS_WINNT,	"Windows NT"		},
		{ NATIVE_OS_WIN95,	"Windows 4.0"		},
		{ NATIVE_OS_WIN2000,	"Windows 5.0"		},
		{ NATIVE_OS_WIN2000,	"Windows 5.1"		},
		{ NATIVE_OS_WIN2000,	"Windows 2000 5.0"	},
		{ NATIVE_OS_NT5_1,	"Windows 2000 5.1"	},
		{ NATIVE_OS_WIN2000,	"Windows 2000"		},
		{ NATIVE_OS_WIN2000,	"Windows 2002"		},
		{ NATIVE_OS_WIN2000,	"Windows .NET"		},
		{ NATIVE_OS_WIN2000,	"Windows Server 2003"	},
		{ NATIVE_OS_WIN2000,	"Windows XP"		},
		{ NATIVE_OS_WINNT,	"UNIX"			},
		{ NATIVE_OS_MACOS,	"MacOS" 		}
	};

	int i;
	int len;
	char *os_name;

	if (native_os == NULL) {
		return (NATIVE_OS_UNKNOWN);
	}

	for (i = 0; i < sizeof (os_table)/sizeof (os_table[0]); ++i) {
		os_name = os_table[i].os_name;
		len = strlen(os_name);

		if (utf8_strncasecmp(os_name, native_os, len) == 0) {
			return (os_table[i].os_value);
		}
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
 * DAVE (Thursby Software: CIFS for MacOS) sometimes uses a Unicode
 * character in the LanMan name. Variations seen so far are:
 *
 *	44 00 41 00 56 00 45 00 00 00        D.A.V.E...
 *
 *	44 00 41 00 56 00 45 00 22 21 20 00 56 00 32 00
 *	2E 00 35 00 2E 00 31 00 00 00        D.A.V.E."!..V.2...5...1...
 *
 * Samba reports its own name (Samba) as its Native LM, which we can
 * map to NT LM 4.0.
 */
int
smbnative_lm_value(char *native_lm)
{
	typedef struct native_lm_table {
		int lm_value;
		char *lm_name;
	} native_lm_table_t;

	static native_lm_table_t lm_table[] = {
		{ NATIVE_LM_NT,		"NT LAN Manager 4.0"		},
		{ NATIVE_LM_NT,		"Windows NT 4.0"		},
		{ NATIVE_LM_NT,		"Windows NT"			},
		{ NATIVE_LM_NT,		"Windows 4.0"			},
		{ NATIVE_LM_WIN2000,	"Windows 2000 LAN Manager"	},
		{ NATIVE_LM_WIN2000,	"Windows 2000 5.0"		},
		{ NATIVE_LM_WIN2000,	"Windows 2000 5.1"		},
		{ NATIVE_LM_WIN2000,	"Windows 2000",			},
		{ NATIVE_LM_WIN2000,	"Windows 2002 5.1"		},
		{ NATIVE_LM_WIN2000,	"Windows 2002"			},
		{ NATIVE_LM_WIN2000,	"Windows .NET 5.2"		},
		{ NATIVE_LM_WIN2000,	"Windows .NET"			},
		{ NATIVE_LM_WIN2000,	"Windows Server 2003"		},
		{ NATIVE_LM_WIN2000,	"Windows XP"			},
		{ NATIVE_LM_NT,		"Samba"				},
		{ NATIVE_LM_NT,		"DAVE"				}
	};

	int i;
	int len;
	char *lm_name;

	if (native_lm == NULL) {
		return (NATIVE_LM_NONE);
	}

	for (i = 0; i < sizeof (lm_table)/sizeof (lm_table[0]); ++i) {
		lm_name = lm_table[i].lm_name;
		len = strlen(lm_name);

		if ((utf8_strncasecmp(lm_name, native_lm, len) == 0) ||
		    (utf8_strncasecmp(&lm_name[1], native_lm, len - 1) == 0)) {
			return (lm_table[i].lm_value);
		}
	}
	return (NATIVE_LM_NONE);
}

/*
 * smbnative_pdc_value
 *
 * This function is used when NetFORCE contacting a PDC
 * to authenticate a connected user to determine and keep
 * the PDC type.
 *
 * The reason for adding this functionality is that NetFORCE
 * doesn't support Samba PDC but code didn't check the PDC type
 * and do authentication agains any PDC. This behaviour could
 * cause problem in some circumstances.
 * Now that we determine the PDC type the authentication code
 * can be configured (by smb.samba.pdc env var) to return access
 * denied to authentication attempts when PDC is Samba.
 */
int
smbnative_pdc_value(char *native_lm)
{
	typedef struct pdc_table {
		int pdc_value;
		char *pdc_lmname;
	} pdc_table_t;

	static pdc_table_t pdc_table[] = {
		{ PDC_WINNT,	"NT LAN Manager 4.0"		},
		{ PDC_WINNT,	"Windows NT 4.0"		},
		{ PDC_WINNT,	"Windows NT"			},
		{ PDC_WINNT,	"Windows 4.0"			},
		{ PDC_WIN2000,	"Windows 2000 LAN Manager"	},
		{ PDC_WIN2000,	"Windows 2000 5.0"		},
		{ PDC_WIN2000,	"Windows 2000 5.1"		},
		{ PDC_WIN2000,	"Windows 2000",			},
		{ PDC_WIN2000,	"Windows 2002 5.1"		},
		{ PDC_WIN2000,	"Windows 2002"			},
		{ PDC_WIN2000,	"Windows .NET 5.2"		},
		{ PDC_WIN2000,	"Windows .NET"			},
		{ PDC_SAMBA,	"Samba"				},
		{ PDC_WINNT,	"DAVE"				}
	};

	int i;
	int len;
	char *pdc_lmname;

	if (native_lm == 0) {
		return (PDC_UNKNOWN);
	}

	for (i = 0; i < sizeof (pdc_table)/sizeof (pdc_table[0]); ++i) {
		pdc_lmname = pdc_table[i].pdc_lmname;
		len = strlen(pdc_lmname);

		if ((utf8_strncasecmp(pdc_lmname, native_lm, len) == 0) ||
		    (utf8_strncasecmp(&pdc_lmname[1], native_lm, len - 1)
		    == 0)) {
			return (pdc_table[i].pdc_value);
		}
	}

	return (PDC_UNKNOWN);
}
