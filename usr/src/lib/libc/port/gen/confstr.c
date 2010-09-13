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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma	weak _confstr = confstr

#include "lint.h"
#include "xpg6.h"
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

typedef struct {
	int	config_value;
	char	*value;
} config;

/*
 * keep these in the same order as in sys/unistd.h
 */
static const config	default_conf[] = {
	{ _CS_LFS_CFLAGS,	"-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64" },
	{ _CS_LFS_LDFLAGS,	""					},
	{ _CS_LFS_LIBS,		""					},
	{ _CS_LFS_LINTFLAGS,	"-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64" },
	{ _CS_LFS64_CFLAGS,	"-D_LARGEFILE64_SOURCE"			},
	{ _CS_LFS64_LDFLAGS,	""					},
	{ _CS_LFS64_LIBS,	""					},
	{ _CS_LFS64_LINTFLAGS,	"-D_LARGEFILE64_SOURCE"			},
	{ _CS_XBS5_ILP32_OFF32_CFLAGS,	""				},
	{ _CS_XBS5_ILP32_OFF32_LDFLAGS,	""				},
	{ _CS_XBS5_ILP32_OFF32_LIBS,	""				},
	{ _CS_XBS5_ILP32_OFF32_LINTFLAGS, ""				},
	{ _CS_XBS5_ILP32_OFFBIG_CFLAGS,
"-Xa -Usun -Usparc -Uunix -Ui386 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64" },
	{ _CS_XBS5_ILP32_OFFBIG_LDFLAGS, ""				},
	{ _CS_XBS5_ILP32_OFFBIG_LIBS,	""				},
	{ _CS_XBS5_ILP32_OFFBIG_LINTFLAGS,
		"-Xa -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"},
	{ _CS_POSIX_V6_ILP32_OFF32_CFLAGS,	""			},
	{ _CS_POSIX_V6_ILP32_OFF32_LDFLAGS,	""			},
	{ _CS_POSIX_V6_ILP32_OFF32_LIBS,	""			},
	{ _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS,
"-Xa -Usun -Usparc -Uunix -Ui386 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64" },
	{ _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS,	""			},
	{ _CS_POSIX_V6_ILP32_OFFBIG_LIBS,	""			},
	{ _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS,
		"POSIX_V6_ILP32_OFF32\nPOSIX_V6_ILP32_OFFBIG\n"
		"POSIX_V6_LP64_OFF64\nPOSIX_V6_LPBIG_OFFBIG"		},
	{ _CS_XBS5_LP64_OFF64_CFLAGS, "-xarch=generic64"		},
	{ _CS_XBS5_LP64_OFF64_LDFLAGS,	"-xarch=generic64"		},
	{ _CS_XBS5_LP64_OFF64_LIBS,	""				},
	{ _CS_XBS5_LP64_OFF64_LINTFLAGS, "-xarch=generic64" 		},
	{ _CS_XBS5_LPBIG_OFFBIG_CFLAGS, "-xarch=generic64" 		},
	{ _CS_XBS5_LPBIG_OFFBIG_LDFLAGS, "-xarch=generic64"		},
	{ _CS_XBS5_LPBIG_OFFBIG_LIBS,	""				},
	{ _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS, "-xarch=generic64"		},
	{ _CS_POSIX_V6_LP64_OFF64_CFLAGS, "-xarch=generic64"		},
	{ _CS_POSIX_V6_LP64_OFF64_LDFLAGS, "-xarch=generic64"		},
	{ _CS_POSIX_V6_LP64_OFF64_LIBS,	""				},
	{ _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS, "-xarch=generic64" 		},
	{ _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS, "-xarch=generic64"		},
	{ _CS_POSIX_V6_LPBIG_OFFBIG_LIBS, ""				},
};

#define	CS_ENTRY_COUNT (sizeof (default_conf) / sizeof (config))

size_t
confstr(int name, char *buf, size_t length)
{
	size_t			conf_length;
	config			*entry;
	int			i;
	char			*path;

	/* Keep _CS_PATH in sync with execvp.c */

	if (name == _CS_PATH) {
		if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
			path = "/usr/xpg6/bin:/usr/xpg4/bin:/usr/ccs/bin:"
			    "/usr/bin:/opt/SUNWspro/bin";
		else
			path = "/usr/xpg4/bin:/usr/ccs/bin:/usr/bin:"
			    "/opt/SUNWspro/bin";

		conf_length = strlen(path) + 1;
		if (length != 0) {
			(void) strncpy(buf, path, length);
			buf[length - 1] = '\0';
		}
		return (conf_length);
	}
	/*
	 * Make sure others are known configuration parameters
	 */
	entry = (config *)default_conf;
	for (i = 0; i < CS_ENTRY_COUNT; i++) {
		if (name == entry->config_value) {
			/*
			 * Copy out the parameter from our tables.
			 */
			conf_length = strlen(entry->value) + 1;
			if (length != 0) {
				(void) strncpy(buf, entry->value, length);
				buf[length - 1] = '\0';
			}
			return (conf_length);
		}
		entry++;
	}

	/* If the entry was not found in table return an error */
	errno = EINVAL;
	return ((size_t)0);
}
