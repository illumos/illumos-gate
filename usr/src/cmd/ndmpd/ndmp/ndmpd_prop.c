/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NDMP configuration management
 */
#include <stdio.h>
#include <stdlib.h>
#include <synch.h>
#include <syslog.h>
#include <strings.h>
#include <ndmpd_prop.h>
#include <libndmp.h>
#include "ndmpd.h"

typedef struct ndmpd_cfg_param {
	char		*sc_name;
	char		*sc_defval;
	char		*sc_value;
	uint32_t	sc_flags;
} ndmpd_cfg_param_t;


static int ndmpd_config_update(ndmpd_cfg_param_t *cfg, char *value);

/*
 * IMPORTANT: any changes to the order of this table's entries
 * need to be reflected in the enum ndmpd_cfg_id_t.
 */
ndmpd_cfg_param_t ndmpd_cfg_table[] =
{
	{"dar-support",			"",	0, NDMP_CF_NOTINIT},
	{"mover-nic",			"",	0, NDMP_CF_NOTINIT},
	{"dump-pathnode",		"",	0, NDMP_CF_NOTINIT},
	{"tar-pathnode",		"",	0, NDMP_CF_NOTINIT},
	{"fh-inode",			"",	0, NDMP_CF_NOTINIT},
	{"ignore-ctime",		"",	0, NDMP_CF_NOTINIT},
	{"include-lmtime",		"",	0, NDMP_CF_NOTINIT},
	{"token-maxseq",		"",	0, NDMP_CF_NOTINIT},
	{"version",			"",	0, NDMP_CF_NOTINIT},
	{"restore-fullpath",		"",	0, NDMP_CF_NOTINIT},
	{"debug-path",			"",	0, NDMP_CF_NOTINIT},
	{"plugin-path",			"",	0, NDMP_CF_NOTINIT},
	{"socket-css",			"",	0, NDMP_CF_NOTINIT},
	{"socket-crs",			"",	0, NDMP_CF_NOTINIT},
	{"mover-recordsize",		"",	0, NDMP_CF_NOTINIT},
	{"restore-wildcard-enable",	"",	0, NDMP_CF_NOTINIT},
	{"cram-md5-username",		"",	0, NDMP_CF_NOTINIT},
	{"cram-md5-password",		"",	0, NDMP_CF_NOTINIT},
	{"cleartext-username",		"",	0, NDMP_CF_NOTINIT},
	{"cleartext-password",		"",	0, NDMP_CF_NOTINIT},
	{"tcp-port",			"",	0, NDMP_CF_NOTINIT},
	{"backup-quarantine",		"",	0, NDMP_CF_NOTINIT},
	{"restore-quarantine",		"",	0, NDMP_CF_NOTINIT},
	{"overwrite-quarantine",	"",	0, NDMP_CF_NOTINIT},
	{"zfs-force-override",		"",	0, NDMP_CF_NOTINIT},
	{"drive-type",			"",	0, NDMP_CF_NOTINIT},
	{"debug-mode",			"",	0, NDMP_CF_NOTINIT},
};

/*
 * Loads all the NDMP configuration parameters and sets up the
 * config table.
 */
int
ndmpd_load_prop(void)
{
	ndmpd_cfg_id_t id;
	ndmpd_cfg_param_t *cfg;
	char *value;

	for (id = 0; id < NDMP_MAXALL; id++) {
		cfg = &ndmpd_cfg_table[id];
		if ((ndmp_get_prop(cfg->sc_name, &value)) == -1) {
			syslog(LOG_DEBUG, "%s %s",
			    cfg->sc_name, ndmp_strerror(ndmp_errno));
			continue;
		}
		/*
		 * enval == 0 could mean two things, either the
		 * config param is not defined, or it has been
		 * removed. If the variable has already been defined
		 * and now enval is 0, it should be removed, otherwise
		 * we don't need to do anything in this case.
		 */
		if ((cfg->sc_flags & NDMP_CF_DEFINED) || value) {
			if (ndmpd_config_update(cfg, value)) {
				free(value);
				return (-1);
			}
		}
		free(value);
	}
	return (0);
}

/*
 * ndmpd_config_update
 *
 * Updates the specified config param with the given value.
 * This function is called both on (re)load and set.
 */
static int
ndmpd_config_update(ndmpd_cfg_param_t *cfg, char *value)
{
	char *curval;
	int rc = 0;
	int len;

	if (value) {
		len = strlen(value);
		if (cfg->sc_value) {
			curval = realloc(cfg->sc_value, (len + 1));
		} else {
			curval = ndmp_malloc(len + 1);
		}

		if (curval) {
			cfg->sc_value = curval;
			(void) strcpy(cfg->sc_value, value);
			cfg->sc_flags |= NDMP_CF_DEFINED;
		} else {
			syslog(LOG_ERR, "Out of memory.");
			rc = -1;
		}
	} else if (cfg->sc_value) {
		free(cfg->sc_value);
		cfg->sc_value = 0;
		cfg->sc_flags &= ~NDMP_CF_DEFINED;
	}

	return (rc);
}

/*
 * Returns value of the specified config param.
 * The return value is a string pointer to the locally
 * allocated memory if the config param is defined
 * otherwise it would be NULL.
 */
char *
ndmpd_get_prop(ndmpd_cfg_id_t id)
{
	char *env_val;

	if (id < NDMP_MAXALL) {
		env_val = ndmpd_cfg_table[id].sc_value;
		return (env_val);
	}

	return (0);
}

/*
 * Similar to ndmpd_get_prop except it will return dflt value
 * if env is not set.
 */
char *
ndmpd_get_prop_default(ndmpd_cfg_id_t id, char *dflt)
{
	char *env;

	env = ndmpd_get_prop(id);

	if (env && *env != 0) {
		return (env);
	} else {
		return (dflt);
	}
}

/*
 * Returns the value of a yes/no config param.
 * Returns 1 is config is set to "yes", otherwise 0.
 */
int
ndmpd_get_prop_yorn(ndmpd_cfg_id_t id)
{
	char *val;

	val = ndmpd_get_prop(id);
	if (val) {
		if (strcasecmp(val, "yes") == 0)
			return (1);
	}

	return (0);
}
