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

#include <sys/types.h>
#include <sys/acctctl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <libdllink.h>
#include <libscf.h>
#include <pwd.h>
#include <auth_attr.h>
#include <nss_dbdefs.h>
#include <secdb.h>
#include <priv.h>
#include <zone.h>

#include "aconf.h"
#include "utils.h"
#include "res.h"

#define	FMRI_FLOW_ACCT	"svc:/system/extended-accounting:flow"
#define	FMRI_PROC_ACCT	"svc:/system/extended-accounting:process"
#define	FMRI_TASK_ACCT	"svc:/system/extended-accounting:task"
#define	FMRI_NET_ACCT	"svc:/system/extended-accounting:net"

#define	NELEM(x)	(sizeof (x)) / (sizeof (x[0]))

typedef struct props {
	char *propname;
	int proptype;
	scf_transaction_entry_t *entry;
	scf_value_t *value;
	struct props *next;
} props_t;

static void	aconf_print_type(acctconf_t *, FILE *, int);
static int	aconf_get_bool(const char *, const char *, uint8_t *);
static int	aconf_get_string(const char *, const char *, char *, size_t);
static props_t	*aconf_prop(const char *, int);
static int	aconf_fmri2type(const char *);

static scf_handle_t	*handle = NULL;
static scf_instance_t	*inst = NULL;
static props_t		*props = NULL;

void
aconf_init(acctconf_t *acp, int type)
{
	void *buf;
	char *tracked;
	char *untracked;

	if ((buf = malloc(AC_BUFSIZE)) == NULL)
		die(gettext("not enough memory\n"));

	if (acctctl(type | AC_STATE_GET, &acp->state,
	    sizeof (acp->state)) == -1)
		die(gettext("cannot get %s accounting state\n"),
		    ac_type_name(type));

	(void) memset(acp->file, 0, sizeof (acp->file));
	if (acctctl(type | AC_FILE_GET, acp->file, sizeof (acp->file)) == -1) {
		if (errno == ENOTACTIVE)
			(void) strlcpy(acp->file, AC_STR_NONE,
			    sizeof (acp->file));
		else
			die(gettext("cannot get %s accounting file name"),
			    ac_type_name(type));
	}
	(void) memset(buf, 0, AC_BUFSIZE);
	if (acctctl(type | AC_RES_GET, buf, AC_BUFSIZE) == -1)
		die(gettext("cannot obtain the list of enabled resources\n"));

	tracked = buf2str(buf, AC_BUFSIZE, AC_ON, type);
	untracked = buf2str(buf, AC_BUFSIZE, AC_OFF, type);
	(void) strlcpy(acp->tracked, tracked, sizeof (acp->tracked));
	(void) strlcpy(acp->untracked, untracked, sizeof (acp->untracked));
	free(tracked);
	free(untracked);
	free(buf);
}

/*
 * SMF start method: configure extended accounting from properties stored in
 * the repository.  Any errors encountered while retrieving properties from
 * the repository, such as missing properties or properties of the wrong type,
 * are fatal as they indicate severe damage to the service (all required
 * properties are delivered in the service manifest and should thus always be
 * present).  No attempts will be made to repair such damage;  the service will
 * be forced into maintenance state by returning SMF_EXIT_ERR_CONFIG.  For all
 * other errors we we try to configure as much as possible and return
 * SMF_EXIT_ERR_FATAL.
 */
int
aconf_setup(const char *fmri)
{
	char file[MAXPATHLEN];
	char tracked[MAXRESLEN];
	char untracked[MAXRESLEN];
	void *buf;
	int type;
	int state;
	uint8_t b;
	int ret = SMF_EXIT_OK;

	if ((type = aconf_fmri2type(fmri)) == -1) {
		warn(gettext("no accounting type for %s\n"), fmri);
		return (SMF_EXIT_ERR_FATAL);
	}

	/*
	 * Net/Flow accounting is not available in non-global zones and
	 * the service instance should therefore never be 'enabled' in
	 * non-global zones.  This is enforced by acctadm(8), but there is
	 * nothing that prevents someone from calling svcadm enable directly,
	 * so we handle that case here by disabling the instance.
	 */
	if ((type == AC_FLOW || type == AC_NET) &&
	    getzoneid() != GLOBAL_ZONEID) {
		(void) smf_disable_instance(fmri, 0);
		warn(gettext("%s accounting cannot be configured in "
		    "non-global zones\n"), ac_type_name(type));
		return (SMF_EXIT_OK);
	}

	if (aconf_scf_init(fmri) == -1) {
		warn(gettext("cannot connect to repository\n"));
		return (SMF_EXIT_ERR_FATAL);
	}
	if (aconf_get_string(AC_PGNAME, AC_PROP_TRACKED, tracked,
	    sizeof (tracked)) == -1) {
		warn(gettext("cannot get %s property\n"), AC_PROP_TRACKED);
		ret = SMF_EXIT_ERR_CONFIG;
		goto out;
	}
	if (aconf_get_string(AC_PGNAME, AC_PROP_UNTRACKED, untracked,
	    sizeof (untracked)) == -1) {
		warn(gettext("cannot get %s property\n"), AC_PROP_UNTRACKED);
		ret = SMF_EXIT_ERR_CONFIG;
		goto out;
	}
	if (aconf_get_string(AC_PGNAME, AC_PROP_FILE, file,
	    sizeof (file)) == -1) {
		warn(gettext("cannot get %s property\n"), AC_PROP_FILE);
		ret = SMF_EXIT_ERR_CONFIG;
		goto out;
	}
	if (aconf_get_bool(AC_PGNAME, AC_PROP_STATE, &b) == -1) {
		warn(gettext("cannot get %s property\n"), AC_PROP_STATE);
		ret = SMF_EXIT_ERR_CONFIG;
		goto out;
	}
	state = (b ? AC_ON : AC_OFF);

	if ((buf = malloc(AC_BUFSIZE)) == NULL) {
		warn(gettext("not enough memory\n"));
		ret = SMF_EXIT_ERR_FATAL;
		goto out;
	}
	(void) memset(buf, 0, AC_BUFSIZE);
	str2buf(buf, untracked, AC_OFF, type);
	str2buf(buf, tracked, AC_ON, type);

	(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);
	if (acctctl(type | AC_RES_SET, buf, AC_BUFSIZE) == -1) {
		warn(gettext("cannot enable/disable %s accounting resources"),
		    ac_type_name(type));
		ret = SMF_EXIT_ERR_FATAL;
	}
	free(buf);

	if (strcmp(file, AC_STR_NONE) != 0) {
		if (open_exacct_file(file, type) == -1)
			ret = SMF_EXIT_ERR_FATAL;
	} else {
		if (acctctl(type | AC_FILE_SET, NULL, 0) == -1) {
			warn(gettext("cannot close %s accounting file"),
			    ac_type_name(type));
			ret = SMF_EXIT_ERR_FATAL;
		}
	}
	if (acctctl(type | AC_STATE_SET, &state, sizeof (state)) == -1) {
		warn(gettext("cannot %s %s accounting"),
		    state == AC_ON ? gettext("enable") : gettext("disable"),
		    ac_type_name(type));
		ret = SMF_EXIT_ERR_FATAL;
	}
	(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);

	if (state == AC_ON && type == AC_NET) {
		/*
		 * Start logging.
		 */
		(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_SYS_DL_CONFIG,
		    NULL);
		(void) dladm_start_usagelog(dld_handle,
		    strncmp(tracked, "basic", strlen("basic")) == 0 ?
		    DLADM_LOGTYPE_LINK : DLADM_LOGTYPE_FLOW, 20);
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_SYS_DL_CONFIG,
		    NULL);
	}
out:
	aconf_scf_fini();
	return (ret);
}

void
aconf_print(FILE *fp, int types)
{
	acctconf_t ac;
	int print_order[] = { AC_TASK, AC_PROC, AC_FLOW, AC_NET };
	int i;

	for (i = 0; i < NELEM(print_order); i++) {
		if (types & print_order[i]) {
			aconf_init(&ac, print_order[i]);
			aconf_print_type(&ac, fp, print_order[i]);
		}
	}
}

static void
aconf_print_type(acctconf_t *acp, FILE *fp, int type)
{
	switch (type) {
	case AC_TASK:
		(void) fprintf(fp,
		    gettext("            Task accounting: %s\n"),
		    acp->state == AC_ON ?
		    gettext("active") : gettext("inactive"));
		(void) fprintf(fp,
		    gettext("       Task accounting file: %s\n"),
		    acp->file);
		(void) fprintf(fp,
		    gettext("     Tracked task resources: %s\n"),
		    acp->tracked);
		(void) fprintf(fp,
		    gettext("   Untracked task resources: %s\n"),
		    acp->untracked);
		break;
	case AC_PROC:
		(void) fprintf(fp,
		    gettext("         Process accounting: %s\n"),
		    acp->state == AC_ON ?
		    gettext("active") : gettext("inactive"));
		(void) fprintf(fp,
		    gettext("    Process accounting file: %s\n"),
		    acp->file);
		(void) fprintf(fp,
		    gettext("  Tracked process resources: %s\n"),
		    acp->tracked);
		(void) fprintf(fp,
		    gettext("Untracked process resources: %s\n"),
		    acp->untracked);
		break;
	case AC_FLOW:
		(void) fprintf(fp,
		    gettext("            Flow accounting: %s\n"),
		    acp->state == AC_ON ?
		    gettext("active") : gettext("inactive"));
		(void) fprintf(fp,
		    gettext("       Flow accounting file: %s\n"),
		    acp->file);
		(void) fprintf(fp,
		    gettext("     Tracked flow resources: %s\n"),
		    acp->tracked);
		(void) fprintf(fp,
		    gettext("   Untracked flow resources: %s\n"),
		    acp->untracked);
		break;
	case AC_NET:
		(void) fprintf(fp,
		    gettext("            Net accounting: %s\n"),
		    acp->state == AC_ON ?
		    gettext("active") : gettext("inactive"));
		(void) fprintf(fp,
		    gettext("       Net accounting file: %s\n"),
		    acp->file);
		(void) fprintf(fp,
		    gettext("     Tracked net resources: %s\n"),
		    acp->tracked);
		(void) fprintf(fp,
		    gettext("   Untracked net resources: %s\n"),
		    acp->untracked);
		break;
	}
}

/*
 * Modified properties are put on the 'props' linked list by aconf_set_string()
 * and aconf_set_bool().  Walk the list of modified properties and write them
 * to the repository.  The list is deleted on exit.
 */
int
aconf_save(void)
{
	scf_propertygroup_t *pg;
	scf_transaction_t *tx;
	props_t *p;
	props_t *q;
	int tx_result;

	if (props == NULL)
		return (0);

	if ((pg = scf_pg_create(handle)) == NULL ||
	    scf_instance_get_pg(inst, AC_PGNAME, pg) == -1 ||
	    (tx = scf_transaction_create(handle)) == NULL)
		goto out;

	do {
		if (scf_pg_update(pg) == -1 ||
		    scf_transaction_start(tx, pg) == -1)
			goto out;

		for (p = props; p != NULL; p = p->next) {
			if (scf_transaction_property_change(tx, p->entry,
			    p->propname, p->proptype) == -1)
				goto out;
			(void) scf_entry_add_value(p->entry, p->value);
		}
		tx_result = scf_transaction_commit(tx);
		scf_transaction_reset(tx);
	} while (tx_result == 0);

out:
	p = props;
	while (p != NULL) {
		scf_value_destroy(p->value);
		scf_entry_destroy(p->entry);
		free(p->propname);
		q = p->next;
		free(p);
		p = q;
	}
	props = NULL;
	scf_transaction_destroy(tx);
	scf_pg_destroy(pg);
	return ((tx_result == 1) ? 0 : -1);
}

boolean_t
aconf_have_smf_auths(void)
{
	char auth[NSS_BUFLEN_AUTHATTR];
	struct passwd *pw;

	if ((pw = getpwuid(getuid())) == NULL)
		return (B_FALSE);

	if (aconf_get_string("general", "action_authorization", auth,
	    sizeof (auth)) == -1 || chkauthattr(auth, pw->pw_name) == 0)
		return (B_FALSE);

	if (aconf_get_string("general", "value_authorization", auth,
	    sizeof (auth)) == -1 || chkauthattr(auth, pw->pw_name) == 0)
		return (B_FALSE);

	if (aconf_get_string("config", "value_authorization", auth,
	    sizeof (auth)) == -1 || chkauthattr(auth, pw->pw_name) == 0)
		return (B_FALSE);

	return (B_TRUE);
}

const char *
aconf_type2fmri(int type)
{
	switch (type) {
	case AC_PROC:
		return (FMRI_PROC_ACCT);
	case AC_TASK:
		return (FMRI_TASK_ACCT);
	case AC_FLOW:
		return (FMRI_FLOW_ACCT);
	case AC_NET:
		return (FMRI_NET_ACCT);
	default:
		die(gettext("invalid type %d\n"), type);
	}
	/* NOTREACHED */
	return (NULL);
}

static int
aconf_fmri2type(const char *fmri)
{
	if (strcmp(fmri, FMRI_PROC_ACCT) == 0)
		return (AC_PROC);
	else if (strcmp(fmri, FMRI_TASK_ACCT) == 0)
		return (AC_TASK);
	else if (strcmp(fmri, FMRI_FLOW_ACCT) == 0)
		return (AC_FLOW);
	else if (strcmp(fmri, FMRI_NET_ACCT) == 0)
		return (AC_NET);
	else
		return (-1);
}

int
aconf_scf_init(const char *fmri)
{
	if ((handle = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(handle) == -1 ||
	    (inst = scf_instance_create(handle)) == NULL ||
	    scf_handle_decode_fmri(handle, fmri, NULL, NULL, inst, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) == -1) {
		aconf_scf_fini();
		return (-1);
	}
	return (0);
}

void
aconf_scf_fini(void)
{
	scf_instance_destroy(inst);
	(void) scf_handle_unbind(handle);
	scf_handle_destroy(handle);
}

static int
aconf_get_string(const char *pgname, const char *propname, char *buf,
    size_t len)
{
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *value;
	int ret = 0;

	if ((pg = scf_pg_create(handle)) == NULL)
		return (-1);

	if (scf_instance_get_pg_composed(inst, NULL, pgname, pg) == -1) {
		scf_pg_destroy(pg);
		return (-1);
	}

	if ((prop = scf_property_create(handle)) == NULL ||
	    (value = scf_value_create(handle)) == NULL ||
	    scf_pg_get_property(pg, propname, prop) == -1 ||
	    scf_property_get_value(prop, value) == -1 ||
	    scf_value_get_astring(value, buf, len) == -1)
		ret = -1;

	scf_value_destroy(value);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	return (ret);
}

static int
aconf_get_bool(const char *pgname, const char *propname, uint8_t *rval)
{
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *value;
	int ret = 0;

	if ((pg = scf_pg_create(handle)) == NULL)
		return (-1);

	if (scf_instance_get_pg_composed(inst, NULL, pgname, pg) == -1) {
		scf_pg_destroy(pg);
		return (-1);
	}

	if ((prop = scf_property_create(handle)) == NULL ||
	    (value = scf_value_create(handle)) == NULL ||
	    scf_pg_get_property(pg, propname, prop) == -1 ||
	    scf_property_get_value(prop, value) == -1 ||
	    scf_value_get_boolean(value, rval) == -1)
		ret = -1;

	scf_value_destroy(value);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	return (ret);
}

int
aconf_set_string(const char *propname, const char *value)
{
	props_t *p;

	if ((p = aconf_prop(propname, SCF_TYPE_ASTRING)) == NULL)
		return (-1);

	if (scf_value_set_astring(p->value, value) == -1)
		return (-1);
	return (0);
}

int
aconf_set_bool(const char *propname, boolean_t value)
{
	props_t *p;

	if ((p = aconf_prop(propname, SCF_TYPE_BOOLEAN)) == NULL)
		return (-1);

	scf_value_set_boolean(p->value, value);
	return (0);
}

static props_t *
aconf_prop(const char *propname, int proptype)
{
	props_t *p;

	if ((p = malloc(sizeof (props_t))) != NULL) {
		if ((p->propname = strdup(propname)) == NULL) {
			free(p);
			return (NULL);
		}
		if ((p->entry = scf_entry_create(handle)) == NULL) {
			free(p->propname);
			free(p);
			return (NULL);
		}
		if ((p->value = scf_value_create(handle)) == NULL) {
			scf_entry_destroy(p->entry);
			free(p->propname);
			free(p);
			return (NULL);
		}
		p->proptype = proptype;
		p->next = props;
		props = p;
	}
	return (p);
}
