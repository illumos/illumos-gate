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

/*
 * This file defines the NT domain environment values and the domain
 * database interface. The database is a single linked list of
 * structures containing domain type, name and SID information.
 */

#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <syslog.h>
#include <synch.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/string.h>
#include <smbsrv/smb_sid.h>

#include <smbsrv/libsmb.h>


static void nt_domain_unlist(nt_domain_t *);

/*
 * Valid domain type identifiers as text. This table must be kept
 * in step with the nt_domain_type_t enum in ntdomain.h.
 */
static char *nt_domain_type_name[NT_DOMAIN_NUM_TYPES] = {
	"null",
	"builtin",
	"local",
	"primary",
	"account",
	"trusted",
	"untrusted"
};


static rwlock_t		nt_domain_lock;
static nt_domain_t	*nt_domain_list;

/*
 * nt_domain_init
 *
 * NT domain database one time initialization. This function should
 * be called during module installation.
 *
 * Returns 0 on successful domain initialization. Less than zero otherwise.
 */
int
nt_domain_init(char *resource_domain, uint32_t secmode)
{
	nt_domain_t *domain;
	smb_sid_t *sid = NULL;
	char sidstr[128];
	char *lsidstr;
	char hostname[NETBIOS_NAME_SZ];
	int rc;

	if (rwlock_init(&nt_domain_lock, USYNC_THREAD, NULL))
		return (SMB_DOMAIN_NODOMAIN_SID);

	if (smb_getnetbiosname(hostname, NETBIOS_NAME_SZ) != 0) {
		(void) rwlock_destroy(&nt_domain_lock);
		return (SMB_DOMAIN_NOMACHINE_SID);
	}

	lsidstr = smb_config_get_localsid();

	if (lsidstr) {
		sid = smb_sid_fromstr(lsidstr);

		if (sid) {
			domain = nt_domain_new(NT_DOMAIN_LOCAL, hostname, sid);
			(void) nt_domain_add(domain);
			free(sid);
		}
		free(lsidstr);
	} else {
		(void) rwlock_destroy(&nt_domain_lock);
		return (SMB_DOMAIN_NOMACHINE_SID);
	}

	if ((sid = smb_sid_fromstr(NT_BUILTIN_DOMAIN_SIDSTR)) != NULL) {
		domain = nt_domain_new(NT_DOMAIN_BUILTIN, "BUILTIN", sid);
		(void) nt_domain_add(domain);
		free(sid);
	}

	if (secmode == SMB_SECMODE_DOMAIN) {
		rc = smb_config_getstr(SMB_CI_DOMAIN_SID, sidstr,
		    sizeof (sidstr));
		sid = (rc == SMBD_SMF_OK) ? smb_sid_fromstr(sidstr) : NULL;
		if (smb_sid_isvalid(sid)) {
			domain = nt_domain_new(NT_DOMAIN_PRIMARY,
			    resource_domain, sid);
			(void) nt_domain_add(domain);
			free(sid);
		} else {
			free(sid);
			(void) rwlock_destroy(&nt_domain_lock);
			return (SMB_DOMAIN_NODOMAIN_SID);
		}

	}

	return (0);
}

/*
 * nt_domain_new
 *
 * Allocate and initialize a new domain structure. On success, a pointer to
 * the new domain structure is returned. Otherwise a null pointer is returned.
 */
nt_domain_t *
nt_domain_new(nt_domain_type_t type, char *name, smb_sid_t *sid)
{
	nt_domain_t *new_domain;

	if ((name == NULL) || (sid == NULL))
		return (NULL);

	if (type == NT_DOMAIN_NULL || type >= NT_DOMAIN_NUM_TYPES)
		return (NULL);

	if ((new_domain = malloc(sizeof (nt_domain_t))) == NULL)
		return (NULL);

	bzero(new_domain, sizeof (nt_domain_t));
	new_domain->type = type;
	new_domain->name = strdup(name);
	new_domain->sid = smb_sid_dup(sid);

	return (new_domain);
}

/*
 * nt_domain_delete
 *
 * Free the memory used by the specified domain structure.
 */
void
nt_domain_delete(nt_domain_t *domain)
{
	if (domain) {
		free(domain->name);
		free(domain->sid);
		free(domain);
	}
}


/*
 * nt_domain_add
 *
 * Add a domain structure to the global list. There is no checking
 * for duplicates. If it's the primary domain, we save the SID in the
 * environment. Returns a pointer to the new domain entry on success.
 * Otherwise a null pointer is returned.
 */
nt_domain_t *
nt_domain_add(nt_domain_t *new_domain)
{
	char sidstr[SMB_SID_STRSZ];

	if (new_domain == NULL)
		return (NULL);

	(void) rw_wrlock(&nt_domain_lock);

	new_domain->next = nt_domain_list;
	nt_domain_list = new_domain;

	if (new_domain->type == NT_DOMAIN_PRIMARY) {
		smb_sid_tostr(new_domain->sid, sidstr);
		(void) smb_config_setstr(SMB_CI_DOMAIN_SID, sidstr);
	}
	(void) rw_unlock(&nt_domain_lock);

	return (new_domain);
}


/*
 * nt_domain_remove
 *
 * Remove a domain from the global list. The memory
 * used by the structure is not freed.
 */
void
nt_domain_remove(nt_domain_t *domain)
{
	(void) rw_wrlock(&nt_domain_lock);
	nt_domain_unlist(domain);
	(void) rw_unlock(&nt_domain_lock);
}


/*
 * nt_domain_flush
 *
 * Flush all domains of the specified type from the list. This is
 * useful for things like updating the list of trusted domains.
 */
void
nt_domain_flush(nt_domain_type_t domain_type)
{
	nt_domain_t *domain = nt_domain_list;

	(void) rw_wrlock(&nt_domain_lock);
	while (domain) {
		if (domain->type == domain_type) {
			nt_domain_unlist(domain);
			nt_domain_delete(domain);
			domain = nt_domain_list;
			continue;
		}
		domain = domain->next;
	}
	(void) rw_unlock(&nt_domain_lock);
}

/*
 * nt_domain_xlat_type
 *
 * Translate a domain type into a text string.
 */
char *
nt_domain_xlat_type(nt_domain_type_t domain_type)
{
	if (domain_type < NT_DOMAIN_NUM_TYPES)
		return (nt_domain_type_name[domain_type]);
	else
		return ("unknown");
}


/*
 * nt_domain_xlat_type_name
 *
 * Translate a domain type test string into a domain type.
 */
nt_domain_type_t
nt_domain_xlat_type_name(char *type_name)
{
	int i;

	for (i = 0; i < NT_DOMAIN_NUM_TYPES; ++i)
		if (utf8_strcasecmp(nt_domain_type_name[i], type_name) == 0)
			return (i);

	return (NT_DOMAIN_NUM_TYPES);
}


/*
 * nt_domain_lookup_name
 *
 * Lookup a domain by its domain name. If the domain is in the list,
 * a pointer to it is returned. Otherwise a null pointer is returned.
 */
nt_domain_t *
nt_domain_lookup_name(char *domain_name)
{
	nt_domain_t *domain = nt_domain_list;

	(void) rw_rdlock(&nt_domain_lock);
	while (domain) {
		if (utf8_strcasecmp(domain->name, domain_name) == 0)
			break;

		domain = domain->next;
	}
	(void) rw_unlock(&nt_domain_lock);

	return (domain);
}


/*
 * nt_domain_lookup_sid
 *
 * Lookup a domain by its domain SID. If the domain is in the list,
 * a pointer to it is returned. Otherwise a null pointer is returned.
 */
nt_domain_t *
nt_domain_lookup_sid(smb_sid_t *domain_sid)
{
	nt_domain_t *domain = nt_domain_list;

	(void) rw_rdlock(&nt_domain_lock);
	while (domain) {
		if (smb_sid_cmp(domain->sid, domain_sid))
			break;

		domain = domain->next;
	}
	(void) rw_unlock(&nt_domain_lock);

	return (domain);
}


/*
 * nt_domain_lookupbytype
 *
 * Lookup a domain by its type. The first matching entry in the list
 * is returned. Otherwise a null pointer is returned.
 */
nt_domain_t *
nt_domain_lookupbytype(nt_domain_type_t type)
{
	nt_domain_t *domain = nt_domain_list;

	(void) rw_rdlock(&nt_domain_lock);
	while (domain) {
		if (domain->type == type)
			break;

		domain = domain->next;
	}
	(void) rw_unlock(&nt_domain_lock);

	return (domain);
}


/*
 * nt_domain_local_sid
 *
 * Return a pointer to the local domain SID. Each system has a SID that
 * represents the local domain, which is named after the local hostname.
 * The local domain SID must exist.
 */
smb_sid_t *
nt_domain_local_sid(void)
{
	nt_domain_t *domain = nt_domain_list;

	(void) rw_rdlock(&nt_domain_lock);
	while (domain) {
		if (domain->type == NT_DOMAIN_LOCAL)
			break;

		domain = domain->next;
	}
	(void) rw_unlock(&nt_domain_lock);

	return (domain->sid);
}


static void
nt_domain_unlist(nt_domain_t *domain)
{
	nt_domain_t **ppdomain = &nt_domain_list;

	while (*ppdomain) {
		if (*ppdomain == domain) {
			*ppdomain = domain->next;
			domain->next = NULL;
			return;
		}
		ppdomain = &(*ppdomain)->next;
	}
}
