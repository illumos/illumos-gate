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
 *	name.c
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#include "dh_gssapi.h"
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/note.h>
#include <thread.h>

extern int
get_der_length(unsigned char **, unsigned int, unsigned int *);

extern unsigned int
der_length_size(unsigned int);

extern int
put_der_length(unsigned int, unsigned char **, unsigned int);

/* Diffie-Hellman ONC RPC netname name type */
static gss_OID_desc __DH_GSS_C_NT_NETNAME_desc =
	{ 9,  "\053\006\004\001\052\002\032\001\001" };

const gss_OID_desc * const __DH_GSS_C_NT_NETNAME = &__DH_GSS_C_NT_NETNAME_desc;

#define	OID_MAX_NAME_ENTRIES  32

/*
 * __dh_gss_compare_name: Diffie-Hellman machanism support for
 * gss_compare_name. Given two gss_name_ts that are presumed to
 * be rpc netnames set the *equal parameter to true if they are
 * the same, else set it to false.
 */

OM_uint32
__dh_gss_compare_name(void *ctx,	/* Per mechanism context (not used) */
		    OM_uint32 *minor,	/* Mechanism status */
		    gss_name_t name1,	/* First name to compare */
		    gss_name_t name2,	/* Second name to compare */
		    int *equal		/* The result */)
{
_NOTE(ARGUNUSED(ctx))

	if (minor == 0 || equal == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;

	if (name1 == 0 || name2 == 0) {
		*minor = DH_BADARG_FAILURE;
		return (GSS_S_BAD_NAME | GSS_S_CALL_INACCESSIBLE_READ);
	}

	*equal = (strcmp((char *)name1, (char *)name2) == 0);

	return (GSS_S_COMPLETE);
}

/*
 * __dh_gss_display_name: Supports gss_display_name for Diffie-Hellman
 * mechanism. This takes a gss internal name and converts it to
 * a counted string suitable for display.
 */
OM_uint32
__dh_gss_display_name(void * ctx, /* Per mechanism context (not used) */
		    OM_uint32* minor, /* Mechanism status */
		    gss_name_t name, /* Diffie-Hellman internal name */
		    gss_buffer_t output, /* Were the printable name goes */
		    gss_OID *name_type /* Name type of the internal name */)
{
_NOTE(ARGUNUSED(ctx))

	if (minor == 0 || output == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (name == 0)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME);

	*minor = DH_SUCCESS;

	output->length = 0;
	output->value = (void *)strdup((char *)name);
	if (output->value == NULL) {
		*minor = DH_NOMEM_FAILURE;
		return (GSS_S_FAILURE);
	}
	output->length = strlen((char *)name) + 1;

/*
 * Note: we no longer copy the name type OID. The current draft of
 * the standard specifies:
 *
 * "The returned gss_OID will be a pointer into static stoarge
 *  and should be treated as read-only by the caller (in particular,
 *  it does not need to be freed)."
 *
 *	if (name_type) {
 *		if ((*minor = __OID_copy(name_type, __DH_GSS_C_NT_NETNAME))
 *			!= DH_SUCCESS) {
 *			free(output->value);
 *			output->value = NULL;
 *			return (GSS_S_FAILURE);
 *		}
 *	}
 */

	if (name_type)
		*name_type = (gss_OID) __DH_GSS_C_NT_NETNAME;

	return (GSS_S_COMPLETE);
}

/*
 * Routine that takes a netname as a character string and assigns it
 * to a an gss_name_t pointed to by output.
 */
static OM_uint32
do_netname_nametype(OM_uint32 *minor, char *input, gss_name_t *output)
{
	if (__dh_validate_principal(input) != DH_SUCCESS)
		return (GSS_S_BAD_NAME);

	*minor = DH_SUCCESS;
	*output = (gss_name_t)strdup((char *)input);

	if (*output == NULL) {
		*minor = DH_NOMEM_FAILURE;
		return (GSS_S_FAILURE);
	}

	return (GSS_S_COMPLETE);
}

/*
 * do_uid_nametype converts a uid to a gss_name_t pointed to by output
 */
static OM_uint32
do_uid_nametype(OM_uint32 *minor, uid_t uid, gss_name_t *output)
{
	char netname[MAXNETNAMELEN+1];

	if (!user2netname(netname, uid, NULL)) {
		*minor = DH_NETNAME_FAILURE;
		return (GSS_S_FAILURE);
	}
	return (do_netname_nametype(minor, netname, output));
}

/*
 * do_username_nametype converts a username to a gss_name_t pointed to by
 * output.
 *
 * A username will be represented by the following:
 * 	name[/node][@security-domain]
 *
 * Then optional security-domain will represent secure rpc domain if
 * present. If not present the local domain will be used. name is the
 * user name as found in the unix password file. If name is root and
 * node is present, then node will represent the host. If the host is
 * a qualified name we assume that it is a DNS name and will only return
 * the first commponnet since we want host name that are relative to
 * the security domain (secure rpc domain).
 */

static OM_uint32
do_username_nametype(OM_uint32 *minor, char *uname, gss_name_t *output)
{
	char netname[MAXNETNAMELEN+1];
	char *user, *node, *domain;
	struct passwd pwd;
	char buff[1024];

	/* Set outputs to sane values */

	*output = 0;
	*minor = DH_SUCCESS;

	/* See if we have a name */
	if (uname == 0) {
		*minor = DH_NO_SUCH_USER;
		return (GSS_S_FAILURE);
	}

	/* copy the name so that we can do surgery on it */
	user = strdup(uname);
	if (user == 0) {
		*minor = DH_NOMEM_FAILURE;
		return (GSS_S_FAILURE);
	}


	/* Look for optional node part */
	node = strchr(user, '/');
	if (node) {
		/*
		 * user is now just the user portion and node
		 * points to the start of the node part.
		 */
		*node++ = '\0';

		/* Now see if there is a domain */
		domain = strchr(node, '@');
	}
	else
		/* Check for a domain */
		domain = strchr(user, '@');

	/* Set domain to the beginning of the domain part if pressent */
	if (domain)
		*domain++ = '\0';

	/*
	 * See if the node part is important. If the user is root get
	 * the host from the node. If node is not present we assume
	 * we're the local host.
	 */
	if (strcmp(user, "root") == 0) {
		char *dot;

		/*
		 * We only want the host part of a qualfied host name. We
		 * assume the domain part of a hostname is a DNS domain,
		 * not an rpc domain. The rpc domain can be specified
		 * in the optional security domain part.
		 */
		if (node) {
			dot = strchr(node, '.');
			if (dot)
				*dot = '\0';
		}
		/*
		 * If node is null, assume local host. If domain is
		 * null assume local domain. See host2netname(3NSL)
		 */
		if (!host2netname(netname, node,  domain)) {
			*minor = DH_NETNAME_FAILURE;
			free(user);
			return (GSS_S_FAILURE);
		}
		free(user);
		return (do_netname_nametype(minor, netname, output));
	}

	/*
	 * We use getpwnam_r to convert the name to uid.  Note it is
	 * important to use getpwnam_r to preserve MT safty.
	 */
	if (getpwnam_r(user, &pwd, buff, sizeof (buff)) == NULL) {
		*minor = DH_NO_SUCH_USER;
		free(user);
		return (GSS_S_FAILURE);
	}

	/* If domain is null assume local domain. See user2netname(3NSL) */
	if (!user2netname(netname, pwd.pw_uid, domain)) {
		*minor = DH_NETNAME_FAILURE;
		free(user);
		return (GSS_S_FAILURE);
	}
	free(user);
	return (do_netname_nametype(minor, netname, output));
}

/*
 * do_hostbase_nametype convert a hostbase service name of the form
 *	service@hostname.
 *
 * For Diffie-Hellman we assume that the service is running with the
 * credtials of the machine, i.e., as root.
 */
static OM_uint32
do_hostbase_nametype(OM_uint32 *minor, char *input, gss_name_t *output)
{
	/* Get the nostname */
	char *host = strchr(input, '@');
	char netname[MAXNETNAMELEN+1];


	/* If no host return bad name */
	if (host == NULL)
		return (GSS_S_BAD_NAME);

	/* Advance pass the "@" sign */
	host += 1;

	/* Convert the hostname to its netname */
	if (!host2netname(netname, host, NULL)) {
		*minor = DH_NETNAME_FAILURE;
		return (GSS_S_FAILURE);
	}

	/* Internalize the netname to output */
	return (do_netname_nametype(minor, netname, output));
}

/*
 * do_exported_netname: Convert an exported Diffie-Hellman name
 * to a Diffie-Hellman internal name.
 */
static OM_uint32
do_exported_netname(dh_context_t ctx, /* Diffie-Hellman mech context */
		    OM_uint32 *minor, /* Mech status */
		    gss_buffer_t input, /* The export name to convert */
		    gss_name_t *output /* The converted internal name */)
{
	/* All export names must start with this */
	const char tokid[] = "\x04\x01";
	const int tokid_len = 2;
	const int OIDlen_len = 2;
	const int namelen_len = 4;
	unsigned char *p = (unsigned char *)input->value;
	OM_uint32 len = input->length;
	int	 mechoidlen;
	OM_uint32 oidlen; /* includes object tag len & DER len bytes */
	OM_uint32 namelen;
	OM_uint32 currlen;
	OM_uint32 bytes;

	*minor = DH_BADARG_FAILURE;

	/* The len must be at least this big */
	if (len < tokid_len + OIDlen_len + namelen_len)
		return (GSS_S_DEFECTIVE_TOKEN);

	/* Export names must start with the token id of 0x04 0x01 */
	if (memcmp(p, tokid, tokid_len) != 0)
		return (GSS_S_DEFECTIVE_TOKEN);
	p += tokid_len;

	/* Decode the Mechanism oid */
	oidlen = (*p++ << 8) & 0xff00;
	oidlen |= *p++ & 0xff;

	/* Check that we actually have the mechanism oid elements */
	if (len < tokid_len + OIDlen_len + oidlen + namelen_len)
		return (GSS_S_DEFECTIVE_TOKEN);

	/* Compare that the input is for this mechanism */
	if (*p++ != 0x06)
		return (GSS_S_DEFECTIVE_TOKEN);
	currlen = len - (tokid_len + OIDlen_len + oidlen + namelen_len);
	if ((mechoidlen = get_der_length(&p, currlen, &bytes)) < 0)
		return (GSS_S_DEFECTIVE_TOKEN);
	if (mechoidlen != ctx->mech->length)
		return (GSS_S_DEFECTIVE_TOKEN);
	if (memcmp(p, ctx->mech->elements, mechoidlen) != 0)
		return (GSS_S_DEFECTIVE_TOKEN);
	p += mechoidlen;

	/* Grab the length of the mechanism specific name per RFC 2078 */
	namelen = (*p++ << 24) & 0xff000000;
	namelen |= (*p++ << 16) & 0xff0000;
	namelen |= (*p++ << 8) & 0xff00;
	namelen |= *p++ & 0xff;

	/* This should alway be false */
	if (len < tokid_len + OIDlen_len + oidlen + namelen_len + namelen)
		return (GSS_S_DEFECTIVE_TOKEN);

	/* Make sure the bytes for the netname oid length are available */
	if (namelen < OIDlen_len)
		return (GSS_S_DEFECTIVE_TOKEN);

	/* Get the netname oid length */
	oidlen = (*p++ << 8) & 0xff00;
	oidlen = *p++ & 0xff;

	/* See if we have the elements of the netname oid */
	if (namelen < OIDlen_len + oidlen)
		return (GSS_S_DEFECTIVE_TOKEN);

	/* Check that the oid is really a netname */
	if (oidlen != __DH_GSS_C_NT_NETNAME->length)
		return (GSS_S_DEFECTIVE_TOKEN);
	if (memcmp(p, __DH_GSS_C_NT_NETNAME->elements,
	    __DH_GSS_C_NT_NETNAME->length) != 0)
		return (GSS_S_DEFECTIVE_TOKEN);

	/* p now points to the netname wich is null terminated */
	p += oidlen;

	/*
	 * How the netname is encoded in an export name type for
	 * this mechanism. See _dh_gss_export_name below.
	 */

	if (namelen != OIDlen_len + oidlen + strlen((char *)p) + 1)
		return (GSS_S_DEFECTIVE_TOKEN);

	/* Grab the netname */
	*output = (gss_name_t)strdup((char *)p);
	if (*output) {
		*minor = 0;
		return (GSS_S_COMPLETE);
	}

	*minor = DH_NOMEM_FAILURE;
	return (GSS_S_FAILURE);
}

/*
 * __dh_gss_import_name: Diffie-Hellman entry point for gss_import_name.
 * Given an input name of a specified name type, convert this to a
 * Diffie-Hellman internal name (netname).
 *
 * The idea here is simply compare the name_type supplied with each
 * name type that we know how to deal with. If we have a match we call
 * the appropriate support routine form above. If we done't have a match
 * we return GSS_S_BAD_NAMETYPE
 */
OM_uint32
__dh_gss_import_name(void *ctx, /* Per mechanism context */
		    OM_uint32 *minor, /* Mechanism status */
		    gss_buffer_t input, /* The name to convert */
		    gss_OID name_type, /* of this name_type */
		    gss_name_t *output /* The converted name */)
{
	char *name;
	OM_uint32 stat;

	if (minor == NULL || output == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (input == NULL || input->value == NULL)
		return (GSS_S_BAD_NAME | GSS_S_CALL_INACCESSIBLE_READ);
	if (name_type == GSS_C_NO_OID)
		return (GSS_S_BAD_NAMETYPE);

	/* Set sane state */
	*minor = DH_SUCCESS;
	*output = GSS_C_NO_NAME;

		/* UID in machine format */
	if (__OID_equal(name_type, GSS_C_NT_MACHINE_UID_NAME)) {
		uid_t uid;
		if (input->length != sizeof (uid_t))
			return (GSS_S_BAD_NAME);
		uid = *(uid_t *)input->value;
		/* Should we assume that the id is network byte order ??? */
		/* uid = htonl(uid); No, this should be the local orfering */
		return (do_uid_nametype(minor, uid, output));

		/* Name that was exported with __dh_gss_export_name */
	} else if (__OID_equal(name_type, GSS_C_NT_EXPORT_NAME)) {
		stat = do_exported_netname((dh_context_t)ctx, minor,
		    input, output);
		return (stat);
	}

	/* Null ternamte name so we can manipulate as a c-style string */
	name = malloc(input->length+1);
	if (name == NULL) {
		*minor = DH_NOMEM_FAILURE;
		return (GSS_S_FAILURE);
	}
	memcpy(name, input->value, input->length);
	name[input->length] = '\0';


		/* Diffie-Hellman (ONC RPC netname) */
	if (__OID_equal(name_type, __DH_GSS_C_NT_NETNAME)) {
		stat = do_netname_nametype(minor, name, output);
		free(name);
		return (stat);
		/* Host based service name (service@hostname) */
	} else if (__OID_equal(name_type, GSS_C_NT_HOSTBASED_SERVICE)) {
		stat = do_hostbase_nametype(minor, name, output);
		free(name);
		return (stat);
		/* Thus local OS user name */
	} else if (__OID_equal(name_type, GSS_C_NT_USER_NAME)) {
		stat = do_username_nametype(minor, name, output);
		free(name);
		return (stat);
		/* The os user id writen as a string */
	} else if (__OID_equal(name_type, GSS_C_NT_STRING_UID_NAME)) {
		char *p;
		/* Convert the name to a uid */
		uid_t uid = (uid_t)strtol(name, &p, 0);
		free(name);
		if (*p != '\0')
			return (GSS_S_BAD_NAME);
		return (do_uid_nametype(minor, uid, output));
	} else {
		/* Any thing else */
		free(name);
		return (GSS_S_BAD_NAMETYPE);
	}
}

/*
 * __dh_gss_release_name: DH entry point for gss_release_name.
 * Release an internal DH name.
 */
OM_uint32
__dh_gss_release_name(void *ctx, OM_uint32 *minor, gss_name_t *name)
{
_NOTE(ARGUNUSED(ctx))

	if (minor == 0 || name == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;

	free(*name);
	*name = GSS_C_NO_NAME;

	return (GSS_S_COMPLETE);
}

/* Lock for initializing oid_name_tab */
static mutex_t name_tab_lock = DEFAULTMUTEX;

/* Table of name types that this mechanism understands */
static const gss_OID_desc * oid_name_tab[OID_MAX_NAME_ENTRIES];

/*
 * __dh_gss_inquire_names_for_mech: DH entry point for
 * gss_inquire_names_for_mech.
 *
 * Return a set of OID name types that a mechanism can understand
 */
OM_uint32
__dh_gss_inquire_names_for_mech(void *ctx, OM_uint32 *minor,
    gss_OID mech, gss_OID_set *names)
{
_NOTE(ARGUNUSED(ctx,mech))

	/* See if we need to initialize the table */
	if (oid_name_tab[0] == 0) {
		mutex_lock(&name_tab_lock);
		/* If nobody sneaked in, initialize the table */
		if (oid_name_tab[0] == 0) {
			oid_name_tab[0] = __DH_GSS_C_NT_NETNAME;
			oid_name_tab[1] = GSS_C_NT_HOSTBASED_SERVICE;
			oid_name_tab[2] = GSS_C_NT_USER_NAME;
			oid_name_tab[3] = GSS_C_NT_MACHINE_UID_NAME;
			oid_name_tab[4] = GSS_C_NT_STRING_UID_NAME;
			oid_name_tab[5] = GSS_C_NT_EXPORT_NAME;
			/* oid_name_tab[6] = GSS_C_NT_ANONYMOUS_NAME; */
		}
		mutex_unlock(&name_tab_lock);
	}

	/* Return the set of OIDS from the table */
	if ((*minor = __OID_copy_set_from_array(names,
	    oid_name_tab, 6)) != DH_SUCCESS)
		return (GSS_S_FAILURE);

	return (GSS_S_COMPLETE);
}


/*
 * Private libgss entry point to convert a principal name to uid.
 */
OM_uint32
__dh_pname_to_uid(void *ctx, /* DH mech context (not used) */
		OM_uint32 *minor, /* Mech status */
		const gss_name_t pname, /* principal */
		uid_t *uid  /* where to put the uid */)
{
_NOTE(ARGUNUSED(ctx))

	gid_t gid;
	gid_t glist[NGRPS];
	int glen;
	/* Convert the principal name to a netname */
	char *netname = (char *)pname;
	char host_netname[MAXNETNAMELEN+1];

	if (pname == 0)
		return (GSS_S_BAD_NAME | GSS_S_CALL_INACCESSIBLE_READ);
	if (minor == 0 || uid == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;
	*uid = UID_NOBODY;

	/* First try to convert as a user */
	if (netname2user(netname, uid, &gid, &glen, glist))
		return (GSS_S_COMPLETE);
	/* Get this hosts netname */
	else if (host2netname(host_netname, NULL, NULL)) {
		/*
		 * If the netname is this host's netname then we're root
		 * else we're nobody.
		 */
		if (strncmp(netname, host_netname, MAXNETNAMELEN) == 0)
			*uid = 0;
		return (GSS_S_COMPLETE);
	}

	/* We could not get a netname */
	*minor = DH_NETNAME_FAILURE;
	return (GSS_S_FAILURE);
}

/*
 * __dh_gss_export_name: Diffie-Hellman support for gss_export_name.
 * Given a Diffie-Hellman internal name return the GSS exported format.
 */
OM_uint32
__dh_gss_export_name(void *ctx, /* Per mechanism context */
		    OM_uint32 *minor, /* Mechanism status */
		    const gss_name_t input_name, /* The name to export */
		    gss_buffer_t exported_name /* Exported name goes here */)
{
	/* input_name is dh principal name */
	dh_principal pname = (dh_principal)input_name;
	dh_context_t dc = (dh_context_t)ctx;
	/* Magic for exported blobs */
	const char tokid[] = "\x04\x01";
	const int tokid_len = 2;
	const int OIDlen_len = 2; /* Why did they do this? */
	const int namelen_len = 4;
	const int mechoid_tag_len = 1;
	unsigned char *p;
	OM_uint32 len;
	OM_uint32 namelen;
	OM_uint32 currlen;
	OM_uint32 oid_der_len = 0;

	if (minor == 0 || exported_name == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	if (input_name == GSS_C_NO_NAME)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	/* Set sane outputs */
	*minor = DH_SUCCESS;
	exported_name->length = 0;
	exported_name->value = NULL;

	/* Determine the length of the name */
	namelen = OIDlen_len + __DH_GSS_C_NT_NETNAME->length
	    + strlen(pname)+1;
	oid_der_len = der_length_size(dc->mech->length);
	/* Find the total length */
	len = tokid_len + OIDlen_len + mechoid_tag_len + oid_der_len
		+ dc->mech->length + namelen_len + namelen;

	/* Allocate the blob */
	p = New(unsigned char, len);
	if (p == NULL) {
		*minor = DH_NOMEM_FAILURE;
		return (GSS_S_FAILURE);
	}
	/* Set the blob to the exported name */
	exported_name->length = len;
	exported_name->value = p;

	/* Start with some magic */
	memcpy(p, tokid, tokid_len);
	p += tokid_len;

	/*
	 * The spec only allows two bytes for the oid length.
	 * We are assuming here that the correct encodeing is MSB first as
	 * was done in libgss.
	 */

	*p++ = ((mechoid_tag_len + oid_der_len + dc->mech->length)
			& 0xff00) >> 8;
	*p++ = ((mechoid_tag_len + oid_der_len + dc->mech->length)
			& 0x00ff);

	/* Now the mechanism OID DER Encoding */
	*p++ = 0x06; /* Universal Tag for OID */
	currlen = len - tokid_len - OIDlen_len - mechoid_tag_len;
	if (!put_der_length(dc->mech->length, &p, currlen) == 0) {
		return (GSS_S_FAILURE);
	}

	/* Now the mechanism OID elements */
	memcpy(p, dc->mech->elements, dc->mech->length);
	p += dc->mech->length;

	/* The name length most MSB first */
	*p++ = (namelen & 0xff000000) >> 24;
	*p++ = (namelen & 0x00ff0000) >> 16;
	*p++ = (namelen & 0x0000ff00) >> 8;
	*p++ = (namelen & 0x000000ff);

	/*
	 * We'll now encode the netname oid. Again we'll just use 2 bytes.
	 * This is the same encoding that the libgss implementor uses, so
	 * we'll just follow along.
	 */

	*p++ = (__DH_GSS_C_NT_NETNAME->length & 0xff00) >> 8;
	*p++ = (__DH_GSS_C_NT_NETNAME->length &0x00ff);

	/* The netname oid values */
	memcpy(p, __DH_GSS_C_NT_NETNAME->elements,
	    __DH_GSS_C_NT_NETNAME->length);

	p += __DH_GSS_C_NT_NETNAME->length;

	/* Now we copy the netname including the null byte to be safe */
	memcpy(p, pname, strlen(pname) + 1);

	return (GSS_S_COMPLETE);
}

/*
 * Support routine for __dh_internal_release_oid. Return True if
 * the supplied OID points to the reference OID or if the elements
 * of the reference OID are the same as the supplied OID. In the
 * latter case, just free the OID container and set the pointer to it
 * to GSS_C_NO_OID. Otherwise return false
 */
static int
release_oid(const gss_OID_desc * const ref, gss_OID *oid)
{
	gss_OID id = *oid;

	if (id == ref)
		return (TRUE);

	/*
	 * If some on create a shallow copy free, the structure point to
	 * id and set the pointer to it to GSS_C_NO_OID
	 */
	if (id->elements == ref->elements) {
		Free(id);
		*oid = GSS_C_NO_OID;
		return (TRUE);
	}

	return (FALSE);
}

/*
 * __dh_gss_internal_release_oid: DH support for the gss_internal_relaese_oid
 * entry. Check that the refence to an oid is one of our mechanisms static
 * OIDS. If it is return true indicating to libgss that we have handled the
 * release of that OID. Otherwise we return false and let libgss deal with it.
 *
 * The only OIDS we know are the calling mechanism found in the context
 * and the shared DH_GSS_C_NT_NETNAME name type
 */
OM_uint32
__dh_gss_internal_release_oid(void *ctx, OM_uint32 *minor, gss_OID *oid)
{
	dh_context_t dhcxt = (dh_context_t)ctx;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;

	if (oid == NULL || *oid == NULL)
		return (GSS_S_COMPLETE);

	if (release_oid(dhcxt->mech, oid))
		return (GSS_S_COMPLETE);

	if (release_oid(__DH_GSS_C_NT_NETNAME, oid))
		return (GSS_S_COMPLETE);

	return (GSS_S_FAILURE);
}
