/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved. *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"

#ifdef GSSAPI

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ssh.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "buffer.h"
#include "bufaux.h"
#include "packet.h"
#include "compat.h"
#include <openssl/evp.h>
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "compat.h"
#include "xlist.h"

#include <netdb.h>

#include "ssh-gss.h"

#ifdef HAVE_GSS_OID_TO_MECH
#include <gssapi/gssapi_ext.h>
#endif /* HAVE_GSS_OID_TO_MECH */

typedef struct {
	char *encoded;
	gss_OID oid;
} ssh_gss_kex_mapping;

static ssh_gss_kex_mapping **gss_enc2oid = NULL;

static void ssh_gssapi_encode_oid_for_kex(const gss_OID oid, char **enc_name);
static char *ssh_gssapi_make_kexalgs_list(gss_OID_set mechs,
    const char *old_kexalgs);

/*
 * Populate gss_enc2oid table and return list of kexnames.
 *
 * If called with both mechs == GSS_C_NULL_OID_SET and kexname_list == NULL
 * then cached gss_enc2oid table is cleaned up.
 */
void
ssh_gssapi_mech_oids_to_kexnames(const gss_OID_set mechs, char **kexname_list)
{
	ssh_gss_kex_mapping **new_gss_enc2oid, **p;
	Buffer buf;
	char *enc_name;
	int i;

	if (kexname_list != NULL)
		*kexname_list = NULL; /* default to failed */

	if (mechs != GSS_C_NULL_OID_SET || kexname_list == NULL) {
		/* Cleanup gss_enc2oid table */
		for (p = gss_enc2oid; p != NULL && *p != NULL; p++) {
			if ((*p)->encoded)
				xfree((*p)->encoded);
			ssh_gssapi_release_oid(&(*p)->oid);
			xfree(*p);
		}
		if (gss_enc2oid)
			xfree(gss_enc2oid);
	}

	if (mechs == GSS_C_NULL_OID_SET && kexname_list == NULL)
		return; /* nothing left to do */

	if (mechs) {
		gss_OID mech;
		/* Populate gss_enc2oid table */
		new_gss_enc2oid = xmalloc(sizeof (ssh_gss_kex_mapping *) *
		    (mechs->count + 1));
		memset(new_gss_enc2oid, 0,
		    sizeof (ssh_gss_kex_mapping *) * (mechs->count + 1));

		for (i = 0; i < mechs->count; i++) {
			mech = &mechs->elements[i];
			ssh_gssapi_encode_oid_for_kex((const gss_OID)mech,
			    &enc_name);

			if (!enc_name)
				continue;

			new_gss_enc2oid[i] =
			    xmalloc(sizeof (ssh_gss_kex_mapping));
			(new_gss_enc2oid[i])->encoded = enc_name;
			(new_gss_enc2oid[i])->oid =
			    ssh_gssapi_dup_oid(&mechs->elements[i]);
		}

		/* Do this last to avoid run-ins with fatal_cleanups */
		gss_enc2oid = new_gss_enc2oid;
	}

	if (!kexname_list)
		return; /* nothing left to do */

	/* Make kex name list */
	buffer_init(&buf);
	for (p = gss_enc2oid; p && *p; p++) {
		buffer_put_char(&buf, ',');
		buffer_append(&buf, (*p)->encoded, strlen((*p)->encoded));
	}

	if (buffer_len(&buf) == 0) {
		buffer_free(&buf);
		return;
	}

	buffer_consume(&buf, 1); /* consume leading ',' */
	buffer_put_char(&buf, '\0');

	*kexname_list = xstrdup(buffer_ptr(&buf));
	buffer_free(&buf);
}

void
ssh_gssapi_mech_oid_to_kexname(const gss_OID mech, char **kexname)
{
	ssh_gss_kex_mapping **p;

	if (mech == GSS_C_NULL_OID || !kexname)
		return;

	*kexname = NULL; /* default to not found */
	if (gss_enc2oid) {
		for (p = gss_enc2oid; p && *p; p++) {
			if (mech->length == (*p)->oid->length &&
			    memcmp(mech->elements, (*p)->oid->elements,
			    mech->length) == 0)
				*kexname = xstrdup((*p)->encoded);
		}
	}

	if (*kexname)
		return; /* found */

	ssh_gssapi_encode_oid_for_kex(mech, kexname);
}

void
ssh_gssapi_oid_of_kexname(const char *kexname, gss_OID *mech)
{
	ssh_gss_kex_mapping **p;

	if (!mech || !kexname || !*kexname)
		return;

	*mech = GSS_C_NULL_OID; /* default to not found */

	if (!gss_enc2oid)
		return;

	for (p = gss_enc2oid; p && *p; p++) {
		if (strcmp(kexname, (*p)->encoded) == 0) {
			*mech = (*p)->oid;
			return;
		}
	}
}

static
void
ssh_gssapi_encode_oid_for_kex(const gss_OID oid, char **enc_name)
{
	Buffer buf;
	OM_uint32 oidlen;
	uint_t enclen;
	const EVP_MD *evp_md = EVP_md5();
	EVP_MD_CTX md;
	uchar_t digest[EVP_MAX_MD_SIZE];
	char *encoded;

	if (oid == GSS_C_NULL_OID || !enc_name)
		return;

	*enc_name = NULL;

	oidlen = oid->length;

	/* No GSS mechs have OIDs as long as 128 -- simplify DER encoding */
	if (oidlen > 128)
		return; /* fail gracefully */

	/*
	 * NOTE:  If we need to support SSH_BUG_GSSAPI_BER this is where
	 * we'd do it.
	 *
	 * That means using "Se3H81ismmOC3OE+FwYCiQ==" for the Kerberos
	 * V mech and "N3+k7/4wGxHyuP8Yxi4RhA==" for the GSI mech.  Ick.
	 */

	buffer_init(&buf);

	/* UNIVERSAL class tag for OBJECT IDENTIFIER */
	buffer_put_char(&buf, 0x06);
	buffer_put_char(&buf, oidlen); /* one octet DER length -- see above */

	/* OID elements */
	buffer_append(&buf, oid->elements, oidlen);

	/* Make digest */
	EVP_DigestInit(&md, evp_md);
	EVP_DigestUpdate(&md, buffer_ptr(&buf), buffer_len(&buf));
	EVP_DigestFinal(&md, digest, NULL);
	buffer_free(&buf);

	/* Base 64 encoding */
	encoded = xmalloc(EVP_MD_size(evp_md)*2);
	enclen = __b64_ntop(digest, EVP_MD_size(evp_md),
	    encoded, EVP_MD_size(evp_md) * 2);
	buffer_init(&buf);
	buffer_append(&buf, KEX_GSS_SHA1, sizeof (KEX_GSS_SHA1) - 1);
	buffer_append(&buf, encoded, enclen);
	buffer_put_char(&buf, '\0');

	debug2("GSS-API Mechanism encoded as %s", encoded);

	*enc_name = xstrdup(buffer_ptr(&buf));
	buffer_free(&buf);
}

static char *
ssh_gssapi_make_kexalgs_list(gss_OID_set mechs, const char *old_kexalgs)
{
	char *gss_kexalgs, *new_kexalgs;
	int len;

	if (mechs == GSS_C_NULL_OID_SET)
		return (xstrdup(old_kexalgs)); /* never null */

	ssh_gssapi_mech_oids_to_kexnames(mechs, &gss_kexalgs);

	if (gss_kexalgs == NULL || *gss_kexalgs == '\0')
		return (xstrdup(old_kexalgs)); /* never null */

	if (old_kexalgs == NULL || *old_kexalgs == '\0')
		return (gss_kexalgs);

	len = strlen(old_kexalgs) + strlen(gss_kexalgs) + 2;
	new_kexalgs = xmalloc(len);
	(void) snprintf(new_kexalgs, len, "%s,%s", gss_kexalgs, old_kexalgs);

	return (new_kexalgs);
}

void
ssh_gssapi_modify_kex(Kex *kex, gss_OID_set mechs, char **proposal)
{
	char *kexalgs, *orig_kexalgs, *p;
	char **hostalg, *orig_hostalgs, *new_hostalgs;
	char **hostalgs;
	gss_OID_set dup_mechs;
	OM_uint32 maj, min;
	int i;

	if (kex == NULL || proposal == NULL ||
	    (orig_kexalgs = proposal[PROPOSAL_KEX_ALGS]) == NULL) {
		fatal("INTERNAL ERROR (%s)", __func__);
	}

	orig_hostalgs = proposal[PROPOSAL_SERVER_HOST_KEY_ALGS];

	if (kex->mechs == GSS_C_NULL_OID_SET && mechs == GSS_C_NULL_OID_SET)
		return; /* didn't offer GSS last time, not offering now */

	if (kex->mechs == GSS_C_NULL_OID_SET || mechs == GSS_C_NULL_OID_SET)
		goto mod_offer; /* didn't offer last time or not offering now */

	/* Check if mechs is congruent to kex->mechs (last offered) */
	if (kex->mechs->count == mechs->count) {
		int present, matches = 0;

		for (i = 0; i < mechs->count; i++) {
			maj = gss_test_oid_set_member(&min,
			    &kex->mechs->elements[i], mechs, &present);

			if (GSS_ERROR(maj)) {
				mechs = GSS_C_NULL_OID_SET;
				break;
			}

			matches += (present) ? 1 : 0;
		}

		if (matches == kex->mechs->count)
			return; /* no change in offer from last time */
	}

mod_offer:
	/*
	 * Remove previously offered mechs from PROPOSAL_KEX_ALGS proposal
	 *
	 * ASSUMPTION: GSS-API kex algs always go in front, so removing
	 * them is a matter of skipping them.
	 */
	p = kexalgs = orig_kexalgs = proposal[PROPOSAL_KEX_ALGS];
	while (p != NULL && *p != '\0' &&
	    strncmp(p, KEX_GSS_SHA1, strlen(KEX_GSS_SHA1)) == 0) {

		if ((p = strchr(p, ',')) == NULL)
			break;
		p++;
		kexalgs = p;

	}
	kexalgs = proposal[PROPOSAL_KEX_ALGS] = xstrdup(kexalgs);
	xfree(orig_kexalgs);

	(void) gss_release_oid_set(&min, &kex->mechs); /* ok if !kex->mechs */

	/* Not offering GSS kexalgs now -> all done */
	if (mechs == GSS_C_NULL_OID_SET)
		return;

	/* Remember mechs we're offering */
	maj = gss_create_empty_oid_set(&min, &dup_mechs);
	if (GSS_ERROR(maj))
		return;
	for (i = 0; i < mechs->count; i++) {
		maj = gss_add_oid_set_member(&min, &mechs->elements[i],
		    &dup_mechs);

		if (GSS_ERROR(maj)) {
			(void) gss_release_oid_set(&min, &dup_mechs);
			return;
		}
	}

	/* Add mechs to kexalgs ... */
	proposal[PROPOSAL_KEX_ALGS] = ssh_gssapi_make_kexalgs_list(mechs,
	    kexalgs);
	kex->mechs = dup_mechs; /* remember what we offer now */

	/*
	 * ... and add null host key alg, if it wasn't there before, but
	 * not if we're the server and we have other host key algs to
	 * offer.
	 *
	 * NOTE: Never remove "null" host key alg once added.
	 */
	if (orig_hostalgs == NULL || *orig_hostalgs == '\0') {
		proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = xstrdup("null");
	} else if (!kex->server) {
		hostalgs = xsplit(orig_hostalgs, ',');
		for (hostalg = hostalgs; *hostalg != NULL; hostalg++) {
			if (strcmp(*hostalg, "null") == 0) {
				xfree_split_list(hostalgs);
				return;
			}
		}
		xfree_split_list(hostalgs);

		if (kex->mechs != GSS_C_NULL_OID_SET) {
			int len;

			len = strlen(orig_hostalgs) + sizeof (",null");
			new_hostalgs = xmalloc(len);
			(void) snprintf(new_hostalgs, len, "%s,null",
			    orig_hostalgs);
			proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = new_hostalgs;
		}

		xfree(orig_hostalgs);
	}
}

/*
 * Yes, we harcode OIDs for some things, for now it's all we can do.
 *
 * We have to reference particular mechanisms due to lack of generality
 * in the GSS-API in several areas: authorization, mapping principal
 * names to usernames, "storing" delegated credentials, and discovering
 * whether a mechanism is a pseudo-mechanism that negotiates mechanisms.
 *
 * Even if they were in some header file or if __gss_mech_to_oid()
 * and/or __gss_oid_to_mech() were standard we'd still have to hardcode
 * the mechanism names, and since the mechanisms have no standard names
 * other than their OIDs it's actually worse [less portable] to hardcode
 * names than OIDs, so we hardcode OIDs.
 *
 * SPNEGO is a difficult problem though -- it MUST NOT be used in SSHv2,
 * but that's true of all possible pseudo-mechanisms that can perform
 * mechanism negotiation, and SPNEGO could have new OIDs in the future.
 * Ideally we could query each mechanism for its feature set and then
 * ignore any mechanisms that negotiate mechanisms, but, alas, there's
 * no interface to do that.
 *
 * In the future, if the necessary generic GSS interfaces for the issues
 * listed above are made available (even if they differ by platform, as
 * we can expect authorization interfaces will), then we can stop
 * referencing specific mechanism OIDs here.
 */
int
ssh_gssapi_is_spnego(gss_OID oid)
{
	return (oid->length == 6 &&
	    memcmp("\053\006\001\005\005\002", oid->elements, 6) == 0);
}

int
ssh_gssapi_is_krb5(gss_OID oid)
{
	return (oid->length == 9 &&
	    memcmp("\x2A\x86\x48\x86\xF7\x12\x01\x02\x02",
	    oid->elements, 9) == 0);
}

int
ssh_gssapi_is_dh(gss_OID oid)
{
	return (oid->length == 9 &&
	    memcmp("\053\006\004\001\052\002\032\002\005",
	    oid->elements, 9) == 0);
}

int
ssh_gssapi_is_gsi(gss_OID oid)
{
	return (oid->length == 9 &&
	    memcmp("\x2B\x06\x01\x04\x01\x9B\x50\x01\x01",
	    oid->elements, 9) == 0);
}

const char *
ssh_gssapi_oid_to_name(gss_OID oid)
{
#ifdef HAVE_GSS_OID_TO_MECH
	return (__gss_oid_to_mech(oid));
#else
	if (ssh_gssapi_is_krb5(oid))
		return ("Kerberos");
	if (ssh_gssapi_is_gsi(oid))
		return ("GSI");
	return ("(unknown)");
#endif /* HAVE_GSS_OID_TO_MECH */
}

char *
ssh_gssapi_oid_to_str(gss_OID oid)
{
#ifdef HAVE_GSS_OID_TO_STR
	gss_buffer_desc	str_buf;
	char		*str;
	OM_uint32	maj, min;

	maj = gss_oid_to_str(&min, oid, &str_buf);

	if (GSS_ERROR(maj))
		return (xstrdup("<gss_oid_to_str() failed>"));

	str = xmalloc(str_buf.length + 1);
	memset(str, 0, str_buf.length + 1);
	strlcpy(str, str_buf.value, str_buf.length + 1);
	(void) gss_release_buffer(&min, &str_buf);

	return (str);
#else
	return (xstrdup("<gss_oid_to_str() unsupported>"));
#endif /* HAVE_GSS_OID_TO_STR */
}

/* Check that the OID in a data stream matches that in the context */
int
ssh_gssapi_check_mech_oid(Gssctxt *ctx, void *data, size_t len)
{

	return (ctx != NULL && ctx->desired_mech != GSS_C_NULL_OID &&
	    ctx->desired_mech->length == len &&
	    memcmp(ctx->desired_mech->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
void
ssh_gssapi_set_oid_data(Gssctxt *ctx, void *data, size_t len)
{
	if (ctx->actual_mech != GSS_C_NULL_OID) {
		xfree(ctx->actual_mech->elements);
		xfree(ctx->actual_mech);
	}
	ctx->actual_mech = xmalloc(sizeof (gss_OID_desc));
	ctx->actual_mech->length = len;
	ctx->actual_mech->elements = xmalloc(len);
	memcpy(ctx->actual_mech->elements, data, len);
}

/* Set the contexts OID */
void
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */

void
ssh_gssapi_error(Gssctxt *ctxt, const char *where)
{
	char *errmsg = ssh_gssapi_last_error(ctxt, NULL, NULL);

	if (where != NULL)
		debug("GSS-API error while %s: %s", where, errmsg);
	else
		debug("GSS-API error: %s", errmsg);

	/* ssh_gssapi_last_error() can't return NULL */
	xfree(errmsg);
}

char *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin, more;
	OM_uint32 maj, min;
	gss_OID mech = GSS_C_NULL_OID;
	gss_buffer_desc msg;
	Buffer b;
	char *ret;

	buffer_init(&b);

	if (ctxt) {
		/* Get status codes from the Gssctxt */
		maj = ctxt->major;
		min = ctxt->minor;
		/* Output them if desired */
		if (major_status)
			*major_status = maj;
		if (minor_status)
			*minor_status = min;
		/* Get mechanism for minor status display */
		mech = (ctxt->actual_mech != GSS_C_NULL_OID) ?
		    ctxt->actual_mech : ctxt->desired_mech;
	} else if (major_status && minor_status) {
		maj = *major_status;
		min = *major_status;
	} else {
		maj = GSS_S_COMPLETE;
		min = 0;
	}

	more = 0;
	/* The GSSAPI error */
	do {
		gss_display_status(&lmin, maj, GSS_C_GSS_CODE,
		    GSS_C_NULL_OID, &more, &msg);

		buffer_append(&b, msg.value, msg.length);
		buffer_put_char(&b, '\n');
		gss_release_buffer(&lmin, &msg);
	} while (more != 0);

	/* The mechanism specific error */
	do {
		/*
		 * If mech == GSS_C_NULL_OID we may get the default
		 * mechanism, whatever that is, and that may not be
		 * useful.
		 */
		gss_display_status(&lmin, min, GSS_C_MECH_CODE, mech, &more,
		    &msg);

		buffer_append(&b, msg.value, msg.length);
		buffer_put_char(&b, '\n');

		gss_release_buffer(&lmin, &msg);
	} while (more != 0);

	buffer_put_char(&b, '\0');
	ret = xstrdup(buffer_ptr(&b));
	buffer_free(&b);

	return (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
void
ssh_gssapi_build_ctx(Gssctxt **ctx, int client, gss_OID mech)
{
	Gssctxt *newctx;


	newctx = (Gssctxt*)xmalloc(sizeof (Gssctxt));
	memset(newctx, 0, sizeof (Gssctxt));


	newctx->local = client;
	newctx->desired_mech = ssh_gssapi_dup_oid(mech);

	/* This happens to be redundant given the memset() above */
	newctx->major = GSS_S_COMPLETE;
	newctx->context = GSS_C_NO_CONTEXT;
	newctx->actual_mech =  GSS_C_NULL_OID;
	newctx->desired_name = GSS_C_NO_NAME;
	newctx->src_name = GSS_C_NO_NAME;
	newctx->dst_name = GSS_C_NO_NAME;
	newctx->creds = GSS_C_NO_CREDENTIAL;
	newctx->deleg_creds = GSS_C_NO_CREDENTIAL;

	newctx->default_creds = (*ctx != NULL) ? (*ctx)->default_creds : 0;

	ssh_gssapi_delete_ctx(ctx);

	*ctx = newctx;
}

gss_OID
ssh_gssapi_dup_oid(gss_OID oid)
{
	gss_OID new_oid;

	new_oid = xmalloc(sizeof (gss_OID_desc));

	new_oid->elements = xmalloc(oid->length);
	new_oid->length = oid->length;
	memcpy(new_oid->elements, oid->elements, oid->length);

	return (new_oid);
}

gss_OID
ssh_gssapi_make_oid(size_t length, void *elements)
{
	gss_OID_desc oid;

	oid.length = length;
	oid.elements = elements;

	return (ssh_gssapi_dup_oid(&oid));
}

void
ssh_gssapi_release_oid(gss_OID *oid)
{
	OM_uint32 min;

	if (oid && *oid == GSS_C_NULL_OID)
		return;
	(void) gss_release_oid(&min, oid);

	if (*oid == GSS_C_NULL_OID)
		return; /* libgss did own this gss_OID and released it */

	xfree((*oid)->elements);
	xfree(*oid);
	*oid = GSS_C_NULL_OID;
}

struct gss_name {
	gss_OID		name_type;
	gss_buffer_t	external_name;
	gss_OID		mech_type;
	void		*mech_name;
};

/* Delete our context, providing it has been built correctly */
void
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	if ((*ctx) == NULL)
		return;

	if ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
#if 0
	/* XXX */
	if ((*ctx)->desired_mech != GSS_C_NULL_OID)
		ssh_gssapi_release_oid(&(*ctx)->desired_mech);
#endif
	if ((*ctx)->actual_mech != GSS_C_NULL_OID)
		(void) ssh_gssapi_release_oid(&(*ctx)->actual_mech);
	if ((*ctx)->desired_name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->desired_name);
#if 0
	if ((*ctx)->src_name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->src_name);
#endif
	if ((*ctx)->dst_name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->dst_name);
	if ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	if ((*ctx)->deleg_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->deleg_creds);

	xfree(*ctx);
	*ctx = NULL;
}

/* Create a GSS hostbased service principal name for a given server hostname */
int
ssh_gssapi_import_name(Gssctxt *ctx, const char *server_host)
{
	gss_buffer_desc name_buf;
	int		ret;

	/* Build target principal */
	name_buf.length = strlen(SSH_GSS_HOSTBASED_SERVICE) +
	    strlen(server_host) + 1; /* +1 for '@' */
	name_buf.value = xmalloc(name_buf.length + 1); /* +1 for NUL */
	ret = snprintf(name_buf.value, name_buf.length + 1, "%s@%s",
	    SSH_GSS_HOSTBASED_SERVICE, server_host);

	debug3("%s: snprintf() returned %d, expected %d", __func__, ret,
	    name_buf.length + 1);

	ctx->major = gss_import_name(&ctx->minor, &name_buf,
	    GSS_C_NT_HOSTBASED_SERVICE, &ctx->desired_name);

	if (GSS_ERROR(ctx->major)) {
		ssh_gssapi_error(ctx, "calling GSS_Import_name()");
		return (0);
	}

	xfree(name_buf.value);

	return (1);
}

OM_uint32
ssh_gssapi_get_mic(Gssctxt *ctx, gss_buffer_desc *buffer, gss_buffer_desc *hash)
{

	ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash);
	if (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx, "while getting MIC");
	return (ctx->major);
}

OM_uint32
ssh_gssapi_verify_mic(Gssctxt *ctx, gss_buffer_desc *buffer,
    gss_buffer_desc *hash)
{
	gss_qop_t qop;

	ctx->major = gss_verify_mic(&ctx->minor, ctx->context, buffer,
	    hash, &qop);
	if (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx, "while verifying MIC");
	return (ctx->major);
}
#endif /* GSSAPI */
