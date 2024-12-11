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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * This file contains all authentication-related functionality for
 * SLP. Two interfaces are exported:
 *
 *  slp_sign:		Creates auth blocks for a given piece of data
 *  slp_verify:		Verifies an auth block for a given piece of data.
 *
 * A shared object which provides crypto-suites and key management
 * functionality is dynamically linked in during intialization. If
 * the shared object cannot be found, the authentication code aborts
 * and an SLP_AUTHENTICATION_FAILED error is returned. Which shared
 * object is actually loaded is controlled by the property
 * sun.net.slp.authBackend; the value of this property should contain
 * either the name of a shared object which implements the necessary
 * interfaces, or a full or relative path to such an object. This value
 * will be passed to dlopen(3C) to resolve the symbols.
 *
 * The shared object must implement the following AMI interfaces:
 *
 *  ami_init
 *  ami_sign
 *  ami_verify
 *  ami_get_cert
 *  ami_get_cert_chain
 *  ami_strerror
 *  ami_end
 *  AMI_MD5WithRSAEncryption_AID
 *  AMI_SHA1WithDSASignature_AID
 *
 * See security/ami.h for more info on these interfaces.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <synch.h>
#include <dlfcn.h>
#include <slp-internal.h>
#include "slp_ami.h"

/* Prototypes for dynamically loaded (dl'd) AMI functions */
static ami_algid **ami_rsa_aid, **ami_dsa_aid;
static AMI_STATUS (*dld_ami_init)(ami_handle_t **, const char *,
				    const char *, const uint_t, const uint_t,
				    const char *);

static AMI_STATUS (*dld_ami_sign)(ami_handle_t *,
				    const uchar_t *,
				    const size_t,
				    const int,
				    const ami_algid *,
				    const uchar_t *,
				    const size_t,
				    const ami_algid *,
				    uchar_t **,
				    size_t *);
static AMI_STATUS (*dld_ami_verify)(ami_handle_t *,
				    const uchar_t *,
				    const size_t,
				    const int,
				    const ami_algid *,
				    const uchar_t *,
				    const size_t,
				    const ami_algid *,
				    const uchar_t *,
				    const size_t);
static AMI_STATUS (*dld_ami_get_cert)(const ami_handle_t *,
				    const char *,
				    ami_cert **,
				    int *);
static AMI_STATUS (*dld_ami_get_cert_chain)(const ami_handle_t *,
					    const ami_cert *,
					    const char **,
					    int flags,
					    ami_cert **,
					    int *);
static AMI_STATUS (*dld_ami_str2dn)(const ami_handle_t *,
				    char *, ami_name **);
static AMI_STATUS (*dld_ami_dn2str)(const ami_handle_t *,
				    ami_name *, char **);
static void (*dld_ami_free_cert_list)(ami_cert **, int);
static void (*dld_ami_free_dn)(ami_name **);
static char *(*dld_ami_strerror)(const ami_handle_t *, const AMI_STATUS);
static AMI_STATUS (*dld_ami_end)(ami_handle_t *);

/* local utilities */
static SLPError get_security_backend();
static SLPError make_tbs(const char *, struct iovec *, int,
			    unsigned int, unsigned char **, size_t *);
static SLPError make_authblock(struct iovec *, int, const char *,
				time_t, caddr_t *, size_t *);
static SLPError do_verify(unsigned char *, size_t, unsigned short,
				const unsigned char *, size_t, const char *);
static char *alias2dn(ami_handle_t *);
static SLPError check_spis(ami_handle_t *, ami_cert *, int, const char *);
static int dncmp(ami_handle_t *, const char *, const char *);

/*
 * Creates a cryptographic signature over the components of authiov, and
 * creates an auth block from the signature. The auth block is placed
 * into msgiov at the index specified by msgiov_index. The timestamp
 * for the auth block is given in ts. Caller must free the auth block
 * when finished.
 *
 * Returns SLP_OK on success, SLP_AUTHENTICATION_FAILED on failure.
 */
SLPError slp_sign(struct iovec *authiov, int authiov_len, time_t ts,
		    struct iovec *msgiov, int msg_index) {

	char *sign_as = NULL;
	char *alias, *aliasp;
	SLPError err = SLP_OK;
	unsigned char num_auths = 0;

	/* This auth block is always at least 1 byte long, for num auths */
	msgiov[msg_index].iov_base = calloc(1, 1);
	msgiov[msg_index].iov_len = 1;

	/* if security is off, just return the empty auth block */
	if (!slp_get_security_on() || slp_get_bypass_auth()) {
	    return (SLP_OK);
	}

	/*
	 * Security is disabled in Solaris 8 due to AMI trouble.
	 * The pragmas and LINTED suppress "statement not reached"
	 * compiler and lint warnings, and should be removed when
	 * security is re-enabled.
	 */
	return (SLP_SECURITY_UNAVAILABLE);

	/* else we should sign this advert */
	if (!(sign_as = (char *)SLPGetProperty(SLP_CONFIG_SIGN_AS)) ||
/*LINTED statement not reached*/
		!*sign_as) {

	    slp_err(LOG_INFO, 0, "slp_sign", "No signing identity given");
	    return (SLP_AUTHENTICATION_FAILED);
	}

	/* Try to initialize security backend */
	if (!(err = get_security_backend()) == SLP_OK) {
	    return (SLP_AUTHENTICATION_FAILED);
	}

	/* dup SPI list so we can destructively modify it */
	if (!(sign_as = strdup(sign_as))) {
	    slp_err(LOG_CRIT, 0, "slp_sign", "out of memory");
	    return (SLP_MEMORY_ALLOC_FAILED);
	}

	/* For each SPI, create an auth block */
	for (aliasp = sign_as; aliasp; ) {
	    alias = aliasp;
	    aliasp = slp_utf_strchr(aliasp, ',');
	    if (aliasp) {
		*aliasp++ = 0;
	    }

	    /* create an auth block for this SPI */
	    err = make_authblock(authiov, authiov_len, alias, ts,
				    &(msgiov[msg_index].iov_base),
				    (size_t *)&(msgiov[msg_index].iov_len));
	    if (err == SLP_MEMORY_ALLOC_FAILED) {
		goto done;
	    } else if (err != SLP_OK) {
		/* else skip and keep going */
		continue;
	    }

	    num_auths++;
	}

done:
	if (sign_as) free(sign_as);

	if (err != SLP_OK) {
	    return (err);
	}

	if (num_auths == 0) {
	    return (SLP_AUTHENTICATION_FAILED);
	} else {
	    size_t off = 0;
	    /* Lay in number of auth blocks created */
	    err = slp_add_byte(msgiov[msg_index].iov_base, 1, num_auths, &off);
	}

	return (err);
}

/*
 * Verifies that the signature(s) contained in authblocks validates
 * the data in authiov. slp_verify will not read more than len bytes
 * from authblocks. n is the stated number of authblocks in authblock.
 * The total length of all auth blocks read is placed in *total.
 *
 * Returns SLP_OK if the verification succeeds.
 */
SLPError slp_verify(struct iovec *authiov, int authiov_len,
		    const char *authblocks, size_t len, int n, size_t *total) {
	int i;
	size_t off, this_ab;
	unsigned short bsd, ablen;
	unsigned int timestamp;
	char *spi = NULL;
	SLPError err = SLP_AUTHENTICATION_FAILED;
	unsigned char *inbytes = NULL;
	size_t inbytes_len;
	unsigned char *sig;
	size_t siglen;

	/* 1st: if bypass_auth == true, just return SLP_OK */
	if (slp_get_bypass_auth()) {
	    return (SLP_OK);
	}

	/* 2nd: If security is off, and there are no auth blocks, OK */
	if (!slp_get_security_on() && n == 0) {
	    return (SLP_OK);
	}

	/*
	 * Security is disabled in Solaris 8 due to AMI trouble.
	 * The pragmas and LINTED suppress "statement not reached"
	 * compiler and lint warnings, and should be removed when
	 * security is re-enabled.
	 */
	return (SLP_SECURITY_UNAVAILABLE);
	/* For all other scenarios, we must verify the auth blocks */
/*LINTED statement not reached*/
	if (get_security_backend() != SLP_OK || n == 0) {
	    return (SLP_AUTHENTICATION_FAILED);
	}

	/*
	 * If we get here, the backend is available and there are auth
	 * blocks to verify. Verify each input auth block.
	 */
	off = 0;	/* offset into raw auth blocks */

	for (i = 0; i < n && off <= len; i++) {
	    this_ab = off;

	    /* BSD */
	    if ((err = slp_get_sht(authblocks, len, &off, &bsd)) != SLP_OK) {
		slp_err(LOG_INFO, 0, "slp_verify", "corrupt auth block");
		goto done;
	    }

	    /* Auth block length */
	    if ((err = slp_get_sht(authblocks, len, &off, &ablen)) != SLP_OK) {
		slp_err(LOG_INFO, 0, "slp_verify", "corrupt auth block");
		goto done;
	    }

	    /* Time stamp */
	    if ((err = slp_get_int32(authblocks, len, &off, &timestamp))
		!= SLP_OK) {
		slp_err(LOG_INFO, 0, "slp_verify", "corrupt auth block");
		goto done;
	    }

	    /* SPI string */
	    if ((err = slp_get_string(authblocks, len, &off, &spi))
		!= SLP_OK) {
		slp_err(LOG_INFO, 0, "slp_verify", "corrupt auth block");
		goto done;
	    }

	    err = make_tbs(
		spi, authiov, authiov_len, timestamp, &inbytes, &inbytes_len);
	    if (err != SLP_OK) {
		goto done;
	    }

	    sig = (unsigned char *)(authblocks + off);
	    siglen = ablen - (off - this_ab);

	    off += siglen;

	    err =  do_verify(inbytes, inbytes_len, bsd, sig, siglen, spi);
	    if (err != SLP_OK) {
		free(spi);
		goto done;
	    }

	    free(spi);
	}

done:
	if (inbytes) free(inbytes);
	*total = off;

	return (err);
}

/*
 * When first called, attempts to dlopen a security shared library
 * and dlsym in the necessary interfaces. The library remains mapped
 * in, so successive calls just return SLP_OK.
 */
static SLPError get_security_backend() {
	static mutex_t be_lock = DEFAULTMUTEX;
	static void *dl = NULL;
	static int got_backend = 0;
	SLPError err = SLP_SECURITY_UNAVAILABLE;
	const char *libname;
	char *dlerr;

	(void) mutex_lock(&be_lock);

	if (got_backend) {
	    (void) mutex_unlock(&be_lock);
	    return (SLP_OK);
	}

	if (!(libname = SLPGetProperty(SLP_CONFIG_AUTH_BACKEND)) ||
	    !*libname) {
	    /* revert to default */
	    libname = "libami.so.1";
	}

	if (!(dl = dlopen(libname, RTLD_LAZY))) {
	    dlerr = dlerror();
	    slp_err(LOG_INFO, 0, "get_security_backend",
				"Could not dlopen AMI library: %s",
				(dlerr ? dlerr : "unknown DL error"));
	    slp_err(LOG_INFO, 0, "get_security_backend",
				"Is AMI installed?");
	    goto done;
	}

	/* Relocate AMI's statically initialized AIDs we need */
	if (!(ami_rsa_aid =
		dlsym(dl, "AMI_MD5WithRSAEncryption_AID"))) {

	    dlerr = dlerror();
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not relocate AMI_MD5WithRSAEncryption_AID: %s",
				(dlerr ? dlerr : "unknown DL error"));
	    goto done;
	}

	if (!(ami_dsa_aid =
		dlsym(dl, "AMI_SHA1WithDSASignature_AID"))) {

	    dlerr = dlerror();
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not relocate AMI_SHA1WithDSASignature_AID: %s",
				(dlerr ? dlerr : "unknown DL error"));
	    goto done;
	}

	/* Bring in the functions we need */
	if (!(dld_ami_init = (AMI_STATUS (*)(ami_handle_t **,
					    const char *,
					    const char *,
					    const uint_t,
					    const uint_t,
					    const char *))dlsym(
						    dl, "ami_init"))) {
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_init");
	    goto done;
	}

	if (!(dld_ami_sign = (AMI_STATUS (*)(ami_handle_t *,
						const uchar_t *,
						const size_t,
						const int,
						const ami_algid *,
						const uchar_t *,
						const size_t,
						const ami_algid *,
						uchar_t **,
						size_t *))dlsym(
							dl, "ami_sign"))) {
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_sign");
	    goto done;
	}

	if (!(dld_ami_verify = (AMI_STATUS (*)(ami_handle_t *,
						const uchar_t *,
						const size_t,
						const int,
						const ami_algid *,
						const uchar_t *,
						const size_t,
						const ami_algid *,
						const uchar_t *,
						const size_t))dlsym(
							dl, "ami_verify"))) {
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_verify");
	    goto done;
	}

	if (!(dld_ami_get_cert = (AMI_STATUS (*)(const ami_handle_t *,
						const char *,
						ami_cert **,
						int *))dlsym(
							dl, "ami_get_cert"))) {
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_get_cert");
	    goto done;
	}

	if (!(dld_ami_get_cert_chain = (AMI_STATUS (*)(const ami_handle_t *,
					    const ami_cert *,
					    const char **,
					    int flags,
					    ami_cert **,
					    int *))dlsym(
						dl, "ami_get_cert_chain"))) {
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_get_cert_chain");
	    goto done;
	}

	if (!(dld_ami_str2dn = (AMI_STATUS (*)(const ami_handle_t *,
						char *, ami_name **))dlsym(
							dl, "ami_str2dn"))) {
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_str2dn");
	    goto done;
	}

	if (!(dld_ami_dn2str = (AMI_STATUS (*)(const ami_handle_t *,
						ami_name *, char **))dlsym(
							dl, "ami_dn2str"))) {
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_dn2str");
	    goto done;
	}

	if (!(dld_ami_free_cert_list = (void (*)(ami_cert **, int))dlsym(
						dl, "ami_free_cert_list"))) {
		    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_free_cert_list");
	    goto done;
	}

	if (!(dld_ami_free_dn = (void (*)(ami_name **))dlsym(
							dl, "ami_free_dn"))) {
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_free_dn");
	    goto done;
	}

	if (!(dld_ami_strerror = (char *(*)(const ami_handle_t *,
					    const AMI_STATUS))dlsym(
						dl, "ami_strerror"))) {
	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_strerror");
	    goto done;
	}

	if (!(dld_ami_end = (AMI_STATUS (*)(ami_handle_t *))dlsym(
							dl, "ami_end"))) {

	    slp_err(LOG_INFO, 0, "get_security_backend",
		    "Could not load ami_end");
	    goto done;
	}

	got_backend = 1;
	err = SLP_OK;

done:
	if (!got_backend && dl) {
	    (void) dlclose(dl);
	}
	(void) mutex_unlock(&be_lock);

	return (err);
}

/*
 * Creates a bytes to-be-signed buffer suitable for input
 * a signature algorithm.
 *
 * The only backend currently available is AMI, which does
 * not support incremental updates for digesting. Hence we
 * must copy all elements of the input iovec into one buffer.
 *
 * This function allocates a single buffer into *buf big enough
 * to hold all necessary elements, sets *buflen to this length, and
 * makes a bytes-to-be-signed buffer. Into this buffer is placed
 * first the SPI string, then all elements of iov, and finally
 * the timestamp. Caller must free *buf.
 *
 * Returns err != SLP_OK only on catastrophic error.
 */
static SLPError make_tbs(const char *spi,
			    struct iovec *iov,
			    int iovlen,
			    unsigned int timestamp,
			    unsigned char **buf,
			    size_t *buflen) {
	int i;
	caddr_t p;
	size_t off;
	SLPError err;

	*buflen = 2 + strlen(spi);

	for (i = 0; i < iovlen; i++) {
	    *buflen += iov[i].iov_len;
	}

	*buflen += sizeof (timestamp);

	if (!(*buf = malloc(*buflen))) {
	    slp_err(LOG_CRIT, 0, "slp_sign", "out of memory");
	    return (SLP_MEMORY_ALLOC_FAILED);
	}

	/* @@@ ok to use caddr_t? */
	p = (caddr_t)*buf;

	/* Lay in SPI string */
	off = 0;
	if ((err = slp_add_string(p, *buflen, spi, &off)) != SLP_OK) {
		return (err);
	}

	p += off;

	/* Copy in elements of iov */
	for (i = 0; i < iovlen; i++) {
	    (void) memcpy(p, iov[i].iov_base, iov[i].iov_len);
	    p += iov[i].iov_len;
	    off += iov[i].iov_len;
	}

	/* Lay in timestamp */
	return (slp_add_int32((char *)*buf, *buflen, timestamp, &off));
}

/*
 * Creates an auth block from the given parameters:
 *
 *   sig_in	IN	Data to be signed
 *   sig_in_len	IN	Length of sig_in
 *   alias	IN	signing alias for this auth block
 *   timestamp	IN	Timestamp for this auth block
 *   abs	IN/OUT	Buffer of accumulated auth blocks
 *   abs_len	IN/OUT	Length of abs
 *
 * For each new auth block, abs is resized as necessary, and the
 * new auth block is appended. abs_len is updated accordingly.
 *
 * Returns SLP_OK if the signing and auth block creation succeeded.
 */
static SLPError make_authblock(struct iovec *authiov, int authiov_len,
				const char *alias, time_t timestamp,
				caddr_t *abs, size_t *abs_len) {

	unsigned char *sig_out = NULL;
	size_t sig_out_len = 0;
	ami_handle_t *amih = NULL;
	AMI_STATUS ami_err;
	size_t off = 0;
	SLPError err = SLP_OK;
	caddr_t ab;
	size_t ab_len;
	unsigned short bsd;
	ami_algid *aid;
	char *dn = NULL;
	unsigned char *sig_in = NULL;
	size_t sig_in_len;

	/* Create the signature */
	if ((ami_err = dld_ami_init(&amih, alias, NULL, 0, 0, NULL))
	    != AMI_OK) {
	    slp_err(LOG_INFO, 0, "make_authblock", "ami_init failed: %s",
		    dld_ami_strerror(amih, ami_err));
	    return (SLP_AUTHENTICATION_FAILED);
	}

	/* determine our DN, to be used as the SPI */
	if (!(dn = alias2dn(amih))) {
	    err = SLP_AUTHENTICATION_FAILED;
	    goto done;
	}

	/* make bytes to-be-signed */
	err = make_tbs(
		dn, authiov, authiov_len, timestamp, &sig_in, &sig_in_len);
	if (err != SLP_OK) {
	    goto done;
	}

	/* @@@ determine the AID and BSD for this alias */
	bsd = 1;
	aid = *ami_rsa_aid;

	if ((ami_err = dld_ami_sign(amih, sig_in, sig_in_len, AMI_END_DATA,
				NULL, NULL, 0, aid, &sig_out, &sig_out_len))
	    != AMI_OK) {

		slp_err(LOG_INFO, 0, "make_authblock", "ami_sign failed: %s",
			dld_ami_strerror(amih, ami_err));
		err = SLP_AUTHENTICATION_FAILED;
		goto done;
	    }

	/* We can now calculate the length of the auth block */
	ab_len =
		2 +			/* BSD */
		2 +			/* length */
		4 +			/* timestamp */
		2 + strlen(dn) +	/* SPI string */
		sig_out_len;		/* the signature */

	/* Grow buffer for already-created auth blocks, if necessary */
	if (*abs_len != 0) {
	    if (!(*abs = realloc(*abs, *abs_len + ab_len))) {
		slp_err(LOG_CRIT, 0, "make_authblock", "out of memory");
		err = SLP_MEMORY_ALLOC_FAILED;
		goto done;
	    }
	}
	ab = *abs + *abs_len;
	*abs_len += ab_len;

	/* BSD */
	err = slp_add_sht(ab, ab_len, bsd, &off);

	/* Auth block length */
	if (err == SLP_OK) {
	    err = slp_add_sht(ab, ab_len, ab_len, &off);
	}

	/* timestamp */
	if (err == SLP_OK) {
	    err = slp_add_int32(ab, ab_len, timestamp, &off);
	}

	/* SPI string */
	if (err == SLP_OK) {
	    err = slp_add_string(ab, ab_len, dn, &off);
	}

	/* Signature */
	if (err == SLP_OK) {
	    (void) memcpy(ab + off, sig_out, sig_out_len);
	}

done:
	if (amih) {
	    dld_ami_end(amih);
	}
	if (dn) free(dn);

	if (sig_in) free(sig_in);
	if (sig_out) free(sig_out);

	if (err == SLP_MEMORY_ALLOC_FAILED) {
	    /* critical error; abort */
	    free(*abs);
	}

	return (err);
}

/*
 * The actual verification routine which interacts with the security
 * backend to get a certificate for the given SPI and use that cert
 * to verify the signature contained in the auth block.
 *
 * inbytes	IN	bytes to be verified
 * inbytes_len	IN	length of inbytes
 * bsd		IN	BSD for this signature
 * sig		IN	the signature
 * siglen	IN	length of sig
 * spi		IN	SPI for this signature, not escaped
 *
 * Returns SLP_OK if the signature is verified, or SLP_AUTHENTICATION_FAILED
 * if any error occured.
 */
static SLPError do_verify(unsigned char *inbytes, size_t inbytes_len,
			    unsigned short bsd, const unsigned char *sig,
			    size_t siglen, const char *esc_spi) {

	AMI_STATUS ami_err;
	ami_handle_t *amih = NULL;
	SLPError err;
	ami_cert *certs = NULL;
	int icert, ccnt;
	ami_algid *aid;
	char *spi = NULL;

	/* Get the right AID */
	switch (bsd) {
	case 1:
		aid = *ami_rsa_aid;
		break;
	case 2:
		aid = *ami_dsa_aid;
		break;
	default:
		slp_err(LOG_INFO, 0, "do_verify",
			"Unsupported BSD %d for given SPI %s", bsd, spi);
		return (SLP_AUTHENTICATION_FAILED);
	}

	if ((ami_err = dld_ami_init(&amih, spi, NULL, 0, 0, NULL)) != AMI_OK) {
	    slp_err(LOG_INFO, 0, "do_verify", "ami_init failed: %s",
		    dld_ami_strerror(amih, ami_err));
	    return (SLP_AUTHENTICATION_FAILED);
	}

	/* unescape SPI */
	if ((err = SLPUnescape(esc_spi, &spi, SLP_FALSE))) {
	    goto done;
	}

	/* get certificate */
	if ((ami_err = dld_ami_get_cert(amih, spi, &certs, &ccnt)) != AMI_OK) {
	    slp_err(LOG_INFO, 0, "do_verify",
		    "Can not get certificate for %s: %s",
		    spi, dld_ami_strerror(amih, ami_err));
	    err = SLP_AUTHENTICATION_FAILED;
	    goto done;
	}

	/* @@@ select the right cert, if more than one */
	icert = 0;

	if ((ami_err = dld_ami_verify(amih, inbytes, inbytes_len, AMI_END_DATA,
				certs[icert].info.pubKeyInfo->algorithm,
				certs[icert].info.pubKeyInfo->pubKey.value,
				certs[icert].info.pubKeyInfo->pubKey.length,
				aid, sig, siglen)) != AMI_OK) {

	    slp_err(LOG_INFO, 0, "do_verify", "ami_verify failed: %s",
		    dld_ami_strerror(amih, ami_err));
	    err = SLP_AUTHENTICATION_FAILED;
	    goto done;
	}

	err = check_spis(amih, certs, icert, spi);

done:
	if (certs) {
	    dld_ami_free_cert_list(&certs, ccnt);
	}

	if (amih) {
	    dld_ami_end(amih);
	}

	if (spi) free(spi);

	return (err);
}

/*
 * Gets this process' DN, or returns NULL on failure. Caller must free
 * the result. The reslting DN will be escaped.
 */
static char *alias2dn(ami_handle_t *amih) {
	ami_cert *certs;
	int ccnt;
	AMI_STATUS status;
	char *answer = NULL;
	char *esc_answer;

	if ((status = dld_ami_get_cert(amih, NULL, &certs, &ccnt)) != AMI_OK) {
	    slp_err(LOG_INFO, 0, "alias2dn",
		    "Can not get my DN: %s",
		    dld_ami_strerror(amih, status));
	    return (NULL);
	}

	if (ccnt == 0) {
	    slp_err(LOG_INFO, 0, "alias2dn",
		    "No cert found for myself");
	    return (NULL);
	}

	if ((status = dld_ami_dn2str(amih, certs[0].info.subject, &answer))
	    != AMI_OK) {
	    slp_err(LOG_INFO, 0, "alias2dn",
		    "Can not convert DN to string: %s",
		    dld_ami_strerror(amih, status));
	    answer = NULL;
	    goto done;
	}

	if (SLPEscape(answer, &esc_answer, SLP_FALSE) != SLP_OK) {
	    free(answer);
	    answer = NULL;
	} else {
	    free(answer);
	    answer = esc_answer;
	}

done:
	dld_ami_free_cert_list(&certs, ccnt);

	return (answer);
}

static SLPError check_spis(ami_handle_t *amih,
			    ami_cert *certs,
			    int icert,
			    const char *spi) {
	ami_cert *chain = NULL;
	int ccnt;
	const char *cas[2];
	char *prop_spi;
	char *ue_spi;
	char *p;
	SLPError err;
	AMI_STATUS ami_err;

	/* If configured SPI == authblock SPI, we are done */
	prop_spi = (char *)SLPGetProperty(SLP_CONFIG_SPI);
	if (!prop_spi || !*prop_spi) {
	    slp_err(LOG_INFO, 0, "do_verify", "no SPI configured");
	    err = SLP_AUTHENTICATION_FAILED;
	    goto done;
	}

	/* dup it so we can modify it */
	if (!(prop_spi = strdup(prop_spi))) {
	    slp_err(LOG_CRIT, 0, "do_verify", "out of memory");
	    err = SLP_MEMORY_ALLOC_FAILED;
	    goto done;
	}

	/* if more than one SPI given, discard all but first */
	if ((p = slp_utf_strchr(prop_spi, ','))) {
	    *p = 0;
	}

	/* unescape configured DNs */
	if ((err = SLPUnescape(prop_spi, &ue_spi, SLP_FALSE)) != SLP_OK) {
	    goto done;
	}
	free(prop_spi);
	prop_spi = ue_spi;

	if (dncmp(amih, prop_spi, spi) == 0) {
	    /* they match, so we are done */
	    err = SLP_OK;
	    goto done;
	}

	/*
	 * Else we need to traverse the cert chain. ami_get_cert_chain
	 * verifies each link in the chain, so no need to do it again.
	 */
	cas[0] = prop_spi;
	cas[1] = NULL;
	ami_err = dld_ami_get_cert_chain(amih, certs + icert, cas, 0,
						&chain, &ccnt);
	if (ami_err != AMI_OK) {
	    slp_err(LOG_INFO, 0, "do_verify",
		    "can not get cert chain: %s",
		    dld_ami_strerror(amih, ami_err));
	    err = SLP_AUTHENTICATION_FAILED;
	    goto done;
	}

	err = SLP_OK;

done:
	if (chain) {
	    dld_ami_free_cert_list(&chain, ccnt);
	}

	if (prop_spi) free(prop_spi);

	return (err);
}

static int dncmp(ami_handle_t *amih, const char *s1, const char *s2) {
	AMI_STATUS status;
	ami_name *dn1 = NULL;
	ami_name *dn2 = NULL;
	char *dnstr1 = NULL;
	char *dnstr2 = NULL;
	int answer;

	/* Normalize: convert to DN structs and back to strings */
	if ((status = dld_ami_str2dn(amih, (char *)s1, &dn1)) != AMI_OK) {
	    slp_err(LOG_INFO, 0, "dncmp",
		    "can not create DN structure for %s: %s",
		    s1,
		    dld_ami_strerror(amih, status));
	    answer = 1;
	    goto done;
	}

	if ((status = dld_ami_str2dn(amih, (char *)s2, &dn2)) != AMI_OK) {
	    slp_err(LOG_INFO, 0, "dncmp",
		    "can not create DN structure for %s: %s",
		    s2,
		    dld_ami_strerror(amih, status));
	    answer = 1;
	    goto done;
	}

	/* convert back to strings */
	if ((status = dld_ami_dn2str(amih, dn1, &dnstr1)) != AMI_OK) {
	    slp_err(LOG_INFO, 0, "dncmp",
		    "can not convert DN to string: %s",
		    dld_ami_strerror(amih, status));
	    answer = 1;
	    goto done;
	}

	if ((status = dld_ami_dn2str(amih, dn2, &dnstr2)) != AMI_OK) {
	    slp_err(LOG_INFO, 0, "dncmp",
		    "can not convert DN to string: %s",
		    dld_ami_strerror(amih, status));
	    answer = 1;
	    goto done;
	}

	answer = strcasecmp(dnstr1, dnstr2);

done:
	if (dn1) {
	    dld_ami_free_dn(&dn1);
	}

	if (dn2) {
	    dld_ami_free_dn(&dn2);
	}

	if (dnstr1) free(dnstr1);
	if (dnstr2) free(dnstr2);

	return (answer);
}
