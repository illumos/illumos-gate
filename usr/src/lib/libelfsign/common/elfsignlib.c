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

#define	ELF_TARGET_ALL	/* get definitions of all section flags */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <stddef.h>
#include <stdlib.h>
#include <libintl.h>
#include <dirent.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/mman.h>
#include <cryptoutil.h>
#include <sha1.h>
#include <sys/crypto/elfsign.h>
#include <libelfsign.h>

#ifndef SHA1_DIGEST_LENGTH
#define	SHA1_DIGEST_LENGTH 20
#endif /* SHA1_DIGEST_LENGTH */

const char SUNW_ELF_SIGNATURE_ID[] =	ELF_SIGNATURE_SECTION;
const char OID_sha1WithRSAEncryption[] = "1.2.840.113549.1.1.5";

static ELFsign_status_t elfsign_adjustoffsets(ELFsign_t ess,
    Elf_Scn *scn, uint64_t new_size);
static ELFsign_status_t elfsign_verify_esa(ELFsign_t ess,
    uchar_t *sig, size_t sig_len);
static uint32_t elfsign_switch_uint32(uint32_t i);
static ELFsign_status_t elfsign_switch(ELFsign_t ess,
    struct filesignatures *fssp, enum ES_ACTION action);

struct filesig_extraction {
	filesig_vers_t	fsx_version;
	char	*fsx_format;
	char	fsx_signer_DN[ELFCERT_MAX_DN_LEN];
	size_t	fsx_signer_DN_len;
	uchar_t	fsx_signature[SIG_MAX_LENGTH];
	size_t	fsx_sig_len;
	char	fsx_sig_oid[100];
	size_t	fsx_sig_oid_len;
	time_t	fsx_time;
};

static char *
version_to_str(filesig_vers_t v)
{
	char	*ret;

	switch (v) {
	case FILESIG_VERSION1:
		ret = "VERSION1";
		break;
	case FILESIG_VERSION2:
		ret = "VERSION2";
		break;
	case FILESIG_VERSION3:
		ret = "VERSION3";
		break;
	case FILESIG_VERSION4:
		ret = "VERSION4";
		break;
	default:
		ret = "UNKNOWN";
		break;
	}
	return (ret);
}

/*
 * Update filesignatures to include the v1/v2 filesig,
 *	composed of signer DN, signature, and OID.
 */
static struct filesignatures *
filesig_insert_dso(struct filesignatures *fssp,
    filesig_vers_t	version,
    const char		*dn,
    int			dn_len,
    const uchar_t	*sig,
    int			sig_len,
    const char		*oid,
    int			oid_len)
{
	struct filesig	*fsgp;
	char		*fsdatap;

	if (oid == NULL) {
		/*
		 * This OID is used for the rsa_md5_sha1 format signature also.
		 * This use is historical, and is hence continued,
		 * despite its lack of technical accuracy.
		 */
		oid = OID_sha1WithRSAEncryption;
		oid_len = strlen(oid);
	}

	/*
	 * for now, always insert a single-signature signature block
	 */
	if (fssp != NULL)
		free(fssp);
	fssp  = (struct filesignatures *)
	    malloc(filesig_ALIGN(sizeof (struct filesignatures) +
	    dn_len + sig_len + oid_len));
	if (fssp == NULL)
		return (fssp);

	fssp->filesig_cnt = 1;
	fssp->filesig_pad = 0;	/* reserve for future use */

	fsgp = &fssp->filesig_sig;
	fsgp->filesig_size = sizeof (struct filesig) +
	    dn_len + sig_len + oid_len;
	fsgp->filesig_version = version;
	switch (version) {
	case FILESIG_VERSION1:
	case FILESIG_VERSION2:
		fsgp->filesig_size -= sizeof (struct filesig) -
		    offsetof(struct filesig, filesig_v1_data[0]);
		fsgp->filesig_v1_dnsize = dn_len;
		fsgp->filesig_v1_sigsize = sig_len;
		fsgp->filesig_v1_oidsize = oid_len;
		fsdatap = &fsgp->filesig_v1_data[0];
		break;
	case FILESIG_VERSION3:
	case FILESIG_VERSION4:
		fsgp->filesig_size -= sizeof (struct filesig) -
		    offsetof(struct filesig, filesig_v3_data[0]);
		fsgp->filesig_v3_time = time(NULL);
		fsgp->filesig_v3_dnsize = dn_len;
		fsgp->filesig_v3_sigsize = sig_len;
		fsgp->filesig_v3_oidsize = oid_len;
		fsdatap = &fsgp->filesig_v3_data[0];
		break;
	default:
		cryptodebug("filesig_insert_dso: unknown version: %d",
		    version);
		free(fssp);
		return (NULL);
	}
	(void) memcpy(fsdatap, dn, dn_len);
	fsdatap += dn_len;
	(void) memcpy(fsdatap, (char *)sig, sig_len);
	fsdatap += sig_len;
	(void) memcpy(fsdatap, oid, oid_len);
	fsdatap += oid_len;
	fsgp = filesig_next(fsgp);
	(void) memset(fsdatap, 0, (char *)(fsgp) - fsdatap);

	return (fssp);
}

/*
 * filesig_extract - extract filesig structure to internal form
 */
static filesig_vers_t
filesig_extract(struct filesig *fsgp, struct filesig_extraction *fsxp)
{
	char	*fsdp;

#define	filesig_extract_common(cp, field, data_var, len_var, len_limit)  { \
	len_var = len_limit; \
	if (len_var > fsgp->field) \
		len_var = fsgp->field; \
	(void) memcpy(data_var, cp, len_var); \
	cp += fsgp->field; }
#define	filesig_extract_str(cp, field, data_var, len_var) \
	filesig_extract_common(cp, field, data_var, len_var, \
	    sizeof (data_var) - 1); \
	data_var[len_var] = '\0';
#define	filesig_extract_opaque(cp, field, data_var, len_var) \
	filesig_extract_common(cp, field, data_var, len_var, sizeof (data_var))

	fsxp->fsx_version = fsgp->filesig_version;
	cryptodebug("filesig_extract: version=%s",
	    version_to_str(fsxp->fsx_version));
	switch (fsxp->fsx_version) {
	case FILESIG_VERSION1:
	case FILESIG_VERSION2:
		/*
		 * extract VERSION1 DN, signature, and OID
		 */
		fsdp = fsgp->filesig_v1_data;
		fsxp->fsx_format = ES_FMT_RSA_MD5_SHA1;
		fsxp->fsx_time = 0;
		filesig_extract_str(fsdp, filesig_v1_dnsize,
		    fsxp->fsx_signer_DN, fsxp->fsx_signer_DN_len);
		filesig_extract_opaque(fsdp, filesig_v1_sigsize,
		    fsxp->fsx_signature, fsxp->fsx_sig_len);
		filesig_extract_str(fsdp, filesig_v1_oidsize,
		    fsxp->fsx_sig_oid, fsxp->fsx_sig_oid_len);
		break;
	case FILESIG_VERSION3:
	case FILESIG_VERSION4:
		fsdp = fsgp->filesig_v3_data;
		fsxp->fsx_format = ES_FMT_RSA_SHA1;
		fsxp->fsx_time = fsgp->filesig_v3_time;
		filesig_extract_str(fsdp, filesig_v3_dnsize,
		    fsxp->fsx_signer_DN, fsxp->fsx_signer_DN_len);
		filesig_extract_opaque(fsdp, filesig_v3_sigsize,
		    fsxp->fsx_signature, fsxp->fsx_sig_len);
		filesig_extract_str(fsdp, filesig_v3_oidsize,
		    fsxp->fsx_sig_oid, fsxp->fsx_sig_oid_len);
		break;
	default:
		break;
	}

	return (fsxp->fsx_version);
}

ELFsign_status_t
elfsign_begin(const char *filename, enum ES_ACTION action, ELFsign_t *essp)
{
	Elf_Cmd		elfcmd;
	int		oflags = 0;
	short		l_type;
	ELFsign_t	ess;
	struct stat	stb;
	union {
		char	c[2];
		short	s;
	}	uorder;
	GElf_Ehdr	elfehdr;
	char		*ident;

	switch (action) {
	case ES_GET:
	case ES_GET_CRYPTO:
		cryptodebug("elfsign_begin for get");
		elfcmd = ELF_C_READ;
		oflags = O_RDONLY | O_NOCTTY | O_NDELAY;
		l_type = F_RDLCK;
		break;
	case ES_UPDATE_RSA_MD5_SHA1:
	case ES_UPDATE_RSA_SHA1:
		cryptodebug("elfsign_begin for update");
		elfcmd = ELF_C_RDWR;
		oflags = O_RDWR | O_NOCTTY | O_NDELAY;
		l_type = F_WRLCK;
		break;
	default:
		return (ELFSIGN_UNKNOWN);
	}

	if ((ess = malloc(sizeof (struct ELFsign_s))) == NULL) {
		return (ELFSIGN_UNKNOWN);
	}
	(void) memset((void *)ess, 0, sizeof (struct ELFsign_s));

	if (!elfcertlib_init(ess)) {
		cryptodebug("elfsign_begin: failed initialization");
		return (ELFSIGN_UNKNOWN);
	}

	ess->es_elf = NULL;
	ess->es_action = action;
	ess->es_version = FILESIG_UNKNOWN;
	ess->es_pathname = NULL;
	ess->es_certpath = NULL;

	if (filename == NULL) {
		*essp = ess;
		return (ELFSIGN_SUCCESS);
	}

	if ((ess->es_fd = open(filename, oflags)) == -1) {
		elfsign_end(ess);
		return (ELFSIGN_INVALID_ELFOBJ);
	}
	if ((fstat(ess->es_fd, &stb) == -1) || !S_ISREG(stb.st_mode)) {
		elfsign_end(ess);
		return (ELFSIGN_INVALID_ELFOBJ);
	}
	if ((ess->es_pathname = strdup(filename)) == NULL) {
		elfsign_end(ess);
		return (ELFSIGN_UNKNOWN);
	}
	/*
	 * The following lock is released in elfsign_end() when we close(2)
	 * the es_fd. This ensures that we aren't trying verify a file
	 * we are currently updating.
	 */
	ess->es_flock.l_type = l_type;
	ess->es_flock.l_whence = SEEK_CUR;
	ess->es_flock.l_start = 0;
	ess->es_flock.l_len = 0;
	if (fcntl(ess->es_fd, F_SETLK, &ess->es_flock) == -1) {
		cryptodebug("fcntl(F_SETLK) of %s failed with: %s",
		    ess->es_pathname, strerror(errno));
		elfsign_end(ess);
		return (ELFSIGN_UNKNOWN);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		elfsign_end(ess);
		return (ELFSIGN_UNKNOWN);
	}

	if ((ess->es_elf = elf_begin(ess->es_fd, elfcmd,
	    (Elf *)NULL)) == NULL) {
		cryptodebug("elf_begin() failed: %s", elf_errmsg(-1));
		elfsign_end(ess);
		return (ELFSIGN_INVALID_ELFOBJ);
	}

	if (gelf_getehdr(ess->es_elf, &elfehdr) == NULL) {
		cryptodebug("elf_getehdr() failed: %s", elf_errmsg(-1));
		elfsign_end(ess);
		return (ELFSIGN_INVALID_ELFOBJ);
	}
	ess->es_has_phdr = (elfehdr.e_phnum != 0);

	uorder.s = ELFDATA2MSB << 8 | ELFDATA2LSB;
	ident = elf_getident(ess->es_elf, NULL);
	if (ident == NULL) {
		cryptodebug("elf_getident() failed: %s", elf_errmsg(-1));
		elfsign_end(ess);
		return (ELFSIGN_INVALID_ELFOBJ);
	}
	ess->es_same_endian = (ident[EI_DATA] == uorder.c[0]);
	ess->es_ei_class = ident[EI_CLASS];

	/*
	 * Call elf_getshstrndx to be sure we have a real ELF object
	 * this is required because elf_begin doesn't check that.
	 */
	if (elf_getshstrndx(ess->es_elf, &ess->es_shstrndx) == 0) {
		elfsign_end(ess);
		cryptodebug("elfsign_begin: elf_getshstrndx failed");
		return (ELFSIGN_INVALID_ELFOBJ);
	}

	/*
	 * Make sure libelf doesn't rearrange section ordering / offsets.
	 */
	(void) elf_flagelf(ess->es_elf, ELF_C_SET, ELF_F_LAYOUT);

	*essp = ess;

	return (ELFSIGN_SUCCESS);
}

/*
 * elfsign_end - cleanup the ELFsign_t
 *
 * IN/OUT:	ess
 */
void
elfsign_end(ELFsign_t ess)
{
	if (ess == NULL)
		return;

	if (ess->es_elf != NULL && ES_ACTISUPDATE(ess->es_action)) {
		if (elf_update(ess->es_elf, ELF_C_WRITE) == -1) {
			cryptodebug("elf_update() failed: %s",
			    elf_errmsg(-1));
			return;
		}
	}

	if (ess->es_fd != -1) {
		(void) close(ess->es_fd);
		ess->es_fd = -1;
	}

	if (ess->es_pathname != NULL) {
		free(ess->es_pathname);
		ess->es_pathname = NULL;
	}
	if (ess->es_certpath != NULL) {
		free(ess->es_certpath);
		ess->es_certpath = NULL;
	}

	if (ess->es_elf != NULL) {
		(void) elf_end(ess->es_elf);
		ess->es_elf = NULL;
	}

	elfcertlib_fini(ess);

	free(ess);
}

/*
 * set the certificate path
 */
ELFsign_status_t
elfsign_setcertpath(ELFsign_t ess, const char *certpath)
{
	/*
	 * Normally use of access(2) is insecure, here we are only
	 * doing it to help provide early failure and better error
	 * checking, so there is no race condition.
	 */
	if (access(certpath, R_OK) != 0) {
		elfsign_end(ess);
		return (ELFSIGN_INVALID_CERTPATH);
	}
	ess->es_certpath = strdup(certpath);

	if (ES_ACTISUPDATE(ess->es_action)) {
		ELFCert_t	cert = NULL;
		char		*subject;

		/* set the version based on the certificate */
		if (elfcertlib_getcert(ess, ess->es_certpath, NULL,
		    &cert, ess->es_action)) {
			if ((subject = elfcertlib_getdn(cert)) != NULL) {
				if (strstr(subject, ELFSIGN_CRYPTO))
					ess->es_version = (ess->es_action ==
					    ES_UPDATE_RSA_MD5_SHA1) ?
					    FILESIG_VERSION1 : FILESIG_VERSION3;
				else
					ess->es_version = (ess->es_action ==
					    ES_UPDATE_RSA_MD5_SHA1) ?
					    FILESIG_VERSION2 : FILESIG_VERSION4;
			}
			elfcertlib_releasecert(ess, cert);
		}
		if (ess->es_version == FILESIG_UNKNOWN)
			return (ELFSIGN_FAILED);
	}
	return (ELFSIGN_SUCCESS);
}

/*
 * set the callback context
 */
void
elfsign_setcallbackctx(ELFsign_t ess, void *ctx)
{
	ess->es_callbackctx = ctx;
}

/*
 * set the signature extraction callback
 */
void
elfsign_setsigvercallback(ELFsign_t ess,
    void (*cb)(void *, void *, size_t, ELFCert_t))
{
	ess->es_sigvercallback = cb;
}

/*
 * elfsign_signatures
 *
 * IN: 	ess, fsspp, action
 * OUT:	fsspp
 */
ELFsign_status_t
elfsign_signatures(ELFsign_t ess,
    struct filesignatures **fsspp,
    size_t *fslen,
    enum ES_ACTION action)
{
	Elf_Scn		*scn = NULL, *sig_scn = NULL;
	GElf_Shdr	shdr;
	Elf_Data	*data = NULL;
	const char	*elf_section = SUNW_ELF_SIGNATURE_ID;
	int		fscnt, fssize;
	struct filesig	*fsgp, *fsgpnext;
	uint64_t	sig_offset = 0;

	cryptodebug("elfsign_signature");
	if ((ess == NULL) || (fsspp == NULL)) {
		cryptodebug("invalid arguments");
		return (ELFSIGN_UNKNOWN);
	}

	cryptodebug("elfsign_signature %s for %s",
	    ES_ACTISUPDATE(action) ? "ES_UPDATE" : "ES_GET", elf_section);

	(void) elf_errno();
	while ((scn = elf_nextscn(ess->es_elf, scn)) != NULL) {
		const char	*sh_name;
		/*
		 * Do a string compare to examine each section header
		 * to see if this is the section that needs to be updated.
		 */
		if (gelf_getshdr(scn, &shdr) == NULL) {
			cryptodebug("gelf_getshdr() failed: %s",
			    elf_errmsg(-1));
			return (ELFSIGN_FAILED);
		}
		sh_name = elf_strptr(ess->es_elf, ess->es_shstrndx,
		    (size_t)shdr.sh_name);
		if (strcmp(sh_name, elf_section) == 0) {
			cryptodebug("elfsign_signature: found %s", elf_section);
			sig_scn = scn;
			break;
		}
		if (shdr.sh_type != SHT_NOBITS &&
		    sig_offset < shdr.sh_offset + shdr.sh_size) {
			sig_offset = shdr.sh_offset + shdr.sh_size;
		}
	}
	if (elf_errmsg(0) != NULL) {
		cryptodebug("unexpected error: %s", elf_section,
		    elf_errmsg(-1));
		return (ELFSIGN_FAILED);
	}

	if (ES_ACTISUPDATE(action) && (sig_scn == NULL))  {
		size_t	old_size, new_size;
		char	*new_d_buf;

		cryptodebug("elfsign_signature: %s not found - creating",
		    elf_section);

		/*
		 * insert section name in .shstrtab
		 */
		if ((scn = elf_getscn(ess->es_elf, ess->es_shstrndx)) == 0) {
			cryptodebug("elf_getscn() failed: %s",
			    elf_errmsg(-1));
			return (ELFSIGN_FAILED);
		}
		if (gelf_getshdr(scn, &shdr) == NULL) {
			cryptodebug("gelf_getshdr() failed: %s",
			    elf_errmsg(-1));
			return (ELFSIGN_FAILED);
		}
		if ((data = elf_getdata(scn, data)) == NULL) {
			cryptodebug("elf_getdata() failed: %s",
			    elf_errmsg(-1));
			return (ELFSIGN_FAILED);
		}
		old_size = data->d_size;
		if (old_size != shdr.sh_size) {
			cryptodebug("mismatch between data size %d "
			    "and section size %lld", old_size, shdr.sh_size);
			return (ELFSIGN_FAILED);
		}
		new_size = old_size + strlen(elf_section) + 1;
		if ((new_d_buf = malloc(new_size)) == NULL)
			return (ELFSIGN_FAILED);

		(void) memcpy(new_d_buf, data->d_buf, old_size);
		(void) strlcpy(new_d_buf + old_size, elf_section,
		    new_size - old_size);
		data->d_buf = new_d_buf;
		data->d_size = new_size;
		data->d_align = 1;
		/*
		 * Add the section name passed in to the end of the file.
		 * Initialize the fields in the Section Header that
		 * libelf will not fill in.
		 */
		if ((sig_scn = elf_newscn(ess->es_elf)) == 0) {
			cryptodebug("elf_newscn() failed: %s",
			    elf_errmsg(-1));
			return (ELFSIGN_FAILED);
		}
		if (gelf_getshdr(sig_scn, &shdr) == 0) {
			cryptodebug("gelf_getshdr() failed: %s",
			    elf_errmsg(-1));
			return (ELFSIGN_FAILED);
		}
		shdr.sh_name = old_size;
		shdr.sh_type = SHT_SUNW_SIGNATURE;
		shdr.sh_flags = SHF_EXCLUDE;
		shdr.sh_addr = 0;
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_size = 0;
		shdr.sh_offset = sig_offset;
		shdr.sh_addralign = 1;

		/*
		 * Flush the changes to the underlying elf32 or elf64
		 * section header.
		 */
		if (gelf_update_shdr(sig_scn, &shdr) == 0) {
			cryptodebug("gelf_update_shdr failed");
			return (ELFSIGN_FAILED);
		}

		if ((data = elf_newdata(sig_scn)) == NULL) {
			cryptodebug("can't add elf data area for %s: %s",
			    elf_section, elf_errmsg(-1));
			return (ELFSIGN_FAILED);
		}
		if (elfsign_adjustoffsets(ess, scn,
		    old_size + strlen(elf_section) + 1) != ELFSIGN_SUCCESS) {
			cryptodebug("can't adjust for new section name %s",
			    elf_section);
			return (ELFSIGN_FAILED);
		}
	} else {
		if (sig_scn == NULL) {
			cryptodebug("can't find signature section");
			*fsspp = NULL;
			return (ELFSIGN_NOTSIGNED);
		}
		if ((data = elf_getdata(sig_scn, NULL)) == 0) {
			cryptodebug("can't get section data for %s",
			    elf_section);
			return (ELFSIGN_FAILED);
		}
	}

	if (ES_ACTISUPDATE(action))  {
		fssize = offsetof(struct filesignatures, _u1);
		if (*fsspp != NULL) {
			fsgp = &(*fsspp)->filesig_sig;
			for (fscnt = 0; fscnt < (*fsspp)->filesig_cnt;
			    fscnt++) {
				fsgpnext = filesig_next(fsgp);
				fssize += (char *)(fsgpnext) - (char *)(fsgp);
				fsgp = fsgpnext;
			}
		}
		if (shdr.sh_addr != 0) {
			cryptodebug("section %s is part of a loadable segment, "
			    "it cannot be changed.\n", elf_section);
			return (ELFSIGN_FAILED);
		}
		if ((data->d_buf = malloc(fssize)) == NULL)
			return (ELFSIGN_FAILED);
		if (*fsspp != NULL) {
			(void) memcpy(data->d_buf, *fsspp, fssize);
			(void) elfsign_switch(ess,
			    (struct filesignatures *)data->d_buf, action);
		}
		data->d_size = fssize;
		data->d_align = 1;
		data->d_type = ELF_T_BYTE;
		cryptodebug("elfsign_signature: data->d_size = %d",
		    data->d_size);
		if (elfsign_adjustoffsets(ess, sig_scn, fssize) !=
		    ELFSIGN_SUCCESS) {
			cryptodebug("can't adjust for revised signature "
			    "section contents");
			return (ELFSIGN_FAILED);
		}
	} else {
		*fsspp = malloc(data->d_size);
		if (*fsspp == NULL)
			return (ELFSIGN_FAILED);
		(void) memcpy(*fsspp, data->d_buf, data->d_size);
		if (elfsign_switch(ess, *fsspp, ES_GET) != ELFSIGN_SUCCESS) {
			free(*fsspp);
			*fsspp = NULL;
			return (ELFSIGN_FAILED);
		}
		*fslen = data->d_size;
	}

	return (ELFSIGN_SUCCESS);
}

static ELFsign_status_t
elfsign_adjustoffsets(ELFsign_t ess, Elf_Scn *scn, uint64_t new_size)
{
	GElf_Ehdr	elfehdr;
	GElf_Shdr	shdr;
	uint64_t	prev_end, scn_offset;
	char		*name;
	Elf_Scn		*scnp;
	Elf_Data	*data;
	ELFsign_status_t	retval = ELFSIGN_FAILED;
	struct scninfo {
		struct scninfo	*scni_next;
		Elf_Scn		*scni_scn;
		uint64_t	scni_offset;
	}		*scnip = NULL, *tmpscnip, **scnipp;

	/* get the size of the current section */
	if (gelf_getshdr(scn, &shdr) == NULL)
		return (ELFSIGN_FAILED);
	if (shdr.sh_size == new_size)
		return (ELFSIGN_SUCCESS);
	scn_offset = shdr.sh_offset;
	name = elf_strptr(ess->es_elf, ess->es_shstrndx,
	    (size_t)shdr.sh_name);
	if (shdr.sh_flags & SHF_ALLOC && ess->es_has_phdr) {
		cryptodebug("elfsign_adjustoffsets: "
		    "can't move allocated section %s", name ? name : "NULL");
		return (ELFSIGN_FAILED);
	}

	/* resize the desired section */
	cryptodebug("elfsign_adjustoffsets: "
	    "resizing %s at 0x%llx from 0x%llx to 0x%llx",
	    name ? name : "NULL", shdr.sh_offset, shdr.sh_size, new_size);
	shdr.sh_size = new_size;
	if (gelf_update_shdr(scn, &shdr) == 0) {
		cryptodebug("gelf_update_shdr failed");
		goto bad;
	}
	prev_end = shdr.sh_offset + shdr.sh_size;

	/*
	 * find sections whose data follows the changed section
	 *	must scan all sections since section data may not
	 *	be in same order as section headers
	 */
	scnp = elf_getscn(ess->es_elf, 0);	/* "seek" to start */
	while ((scnp = elf_nextscn(ess->es_elf, scnp)) != NULL) {
		if (gelf_getshdr(scnp, &shdr) == NULL)
			goto bad;
		if (shdr.sh_offset <= scn_offset)
			continue;
		name = elf_strptr(ess->es_elf, ess->es_shstrndx,
		    (size_t)shdr.sh_name);
		if (shdr.sh_flags & SHF_ALLOC && ess->es_has_phdr) {
			if (shdr.sh_type == SHT_NOBITS) {
				/* .bss can occasionally overlap .shrtab */
				continue;
			}
			cryptodebug("elfsign_adjustoffsets: "
			    "can't move allocated section %s",
			    name ? name : "NULL");
			goto bad;
		}
		/*
		 * force reading of data to memory image
		 */
		data = NULL;
		while ((data = elf_rawdata(scnp, data)) != NULL)
			;
		/*
		 * capture section information
		 * insert into list in order of sh_offset
		 */
		cryptodebug("elfsign_adjustoffsets: "
		    "may have to adjust section %s, offset 0x%llx",
		    name ? name : "NULL", shdr.sh_offset);
		tmpscnip = (struct scninfo *)malloc(sizeof (struct scninfo));
		if (tmpscnip == NULL) {
			cryptodebug("elfsign_adjustoffsets: "
			    "memory allocation failure");
			goto bad;
		}
		tmpscnip->scni_scn = scnp;
		tmpscnip->scni_offset = shdr.sh_offset;
		for (scnipp = &scnip; *scnipp != NULL;
		    scnipp = &(*scnipp)->scni_next) {
			if ((*scnipp)->scni_offset > tmpscnip->scni_offset)
				break;
		}
		tmpscnip->scni_next = *scnipp;
		*scnipp = tmpscnip;
	}

	/* move following sections as necessary */
	for (tmpscnip = scnip; tmpscnip != NULL;
	    tmpscnip = tmpscnip->scni_next) {
		scnp = tmpscnip->scni_scn;
		if (gelf_getshdr(scnp, &shdr) == NULL) {
			cryptodebug("elfsign_adjustoffsets: "
			    "elf_getshdr for section %d failed",
			    elf_ndxscn(scnp));
			goto bad;
		}
		if (shdr.sh_offset >= prev_end)
			break;
		prev_end = (prev_end + shdr.sh_addralign - 1) &
		    (-shdr.sh_addralign);
		name = elf_strptr(ess->es_elf, ess->es_shstrndx,
		    (size_t)shdr.sh_name);
		cryptodebug("elfsign_adjustoffsets: "
		    "moving %s size 0x%llx from 0x%llx to 0x%llx",
		    name ? name : "NULL", shdr.sh_size,
		    shdr.sh_offset, prev_end);
		shdr.sh_offset = prev_end;
		if (gelf_update_shdr(scnp, &shdr) == 0) {
			cryptodebug("gelf_update_shdr failed");
			goto bad;
		}
		prev_end = shdr.sh_offset + shdr.sh_size;
	}

	/*
	 * adjust section header offset in elf header
	 */
	if (gelf_getehdr(ess->es_elf, &elfehdr) == NULL) {
		cryptodebug("elf_getehdr() failed: %s", elf_errmsg(-1));
		goto bad;
	}
	if (elfehdr.e_shoff < prev_end) {
		if (ess->es_ei_class == ELFCLASS32)
			prev_end = (prev_end + ELF32_FSZ_OFF - 1) &
			    (-ELF32_FSZ_OFF);
		else if (ess->es_ei_class == ELFCLASS64)
			prev_end = (prev_end + ELF64_FSZ_OFF - 1) &
			    (-ELF64_FSZ_OFF);
		cryptodebug("elfsign_adjustoffsets: "
		    "move sh_off from 0x%llx to 0x%llx",
		    elfehdr.e_shoff, prev_end);
		elfehdr.e_shoff = prev_end;
		if (gelf_update_ehdr(ess->es_elf, &elfehdr) == 0) {
			cryptodebug("elf_update_ehdr() failed: %s",
			    elf_errmsg(-1));
			goto bad;
		}
	}

	retval = ELFSIGN_SUCCESS;

bad:
	while (scnip != NULL) {
		tmpscnip = scnip->scni_next;
		free(scnip);
		scnip = tmpscnip;
	}
	return (retval);
}

struct filesignatures *
elfsign_insert_dso(ELFsign_t ess,
    struct filesignatures *fssp,
    const char		*dn,
    int			dn_len,
    const uchar_t	*sig,
    int			sig_len,
    const char		*oid,
    int			oid_len)
{
	return (filesig_insert_dso(fssp, ess->es_version, dn, dn_len,
	    sig, sig_len, oid, oid_len));
}

/*ARGSUSED*/
filesig_vers_t
elfsign_extract_sig(ELFsign_t ess,
    struct filesignatures *fssp,
    uchar_t		*sig,
    size_t		*sig_len)
{
	struct filesig_extraction	fsx;
	filesig_vers_t	version;

	if (fssp == NULL)
		return (FILESIG_UNKNOWN);
	if (fssp->filesig_cnt != 1)
		return (FILESIG_UNKNOWN);
	version = filesig_extract(&fssp->filesig_sig, &fsx);
	switch (version) {
	case FILESIG_VERSION1:
	case FILESIG_VERSION2:
	case FILESIG_VERSION3:
	case FILESIG_VERSION4:
		if (*sig_len >= fsx.fsx_sig_len) {
			(void) memcpy((char *)sig, (char *)fsx.fsx_signature,
			    *sig_len);
			*sig_len = fsx.fsx_sig_len;
		} else
			version = FILESIG_UNKNOWN;
		break;
	default:
		version = FILESIG_UNKNOWN;
		break;
	}

	if (ess->es_version == FILESIG_UNKNOWN) {
		ess->es_version = version;
	}

	return (version);
}

static ELFsign_status_t
elfsign_hash_common(ELFsign_t ess, uchar_t *hash, size_t *hash_len,
    boolean_t hash_mem_resident)
{
	Elf_Scn		*scn = NULL;
	ELFsign_status_t elfstat;
	GElf_Shdr	shdr;
	SHA1_CTX	ctx;

	/* The buffer must be large enough to hold the hash */
	if (*hash_len < SHA1_DIGEST_LENGTH)
		return (ELFSIGN_FAILED);

	bzero(hash, *hash_len);

	/* Initialize the digest session */
	SHA1Init(&ctx);

	scn = elf_getscn(ess->es_elf, 0);	/* "seek" to start */
	(void) elf_errno();
	while ((scn = elf_nextscn(ess->es_elf, scn)) != 0) {
		char *name = NULL;
		Elf_Data *data = NULL;

		if (gelf_getshdr(scn, &shdr) == NULL) {
			elfstat = ELFSIGN_FAILED;
			goto done;
		}

		name = elf_strptr(ess->es_elf, ess->es_shstrndx,
		    (size_t)shdr.sh_name);
		if (name == NULL)
			name = "NULL";

		if (!hash_mem_resident &&
		    (ess->es_version == FILESIG_VERSION1 ||
		    ess->es_version == FILESIG_VERSION3)) {
			/*
			 * skip the signature section only
			 */
			if (shdr.sh_type == SHT_SUNW_SIGNATURE) {
				cryptodebug("elfsign_hash: skipping %s", name);
				continue;
			}
		} else if (!(shdr.sh_flags & SHF_ALLOC)) {
			/*
			 * select only memory resident sections
			 */
			cryptodebug("elfsign_hash: skipping %s", name);
			continue;
		}

		/*
		 * throw this section into the hash
		 *   use elf_rawdata for endian-independence
		 *   use elf_getdata to get update of .shstrtab
		 */
		while ((data = (shdr.sh_type == SHT_STRTAB ?
		    elf_getdata(scn, data) : elf_rawdata(scn, data))) != NULL) {
			if (data->d_buf == NULL) {
				cryptodebug("elfsign_hash: %s has NULL data",
				    name);
				continue;
			}
			cryptodebug("elfsign_hash: updating hash "
			    "with %s data size=%d", name, data->d_size);
			SHA1Update(&ctx, data->d_buf, data->d_size);
		}
	}
	if (elf_errmsg(0) != NULL) {
		cryptodebug("elfsign_hash: %s", elf_errmsg(-1));
		elfstat = ELFSIGN_FAILED;
		goto done;
	}

	SHA1Final(hash, &ctx);
	*hash_len = SHA1_DIGEST_LENGTH;
	{ /* DEBUG START */
		const int hashstr_len = (*hash_len) * 2 + 1;
		char *hashstr = malloc(hashstr_len);

		if (hashstr != NULL) {
			tohexstr(hash, *hash_len, hashstr, hashstr_len);
			cryptodebug("hash value is: %s", hashstr);
			free(hashstr);
		}
	} /* DEBUG END */
	elfstat = ELFSIGN_SUCCESS;
done:
	return (elfstat);
}

/*
 * elfsign_hash - return the hash of the ELF sections affecting execution.
 *
 * IN:		ess, hash_len
 * OUT:		hash, hash_len
 */
ELFsign_status_t
elfsign_hash(ELFsign_t ess, uchar_t *hash, size_t *hash_len)
{
	return (elfsign_hash_common(ess, hash, hash_len, B_FALSE));
}

/*
 * elfsign_hash_mem_resident - return the hash of the ELF sections
 * with only memory resident sections.
 *
 * IN:		ess, hash_len
 * OUT:		hash, hash_len
 */
ELFsign_status_t
elfsign_hash_mem_resident(ELFsign_t ess, uchar_t *hash, size_t *hash_len)
{
	return (elfsign_hash_common(ess, hash, hash_len, B_TRUE));
}

/*
 * elfsign_hash_esa = return the hash of the esa_buffer
 *
 * IN:          ess, esa_buf, esa_buf_len, hash_len
 * OUT:         hash, hash_len
 */
ELFsign_status_t
elfsign_hash_esa(ELFsign_t ess, uchar_t *esa_buf, size_t esa_buf_len,
    uchar_t **hash, size_t *hash_len)
{
	SHA1_CTX ctx;

	cryptodebug("esa_hash version is: %s",
	    version_to_str(ess->es_version));
	if (ess->es_version <= FILESIG_VERSION2) {
		/*
		 * old rsa_md5_sha1 format
		 * signed with MD5 digest, just pass full esa_buf
		 */
		*hash = esa_buf;
		*hash_len = esa_buf_len;
		return (ELFSIGN_SUCCESS);
	}

	if (*hash_len < SHA1_DIGEST_LENGTH)
		return (ELFSIGN_FAILED);

	bzero(*hash, *hash_len);
	SHA1Init(&ctx);
	SHA1Update(&ctx, esa_buf, esa_buf_len);
	SHA1Final(*hash, &ctx);
	*hash_len = SHA1_DIGEST_LENGTH;

	{ /* DEBUG START */
		const int hashstr_len = (*hash_len) * 2 + 1;
		char *hashstr = malloc(hashstr_len);

		if (hashstr != NULL) {
			tohexstr(*hash, *hash_len, hashstr, hashstr_len);
			cryptodebug("esa_hash value is: %s", hashstr);
			free(hashstr);
		}
	} /* DEBUG END */

	return (ELFSIGN_SUCCESS);
}

/*
 * elfsign_verify_signature - Verify the signature of the ELF object.
 *
 * IN:		ess
 * OUT:		esipp
 * RETURNS:
 *	ELFsign_status_t
 */
ELFsign_status_t
elfsign_verify_signature(ELFsign_t ess, struct ELFsign_sig_info **esipp)
{
	ELFsign_status_t	ret = ELFSIGN_FAILED;
	struct	filesignatures *fssp;
	struct	filesig *fsgp;
	size_t	fslen;
	struct filesig_extraction	fsx;
	uchar_t	hash[SIG_MAX_LENGTH];
	size_t	hash_len;
	ELFCert_t	cert = NULL;
	int	sigcnt;
	int	nocert = 0;
	struct ELFsign_sig_info	*esip = NULL;

	if (esipp != NULL) {
		esip = (struct ELFsign_sig_info *)
		    calloc(1, sizeof (struct ELFsign_sig_info));
		*esipp = esip;
	}

	/*
	 * Find out which cert we need, based on who signed the ELF object
	 */
	if (elfsign_signatures(ess, &fssp, &fslen, ES_GET) != ELFSIGN_SUCCESS) {
		return (ELFSIGN_NOTSIGNED);
	}

	if (fssp->filesig_cnt < 1) {
		ret = ELFSIGN_FAILED;
		goto cleanup;
	}

	fsgp = &fssp->filesig_sig;

	/*
	 * Scan the signature block, looking for a verifiable signature
	 */
	for (sigcnt = 0; sigcnt < fssp->filesig_cnt;
	    sigcnt++, fsgp = filesig_next(fsgp)) {
		ess->es_version = filesig_extract(fsgp, &fsx);
		cryptodebug("elfsign_verify_signature: version=%s",
		    version_to_str(ess->es_version));
		switch (ess->es_version) {
		case FILESIG_VERSION1:
		case FILESIG_VERSION2:
		case FILESIG_VERSION3:
		case FILESIG_VERSION4:
			break;
		default:
			ret = ELFSIGN_FAILED;
			goto cleanup;
		}

		cryptodebug("elfsign_verify_signature: signer_DN=\"%s\"",
		    fsx.fsx_signer_DN);
		cryptodebug("elfsign_verify_signature: algorithmOID=\"%s\"",
		    fsx.fsx_sig_oid);
		/* return signer DN if requested */
		if (esipp != NULL) {
			esip->esi_format = fsx.fsx_format;
			if (esip->esi_signer != NULL)
				free(esip->esi_signer);
			esip->esi_signer = strdup(fsx.fsx_signer_DN);
			esip->esi_time = fsx.fsx_time;
		}

		/*
		 * look for certificate
		 */
		if (cert != NULL)
			elfcertlib_releasecert(ess, cert);

		/*
		 * skip unfound certificates
		 */
		if (!elfcertlib_getcert(ess, ess->es_certpath,
		    fsx.fsx_signer_DN, &cert, ess->es_action)) {
			cryptodebug("unable to find certificate "
			    "with DN=\"%s\" for %s",
			    fsx.fsx_signer_DN, ess->es_pathname);
			nocert++;
			continue;
		}

		/*
		 * skip unverified certificates
		 *	force verification of crypto certs
		 */
		if ((ess->es_action == ES_GET_CRYPTO ||
		    strstr(fsx.fsx_signer_DN, ELFSIGN_CRYPTO)) &&
		    !elfcertlib_verifycert(ess, cert)) {
			cryptodebug("elfsign_verify_signature: invalid cert");
			nocert++;
			continue;
		}

		/*
		 * At this time the only sha1WithRSAEncryption is supported,
		 * so check that is what we have and skip with anything else.
		 */
		if (strcmp(fsx.fsx_sig_oid, OID_sha1WithRSAEncryption) != 0) {
			continue;
		}

		nocert = 0;
		/*
		 * compute file hash
		 */
		hash_len = sizeof (hash);
		if (elfsign_hash(ess, hash, &hash_len) != ELFSIGN_SUCCESS) {
			cryptodebug("elfsign_verify_signature:"
			    " elfsign_hash failed");
			ret = ELFSIGN_FAILED;
			break;
		}

		{ /* DEBUG START */
			const int sigstr_len = fsx.fsx_sig_len * 2 + 1;
			char *sigstr = malloc(sigstr_len);

			if (sigstr != NULL) {
				tohexstr(fsx.fsx_signature, fsx.fsx_sig_len,
				    sigstr, sigstr_len);
				cryptodebug("signature value is: %s", sigstr);
				free(sigstr);
			}
		} /* DEBUG END */

		if (elfcertlib_verifysig(ess, cert,
		    fsx.fsx_signature, fsx.fsx_sig_len, hash, hash_len)) {
			if (ess->es_sigvercallback)
				(ess->es_sigvercallback)
				    (ess->es_callbackctx, fssp, fslen, cert);
			/*
			 * The signature is verified!
			 * Check if this is a restricted provider
			 */
			if (strstr(fsx.fsx_signer_DN, USAGELIMITED) == NULL)
				ret = ELFSIGN_SUCCESS;
			else {
				cryptodebug("DN is tagged for usagelimited");
				ret = elfsign_verify_esa(ess,
				    fsx.fsx_signature, fsx.fsx_sig_len);
			}
			break;
		}

		cryptodebug("elfsign_verify_signature: invalid signature");
	}

cleanup:
	if (cert != NULL)
		elfcertlib_releasecert(ess, cert);

	free(fssp);
	if (ret == ELFSIGN_FAILED && nocert)
		ret = ELFSIGN_INVALID_CERTPATH;
	return (ret);
}

/*
 * Verify the contents of the .esa file, as per Jumbo export control
 * document.  Logic in this function should remain unchanged, unless
 * a misinterpretation of the jumbo case was found or if there are
 * changes in export regulations necessitating a change.
 *
 * If the .esa file exists, but is somehow corrupted, we just return
 * that this is restricted.  This is consistent with the Jumbo export
 * case covering this library and other compenents of ON.  Do not change
 * this logic without consulting export control.
 *
 * Please see do_gen_esa() for a description of the esa file format.
 *
 */
static ELFsign_status_t
elfsign_verify_esa(ELFsign_t ess, uchar_t *orig_sig, size_t orig_sig_len)
{
	ELFsign_status_t ret = ELFSIGN_RESTRICTED;
	char	*elfobj_esa = NULL;
	size_t	elfobj_esa_len;
	int	esa_fd = -1;
	size_t	esa_buf_len = 0;
	uchar_t *main_sig;
	size_t	main_sig_len = 0;
	uchar_t hash[SIG_MAX_LENGTH], *hash_ptr = hash;
	size_t  hash_len = SIG_MAX_LENGTH;
	char 	*esa_dn = NULL;
	size_t	esa_dn_len = 0;
	uchar_t	*esa_sig;
	size_t	esa_sig_len = 0;
	uchar_t *esa_file_buffer = NULL, *esa_file_ptr;
	struct stat statbuf;
	ELFCert_t cert = NULL;

	cryptodebug("elfsign_verify_esa");

	/* does the activation file exist? */
	elfobj_esa_len = strlen(ess->es_pathname) + ESA_LEN + 1;
	elfobj_esa = malloc(elfobj_esa_len);
	if (elfobj_esa == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to allocate buffer for esa filename."));
		goto cleanup;
	}

	(void) strlcpy(elfobj_esa, ess->es_pathname, elfobj_esa_len);
	(void) strlcat(elfobj_esa, ESA, elfobj_esa_len);

	if ((esa_fd = open(elfobj_esa, O_RDONLY|O_NONBLOCK)) == -1) {
		cryptodebug("No .esa file was found, or it was unreadable");
		goto cleanup;
	}

	cryptodebug("Reading contents of esa file %s", elfobj_esa);

	if (fstat(esa_fd, &statbuf) == -1) {
		cryptoerror(LOG_STDERR,
		    gettext("Can't stat %s"), elfobj_esa);
		goto cleanup;
	}

	/*
	 * mmap the buffer to save on syscalls
	 */
	esa_file_buffer = (uchar_t *)mmap(NULL, statbuf.st_size, PROT_READ,
	    MAP_PRIVATE, esa_fd, 0);

	if (esa_file_buffer == MAP_FAILED) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to mmap file to a buffer for %s."),
		    elfobj_esa);
		goto cleanup;
	}

	esa_file_ptr = esa_file_buffer;
	elfsign_buffer_len(ess, &main_sig_len, esa_file_ptr, ES_GET);
	esa_file_ptr += sizeof (uint32_t);
	cryptodebug("Contents of esa file: main_sig_len=%d", main_sig_len);
	main_sig = esa_file_ptr;

	esa_file_ptr += main_sig_len;

	/* verify .esa main signature versus original signature */
	if (main_sig_len != orig_sig_len ||
	    memcmp(main_sig, orig_sig, orig_sig_len) != 0) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to match original signature from %s."),
		    elfobj_esa);
		goto cleanup;
	}

	elfsign_buffer_len(ess, &esa_dn_len, esa_file_ptr, ES_GET);
	esa_file_ptr += sizeof (uint32_t);
	cryptodebug("Contents of esa file: esa_dn_len=%d", esa_dn_len);

	esa_dn = malloc(esa_dn_len + 1);
	if (esa_dn == NULL) {
		cryptoerror(LOG_ERR,
		    gettext("Unable to allocate memory for dn buffer."));
		goto cleanup;
	}
	(void) memcpy(esa_dn, esa_file_ptr, esa_dn_len);
	esa_dn[esa_dn_len] = '\0';
	esa_file_ptr += esa_dn_len;
	cryptodebug("Contents of esa file: esa_dn=%s", esa_dn);

	elfsign_buffer_len(ess, &esa_sig_len, esa_file_ptr, ES_GET);
	esa_file_ptr += sizeof (uint32_t);
	cryptodebug("Contents of esa file: esa_sig_len=%d", esa_sig_len);

	esa_sig = esa_file_ptr;

	cryptodebug("Read esa contents, now verifying");

	/*
	 * dn used in .esa file should not be limited.
	 */
	if (strstr(esa_dn, USAGELIMITED) != NULL) {
		cryptoerror(LOG_ERR,
		    gettext("DN for .esa file is tagged as limited for %s.\n"
		    "Activation files should only be tagged as unlimited.\n"
		    "Please contact vendor for this provider"),
		    ess->es_pathname);
		goto cleanup;
	}

	if (!elfcertlib_getcert(ess, ess->es_certpath, esa_dn, &cert,
	    ess->es_action)) {
		cryptodebug(gettext("unable to find certificate "
		    "with DN=\"%s\" for %s"),
		    esa_dn, ess->es_pathname);
		goto cleanup;
	}

	/*
	 * Since we've already matched the original signature
	 * and the main file signature, we can just verify the esa signature
	 * against the main file signature.
	 */
	esa_buf_len = sizeof (uint32_t) + main_sig_len;

	if (elfsign_hash_esa(ess, esa_file_buffer, esa_buf_len,
	    &hash_ptr, &hash_len) != ELFSIGN_SUCCESS) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to hash activation contents."));
		goto cleanup;
	}


	if (!elfcertlib_verifysig(ess, cert, esa_sig, esa_sig_len,
	    hash_ptr, hash_len)) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to verify .esa contents for %s"),
		    ess->es_pathname);
		goto cleanup;
	}

	cryptodebug("Verified esa contents");
	if (ess->es_sigvercallback)
		(ess->es_sigvercallback) (ess->es_callbackctx,
		    esa_file_buffer, statbuf.st_size, cert);

	/*
	 * validate the certificate used to sign the activation file
	 */
	if (!elfcertlib_verifycert(ess, cert)) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to verify .esa certificate %s for %s"),
		    esa_dn, ess->es_pathname);
		goto cleanup;
	}

	cryptodebug("Verified esa certificate");
	ret = ELFSIGN_SUCCESS;

cleanup:
	if (elfobj_esa != NULL)
		free(elfobj_esa);

	if (esa_fd != -1)
		(void) close(esa_fd);

	if (esa_file_buffer != NULL)
		(void) munmap((caddr_t)esa_file_buffer, statbuf.st_size);

	if (esa_dn != NULL)
		free(esa_dn);

	if (cert != NULL)
		elfcertlib_releasecert(ess, cert);

	return (ret);
}

static uint32_t
elfsign_switch_uint32(uint32_t i)
{
	return (((i & 0xff) << 24) | ((i & 0xff00) << 8) |
	    ((i >> 8) & 0xff00) | ((i >> 24) & 0xff));
}

static uint64_t
elfsign_switch_uint64(uint64_t i)
{
	return (((uint64_t)elfsign_switch_uint32(i) << 32) |
	    (elfsign_switch_uint32(i >> 32)));
}

/*
 * If appropriate, switch the endianness of the filesignatures structure
 *	Examine the structure only when it is in native endianness
 */
static ELFsign_status_t
elfsign_switch(ELFsign_t ess, struct filesignatures *fssp,
    enum ES_ACTION action)
{
	int		fscnt;
	filesig_vers_t	version;
	struct filesig	*fsgp, *fsgpnext;

	if (ess->es_same_endian)
		return (ELFSIGN_SUCCESS);

	if (ES_ACTISUPDATE(action))
		fscnt = fssp->filesig_cnt;
	fssp->filesig_cnt = elfsign_switch_uint32(fssp->filesig_cnt);
	if (!ES_ACTISUPDATE(action))
		fscnt = fssp->filesig_cnt;

	fsgp = &(fssp)->filesig_sig;
	for (; fscnt > 0; fscnt--, fsgp = fsgpnext) {
		if (ES_ACTISUPDATE(action)) {
			version = fsgp->filesig_version;
			fsgpnext = filesig_next(fsgp);
		}
		fsgp->filesig_size =
		    elfsign_switch_uint32(fsgp->filesig_size);
		fsgp->filesig_version =
		    elfsign_switch_uint32(fsgp->filesig_version);
		if (!ES_ACTISUPDATE(action)) {
			version = fsgp->filesig_version;
			fsgpnext = filesig_next(fsgp);
		}
		switch (version) {
		case FILESIG_VERSION1:
		case FILESIG_VERSION2:
			fsgp->filesig_v1_dnsize =
			    elfsign_switch_uint32(fsgp->filesig_v1_dnsize);
			fsgp->filesig_v1_sigsize =
			    elfsign_switch_uint32(fsgp->filesig_v1_sigsize);
			fsgp->filesig_v1_oidsize =
			    elfsign_switch_uint32(fsgp->filesig_v1_oidsize);
			break;
		case FILESIG_VERSION3:
		case FILESIG_VERSION4:
			fsgp->filesig_v3_time =
			    elfsign_switch_uint64(fsgp->filesig_v3_time);
			fsgp->filesig_v3_dnsize =
			    elfsign_switch_uint32(fsgp->filesig_v3_dnsize);
			fsgp->filesig_v3_sigsize =
			    elfsign_switch_uint32(fsgp->filesig_v3_sigsize);
			fsgp->filesig_v3_oidsize =
			    elfsign_switch_uint32(fsgp->filesig_v3_oidsize);
			break;
		default:
			cryptodebug("elfsign_switch: failed");
			return (ELFSIGN_FAILED);
		}
	}
	return (ELFSIGN_SUCCESS);
}

/*
 * get/put an integer value from/to a buffer, possibly of opposite endianness
 */
void
elfsign_buffer_len(ELFsign_t ess, size_t *ip, uchar_t *cp,
    enum ES_ACTION action)
{
	uint32_t tmp;

	if (!ES_ACTISUPDATE(action)) {
		/* fetch integer from buffer */
		(void) memcpy(&tmp, cp, sizeof (tmp));
		if (!ess->es_same_endian) {
			tmp = elfsign_switch_uint32(tmp);
		}
		*ip = tmp;
	} else {
		/* put integer into buffer */
		tmp = *ip;
		if (!ess->es_same_endian) {
			tmp = elfsign_switch_uint32(tmp);
		}
		(void) memcpy(cp, &tmp, sizeof (tmp));
	}
}

char const *
elfsign_strerror(ELFsign_status_t elferror)
{
	char const *msg = NULL;

	switch (elferror) {
		case ELFSIGN_SUCCESS:
			msg = gettext("sign or verify of ELF object succeeded");
			break;
		case ELFSIGN_FAILED:
			msg = gettext("sign or verify of ELF object failed");
			break;
		case ELFSIGN_NOTSIGNED:
			msg = gettext("ELF object not signed");
			break;
		case ELFSIGN_INVALID_CERTPATH:
			msg = gettext("cannot access certificate");
			break;
		case ELFSIGN_INVALID_ELFOBJ:
			msg = gettext("unable to open as an ELF object");
			break;
		case ELFSIGN_RESTRICTED:
			msg = gettext("ELF object is restricted");
			break;
		case ELFSIGN_UNKNOWN:
		default:
			msg = gettext("Unknown error");
			break;
	}

	return (msg);
}

boolean_t
elfsign_sig_info(struct filesignatures *fssp, struct ELFsign_sig_info **esipp)
{
	struct filesig_extraction	fsx;
	struct ELFsign_sig_info	*esip;

	esip = (struct ELFsign_sig_info *)
	    calloc(1, sizeof (struct ELFsign_sig_info));
	*esipp = esip;
	if (esip == NULL)
		return (B_FALSE);

	switch (filesig_extract(&fssp->filesig_sig, &fsx)) {
	case FILESIG_VERSION1:
	case FILESIG_VERSION2:
	case FILESIG_VERSION3:
	case FILESIG_VERSION4:
		esip->esi_format = fsx.fsx_format;
		esip->esi_signer = strdup(fsx.fsx_signer_DN);
		esip->esi_time = fsx.fsx_time;
		break;
	default:
		free(esip);
		*esipp = NULL;
	}

	return (*esipp != NULL);
}

void
elfsign_sig_info_free(struct ELFsign_sig_info *esip)
{
	if (esip != NULL) {
		free(esip->esi_signer);
		free(esip);
	}
}
