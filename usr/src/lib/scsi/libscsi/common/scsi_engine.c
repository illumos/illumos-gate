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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/isa_defs.h>
#include <sys/systeminfo.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>
#include <sys/scsi/impl/uscsi.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>

#include <scsi/libscsi.h>
#include "libscsi_impl.h"

static const libscsi_engine_t *
get_engine(libscsi_hdl_t *hp, const char *name)
{
	libscsi_engine_impl_t *eip;
	const libscsi_engine_t *ep;
	const char *engine_path, *p, *q;
	char engine_dir[MAXPATHLEN];
	char engine_lib[MAXPATHLEN];
	char init_name[MAXPATHLEN];
	void *dl_hdl;
	libscsi_engine_init_f init;
	boolean_t found_lib = B_FALSE, found_init = B_FALSE;
	int dirs_tried = 0;
	char isa[257];

	for (eip = hp->lsh_engines; eip != NULL; eip = eip->lsei_next) {
		if (strcmp(eip->lsei_engine->lse_name, name) == 0)
			return (eip->lsei_engine);
	}

	if ((engine_path = getenv("LIBSCSI_ENGINE_PATH")) == NULL)
		engine_path = LIBSCSI_DEFAULT_ENGINE_PATH;

#if defined(_LP64)
	if (sysinfo(SI_ARCHITECTURE_64, isa, sizeof (isa)) < 0)
		isa[0] = '\0';
#else
	isa[0] = '\0';
#endif

	for (p = engine_path; p != NULL; p = q) {
		if ((q = strchr(p, ':')) != NULL) {
			ptrdiff_t len = q - p;
			(void) strncpy(engine_dir, p, len);
			engine_dir[len] = '\0';
			while (*q == ':')
				++q;
			if (*q == '\0')
				q = NULL;
			if (len == 0)
				continue;
		} else {
			(void) strcpy(engine_dir, p);
		}
		if (engine_dir[0] != '/')
			continue;

		++dirs_tried;

		(void) snprintf(engine_lib, MAXPATHLEN, "%s/%s/%s%s",
		    engine_dir, isa, name, LIBSCSI_ENGINE_EXT);

		dl_hdl = dlopen(engine_lib,
		    RTLD_LOCAL | RTLD_LAZY | RTLD_PARENT);
		if (dl_hdl == NULL) {
			if (!found_lib)
				(void) libscsi_error(hp, ESCSI_NOENGINE,
				    "unable to dlopen %s: %s", engine_lib,
				    dlerror());
			continue;
		}
		found_lib = B_TRUE;
		(void) snprintf(init_name, MAXPATHLEN, "libscsi_%s_init", name);
		init = (libscsi_engine_init_f)dlsym(dl_hdl, init_name);
		if (init == NULL) {
			if (!found_init)
				(void) libscsi_error(hp, ESCSI_NOENGINE,
				    "failed to find %s in %s: %s", init_name,
				    engine_lib, dlerror());
			(void) dlclose(dl_hdl);
			continue;
		}
		if ((ep = init(hp)) == NULL) {
			(void) dlclose(dl_hdl);
			/*
			 * libscsi errno set by init.
			 */
			return (NULL);
		}
		if (ep->lse_libversion != hp->lsh_version) {
			(void) dlclose(dl_hdl);
			(void) libscsi_error(hp, ESCSI_ENGINE_VER, "engine "
			    "%s version %u does not match library version %u",
			    engine_lib, ep->lse_libversion, hp->lsh_version);
			return (NULL);
		}

		eip = libscsi_zalloc(hp, sizeof (libscsi_engine_impl_t));
		if (eip == NULL) {
			(void) dlclose(dl_hdl);
			return (NULL);
		}
		eip->lsei_engine = ep;
		eip->lsei_dl_hdl = dl_hdl;
		eip->lsei_next = hp->lsh_engines;
		hp->lsh_engines = eip;

		return (ep);
	}

	if (dirs_tried == 0)
		(void) libscsi_error(hp, ESCSI_ENGINE_BADPATH, "no valid "
		    "directories found in engine path %s", engine_path);

	return (NULL);
}

static void
scsi_parse_mtbf(const char *envvar, uint_t *intp)
{
	const char *strval;
	int intval;

	if ((strval = getenv(envvar)) != NULL &&
	    (intval = atoi(strval)) > 0) {
		srand48(gethrtime());
		*intp = intval;
	}
}

libscsi_target_t *
libscsi_open(libscsi_hdl_t *hp, const char *engine, const void *target)
{
	const libscsi_engine_t *ep;
	libscsi_target_t *tp;
	void *private;

	if (engine == NULL) {
		if ((engine = getenv("LIBSCSI_DEFAULT_ENGINE")) == NULL)
			engine = LIBSCSI_DEFAULT_ENGINE;
	}

	if ((ep = get_engine(hp, engine)) == NULL)
		return (NULL);

	if ((tp = libscsi_zalloc(hp, sizeof (libscsi_target_t))) == NULL)
		return (NULL);

	if ((private = ep->lse_ops->lseo_open(hp, target)) == NULL) {
		libscsi_free(hp, tp);
		return (NULL);
	}

	scsi_parse_mtbf("LIBSCSI_MTBF_CDB", &tp->lst_mtbf_cdb);
	scsi_parse_mtbf("LIBSCSI_MTBF_READ", &tp->lst_mtbf_read);
	scsi_parse_mtbf("LIBSCSI_MTBF_WRITE", &tp->lst_mtbf_write);

	tp->lst_hdl = hp;
	tp->lst_engine = ep;
	tp->lst_priv = private;

	++hp->lsh_targets;

	if (libscsi_get_inquiry(hp, tp) != 0) {
		libscsi_close(hp, tp);
		return (NULL);
	}

	return (tp);
}

libscsi_hdl_t *
libscsi_get_handle(libscsi_target_t *tp)
{
	return (tp->lst_hdl);
}

void
libscsi_close(libscsi_hdl_t *hp, libscsi_target_t *tp)
{
	tp->lst_engine->lse_ops->lseo_close(hp, tp->lst_priv);
	libscsi_free(hp, tp->lst_vendor);
	libscsi_free(hp, tp->lst_product);
	libscsi_free(hp, tp->lst_revision);
	libscsi_free(hp, tp);
	--hp->lsh_targets;
}

sam4_status_t
libscsi_action_get_status(const libscsi_action_t *ap)
{
	const libscsi_action_impl_t *aip = (const libscsi_action_impl_t *)ap;

	return (aip->lsai_status);
}

/*
 * Set the timeout in seconds for this action.  If no timeout is specified
 * or if the timeout is set to 0, an implementation-specific timeout will be
 * used (which may vary based on the target, command or other variables).
 * Not all engines support all timeout values.  Setting the timeout to a value
 * not supported by the engine will cause engine-defined behavior when the
 * action is executed.
 */
void
libscsi_action_set_timeout(libscsi_action_t *ap, uint32_t timeout)
{
	libscsi_action_impl_t *aip = (libscsi_action_impl_t *)ap;

	aip->lsai_timeout = timeout;
}

/*
 * Obtain the timeout setting for this action.
 */
uint32_t
libscsi_action_get_timeout(const libscsi_action_t *ap)
{
	const libscsi_action_impl_t *aip = (const libscsi_action_impl_t *)ap;

	return (aip->lsai_timeout);
}

/*
 * Returns the flags associated with this action.  Never fails.
 */
uint_t
libscsi_action_get_flags(const libscsi_action_t *ap)
{
	const libscsi_action_impl_t *aip = (const libscsi_action_impl_t *)ap;

	return (aip->lsai_flags);
}

/*
 * Returns the address of the action's CDB.  The CDB buffer is guaranteed to
 * be large enough to hold the complete CDB for the command specified when the
 * action was allocated.  Therefore, changing the command/opcode portion of
 * the CDB has undefined effects.  The remainder of the CDB may be modified.
 */
uint8_t *
libscsi_action_get_cdb(const libscsi_action_t *ap)
{
	const libscsi_action_impl_t *aip = (const libscsi_action_impl_t *)ap;

	return (aip->lsai_cdb);
}

/*
 * Places the address of the action buffer in the location pointed to by bp,
 * if bp is not NULL.  If ap is not NULL, it will contain the allocated size
 * of the buffer itself.  If vp is not NULL, it will contain the number of
 * bytes of valid data currently stored in the buffer.
 *
 * If the action has LIBSCSI_AF_WRITE set and it has not yet been executed
 * successfully, the entire buffer is assumed to contain valid data.
 *
 * If the action has LIBSCSI_AF_READ set and it has not yet been executed
 * successfully, the amount of valid data is 0.
 *
 * If both LIBSCSI_AF_READ and LIBSCSI_AF_WRITE are clear, this function
 * fails with ESCSI_BADFLAGS to indicate that the action flags are
 * incompatible with the action data buffer.
 */
int
libscsi_action_get_buffer(const libscsi_action_t *ap, uint8_t **bp,
    size_t *sp, size_t *vp)
{
	const libscsi_action_impl_t *aip = (const libscsi_action_impl_t *)ap;

	if ((aip->lsai_flags & (LIBSCSI_AF_READ | LIBSCSI_AF_WRITE)) == 0)
		return (libscsi_error(aip->lsai_hdl, ESCSI_BADFLAGS,
		    "data buffer not supported for actions with both "
		    "LIBSCSI_AF_READ and LIBSCSI_AF_WRITE clear"));

	if ((aip->lsai_flags & LIBSCSI_AF_WRITE) &&
	    aip->lsai_status == LIBSCSI_STATUS_INVALID) {
		if (bp != NULL)
			*bp = aip->lsai_data;
		if (sp != NULL)
			*sp = aip->lsai_data_alloc;
		if (vp != NULL)
			*vp = aip->lsai_data_alloc;

		return (0);
	}

	if ((aip->lsai_flags & LIBSCSI_AF_READ) &&
	    aip->lsai_status != LIBSCSI_STATUS_INVALID) {
		if (bp != NULL)
			*bp = aip->lsai_data;
		if (sp != NULL)
			*sp = aip->lsai_data_alloc;
		if (vp != NULL)
			*vp = aip->lsai_data_len;

		return (0);
	}

	if (aip->lsai_flags & LIBSCSI_AF_WRITE) {
		if (bp != NULL)
			*bp = NULL;
		if (sp != NULL)
			*sp = NULL;
		if (vp != NULL)
			*vp = 0;
	} else {
		if (bp != NULL)
			*bp = aip->lsai_data;
		if (sp != NULL)
			*sp = aip->lsai_data_alloc;
		if (vp != NULL)
			*vp = 0;
	}

	return (0);
}

/*
 * Obtain a pointer to the sense buffer for this action, if any, along with
 * the size of the sense buffer and the amount of valid data it contains.
 */
int
libscsi_action_get_sense(const libscsi_action_t *ap, uint8_t **bp,
    size_t *sp, size_t *vp)
{
	const libscsi_action_impl_t *aip = (const libscsi_action_impl_t *)ap;

	if (!(aip->lsai_flags & LIBSCSI_AF_RQSENSE))
		return (libscsi_error(aip->lsai_hdl, ESCSI_BADFLAGS,
		    "sense data unavailable: LIBSCSI_AF_RQSENSE is clear"));

	if (vp != NULL) {
		if (aip->lsai_status == LIBSCSI_STATUS_INVALID)
			*vp = 0;
		else
			*vp = aip->lsai_sense_len;
	}

	if (bp != NULL) {
		ASSERT(aip->lsai_sense_data != NULL);
		*bp = aip->lsai_sense_data;
	}

	if (sp != NULL)
		*sp = UINT8_MAX;

	return (0);
}

/*
 * Set the SCSI status of the action.
 *
 * Engines only.
 */
void
libscsi_action_set_status(libscsi_action_t *ap, sam4_status_t status)
{
	libscsi_action_impl_t *aip = (libscsi_action_impl_t *)ap;

	ASSERT(aip->lsai_status == LIBSCSI_STATUS_INVALID);

	aip->lsai_status = status;
}

/*
 * Set the length of valid data returned by a READ action.  If the action is
 * not a READ action, or the length exceeds the size of the buffer, an error
 * results.
 *
 * Engines only.
 */
int
libscsi_action_set_datalen(libscsi_action_t *ap, size_t len)
{
	libscsi_action_impl_t *aip = (libscsi_action_impl_t *)ap;

	if ((aip->lsai_flags & LIBSCSI_AF_READ) == 0)
		return (libscsi_error(aip->lsai_hdl, ESCSI_BADFLAGS,
		    "data cannot be returned for actions with LIBSCSI_AF_READ "
		    "clear"));
	if (len > aip->lsai_data_alloc)
		return (libscsi_error(aip->lsai_hdl, ESCSI_BADLENGTH,
		    "data length %lu exceeds allocated buffer capacity %lu",
		    (ulong_t)len, (ulong_t)aip->lsai_data_alloc));

	ASSERT(aip->lsai_data_len == 0);
	aip->lsai_data_len = len;

	return (0);
}

/*
 * Set the length of the valid sense data returned following the command, if
 * LIBSCSI_AF_RQSENSE is set for this action.  Otherwise, fail.
 *
 * Engines only.
 */
int
libscsi_action_set_senselen(libscsi_action_t *ap, size_t len)
{
	libscsi_action_impl_t *aip = (libscsi_action_impl_t *)ap;

	if (!(aip->lsai_flags & LIBSCSI_AF_RQSENSE))
		return (libscsi_error(aip->lsai_hdl, ESCSI_BADFLAGS,
		    "sense data not supported: LIBSCSI_AF_RQSENSE is clear"));

	if (len > UINT8_MAX)
		return (libscsi_error(aip->lsai_hdl, ESCSI_BADLENGTH,
		    "sense length %lu exceeds allocated buffer capacity %lu",
		    (ulong_t)len, (ulong_t)UINT8_MAX));

	ASSERT(aip->lsai_sense_len == 0);
	aip->lsai_sense_len = len;

	return (0);
}

/*
 * Allocate an action object.  The object will contain a CDB area sufficiently
 * large to hold a CDB for the given command, and the CDB's opcode will be
 * filled in.  A pointer to this CDB, the contents of which may be modified by
 * the caller, may be obtained by a subsequent call to libscsi_action_cdb().
 *
 * If flags includes LIBSCSI_AF_READ or LIBSCSI_AF_WRITE, buflen must be
 * greater than zero.  Otherwise, buflen must be 0 and buf must be NULL.
 * If buflen is nonzero but buf is NULL, a suitably-sized buffer will be
 * allocated; otherwise, the specified buffer will be used.  In either case,
 * a pointer to the buffer may be obtained via a subsequent call to
 * libscsi_action_buffer().
 *
 * If flags includes LIBSCSI_AF_RQSENSE, a REQUEST SENSE command will be
 * issued immediately following the termination of the specified command.
 * A buffer will be allocated to receive this sense data.  Following successful
 * execution of the action, a pointer to this buffer and the length of
 * valid sense data may be obtained by a call to libscsi_action_sense().
 * If cmd is SPC3_CMD_REQUEST_SENSE, this flag must be clear.
 */
libscsi_action_t *
libscsi_action_alloc(libscsi_hdl_t *hp, spc3_cmd_t cmd, uint_t flags,
    void *buf, size_t buflen)
{
	libscsi_action_impl_t *aip;
	size_t cdbsz, sz;
	ptrdiff_t off;

	/*
	 * If there's no buffer, it makes no sense to try to read or write
	 * data.  Likewise, if we're neither reading nor writing data, we
	 * should not have a buffer.  Both of these are programmer error.
	 */
	if (buflen == 0 && (flags & (LIBSCSI_AF_READ | LIBSCSI_AF_WRITE))) {
		(void) libscsi_error(hp, ESCSI_NEEDBUF, "a buffer is "
		    "required when reading or writing");
		return (NULL);
	}
	if (buflen > 0 && !(flags & (LIBSCSI_AF_READ | LIBSCSI_AF_WRITE))) {
		(void) libscsi_error(hp, ESCSI_BADFLAGS, "one of "
		    "LIBSCSI_AF_READ and LIBSCSI_AF_WRITE must be specified "
		    "in order to use a buffer");
		return (NULL);
	}
	if (cmd == SPC3_CMD_REQUEST_SENSE && (flags & LIBSCSI_AF_RQSENSE)) {
		(void) libscsi_error(hp, ESCSI_BADFLAGS, "request sense "
		    "flag not allowed for request sense command");
		return (NULL);
	}

	if ((sz = cdbsz = libscsi_cmd_cdblen(hp, cmd)) == 0)
		return (NULL);

	/*
	 * If the caller has asked for a buffer but has not provided one, we
	 * will allocate it in our internal buffer along with the CDB and
	 * request sense space (if requested).
	 */
	if (buf == NULL)
		sz += buflen;

	if (flags & LIBSCSI_AF_RQSENSE)
		sz += UINT8_MAX;

	sz += offsetof(libscsi_action_impl_t, lsai_buf[0]);

	if ((aip = libscsi_zalloc(hp, sz)) == NULL)
		return (NULL);

	aip->lsai_hdl = hp;
	aip->lsai_flags = flags;

	off = 0;

	aip->lsai_cdb = aip->lsai_buf + off;
	aip->lsai_cdb_len = cdbsz;
	off += cdbsz;
	aip->lsai_cdb[0] = (uint8_t)cmd;

	if (buflen > 0) {
		if (buf != NULL) {
			aip->lsai_data = buf;
		} else {
			aip->lsai_data = aip->lsai_buf + off;
			off += buflen;
		}
		aip->lsai_data_alloc = buflen;
		if (flags & LIBSCSI_AF_WRITE)
			aip->lsai_data_len = buflen;
	}

	if (flags & LIBSCSI_AF_RQSENSE) {
		aip->lsai_sense_data = aip->lsai_buf + off;
		off += UINT8_MAX;
	}

	aip->lsai_status = LIBSCSI_STATUS_INVALID;

	return ((libscsi_action_t *)aip);
}

void
libscsi_action_free(libscsi_action_t *ap)
{
	libscsi_action_impl_t *aip = (libscsi_action_impl_t *)ap;

	libscsi_free(aip->lsai_hdl, aip);
}

/*
 * For testing purposes, we allow data to be corrupted via an environment
 * variable setting.  This helps ensure that higher level software can cope with
 * arbitrarily broken targets.  The mtbf value represents the number of bytes we
 * will see, on average, in between each failure.  Therefore, for each N bytes,
 * we would expect to see (N / mtbf) bytes of corruption.
 */
static void
scsi_inject_errors(void *data, size_t len, uint_t mtbf)
{
	char *buf = data;
	double prob;
	size_t index;

	if (len == 0)
		return;

	prob = (double)len / mtbf;

	while (prob > 1) {
		index = lrand48() % len;
		buf[index] = (lrand48() % 256);
		prob -= 1;
	}

	if (drand48() <= prob) {
		index = lrand48() % len;
		buf[index] = (lrand48() % 256);
	}
}

int
libscsi_exec(libscsi_action_t *ap, libscsi_target_t *tp)
{
	libscsi_action_impl_t *aip = (libscsi_action_impl_t *)ap;
	libscsi_hdl_t *hp = aip->lsai_hdl;
	int ret;

	if (tp->lst_mtbf_write != 0 &&
	    (aip->lsai_flags & LIBSCSI_AF_WRITE)) {
		scsi_inject_errors(aip->lsai_data, aip->lsai_data_len,
		    tp->lst_mtbf_write);
	}

	if (tp->lst_mtbf_cdb != 0) {
		scsi_inject_errors(aip->lsai_cdb, aip->lsai_cdb_len,
		    tp->lst_mtbf_cdb);
	}

	ret = tp->lst_engine->lse_ops->lseo_exec(hp, tp->lst_priv, ap);

	if (ret == 0 && tp->lst_mtbf_read != 0 &&
	    (aip->lsai_flags & LIBSCSI_AF_READ)) {
		scsi_inject_errors(aip->lsai_data, aip->lsai_data_len,
		    tp->lst_mtbf_read);
	}

	return (ret);
}

int
libscsi_max_transfer(libscsi_target_t *tp, size_t *sizep)
{
	libscsi_hdl_t *hp = tp->lst_hdl;
	if (tp->lst_engine->lse_ops->lseo_max_transfer == NULL) {
		return (libscsi_error(hp, ESCSI_NOTSUP, "max transfer "
		    "request not supported by engine"));
	}

	return (tp->lst_engine->lse_ops->lseo_max_transfer(hp, tp->lst_priv,
	    sizep));
}
