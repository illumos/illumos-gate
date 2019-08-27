/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Frame I/O utility functions
 */

#include <sys/frameio.h>

#include <sys/file.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/inttypes.h>

static kmem_cache_t *frameio_cache;

int
frameio_init(void)
{
	frameio_cache = kmem_cache_create("frameio_cache",
	    sizeof (frameio_t) + sizeof (framevec_t) * FRAMEIO_NVECS_MAX,
	    0, NULL, NULL, NULL, NULL, NULL, 0);
	if (frameio_cache == NULL)
		return (1);

	return (0);
}

void
frameio_fini(void)
{
	if (frameio_cache != NULL)
		kmem_cache_destroy(frameio_cache);
}

frameio_t *
frameio_alloc(int kmflags)
{
	return (kmem_cache_alloc(frameio_cache, kmflags));
}

void
frameio_free(frameio_t *fio)
{
	kmem_cache_free(frameio_cache, fio);
}

/*
 * Ensure that we don't see any garbage in the framevecs that we're nominally
 * supposed to work with. Specifically we want to make sure that the buflen and
 * the address are not zero.
 */
static int
frameio_hdr_check_vecs(frameio_t *fio)
{
	int i;
	for (i = 0; i < fio->fio_nvecs; i++)
		if (fio->fio_vecs[i].fv_buf == NULL ||
		    fio->fio_vecs[i].fv_buflen == 0)
			return (EINVAL);

	return (0);
}

/*
 * We have to copy in framevec32_t's. To work around the data model issues and
 * trying not to copy memory we first copy in the framevec32_t data into the
 * standard fio_vec space. Next we work backwards copying a given framevec32_t
 * to a temporaory framevec_t and then overwrite the frameio_t's data. Note that
 * it is important that we do this in reverse so as to ensure that we don't
 * clobber data as the framevec_t is larger than the framevec32_t.
 */
static int
frameio_hdr_copyin_ilp32(frameio_t *fio, const void *addr)
{
	framevec32_t *vec32p;
	framevec_t fv;
	int i;

	vec32p = (framevec32_t *)&fio->fio_vecs[0];

	if (ddi_copyin(addr, vec32p, sizeof (framevec32_t) * fio->fio_nvecs,
	    0) != 0)
		return (EFAULT);

	for (i = fio->fio_nvecs - 1; i >= 0; i--) {
		fv.fv_buf = (void *)(uintptr_t)vec32p[i].fv_buf;
		fv.fv_buflen = vec32p[i].fv_buflen;
		fv.fv_actlen = vec32p[i].fv_actlen;
		fio->fio_vecs[i].fv_buf = fv.fv_buf;
		fio->fio_vecs[i].fv_buflen = fv.fv_buflen;
		fio->fio_vecs[i].fv_actlen = fv.fv_actlen;
	}

	return (frameio_hdr_check_vecs(fio));
}

/*
 * Copy in a frame io header into fio with space for up to nvecs. If the frameio
 * contains more vectors than specified it will be ignored. mode should contain
 * information about the datamodel.
 */
int
frameio_hdr_copyin(frameio_t *fio, int max_vecs, const void *addr, uint_t mode)
{
	int model = ddi_model_convert_from(mode & FMODELS);
	int cpf = mode & FKIOCTL ? FKIOCTL : 0;
	size_t fsize = model == DDI_MODEL_ILP32 ?
	    sizeof (frameio32_t) : sizeof (frameio_t);

	/*
	 * The start of the header is the same in all data models for the
	 * current verison.
	 */
	if (ddi_copyin(addr, fio, fsize, cpf) != 0)
		return (EFAULT);

	if (fio->fio_version != FRAMEIO_VERSION_ONE)
		return (EINVAL);

	if (fio->fio_nvecs > FRAMEIO_NVECS_MAX || fio->fio_nvecs == 0)
		return (EINVAL);

	if (fio->fio_nvpf == 0)
		return (EINVAL);

	if (fio->fio_nvecs % fio->fio_nvpf != 0)
		return (EINVAL);

	if (fio->fio_nvecs > max_vecs)
		return (EOVERFLOW);

	addr = (void *)((uintptr_t)addr + fsize);
	if (model == DDI_MODEL_ILP32) {
		if (cpf != 0)
			return (EINVAL);
		return (frameio_hdr_copyin_ilp32(fio, addr));
	}

	if (ddi_copyin(addr, &fio->fio_vecs[0],
	    sizeof (framevec_t) * fio->fio_nvecs, cpf) != 0)
		return (EFAULT);

	return (frameio_hdr_check_vecs(fio));
}

static mblk_t *
frameio_allocb(size_t sz)
{
	mblk_t *mp;

	mp = allocb(sz, 0);
	if (mp == NULL)
		return (NULL);

	mp->b_datap->db_type = M_DATA;
	return (mp);
}

static int
framevec_mblk_read(framevec_t *fv, mblk_t **mpp, int cpf)
{
	mblk_t *mp;
	cpf = cpf != 0 ? FKIOCTL : 0;

	mp = frameio_allocb(fv->fv_buflen);

	if (mp == NULL) {
		freemsg(mp);
		return (EAGAIN);
	}

	if (ddi_copyin(fv->fv_buf, mp->b_wptr, fv->fv_buflen,
	    cpf) != 0) {
		freemsg(mp);
		return (EFAULT);
	}

	mp->b_wptr += fv->fv_buflen;
	*mpp = mp;
	return (0);
}

/*
 * Read a set of frame vectors that make up a single message boundary and return
 * that as a single message in *mpp that consists of multiple data parts.
 */
static int
frameio_mblk_read(frameio_t *fio, framevec_t *fv, mblk_t **mpp, int cpf)
{
	int nparts = fio->fio_nvpf;
	int part, error;
	mblk_t *mp;

	*mpp = NULL;
	cpf = cpf != 0 ? FKIOCTL : 0;

	/*
	 * Construct the initial frame
	 */
	for (part = 0; part < nparts; part++) {
		error = framevec_mblk_read(fv, &mp, cpf);
		if (error != 0) {
			freemsg(*mpp);
			return (error);
		}

		if (*mpp == NULL)
			*mpp = mp;
		else
			linkb(*mpp, mp);
		fv++;
	}

	return (0);
}

/*
 * Read data from a series of frameio vectors into a message block chain. A
 * given frameio request has a number of discrete messages divided into
 * individual vectors based on fio->fio_nvcspframe. Each discrete message will
 * be constructed into a message block chain pointed to by b_next.
 *
 * If we get an EAGAIN while trying to construct a given message block what we
 * return depends on what else we've done so far. If we have succesfully
 * completed at least one message then we free everything else we've done so
 * far and return that. If no messages have been completed we return EAGAIN. If
 * instead we encounter a different error, say EFAULT, then all of the fv_actlen
 * entries values are undefined.
 */
int
frameio_mblk_chain_read(frameio_t *fio, mblk_t **mpp, int *nvecs, int cpf)
{
	int error = ENOTSUP;
	int nframes = fio->fio_nvecs / fio->fio_nvpf;
	int frame;
	framevec_t *fv;
	mblk_t *mp, *bmp = NULL;

	/*
	 * Protect against bogus kernel subsystems.
	 */
	VERIFY(fio->fio_nvecs > 0);
	VERIFY(fio->fio_nvecs % fio->fio_nvpf == 0);

	*mpp = NULL;
	cpf = cpf != 0 ? FKIOCTL : 0;

	fv = &fio->fio_vecs[0];
	for (frame = 0; frame < nframes; frame++) {
		error = frameio_mblk_read(fio, fv, &mp, cpf);
		if (error != 0)
			goto failed;

		if (bmp != NULL)
			bmp->b_next = mp;
		else
			*mpp = mp;
		bmp = mp;
	}

	*nvecs = nframes;
	return (0);
failed:
	/*
	 * On EAGAIN we've already taken care of making sure that we have no
	 * leftover messages, eg. they were never linked in.
	 */
	if (error == EAGAIN) {
		if (frame != 0)
			error = 0;
		if (nvecs != NULL)
			*nvecs = frame;
		ASSERT(*mpp != NULL);
	} else {
		for (mp = *mpp; mp != NULL; mp = bmp) {
			bmp = mp->b_next;
			freemsg(mp);
		}
		if (nvecs != NULL)
			*nvecs = 0;
		*mpp = NULL;
	}
	return (error);
}

size_t
frameio_frame_length(frameio_t *fio, framevec_t *fv)
{
	int i;
	size_t len = 0;

	for (i = 0; i < fio->fio_nvpf; i++, fv++)
		len += fv->fv_buflen;

	return (len);
}

/*
 * Write a portion of an mblk to the current.
 */
static int
framevec_write_mblk_part(framevec_t *fv, mblk_t *mp, size_t len, size_t moff,
    size_t foff, int cpf)
{
	ASSERT(len <= MBLKL(mp) - moff);
	ASSERT(len <= fv->fv_buflen - fv->fv_actlen);
	cpf = cpf != 0 ? FKIOCTL : 0;

	if (ddi_copyout(mp->b_rptr + moff, (caddr_t)fv->fv_buf + foff, len,
	    cpf) != 0)
		return (EFAULT);
	fv->fv_actlen += len;

	return (0);
}

/*
 * Because copying this out to the user might fail we don't want to update the
 * b_rptr in case we need to copy it out again.
 */
static int
framevec_map_blk(frameio_t *fio, framevec_t *fv, mblk_t *mp, int cpf)
{
	int err;
	size_t msize, blksize, len, moff, foff;

	msize = msgsize(mp);
	if (msize > frameio_frame_length(fio, fv))
		return (EOVERFLOW);

	moff = 0;
	foff = 0;
	blksize = MBLKL(mp);
	fv->fv_actlen = 0;
	while (msize != 0) {
		len = MIN(blksize, fv->fv_buflen - fv->fv_actlen);
		err = framevec_write_mblk_part(fv, mp, len, moff, foff, cpf);
		if (err != 0)
			return (err);

		msize -= len;
		blksize -= len;
		moff += len;
		foff += len;

		if (blksize == 0 && msize != 0) {
			mp = mp->b_cont;
			ASSERT(mp != NULL);
			moff = 0;
			blksize = MBLKL(mp);
		}

		if (fv->fv_buflen == fv->fv_actlen && msize != 0) {
			fv++;
			fv->fv_actlen = 0;
			foff = 0;
		}
	}

	return (0);
}

int
frameio_mblk_chain_write(frameio_t *fio, frameio_write_mblk_map_t map,
    mblk_t *mp, int *nwrite, int cpf)
{
	int mcount = 0;
	int ret = 0;

	if (map != MAP_BLK_FRAME)
		return (EINVAL);

	while (mp != NULL && mcount < fio->fio_nvecs) {
		ret = framevec_map_blk(fio, &fio->fio_vecs[mcount], mp, cpf);
		if (ret != 0)
			break;
		mcount += fio->fio_nvpf;
		mp = mp->b_next;
	}

	if (ret != 0 && mcount == 0) {
		if (nwrite != NULL)
			*nwrite = 0;
		return (ret);
	}

	if (nwrite != NULL)
		*nwrite = mcount / fio->fio_nvpf;

	return (0);
}

/*
 * Copy out nframes worth of frameio header data back to userland.
 */
int
frameio_hdr_copyout(frameio_t *fio, int nframes, void *addr, uint_t mode)
{
	int i;
	int model = ddi_model_convert_from(mode & FMODELS);
	framevec32_t *vec32p;
	framevec32_t f;

	if (fio->fio_nvecs / fio->fio_nvpf < nframes)
		return (EINVAL);

	fio->fio_nvecs = nframes * fio->fio_nvpf;

	if (model == DDI_MODEL_NONE) {
		if (ddi_copyout(fio, addr,
		    sizeof (frameio_t) + fio->fio_nvecs * sizeof (framevec_t),
		    mode & FKIOCTL) != 0)
			return (EFAULT);
		return (0);
	}

	ASSERT(model == DDI_MODEL_ILP32);

	vec32p = (framevec32_t *)&fio->fio_vecs[0];
	for (i = 0; i < fio->fio_nvecs; i++) {
		f.fv_buf = (caddr32_t)(uintptr_t)fio->fio_vecs[i].fv_buf;
		if (fio->fio_vecs[i].fv_buflen > UINT_MAX ||
		    fio->fio_vecs[i].fv_actlen > UINT_MAX)
			return (EOVERFLOW);
		f.fv_buflen = fio->fio_vecs[i].fv_buflen;
		f.fv_actlen = fio->fio_vecs[i].fv_actlen;
		vec32p[i].fv_buf = f.fv_buf;
		vec32p[i].fv_buflen = f.fv_buflen;
		vec32p[i].fv_actlen = f.fv_actlen;
	}

	if (ddi_copyout(fio, addr,
	    sizeof (frameio32_t) + fio->fio_nvecs * sizeof (framevec32_t),
	    mode & FKIOCTL) != 0)
		return (EFAULT);
	return (0);
}

void
frameio_mark_consumed(frameio_t *fio, int nframes)
{
	int i;

	ASSERT(fio->fio_nvecs / fio->fio_nvpf >= nframes);
	for (i = 0; i < nframes * fio->fio_nvpf; i++)
		fio->fio_vecs[i].fv_actlen = fio->fio_vecs[i].fv_buflen;
}
