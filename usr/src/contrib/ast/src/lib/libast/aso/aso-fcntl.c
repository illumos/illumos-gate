/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped

#include "asohdr.h"

#if defined(_UWIN) && defined(_BLD_ast) || !_aso_fcntl

NoN(aso_meth_fcntl)

#else

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct APL_s
{
	int		fd;
	size_t		size;
	char		path[1];
} APL_t;

static void*
aso_init_fcntl(void* data, const char* details)
{
	APL_t*		apl = (APL_t*)data;
	char*		path;
	char*		opt;
	size_t		size;
	size_t		references;
	int		n;
	int		fd;
	int		drop;
	int		perm;
	struct flock	lock;
	char		buf[PATH_MAX];
	char		tmp[64];

	if (apl)
	{
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = apl->size;
		lock.l_len = sizeof(references);
		if (fcntl(apl->fd, F_SETLKW, &lock) >= 0)
		{
			if (lseek(apl->fd, apl->size, SEEK_SET) != apl->size)
				references = 0;
			else if (read(apl->fd, &references, sizeof(references)) != sizeof(references))
				references = 0;
			else if (references > 0)
			{
				references--;
				if (lseek(apl->fd, apl->size, SEEK_SET) != apl->size)
					references = 0;
				else if (write(apl->fd, &references, sizeof(references)) != sizeof(references))
					references = 0;
			}
			lock.l_type = F_UNLCK;
			fcntl(apl->fd, F_SETLK, &lock);
			if (!references)
				remove(apl->path);
		}
		close(apl->fd);
		free(apl);
		return 0;
	}
	fd = -1;
	perm = S_IRUSR|S_IWUSR;
	drop = 0;
	size = 32 * 1024 - sizeof(references);
	if (path = (char*)details)
		while (opt = strchr(path, ','))
		{
			if (strneq(path, "perm=", 5))
			{
				if ((n = opt - (path + 5)) >= sizeof(tmp))
					n = sizeof(tmp) - 1;
				memcpy(tmp, path + 5, n);
				tmp[n] = 0;
				perm = strperm(tmp, NiL, perm);
			}
			else if (strneq(path, "size=", 5))
			{
				size = strtoul(path + 5, NiL, 0);
				if (size <= sizeof(references))
					goto bad;
				size -= sizeof(references);
			}
			path = opt + 1;
		}
	if (!path || !*path)
	{
		if (!(path = pathtemp(buf, sizeof(buf), NiL, "aso", &fd)))
			return 0;
		drop = 1;
	}
	if (!(apl = newof(0, APL_t, 1, strlen(path))))
		goto bad;
	if (fd >= 0 || (fd = open(path, O_RDWR|O_cloexec)) < 0 && (fd = open(path, O_CREAT|O_RDWR|O_cloexec, perm)) >= 0)
	{
		if (lseek(fd, size, SEEK_SET) != size)
			goto bad;
		references = 1;
		if (write(fd, &references, sizeof(references)) != sizeof(references))
			goto bad;
	}
	else
	{
		if ((size = lseek(fd, 0, SEEK_END)) <= sizeof(references))
			goto bad;
		size -= sizeof(references);
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = 0;
		lock.l_len = sizeof(references);
		if (fcntl(fd, F_SETLKW, &lock) < 0)
			goto bad;
		if (lseek(fd, size, SEEK_SET) != size)
			goto bad;
		if (read(fd, &references, sizeof(references)) != sizeof(references))
			goto bad;
		references++;
		if (lseek(fd, size, SEEK_SET) != size)
			goto bad;
		if (write(fd, &references, sizeof(references)) != sizeof(references))
			goto bad;
		lock.l_type = F_UNLCK;
		fcntl(fd, F_SETLK, &lock);
	}
	apl->fd = fd;
	apl->size = size;
	strcpy(apl->path, path);
	return apl;
 bad:
	if (apl)
		free(apl);
	if (fd >= 0)
		close(fd);
	if (drop)
		remove(path);
	return 0;
}

static ssize_t
aso_lock_fcntl(void* data, ssize_t k, void volatile* p)
{
	APL_t*		apl = (APL_t*)data;
	struct flock	lock;

	if (!apl)
		return -1;
	if (k > 0)
		lock.l_type = F_UNLCK;
	else
	{
		lock.l_type = F_WRLCK;
		k = HASH(p, apl->size) + 1;
	}
	lock.l_whence = SEEK_SET;
	lock.l_start = k - 1;
	lock.l_len = 1;
	return fcntl(apl->fd, F_SETLKW, &lock) < 0 ? -1 : k;
}

Asometh_t	_aso_meth_fcntl = { "fcntl", ASO_PROCESS, aso_init_fcntl, aso_lock_fcntl };

#endif
