/*
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <a.out.h>

#define BSIZ 8*1024	/* size of local buffers */

/*
 * _nlist - retreive attributes from name list (string table version)
 *
 * Note: This is a modified form of the original nlist() function.
 *       It takes a file descriptor instead of a filename argument
 *       and is intended to be called by nlist(3) and kvmnlist(3K).
 *       The algorithm has been modified from the original to use local
 *       (rather than stdio) buffering and issues considerably fewer lseeks.
 */
int
_nlist(int fd, struct nlist *list)
{
	struct nlist *p, *q;
	char *s1, *s2;
	int soff;
	int stroff = 0;
	int n, m;
	int maxlen, nreq;
	long sa;		/* symbol address */
	long ss;		/* start of strings */
	struct exec buf;
	struct nlist space[BSIZ/sizeof (struct nlist)];
	char strs[BSIZ];

	maxlen = 0;
	for (q = list, nreq = 0; q->n_un.n_name && q->n_un.n_name[0];
	    q++, nreq++) {
		q->n_type = 0;
		q->n_value = 0;
		q->n_desc = 0;
		q->n_other = 0;
		n = strlen(q->n_un.n_name);
		if (n > maxlen)
			maxlen = n;
	}
	if ((fd == -1) || (lseek(fd, 0L, 0) == -1) ||
	    (read(fd, (char*)&buf, sizeof buf) != sizeof buf) || N_BADMAG(buf))
		return (-1);
	sa = N_SYMOFF(buf);
	ss = sa + buf.a_syms;
	n = buf.a_syms;
	while (n) {
		m = MIN(n, sizeof (space));
		lseek(fd, sa, 0);
		if (read(fd, (char *)space, m) != m)
			break;
		sa += m;
		n -= m;
		for (q = space; (m -= sizeof (struct nlist)) >= 0; q++) {
			soff = q->n_un.n_strx;
			if (soff == 0 || q->n_type & N_STAB)
				continue;
			if ((soff + maxlen + 1) >= stroff) {
				/*
				 * Read strings into local cache.
				 * Assumes (maxlen < sizeof (strs)).
				 */
				lseek(fd, ss+soff, 0);
				read(fd, strs, sizeof strs);
				stroff = soff + sizeof (strs);
			}
			for (p = list;
			     p->n_un.n_name && p->n_un.n_name[0];
			     p++) {
				if (p->n_type != 0)
					continue;
				s1 = p->n_un.n_name;
				s2 = &strs[soff-(stroff-sizeof (strs))];
				while (*s1) {
					if (*s1++ != *s2++)
						goto cont;
				}
				if (*s2)
					goto cont;
				p->n_value = q->n_value;
				p->n_type = q->n_type;
				p->n_desc = q->n_desc;
				p->n_other = q->n_other;
				if (--nreq == 0)
					goto alldone;
				break;
cont:				;
			}
		}
	}
alldone:
	return (nreq);
}
