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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Copyright (c) 1987 by Sun Microsystems, Inc.
 */

#include <strings.h>
#include <sys/param.h>
#include <errno.h>

extern char	*getwd();

/* LINTLIBRARY */

/*
 * Input name in raw, canonicalized pathname output to canon.  If dosymlinks
 * is nonzero, resolves all symbolic links encountered during canonicalization
 * into an equivalent symlink-free form.  Returns 0 on success, -1 on failure.
 * The routine fails if the current working directory can't be obtained or if
 * either of the arguments is NULL.
 *
 * Sets errno on failure.
 */
int
pathcanon(raw, canon, dosymlinks)
    char	*raw,
		*canon;
    int		dosymlinks;
{
    register char	*s,
			*d;
    register char	*limit = canon + MAXPATHLEN;
    char		*modcanon;
    int			nlink = 0;

    /*
     * Do a bit of sanity checking.
     */
    if (raw == NULL || canon == NULL) {
	errno = EINVAL;
	return (-1);
    }

    /*
     * If the path in raw is not already absolute, convert it to that form.
     * In any case, initialize canon with the absolute form of raw.  Make
     * sure that none of the operations overflow the corresponding buffers.
     * The code below does the copy operations by hand so that it can easily
     * keep track of whether overflow is about to occur.
     */
    s = raw;
    d = canon;
    if (*s != '/') {
	/* Relative; prepend the working directory. */
	if (getwd(d) == NULL) {
	    /* Use whatever errno value getwd may have left around. */
	    return (-1);
	}
	d += strlen(d);
	/* Add slash to separate working directory from relative part. */
	if (d < limit)
	    *d++ = '/';
	modcanon = d;
    } else
	modcanon = canon;
    while (d < limit && *s)
	*d++ = *s++;

    /* Add a trailing slash to simplify the code below. */
    s = "/";
    while (d < limit && (*d++ = *s++))
	continue;
	

    /*
     * Canonicalize the path.  The strategy is to update in place, with
     * d pointing to the end of the canonicalized portion and s to the
     * current spot from which we're copying.  This works because
     * canonicalization doesn't increase path length, except as discussed
     * below.  Note also that the path has had a slash added at its end.
     * This greatly simplifies the treatment of boundary conditions.
     */
    d = s = modcanon;
    while (d < limit && *s) {
	if ((*d++ = *s++) == '/' && d > canon + 1) {
	    register char  *t = d - 2;

	    switch (*t) {
	    case '/':
		/* Found // in the name. */
		d--;
		continue;
	    case '.': 
		switch (*--t) {
		case '/':
		    /* Found /./ in the name. */
		    d -= 2;
		    continue;
		case '.': 
		    if (*--t == '/') {
			/* Found /../ in the name. */
			while (t > canon && *--t != '/')
			    continue;
			d = t + 1;
		    }
		    continue;
		default:
		    break;
		}
		break;
	    default:
		break;
	    }
	    /*
	     * We're at the end of a component.  If dosymlinks is set
	     * see whether the component is a symbolic link.  If so,
	     * replace it by its contents.
	     */
	    if (dosymlinks) {
		char		link[MAXPATHLEN + 1];
		register int	llen;

		/*
		 * See whether it's a symlink by trying to read it.
		 *
		 * Start by isolating it.
		 */
		*(d - 1) = '\0';
		if ((llen = readlink(canon, link, sizeof link)) >= 0) {
		    /* Make sure that there are no circular links. */
		    nlink++;
		    if (nlink > MAXSYMLINKS) {
			errno = ELOOP;
			return (-1);
		    }
		    /*
		     * The component is a symlink.  Since its value can be
		     * of arbitrary size, we can't continue copying in place.
		     * Instead, form the new path suffix in the link buffer
		     * and then copy it back to its proper spot in canon.
		     */
		    t = link + llen;
		    *t++ = '/';
		    /*
		     * Copy the remaining unresolved portion to the end
		     * of the symlink. If the sum of the unresolved part and
		     * the readlink exceeds MAXPATHLEN, the extra bytes
		     * will be dropped off. Too bad!
		     */
		    (void) strncpy(t, s, sizeof link - llen - 1);
		    link[sizeof link - 1] = '\0';
		    /*
		     * If the link's contents are absolute, copy it back
		     * to the start of canon, otherwise to the beginning of
		     * the link's position in the path.
		     */
		    if (link[0] == '/') {
			/* Absolute. */
			(void) strcpy(canon, link);
			d = s = canon;
		    }
		    else {
			/*
			 * Relative: find beginning of component and copy.
			 */
			--d;
			while (d > canon && *--d != '/')
			    continue;
			s = ++d;
			/*
			 * If the sum of the resolved part, the readlink
			 * and the remaining unresolved part exceeds
			 * MAXPATHLEN, the extra bytes will be dropped off.
			*/
			if (strlen(link) >= (limit - s)) {
				(void) strncpy(s, link, limit - s);
				*(limit - 1) = '\0';
			} else {
				(void) strcpy(s, link);
			}
		    }
		    continue;
		} else {
		   /*
		    * readlink call failed. It can be because it was
		    * not a link (i.e. a file, dir etc.) or because the
		    * the call actually failed.
		    */
		    if (errno != EINVAL)
			return (-1);
		    *(d - 1) = '/';	/* Restore it */
		}
	    } /* if (dosymlinks) */
	}
    } /* while */

    /* Remove the trailing slash that was added above. */
    if (*(d - 1) == '/' && d > canon + 1)
	    d--;
    *d = '\0';
    return (0);
}

/*
 * Canonicalize the path given in raw, resolving away all symbolic link
 * components.  Store the result into the buffer named by canon, which
 * must be long enough (MAXPATHLEN bytes will suffice).  Returns NULL
 * on failure and canon on success.
 *
 * The routine indirectly invokes the readlink() system call and getwd()
 * so it inherits the possibility of hanging due to inaccessible file 
 * system resources.
 */
char *
realpath(raw, canon)
    char	*raw;
    char	*canon;
{
    return (pathcanon(raw, canon, 1) < 0 ? NULL : canon);
}
