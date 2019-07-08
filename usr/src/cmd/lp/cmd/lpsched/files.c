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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "lpsched.h"
#include <syslog.h>
#include <strings.h>

static char time_buf[50];
#ifdef LP_USE_PAPI_ATTR
static char *extractReqno(char *req_file);
#endif

/**
 ** chfiles() - CHANGE OWNERSHIP OF FILES, RETURN TOTAL SIZE
 **/

off_t chfiles ( char * * list, uid_t uid, gid_t gid )	/* funcdef */
{
    size_t	total;
    struct stat	stbuf;
    char	*file;
    
    total = 0;

    while(file = *list++)
    {
	if (STRNEQU(Lp_Temp, file, strlen(Lp_Temp)) ||
	    STRNEQU(Lp_Tmp, file, strlen(Lp_Tmp)))
	{
	    /*
	     * Once this routine (chfiles) is called for a request,
	     * any temporary files are ``ours'', i.e. they are on our
	     * machine. A user running on an RFS-connected remote machine
	     * can't necessarily know our machine name, so can't put
	     * the files where they belong (Lp_Tmp/machine). But now we
	     * can. Of course, this is all done with mirrors, as Lp_Temp
	     * and Lp_Tmp/local-machine are symbolicly linked. So we just
	     * change the name. This saves on wear and tear later.
	     */
	    if (STRNEQU(Lp_Temp, file, strlen(Lp_Temp)))
	    {
		char *newfile = makepath(Lp_Tmp, Local_System,
				file + strlen(Lp_Temp) + 1, NULL);

		Free(file);
		list[-1] = file = newfile;
	    }
	    
	    (void) chownmod(file, uid, gid, 0600);
	}

	if (Stat(file, &stbuf) == -1)
	    return(-1);

	switch (stbuf.st_mode & S_IFMT) {
	case 0:
	case S_IFREG:
	    break;

	case S_IFIFO:
	    if (!isadmin(uid))
		return(-1);
	    /*
	     * If any of the files is a FIFO, the size indicator
	     * becomes meaningless. On the other hand, returning
	     * a total of zero causes the request to be rejected,
	     * so we return something > 0.
	     */
	    stbuf.st_size = 1;
	    break;

	case S_IFDIR:
	case S_IFCHR:
	case S_IFBLK:
	default:
	    return(-1);
	}

	total += stbuf.st_size;
    }
    return(total);
}

/**
 ** rmfiles() - DELETE/LOG FILES FOR DEFUNCT REQUEST
 **/

void rmfiles ( RSTATUS * rp, int log_it )	/* funcdef */
{
    char	**file	= rp->request->file_list;
    char	*path;
    char	num[STRSIZE(MOST_FILES) + 1];
    static int	fd	= -1;
    int		reqfd;
    int		count	= 0;
#ifdef LP_USE_PAPI_ATTR
    struct stat	tmpBuf;
    char	*idno = NULL;
    char 	tmpName[BUFSIZ];
#endif


    if (rp->req_file) {
	    char *p, *q;

	   /*
	    * The secure request file is removed first to prevent
	    * reloading should the system crash while in rmfiles().
	    */
	    path = makepath(Lp_Requests, rp->req_file, (char *)0);
	    (void) Unlink(path);
	    Free(path);

	    /*
	     * Copy the request file to the log file, if asked,
	     * or simply remove it.
	     */
	    path = makepath(Lp_Tmp, rp->req_file, (char *)0);
	    if (log_it && rp->secure && rp->secure->req_id) {
		if (fd == -1)
		    fd = open_locked(Lp_ReqLog, "a", MODE_NOREAD);
		if ((fd  >= 0) && (reqfd = Open(path, O_RDONLY, 0)) != -1) {
		    register int	n;
		    char		buf[BUFSIZ];

		    (void) strftime(time_buf, sizeof (time_buf),
			NULL, localtime(&(rp->secure->date)));
		    fdprintf(fd, "= %s, uid %u, gid %u, size %ld, %s\n",
			rp->secure->req_id, rp->secure->uid, rp->secure->gid,
			rp->secure->size, time_buf);
		    if (rp->slow)
			fdprintf(fd, "x %s\n", rp->slow);
		    if (rp->fast)
			fdprintf(fd, "y %s\n", rp->fast);
		    if (rp->printer && rp->printer->printer)
			fdprintf(fd, "z %s\n", rp->printer->printer->name);
		    while ((n = Read(reqfd, buf, BUFSIZ)) > 0)
			write (fd, buf, n);
		    Close (reqfd);
		}
	    }
	    (void)Unlink (path);		/* remove request file */
	    Free (path);

	    p = strdup(rp->req_file);		/* remove host/id file */
	    if (q = strrchr(p, '-')) {
		    *q = '\0';
		    path = makepath(Lp_Tmp, p, NULL);
		    (void) Unlink(path);
		    Free(path);
	    }
	    Free(p);

#ifdef LP_USE_PAPI_ATTR
	/* Look for a PAPI job attribute file, if it exists remove it */
	idno = extractReqno(rp->req_file);
	snprintf(tmpName, sizeof (tmpName), "%s-%s", idno, LP_PAPIATTRNAME);
	path = makepath(Lp_Temp, tmpName, (char *)0);

	if (((path != NULL) && (idno != NULL)) && (stat(path, &tmpBuf) == 0))
	{
	    /* PAPI job attribute file exists for this job so remove it */
	    (void) Unlink(path);
	}

	Free(idno);
	Free(path);
#endif
    }

    if (file)					/* remove file in filelist */
	while(*file)
	{
		/*
		 * The copies of user files.
		 */
		if ((STRNEQU(Lp_Temp, *file, strlen(Lp_Temp)) ||
		    STRNEQU(Lp_Tmp, *file, strlen(Lp_Tmp))) &&
		    (! strstr(*file, "../")))

		    (void) Unlink(*file);

		count++;
		file++;
	}

    if (rp->secure && rp->secure->req_id) {
	char *p;
	p = getreqno(rp->secure->req_id);

	/*
	 * The filtered files. We can't rely on just the RS_FILTERED
	 * flag, since the request may have been cancelled while
	 * filtering. On the other hand, just checking "rp->slow"
	 * doesn't mean that the files exist, because the request
	 * may have been canceled BEFORE filtering started. Oh well.
	 */
	if (rp->slow)
	    while(count > 0)
	    {
		sprintf(num, "%d", count--);
		path = makestr(Lp_Temp, "/F", p, "-", num, (char *)0);
		Unlink(path);
		Free(path);
	    }

	/*
	 * The notify/error file.
	 */
	path = makepath(Lp_Temp, p, (char *)0);
	(void) Unlink(path);
	Free(path);
    }
}

/**
 ** _alloc_req_id(void) - ALLOCATE NEXT REQUEST ID
 **/

#define	SEQF_DEF_START	1
#define	SEQF_DEF_END	59999
#define	SEQF_DEF_INCR	1
#define	SEQF		".SEQF"


long
_alloc_req_id ( void )
{
	static short		started	= 0;

	static int		fd;

	static long		start;
	static long		end;
	static long		incr;
	static long		curr;
	static long		wrap;

	static char		fmt[
				STRSIZE(BIGGEST_REQID_S)/* start   */
			      + 1			/* :       */
			      + STRSIZE(BIGGEST_REQID_S)/* end     */
			      + 1			/* :       */
			      + STRSIZE(BIGGEST_REQID_S)/* incr    */
			      + 1			/* :       */
			      + 4			/* %ld\n   */
			      + 1			/* (nul)   */
				];

	char 			buf[256];
	int len;

	long			ret;


	if (!started) {
		snprintf(buf, sizeof (buf), "%s/%s", Lp_Temp, SEQF);
		if (((fd = open_locked(buf, "r+", 0644)) < 0) &&
		    ((fd = open_locked(buf, "w", 0644)) < 0))
			fail ("Can't open file %s (%s).\n", buf, PERROR);

		lseek(fd, 0, SEEK_SET);

		read(fd, buf, sizeof (buf));
		if (sscanf(buf, "%ld:%ld:%ld:%ld\n", &start, &end, &incr, &curr) != 4) {
			start = SEQF_DEF_START;
			end = SEQF_DEF_END;
			curr = start;
			incr = SEQF_DEF_INCR;
		}

		if (start < 0)
			start = SEQF_DEF_START;
		if (end > SEQF_DEF_END)
			end = SEQF_DEF_END;
		if (curr < start || curr > end)
			curr = start;

		sprintf (fmt, "%ld:%ld:%ld:%%ld\n", start, end, incr);
		started = 1;
	}

	wrap = curr;
	do {	
		ret = curr;
		if ((curr += incr) > end)
	    	curr = start;

	} while ( wrap != curr && ((RSTATUS *)request_by_id_num(ret)) ) ; 

	/* write the new id file */
	lseek(fd, 0, SEEK_SET);
	len = sprintf(buf, fmt, curr);
	write(fd, buf, len);
	ftruncate(fd, len);

	if (curr == wrap) {
		note("alloc_req_id(): out of ids\n");
		errno = EEXIST;
		return(SEQF_DEF_START-1);
	} else
		return (ret);
}

/**
 ** _alloc_file() - ALLOCATE FILES FOR A REQUEST
 **/

char *
_alloc_files (
	int			num,
	char *			prefix,
	uid_t			uid,
	gid_t			gid
)
{
	static char		base[
				1			/* F       */
			      + STRSIZE(BIGGEST_REQID_S)/* req-id  */
			      + 1			/* -       */
			      + STRSIZE(MOST_FILES_S)	/* file-no */
			      + 1			/* (nul)   */
				];

	char *			file;
	char *			cp;

	int			fd;
	int			plus;


	if (num > BIGGEST_REQID)
		return (0);

	if (!prefix) {
		int id;

		if ((id = _alloc_req_id()) < SEQF_DEF_START )
			return(NULL); /* Out of request IDs (errno = EEXIST) */
		snprintf (base, sizeof (base), "%d-%d", id, MOST_FILES);
		plus = 0;
	} else {
		if (strlen(prefix) > (size_t) 6)
			return (0);
		snprintf (base, sizeof (base), "F%s-%d", prefix, MOST_FILES);
		plus = 1;
	}

	file = makepath(Lp_Temp, base, (char *)0);
        
	cp = strrchr(file, '-') + 1;
	while (num--) {
		sprintf (cp, "%d", num + plus);
		if ((fd = Open(file, O_CREAT|O_TRUNC, 0600)) == -1) {
			Free (file);
			return (0);
		} else {
			Close (fd);
			(void) chownmod(file, uid, gid, 0600);
		}
	}

#ifdef LP_USE_PAPI_ATTR
	if (prefix == NULL)
	{
		/*
		 * Initial job request (s_alloc_files) so create an empty PAPI
		 * Attribute file; note, this file will only be used if the
		 * print job has been submitted via the PAPI interface.
		 */

		file = (char *)Realloc(file, strlen(file) +
					strlen(LP_PAPIATTRNAME) + 1);
		if (file != NULL)
		{
			cp = strrchr(file, '-') + 1;
			sprintf(cp, "%s", LP_PAPIATTRNAME);

			if ((fd = Open(file, O_CREAT|O_TRUNC, 0600)) == -1)
			{
				Free(file);
				return (0);
			}
			else
			{
				Close(fd);
				(void) chownmod(file, uid, gid, 0600);
			}

			Free(file);
		}
	}
#endif


	if ((cp = strrchr(base, '-')))
		*cp = 0;

	return (base);
}


#ifdef LP_USE_PAPI_ATTR
static char *extractReqno(char *req_file)

{
	char *start = NULL;
	char *end = NULL;
	char *result = NULL;

	start = strrchr(req_file, '/');
	end = strrchr(req_file, '-');

	if ((start != NULL) && (end != NULL))
	{
		start++;
		if (end > start)
		{
			int n = end - start;
			result = (char *)Malloc(n+1);
			strncpy(result, start, n);
			result[n] = '\0';
		}
	}

	return (result);
} /* extractReqno() */
#endif
