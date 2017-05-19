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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include "uucp.h"
#include "log.h"

void notify(), lnotify(), unlinkdf(), arrived();
static void stmesg();
static int nospace();

struct Proto {
	char P_id;
	int (*P_turnon)();
	int (*P_rdmsg)();
	int (*P_wrmsg)();
	int (*P_rddata)();
	int (*P_wrdata)();
	int (*P_turnoff)();
};

extern char _Protocol[];
extern char *findProto();

extern char uuxqtarg[];

extern int gturnon(), gturnoff();
extern int grdmsg(), grddata();
extern int gwrmsg(), gwrdata();

extern int wmesg(), rmesg(), expfile(), putinpub(), stptcl();
extern void setline(), TMname(), cleanup(), pfEndfile(), statlog(), mailst();

#ifdef	D_PROTOCOL
extern int dturnon(), dturnoff();
extern int drdmsg(), drddata();
extern int dwrmsg(), dwrdata();
#endif	/* D_PROTOCOL */

#ifdef	X_PROTOCOL
extern int xturnon(), xturnoff();
extern int xrdmsg(), xrddata();
extern int xwrmsg(), xwrdata();
#endif	/* X_PROTOCOL */

#ifdef E_PROTOCOL
extern int eturnon(), eturnoff();
extern int erdmsg(), erddata();
extern int ewrmsg(), ewrdata();
extern int trdmsg(), twrmsg();
extern int trddata(), twrdata();
#endif /* E_PROTOCOL */

#ifdef F_PROTOCOL
extern int fturnon(), fturnoff();
extern int frdmsg(), frddata();
extern int fwrmsg(), fwrdata();
#endif	/* F_PROTOCOL */

extern int imsg();
extern int omsg();
extern int turnoff();
extern long strtol();

struct Proto Ptbl[]={
	{'g', gturnon, grdmsg, gwrmsg, grddata, gwrdata, gturnoff},
	{'G', gturnon, grdmsg, gwrmsg, grddata, gwrdata, gturnoff},

#ifdef E_PROTOCOL
	{'e', eturnon, erdmsg, ewrmsg, erddata, ewrdata, eturnoff},
	{'t', eturnon, trdmsg, twrmsg, trddata, twrdata, eturnoff},
#endif /* E_PROTOCOL */ 

#ifdef	D_PROTOCOL
	{'d', dturnon, drdmsg, dwrmsg, drddata, dwrdata, dturnoff},
#endif	/* D_PROTOCOL */

#ifdef	X_PROTOCOL
	{'x', xturnon, xrdmsg, xwrmsg, xrddata, xwrdata, xturnoff},
#endif	/* X_PROTOCOL */

#ifdef	F_PROTOCOL
	{'f', fturnon, frdmsg, fwrmsg, frddata, fwrdata, fturnoff},
#endif	/* F_PROTOCOL */
	'\0'
};

#define VALIDSIZE sizeof(Ptbl)/sizeof(struct Proto)

int (*Rdmsg)()=imsg, (*Rddata)();
int (*Wrmsg)()=omsg, (*Wrdata)();
int (*Turnon)(), (*Turnoff)()=turnoff;


#define YES "Y"
#define NO "N"

#define TBUFSIZE	128	/* temporary buffer size */
#define FLENRADIX	(16)	/* output radix for file start point */

/*
 * failure messages
 */
#define EM_MAX		10
#define EM_LOCACC	"N1"	/* local access to file denied */
#define EM_RMTACC	"N2"	/* remote access to file/path denied */
#define EM_BADUUCP	"N3"	/* a bad uucp command was generated */
#define EM_NOTMP	"N4"	/* remote error - can't create temp */
#define EM_RMTCP	"N5"	/* can't copy to remote directory - file in public */
#define EM_LOCCP	"N6"	/* can't copy on local system */
#define EM_SEEK		"N7"	/* can't seek to checkpoint */
/* 	EM_		"N8" */	/* placeholder*/
/* 	EM_		"N9" */	/* placeholder*/
#define EM_ULIMIT	"N10"	/* receiver ulimit exceeded */

char *Em_msg[] = {
	"COPY FAILED (reason not given by remote)",
	"local access to file denied",
	"remote access to path/file denied",
	"system error - bad uucp command generated",
	"remote system can't create temp file",
	"can't copy to file/directory - file left in PUBDIR/user/file",
	"can't copy to file/directory - file left in PUBDIR/user/file",
	"can't seek to checkpoint",
	"COPY FAILED (reason not given by remote)", /* placeholder */
	"COPY FAILED (reason not given by remote)", /* placeholder */
	"file exceeds ulimit of receiving system",
	"forwarding error"
};


#define XUUCP 'X'	/* execute uucp (string) */
#define SLTPTCL 'P'	/* select protocol  (string)  */
#define USEPTCL 'U'	/* use protocol (character) */
#define RCVFILE 'R'	/* receive file (string) */
#define SNDFILE 'S'	/* send file (string) */
#define RQSTCMPT 'C'	/* request complete (string - yes | no) */
#define HUP     'H'	/* ready to hangup (string - yes | no) */
#define RESET	'X'	/* reset line modes */

#define W_MAX		10	/* maximum number of C. files per line */
#define W_MIN		7	/* min number of entries */
#define W_TYPE		wrkvec[0]
#define W_FILE1		wrkvec[1]
#define W_FILE2		wrkvec[2]
#define W_USER		wrkvec[3]
#define W_OPTNS		wrkvec[4]
#define W_DFILE		wrkvec[5]
#define W_MODE		wrkvec[6]
#define W_NUSER		wrkvec[7]
#define W_SFILE		wrkvec[8]
#define W_RDFILE	wrkvec[8]
#define W_POINT		wrkvec[9]
#define W_FSIZE		wrkvec[9]
#define W_RFILE		wrkvec[5]
#define W_XFILE		wrkvec[5]
char	*mf;

#define RMESG(m, s) if (rmesg(m, s) != 0) {(*Turnoff)(); return(FAIL);}
#define RAMESG(s) if (rmesg('\0', s) != 0) {(*Turnoff)(); return(FAIL);}
#define WMESG(m, s) if(wmesg(m, s) != 0) {(*Turnoff)(); return(FAIL);}

char Wfile[MAXFULLNAME] = {'\0'};
char Dfile[MAXFULLNAME];

char	*wrkvec[W_MAX+1];
int	statfopt;

/*
 * Create restart point filename
 */

static void
Pname(fileid, dfile, direct)
  char *fileid;
  char *dfile;
  int  direct;		/* indicates a direct delivery temp file nameneeded */
{
    char *p;

	    /*
	     * If the file is direct delivery, then its name is:
	     *
	     *		/dir/dir/dir/.Pnnnnnnnn
	     *
	     * in the target directory.  We create this by replacing the
	     * name of the target file with the D.nnnnnn name from the
	     * work vector, and then overwriting the D. with .P
	     */

	    if (direct) {
		if (p = strrchr(dfile, '/')) {	/* find the last slash */
			p++;
			strcpy(p, fileid);	/* append D.nnnnn name to dir */
			*p++ = '.';
			*p = 'P';		/* replace beginning with .P */
	    		DEBUG(7, "Point file (direct) =%s\n", dfile);
			return;
		}
	    }
	    strcpy(dfile, RemSpool);
	    strcat(dfile, "/");
	    p = dfile + strlen(Dfile);
	    strcat(dfile, fileid);
	    *p = 'P';
	    DEBUG(7, "Point file=%s\n", dfile);
	return;
}


/*
 * execute the conversation between the two machines 
 * after both programs are running.
 * returns:
 *	SUCCESS 	-> ok
 *	FAIL 		-> failed
 */
int
cntrl()
{
	FILE * fp;
	struct stat stbuf;
	char *	p;
	long 	startp;		/* checkpoint restart point */
	long	actualsize;	/* actual file size */
	long	im;
	long	lfilemode;
	mode_t	filemode;
	int	status;
	int	i, narg;
	int	mailopt, ntfyopt;
	int	ret;
	char	tbuf[TBUFSIZE];
	char	rqstr[BUFSIZ];	/* contains the current request message */
	char	msg[BUFSIZ];
	char	filename[MAXFULLNAME], wrktype;
	char	fsize[NAMESIZE];	/* holds file size/checkpoint string */
	char	localname[MAXFULLNAME];	/* real local system name */
	char	Recspool[MAXFULLNAME];	/* spool area for slave uucico */
	static pid_t	pnum;
	extern int uuxqtflag;	/* set if received X. or D. file */

	pnum = getpid();
	Wfile[0] = '\0';
	(void) sprintf(Recspool, "%s/%s", SPOOL, Rmtname);
top:
	(void) strcpy(User, Uucp);
	statfopt = 0;
	*Jobid = '\0';
	DEBUG(4, "*** TOP ***  -  Role=%d, ", Role);
	setline(RESET);
	if (Role == MASTER) {

		/*
		 * get work
		 */
		pfFindFile();
		if ((narg = gtwvec(Wfile, wrkvec, W_MAX)) == 0) {
			acEnd(COMPLETE); /*stop collecting accounting log */
			WMESG(HUP, ""); /* I(master) am done. want me to quit? */
			RMESG(HUP, msg);
			goto process;
		}
		DEBUG(7, "Wfile - %s,", Wfile);
		strncpy(Jobid, BASENAME(Wfile, '/')+2, NAMESIZE);
		Jobid[NAMESIZE-1] = '\0';
		DEBUG(7, "Jobid = %s\n", Jobid);
		wrktype = W_TYPE[0];
		pfFound(Jobid, W_OPTNS, Nstat.t_qtime);
		mailopt = strchr(W_OPTNS, 'm') != NULL;
		statfopt = strchr(W_OPTNS, 'o') != NULL;
		ntfyopt = strchr(W_OPTNS, 'n') != NULL;

		uucpname(localname); /* get real local machine name */
		acDojob(Jobid, localname, W_USER); 
		scRequser(W_USER); /* log requestor user id */

		/*
		 * We used to check for corrupt workfiles here (narg < 5),
		 * but we were doing it wrong, and besides, anlwrk.c is the
		 * appropriate place to do it.
		 */

		(void) sprintf(User, "%s", W_USER);
		if (wrktype == SNDFILE ) {
			(void) sprintf(rqstr, "%s!%s --> %s!%s (%s)", Myname,
			    W_FILE1, Rmtname, W_FILE2, User);

			/* log destination node, user and file name */

			scDest(Rmtname,NOTAVAIL,W_FILE2); 

			/* log source node, file owner, file name, mod time and size */

			scSrc(Myname,scOwn(W_FILE1),W_FILE1,scMtime(W_FILE1)
						,scSize(W_FILE1)); 
							
			logent(rqstr, "REQUEST");
			CDEBUG(1, "Request: %s\n", rqstr);
			mf = W_SFILE;
			(void) strcpy(filename, W_FILE1);
			expfile(filename);
			(void) strcpy(Dfile, W_DFILE);
			if ( (fp = fopen(Dfile, "r")) == NULL) {
			    if ( (fp = fopen(filename, "r")) == NULL) {
				/*  cannot read spool or original file */
				unlinkdf(Dfile);
				lnotify(User, rqstr, "can't access");
				(void) sprintf(msg, "CAN'T READ %s %d",
					filename, errno);
				logent(msg, "FAILED");
				CDEBUG(1, "Failed: Can't Read %s\n", filename);
		    		scWrite();	/* log the security violation */
				goto top;
			    } else {
				/* ensure original file is publicly readable */
				if ( !F_READANY(fileno(fp)) ) {
				    /* access denied */
				    logent("DENIED", "ACCESS");
				    unlinkdf(W_DFILE);
				    lnotify(User, rqstr, "access denied");
				    CDEBUG(1, "Failed: Access Denied\n%s", "");
		    		    scWrite();	/* log the security violation */
				    goto top;
				}
			    }
			}

			if (Restart && !(fstat(fileno(fp), &stbuf))) {
				(void) sprintf(fsize, "0x%lx", stbuf.st_size);
				W_FSIZE = fsize; /* set file size in vector */
			}

			/* Check whether remote's ulimit is exceeded */
			if (SizeCheck) {
				if (((stbuf.st_size-1)/512 + 1) > RemUlimit) {
					/* remote ulimit exceeded */
					unlinkdf(Dfile);
					lnotify(User, rqstr, "remote ulimit exceeded");
					logent("DENIED", "REMOTE ULIMIT EXCEEDED");
					CDEBUG(1, "Denied: remote ulimit exceeded %s\n", filename);
					scWrite();
					(void) fclose(fp);
					goto top;
				}
			}
		}

		if (wrktype == RCVFILE) {
			(void) sprintf(rqstr, "%s!%s --> %s!%s (%s)", Rmtname,
			    W_FILE1, Myname, W_FILE2, User);

			/* log destination node, user and file name */

			scDest(Myname,NOTAVAIL,W_FILE2); 

			/* log source node, file owner, file name, mod time and size */

			scSrc(Rmtname,NOTAVAIL,W_FILE1,NOTAVAIL,NOTAVAIL); 

			logent(rqstr, "REQUEST");
			CDEBUG(1, "Request: %s\n", rqstr);
			mf = W_RFILE;
			(void) strcpy(filename, W_FILE2);

			/* change Wrkdir to SPOOL/Rmtname in case the file being
			** requested is needed for some remote execution.
			*/

			(void) strcpy(Wrkdir, Recspool);
			expfile(filename);

			/* now change Wrkdir back to what it was 
			** just being paranoid.
			*/

			(void) strcpy(Wrkdir, RemSpool);
			if (chkperm(W_FILE1, filename, strchr(W_OPTNS, 'd'))) {

				/* access denied */
				logent("DENIED", "ACCESS");
				lnotify(User, rqstr, "access denied");
				CDEBUG(1, "Failed: Access Denied--File: %s\n", 
				    filename);
		    		scWrite();	/* log the security violation */
				goto top;
			}

			/*
			 * If we are not going to spool the file in the spool
			 * directory, just use the destination file name.  If we
			 * are not supporting restart, wipe out the target file.
			 * else:
			 *
			 * If restart is enabled, make up the Point file name
			 * as the file to open, else use the TM style name.
			 *
			 * If we run into a spool name of "D.0", this implies
			 * that someone forgot to install the new uucp and
			 * uux commands.  Such jobs will not be checkpointed.
			 */

			    
			if (Restart && (strlen(W_RDFILE) > (size_t) 6)) {
				if (noSpool()) {
				    strcpy(Dfile, filename);	/* use Dest file directly */
				    Pname(W_RDFILE, Dfile, TRUE);
				}
				else
				    Pname(W_RDFILE, Dfile, FALSE);
			}
			else {
			    TMname(Dfile, pnum); /* get TM file name */
			    unlink(Dfile);
			}

			/*
			 * If the spool file exists, it better have the right owner
			 * and permissions!
			 */

			if (Restart && noSpool()) {
				if ((! stat(Dfile, &stbuf)) &&
				    ((stbuf.st_mode != (DFILEMODE|S_IFREG)) ||
				    ((stbuf.st_gid != UUCPGID) ||
				     (stbuf.st_uid != UUCPUID)))) {
				    lnotify(User, rqstr,
					"bad spool file ownership/permissions");
				    logent("BAD DESTFILE OWNER/PERMS", "FAIL");
				    CDEBUG(1, "Failed: bad dest file owner/perms 0%o; fail\n", stbuf.st_mode);
				    goto top;
				}
			}
			if ( ((fp = fopen(Dfile, "a+")) == NULL)
			     || nospace(Dfile)) {

				/* can not create temp */
				if (noSpool())
				    logent("CAN'T CREATE/OPEN DEST FILE", "FAILED");
				else
				    logent("CAN'T CREATE TM FILE", "FAILED");
				CDEBUG(1, "Failed: No Space!\n%s", "");
				unlinkdf(Dfile);
				assert(Ct_CREATE, Dfile, nospace(Dfile),
				    __FILE__, __LINE__);
				cleanup(FAIL);
			}

			/*
			 * Send the W_POINT value to the other side.
			 */

			if (Restart) {
			    if (fstat (fileno(fp), &stbuf)) {
				logent("CAN'T STAT DFILE", "START FROM BEGINNING");
				stbuf.st_size = 0L;
			    }

			    /*
			     * find a good start point.  Take care of simple
			     * underflow and the signed nature of longs.
			     */

			    DEBUG(7, "Dfile length 0x%lx\n", stbuf.st_size);
			    startp = stbuf.st_size - (stbuf.st_size % BUFSIZ);
			    if((stbuf.st_size >= 0) && (startp < 0))
				startp = 0;

			    if(startp)
			    {
				if(startp < 0)
				    sprintf(tbuf,"start=0x%lx", startp);
				else
				    sprintf(tbuf,"start=%ld", startp);
	
				logent(tbuf, "RESTART");
			    }

			    sprintf(fsize, "0x%lx", startp);
			    W_POINT = fsize; /* set start point in vector */
			    if (lseek(fileno(fp), startp, 0) == -1) {
				WMESG(SNDFILE, EM_SEEK);
				logent("CAN'T SEEK", "DENIED");
				CDEBUG(1, "Failed, Can't seek in Dfile\n%s", "");
				unlinkdf(Dfile);
				goto top;
		    	    }
		    	    fp->_cnt = 0;
		    	    fp->_ptr = fp->_base;
			}

			Seqn++;
			chmod(Dfile, DFILEMODE);	/* no peeking! */
			chown(Dfile, UUCPUID, UUCPGID);

		}
		DEBUG(4, "wrktype - %c\n ", wrktype);

		/* Build up the message itself */

		msg[0] = '\0';
		for (i = 1; i < narg; i++) {
			(void) strcat(msg, " ");
			(void) strcat(msg, wrkvec[i]);
		}

		WMESG(wrktype, msg); /* I(master) am sending you our work file */
		RMESG(wrktype, msg); /* I(master) am waiting for your response */
		goto process;
	}

	/*
	 * role is slave
	 */

	RAMESG(msg); /* I(slave) am waiting for our work file */

process:

	DEBUG(4, " PROCESS: msg - %s\n", msg);
	switch (msg[0]) {

	case RQSTCMPT:
		DEBUG(4, "%s\n", "RQSTCMPT:");
		if (msg[1] == 'N') {
			i = atoi(&msg[2]);
			if (i < 0 || i > EM_MAX) 
				i = 0;
			logent(Em_msg[i], "REQUESTED");
		}
		if (Role == MASTER) {
		        notify(mailopt, W_USER, rqstr, Rmtname, &msg[1]);
		}
		pfEndfile("");	/* "" indicates the file transfer completely */
		goto top;

	case HUP:
		DEBUG(4, "%s\n", "HUP:");
		if (msg[1] == 'Y') {
			WMESG(HUP, YES); /* let's quit */
			(*Turnoff)();
			Rdmsg = imsg;
			Wrmsg = omsg;
			Turnoff = turnoff;
			return(0);
		}

		if (msg[1] == 'N') {
			ASSERT(Role == MASTER, Wr_ROLE, "", Role);
			Role = SLAVE;
			scReqsys(Rmtname); /* log requestor system */
			chremdir(Rmtname);
			goto top;
		}

		/*
		 * get work
		 */
		if ( (switchRole() == FALSE) || !iswrk(Wfile) ) {
			DEBUG(5, "SLAVE-switchRole (%s)\n",
			    switchRole() ? "TRUE" : "FALSE");
			WMESG(HUP, YES); /* let's quit */
			RMESG(HUP, msg);
			goto process;
		}

		/* Note that Wfile is the first C. to process at top
		 * set above by iswrk() call
		 */
		if (uuxqtflag) {
			xuuxqt(uuxqtarg);
			uuxqtflag = 0;
		}
		WMESG(HUP, NO); /* don't quit. I(slave) have more to do */
		Role = MASTER;
		uucpname(localname); /* get real local machine name */
		scReqsys(localname); /* log requestor system */
		acInit("xfer");
		goto top;

	case XUUCP:
		/*
		 * slave part
		 * No longer accepted
		 */

		WMESG(XUUCP, NO);
		goto top;

	case SNDFILE:

		/*
		 * MASTER section of SNDFILE
		 */
		DEBUG(4, "%s\n", "SNDFILE:");
		if (msg[1] == 'N')
		   {
		    i = atoi(&msg[2]);
		    if (i < 0 || i > EM_MAX)
			i = 0;
		    logent(Em_msg[i], "REQUEST");
		    notify(mailopt, W_USER, rqstr, Rmtname, &msg[1]);
		    ASSERT(Role == MASTER, Wr_ROLE, "", Role);
		    (void) fclose(fp);
		    /* if remote is out of tmp space, then just hang up */
		    ASSERT(i != 4, Em_msg[4], Rmtname, i);	/* EM_NOTMP */
		    unlinkdf(W_DFILE);
		    scWrite();	/* something is wrong on other side, 
				   log the security violation */
		    Seqn++;
		    goto top;
		   }

		if (msg[1] == 'Y') {

			/*
			 * send file
			 */
			ASSERT(Role == MASTER, Wr_ROLE, "", Role);
			if (fstat(fileno(fp), &stbuf)) /* never fail but .. */
			    stbuf.st_size = 0;  /* for time loop calculation */

			/*
			 * If checkpoint restart is enabled, seek to the 
			 * starting point in the file.  We use hex because
			 * C doesn't support unsigned long directly.
			 */

			if (Restart) {
			    if((startp = strtol(&msg[2], (char **) 0, FLENRADIX))) {
			        CDEBUG(1, "Restart point=0x%lx\n", startp);
				if(startp < 0)
				    sprintf(tbuf,"start=0x%lx", startp);
				else
				    sprintf(tbuf,"start=%ld", startp);
				p = tbuf + strlen(tbuf);
				if (stbuf.st_size < 0)
				    sprintf(p,", length=0x%lx", stbuf.st_size);
				else
				    sprintf(p,", length=%ld", stbuf.st_size);
	
				logent(tbuf, "RESTART");
				errno = 0;
				if (lseek(fileno(fp), startp, 0) == -1) {
				    logent(strerror(errno), "FSEEK ERROR");
				    (void) fclose(fp);
				    (*Turnoff)();
		    		    Seqn++;
				    return(FAIL);
				}
				fp->_cnt = 0;
				fp->_ptr = fp->_base;
			    }
			}
			(void) millitick();	/* start msec timer */
			pfStrtXfer(MCHAR, SNDFILE);
			scStime(); 	/* log start transfer time for security log */

		/* (ret != 0) implies the trammission error occurred.
     	           If checkpoint protocol is available then the next 
		   transfer will restart from the breakpoint of the file, 
		   otherwise from the beginning of the file  */

			ret = (*Wrdata)(fp, Ofn);

		/* the second millitick() returns the duration between 
		   the first and second call. 
   		   writes "PARTIAL FILE to the transfer log indicating  
		   a transmission error. */

			statlog( "->", getfilesize(), millitick(),
					(ret) ? "PARTIAL FILE" : ""  );

			acInc();	/* increment job size in accounting log					 */
			pfEndXfer();
			scEtime();	/* log end transfer time for security log */
		    	Seqn++;
			(void) fclose(fp);
			if (ret != 0) {
				pfEndfile("PARTIAL FILE");
				acEnd(PARTIAL); /*stop collecting accounting log */
				(*Turnoff)();
				return(FAIL);
			}

			/* loop depending on the size of the file */
			/* give an extra try for each megabyte */
			for (im = stbuf.st_size >> 10; im >= 0; --im) {
		    	    if ((ret = rmesg(RQSTCMPT, msg)) == 0)
				break;	/* got message */
			}
			if (ret != 0) {
			    (*Turnoff)();
			     return(FAIL);
			}
			unlinkdf(W_DFILE);
			goto process;
		}

		/* 
		 * SLAVE section of SNDFILE
		 */
		ASSERT(Role == SLAVE, Wr_ROLE, "", Role);

		/*
		 * request to receive file
		 * check permissions
		 */
		i = getargs(msg, wrkvec, W_MAX);

		scRequser(W_USER); /* log requestor user id */

		/* log destination node, user and file name */

		scDest(Myname,NOTAVAIL,W_FILE2); 

		/* log source node, file owner, file name, mod time and size */

		scSrc(Rmtname,NOTAVAIL,W_FILE1,NOTAVAIL,NOTAVAIL); 

		/* Check for bad request */
		if (i < W_MIN) {
			WMESG(SNDFILE, EM_BADUUCP); /* you(remote master) gave me
							bad work file */
			logent("DENIED", "TOO FEW ARGS IN SLAVE SNDFILE");
			goto top;
		}
		/* SLAVE gets the original filesize from sender (MASTER) */
		/* This will be used to check the length of the P. file */
		if (Restart) {
		    if (W_FSIZE && (*W_FSIZE != '\0')) {
			actualsize = strtol(W_FSIZE, (char **) 0, FLENRADIX);
			CDEBUG(7, "Actual File Length %ld\n", actualsize);
		    } else {
			actualsize = -1;
			CDEBUG(7, "Actual File Length Not Provided\n%s", "");
		    }
		}

		mf = W_SFILE;
		(void) sprintf(rqstr, "%s!%s --> %s!%s (%s)", Rmtname,
			    W_FILE1, Myname, W_FILE2, W_USER);
		logent(rqstr, "REMOTE REQUESTED");
		DEBUG(4, "msg - %s\n", msg);
		CDEBUG(1, "Remote Requested: %s\n", rqstr);
		(void) strcpy(filename, W_FILE2);
		expfile(filename);
		DEBUG(4, "SLAVE - filename: %s\n", filename);
		if (chkpth(filename, CK_WRITE)
		     || chkperm(W_FILE1, filename, strchr(W_OPTNS, 'd'))) {
			WMESG(SNDFILE, EM_RMTACC); /* you(remote master) can't 
						send data to this file(directory) */
			logent("DENIED", "PERMISSION");
			CDEBUG(1, "Failed: Access Denied\n%s", "");
		    	scWrite(); /* log security violation */	
			goto top;
		}
		(void) sprintf(User, "%s", W_USER);

		DEBUG(4, "chkpth ok Rmtname - %s\n", Rmtname);

		

		if (Restart && (strlen(W_DFILE) > (size_t) 6)) {
			if (noSpool()) {
			    strcpy(Dfile, filename);	/* use Dest file directly */
			    Pname(W_DFILE, Dfile, TRUE);
			    if (! Restart)
				unlink(Dfile);
			}
			else
			    Pname(W_DFILE, Dfile, FALSE);
		}
		else {
		    TMname(Dfile, pnum); /* get TM file name */
		    unlink(Dfile);
		}

		/*
		 * If the spool file exists, it better have the right owner
		 * and permissions!
		 */

		if (Restart && noSpool()) {
			if ((! stat(Dfile, &stbuf)) &&
			    ((stbuf.st_mode != (DFILEMODE|S_IFREG)) ||
			    ((stbuf.st_gid != UUCPGID) ||
			     (stbuf.st_uid != UUCPUID)))) {
			    WMESG(SNDFILE, EM_NOTMP); /* I(slave) see bad perms */
			    logent("BAD DESTFILE OWNER/PERMS", "FAILED");
			    CDEBUG(1, "Failed: bad dest file owner/perms 0%o\n", stbuf.st_mode);
			    goto top;
			}
		}
		if ( ((fp = fopen(Dfile, "a+")) == NULL) || nospace(Dfile) ) {
			WMESG(SNDFILE, EM_NOTMP); /* I(slave) can't create TM file */
			logent("CAN'T OPEN", "DENIED");
			CDEBUG(1, "Failed: Can't Create Temp File\n%s", "");
			unlinkdf(Dfile);
			goto top;
		}
		chmod(Dfile, DFILEMODE);	/* no peeking! */
		chown(Dfile, UUCPUID, UUCPGID);
		if (Restart && (strlen(W_DFILE) > (size_t) 6)) {
		    if(fstat(fileno(fp), &stbuf)) {
			WMESG(SNDFILE, EM_NOTMP);
			logent("CAN'T STAT", "DENIED");
			CDEBUG(1, "Failed: Can't Stat Temp File\n%s", "");
			unlinkdf(Dfile);
			Seqn++;
			goto top;
		    }
		    /*
		     * find a good start point.  Take care of simple underflow
		     * and the signed nature of longs.
		     */

		    DEBUG(7, "Dfile length 0x%lx\n", stbuf.st_size);
		    startp = stbuf.st_size - (stbuf.st_size % BUFSIZ);
		    if((stbuf.st_size >= 0) && (startp < 0))
			startp = 0;

		    if(startp)
		    {
			if(startp < 0)
			    sprintf(tbuf,"start=0x%lx", startp);
			else
			    sprintf(tbuf,"start=%ld", startp);

			logent(tbuf, "RESTART");
		    }

		    sprintf(tbuf, "%s 0x%lx", YES, startp);
		    if (lseek(fileno(fp), startp, 0) == -1) {
			WMESG(SNDFILE, EM_SEEK);
			logent("CAN'T SEEK", "DENIED");
			CDEBUG(1, "Failed, Can't seek in Dfile\n%s", "");
			unlinkdf(Dfile);
			Seqn++;
			goto top;
		    }
		    fp->_cnt = 0;
		    fp->_ptr = fp->_base;
		    CDEBUG(1," restart msg %s\n", tbuf);
		    WMESG(SNDFILE, tbuf);	
		}
		else
		    WMESG(SNDFILE, YES);	/* I(slave) clear to send */
		(void) millitick();	/* start msec timer */
		pfStrtXfer(SCHAR, RCVFILE);
		scStime(); 	/* log start transfer time for security log */
		/* (ret != 0) implies the trammission error occurred.
     	           If checkpoint protocol is available then the next 
		   recieve will restart from the breakpoint of the file, 
		   otherwise from the beginning of the file  */

		setline(RCVFILE);
		ret = (*Rddata)(Ifn, fp);
		setline(SNDFILE);

		/* the second millitick() returns the duration between 
		   the first and second call. 
   		   writes "PARTIAL FILE to the transfer log indicating  
		   a transmission error. */

		statlog( "<-", getfilesize(), millitick(),
				(ret) ? "PARTIAL FILE" : ""  );

		pfEndXfer();
		scEtime();	/* log end transfer time for security log */
		Seqn++;

		if (ret != 0) {
			pfEndfile("PARTIAL FILE");
			(void) fclose(fp);
			if ( ret == EFBIG ) {
				WMESG(RQSTCMPT, EM_ULIMIT);
				logent("FILE EXCEEDS ULIMIT","FAILED");
				CDEBUG(1, "Failed: file size exceeds ulimit%s\n", "");
				goto top;
			}
			(*Turnoff)();
			logent("INPUT FAILURE", "IN SEND/SLAVE MODE");
			return(FAIL);
		}
		if (Restart && (actualsize != -1)) {
		    if (fstat(fileno(fp), &stbuf)) {
			(void) fclose(fp);
			unlinkdf(Dfile);
			(*Turnoff)();
			logent("CAN'T STAT PFILE", "FAILED");
			return(FAIL);
		    }
		    if (stbuf.st_size != actualsize) {
			(void) fclose(fp);
			unlinkdf(Dfile);
			(*Turnoff)();
			logent("RECEIVED SIZE NOT EQUAL TO ACTUAL SIZE", "FAILED");
			CDEBUG(1, "Failed: receive size %ld ", stbuf.st_size);
			CDEBUG(1, "not equal to actual size %ld\n", actualsize);
			return(FAIL);
		    }
		}
		(void) fclose(fp);

		/* copy to user directory */
		ntfyopt = strchr(W_OPTNS, 'n') != NULL;

		/*
		 * See if spool file and target file in the same file system
		 */

		ret = 0;
		if (p = strrchr(Dfile, '/'))
		{
			*p = '\0';
			ret = PREFIX(Dfile, filename);
			*p = '/';
		}
			
		if (noSpool() && ret)
		{
		    /*
		     * if we are not already in the right file, and
		     * it is theoretically in the same file system,
		     * link it there...
		     */

		    if(strcmp (filename, Dfile)) {
			    unlink(filename);
			    if(link(Dfile, filename))
			    {
				logent("FAILED", "MOVE");
				scWrite();
				putinpub(filename, Dfile, BASENAME(W_USER,'!'));
			    }
			    else
	    			DEBUG(7, "linked Point file to %s\n", filename);
			    unlink(Dfile);
		    }
		    else
		    	DEBUG(7, "Point file and %s the same\n", filename);
		    status = 0;			/* all done */
		}
		else
		    status = xmv(Dfile, filename);

		scSize(Dfile);	/* log source file size */
		WMESG(RQSTCMPT, status ? EM_RMTCP : YES);
		if (status == 0) {
			sscanf(W_MODE, "%lo", &lfilemode);
			if (lfilemode <= 0)
				filemode = PUB_FILEMODE;
			else
				filemode = (mode_t)lfilemode;
			if (PREFIX(RemSpool, filename))
			    chmod(filename, DFILEMODE);
			else
			    chmod(filename, (filemode & LEGALMODE) | PUB_FILEMODE);
			arrived(ntfyopt, filename, W_NUSER, Rmtname, User);
		} else {
			logent("FAILED",  "COPY");
			scWrite();	/* log the security violation */
			status = putinpub(filename, Dfile,
			    BASENAME(W_USER, '!'));
			DEBUG(4, "->PUBDIR %d\n", status);
			if (status == 0)
				arrived(ntfyopt, filename, W_NUSER,
				    Rmtname, User);
		}
		pfEndfile("");	/* "" indicates the file transfer completely */
		if ( W_FILE2[1] == '.'  &&
		    (W_FILE2[0] == XQTPRE || W_FILE2[0] == DATAPRE) )
			uuxqtflag = 1;
		goto top;

	case RCVFILE:

		/*
		 * MASTER section of RCVFULE 
		 */
		DEBUG(4, "%s\n", "RCVFILE:");
		if (msg[1] == 'N') {
			i = atoi(&msg[2]);
			if (i < 0 || i > EM_MAX)
				i = 0;
			logent(Em_msg[i], "REQUEST");
		        notify(mailopt, W_USER, rqstr, Rmtname, &msg[1]);
			ASSERT(Role == MASTER, Wr_ROLE, "", Role);
			(void) fclose(fp);
			unlinkdf(Dfile);
		    	scWrite();	/* something is wrong on other side, 
					   log the security violation */
			goto top;
		}

		if (msg[1] == 'Y') {

		/* MASTER gets the original filesize from sender (SLAVE) */
		/* This will be used to check the length of the P. file */
			if (Restart) {
			    *fsize = '\0';
			    sscanf(&msg[2], "%*o %s", fsize);
			    if (*fsize != '\0') {
				actualsize = strtol(fsize, (char **) 0, FLENRADIX);
				CDEBUG(7, "Actual File Length %ld\n", actualsize);
			    } else {
				actualsize = -1;
				CDEBUG(7, "Actual File Length Not Provided\n%s", "");
			    }
			}

			/*
			 * receive file
			 */
			ASSERT(Role == MASTER, Wr_ROLE, "", Role);
			(void) millitick();	/* start msec timer */
			pfStrtXfer(MCHAR, SNDFILE);
			scStime();
		/* (ret != 0) implies the trammission error occurred.
     	           If checkpoint protocol is available then the next 
		   recieve will restart from the breakpoint of the file, 
		   otherwise from the beginning of the file  */

			ret = (*Rddata)(Ifn, fp);

		/* the second millitick() returns the duration between 
		   the first and second call. 
   		   writes "PARTIAL FILE to the transfer log indicating  
		   a transmission error. */

			statlog( "<-", getfilesize(), millitick(),
				(ret) ? "PARTIAL FILE" : ""  );
			pfEndXfer();
			scEtime();
			if (ret != 0) {
				pfEndfile("PARTIAL FILE");
				(void) fclose(fp);
				if ( ret == EFBIG ) {
					WMESG(RQSTCMPT, EM_ULIMIT);
					logent("FILE EXCEEDS ULIMIT","FAILED");
					CDEBUG(1, "Failed: file size exceeds ulimit%s\n", "");
					goto top;
				}
				(*Turnoff)();
				logent("INPUT FAILURE", "IN RECEIVE/MASTER MODE");
				return(FAIL);
			}
			if (Restart && (actualsize != -1)) {
			    if (fstat(fileno(fp), &stbuf)) {
				(void) fclose(fp);
				unlinkdf(Dfile);
				(*Turnoff)();
				logent("CAN'T STAT PFILE", "FAILED");
				return(FAIL);
			    }
			    if (stbuf.st_size != actualsize) {
				(void) fclose(fp);
				unlinkdf(Dfile);
				(*Turnoff)();
				logent("RECEIVED SIZE NOT EQUAL TO ACTUAL SIZE", "FAILED");
				CDEBUG(1, "Failed: receive size %ld ", stbuf.st_size);
				CDEBUG(1, "not equal to actual size %ld\n", actualsize);
				return(FAIL);
			    }
			}
			(void) fclose(fp);

			/*
			 * See if spool file and target file in the same file system
			 */

			ret = 0;
			if (p = strrchr(Dfile, '/'))
			{
				*p = '\0';
				ret = PREFIX(Dfile, filename);
				*p = '/';
			}
				
			if (noSpool() && ret)
			{
			    /*
			     * if we are not already in the right file, and
			     * it is theoretically in the same file system,
			     * link it there...
			     */

			    if(strcmp (filename, Dfile)) {
				    unlink(filename);
				    if(link(Dfile, filename))
				    {
					logent("FAILED", "MOVE");
					scWrite();
					putinpub(filename, Dfile, W_USER);
				    }
				    else
					DEBUG(7, "linked Point file to %s\n", filename);
				    unlink(Dfile);
			    }
			    else
				DEBUG(7, "Point file and %s the same\n", filename);
			    status = 0;			/* all done */
			}
			else
			    status = xmv(Dfile, filename);

			WMESG(RQSTCMPT, status ? EM_RMTCP : YES);
			notify(mailopt, W_USER, rqstr, Rmtname,
			    status ? EM_LOCCP : YES);
			if (status == 0) {
			    sscanf(&msg[2], "%lo", &lfilemode);
			    if (lfilemode <= 0)
				filemode = PUB_FILEMODE;
			    else
				filemode = (mode_t)lfilemode;
			    if (PREFIX(RemSpool, filename))
				chmod(filename, DFILEMODE);
			    else
				chmod(filename, (filemode & LEGALMODE) | PUB_FILEMODE);
			} else {
			    logent("FAILED", "COPY");
		    	    scWrite();	/* log the security violation */
			    putinpub(filename, Dfile, W_USER);
			}
			pfEndfile("");	/* "" indicates the file transfer completely */
			if ( W_FILE2[1] == '.'  &&
			    (W_FILE2[0] == XQTPRE || W_FILE2[0] == DATAPRE) )
				uuxqtflag = 1;
			goto top;
		}

		/*
		 * SLAVE section of RCVFILE
		 * (request to send file)
		 */
		ASSERT(Role == SLAVE, Wr_ROLE, "", Role);

		/* check permissions */
		i = getargs(msg, wrkvec, W_MAX);

		scRequser(W_USER); /* log requestor user id */

		/* log destination node, user and file name */

		scDest(Rmtname,NOTAVAIL,W_FILE2); 

		/* log source node, file owner, file name, mod time and size */

		scSrc(Myname,scOwn(W_FILE1),W_FILE1,scMtime(W_FILE1),scSize(W_FILE1)); 
		/* Check for bad request */
		if (i < 5) {
			WMESG(RCVFILE, EM_BADUUCP); /* you(remote master) gave me
							bad work file */
			logent("DENIED", "TOO FEW ARGS IN SLAVE RCVFILE");
			goto top;
		}

		(void) sprintf(rqstr, "%s!%s --> %s!%s (%s)", Myname,
			    W_FILE1, Rmtname, W_FILE2, W_USER);
		logent(rqstr, "REMOTE REQUESTED");
		CDEBUG(1, "Remote Requested: %s\n", rqstr);
		mf = W_RFILE;
		DEBUG(4, "msg - %s\n", msg);
		DEBUG(4, "W_FILE1 - %s\n", W_FILE1);
		(void) strcpy(filename, W_FILE1);
		expfile(filename);
		if (DIRECTORY(filename)) {
			(void) strcat(filename, "/");
			(void) strcat(filename, BASENAME(W_FILE2, '/'));
		}
		(void) sprintf(User, "%s", W_USER);

		if (requestOK() == FALSE) {
			/* remote can't request data from my system */
			WMESG(RCVFILE, EM_RMTACC);
			logent("DENIED", "REQUESTING");
			CDEBUG(1, "Failed: Access Denied\n%s", "");
		    	scWrite();	/* log the security violation */
			goto top;
		}
		DEBUG(4, "requestOK for Loginuser - %s\n", Loginuser);

		if ((fp = fopen(filename, "r")) == NULL) {
			WMESG(RCVFILE, EM_RMTACC); /* you(remote master) can't
							read my file */
			logent("CAN'T OPEN", "DENIED");
			CDEBUG(1, "Failed: Can't Open %s\n", filename);
		    	scWrite();	/* log the security violation */
			goto top;
		}

		if (chkpth(filename, CK_READ) || !F_READANY(fileno(fp))) {
			WMESG(RCVFILE, EM_RMTACC); /* you(remote master) can't 
							retrive my file */
			logent("DENIED", "PERMISSION");
			CDEBUG(1, "Failed: Access Denied\n%s", "");
		    	scWrite();	/* log the security violation */
			fclose(fp);
			goto top;
		}
		DEBUG(4, "chkpth ok Loginuser - %s\n", Loginuser);

		ASSERT(fstat(fileno(fp), &stbuf) == 0, Ct_STAT,
		    filename, errno);

		/* Check whether remote's ulimit is exceeded */
		if (SizeCheck) {
			if (((stbuf.st_size-1)/512 + 1) > RemUlimit) {
				/* remote ulimit exceeded */
				WMESG(RCVFILE, EM_ULIMIT);
				logent("DENIED", "REMOTE ULIMIT EXCEEDED");
				CDEBUG(1, "Denied: remote ulimit exceeded %s\n", filename);
				scWrite();
				(void) fclose(fp);
				goto top;
			}
		}

		/*
		 * ok to send file
		 */
		
		if (Restart && i >= 10) {
		    if (startp = strtol(W_POINT, (char **) 0, FLENRADIX)) {
			CDEBUG(1,"Restart point=0x%lx\n", startp);
			errno = 0;
			if (lseek(fileno(fp), startp, 0) == -1) {
			    WMESG(RCVFILE, EM_SEEK);
			    logent(strerror(errno), "FSEEK ERROR");
			    (void) fclose(fp);
			    goto top;
			}
			fp->_cnt = 0;
			fp->_ptr = fp->_base;
			if(startp < 0)
			    sprintf(tbuf,"start=0x%lx", startp);
			else
			    sprintf(tbuf,"start=%ld", startp);
			p = tbuf + strlen(tbuf);
			if (stbuf.st_size < 0)
			    sprintf(p,", length=0x%lx", stbuf.st_size);
			else
			    sprintf(p,", length=%ld", stbuf.st_size);

			logent(tbuf, "RESTART");
		   }
		}

		if (Restart)
			(void) sprintf(msg, "%s %lo 0x%lx", YES,
				(long) (stbuf.st_mode & LEGALMODE),
				(long) stbuf.st_size);
		else
			(void) sprintf(msg, "%s %lo", YES,
				(long) (stbuf.st_mode & LEGALMODE));
		WMESG(RCVFILE, msg); /* I(slave) send you my file now */
		Seqn++;
		(void) millitick();	/* start msec timer */
		scStime();
		pfStrtXfer(SCHAR, SNDFILE);
		/* (ret != 0) implies the trammission error occurred.
     	           If checkpoint protocol is available then the next 
		   transfer will restart from the breakpoint of the file, 
		   otherwise from the beginning of the file  */

		ret = (*Wrdata)(fp, Ofn);

		/* the second millitick() returns the duration between 
		   the first and second call. 
   		   writes "PARTIAL FILE to the transfer log indicating  
		   a transmission error. */

		statlog( "->", getfilesize(), millitick(),
					(ret) ? "PARTIAL FILE" : ""  );
		pfEndXfer();
		scEtime();

		(void) fclose(fp);
		if (ret != 0) {
			pfEndfile("PARTIAL FILE");
			(*Turnoff)();
			return(FAIL);
		}

		/* loop depending on the size of the file */
		/* give an extra try for each megabyte */
		/* stbuf set in fstat several lines back  */
		for (im = stbuf.st_size >> 10; im >= 0; --im) {
		    if ((ret = rmesg(RQSTCMPT, msg)) == 0)
			break;	/* got message */
		}
		if (ret != 0) {
		    (*Turnoff)();
		     return(FAIL);
		}
		goto process;
	}
	(*Turnoff)();
	return(FAIL);
}



/*
 * read message
 * returns:
 *	0	-> success
 *	FAIL	-> failure
 */
int
rmesg(c, msg)
char *msg, c;
{
	char str[50];

	DEBUG(4, "rmesg - '%c' ", c);
	if ((*Rdmsg)(msg, Ifn) != 0) {
		DEBUG(4, "got %s\n", "FAIL");
		(void) sprintf(str, "expected '%c' got FAIL", c);
		logent(str, "BAD READ");
		return(FAIL);
	}
	if (c != '\0' && msg[0] != c) {
		DEBUG(4, "got %s\n", msg);
		(void) sprintf(str, "expected '%c' got %s", c, msg);
		logent(str, "BAD READ");
		return(FAIL);
	}
	DEBUG(4, "got %s\n", msg);
	return(0);
}


/*
 * write a message
 * returns:
 *	0	-> ok
 *	FAIL	-> ng
 */
int
wmesg(m, s)
char *s, m;
{
	CDEBUG(4, "wmesg '%c'", m);
	CDEBUG(4, "%s\n", s);
	return((*Wrmsg)(m, s, Ofn));
}


/*
 * mail results of command
 * return: 
 *	none
 */
void
notify(mailopt, user, msgin, sys, msgcode)
char *user, *msgin, *sys;
char *msgcode;
{
	int i;
	char str[BUFSIZ];
	char *msg;

	DEBUG(4,"mailopt %d, ", mailopt);
	DEBUG(4,"statfopt %d\n", statfopt);
	if (statfopt == 0 && mailopt == 0 && *msgcode == 'Y')
		return;
	if (*msgcode == 'Y')
		msg = "copy succeeded";
	else {
		i = atoi(msgcode + 1);
		if (i < 1 || i > EM_MAX)
			i = 0;
		msg = Em_msg[i];
	}
	if(statfopt){
		stmesg(msgin, msg);
		return;
	}
	(void) sprintf(str, "REQUEST: %s\n(SYSTEM: %s)  %s\n",
		msgin, sys, msg);
	mailst(user, msg, str, "", "");
	return;
}

/*
 * local notify
 * return:
 *	none
 */
void
lnotify(user, msgin, mesg)
char *user, *msgin, *mesg;
{
	char mbuf[BUFSIZ];

	if(statfopt){
		stmesg(msgin, mesg);
		return;
	}
	(void) sprintf(mbuf, "REQUEST: %s\n(SYSTEM: %s)  %s\n",
		msgin, Myname, mesg);
	mailst(user, mesg, mbuf, "", "");
	return;
}

/*ARGSUSED*/
static void
stmesg(f, m)
char	*f, *m;
{
#ifdef notdef
	FILE	*Cf;
	time_t	clock;
	long	td, th, tm, ts;
#endif
	char msg[BUFSIZ];

	DEBUG(4,"STMES %s\n",mf);
	sprintf(msg, "STMESG - %s", mf);
	logent("DENIED", msg);
#ifdef notdef
	/*
	 * This code is a giant security hole.
	 * No checking is done on what file is
	 * written and chmod'ed.  For now we
	 * just ifdef this out.
	 */
	if((Cf = fopen(mf, "a+")) == NULL){
		chmod(mf, PUB_FILEMODE);
		return;
	}
	(void) time(&clock);
	(void) fprintf(Cf, "uucp job: %s (%s) ", Jobid, timeStamp());
	td = clock - Nstat.t_qtime;
	ts = td%60;
	td /= 60;
	tm = td%60;
	td /= 60;
	th = td;
	(void) fprintf(Cf, "(%ld:%ld:%ld)\n%s\n%s\n\n", th, tm, ts, f, m);
	(void) fclose(Cf);
	chmod(mf, PUB_FILEMODE);
#endif
}

/*
 * converse with the remote machine, agree upon a 
 * protocol (if possible) and start the protocol.
 * return:
 *	SUCCESS	-> successful protocol selection
 *	FAIL	-> can't find common or open failed
 */
int
startup(void)
{
	extern void blptcl();
	extern int fptcl();
	char msg[BUFSIZ], str[BUFSIZ];

	Rdmsg = imsg;
	Wrmsg = omsg;
	Turnoff = turnoff;
	blptcl(str);
	if (Role == MASTER) {
		RMESG(SLTPTCL, msg);
		if ( fptcl(&msg[1], str) == FAIL) {
		    /* no protocol match */
		    WMESG(USEPTCL, NO);
		    return(FAIL);
		} else {
		    /* got protocol match */
		    WMESG(USEPTCL, &msg[1]);
		    return(stptcl(&msg[1]));
		}
	} else {
		WMESG(SLTPTCL, str);
		RMESG(USEPTCL, msg);
		if ( fptcl(&msg[1], str) == FAIL ) {
			return(FAIL);
		} else {
		    return(stptcl(&msg[1]));
		}
	}
}

/*
 * choose a protocol from the input string (str)
 * and return the found letter.
 * Use the MASTER string (valid) for order of selection.
 * return:
 *	'\0'		-> no acceptable protocol
 *	any character	-> the chosen protocol
 */
int
fptcl(str, valid)
char *str, *valid;
{
	char *l;

	DEBUG(9, "Slave protocol list(%s)\n", str);
	DEBUG(9, "Master protocol list(%s)\n", valid);

	for (l = valid; *l != '\0'; l++) {
		if ( strchr(str, *l) != NULL) {
		    *str = *l;
		    *(str+1) = '\0';
		    /* also update string with parms */
		    strcpy(_Protocol, findProto(_Protocol, *str));
		    return(SUCCESS);
		}
	}
	return(FAIL);
}

/*
 * build a string of the letters of the available
 * protocols and return the string (str).  The string consists of protocols
 * that are specified in the Systems and Devices files.  If nothing was
 * specified in those files, then the string is the list of protocols from
 * our Ptble.
 *
 *	str =		place to put the protocol list
 *	length =	size of buffer at str
 *
 * return:
 *	a pointer to string (str)
 */
void
blptcl(str)
char *str;
{
	struct Proto *p;
	char *validPtr;

	/* Build list of valid protocols. */
	for (validPtr = str, p = Ptbl; (*validPtr = p->P_id) != NULLCHAR;
		validPtr++, p++);

	/* Build _Protocol */
	(void) protoString(str);	/* Get desired protocols. */
	return;
}

/*
 * set up the six routines (Rdmg. Wrmsg, Rddata
 * Wrdata, Turnon, Turnoff) for the desired protocol.
 * returns:
 *	SUCCESS 	-> ok
 *	FAIL		-> no find or failed to open
 */
int
stptcl(c)
char *c;
{
	struct Proto *p;

	for (p = Ptbl; p->P_id != '\0'; p++) {
		if (*c == p->P_id) {

			/*
			 * found protocol 
			 * set routine
			 */
			Rdmsg = p->P_rdmsg;
			Wrmsg = p->P_wrmsg;
			Rddata = p->P_rddata;
			Wrdata = p->P_wrdata;
			Turnon = p->P_turnon;
			Turnoff = p->P_turnoff;
			if ((*Turnon)() != 0)
				break;
			CDEBUG(4, "Proto started %c\n", *c);
			pfPtcl(c);
			return(SUCCESS);
		}
	}
	CDEBUG(4, "Proto start-fail %c\n", *c);
	return(FAIL);
}

/*
 * unlink D. file
 * returns:
 *	none
 */
void
unlinkdf(file)
char *file;
{
	if (strlen(file) > (size_t) 6)
		(void) unlink(file);
	return;
}

/*
 * notify receiver of arrived file
 * returns:
 *	none
 */
void
arrived(opt, file, nuser, rmtsys, rmtuser)
char *file, *nuser, *rmtsys, *rmtuser;
{
	char mbuf[200];

	if (!opt)
		return;
	(void) sprintf(mbuf, "%s from %s!%s arrived\n", file, rmtsys, rmtuser);
	mailst(nuser, mbuf, mbuf, "", "");
	return;
}


/*
 * Check to see if there is space for file
 */

#define FREESPACE 50  /* Minimum freespace in blocks to permit transfer */
#define FREENODES 5   /* Minimum number of inodes to permit transfer */

/*ARGSUSED*/
static int
nospace(name)
char *name;
#ifdef NOUSTAT
{return(FALSE);}
#else
{
	struct stat statb;
#ifdef STATFS
	struct statfs statfsb;
#else
	struct ustat ustatb;
#endif

	if( stat(name, &statb) < 0 )
		return(TRUE);
#ifdef	RT
	if( (statb.st_mode|S_IFMT) == S_IFREG ||
	    (statb.st_mode|S_IFMT) == S_IFEXT ||
	    (statb.st_mode&S_IFMT) == S_IF1EXT )
#else
	if( (statb.st_mode&S_IFMT) == S_IFREG )
#endif
	{
#ifdef STATFS
		if( statfs(name, &statfsb)<0 )
#else
		if( ustat(statb.st_dev, &ustatb)<0 )
#endif
			return(TRUE);
#ifdef STATFS
		/*
		 * Use 512-byte blocks, because that's the unit "ustat" tends
		 * to work in.
		 */
		if( ((statfsb.f_bavail*statfsb.f_bsize)/512) < FREESPACE )
#else
		if( ustatb.f_tfree < FREESPACE )
#endif
		{
			logent("FREESPACE IS LOW","REMOTE TRANSFER DENIED - ");
			return(TRUE);
		}
#ifdef STATFS
		/*
		 * The test for "> 0" is there because the @$%#@#@$ NFS
		 * protocol doesn't pass the number of free files over the
		 * wire, so "statfs" on an NFS file system always returns -1.
		 */
		if( statfsb.f_ffree > 0
		    && statfsb.f_ffree < FREENODES )
#else
		if( ustatb.f_tinode < FREENODES )
#endif
		{
			logent("TOO FEW INODES","REMOTE TRANSFER DENIED - ");
			return(TRUE);
		}
	}
	return(FALSE);
}
#endif

#ifdef V7USTAT
int
ustat(dev, ustat)
int	dev;
struct ustat *ustat;
{
	FILE	*dfp, *popen();
	char	*fval, buf[BUFSIZ];

	sprintf(buf, "%s %d %d 2>&1", V7USTAT, major(dev), minor(dev));
	if ((dfp = popen(buf, "r")) == NULL)
		return(-1);
	fval = fgets(buf, sizeof(buf), dfp);
	if (pclose(dfp) != 0
	 || fval == NULL
	 || sscanf(buf, "%d %d", &ustat->f_tfree, &ustat->f_tinode) != 2)
		return(-1);
	return(0);
}
#endif	/* V7USTAT */
