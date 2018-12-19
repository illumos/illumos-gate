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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 *  setuname [-t] [-s name] [-n node] 
 */

/*
 *  Header files referenced:
 *	<stdio.h>	Standard I/O 
 *	<unistd.h>	Standard UNIX definitions
 *	<string.h>	String handling 
 *	<fmtmsg.h>	Standard message generation 
 *	<ctype.h>	Character types
 *	<errno.h>	Error handling
 *	<signal.h>	Signal handling 
 *	<sys/types.h>	Data types
 *	<sys/fcntl.h>	File control
 *	<sys/utsname.h>	System Name
 *	<sys/sys3b.h>	sys3b() definitions
 *	<nlist.h>	Definitions for Sun symbol table entries
 */

#include	<stdio.h>
#include	<unistd.h>
#include	<string.h>
#include	<fmtmsg.h>
#include	<ctype.h>
#include	<errno.h>
#include	<signal.h>
#include	<sys/types.h>
#include	<sys/uio.h>
#include	<sys/fcntl.h>
#include	<sys/psw.h>
#include	<sys/utsname.h>

#if u3b || u3b15 || u3b2
#include	<sys/sys3b.h>
#endif

#if sun
#include	<nlist.h>
#include	<kvm.h>
#endif

/*
 * Externals referenced (and not defined in a header)
 *	optind		index to the next arg for getopt()
 *	opterr		FLAG, TRUE tells getopt() to write messages
 *	optarg		Ptr to an option's argument
 *	getopt()	Gets an option from the command line
 *	putenv()	Writes values into the environment
 *	exit()		Exit the process
 *	access()	Check accessibility of a file
 *	malloc()	Allocate a block of main memory
 *	free()		Free allocated space
 *	lseek()		Seek within a file 
 *	open()		Open a file
 *	close()		Close an open file
 */
 
extern	int		optind;		/* argv[] index of next arg */
extern	int		opterr;		/* TRUE if getopt() is to print msgs */
extern	char	       *optarg;		/* Argument to parsed option */
extern	int		getopt();	/* Get an option from the command line */
extern	int	       	putenv();	/* Put a value into the environment */
extern	void		exit();		/* Exit the process */
extern	int		access();	/* Check the accessibility of a file */
extern	void	       *malloc();	/* Get a chunk of main memory */
extern	void		free();		/* Free alloc'd space */
extern	long		lseek();	/* Seek within a file */
extern	int		open();		/* Open a file */
extern	int		close();	/* Close an open a file */

/*
 *  L O C A L   D E F I N I T I O N S
 */

/*
 * Constants 
 */

#ifndef	TRUE
#define	TRUE		(1)
#endif

#ifndef	FALSE
#define	FALSE		(0)
#endif

#ifndef	NULL
#define	NULL		(0)
#endif

#define	OPTSTRING	"tn:s:"

#define	EX_OK		0
#define	EX_ERROR	1

#define	RC_FILENAME	"/etc/rc2.d/S18setuname"
#define RC_DIRNAME	"/etc/rc2.d"


/*
 *  Messages
 */

#define	E_USAGE		"usage: setuname [-t] [-s name] [-n node]"
#define	E_MISSING	"Either -s name or -n node must be specified"
#define	E_UNAME		"Unable to get existing uname values"
#define E_INVNAME	"System-name invalid: %s"
#define E_LONGNAME	"System-name too long: %s"
#define E_INVNODE	"Network node-name invalid: %s"
#define E_LONGNODE	"Network node-name too long: %s"
#define E_NOPERMS	"No permissions, request denied"
#define E_NOSUCHDIR	"Directory doesn't exist: %s"
#define	E_INTERNAL	"Internal error: %d"

/*
 * Macros:
 *	stdmsg(r,l,s,t)	    Write a standard message.  
 *				'r' is the recoverability flag
 *				'l' is the label
 *				's' is the severity 
 *				't' is the text.
 *	strend(p)	    Return the address of the end of a string
 *			    (This is supposed to be defined in <sys/inline.h>
 *			    but that file has string-handing def'ns that
 *			    conflict with <string.h>, so we can't use it!
 *			    MR dn89-04701 requests this fix.
 */
 
#define	stdmsg(r,l,s,t)	(void) fmtmsg(MM_PRINT|MM_UTIL|r,l,s,t,MM_NULLACT,MM_NULLTAG)
#define strend(p)       strrchr(p,'\0')

/*
 * Local functions:
 *	setuname	Changes the system name and the network node name 
 */

static int	setuname();		/* This does the "real" work */


/*
 * Local data
 *	lbl		Buffer for the standard message label
 *	txt		Buffer for the standard message text
 */
 
static	char		lbl[MM_MXLABELLN+1];	/* Space for std msg label */
static	char		msg[MM_MXTXTLN+1];	/* Space for std msg text  */

/*
 *  int main(argc, argv)
 *	int	argc
 *	char   *argv;
 */

int 
main(argc, argv)
	int	argc;			/* Argument count  */
	char   *argv[];			/* Argument vector */
{
	/* Automatic data */
	char	       *n_arg;			/* Ptr to arg for -n */
	char	       *s_arg;			/* Ptr to arg for -s */
	int		t_seen;			/* FLAG, -t option seen */
	char	       *cmdname;		/* Ptr to the command's name */
	char	       *p;			/* Temp pointer */
	int		usageerr;		/* FLAG, TRUE if usage error */
	int		exitcode;		/* Value to exit with */
	int		c;			/* Temp character */
	int		ok;			/* Flag, everything okay? */

	/* Build the standard-message label */
	if (p = strrchr(argv[0], '/')) cmdname = p+1;
	else cmdname = argv[0];
	(void) strcat(strcpy(lbl, "UX:"), cmdname);

	/* Make only the text in standard messages appear (SVR4.0 only) */
	(void) putenv("MSGVERB=text");

	
	/* Initializations */
	n_arg = s_arg = (char *) NULL;
	t_seen = FALSE;


	/* 
	 * Parse command 
	 */

	usageerr = FALSE;
	opterr = FALSE;
	while (!usageerr && (c = getopt(argc, argv, OPTSTRING)) != EOF) switch(c) {

	case 'n':			/* -n node */
	    if (n_arg) usageerr = TRUE;
	    else n_arg = optarg;
	    break;

	case 's':			/* -s name */
	    if (s_arg) usageerr = TRUE;
	    else s_arg = optarg;
	    break;

	case 't':			/* -t */
	    if (t_seen) usageerr = TRUE;
	    else t_seen = TRUE;
	    break;
	    
	default:			/* Something that doesn't exist */
	    usageerr = TRUE;
	}   /* switch() */

	/* If there was a usage error, report the error and exit */
	if ((argc >= (optind+1)) || usageerr) {
	    stdmsg(MM_NRECOV, lbl, MM_ERROR, E_USAGE);
	    exit(EX_ERROR);
	}

	/* Either -n <node> or -s <name> has to be specified */
	if (!(n_arg || s_arg)) {
	    stdmsg(MM_NRECOV, lbl, MM_ERROR, E_MISSING);
	    exit(EX_ERROR);
	}


	/* 
	 * Validate arguments:
	 *  - The length of the system name must be less than SYS_NMLN-1
	 *    characters,
	 *  - The length of the network node-name must be less than 
	 *    SYS_NMLN-1 characters,
	 *  - The system name must equal [a-zA-Z0-9-_]+,
	 *  - The network node-name must equal [a-zA-Z0-9-_]+.
	 */

	/* Check the length and the character-set of the system name */
	if (s_arg) {

	    /* Check length of the system name */
	    if (strlen(s_arg) > (size_t)(SYS_NMLN-1)) {
		(void) sprintf(msg, E_LONGNAME, s_arg);
		stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
		exit(EX_ERROR);
	    }

	    /* Check the character-set */
	    ok = TRUE;
	    for (p = s_arg ; ok && *p ; p++) {
		if (!isalnum(*p) && (*p != '-') && (*p != '_')) ok = FALSE;
	    }
	    if (!ok || (p == s_arg)) {
		(void) sprintf(msg, E_INVNAME, s_arg);
		stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
		exit(EX_ERROR);
	    }
	}

	/* Check the length and the character-set of the network node-name */

	if (n_arg) {

	    /* Check length of the network node-name */
	    if (strlen(n_arg) > (size_t)(SYS_NMLN-1)) {
		(void) sprintf(msg, E_LONGNODE, n_arg);
		stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
		exit(EX_ERROR);
	    }

	    /* Check the character-set */
	    ok = TRUE;
	    for (p = n_arg ; ok && *p ; p++) {
		if (!isalnum(*p) && (*p != '-') && (*p != '_')) ok = FALSE;
	    }
	    if (!ok || (p == n_arg)) {
		(void) sprintf(msg, E_INVNODE, n_arg);
		stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
		exit(EX_ERROR);
	    }
	}


	/*
	 * Make sure we have access to needed resources:
	 *   -  Read/write access to kernel memory (/dev/kmem)
	 *   -  If -t is not specified, read/write access to /etc/rc2.d
	 *   -  If -t is not specified, read access to /etc/rc2.d/S18setuname
	 */
	
	if (access("/dev/kmem", R_OK|W_OK) == 0) {
	    if (access(RC_DIRNAME, R_OK|W_OK) == 0) {
		if ((access(RC_FILENAME, R_OK) != 0) && 
		    (access(RC_FILENAME, F_OK) == 0)) {
		    stdmsg(MM_NRECOV, lbl, MM_ERROR, E_NOPERMS);
		    exit(EX_ERROR);
		}
	    } 
	    else {
		if (access(RC_DIRNAME, F_OK) == 0) {
		    stdmsg(MM_NRECOV, lbl, MM_ERROR, E_NOPERMS);
		    exit(EX_ERROR);
		} 
		else {
		    (void) sprintf(msg, E_NOSUCHDIR, RC_DIRNAME);
		    stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
		    exit(EX_ERROR);
		}
	    }
	} 
	else {
	    stdmsg(MM_NRECOV, lbl, MM_ERROR, E_NOPERMS);
	    exit(EX_ERROR);
	}


	/* Attempt the setuname */
	if (setuname(t_seen, s_arg, n_arg) == 0) exitcode = EX_OK;
	else {
	    (void) sprintf(msg, E_INTERNAL, errno);
	    stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
	    exitcode = EX_ERROR;
	}

	/* Finished */
	return (exitcode);
}  /* main() */

/*
 * int setuname(temp, name, node)
 *	int	temp
 *	char   *name
 *	char   *node
 *
 *	Set any or all of the following machine parameters, either
 *	temporarily or permanently, depending on <temp>.
 *	    - System name
 *	    - Network Node-name
 */

static int 
setuname(temp, sysname, nodename)
	int	temp;		/* Set in kernel only flag */
	char   *sysname;	/* System name */
	char   *nodename;	/* Network node-name */
{
	/* Automatic Data */
	struct utsname	utsname;	/* Space for the kernel's utsname information */
#if u3b || u3b15 || u3b2
	struct s3bsym  *symbtbl;	/* The kernel's symbol table */
#endif
#if sun
	struct nlist nl[] = {
		{"utsname", 0, 0, 0, 0, 0},
		{NULL}
	};
	kvm_t *kd;
#endif
	uintptr_t	utsname_addr;	/* Addr of "utsname" in the kernel */
	char	       *sysnm = (char *)NULL;		/* System name to set (from file or arg) */
	char	       *nodenm = (char *)NULL;		/* Network node-name to set (from file or arg) */
	FILE	       *fd;		/* Std I/O File Descriptor for /etc/rc2.d/S18setuname */
	char	       *p;		/* Temp pointer */
	void	      (*oldsighup)();	/* Function to call for SIGHUP */
	void	      (*oldsigint)();	/* Function to call for SIGINT */
	int		rtncd;		/* Value to return to the caller */
	unsigned long	symbtblsz;	/* The size of the kernel's symbol table, in bytes */
	int		memfd;		/* File descriptor:  open kernel memory */
	int		i;		/* Temp counter */	


	/* Nothing's gone wrong yet (but we've only just begun!) */
	rtncd = 0;


	/*
	 * Get the virtual address of the symbol "utsname" in the kernel
	 * so we can get set the system name and/or the network node-name
	 * directly in the kernel's memory space.
	 */

#if u3b || u3b15 || u3b2
	if ((sys3b(S3BSYM, (struct s3bsym *) &symbtblsz, sizeof(symbtblsz)) == 0) &&
	    (symbtbl = (struct s3bsym *) malloc(symbtblsz))) {

	    (void) sys3b(S3BSYM, symbtbl, symbtblsz);
	    p = (char *) symbtbl;
	    for (i = symbtbl->count; i-- && (strcmp(p, "utsname") != 0) ; p = S3BNXTSYM(p)) ;
	    if (i >= 0) utsname_addr = S3BSVAL(p);
	    else rtncd = -1;
	    free((void *) symbtbl);

	} else rtncd = -1;

#elif sun
        /* Check out namelist and memory files. */
	if ((kd = kvm_open(NULL, NULL, NULL, O_RDWR, NULL)) == NULL)
		rtncd = -1;
	else if (kvm_nlist(kd, nl) != 0)
		rtncd = -1;
	else if (nl[0].n_value == 0)
		rtncd = -1;
	else
		utsname_addr = (uintptr_t)nl[0].n_value;
#else
	if (nlist("/unix", nl) != 0)
		rtncd = -1;
#endif
	if (rtncd != 0) return(rtncd);

	/* 
	 * Open the kernel's memory, get the existing "utsname" structure,
	 * change the system name and/or the network node-name in that struct,
	 * write it back out to kernel memory, then close kernel memory.
	 */
#ifdef sun
	if (kvm_kread(kd, utsname_addr, &utsname, sizeof (utsname)) ==
	    sizeof (utsname)) {
		if (sysname)
			(void) strncpy(utsname.sysname, sysname,
			    sizeof (utsname.sysname));
		if (nodename)
			(void) strncpy(utsname.nodename, nodename,
			    sizeof (utsname.nodename));
		(void) kvm_kwrite(kd, utsname_addr, &utsname, sizeof (utsname));
		(void) kvm_close(kd);
	} else
		return (-1);
#else /* sun */
	if ((memfd = open("/dev/kmem", O_RDWR, 0)) > 0) {
	    if ((lseek(memfd, (long) utsname_addr, SEEK_SET) != -1) && 
		(read(memfd, &utsname, sizeof(utsname)) == sizeof(utsname))) {
		if (sysname) (void) strncpy(utsname.sysname, sysname, sizeof(utsname.sysname));
		if (nodename) (void) strncpy(utsname.nodename, nodename, sizeof(utsname.nodename));
		(void) lseek(memfd, (long) utsname_addr, SEEK_SET);
		(void) write(memfd, &utsname, sizeof(utsname));
		(void) close(memfd);
	    } else rtncd = -1;
	} else rtncd = -1;
	if (rtncd != 0) return(rtncd);
#endif /* sun */


	/*
	 * If the "temp" flag is FALSE, we need to permanently set the
	 * system name in the file  /etc/rc2.d/S18setuname
	 */

	if (!temp) {
	    /* 
	     * If a name was specified by the caller, use that, otherwise, use
	     * whatever was in the "rc" file.
	     */

		if (sysname) sysnm = sysname;
		if (nodename) nodenm = nodename;


	    /* 
	     * Write the file /etc/rc2.d/S18setuname so that the system name is
	     * set on boots and state changes.  
	     *
	     * DISABLED SIGNALS: SIGHUP, SIGINT
	     */

	    /* Give us a reasonable chance to complete without interruptions */
		oldsighup = signal(SIGHUP, SIG_IGN);
		oldsigint = signal(SIGINT, SIG_IGN);

	    /* Write the new setuname "rc" file */
		if (sysname != NULL) {
			if ((fd = fopen(RC_FILENAME, "w")) != (FILE *) NULL) {
				(void) fprintf(fd, "# %s\n", sysnm);
				(void) fprintf(fd, "#\n");
				(void) fprintf(fd, "# This script, generated by the setuname command,\n");
				(void) fprintf(fd, "# sets the system's system-name\n");
				(void) fprintf(fd, "#\n");
				if (sysnm && *sysnm)
					(void) fprintf(fd, "setuname -t -s %s\n", sysnm);
				(void) fclose(fd);
			} else return(rtncd = -1);
		}

		if(nodename != NULL) {
			char curname[SYS_NMLN];
			int curlen;
			FILE *file;

			if ((file = fopen("/etc/nodename", "r")) != NULL) {
				curlen = fread(curname, sizeof(char), SYS_NMLN, file);
				for (i = 0; i < curlen; i++) {
					if (curname[i] == '\n') {
						curname[i] = '\0';
						break;
					}
				}
				if (i == curlen) {
					curname[curlen] = '\0';
				}
				(void)fclose(file);
			} else {
				curname[0] = '\0';
			}
			if (strcmp(curname, nodenm) != 0) {
				if ((file = fopen("/etc/nodename", "w")) == NULL) {
					(void) fprintf(stderr, "setuname: error in writing name\n");
					exit(1);
				} 
				if (fprintf(file, "%s\n", nodenm) < 0) {
					(void) fprintf(stderr, "setuname: error in writing name\n");
					exit(1);
				}
				(void)fclose(file);
			}		
		}
	    /* Restore signal handling */
		(void) signal(SIGHUP, oldsighup);
		(void) signal(SIGINT, oldsigint);
	}	/* if (!temp) */

	/* Fini */
	return(rtncd);
}
