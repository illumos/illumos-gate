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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Included files
 */
#include <arpa/inet.h>
#include <mk/defs.h>
#include <mksh/misc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <rpc/rpc.h>		/* host2netname(), netname2host() */
#include <libintl.h>

/*
 * Defined macros
 */

/*
 * typedefs & structs
 */

/*
 * Static variables
 */

/*
 * File table of contents
 */
static int		get_max(wchar_t **ms_address, wchar_t *hostname);
static Boolean		pskip_comment(wchar_t **cp_address);
static void		pskip_till_next_word(wchar_t **cp);
static Boolean		pskip_white_space(wchar_t **cp_address);


/*
 *	read_make_machines(Name make_machines_name)
 *
 *	For backwards compatibility w/ PMake 1.x, when DMake 2.x is
 *	being run in parallel mode, DMake should parse the PMake startup
 *	file $(HOME)/.make.machines to get the PMake max jobs.
 *
 *	Return value:
 *		int of PMake max jobs
 *
 *	Parameters:
 *		make_machines_name	Name of .make.machines file
 *
 */
int
read_make_machines(Name make_machines_name)
{
	wchar_t 		c;
	Boolean			default_make_machines;
	struct hostent		*hp;
	wchar_t			local_host[MAX_HOSTNAMELEN + 1];
	char			local_host_mb[MAX_HOSTNAMELEN + 1] = "";
	int			local_host_wslen;
	wchar_t			full_host[MAXNETNAMELEN + 1];
	int			full_host_wslen = 0;
	char			*homedir;
	Name			MAKE_MACHINES;
	struct stat		make_machines_buf;
	FILE			*make_machines_file;
	wchar_t			*make_machines_list = NULL;
	char			*make_machines_list_mb = NULL;
	wchar_t			make_machines_path[MAXPATHLEN];
	char			mb_make_machines_path[MAXPATHLEN];
	wchar_t			*mp;
	wchar_t			*ms;
	int			pmake_max_jobs = 0;
	struct utsname		uts_info;


	MBSTOWCS(wcs_buffer, "MAKE_MACHINES");
	MAKE_MACHINES = GETNAME(wcs_buffer, FIND_LENGTH);
	/* Did the user specify a .make.machines file on the command line? */
	default_make_machines = false;
	if (make_machines_name == NULL) {
		/* Try reading the default .make.machines file, in $(HOME). */
		homedir = getenv("HOME");
		if ((homedir != NULL) && (strlen(homedir) < (sizeof(mb_make_machines_path) - 16))) {
			sprintf(mb_make_machines_path,
			 "%s/.make.machines", homedir);
			MBSTOWCS(make_machines_path, mb_make_machines_path);
			make_machines_name = GETNAME(make_machines_path, FIND_LENGTH);
			default_make_machines = true;
		}
		if (make_machines_name == NULL) {
			/*
			 * No $(HOME)/.make.machines file.
			 * Return 0 for PMake max jobs.
			 */
			return(0);
		}
	}
/*
	make_machines_list_mb = getenv(MAKE_MACHINES->string_mb);
 */
	/* Open the .make.machines file. */
	if ((make_machines_file = fopen(make_machines_name->string_mb, "r")) == NULL) {
		if (!default_make_machines) {
			/* Error opening .make.machines file. */
			fatal(gettext("Open of %s failed: %s"),
			      make_machines_name->string_mb,
			      errmsg(errno));
		} else {
			/*
			 * No $(HOME)/.make.machines file.
			 * Return 0 for PMake max jobs.
			 */
			return(0);
		}
	/* Stat the .make.machines file to get the size of the file.  */
	} else if (fstat(fileno(make_machines_file), &make_machines_buf) < 0) {
		/* Error stat'ing .make.machines file. */
		fatal(gettext("Stat of %s failed: %s"),
		      make_machines_name->string_mb,
		      errmsg(errno));
	} else {
		/* Allocate memory for "MAKE_MACHINES=<contents of .m.m>" */
		make_machines_list_mb =
		  (char *) getmem((int) (strlen(MAKE_MACHINES->string_mb) +
		                         2 +
		                         make_machines_buf.st_size));
		sprintf(make_machines_list_mb,
			"%s=",
			MAKE_MACHINES->string_mb);
		/* Read in the .make.machines file. */
		if (fread(make_machines_list_mb + strlen(MAKE_MACHINES->string_mb) + 1,
			  sizeof(char),
			  (int) make_machines_buf.st_size,
			  make_machines_file) != make_machines_buf.st_size) {
			/*
			 * Error reading .make.machines file.
			 * Return 0 for PMake max jobs.
			 */
			warning(gettext("Unable to read %s"),
				make_machines_name->string_mb);
			(void) fclose(make_machines_file);
			retmem_mb((caddr_t) make_machines_list_mb);
			return(0);
		} else {
			(void) fclose(make_machines_file);
			/* putenv "MAKE_MACHINES=<contents of .m.m>" */
			*(make_machines_list_mb +
			  strlen(MAKE_MACHINES->string_mb) +
			  1 +
			  make_machines_buf.st_size) = (int) nul_char;
			if (putenv(make_machines_list_mb) != 0) {
				warning(gettext("Couldn't put contents of %s in environment"),
					make_machines_name->string_mb);
			} else {
				make_machines_list_mb += strlen(MAKE_MACHINES->string_mb) + 1;
				make_machines_list = ALLOC_WC(strlen(make_machines_list_mb) + 1);
				(void) mbstowcs(make_machines_list,
				                make_machines_list_mb,
				                (strlen(make_machines_list_mb) + 1));
			}
		}
	}

	uname(&uts_info);
	strcpy(local_host_mb, &uts_info.nodename[0]);
	MBSTOWCS(local_host, local_host_mb);
	local_host_wslen = wcslen(local_host);

	// There is no getdomainname() function on Solaris.
	// And netname2host() function does not work on Linux.
	// So we have to use different APIs.
	if (host2netname(mbs_buffer, NULL, NULL) &&
	    netname2host(mbs_buffer, mbs_buffer2, MAXNETNAMELEN+1)) {
		MBSTOWCS(full_host, mbs_buffer2);
		full_host_wslen = wcslen(full_host);
	}

	for (ms = make_machines_list;
	     (ms) && (*ms );
	     ) {
		/*
		 * Skip white space and comments till you reach
		 * a machine name.
		 */
		pskip_till_next_word(&ms);

		/*
		 * If we haven't reached the end of file, process the
		 * machine name.
		 */
		if (*ms) {
			/* 
			 * If invalid machine name decrement counter 
			 * and skip line.
			 */
			mp = ms;
			SKIPWORD(ms);
			c = *ms;
			*ms++ = '\0'; /* Append null to machine name. */
			/*
			 * If this was the beginning of a comment
			 * (we overwrote a # sign) and it's not
			 * end of line yet, shift the # sign.
			 */
			if ((c == '#') && (*ms != '\n') && (*ms)) {
				*ms = '#';
			}
			WCSTOMBS(mbs_buffer, mp);
			/*
			 * Print "Ignoring unknown host" if:
			 * 1) hostname is longer than MAX_HOSTNAMELEN, or
			 * 2) hostname is unknown
			 */
			if ((wcslen(mp) > MAX_HOSTNAMELEN) ||
			    ((hp = gethostbyname(mbs_buffer)) == NULL)) {
				warning(gettext("Ignoring unknown host %s"),
					mbs_buffer);
				SKIPTOEND(ms);
				/* Increment ptr if not end of file. */
				if (*ms) {
					ms++;
				}
			} else {
				/* Compare current hostname with local_host. */
				if (wcslen(mp) == local_host_wslen &&
				    IS_WEQUALN(mp, local_host, local_host_wslen)) {
					/*
					 * Bingo, local_host is in .make.machines.
					 * Continue reading.
					 */
					pmake_max_jobs = PMAKE_DEF_MAX_JOBS;
				/* Compare current hostname with full_host. */
				} else if (wcslen(mp) == full_host_wslen &&
					   IS_WEQUALN(mp, full_host, full_host_wslen)) {
					/*
					 * Bingo, full_host is in .make.machines.
					 * Continue reading.
					 */
					pmake_max_jobs = PMAKE_DEF_MAX_JOBS;
				} else {
					if (c != '\n') {
					    SKIPTOEND(ms);
					    if (*ms) {
						ms++;
					    }
					}
					continue;
				}
				/* If we get here, local_host is in .make.machines. */
				if (c != '\n')  {
					/* Now look for keyword 'max'. */
					MBSTOWCS(wcs_buffer, "max");
					SKIPSPACE(ms);
					while ((*ms != '\n') && (*ms)) {
						if (*ms == '#') {
							pskip_comment(&ms);
						} else if (IS_WEQUALN(ms, wcs_buffer, 3)) {
							/* Skip "max". */
							ms += 3; 
							pmake_max_jobs = get_max(&ms, mp); 
							SKIPSPACE(ms);
						} else {
							warning(gettext("unknown option for host %s"), mbs_buffer);
							SKIPTOEND(ms);
							break;
						}
					}
				}
				break; /* out of outermost for() loop. */
			}
		}
	}
	retmem(make_machines_list);
	return(pmake_max_jobs);
}

/*
 *	pskip_till_next_word(cp)
 *
 *	Parameters:
 *		cp		the address of the string pointer.
 *
 *	On return:
 *		cp		points to beginning of machine name.
 *
 */
static void
pskip_till_next_word(wchar_t **cp)
{
	/*
	 * Keep recursing until all combinations of white spaces
	 * and comments have been skipped.
	 */
	if (pskip_white_space(cp) || pskip_comment(cp)) {
		pskip_till_next_word(cp);
	}
}

/*
 *	pskip_white_space(cp_address)
 *
 *	Advances the string pointer so that it points to the first
 *	non white character (space/tab/linefeed).
 *
 *	Parameters:
 *		cp_address	the address of the string pointer.
 *
 *	Return Value:
 *				True if the pointer was changed.
 *
 */
static Boolean
pskip_white_space(wchar_t **cp_address)
{
	wchar_t		*cp = *cp_address;

	while (*cp && iswspace(*cp)) {
		cp++;
	}
	/* Have we skipped any characters? */
	if (cp != *cp_address) {
		*cp_address = cp;
		return(true);
	} else {
		return(false);
	}
}

/*
 *	pskip_comment(cp_address)
 *
 *	If cp_address is pointing to '#' (the beginning of a comment),
 *	increment the pointer till you reach end of line.
 *
 *	Parameters:
 *		cp_address	the address of the string pointer.
 *
 *	Return Value:
 *				True if the pointer was changed.
 *
 */
static Boolean
pskip_comment(wchar_t **cp_address)
{
	wchar_t		*cp = *cp_address;

	/* Is this the beginning of a comment? Skip till end of line. */
	if (*cp == '#') {
		SKIPTOEND(cp);
	}
	/* Have we skipped a comment line? */
	if (cp != *cp_address)	{
		*cp_address = cp;
		return(true);
	} else {
		return(false);
	}
}

static int
get_max(wchar_t **ms_address, wchar_t *hostname)
{
	wchar_t 	*ms = *ms_address;
	int		limit = PMAKE_DEF_MAX_JOBS; /* Default setting. */

	WCSTOMBS(mbs_buffer, hostname);
	/* Look for `='. */
	SKIPSPACE(ms);
	if ((!*ms) || (*ms == '\n') || (*ms != '=')) {
		SKIPTOEND(ms);
		warning(gettext("expected `=' after max, ignoring rest of line for host %s"),
			mbs_buffer);
		*ms_address = ms;
		return((int) limit);
	} else {
		ms++;
		SKIPSPACE(ms);
		if ((*ms != '\n') && (*ms != '\0')) {
			/* We've found, hopefully, a valid "max" value. */
			limit = (int) wcstol(ms, &ms, 10);
			if (limit < 1) {
				limit = PMAKE_DEF_MAX_JOBS;
				warning(gettext("max value cannot be less than or equal to zero for host %s"), mbs_buffer);
			}
		} else {
			/* No "max" value after "max=". */
			warning(gettext("no max value specified for host %s"), mbs_buffer);
		}
		*ms_address = ms;
		return(limit);
	}
}


