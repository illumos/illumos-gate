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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*LINTLIBRARY*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <rpcsvc/ypclnt.h>

char glob_stdout[BUFSIZ];
char glob_stderr[BUFSIZ];

void f_cleanup(FILE *fp, char *tmpf);
void fd_cleanup(int fd1, int fd2);
static void _freeList(char ***list);

extern void **list_append(void **list, void *item);

#ifdef MAIN

#define	THOSTNAME "cherwell"
#define	TPRINTERNAME "c"

int
main() {
	char *host = THOSTNAME;
	const char *user = "cn=Directory Manager";
	const char *passwd = "directorymanager";
	int result = 0;

	result = _updateldap("add", host, user, passwd,
		    "_pmTestAuthToken", NULL, NULL, "new comment", "false");
	if (result != 0) {
		printf("Add 1 failed, err code = %d\n");
	}

	result = _updateldap("delete", host, user, passwd,
		    "_pmTestAuthToken", NULL, NULL, NULL, "false");
	if (result != 0) {
		printf("Delete 1 failed, err code = %d\n");
	}

	result = _updateldap("delete", host, user, passwd, TPRINTERNAME,
			THOSTNAME, "", "new comment", "true");
	if (result != 0) {
		printf("delete failed, err code = %d\n");
	}

	result = _updateldap("delete", host, user, passwd, "_default",
			THOSTNAME, "", "new comment", "true");
	if (result != 0) {
		printf("delete failed, err code = %d\n");
	}

	result = _updateldap("add", host, user, passwd, TPRINTERNAME,
			THOSTNAME, "Solaris", "new comment", "true");
	if (result != 0) {
		printf("add failed, err code = %d\n");
	}

	result = _updateldap("modify", host, user, passwd, TPRINTERNAME,
			THOSTNAME, "", "modified comment", "true");
	if (result != 0) {
		printf("modify failed, err code = %d\n");
	}

	result = _updateldap("modify", host, user, passwd, TPRINTERNAME,
			THOSTNAME, "", NULL, "false");
	if (result != 0) {
		printf("modify failed, err code = %d\n");
	}


	exit(0);
}
#endif


int
_dorexec(
	const char *host,
	const char *user,
	const char *passwd,
	const char *cmd,
	const char *locale) {

	int ret = 0;
	int fd = 0;
	int fd2 = 1;

	FILE *fderr;
	char *ferr;

	(void) memset(glob_stdout, 0, BUFSIZ);
	(void) memset(glob_stderr, 0, BUFSIZ);

	/*
	 * Re-direct stderr to a file
	 */
	ferr = tempnam(NULL, NULL);
	if (ferr != NULL) {
		fderr = freopen(ferr, "w+", stderr);
	}

	fd = rexec((char **)&host, htons(512), user,
	    passwd, cmd, &fd2);

	if (fd > -1) {
		/*
		 * rexec worked. Clean up stderr file.
		 */
		f_cleanup(fderr, ferr);

		ret = read(fd, glob_stdout, BUFSIZ - 1);
		if (ret < 0) {
			(void) strncpy(glob_stderr, strerror(errno),
			    (BUFSIZ - 1));
			fd_cleanup(fd, fd2);
			return (errno);
		}

		ret = read(fd2, glob_stderr, BUFSIZ - 1);
		if (ret < 0) {
			(void) strncpy(glob_stderr, strerror(errno),
			    (BUFSIZ - 1));
			fd_cleanup(fd, fd2);
			return (errno);
		}
	} else {
		/*
		 * rexec failed. Read from the stderr file.
		 */
		if (fderr != NULL) {
			char tmpbuf[BUFSIZ];

			(void) rewind(fderr);
			strcpy(glob_stderr, "");
			while (fgets(tmpbuf, BUFSIZ - 1,
			    fderr) != NULL) {
				if ((strlen(glob_stderr) +
				    strlen(tmpbuf)) > BUFSIZ - 1) {
					break;
				} else {
					(void) strcat(glob_stderr, tmpbuf);
				}
			}
		}
		f_cleanup(fderr, ferr);
		fd_cleanup(fd, fd2);
		return (1);
	}
	fd_cleanup(fd, fd2);
	return (0);
}

void
fd_cleanup(int fd, int fd2)
{
	if (fd > 0) {
		(void) close(fd);
	}
	if (fd2 > 0) {
		(void) close(fd2);
	}
}

void
f_cleanup(FILE *fp, char *tmpf)
{
	if (fp != NULL) {
		(void) fclose(fp);
	}
	if (tmpf != NULL) {
		(void) unlink(tmpf);
		(void) free(tmpf);
	}
}

struct ns_bsd_addr {
	char  *server;		/* server name */
	char  *printer;		/* printer name or NULL */
	char  *extension;	/* RFC-1179 conformance */
	char  *pname;		/* Local printer name */
};
typedef struct ns_bsd_addr ns_bsd_addr_t;

/* Key/Value pair structure */
struct ns_kvp {
	char *key;	/* key */
	void *value;	/* value converted */
};
typedef struct ns_kvp ns_kvp_t;

/*
 * Information needed to update a name service.
 * Currently only used for ldap. (see lib/print/ns.h)
 */

/* LDAP bind password security type */

typedef enum NS_PASSWD_TYPE {
	NS_PW_INSECURE = 0,
	NS_PW_SECURE = 1
} NS_PASSWD_TYPE;


struct ns_cred {
	char	*binddn;
	char	*passwd;
	char	*host;
	int	port;			/* LDAP port, 0 = default */
	NS_PASSWD_TYPE passwdType;	/* password security type */
	uchar_t  *domainDN;		/* NS domain DN */
};
typedef struct ns_cred ns_cred_t;

/* LDAP specific NS Data */

typedef struct NS_LDAPDATA {
	char **attrList;	/* list of user defined Key Value Pairs */
} NS_LDAPDATA;

/* Printer Object structure */
struct ns_printer {
	char	*name;		/* primary name of printer */
	char	**aliases;	/* aliases for printer */
	char	*source;	/* name service derived from */
	ns_kvp_t	**attributes;	/* key/value pairs. */
	ns_cred_t	*cred;	/* info to update name service */
	void	*nsdata;	/* name service specific data */
};
typedef struct ns_printer ns_printer_t;

extern ns_printer_t *ns_printer_get_name(const char *, const char *);
extern int ns_printer_put(const ns_printer_t *);
extern char *ns_get_value_string(const char *, const ns_printer_t *);
extern int ns_set_value(const char *, const void *, ns_printer_t *);
extern int ns_set_value_from_string(const char *, const char *,
					ns_printer_t *);
extern ns_bsd_addr_t *bsd_addr_create(const char *, const char *,
					const char *);
extern char *bsd_addr_to_string(const ns_bsd_addr_t *);
extern void ns_printer_destroy(ns_printer_t *);

int
_updateoldyp(
	const char *action,
	const char *printername,
	const char *printserver,
	const char *extensions,
	const char *comment,
	const char *isdefault) {

	ns_printer_t *printer;
	ns_bsd_addr_t *addr;
	int status = 0;

	char mkcmd[BUFSIZ];
	char *domain = NULL;
	char *host = NULL;

	/*
	 * libprint returns before we know that the printers.conf
	 * map is made. So we'll make it again.
	 */
	(void) yp_get_default_domain(&domain);

	if ((yp_master(domain, "printers.conf.byname", &host) != 0) &&
	    (yp_master(domain, "passwd.byname", &host) != 0)) {
		strcpy(mkcmd, "/usr/bin/sleep 1");
	} else {
		sprintf(mkcmd, "/usr/bin/rsh -n %s 'cd /var/yp; "
				"/usr/ccs/bin/make -f /var/yp/Makefile "
				"-f /var/yp/Makefile.print printers.conf "
				"> /dev/null'", host);
	}

	if (strcmp(action, "delete") == 0) {
		if ((printer = (ns_printer_t *)
		    ns_printer_get_name(printername, "nis")) == NULL) {
			return (0);
		}

		printer->attributes = NULL;
		status = ns_printer_put(printer);
		if (status != 0) {
			(void) free(printer);
			return (status);
		}

		if ((printer = (ns_printer_t *)
		    ns_printer_get_name("_default", "nis")) != NULL) {
			char *dflt = (char *)
			    ns_get_value_string("use", printer);
			if ((dflt != NULL) &&
			    (strcmp(dflt, printername) == 0)) {
				printer->attributes = NULL;
				status = ns_printer_put(printer);
				if (status != 0) {
					(void) free(printer);
					return (status);
				}
			}
		}
		(void) free(printer);
		(void) system(mkcmd);
		return (0);

	} else if (strcmp(action, "add") == 0) {
		printer = (ns_printer_t *)malloc(sizeof (*printer));
		memset(printer, 0, sizeof (*printer));
		printer->name = (char *)printername;
		printer->source = "nis";

		addr = (ns_bsd_addr_t *)malloc(sizeof (*addr));
		memset(addr, 0, sizeof (*addr));
		addr->printer = (char *)printername;
		addr->server = (char *)printserver;
		if ((extensions != NULL) &&
		    (strlen(extensions) > 0)) {
			addr->extension = (char *)extensions;
		}
		ns_set_value("bsdaddr", addr, printer);

		if ((comment != NULL) && (strlen(comment) > 0)) {
			ns_set_value_from_string("description",
			    comment, printer);
		}
		status = ns_printer_put(printer);
		if (status != 0) {
			(void) free(addr);
			(void) free(printer);
			return (status);
		}

		if (strcmp(isdefault, "true") == 0) {
			printer->name = "_default";
			printer->attributes = NULL;
			ns_set_value_from_string("use", printername, printer);
			status = ns_printer_put(printer);
			if (status != 0) {
				(void) free(addr);
				(void) free(printer);
				return (status);
			}
		}
		(void) free(addr);
		(void) free(printer);
		(void) system(mkcmd);
		return (0);
	}

	/*
	 * Modify
	 */
	if ((printer = (ns_printer_t *)
	    ns_printer_get_name(printername, "nis")) == NULL) {
		return (1);
	}
	if ((comment != NULL) && (strlen(comment) > 0)) {
		ns_set_value_from_string("description", comment, printer);
	} else {
		ns_set_value_from_string("description",
		    NULL, printer);
	}
	status = ns_printer_put(printer);
	if (status != 0) {
		(void) free(printer);
		return (status);
	}

	if ((printer = (ns_printer_t *)
	    ns_printer_get_name("_default", "nis")) != NULL) {
		char *dflt = (char *)ns_get_value_string("use", printer);
		if (strcmp(printername, dflt) == 0) {
			if (strcmp(isdefault, "false") == 0) {
				/*
				 * We were the default printer but not
				 * any more.
				 */
				printer->attributes = NULL;
				status = ns_printer_put(printer);
				if (status != 0) {
					(void) free(printer);
					return (status);
				}
			}
		} else {
			if (strcmp(isdefault, "true") == 0) {
				ns_set_value_from_string("use",
				    printername, printer);
				status = ns_printer_put(printer);
				if (status != 0) {
					(void) free(printer);
					return (status);
				}
			}
		}
	} else {
		printer = (ns_printer_t *)malloc(sizeof (*printer));
		memset(printer, 0, sizeof (*printer));
		printer->name = "_default";
		printer->source = "nis";
		ns_set_value_from_string("use", printername, printer);
		status = ns_printer_put(printer);
		if (status != 0) {
			(void) free(printer);
			return (status);
		}
	}
	(void) system(mkcmd);
	return (0);
}

int
_updateldap(
	const char *action,
	const char *host,
	const char *binddn,
	const char *passwd,
	const char *printername,
	const char *printserver,
	const char *extensions,
	const char *comment,
	const char *isdefault)

{
	ns_printer_t *printer;
	ns_bsd_addr_t *addr;
	ns_cred_t *cred;

	char *item = NULL;
	char **attrList = NULL;

	int status;

	if (printserver == NULL) {
		/* printserver not given so use host */
		printserver = host;
	}

	cred = (ns_cred_t *)malloc(sizeof (*cred));
	(void) memset(cred, '\0', sizeof (*cred));
	cred->passwd = strdup((char *)passwd);
	cred->binddn = strdup((char *)binddn);
	cred->host = strdup((char *)host);

	cred->passwdType = NS_PW_INSECURE; /* use default */
	cred->port = 0;		/* use default */
	cred->domainDN = NULL;	/* use default */

	if (strcmp(action, "delete") == 0) {
		/*
		 * Delete printer object from LDAP directory DIT
		 */

		if ((printer = (ns_printer_t *)
		    ns_printer_get_name(printername, "ldap")) == NULL) {
			return (0);
		}

		printer->attributes = NULL;
		printer->nsdata = malloc(sizeof (NS_LDAPDATA));
		if (printer->nsdata == NULL) {
			return (1);
		}
		((NS_LDAPDATA *)(printer->nsdata))->attrList = NULL;
		printer->cred = cred;
		printer->source = strdup("ldap");
		status = ns_printer_put(printer);
		free(printer->nsdata);
		(void) ns_printer_destroy(printer);

		if (status != 0) {
			return (status);
		}

		if ((printer = (ns_printer_t *)
		    ns_printer_get_name("_default", "ldap")) != NULL) {
			char *dflt = (char *)
			    ns_get_value_string("use", printer);
			if ((dflt != NULL) &&
			    (strcmp(dflt, printername) == 0)) {
				printer->attributes = NULL;
				printer->nsdata = malloc(sizeof (NS_LDAPDATA));
				if (printer->nsdata == NULL) {
					(void) ns_printer_destroy(printer);
					return (1);
				}
		((NS_LDAPDATA *)(printer->nsdata))->attrList = NULL;
				printer->cred = cred;
				printer->source = strdup("ldap");
				status = ns_printer_put(printer);
				free(printer->nsdata);
				if (status != 0) {
					(void) ns_printer_destroy(printer);
					return (status);
				}
			}

			(void) ns_printer_destroy(printer);
		}
		return (0);

	} else if (strcmp(action, "add") == 0) {
		/*
		 * Add new printer object into LDAP directory DIT
		 */

		printer = (ns_printer_t *)malloc(sizeof (*printer));
		if (printer == NULL) {
			return (1);
		}
		(void) memset(printer, 0, sizeof (*printer));
		printer->name = strdup((char *)printername);
		printer->source = strdup("ldap");

		printer->cred = cred;

		/* set BSD address in attribute list */

		if (extensions == NULL) {
			item = (char *)malloc(strlen("bsdaddr") +
						strlen(printserver) +
						strlen(printername) +
						strlen("Solaris") + 6);
		} else {
			item = (char *)malloc(strlen("bsdaddr") +
						strlen(printserver) +
						strlen(printername) +
						strlen(extensions) + 6);
		}
		if (item == NULL) {
			(void) ns_printer_destroy(printer);
			return (1);
		}

		if (extensions == NULL) {
			sprintf(item, "%s=%s,%s,%s", "bsdaddr",
				printserver, printername, "Solaris");
		} else {
			sprintf(item, "%s=%s,%s,%s", "bsdaddr",
				printserver, printername, extensions);
		}

		attrList = (char **)list_append((void**)attrList,
						(void *)item);
		if ((comment != NULL) && (strlen(comment) > 0)) {
			item = (char *)malloc(strlen("description") +
							strlen(comment) + 4);
			if (item == NULL) {
				(void) ns_printer_destroy(printer);
				return (1);
			}
			sprintf(item, "%s=%s", "description", comment);
			attrList = (char **)list_append((void**)attrList,
							(void *)item);
		}

		printer->attributes = NULL;
		printer->nsdata = malloc(sizeof (NS_LDAPDATA) + 2);
		if (printer->nsdata == NULL) {
			(void) ns_printer_destroy(printer);
			return (1);
		}
		((NS_LDAPDATA *)(printer->nsdata))->attrList = attrList;

		status = ns_printer_put(printer);
		_freeList(&attrList);
		if (status != 0) {
			free(printer->nsdata);
			(void) ns_printer_destroy(printer);
			return (status);
		}

		if (strcmp(isdefault, "true") == 0) {
			(void) free(printer->name);

			printer->name = strdup("_default");
			printer->attributes = NULL;

			attrList = NULL;
			item = (char *)malloc(strlen("use") +
						strlen(printername) + 4);
			if (item == NULL) {
				(void) ns_printer_destroy(printer);
				return (1);
			}
			sprintf(item, "%s=%s", "use", printername);
			attrList = (char **)list_append((void**)attrList,
							(void *)item);

			((NS_LDAPDATA *)(printer->nsdata))->attrList = attrList;

			status = ns_printer_put(printer);
			_freeList(&attrList);
			free(printer->nsdata);
			if (status != 0) {
				(void) ns_printer_destroy(printer);
				return (status);
			}
		}
		(void) ns_printer_destroy(printer);
		return (0);
	}

	/*
	 * Modify printer object in the LDAP directory DIT
	 */

	if ((printer = (ns_printer_t *)
	    ns_printer_get_name(printername, "ldap")) == NULL) {
		return (1);
	}
	printer->cred = cred;
	printer->source = strdup("ldap");

	if ((comment != NULL) && (strlen(comment) > 0)) {
		item = (char *)malloc(strlen("description") +
						strlen(comment) + 4);
		if (item == NULL) {
			(void) ns_printer_destroy(printer);
			return (1);
		}
		sprintf(item, "%s=%s", "description", comment);
		attrList = (char **)list_append((void**)attrList, (void *)item);
	} else {
		item = (char *)malloc(strlen("description") + 4);
		if (item == NULL) {
			(void) ns_printer_destroy(printer);
			return (1);
		}
		sprintf(item, "%s=", "description");
		attrList = (char **)list_append((void**)attrList, (void *)item);
	}

	printer->attributes = NULL;
	printer->nsdata = malloc(sizeof (NS_LDAPDATA));
	if (printer->nsdata == NULL) {
		(void) ns_printer_destroy(printer);
		return (1);
	}
	((NS_LDAPDATA *)(printer->nsdata))->attrList = attrList;

	status = ns_printer_put(printer);
	_freeList(&attrList);
	free(printer->nsdata);
	if (status != 0) {
		(void) ns_printer_destroy(printer);
		return (status);
	}

	/*
	 * Handle the default printer.
	 */
	if ((printer = (ns_printer_t *)
	    ns_printer_get_name("_default", "ldap")) != NULL) {
		char *dflt = (char *)ns_get_value_string("use", printer);

		printer->source = strdup("ldap");
		printer->cred = cred;
		if (strcmp(printername, dflt) == 0) {
			if (strcmp(isdefault, "false") == 0) {
				/*
				 * We were the default printer but not
				 * any more. So delete the default entry
				 */
				printer->attributes = NULL;
				printer->nsdata = malloc(sizeof (NS_LDAPDATA));
				if (printer->nsdata == NULL) {
					(void) ns_printer_destroy(printer);
					return (1);
				}
			((NS_LDAPDATA *)(printer->nsdata))->attrList = NULL;
				status = ns_printer_put(printer);
				free(printer->nsdata);
				if (status != 0) {
					(void) ns_printer_destroy(printer);
					return (status);
				}
			}
		} else if (strcmp(isdefault, "true") == 0) {
			/*
			 * Modify this default entry to use us.
			 */
			printer->attributes = NULL;
			printer->nsdata = malloc(sizeof (NS_LDAPDATA));
			if (printer->nsdata == NULL) {
				(void) ns_printer_destroy(printer);
				return (1);
			}
			attrList = NULL;
			item = (char *)malloc(strlen("use") +
						strlen(printername) + 4);
			if (item == NULL) {
				(void) ns_printer_destroy(printer);
				return (1);
			}
			sprintf(item, "%s=%s", "use", printername);
			attrList = (char **)list_append((void**)attrList,
							(void *)item);

			((NS_LDAPDATA *)(printer->nsdata))->attrList = attrList;

			status = ns_printer_put(printer);
			_freeList(&attrList);
			free(printer->nsdata);

			if (status != 0) {
				(void) ns_printer_destroy(printer);
				return (status);
			}
		}
	} else if (strcmp(isdefault, "true") == 0) {
		/*
		 * No default entry existed and we need one.
		 */
		printer = (ns_printer_t *)malloc(sizeof (*printer));
		(void) memset(printer, 0, sizeof (*printer));
		printer->name = strdup("_default");
		printer->source = strdup("ldap");
		printer->cred = cred;

		printer->nsdata = malloc(sizeof (NS_LDAPDATA));
		if (printer->nsdata == NULL) {
			(void) ns_printer_destroy(printer);
			return (1);
		}

		attrList = NULL;
		item = (char *)malloc(strlen("use") + strlen(printername) + 4);
		if (item == NULL) {
			(void) ns_printer_destroy(printer);
			return (1);
		}
		sprintf(item, "%s=%s", "use", printername);
		attrList = (char **)list_append((void**)attrList, (void *)item);

		((NS_LDAPDATA *)(printer->nsdata))->attrList = attrList;

		status = ns_printer_put(printer);
		_freeList(&attrList);
		free(printer->nsdata);

		if (status != 0) {
			(void) ns_printer_destroy(printer);
			return (status);
		}
	}

	(void) ns_printer_destroy(printer);
	return (0);
}




/*
 * *****************************************************************************
 *
 * Function:    _freeList()
 *
 * Description: Free the list created by list_append() where the items in
 *              the list have been strdup'ed.
 *
 * Parameters:
 * Input:       char ***list   - returned set of kvp values
 *
 * Result:      void
 *
 * *****************************************************************************
 */

static void
_freeList(char ***list)

{
	int i = 0;

	/* ------ */

	if (list != NULL) {
		if (*list != NULL) {
			for (i = 0; (*list)[i] != NULL; i++) {
				free((*list)[i]);
			}
			free(*list);
		}

		*list = NULL;
	}
} /* _freeList */
