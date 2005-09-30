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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	nisaddcred.c
 *
 * This utility is used to add credentials for a user to the NIS+ databases.
 * Its syntax is as follows :
 * nisaddcred [-p principal] [-P nis+_principal] [-l login_passwd] flavor
 * nisaddcred -r [nis+_principal]
 */

/*
 * The code is set up so that it may be possible to pass 'domain'
 * as an optional argument.  However, it is not clear whether it
 * makes any sense to addcreds to other domains, and whether
 * the code itself would work.
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <pwd.h>
#include <limits.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_dhext.h>
#define	CRED_TABLE	"cred.org_dir"

void
usage(cmd)
	char *cmd;
{
	fprintf(stderr,
"usage:\n\t%s [-p principal] [-P NIS+_principal] [-l login_password] ",
									cmd);
	fprintf(stderr, "flavor\n");
	fprintf(stderr,
		"\t%s -r [NIS+_principal]\n", cmd);
	exit(1);
}

extern int make_des_cred(), make_kerb_cred(),
	make_rsa_cred(), make_local_cred(), make_dhext_cred();
extern char 	*get_des_cred(), *get_kerb_cred(),
		*get_rsa_cred(), *get_local_cred(), *get_dhext_cred();

static
struct {
	char	*name;
	int	(*makecred)();
	char	*(*pname)();
} known_flavors[] = {
	{ "local", make_local_cred, get_local_cred },	/* LOCAL ALWAYS 0! */
	{ "des", make_des_cred, get_des_cred },
#ifdef KERB_RSA_CREDS
	{ "kerb", make_kerb_cred, get_kerb_cred },
	{ "rsa", make_rsa_cred, get_rsa_cred },
#endif /* KERB_RSA_CREDS */
	{ NULL, NULL}};

extern int optind;
extern char *optarg;
extern nis_name nis_local_host();

char *program_name = "nisaddcred";
uid_t my_uid;
nis_name my_nisname = 0;
char *my_host;
char *my_group;
char nispasswd[sizeof (des_block)+1];
int explicit_domain; /* if true, then a domain was specified on command line */

/*
 * Similar to nis_local_principal (nis_subr.c) except
 * this gets the results from the MASTER_ONLY and no FOLLOW_PATH.
 * We only want the master because we'll be making updates there,
 * and also the replicas may not have seen the 'nisaddacred local'
 * that may have just occurred.
 * Returns NULL if not found.
 */
char *
default_principal(directory)
char *directory;
{
	nis_result	*res;
	char		buf[NIS_MAXNAMELEN+1];
	static char	principal_name[NIS_MAXNAMELEN+1];
	uid_t		uid;


	uid = my_uid;

	if (uid == 0)
		return (nis_local_host());

	sprintf(buf, "[auth_name=%d,auth_type=LOCAL],%s.%s",
		uid, CRED_TABLE, directory);

	if (buf[strlen(buf)-1] != '.')
		strcat(buf, ".");

	res = nis_list(buf, MASTER_ONLY+USE_DGRAM+NO_AUTHINFO+FOLLOW_LINKS,
								NULL, NULL);

	if (res == NULL) {
		fprintf(stderr,
			"%s: unable to get result from NIS+ server.",
			program_name);
		exit(1);
	}
	switch (res->status) {
	case NIS_SUCCESS:
		if (res->objects.objects_len > 1) {
			/*
			 * More than one principal with same uid?
			 * something wrong with cred table. Should be unique
			 * Warn user and continue.
			 */
			fprintf(stderr,
			"%s: LOCAL entry for %d in directory \"%s\" not unique",
						program_name, uid, directory);
		}
		strcpy(principal_name, ENTRY_VAL(res->objects.objects_val, 0));
		nis_freeresult(res);
		return (principal_name);

	case NIS_NOTFOUND:
		nis_freeresult(res);
		return (NULL);

	case NIS_TRYAGAIN :
		fprintf(stderr,
			"%s: NIS+ server busy, try again later.\n",
			program_name);
		exit(1);

	case NIS_PERMISSION :
		fprintf(stderr,
			"%s: insufficent permission to update credentials.\n",
			program_name);
		exit(1);

	default:
		fprintf(stderr,
			"%s: error talking to server, NIS+ error: %s.\n",
			program_name, nis_sperrno(res->status));
		exit(1);
	}
	return (NULL);
}

/* Check whether this principal already has this type of credentials */
nis_error
cred_exists(char *nisprinc, char *flavor, char *domain)
{
	char sname[NIS_MAXNAMELEN+1];
	nis_result	*res;
	nis_error status;

	sprintf(sname, "[cname=\"%s\",auth_type=%s],%s.%s",
		nisprinc, flavor, CRED_TABLE, domain);
	if (sname[strlen(sname)-1] != '.')
		strcat(sname, ".");

	/* Don't want FOLLOW_PATH here */
	res = nis_list(sname, MASTER_ONLY+USE_DGRAM+NO_AUTHINFO+FOLLOW_LINKS,
								NULL, NULL);

	status = res->status;
	switch (status) {
	case NIS_NOTFOUND:
		break;
	case NIS_TRYAGAIN :
		fprintf(stderr, "%s: NIS+ server busy, try again later.\n",
			program_name);
		exit(1);
	case NIS_PERMISSION :
		fprintf(stderr,
		"%s: insufficent permission to look at credentials table\n",
			program_name);
		exit(1);
	case NIS_SUCCESS:
	case NIS_S_SUCCESS:
		break;
	default:
		fprintf(stderr,
			"%s: error looking at cred table, NIS+ error: %s\n",
			program_name, nis_sperrno(res->status));
		exit(1);
	}
	nis_freeresult(res);
	return (status);
}

/* Check that someone else don't have the same auth information already */
nis_error
auth_exists(char *princname, char *auth_name, char *auth_type, char *domain)
{
	char sname[NIS_MAXNAMELEN+1];
	nis_result	*res;
	nis_error status;
	char *foundprinc;

	sprintf(sname, "[auth_name=%s,auth_type=%s],%s.%s",
				auth_name, auth_type, CRED_TABLE, domain);
	if (sname[strlen(sname)-1] != '.')
		strcat(sname, ".");
	/* Don't want FOLLOW_PATH here */
	res = nis_list(sname, MASTER_ONLY+USE_DGRAM+NO_AUTHINFO+FOLLOW_LINKS,
								NULL, NULL);

	status = res->status;
	switch (res->status) {
	case NIS_NOTFOUND:
		break;
	case NIS_TRYAGAIN :
		fprintf(stderr,
			"%s: NIS+ server busy, try again later.\n",
			program_name);
		exit(1);
	case NIS_PERMISSION :
		fprintf(stderr,
		"%s: insufficent permission to look up old credentials.\n",
								program_name);
		exit(1);
	case NIS_SUCCESS:
		foundprinc = ENTRY_VAL(res->objects.objects_val, 0);
		if (strcmp(foundprinc, princname) != 0) {
			fprintf(stderr,
	"%s: %s credentials with auth_name '%s' already belongs to '%s'.\n",
				program_name, auth_type, auth_name, foundprinc);
			exit(1);
		}
		break;
	default:
		fprintf(stderr,
			"%s: error looking at cred table, NIS+ error: %s\n",
			program_name, nis_sperrno(res->status));
		exit(1);
	}
	nis_freeresult(res);
	return (status);
}

int
modify_cred_obj(obj, domain)
	char *domain;
	nis_object *obj;
{
	int status = 0;
	char sname[NIS_MAXNAMELEN+1];
	nis_result	*res;

	sprintf(sname, "%s.%s", CRED_TABLE, domain);
	res = nis_modify_entry(sname, obj, 0);
	switch (res->status) {
	case NIS_TRYAGAIN :
		fprintf(stderr,
			"%s: NIS+ server busy, try again later.\n",
			program_name);
		exit(1);
	case NIS_PERMISSION :
		fprintf(stderr,
			"%s: insufficent permission to update credentials.\n",
			program_name);
		exit(1);
	case NIS_SUCCESS :
		status = 1;
		break;
	default:
		fprintf(stderr,
			"%s: error creating credential, NIS+ error: %s.\n",
			program_name, nis_sperrno(res->status));
		exit(1);
	}
	nis_freeresult(res);
	return (status);
}


int
add_cred_obj(obj, domain)
	char *domain;
	nis_object *obj;
{
	int status = 0;
	char sname[NIS_MAXNAMELEN+1];
	nis_result	*res;

	/* Assume check for cred_exists performed already */

	sprintf(sname, "%s.%s", CRED_TABLE, domain);
	res = nis_add_entry(sname, obj, 0);
	switch (res->status) {
	case NIS_TRYAGAIN :
		fprintf(stderr,
			"%s: NIS+ server busy, try again later.\n",
			program_name);
		exit(1);
	case NIS_PERMISSION :
		fprintf(stderr,
			"%s: insufficent permission to update credentials.\n",
			program_name);
		exit(1);
	case NIS_SUCCESS :
		status = 1;
		break;
	default:
		fprintf(stderr,
			"%s: error creating credential, NIS+ error: %s.\n",
			program_name, nis_sperrno(res->status));
		exit(1);
	}
	nis_freeresult(res);
	return (status);
}

void
unknown_flavor(char *flavor)
{
	mechanism_t	**mechlist;
	int i;

	mechlist = __nis_get_mechanisms(FALSE);
	fprintf(stderr, "%s: unknown flavor '%s'\n", program_name, flavor);

	fprintf(stderr, "known flavors are: ");
	for (i = 0; known_flavors[i].name; i++)
		if (known_flavors[i+1].name)
			fprintf(stderr, "%s, ", known_flavors[i].name);
		else {
			if (mechlist &&
			    !(AUTH_DES_COMPAT_CHK(mechlist[0]) &&
				!mechlist[1])) {
				int	count;

				fprintf(stderr, "%s, ", known_flavors[i].name);
				for (count = 0; mechlist[count]; count++) {
					if (mechlist[count+1])
						fprintf(stderr, "%s\n",
							mechlist[count]->alias);
					else
						fprintf(stderr, "%s.\n",
							mechlist[count]->alias);
				}
				__nis_release_mechanisms(mechlist);
			} else
				fprintf(stderr, "%s.\n",
					known_flavors[i].name);
		}
	exit(1);
}

void
perform_add(flavor, domain, nisprinc, princ)
	char *flavor;
	char *domain;
	char *nisprinc;
	char *princ;
{
	int	i, status, fl;
	int	(*mc)();
	char	*(*gp)();

	fl = strlen(flavor);
	for (i = 0; i < fl; i++)
		*(flavor+i) = tolower(*(flavor+i));

	/* See if given flavor is one that we know */
	for (i = 0, mc = NULL; !mc && known_flavors[i].name; i++)
		if (strcmp(known_flavors[i].name, flavor) == 0) {
			mc = known_flavors[i].makecred;
			gp = known_flavors[i].pname;
			break;
		}

	if (! mc) {
		keylen_t	kl;
		algtype_t	at;

		if (strcmp(flavor, "dh192-0")) {
			/* It could be a GSS/DHEXT type */
			if (__nis_translate_mechanism(flavor, &kl, &at) == -1)
				unknown_flavor(flavor);
		} else {
			mc = make_dhext_cred;
			gp = get_des_cred;
		}

		mc = make_dhext_cred;
		gp = get_dhext_cred;
	}

	/*
	 * Call the function that will build the appropriate credential.
	 * When called, both the principal *and* the domain must be specified.
	 * some functions will complain if the domain and the domain of the
	 * principal (if fully qualified) differ.
	 */
	if (! princ) {
		princ = (*gp)(domain, flavor);
		if (princ == NULL) {
			fprintf(stderr,
	"%s: unable to determine your principal name for this flavor.\n",
				program_name);
			exit(1);
		}
	}

	status = (*mc)(nisprinc, princ, domain, flavor);
	if (! status) {
		fprintf(stderr, "%s: unable to create credential.\n",
			program_name);
		exit(1);
	}
}

void
perform_remove(domain, nis_princ)
char *domain;
char *nis_princ;
{
	char sname[NIS_MAXNAMELEN+1];
	nis_result *res;

	if (nis_princ == NULL)
		nis_princ = default_principal(domain);

	sprintf(sname, "[cname=\"%s\"],%s.%s", nis_princ, CRED_TABLE, domain);
	if (sname[strlen(sname)-1] != '.')
		strcat(sname, ".");
	res = nis_remove_entry(sname, 0, REM_MULTIPLE);

	if (res->status != NIS_SUCCESS) {
		nis_perror(res->status, "could not remove entry");
		exit(1);
	}
	nis_freeresult(res);

/* Should do keylogout here if removing my own des credentials */
}


nis_object *
init_entry()
{
	static nis_object	obj;
	static entry_col	cred_data[10];
	entry_obj		*eo;

	memset((char *)(&obj), 0, sizeof (obj));
	memset((char *)(cred_data), 0, sizeof (entry_col) * 10);

	obj.zo_name = "cred";
	obj.zo_group = "";
	obj.zo_ttl = 43200;
	obj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eo = &(obj.EN_data);
	eo->en_type = "cred_tbl";
	eo->en_cols.en_cols_val = cred_data;
	eo->en_cols.en_cols_len = 5;
	cred_data[4].ec_flags |= EN_CRYPT;
	return (&obj);
}

int
main(int argc, char *argv[])
{
	char	*princ = NULL;
	char	*nisprinc = NULL;
	char	*domain = nis_local_directory();
	char	*flavor = NULL;
	int	len;
	int	c;
	char	*p;
	int	add_op = 1;    /* whether this operation is an add */

	program_name = argv[0];
	nispasswd[0] = '\0';

	if (argc == 1)
		usage(program_name);

	while ((c = getopt(argc, argv, "p:P:l:r")) != -1) {
		switch (c) {
		case 'p' :
			if (add_op == 0) {
				fprintf(stderr,
			"%s: cannot combine any other option with -r.\n",
					program_name);
				usage(program_name);
			}
			princ = optarg;
			break;
		case 'P' :
			if (add_op == 0) {
				fprintf(stderr,
			"%s: cannot combine any other option with -r.\n",
					program_name);
				usage(program_name);
			}
			nisprinc = optarg;
			break;
		case 'r':
			if ((princ != NULL) || (nisprinc != NULL) ||
			    (nispasswd[0] != '\0')) {
				fprintf(stderr,
			"%s: cannot combine any other option with -r.\n",
					program_name);
				usage(program_name);
			}
			add_op = 0;
			if ((argc == 2) && getuid() == 0) {
				struct stat buf;
				int ret;
				char *ptr, ansbuf[BUFSIZ];

				ret = stat("/var/nis/data", &buf);
				if (ret == 0) {
		fputs("\n\tThis machine appears to be a NIS+ server!!!\n",
								stderr);
		fputs("Are you sure you want to REMOVE it's credential?(Y/N) ",
								stderr);
					ansbuf[0] = '\0';
					ptr = gets(ansbuf);
					if (ansbuf[0] != 'y' &&
							ansbuf[0] != 'Y') {
		fputs("\nOkay not REMOVING this NIS+ server's credential\n",
								stderr);
						exit(1);
					}
				}
			}
			break;
		case 'l':
			if (add_op == 0) {
				fprintf(stderr,
			"%s: cannot combine any other option with -r.\n",
					program_name);
				usage(program_name);
			}
			strncpy(nispasswd, optarg, sizeof (des_block));
			nispasswd[sizeof (des_block)] = '\0';
			break;
		case '?' :
		default :
			fprintf(stderr, "%s: unrecognized option.\n",
				program_name);
			usage(program_name);
			break;
		}
	}


	if (add_op) {
		if (optind == argc) {
			fprintf(stderr,
				"%s: Authentication Flavor name required.\n",
				program_name);
			usage(program_name);
		}
		flavor = argv[optind++];

		if (optind < argc) {
			domain = argv[optind++];
			explicit_domain++;
		}
	} else {
		if (optind < argc)
			nisprinc = argv[optind++];
		if (optind < argc) {
			domain = argv[optind++];
			explicit_domain++;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "%s: too many parameters\n", program_name);
		usage(program_name);
	}

	/* Information about user running nisaddcred */
	my_uid = geteuid();
	my_nisname = default_principal(nis_local_directory());
	my_host = nis_local_host();
	my_group = nis_local_group();

	/*
	 *  Do a centralized check of nisprinc to make sure that
	 *  it has a trailing ".", which is a common mistake that
	 *  we can easily correct.
	 */
	if (nisprinc) {
		len = strlen(nisprinc);
		if (len == 0 || nisprinc[len-1] != '.') {
			p = malloc(len + 2);	/* 1 for '.' and 1 for '\0' */
			if (p == NULL) {
				fprintf(stderr,
					"%s: out of memory\n", program_name);
				exit(1);
			}
			strcpy(p, nisprinc);
			strcat(p, ".");
			nisprinc = p;
		}
	}

	/*
	 *  Do the same checking for domain, if it was specified on
	 *  the command line.
	 */
	if (explicit_domain) {
		len = strlen(domain);
		if (len == 0 || domain[len-1] != '.') {
			p = malloc(len + 2);	/* 1 for '.' and 1 for '\0' */
			if (p == NULL) {
				fprintf(stderr,
					"%s: out of memory\n", program_name);
				exit(1);
			}
			strcpy(p, domain);
			strcat(p, ".");
			domain = p;
		}
	}

	if (add_op) {
		perform_add(flavor, domain, nisprinc, princ);
	} else
		perform_remove(domain, nisprinc);
	return (0);
}

/*
 *  Get the password entry corresponding to 'uid' in the specified
 *  domain.  If the domain is NULL and we can't get the information,
 *  then we get it locally (if USE_LOCAL_INFO is defined).
 */
struct passwd *
domain_getpwuid(domain, uid)
	char *domain;
	int uid;
{
	struct passwd *pw;
	nis_error err;
	struct passwd *getpwuid_nisplus_master();

	pw = getpwuid_nisplus_master(domain, uid, &err);

#ifdef USE_LOCAL_INFO
	/*
	 * If no domain was specified on the command line and we didn't
	 * get a password entry from NIS+, then try getting it locally.
	 */
	if (! explicit_domain && pw == 0)
		pw = getpwuid(uid);
#endif /* USE_LOCAL_INFO */

	if (pw == 0) {
		if (err == NIS_NOTFOUND)
			fprintf(stderr,
				"%s: no password entry found for uid %d\n",
				program_name, uid);
		else
			fprintf(stderr,
	"%s: could not get the password entry for uid %d: %s\n",
				program_name, uid, nis_sperrno(err));
	}

	return (pw);
}

/*
 *  Get the shadow entry corresponding to 'name' in the specified
 *  domain.  If the domain is NULL and we can't get the information,
 *  then we get it locally (if USE_LOCAL_INFO is defined).
 */
struct spwd *
domain_getspnam(domain, name)
	char *domain;
	char *name;
{
	struct spwd *spw;
	nis_error err;
	struct spwd *getspnam_nisplus_master();

	spw = getspnam_nisplus_master(domain, name, &err);

#ifdef USE_LOCAL_INFO
	/*
	 * If no domain was specified on the command line and we didn't
	 * get a shadow entry from NIS+, then try getting it locally.
	 */
	if (! explicit_domain && spw == 0)
		spw = getspnam(name);
#endif /* USE_LOCAL_INFO */

	if (spw == 0) {
		if (err == NIS_NOTFOUND)
			fprintf(stderr,
				"%s: no password entry found for user %s\n",
				program_name, name);
		else
			fprintf(stderr,
	"%s: could not get the password entry for user %s: %s\n",
				program_name, name, nis_sperrno(err));
	}

	return (spw);
}
