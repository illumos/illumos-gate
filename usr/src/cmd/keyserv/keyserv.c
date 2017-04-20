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
 * Copyright 2017 Joyent Inc
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * keyserv - server for storing private encryption keys
 *   keyserv(1M) performs multiple functions:  it stores secret keys per uid; it
 *   performs public key encryption and decryption operations; and it generates
 *   "random" keys.  keyserv(1M) will talk to no one but a local root process on
 *   the local transport only.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <deflt.h>
#include <rpc/rpc.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <pwd.h>
#include <rpc/des_crypt.h>
#include <rpc/key_prot.h>
#include <thread.h>
#include "rpc/svc_mt.h"
#include <rpcsvc/nis_dhext.h>
#include <syslog.h>
#include <libscf.h>
#include <sys/debug.h>

#include "debug.h"
#include "keyserv_cache.h"

#ifdef KEYSERV_RANDOM
extern long random();
#endif

extern keystatus pk_setkey();
extern keystatus pk_encrypt();
extern keystatus pk_decrypt();
extern keystatus pk_netput();
extern keystatus pk_netget();
extern keystatus pk_get_conv_key();
extern bool_t svc_get_local_cred();

extern keystatus pk_setkey3();
extern keystatus pk_encrypt3();
extern keystatus pk_decrypt3();
extern keystatus pk_netput3();
extern keystatus pk_netget3();
extern keystatus pk_get_conv_key3();
extern keystatus pk_clear3();

extern int init_mechs();
extern int addmasterkey();
extern int storeotherrootkeys();
extern int setdeskeyarray();

extern int getdomainname();

static void randomize();
static void usage();
static void defaults();
static int getrootkey();
static int get_cache_size(char *);
static bool_t get_auth();

#ifdef DEBUG
extern int test_debug();
extern int real_debug();
int debugging = 1;
#else
int debugging = 0;
#endif

static void keyprogram();
static des_block masterkey;
char *getenv();
static char ROOTKEY[] = "/etc/.rootkey";

static char *defaults_file = "/etc/default/keyserv";
static int use_nobody_keys = TRUE;

/*
 * Hack to allow the keyserver to use AUTH_DES. The only functions
 * that get called are key_encryptsession_pk, key_decryptsession_pk,
 * and key_gendes.
 *
 * The approach is to have the keyserver fill in pointers to local
 * implementations of these functions, and to call those in key_call().
 */

bool_t __key_encrypt_pk_2_svc();
bool_t __key_decrypt_pk_2_svc();
bool_t __key_gen_1_svc();

extern bool_t (*__key_encryptsession_pk_LOCAL)();
extern bool_t (*__key_decryptsession_pk_LOCAL)();
extern bool_t (*__key_gendes_LOCAL)();

static int nthreads = 32;

/* Disk caching of common keys on by default */
int disk_caching = 1;

mechanism_t **mechs;

/*
 * The default size for all types of mech.
 * positive integers denote multiples of 1MB
 * negative integers denote number of entries
 * same goes for non-null entries in cache_size
 */
static int default_cache = 1;

int *cache_size;
char **cache_options;

int
main(int argc, char *argv[])
{
	int sflag = 0, s1flag = 0, s2flag = 0, nflag = 0, dflag = 0, eflag = 0;
	char *options, *value;
	extern char *optarg;
	extern int optind;
	int c, d;
	struct rlimit rl;
	int mode = RPC_SVC_MT_AUTO;
	int maxrecsz = RPC_MAXDATASIZE;

	void detachfromtty(void);
	int setmodulus();
	int pk_nodefaultkeys();
	int svc_create_local_service();

	char domainname[MAXNETNAMELEN + 1];

	/*
	 * Set our allowed number of file descriptors to the max
	 * of what the system will allow, limited by FD_SETSIZE.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		rlim_t limit;

		if ((limit = rl.rlim_max) > FD_SETSIZE)
			limit = FD_SETSIZE;
		rl.rlim_cur = limit;
		(void) setrlimit(RLIMIT_NOFILE, &rl);
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	__key_encryptsession_pk_LOCAL = &__key_encrypt_pk_2_svc;
	__key_decryptsession_pk_LOCAL = &__key_decrypt_pk_2_svc;
	__key_gendes_LOCAL = &__key_gen_1_svc;

	/*
	 * Pre-option initialisation
	 */
	(void) umask(066);	/* paranoia */
	if (geteuid() != 0) {
		(void) fprintf(stderr, "%s must be run as root\n", argv[0]);
		exit(1);
	}
	setmodulus(HEXMODULUS);
	openlog("keyserv", LOG_PID, LOG_DAEMON);

	/*
	 * keyserv will not work with a null domainname.
	 */
	if (getdomainname(domainname, MAXNETNAMELEN+1) ||
	    (domainname[0] == '\0')) {
		syslog(LOG_ERR, "could not get a valid domainname.\n");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/*
	 * Initialise security mechanisms
	 */
	cache_size = NULL;
	cache_options = NULL;
	if (init_mechs() == -1) {
		disk_caching = 0;
	}

	defaults();

	while ((c = getopt(argc, argv, "ndDet:cs:")) != -1)
		switch (c) {
		case 'n':
			nflag++;
			break;
		case 'd':
			dflag++;
			use_nobody_keys = FALSE;
			break;
		case 'e':
			eflag++;
			use_nobody_keys = TRUE;
			break;
		case 'D':
			debugging = 1;
			break;
		case 't':
			nthreads = atoi(optarg);
			break;
		case 'c':
			disk_caching = 0;
			break;
		case 's':
			if (!disk_caching) {
				fprintf(stderr, "missing configuration file");
				fprintf(stderr, " or -c option specified\n");
				usage();
			}
			sflag++;
			/*
			 * Which version of [-s] do we have...?
			 */
			if (strchr((const char *) optarg, '=') == NULL) {
				/*
				 * -s <size>
				 */
				if (s1flag) {
					fprintf(stderr, "duplicate"
					    " [-s <size>]\n");
					usage();
				}
				s1flag++;
				default_cache = get_cache_size(optarg);
				break;
			}
			/*
			 * -s <mechtype>=<size>[,...]
			 */
			s2flag++;
			options = optarg;
			while (*options != '\0') {
				d = getsubopt(&options, cache_options, &value);
				if (d == -1) {
					/* Ignore unknown mechtype */
					continue;
				}
				if (value == NULL) {
					fprintf(stderr,
					    "missing cache size for "
					    "mechtype %s\n", cache_options[d]);
					usage();
				}
				cache_size[d] = get_cache_size(value);
			}
			break;
		default:
			usage();
			break;
		}


	if (dflag && eflag) {
		(void) fprintf(stderr, "specify only one of -d and -e\n");
		usage();
	}

	if (use_nobody_keys == FALSE) {
		pk_nodefaultkeys();
	}

	if (optind != argc) {
		usage();
	}

	if (!disk_caching && sflag) {
		fprintf(stderr, "missing configuration file");
		fprintf(stderr, " or -c option specified\n");
		usage();
	}

	if (debugging) {
		if (disk_caching) {
			char **cpp = cache_options;
			int *ip = cache_size;
			(void) fprintf(stderr, "default disk cache size: ");
			if (default_cache < 0) {
				(void) fprintf(stderr, "%d entries\n",
				    abs(default_cache));
			} else {
				(void) fprintf(stderr, "%dMB\n", default_cache);
			}

			(void) fprintf(stderr, "supported mechanisms:\n");
			(void) fprintf(stderr, "\talias\t\tdisk cache size\n");
			(void) fprintf(stderr, "\t=====\t\t===============\n");
			while (*cpp != NULL) {
				(void) fprintf(stderr, "\t%s\t\t", *cpp++);
				if (*ip < 0) {
					(void) fprintf(stderr, "%d entries\n",
					    abs(*ip));
				} else {
					(void) fprintf(stderr, "%dMB\n", *ip);
				}
				ip++;
			}
		} else {
			(void) fprintf(stderr,
			    "common key disk caching disabled\n");
		}
	}
	/*
	 * Post-option initialisation
	 */
	if (disk_caching) {
		int i;
		for (i = 0; mechs[i]; i++) {
			if ((AUTH_DES_COMPAT_CHK(mechs[i])) ||
			    (mechs[i]->keylen < 0) || (mechs[i]->algtype < 0))
				continue;
			create_cache_file(mechs[i]->keylen, mechs[i]->algtype,
			    cache_size[i] ? cache_size[i] : default_cache);
		}
	}
	getrootkey(&masterkey, nflag);

	/*
	 * Set MT mode
	 */
	if (nthreads > 0) {
		(void) rpc_control(RPC_SVC_MTMODE_SET, &mode);
		(void) rpc_control(RPC_SVC_THRMAX_SET, &nthreads);
	}

	/*
	 * Enable non-blocking mode and maximum record size checks for
	 * connection oriented transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &maxrecsz)) {
		syslog(LOG_INFO, "unable to set max RPC record size");
	}

	if (svc_create_local_service(keyprogram, KEY_PROG, KEY_VERS,
	    "netpath", "keyserv") == 0) {
		syslog(LOG_ERR,
		    "%s: unable to create service for version %d\n",
		    argv[0], KEY_VERS);
		exit(1);
	}

	if (svc_create_local_service(keyprogram, KEY_PROG, KEY_VERS2,
	    "netpath", "keyserv") == 0) {
		syslog(LOG_ERR,
		    "%s: unable to create service for version %d\n",
		    argv[0], KEY_VERS2);
		exit(1);
	}

	if (svc_create_local_service(keyprogram, KEY_PROG, KEY_VERS3,
	    "netpath", "keyserv") == 0) {
		syslog(LOG_ERR,
		    "%s: unable to create service for version %d\n",
		    argv[0], KEY_VERS3);
		exit(1);
	}

	if (!debugging) {
		detachfromtty();
	}

	if (svc_create(keyprogram, KEY_PROG, KEY_VERS, "door") == 0) {
		syslog(LOG_ERR,
		    "%s: unable to create service over doors for version %d\n",
		    argv[0], KEY_VERS);
		exit(1);
	}

	if (svc_create(keyprogram, KEY_PROG, KEY_VERS2, "door") == 0) {
		syslog(LOG_ERR,
		    "%s: unable to create service over doors for version %d\n",
		    argv[0], KEY_VERS2);
		exit(1);
	}

	if (svc_create(keyprogram, KEY_PROG, KEY_VERS3, "door") == 0) {
		syslog(LOG_ERR,
		    "%s: unable to create service over doors for version %d\n",
		    argv[0], KEY_VERS3);
		exit(1);
	}

	svc_run();
	abort();
	/* NOTREACHED */
	return (0);
}


/*
 * In the event that we don't get a root password, we try to
 * randomize the master key the best we can
 */
static void
randomize(master)
	des_block *master;
{
	int i;
	int seed;
	struct timeval tv;
	int shift;

	seed = 0;
	for (i = 0; i < 1024; i++) {
		(void) gettimeofday(&tv, (struct timezone *)NULL);
		shift = i % 8 * sizeof (int);
		seed ^= (tv.tv_usec << shift) | (tv.tv_usec >> (32 - shift));
	}
#ifdef KEYSERV_RANDOM
	srandom(seed);
	master->key.low = random();
	master->key.high = random();
	srandom(seed);
#else
	/* use stupid dangerous bad rand() */
	srand(seed);
	master->key.low = rand();
	master->key.high = rand();
	srand(seed);
#endif
}

static char *
fgets_ignorenul(char *s, int n, FILE *stream)
{
	int fildes = fileno(stream);
	int i = 0;
	int rs = 0;
	char c;

	if (fildes < 0)
		return (NULL);

	while (i < n - 1) {
		rs = read(fildes, &c, 1);
		switch (rs) {
		case 1:
			break;
		case 0:
			/* EOF */
			if (i > 0)
				s[i] = '\0';
			return (NULL);
			break;
		default:
			return (NULL);
		}
		switch (c) {
		case '\0':
			break;
		case '\n':
			s[i] = c;
			s[++i] = '\0';
			return (s);
		default:
		if (c != '\0')
			s[i++] = c;
		}
	}
	s[i] = '\0';
	return (s);
}

/* Should last until 16384-bit DH keys */
#define	MAXROOTKEY_LINE_LEN	4224
#define	MAXROOTKEY_LEN		4096
#define	ROOTKEY_FILE		"/etc/.rootkey"

static int
getotherrootkeys(char *name)
{
	FILE		*rootkey;
	char		line[MAXROOTKEY_LINE_LEN];
	char		key[MAXROOTKEY_LEN];
	algtype_t	algtype;
	int		count = 0;

	if (!(rootkey = fopen(ROOTKEY, "r")))
		return (0);

	while (fgets_ignorenul(line, MAXROOTKEY_LINE_LEN, rootkey)) {
		debug(KEYSERV_DEBUG0, ("ROOTKEY %d: %s\n", count, line));
		count++;
		if (sscanf(line, "%s %d", key, &algtype) < 2) {
			/*
			 * No encryption algorithm found in the file
			 * (algtype) so default to DES.
			 */
			algtype = AUTH_DES_ALGTYPE;
		}
		if (!strlen(key))
			continue;
		addmasterkey(key, name, algtype);
	}
	fclose(rootkey);
	return (1);
}

/*
 * Try to get root's secret key, by prompting if terminal is a tty, else trying
 * from standard input.
 * Returns 1 on success.
 */
static int
getrootkey(master, prompt)
	des_block *master;
	int prompt;
{
	char *passwd;
	char name[MAXNETNAMELEN + 1];
	char secret[HEXKEYBYTES + 1];
	FILE *fp;
	int passwd2des();
	int retval;

	randomize(master);
	if (!getnetname(name)) {
	    (void) fprintf(stderr, "keyserv: \
failed to generate host's netname when establishing root's key.\n");
	    return (0);
	}
	if (!prompt) {
		return (getotherrootkeys(name));
	}
	/*
	 * Decrypt yellow pages publickey entry to get secret key
	 */
	passwd = getpass("root password:");
	passwd2des(passwd, master);
	if (!getsecretkey(name, secret, passwd)) {
		(void) fprintf(stderr,
		"Can't find %s's secret key\n", name);
		return (0);
	}
	if (secret[0] == 0) {
		(void) fprintf(stderr,
	"Password does not decrypt secret key for %s\n", name);
		return (0);
	}
	if ((fp = fopen(ROOTKEY, "w")) == NULL) {
		(void) fprintf(stderr,
			"Cannot open %s for write\n", ROOTKEY);
		return (0);
	}
	retval = storeotherrootkeys(fp, name, passwd, secret);
	fclose(fp);
	return (retval);
}

/*
 * Procedures to implement RPC service.  These procedures are named
 * differently from the definitions in key_prot.h (generated by rpcgen)
 * because they take different arguments.
 */
char *
strstatus(status)
	keystatus status;
{
	switch (status) {
	case KEY_SUCCESS:
		return ("KEY_SUCCESS");
	case KEY_NOSECRET:
		return ("KEY_NOSECRET");
	case KEY_UNKNOWN:
		return ("KEY_UNKNOWN");
	case KEY_SYSTEMERR:
		return ("KEY_SYSTEMERR");
	case KEY_BADALG:
		return ("KEY_BADALG");
	case KEY_BADLEN:
		return ("KEY_BADLEN");
	default:
		return ("(bad result code)");
	}
}

bool_t
__key_set_1_svc(uid, key, status)
	uid_t uid;
	keybuf key;
	keystatus *status;
{
	if (debugging) {
		(void) fprintf(stderr, "set(%d, %.*s) = ", uid,
				sizeof (keybuf), key);
	}
	*status = pk_setkey(uid, key);
	if (debugging) {
		(void) fprintf(stderr, "%s\n", strstatus(*status));
		(void) fflush(stderr);
	}
	return (TRUE);
}

bool_t
__key_encrypt_pk_2_svc(uid, arg, res)
	uid_t uid;
	cryptkeyarg2 *arg;
	cryptkeyres *res;
{

	if (debugging) {
		(void) fprintf(stderr, "encrypt(%d, %s, %08x%08x) = ", uid,
				arg->remotename, arg->deskey.key.high,
				arg->deskey.key.low);
	}
	res->cryptkeyres_u.deskey = arg->deskey;
	res->status = pk_encrypt(uid, arg->remotename, &(arg->remotekey),
				&res->cryptkeyres_u.deskey);
	if (debugging) {
		if (res->status == KEY_SUCCESS) {
			(void) fprintf(stderr, "%08x%08x\n",
					res->cryptkeyres_u.deskey.key.high,
					res->cryptkeyres_u.deskey.key.low);
		} else {
			(void) fprintf(stderr, "%s\n", strstatus(res->status));
		}
		(void) fflush(stderr);
	}
	return (TRUE);
}

bool_t
__key_decrypt_pk_2_svc(uid, arg, res)
	uid_t uid;
	cryptkeyarg2 *arg;
	cryptkeyres *res;
{

	if (debugging) {
		(void) fprintf(stderr, "decrypt(%d, %s, %08x%08x) = ", uid,
				arg->remotename, arg->deskey.key.high,
				arg->deskey.key.low);
	}
	res->cryptkeyres_u.deskey = arg->deskey;
	res->status = pk_decrypt(uid, arg->remotename, &(arg->remotekey),
				&res->cryptkeyres_u.deskey);
	if (debugging) {
		if (res->status == KEY_SUCCESS) {
			(void) fprintf(stderr, "%08x%08x\n",
					res->cryptkeyres_u.deskey.key.high,
					res->cryptkeyres_u.deskey.key.low);
		} else {
			(void) fprintf(stderr, "%s\n", strstatus(res->status));
		}
		(void) fflush(stderr);
	}
	return (TRUE);
}

bool_t
__key_net_put_2_svc(uid, arg, status)
	uid_t uid;
	key_netstarg *arg;
	keystatus *status;
{

	if (debugging) {
		(void) fprintf(stderr, "net_put(%s, %.*s, %.*s) = ",
			arg->st_netname, sizeof (arg->st_pub_key),
			arg->st_pub_key, sizeof (arg->st_priv_key),
			arg->st_priv_key);
	};

	*status = pk_netput(uid, arg);

	if (debugging) {
		(void) fprintf(stderr, "%s\n", strstatus(*status));
		(void) fflush(stderr);
	}

	return (TRUE);
}

/* ARGSUSED */
bool_t
__key_net_get_2_svc(uid, arg, keynetname)
	uid_t uid;
	void *arg;
	key_netstres *keynetname;
{

	if (debugging)
		(void) fprintf(stderr, "net_get(%d) = ", uid);

	keynetname->status = pk_netget(uid, &keynetname->key_netstres_u.knet);
	if (debugging) {
		if (keynetname->status == KEY_SUCCESS) {
			fprintf(stderr, "<%s, %.*s, %.*s>\n",
			keynetname->key_netstres_u.knet.st_netname,
			sizeof (keynetname->key_netstres_u.knet.st_pub_key),
			keynetname->key_netstres_u.knet.st_pub_key,
			sizeof (keynetname->key_netstres_u.knet.st_priv_key),
			keynetname->key_netstres_u.knet.st_priv_key);
		} else {
			(void) fprintf(stderr, "NOT FOUND\n");
		}
		(void) fflush(stderr);
	}

	return (TRUE);

}

bool_t
__key_get_conv_2_svc(uid, arg, res)
	uid_t uid;
	keybuf arg;
	cryptkeyres *res;
{

	if (debugging)
		(void) fprintf(stderr, "get_conv(%d, %.*s) = ", uid,
			sizeof (arg), arg);


	res->status = pk_get_conv_key(uid, arg, res);

	if (debugging) {
		if (res->status == KEY_SUCCESS) {
			(void) fprintf(stderr, "%08x%08x\n",
				res->cryptkeyres_u.deskey.key.high,
				res->cryptkeyres_u.deskey.key.low);
		} else {
			(void) fprintf(stderr, "%s\n", strstatus(res->status));
		}
		(void) fflush(stderr);
	}
	return (TRUE);
}


bool_t
__key_encrypt_1_svc(uid, arg, res)
	uid_t uid;
	cryptkeyarg *arg;
	cryptkeyres *res;
{

	if (debugging) {
		(void) fprintf(stderr, "encrypt(%d, %s, %08x%08x) = ", uid,
				arg->remotename, arg->deskey.key.high,
				arg->deskey.key.low);
	}
	res->cryptkeyres_u.deskey = arg->deskey;
	res->status = pk_encrypt(uid, arg->remotename, NULL,
				&res->cryptkeyres_u.deskey);
	if (debugging) {
		if (res->status == KEY_SUCCESS) {
			(void) fprintf(stderr, "%08x%08x\n",
					res->cryptkeyres_u.deskey.key.high,
					res->cryptkeyres_u.deskey.key.low);
		} else {
			(void) fprintf(stderr, "%s\n", strstatus(res->status));
		}
		(void) fflush(stderr);
	}
	return (TRUE);
}

bool_t
__key_decrypt_1_svc(uid, arg, res)
	uid_t uid;
	cryptkeyarg *arg;
	cryptkeyres *res;
{
	if (debugging) {
		(void) fprintf(stderr, "decrypt(%d, %s, %08x%08x) = ", uid,
				arg->remotename, arg->deskey.key.high,
				arg->deskey.key.low);
	}
	res->cryptkeyres_u.deskey = arg->deskey;
	res->status = pk_decrypt(uid, arg->remotename, NULL,
				&res->cryptkeyres_u.deskey);
	if (debugging) {
		if (res->status == KEY_SUCCESS) {
			(void) fprintf(stderr, "%08x%08x\n",
					res->cryptkeyres_u.deskey.key.high,
					res->cryptkeyres_u.deskey.key.low);
		} else {
			(void) fprintf(stderr, "%s\n", strstatus(res->status));
		}
		(void) fflush(stderr);
	}
	return (TRUE);
}

/* ARGSUSED */
bool_t
__key_gen_1_svc(v, s, key)
	void *v;
	struct svc_req *s;
	des_block *key;
{
	struct timeval time;
	static des_block keygen;
	static mutex_t keygen_mutex = DEFAULTMUTEX;
	int r;

	(void) gettimeofday(&time, (struct timezone *)NULL);
	(void) mutex_lock(&keygen_mutex);
	keygen.key.high += (time.tv_sec ^ time.tv_usec);
	keygen.key.low += (time.tv_sec ^ time.tv_usec);
	r = ecb_crypt((char *)&masterkey, (char *)&keygen, sizeof (keygen),
		DES_ENCRYPT | DES_HW);
	if (r != DESERR_NONE && r != DESERR_NOHWDEVICE) {
		mutex_unlock(&keygen_mutex);
		return (FALSE);
	}
	*key = keygen;
	mutex_unlock(&keygen_mutex);

	des_setparity_g(key);
	if (debugging) {
		(void) fprintf(stderr, "gen() = %08x%08x\n", key->key.high,
					key->key.low);
		(void) fflush(stderr);
	}
	return (TRUE);
}

/* ARGSUSED */
bool_t
__key_getcred_1_svc(uid, name, res)
	uid_t uid;
	netnamestr *name;
	getcredres *res;
{
	struct unixcred *cred;

	cred = &res->getcredres_u.cred;
	if (!netname2user(*name, (uid_t *)&cred->uid, (gid_t *)&cred->gid,
			(int *)&cred->gids.gids_len,
					(gid_t *)cred->gids.gids_val)) {
		res->status = KEY_UNKNOWN;
	} else {
		res->status = KEY_SUCCESS;
	}
	if (debugging) {
		(void) fprintf(stderr, "getcred(%s) = ", *name);
		if (res->status == KEY_SUCCESS) {
			(void) fprintf(stderr, "uid=%d, gid=%d, grouplen=%d\n",
				cred->uid, cred->gid, cred->gids.gids_len);
		} else {
			(void) fprintf(stderr, "%s\n", strstatus(res->status));
		}
		(void) fflush(stderr);
	}
	return (TRUE);
}

/*
 * Version 3 procedures follow...
 */

static bool_t
__key_set_3_svc(uid_t uid, setkeyarg3 *arg, keystatus *status)
{
	debug(KEYSERV_DEBUG, ("__key_set_3_svc(%d, %d, %d)",
	    uid, arg->algtype, arg->keylen));
	*status = pk_setkey3(uid, arg);
	debug(KEYSERV_DEBUG, ("__key_set_3_svc %s", strstatus(*status)));
	return (TRUE);
}

static bool_t
__key_encrypt_3_svc(uid_t uid, cryptkeyarg3 *arg, cryptkeyres3 *res)
{
	int len, i;
	des_block *dp;

	debug(KEYSERV_DEBUG, ("encrypt_3(%d %d %s)", uid,
	    arg->deskey.deskeyarray_len, arg->remotename));
	res->status = pk_encrypt3(uid, arg, &res->cryptkeyres3_u.deskey);
	len = res->cryptkeyres3_u.deskey.deskeyarray_len;
	dp = res->cryptkeyres3_u.deskey.deskeyarray_val;
	for (i = 0; i < len; i++) {
		debug(KEYSERV_DEBUG0, ("encrypt_3 retval[%d] == (%x,%x)",
		    i, dp->key.high, dp->key.low));
		dp++;
	}
	debug(KEYSERV_DEBUG, ("encrypt_3 returned %s", strstatus(res->status)));
	return (TRUE);
}

static bool_t
__key_decrypt_3_svc(uid_t uid, cryptkeyarg3 *arg, cryptkeyres3 *res)
{
	int len, i;
	des_block *dp;

	debug(KEYSERV_DEBUG, ("decrypt_3(%d, %d, %s)", uid,
	    arg->deskey.deskeyarray_len, arg->remotename));
	res->status = pk_decrypt3(uid, arg, &res->cryptkeyres3_u.deskey);
	len = res->cryptkeyres3_u.deskey.deskeyarray_len;
	dp = res->cryptkeyres3_u.deskey.deskeyarray_val;
	for (i = 0; i < len; i++) {
		debug(KEYSERV_DEBUG0, ("decrypt_3 retval[%d] == (%x,%x)",
		    i, dp->key.high, dp->key.low));
		dp++;
	}
	debug(KEYSERV_DEBUG, ("decrypt_3 returned %s", strstatus(res->status)));
	return (TRUE);
}

/* ARGSUSED */
static bool_t
__key_gen_3_svc(void *v, keynum_t *kp, deskeyarray *res)
{
	int i;
	keynum_t keynum = *kp;

	debug(KEYSERV_DEBUG, ("gen_3(%d %x)", keynum, res));
	res->deskeyarray_val = 0;
	if (!setdeskeyarray(res, keynum)) {
		return (FALSE);
	}
	for (i = 0; i < keynum; i++) {
		debug(KEYSERV_DEBUG, ("gen_3 calling gen_1 %x",
		    res->deskeyarray_val+i));
		__key_gen_1_svc((void *) NULL, (struct svc_req *)NULL,
		    res->deskeyarray_val+i);
		debug(KEYSERV_DEBUG, ("gen_3 val %d %x",
		    i, *(int *)(res->deskeyarray_val+i)));
	}
	return (TRUE);
}

static void
__key_gen_3_svc_free(deskeyarray *dp)
{
	free(dp->deskeyarray_val);
}

static bool_t
__key_getcred_3_svc(uid_t uid, netnamestr *name, getcredres3 *res)
{
	return (__key_getcred_1_svc(uid, name, (getcredres *)res));
}

static bool_t
__key_encrypt_pk_3_svc(uid_t uid, cryptkeyarg3 *arg, cryptkeyres3 *res)
{
	debug(KEYSERV_DEBUG, ("encrypt_pk_3(%d, %s)", uid, arg->remotename));
	res->status = pk_encrypt3(uid, arg, &res->cryptkeyres3_u.deskey);
	debug(KEYSERV_DEBUG, ("encrypt returned %s", strstatus(res->status)));
	return (TRUE);
}

static void
__key_encrypt_pk_3_svc_free(cryptkeyres3 *res)
{
	if (res->status == KEY_SUCCESS) {
		free(res->cryptkeyres3_u.deskey.deskeyarray_val);
	}
}

static bool_t
__key_decrypt_pk_3(uid_t uid, cryptkeyarg3 *arg, cryptkeyres3 *res)
{
	debug(KEYSERV_DEBUG, ("decrypt_pk_3(%d, %s)", uid, arg->remotename));
	res->status = pk_decrypt3(uid, arg, &res->cryptkeyres3_u.deskey);
	debug(KEYSERV_DEBUG, ("encrypt returned %s", strstatus(res->status)));
	return (TRUE);
}

static void
__key_decrypt_pk_3_free(cryptkeyres3 *res)
{
	if (res->status == KEY_SUCCESS) {
		free(res->cryptkeyres3_u.deskey.deskeyarray_val);
	}
}

static bool_t
__key_net_put_3_svc(uid_t uid, key_netstarg3 *arg, keystatus *status)
{
	debug(KEYSERV_DEBUG, ("net_put_3 (%d, %x)", uid, arg));
	*status = pk_netput3(uid, arg);
	debug(KEYSERV_DEBUG, ("net_put_3 ret %s", strstatus(*status)));
	return (TRUE);
}

static bool_t
__key_net_get_3_svc(uid_t uid, mechtype *arg, key_netstres3 *keynetname)
{
	debug(KEYSERV_DEBUG, ("net_get_3 (%d, %x)", uid, arg));
	keynetname->status = pk_netget3(uid,
	    arg, &keynetname->key_netstres3_u.knet);
	debug(KEYSERV_DEBUG,
	    ("net_get_3 ret %s", strstatus(keynetname->status)));
	return (TRUE);
}

static void
__key_net_get_3_svc_free(key_netstres3 *keynetname)
{
	if (keynetname->status == KEY_SUCCESS) {
		free(keynetname->key_netstres3_u.knet.st_priv_key.keybuf3_val);
		free(keynetname->key_netstres3_u.knet.st_pub_key.keybuf3_val);
		free(keynetname->key_netstres3_u.knet.st_netname);
	}
}

static bool_t
__key_get_conv_3_svc(uid_t uid, deskeyarg3 *arg, cryptkeyres3 *res)
{
	debug(KEYSERV_DEBUG, ("get_conv_3(%d %x %x)", uid, arg, res));
	res->status = pk_get_conv_key3(uid, arg, res);
	debug(KEYSERV_DEBUG,
	    ("get_conv_3 ret %s", strstatus(res->status)));
	return (TRUE);
}

/* ARGSUSED */
static bool_t
__key_clear_3_svc(uid_t uid, void *arg, keystatus *status)
{
	debug(KEYSERV_DEBUG, ("clear_3(%d)", uid));
	*status = pk_clear3(uid);
	debug(KEYSERV_DEBUG, ("clear_3 ret %s", strstatus(*status)));
	return (TRUE);
}

/*
 * RPC boilerplate
 */
static void
keyprogram(rqstp, transp)
	struct svc_req *rqstp;
	SVCXPRT *transp;
{
	union {
		keybuf key_set_1_arg;
		cryptkeyarg key_encrypt_1_arg;
		cryptkeyarg key_decrypt_1_arg;
		netnamestr key_getcred_1_arg;
		cryptkeyarg key_encrypt_2_arg;
		cryptkeyarg key_decrypt_2_arg;
		netnamestr key_getcred_2_arg;
		cryptkeyarg2 key_encrypt_pk_2_arg;
		cryptkeyarg2 key_decrypt_pk_2_arg;
		key_netstarg key_net_put_2_arg;
		netobj  key_get_conv_2_arg;
		keybuf3 key_set_3_arg;
		cryptkeyarg3 key_encrypt_3_arg;
		cryptkeyarg3 key_decrypt_3_arg;
		cryptkeyarg3 key_encrypt_pk_3_arg;
		cryptkeyarg3 key_decrypt_pk_3_arg;
		keynum_t key_gen_3_arg;
		netnamestr key_getcred_3_arg;
		key_netstarg3 key_net_put_3_arg;
		key_netstarg3 key_net_get_3_arg;
		deskeyarg3 key_get_conv_3_arg;
	} argument;
	union {
		keystatus status;
		cryptkeyres cres;
		des_block key;
		getcredres gres;
		key_netstres keynetname;
		cryptkeyres3 cres3;
		deskeyarray keyarray;
		getcredres3 gres3;
		key_netstres3 keynetname3;
	} result;
	uint_t gids[MAXGIDS];
	char netname_str[MAXNETNAMELEN + 1];
	bool_t (*xdr_argument)(), (*xdr_result)();
	bool_t (*local)();
	void (*local_free)() = NULL;
	bool_t retval;
	uid_t uid;
	int check_auth;

	switch (rqstp->rq_proc) {
	case NULLPROC:
		svc_sendreply(transp, xdr_void, (char *)NULL);
		return;

	case KEY_SET:
		xdr_argument = xdr_keybuf;
		xdr_result = xdr_int;
		local = __key_set_1_svc;
		check_auth = 1;
		break;

	case KEY_ENCRYPT:
		xdr_argument = xdr_cryptkeyarg;
		xdr_result = xdr_cryptkeyres;
		local = __key_encrypt_1_svc;
		check_auth = 1;
		break;

	case KEY_DECRYPT:
		xdr_argument = xdr_cryptkeyarg;
		xdr_result = xdr_cryptkeyres;
		local = __key_decrypt_1_svc;
		check_auth = 1;
		break;

	case KEY_GEN:
		xdr_argument = xdr_void;
		xdr_result = xdr_des_block;
		local = __key_gen_1_svc;
		check_auth = 0;
		break;

	case KEY_GETCRED:
		xdr_argument = xdr_netnamestr;
		xdr_result = xdr_getcredres;
		local = __key_getcred_1_svc;
		result.gres.getcredres_u.cred.gids.gids_val = gids;
		check_auth = 0;
		break;

	case KEY_ENCRYPT_PK:
		xdr_argument = xdr_cryptkeyarg2;
		xdr_result = xdr_cryptkeyres;
		local = __key_encrypt_pk_2_svc;
		check_auth = 1;
		break;

	case KEY_DECRYPT_PK:
		xdr_argument = xdr_cryptkeyarg2;
		xdr_result = xdr_cryptkeyres;
		local = __key_decrypt_pk_2_svc;
		check_auth = 1;
		break;


	case KEY_NET_PUT:
		xdr_argument = xdr_key_netstarg;
		xdr_result = xdr_keystatus;
		local = __key_net_put_2_svc;
		check_auth = 1;
		break;

	case KEY_NET_GET:
		xdr_argument = (xdrproc_t)xdr_void;
		xdr_result = xdr_key_netstres;
		local = __key_net_get_2_svc;
		result.keynetname.key_netstres_u.knet.st_netname = netname_str;
		check_auth = 1;
		break;

	case KEY_GET_CONV:
		xdr_argument = (xdrproc_t)xdr_keybuf;
		xdr_result = xdr_cryptkeyres;
		local = __key_get_conv_2_svc;
		check_auth = 1;
		break;

	/*
	 * Version 3 procedures follow...
	 */

	case KEY_SET_3:
		xdr_argument = (xdrproc_t)xdr_setkeyarg3;
		xdr_result = xdr_keystatus;
		local = __key_set_3_svc;
		check_auth = 1;
		break;

	case KEY_ENCRYPT_3:
		xdr_argument = (xdrproc_t)xdr_cryptkeyarg3;
		xdr_result = xdr_cryptkeyres3;
		local = __key_encrypt_3_svc;
		check_auth = 1;
		break;

	case KEY_DECRYPT_3:
		xdr_argument = (xdrproc_t)xdr_cryptkeyarg3;
		xdr_result = xdr_cryptkeyres3;
		local = __key_decrypt_3_svc;
		check_auth = 1;
		break;

	case KEY_GEN_3:
		xdr_argument = (xdrproc_t)xdr_keynum_t;
		xdr_result = xdr_deskeyarray;
		local = __key_gen_3_svc;
		local_free = __key_gen_3_svc_free;
		check_auth = 0;
		break;

	case KEY_GETCRED_3:
		xdr_argument = (xdrproc_t)xdr_netnamestr;
		xdr_result = xdr_getcredres3;
		local = __key_getcred_3_svc;
		check_auth = 0;
		break;

	case KEY_ENCRYPT_PK_3:
		xdr_argument = (xdrproc_t)xdr_cryptkeyarg3;
		xdr_result = xdr_cryptkeyres3;
		local = __key_encrypt_pk_3_svc;
		local_free = __key_encrypt_pk_3_svc_free;
		check_auth = 1;
		break;

	case KEY_DECRYPT_PK_3:
		xdr_argument = (xdrproc_t)xdr_cryptkeyarg3;
		xdr_result = xdr_cryptkeyres3;
		local = __key_decrypt_pk_3;
		local_free = __key_decrypt_pk_3_free;
		check_auth = 1;
		break;

	case KEY_NET_PUT_3:
		xdr_argument = (xdrproc_t)xdr_key_netstarg3;
		xdr_result = xdr_keystatus;
		local = __key_net_put_3_svc;
		check_auth = 1;
		break;

	case KEY_NET_GET_3:
		xdr_argument = (xdrproc_t)xdr_mechtype;
		xdr_result = xdr_key_netstres3;
		local = __key_net_get_3_svc;
		local_free = __key_net_get_3_svc_free;
		check_auth = 1;
		break;

	case KEY_GET_CONV_3:
		xdr_argument = (xdrproc_t)xdr_deskeyarg3;
		xdr_result = xdr_cryptkeyres3;
		local = __key_get_conv_3_svc;
		check_auth = 1;
		break;

	case KEY_CLEAR_3:
		xdr_argument = (xdrproc_t)xdr_void;
		xdr_result = xdr_keystatus;
		local = __key_clear_3_svc;
		check_auth = 1;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	if (check_auth) {
		if (!get_auth(transp, rqstp, &uid)) {
			if (debugging) {
				(void) fprintf(stderr,
					"not local privileged process\n");
			}
			svcerr_weakauth(transp);
			return;
		}
	}

	memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t)&argument)) {
		svcerr_decode(transp);
		return;
	}
	retval = (*local)(uid, &argument, &result);
	if (retval && !svc_sendreply(transp, xdr_result, (char *)&result)) {
		if (debugging)
			(void) fprintf(stderr, "unable to reply\n");
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, xdr_argument, (caddr_t)&argument)) {
		if (debugging)
			(void) fprintf(stderr,
			"unable to free arguments\n");
		exit(1);
	}
	if (local_free) {
		(*local_free)(&result);
	}
}

static bool_t
get_auth(trans, rqstp, uid)
	SVCXPRT *trans;
	struct svc_req *rqstp;
	uid_t *uid;
{
	svc_local_cred_t cred;

	if (!svc_get_local_cred(trans, &cred)) {
		if (debugging)
			fprintf(stderr, "svc_get_local_cred failed %s %s\n",
				trans->xp_netid, trans->xp_tp);
		return (FALSE);
	}
	if (debugging)
		fprintf(stderr, "local_uid  %d\n", cred.euid);
	if (rqstp->rq_cred.oa_flavor == AUTH_SYS ||
	    rqstp->rq_cred.oa_flavor == AUTH_LOOPBACK) {
		CTASSERT(sizeof (struct authunix_parms) <= RQCRED_SIZE);
/* LINTED pointer alignment */
		*uid = ((struct authunix_parms *)rqstp->rq_clntcred)->aup_uid;
		return (*uid == cred.euid || cred.euid == 0);
	} else {
		*uid = cred.euid;
		return (TRUE);
	}
}

static int
get_cache_size(size)
char *size;
{
	int csize, len;

	len = (int)strlen(size);
	if (len == 0) {
		usage();
	}

	if (size[len-1] == 'M' || size[len-1] == 'm') {
		/*
		 * cache size in MB
		 */
		size[len-1] = '\0';
		csize = atoi(size);
	} else {
		csize = atoi(size);
		/*
		 * negative size indicates number of entries in cache
		 */
		csize = 0 - csize;
	}

	if (csize == 0) {
		(void) fprintf(stderr, "invalid cache size: %s\n", size);
		usage();
	}

	return (csize);
}

static void
usage()
{
	(void) fprintf(stderr, "usage: \n");
	(void) fprintf(stderr, "keyserv [-c]|[-s ");
	(void) fprintf(stderr, "<size>|<mechtype>=<size>[,...]] [-n] [-D] ");
	(void) fprintf(stderr, "[-d | -e] ");
	(void) fprintf(stderr, "[-t threads]\n");
	(void) fprintf(stderr, "-d disables the use of default keys\n");
	(void) fprintf(stderr, "-e enables the use of default keys\n");
	exit(1);
}

static void
defaults(void)
{
	register int  flags;
	register char *ptr;

	if (defopen(defaults_file) == 0) {
		/*
		 * ignore case
		 */
		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);

		if ((ptr = defread("ENABLE_NOBODY_KEYS=")) != NULL) {
			if (strcasecmp(ptr, "NO") == 0) {
				use_nobody_keys = FALSE;
			}
		}

		(void) defopen((char *)NULL);
	}
}
