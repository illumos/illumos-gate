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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Joyent, Inc.
 */

#ifndef	_IPSEC_UTIL_H
#define	_IPSEC_UTIL_H

/*
 * Headers and definitions for support functions that are shared by
 * the ipsec utilities ipseckey and ikeadm.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <setjmp.h>
#include <stdio.h>
#include <err.h>
#include <errfp.h>
#include <net/pfpolicy.h>
#include <libtecla.h>

#ifndef A_CNT
/* macros for array manipulation */
#define	A_CNT(arr)	(sizeof (arr)/sizeof (arr[0]))
#define	A_END(arr)	(&arr[A_CNT(arr)])
#endif

/* used for file parsing */
#define	NBUF_SIZE	16
#define	COMMENT_CHAR	'#'
#define	CONT_CHAR	'\\'
#define	QUOTE_CHAR	'"'
/*
 * Input buffer size limits maximum line length for both file parsing and
 * interactive mode. 4K chars should be enough even for broad commands and
 * all possible key lenghts of today's symmetric ciphers entered via
 * ipseckey(1M) which has the most bifurcated grammar from all IPsec commands.
 */
#define	IBUF_SIZE	4096

/* used for command-line parsing */
#define	START_ARG	8
#define	TOO_MANY_ARGS	(START_ARG << 9)

/* Return codes for argv/argc vector creation */
#define	TOO_MANY_TOKENS		-3
#define	MEMORY_ALLOCATION	-2
#define	COMMENT_LINE		1
#define	SUCCESS			0

/* Flags for {bytecnt,secs}2out() */
#define	SPC_NOSPACES	0x00000000		/* no space prefix/suffix */
#define	SPC_BEGIN	0x00000001		/* put space at the beginning */
#define	SPC_END		0x00000002		/* put space at the end */
#define	SPC_BOTH	SPC_BEGIN|SPC_END	/* print both spaces */

/*
 * The following lengths should be sufficient for character buffers passed to
 * bytecnt2str(),secs2str(). This is because the string output of these
 * functions consists of limited number and units. The lengths should be also
 * sufficient for bytecnt2out(),secs2out() functions.
 */
#define	BYTE_STR_SIZE		16
#define	SECS_STR_SIZE		20

/*
 * Time printing defines...
 *
 * TBUF_SIZE is pretty arbitrary.  Perhaps it shouldn't be.
 */
#define	TBUF_SIZE	50
#define	TIME_MAX	LONG_MAX

#ifndef INSECURE_PERMS
#define	INSECURE_PERMS(sbuf)	(((sbuf).st_uid != 0) || \
	((sbuf).st_mode & S_IRWXG) || ((sbuf).st_mode & S_IRWXO))
#endif

#ifndef PKCS11_TOKSIZE
#define	PKCS11_TOKSIZE 32	/* Fixed length of PKCS#11 token string len. */
#endif

/*
 * Solaris UDP port used to communicate with the Solaris Cluster
 * daemon. It is used only when the node is booted in cluster mode.
 */
#define	CLUSTER_UDP_PORT	2005

/* For keyword-lookup tables */
typedef struct keywdtab {
	uint_t	kw_tag;
	char	*kw_str;
} keywdtab_t;

/*
 * These different exit states are designed to give consistant behaviour
 * when a program needs to exit because of an error. These exit_types
 * are used in macros, defined later in this file, which call ipsecutil_exit().
 * What happens when ipsecutil_exit() may differ if the command was started
 * on the command line or via smf(5), See ipsecutil_exit() source for details.
 *
 * Note: The calling function should decide what "debug mode" is before calling
 * ipsecutil_exit() with DEBUG_FATAL.
 */
typedef enum exit_type {
	SERVICE_EXIT_OK,	/* Exit without error. */
	SERVICE_DEGRADE,	/* A hint that service should be degraded. */
	SERVICE_BADPERM,	/* A Permission error occured. */
	SERVICE_BADCONF,	/* Misconfiguration. */
	SERVICE_MAINTAIN,	/* smf(5) to put service in maintenance mode. */
	SERVICE_DISABLE,	/* Tell smf(5) to disable me. */
	SERVICE_FATAL,		/* Whatever happened is not fixable. */
	SERVICE_RESTART,	/* Tell smf(5) to restart the service. */
	DEBUG_FATAL		/* Exit in debug mode. */
} exit_type_t;

/*
 * Function Prototypes
 */

/*
 * Print errno and if cmdline or readfile, exit; if interactive reset state
 */
extern void ipsecutil_exit(exit_type_t, char *, FILE *, const char *fmt, ...);
extern void bail(char *);

/*
 * Localization macro - Only to be used from usr/src/cmd because Macros
 * are not expanded in usr/src/lib when message catalogs are built.
 */
#define	Bail(s)	bail(dgettext(TEXT_DOMAIN, s))

/*
 * Print caller-supplied, variable-arg error message, then exit if cmdline
 * or readfile, or reset state if interactive.
 */
extern void bail_msg(char *, ...);

/*
 * dump_XXX functions produce ASCII output from the passed in data.
 *
 * Because certain errors need to do this stderr, dump_XXX functions
 * take a FILE pointer.
 */

extern int dump_sockaddr(struct sockaddr *, uint8_t, boolean_t, FILE *,
    boolean_t);

extern int dump_key(uint8_t *, uint_t, uint_t, FILE *, boolean_t);

extern int dump_aalg(uint8_t, FILE *);

extern int dump_ealg(uint8_t, FILE *);

/* return true if sadb string is printable (based on type), false otherwise */
extern boolean_t dump_sadb_idtype(uint8_t, FILE *, int *);

/*
 * do_interactive: Enter a mode where commands are read from a file;
 * treat stdin special.  infile is the file cmds are read from;
 * promptstring is the string printed to stdout (if the cmds are
 * being read from stdin) to prompt for a new command; parseit is
 * the function to be called to process the command line once it's
 * been read in and broken up into an argv/argc vector.
 */

/* callback function passed in to do_interactive() */
typedef void (*parse_cmdln_fn)(int, char **, char *, boolean_t);

extern void do_interactive(FILE *, char *, char *, char *, parse_cmdln_fn,
    CplMatchFn *);

extern uint_t lines_parsed;
extern uint_t lines_added;

/* convert a string to an IKE_PRIV_* constant */
extern int privstr2num(char *);

/* convert a string to a D_* debug flag */
extern int dbgstr2num(char *);

/* convert a string of debug strings with +|- delimiters to a debug level */
extern int parsedbgopts(char *);

/*
 * SSL library (OpenSSL)
 */
#define	LIBSSL	"libssl.so"

void libssl_load(void);

/*
 * crypto library (OpenSSL)
 */
#define	LIBCRYPTO	"libcrypto.so"

void libcrypto_load(void);

/*
 * functions to manipulate the IKEv1 kmcookie-label mapping file
 */

#define	KMCFILE		"/var/run/ipsec_kmc_map"

/*
 * Insert a mapping into the file (if it's not already there), given the
 * new label.  Return the assigned cookie, or -1 on error.
 */
extern int kmc_insert_mapping(char *);

/*
 * Lookup the given cookie and return its corresponding label.  Return
 * a pointer to the label on success, NULL on error (or if the label is
 * not found).
 */
extern char *kmc_lookup_by_cookie(int);

/*
 * These globals are declared for us in ipsec_util.c, since it needs to
 * refer to them also...
 */
extern boolean_t nflag;	/* Avoid nameservice? */
extern boolean_t pflag;	/* Paranoid w.r.t. printing keying material? */
extern boolean_t interactive;
extern boolean_t readfile;
extern uint_t lineno;
extern char numprint[NBUF_SIZE];

/* For error recovery in interactive or read-file mode. */
extern jmp_buf env;

/*
 * Back-end stuff for getalgby*().
 */

#define	INET_IPSECALGSPATH	"/etc/inet/"
#define	INET_IPSECALGSFILE	(INET_IPSECALGSPATH "ipsecalgs")

/* To preserve packages delimiters in /etc/inet/ipsecalgs */
typedef struct ipsecalgs_pkg {
	int alg_num;
	char *pkg_name;
} ipsecalgs_pkg_t;

/*
 * The cached representation of /etc/inet/ipsecalgs is represented by:
 * - A dynamically-grown (optionally sorted) array of IPsec protocols
 * - Each protocol has an array (again, dynamically grown and sorted)
 *   of algorithms, each a full-fledged struct ipsecalgent.
 * - The getipsecalg*() routines will search the list, then duplicate the
 *   struct ipsecalgent and return it.
 */

typedef enum {
	LIBIPSEC_ALGS_EXEC_SYNC,
	LIBIPSEC_ALGS_EXEC_ASYNC
} ipsecalgs_exec_mode_t;

typedef struct ipsec_proto {
	int proto_num;
	char *proto_name;
	char *proto_pkg;
	int proto_numalgs;
	struct ipsecalgent **proto_algs;
	ipsecalgs_pkg_t *proto_algs_pkgs;
	int proto_algs_npkgs;
	ipsecalgs_exec_mode_t proto_exec_mode;
} ipsec_proto_t;

extern void _build_internal_algs(ipsec_proto_t **, int *);
extern int _str_to_ipsec_exec_mode(char *, ipsecalgs_exec_mode_t *);

extern int addipsecalg(struct ipsecalgent *, uint_t);
extern int delipsecalgbyname(const char *, int);
extern int delipsecalgbynum(int, int);
extern int addipsecproto(const char *, int, ipsecalgs_exec_mode_t, uint_t);
extern int delipsecprotobyname(const char *);
extern int delipsecprotobynum(int);
extern int *getipsecprotos(int *);
extern int *getipsecalgs(int *, int);
extern int list_ints(FILE *, int *);
extern const char *ipsecalgs_diag(int);
extern int ipsecproto_get_exec_mode(int, ipsecalgs_exec_mode_t *);
extern int ipsecproto_set_exec_mode(int, ipsecalgs_exec_mode_t);

/* Flags for add/delete routines. */
#define	LIBIPSEC_ALGS_ADD_FORCE 0x00000001

/*
 * Helper definitions for indices into array of key sizes when key sizes
 * are defined by range.
 */
#define	LIBIPSEC_ALGS_KEY_DEF_IDX	0	/* default key size */
#define	LIBIPSEC_ALGS_KEY_MIN_IDX	1	/* min key size */
#define	LIBIPSEC_ALGS_KEY_MAX_IDX	2	/* max key size */
#define	LIBIPSEC_ALGS_KEY_NUM_VAL	4	/* def, min, max, 0 */

/* Error codes for IPsec algorithms management */
#define	LIBIPSEC_ALGS_DIAG_ALG_EXISTS		-1
#define	LIBIPSEC_ALGS_DIAG_PROTO_EXISTS		-2
#define	LIBIPSEC_ALGS_DIAG_UNKN_PROTO		-3
#define	LIBIPSEC_ALGS_DIAG_UNKN_ALG		-4
#define	LIBIPSEC_ALGS_DIAG_NOMEM		-5
#define	LIBIPSEC_ALGS_DIAG_ALGSFILEOPEN		-6
#define	LIBIPSEC_ALGS_DIAG_ALGSFILEFDOPEN	-7
#define	LIBIPSEC_ALGS_DIAG_ALGSFILELOCK		-8
#define	LIBIPSEC_ALGS_DIAG_ALGSFILERENAME	-9
#define	LIBIPSEC_ALGS_DIAG_ALGSFILEWRITE	-10
#define	LIBIPSEC_ALGS_DIAG_ALGSFILECHMOD	-11
#define	LIBIPSEC_ALGS_DIAG_ALGSFILECHOWN	-12
#define	LIBIPSEC_ALGS_DIAG_ALGSFILECLOSE	-13

/* /etc/inet/ipsecalgs keywords and package sections delimiters */
#define	LIBIPSEC_ALGS_LINE_PROTO		"PROTO|"
#define	LIBIPSEC_ALGS_LINE_ALG			"ALG|"
#define	LIBIPSEC_ALGS_LINE_PKGSTART		"# Start "
#define	LIBIPSEC_ALGS_LINE_PKGEND		"# End "

/* Put these in libnsl for and process caching testing. */
extern int *_real_getipsecprotos(int *);
extern int *_real_getipsecalgs(int *, int);
extern struct ipsecalgent *_duplicate_alg(struct ipsecalgent *);
extern void _clean_trash(ipsec_proto_t *, int);

/* spdsock support functions */

/* Return values for spdsock_get_ext(). */
#define	KGE_OK	0
#define	KGE_DUP	1
#define	KGE_UNK	2
#define	KGE_LEN	3
#define	KGE_CHK	4

extern int spdsock_get_ext(spd_ext_t *[], spd_msg_t *, uint_t, char *, uint_t);
extern const char *spdsock_diag(int);

/* PF_KEY (keysock) support functions */
extern const char *keysock_diag(int);
extern int in_masktoprefix(uint8_t *, boolean_t);

/* SA support functions */

extern char *secs2out(unsigned int, char *, int, int);
extern char *secs2str(unsigned int, char *, int);
extern char *bytecnt2out(uint64_t, char *, size_t, int);
extern char *bytecnt2str(uint64_t, char *, size_t);
extern void print_diagnostic(FILE *, uint16_t);
extern void print_sadb_msg(FILE *, struct sadb_msg *, time_t, boolean_t);
extern void print_sa(FILE *, char *, struct sadb_sa *);
extern void printsatime(FILE *, int64_t, const char *, const char *,
    const char *, boolean_t);
extern void print_lifetimes(FILE *, time_t, struct sadb_lifetime *,
    struct sadb_lifetime *, struct sadb_lifetime *, struct sadb_lifetime *,
    boolean_t vflag);
extern void print_address(FILE *, char *, struct sadb_address *, boolean_t);
extern void print_asn1_name(FILE *, const unsigned char *, long);
extern void print_key(FILE *, char *, struct sadb_key *);
extern void print_ident(FILE *, char *, struct sadb_ident *);
extern void print_sens(FILE *, char *, const struct sadb_sens *, boolean_t);
extern void print_prop(FILE *, char *, struct sadb_prop *);
extern void print_eprop(FILE *, char *, struct sadb_prop *);
extern void print_supp(FILE *, char *, struct sadb_supported *);
extern void print_spirange(FILE *, char *, struct sadb_spirange *);
extern void print_kmc(FILE *, char *, struct sadb_x_kmc *);
extern void print_samsg(FILE *, uint64_t *, boolean_t, boolean_t, boolean_t);
extern char *rparsesatype(int);
extern char *rparsealg(uint8_t, int);
extern char *rparseidtype(uint16_t);
extern boolean_t save_lifetime(struct sadb_lifetime *, FILE *);
extern boolean_t save_address(struct sadb_address *, FILE *);
extern boolean_t save_key(struct sadb_key *, FILE *);
extern boolean_t save_ident(struct sadb_ident *, FILE *);
extern void save_assoc(uint64_t *, FILE *);
extern FILE *opensavefile(char *);
extern const char *do_inet_ntop(const void *, char *, size_t);

/*
 * Label conversion convenience functions.
 */

#include <tsol/label.h>

extern void ipsec_convert_sens_to_bslabel(const struct sadb_sens *,
    bslabel_t *);
extern int ipsec_convert_sl_to_sens(int doi, bslabel_t *, struct sadb_sens *);
extern void ipsec_convert_bslabel_to_string(bslabel_t *, char **);
extern void ipsec_convert_bslabel_to_hex(bslabel_t *, char **);

/*
 * These exit macros give a consistent exit behaviour for all
 * programs that use libipsecutil. These wll work in usr/src/cmd
 * and usr/src/lib, but because macros in usr/src/lib don't get
 * expanded when I18N message catalogs are built, avoid using
 * these with text inside libipsecutil. See source of ipsecutil_exit()
 * for more details.
 */
#define	EXIT_OK(x) \
	ipsecutil_exit(SERVICE_EXIT_OK, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x))
#define	EXIT_OK2(x, y) \
	ipsecutil_exit(SERVICE_EXIT_OK, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x), y)
#define	EXIT_OK3(x, y, z) \
	ipsecutil_exit(SERVICE_EXIT_OK, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x), y, z)
#define	EXIT_BADCONFIG(x) \
	ipsecutil_exit(SERVICE_BADCONF, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x))
#define	EXIT_BADCONFIG2(x, y) \
	ipsecutil_exit(SERVICE_BADCONF, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x), y)
#define	EXIT_BADCONFIG3(x, y, z) \
	ipsecutil_exit(SERVICE_BADCONF, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x), y, z)
#define	EXIT_MAINTAIN(x) \
	ipsecutil_exit(SERVICE_MAINTAIN, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x))
#define	EXIT_MAINTAIN2(x, y) \
	ipsecutil_exit(SERVICE_MAINTAIN, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x), y)
#define	EXIT_DEGRADE(x) \
	ipsecutil_exit(SERVICE_DEGRADE, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x))
#define	EXIT_BADPERM(x) \
	ipsecutil_exit(SERVICE_BADPERM, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x))
#define	EXIT_BADPERM2(x, y) \
	ipsecutil_exit(SERVICE_BADPERM, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x), y)
#define	EXIT_FATAL(x) \
	ipsecutil_exit(SERVICE_FATAL, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x))
#define	EXIT_FATAL2(x, y) \
	ipsecutil_exit(SERVICE_FATAL, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x), y)
#define	EXIT_FATAL3(x, y, z) \
	ipsecutil_exit(SERVICE_FATAL, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x), y, z)
#define	EXIT_RESTART(x) \
	ipsecutil_exit(SERVICE_RESTART, my_fmri, debugfile, \
	dgettext(TEXT_DOMAIN, x))

#ifdef __cplusplus
}
#endif

#endif	/* _IPSEC_UTIL_H */
