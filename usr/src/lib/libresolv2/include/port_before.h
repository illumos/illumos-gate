/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef SUNW_OPTIONS
#include "conf/sunoptions.h"
#endif

#define __EXTENSIONS__
/* #define SVR4 */
#ifdef	WANT_IRS_NIS
#undef	WANT_IRS_NIS
#endif
#undef WANT_IRS_PW
#undef WANT_IRS_GR
#define SIG_FN void
#define ISC_SOCKLEN_T int
#include "os_version.h"
#if (OS_MAJOR == 5 && OS_MINOR < 5)
#undef HAS_PTHREADS
#else
#define HAS_PTHREADS
#endif

#if defined(HAS_PTHREADS) && defined(_REENTRANT)
#define DO_PTHREADS
#endif

#define GROUP_R_RETURN struct group *
#define GROUP_R_SET_RETURN void
#undef GROUP_R_SET_RESULT /*empty*/
#define GROUP_R_END_RETURN void
#undef GROUP_R_END_RESULT  /*empty*/
#define GROUP_R_ARGS char *buf, int buflen
#undef GROUP_R_ENT_ARGS /*empty*/
#define GROUP_R_OK gptr
#define GROUP_R_BAD NULL
#define GETGROUPLIST_ARGS const char *name, gid_t basegid, gid_t *groups, \
		      int *ngroups

#define HOST_R_RETURN struct hostent *
#define HOST_R_SET_RETURN void
#undef HOST_R_SET_RESULT /*empty*/
#define HOST_R_END_RETURN void
#define HOST_R_END_RESULT(x)	/*empty*/
#define HOST_R_ARGS char *buf, int buflen, int *h_errnop
#undef HOST_R_ENT_ARGS /*empty*/
#define HOST_R_COPY buf, buflen
#define HOST_R_COPY_ARGS char *buf, int buflen
#define HOST_R_ERRNO *h_errnop = h_errno
#define HOST_R_OK hptr
#define HOST_R_BAD NULL

#define NET_R_RETURN struct netent *
#define NET_R_SET_RETURN void
#undef NET_R_SET_RESULT /*empty*/
#define NET_R_END_RETURN void
#define NET_R_END_RESULT(x)  /*empty*/
#define NET_R_ARGS char *buf, int buflen
#undef NET_R_ENT_ARGS /*empty*/
#define NET_R_COPY buf, buflen
#define NET_R_COPY_ARGS NET_R_ARGS
#define NET_R_OK nptr
#define NET_R_BAD NULL

#define NGR_R_RETURN int
#define NGR_R_SET_RETURN void
#undef NGR_R_SET_RESULT /*empty*/
#define NGR_R_END_RETURN void
#ifdef	ORIGINAL_ISC_CODE
#undef NGR_R_END_RESULT  /*empty*/
#else
#define NGR_R_END_RESULT(x)  /*empty*/
#endif
#define NGR_R_ARGS char *buf, int buflen
#undef NGR_R_ENT_ARGS /*empty*/
#define NGR_R_COPY buf, buflen
#define NGR_R_COPY_ARGS NGR_R_ARGS
#define NGR_R_OK 1
#define NGR_R_BAD (0)

#define PROTO_R_RETURN struct protoent *
#define PROTO_R_SET_RETURN void
#undef PROTO_R_SET_RESULT /*empty*/
#define PROTO_R_END_RETURN void
#define PROTO_R_END_RESULT(x)  /*empty*/
#define PROTO_R_ARGS char *buf, int buflen
#undef PROTO_R_ENT_ARGS /*empty*/
#define PROTO_R_COPY buf, buflen
#define PROTO_R_COPY_ARGS PROTO_R_ARGS
#define PROTO_R_OK pptr
#define PROTO_R_BAD NULL

#define PASS_R_RETURN struct passwd *
#define PASS_R_SET_RETURN void
#undef PASS_R_SET_RESULT /*empty*/
#define PASS_R_END_RETURN void
#undef PASS_R_END_RESULT  /*empty*/
#define PASS_R_ARGS char *buf, int buflen
#undef PASS_R_ENT_ARGS /*empty*/
#define PASS_R_COPY buf, buflen
#define PASS_R_COPY_ARGS PASS_R_ARGS
#define PASS_R_OK pwptr
#define PASS_R_BAD NULL

#define SERV_R_RETURN struct servent *
#define SERV_R_SET_RETURN void
#undef SERV_R_SET_RESULT /*empty*/
#define SERV_R_END_RETURN void
#define SERV_R_END_RESULT(x)  /*empty*/
#define SERV_R_ARGS char *buf, int buflen
#undef SERV_R_ENT_ARGS /*empty*/
#define SERV_R_COPY buf, buflen
#define SERV_R_COPY_ARGS SERV_R_ARGS
#define SERV_R_OK sptr
#define SERV_R_BAD NULL

/* make #include <sys/ioctl.h> also #include <sys/sockio.h> */
#define BSD_COMP

#include <limits.h>	/* _POSIX_PATH_MAX */

#ifdef __GNUC__
#define ISC_FORMAT_PRINTF(fmt, args) \
	__attribute__((__format__(__printf__, fmt, args)))
#else
#define ISC_FORMAT_PRINTF(fmt, args)
#endif

/*
 * Remove compiler warnings without modifying ISC source by including
 * various headers here, mostly to get function prototypes.
 */
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sys/types.h>
#include "sys/bitypes.h"
#include "sys/cdefs.h"

#define	HAS_INET6_STRUCTS
#define	H_ERRNO_IS_FUNCTION
