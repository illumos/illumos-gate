#ifndef MANDOC_CONFIG_H
#define	MANDOC_CONFIG_H

#include <sys/types.h>

#define	MAN_CONF_FILE "/etc/man.conf"
#define	MANPATH_BASE "/usr/share/man"
#define	MANPATH_DEFAULT "/usr/share/man:/usr/gnu/share/man"

#define	UTF8_LOCALE "en_US.UTF-8"
#define	EFTYPE EINVAL

#define	HAVE_ENDIAN 1
#define	HAVE_ERR 1
#define	HAVE_FTS 1
#define	HAVE_NTOHL 1
#define	HAVE_OHASH 0
#define	HAVE_PLEDGE 0
#define	HAVE_PROGNAME 1
#define	HAVE_REWB_BSD 1
#define	HAVE_REWB_SYSV 1
#define	HAVE_SANDBOX_INIT 0
#define	HAVE_STRPTIME 1
#define	HAVE_SYS_ENDIAN 0
#define	HAVE_WCHAR 1

#define	BINM_APROPOS "apropos"
#define	BINM_MAN "man"
#define	BINM_WHATIS "whatis"
#define	BINM_MAKEWHATIS "man -w"

#endif /* MANDOC_CONFIG_H */
