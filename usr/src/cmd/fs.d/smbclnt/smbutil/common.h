#ifndef _SMBUTIL_COMMON_H
#define	_SMBUTIL_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>

int  cmd_crypt(int argc, char *argv[]);
int  cmd_help(int argc, char *argv[]);
int  cmd_login(int argc, char *argv[]);
int  cmd_logout(int argc, char *argv[]);
int  cmd_logoutall(int argc, char *argv[]);
int  cmd_lookup(int argc, char *argv[]);
int  cmd_print(int argc, char *argv[]);
int  cmd_status(int argc, char *argv[]);
int  cmd_view(int argc, char *argv[]);

/* No crypt_usage? */
void help_usage(void);
void login_usage(void);
void logout_usage(void);
void logoutall_usage(void);
void lookup_usage(void);
void print_usage(void);
void status_usage(void);
void view_usage(void);

extern int loadsmbvfs();

#ifdef __cplusplus
}
#endif

#endif	/* _SMBUTIL_COMMON_H */
