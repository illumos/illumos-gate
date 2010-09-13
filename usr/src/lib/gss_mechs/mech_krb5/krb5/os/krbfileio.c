/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include "k5-int.h"
#include <sys/file.h>
#include <fcntl.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

krb5_error_code
krb5_create_secure_file(krb5_context context, const char *pathname)
{
	int 	fd;
	int 	open_flag;

	open_flag = O_CREAT|O_EXCL|O_TRUNC|O_RDWR;

	/*
	 * Make sure file name is reserved.
	 * The O_BINARY flag is not a supported flag in the Solaris
	 * open(2) system call, but it is included here to be consistent
	 * with other open calls in the Kerberos library code.
	 */

	fd = open(pathname, open_flag | O_BINARY, 0600);
	if (fd == -1) {
		return (errno);
	} else {
		close(fd);
		return (0);
	}
}

krb5_error_code
krb5_sync_disk_file(krb5_context context, FILE *fp)
{
	if (fp == NULL) {
		(void) fclose(fp);
		return (errno);
	}
	if ((fflush(fp) == EOF) || ferror(fp) || (fsync(fileno(fp)) == -1)) {
		return (errno);
	}
	return (0);
}
