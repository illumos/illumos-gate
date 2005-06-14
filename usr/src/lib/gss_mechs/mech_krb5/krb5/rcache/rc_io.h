#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/rcache/rc_io.h
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */

/*
 * Declarations for the I/O sub-package of the replay cache
 */

#ifndef KRB5_RC_IO_H
#define KRB5_RC_IO_H

typedef struct krb5_rc_iostuff
 {
  int fd;
#ifdef MSDOS_FILESYSTEM
  long mark;
#else
  int mark; /* on newer systems, should be pos_t */
#endif
  char *fn;
 }
krb5_rc_iostuff;

/* first argument is always iostuff for result file */

krb5_error_code krb5_rc_io_creat 
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *,
		   char **));
krb5_error_code krb5_rc_io_open 
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *,
		   char *));
krb5_error_code krb5_rc_io_move 
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *,
		   krb5_rc_iostuff *));
krb5_error_code krb5_rc_io_write 
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *,
		   krb5_pointer,
		   int));
krb5_error_code krb5_rc_io_read 
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *,
		   krb5_pointer,
		   int));
krb5_error_code krb5_rc_io_close 
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *));
krb5_error_code krb5_rc_io_destroy 
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *));
krb5_error_code krb5_rc_io_mark 
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *));
krb5_error_code krb5_rc_io_unmark 
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *));
krb5_error_code krb5_rc_io_sync
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *));
long krb5_rc_io_size
	PROTOTYPE((krb5_context,
		   krb5_rc_iostuff *));
#endif
