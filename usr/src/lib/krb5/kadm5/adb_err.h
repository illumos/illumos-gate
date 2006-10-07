#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING 
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */

#include <com_err.h>

#define OSA_ADB_NOERR                            (28810240L)
#define OSA_ADB_DUP                              (28810241L)
#define OSA_ADB_NOENT                            (28810242L)
#define OSA_ADB_DBINIT                           (28810243L)
#define OSA_ADB_BAD_POLICY                       (28810244L)
#define OSA_ADB_BAD_PRINC                        (28810245L)
#define OSA_ADB_BAD_DB                           (28810246L)
#define OSA_ADB_XDR_FAILURE                      (28810247L)
#define OSA_ADB_FAILURE                          (28810248L)
#define OSA_ADB_BADLOCKMODE                      (28810249L)
#define OSA_ADB_CANTLOCK_DB                      (28810250L)
#define OSA_ADB_NOTLOCKED                        (28810251L)
#define OSA_ADB_NOLOCKFILE                       (28810252L)
#define OSA_ADB_NOEXCL_PERM                      (28810253L)
#define ERROR_TABLE_BASE_adb (28810240L)

extern const struct error_table et_adb_error_table;

#if !defined(_WIN32)
/* for compatibility with older versions... */
extern void initialize_adb_error_table (void) /*@modifies internalState@*/;
#else
#define initialize_adb_error_table()
#endif

#if !defined(_WIN32)
#define init_adb_err_tbl initialize_adb_error_table
#define adb_err_base ERROR_TABLE_BASE_adb
#endif
