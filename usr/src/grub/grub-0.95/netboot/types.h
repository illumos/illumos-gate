#ifndef _TYPES_H
#define _TYPES_H

/* I'm architecture independed :-) */

/* 
 * It's architecture depended headers for common integer types
 */
#include "stdint.h"

/* 
 * Here are some RPC types define from linux /usr/include/rpc/types.h
 */
typedef int bool_t;
typedef int enum_t;
typedef uint32_t rpcprog_t;
typedef uint32_t rpcvers_t;
typedef uint32_t rpcproc_t;
typedef uint32_t rpcprot_t;
typedef uint32_t rpcport_t;

/* For bool_t */
/* typedef enum { */
/*  	FALSE = 0, */
/*  	TRUE = 1 */
/* } boolean_t; */



/* Some BSD or RPC style types */
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef long long quad_t;
typedef unsigned long long u_quad_t;
typedef struct {
	int __val[2];
}fsid_t;			/* Type of file system IDs, from bits/types.h */

typedef int daddr_t;		/* The type of a disk address, from bits/types.h */
typedef char * caddr_t;

#endif /* _TYPES_H */
