/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file defines macros and constants related to traversing file
 * system hieratchy in post-order, pre-order and level-order ways.
 */

#ifndef _TRAVERSE_H_
#define	_TRAVERSE_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Library functions for traversing file system hierarchy in
 * post-order, pre-order and level-order.
 *
 * This example will be used in the following descriptions.
 * All alphabetical entries are directory and all the numerical
 * entries are non-directory entries.
 *
 * AAA
 * AAA/BBB
 * AAA/BBB/1
 * AAA/BBB/2
 * AAA/BBB/3
 * AAA/CCC
 * AAA/CCC/EEE
 * AAA/CCC/EEE/4
 * AAA/CCC/EEE/5
 * AAA/CCC/EEE/6
 * AAA/CCC/EEE/7
 * AAA/CCC/EEE/8
 * AAA/CCC/9
 * AAA/XXX
 * AAA/ZZZ
 * AAA/10
 * AAA/11
 * AAA/12
 * AAA/13
 *
 * Each traversing function gets an argument of 'struct fs_traverse *'
 * type.  The fields of this structure are explained below.
 *
 * For each entry while traversing, the callback function is
 * called and three arguments are passed to it.  The argument
 * specified in the struct fs_traverse, a struct fst_node for the
 * path and a struct fst_node for the entry.
 *
 * For the root of the traversing, the fields of struct fst_node
 * of the entry are all NULL.
 *
 * If the path to be traversed is not a directory, the callback
 * function is called on it.  The fields of the 'struct fst_node'
 * argument for entry are all NULL.
 *
 *
 * POST-ORDER:
 * Post-order means that the directory is processed after all
 * its children are processed.  Post-order traversing of the above
 * hierarchy will be like this:
 *
 * AAA/BBB, 1
 * AAA/BBB, 2
 * AAA/BBB, 3
 * AAA, BBB
 * AAA/CCC/EEE, 6
 * AAA/CCC/EEE, 5
 * AAA/CCC/EEE, 8
 * AAA/CCC/EEE, 4
 * AAA/CCC/EEE, 7
 * AAA/CCC, EEE
 * AAA/CCC, 9
 * AAA, CCC
 * AAA, XXX
 * AAA, ZZZ
 * AAA, 10
 * AAA, 11
 * AAA, 12
 * AAA, 13
 * AAA
 *
 * In post-order the callback function returns 0 on success
 * or non-zero to stop further traversing the hierarchy.
 *
 * One of the applications of post-order traversing of a
 * hierarchy can be deleting the hierarchy from the file system.
 *
 *
 * PRE-ORDER:
 * Pre-order means that the directory is processed before
 * any of its children are processed.  Pre-order traversing of
 * the above hierarchy will be like this:
 *
 * AAA
 * AAA, BBB
 * AAA/BBB, 1
 * AAA/BBB, 2
 * AAA/BBB, 3
 * AAA, CCC
 * AAA/CCC, EEE
 * AAA/CCC/EEE, 6
 * AAA/CCC/EEE, 5
 * AAA/CCC/EEE, 8
 * AAA/CCC/EEE, 4
 * AAA/CCC/EEE, 7
 * AAA/CCC, 9
 * AAA, XXX
 * AAA, ZZZ
 * AAA, 10
 * AAA, 11
 * AAA, 12
 * AAA, 13
 *
 * In pre-order, the callback function can return 3 values:
 *     0: means that the traversing should continue.
 *
 *     < 0: means that the traversing should be stopped immediately.
 *
 *     FST_SKIP: means that no further entries of this directory
 *         should be processed.  Traversing continues with the
 *         next directory of the same level.  For example, if
 *         callback returns FST_SKIP on AAA/BBB, the callback
 *         will not be called on 1, 2, 3 and traversing will
 *         continue with AAA/CCC.
 *
 *
 * LEVEL-ORDER:
 * This is a special case of pre-order.  In this method,
 * all the non-directory entries of a directory are processed
 * and then come the directory entries.  Level-order traversing
 * of the above hierarchy will be like this:
 *
 * AAA
 * AAA, 10
 * AAA, 11
 * AAA, 12
 * AAA, 13
 * AAA, BBB
 * AAA/BBB, 1
 * AAA/BBB, 2
 * AAA/BBB, 3
 * AAA, CCC
 * AAA/CCC, 9
 * AAA/CCC, EEE
 * AAA/CCC/EEE, 6
 * AAA/CCC/EEE, 5
 * AAA/CCC/EEE, 8
 * AAA/CCC/EEE, 4
 * AAA/CCC/EEE, 7
 * AAA, XXX
 * AAA, ZZZ
 *
 * The rules of pre-order for the return value of callback
 * function applies for level-order.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include "tlm.h"

/*
 * To prune a directory when traversing it, this return
 * value should be returned by the callback function in
 * level-order and pre-order traversing.
 *
 * In level-order processing, this return value stops
 * reading the rest of the directory and calling the callback
 * function for them.  Traversing will continue with the next
 * directory of the same level.  The children of the current
 * directory will be pruned too.  For example on this ,
 *
 */
#define	FST_SKIP	1


#define	SKIP_ENTRY	2


/*
 * Directives for traversing file system.
 *
 * FST_STOP_ONERR: Stop travergins when stat fails on an entry.
 * FST_STOP_ONLONG: Stop on detecting long path.
 * FST_VERBOSE: Verbose running.
 */
#define	FST_STOP_ONERR		0x00000001
#define	FST_STOP_ONLONG		0x00000002
#define	FST_VERBOSE		0x80000000


typedef void (*ft_log_t)();


/*
 * The arguments of traversing file system contains:
 *     path: The physical path to be traversed.
 *
 *     lpath	The logical path to be passed to the callback
 *         	function as path.
 *         	If this is set to NULL, the default value will be
 *         	the 'path'.
 *
 *         	For example, traversing '/v1.chkpnt/backup/home' as
 *         	physical path can have a logical path of '/v1/home'.
 *
 *     flags	Show how the traversing should be done.
 *         	Values of this field are of FST_ constants.
 *
 *     callbk	The callback function pointer.  The callback
 *         	function is called like this:
 *         	(*ft_callbk)(
 *         		void *ft_arg,
 *         		struct fst_node *path,
 *         		struct fst_node *entry)
 *
 *     arg	The 'void *' argument to be passed to the call
 *		back function.
 *
 *     logfp	The log function pointer.  This function
 *         	is called to log the messages.
 *         	Default is logf().
 */
typedef struct fs_traverse {
	char *ft_path;
	char *ft_lpath;
	unsigned int ft_flags;
	int (*ft_callbk)();
	void *ft_arg;
	ft_log_t ft_logfp;
} fs_traverse_t;

/*
 * Traversing Nodes.  For each path and node upon entry this
 * structure is passed to the callback function.
 */
typedef struct fst_node {
	char *tn_path;
	fs_fhandle_t *tn_fh;
	struct stat64 *tn_st;
} fst_node_t;

extern int traverse_post(fs_traverse_t *);
extern int traverse_pre(fs_traverse_t *);
extern int traverse_level(fs_traverse_t *);
#undef	getdents
extern int getdents(int, struct dirent *, size_t);
#ifdef __cplusplus
}
#endif

#endif /* _TRAVERSE_H_ */
