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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#ifndef	_REPCACHE_PROTOCOL_H
#define	_REPCACHE_PROTOCOL_H

/*
 * The Repository Cache Protocol
 * -----------------------------
 *
 * 1. Introduction
 * ---------------
 * This header file defines the private protocols between libscf(3lib) and
 * svc.configd(1m).  There are two separate protocols:
 *
 * 1.	The 'global' protocol, accessible via an fattach(3C)ed door located
 *	at REPOSITORY_DOOR_NAME.
 *
 * 2.	The 'client' protocol, accessible through a door created using the
 *	global protocol, which allows access to the repository.
 *
 * 1.1 Design restrictions
 * -----------------------
 * A basic constraint of the door IPC mechanism is that there is no reliable
 * delivery.  In particular:
 *
 * 1.	If libscf(3lib) recieves an EINTR from door_call(), it doesn't know
 *      whether or not the server recieved (and is processing) its request.
 *
 * 2.	When svc.configd(1M) calls door_return(), the client may have already
 *	received an EINTR, aborting its door_call().  In this case, the
 *	returned values are dropped on the floor.
 *
 * The practical upshot of all of this is simple:
 *
 *	Every individual protocol action must be idempotent.
 *
 * That is, a client must be able to retry any single request multiple times,
 * and get the correct results.
 *
 * 1.2. Protocol shorthand
 * -----------------------
 * We represent by "REQUEST(arg1, arg2) -> result, res1, [desc]" a request code
 * of REP_PROTOCOL_REQUEST (or REPOSITORY_DOOR_REQUEST), which takes two
 * additional arguments, arg1 and arg2, and returns a result code, res1, and
 * a file descriptor desc.
 *
 * If an error occurs, the server will usually only send the result code. (a
 * short return)
 *
 * Inside the protocol destription, <foo> indicates the type foo indicates.
 *
 * 2. The Global protocol
 * ----------------------
 * Everything starting with "REPOSITORY_DOOR" or "repository_door" belongs
 * to the global protocol.
 *
 * 2.1. Global requests
 * --------------------
 *
 * REQUEST_CONNECT(rdr_flags, ...) -> result, [new_door]
 *	Request a new Client door.  rdr_flags determines attributes of the
 *	connection:
 *
 *	    FLAG_DEBUG
 *		Sets connection debugging flags to those in rdr_debug.
 *
 *	The new door is returned with DOOR_RELEASE set, so if the client does
 *	not recieve the response, the new door will recieve an unref
 *	notification.  This makes this request idempotent.
 *
 * 2.2. Global reponse codes
 * -------------------------
 * GLXXX: This needs to be thought through.
 *
 * SUCCESS
 * FAIL_BAD_REQUEST
 * FAIL_VERSION_MISMATCH
 * FAIL_BAD_FLAG
 * FAIL_BAD_USER
 * FAIL_NO_RESOURCES
 *
 * 3. The Client protocol
 * ----------------------
 * Everything starting with "REP_PROTOCOL" or "rep_protocol" belongs to the
 * client protocol.
 *
 * 3.1. Techniques used
 * --------------------
 * 3.1.1. Client-controlled identifiers
 *
 * An idiom the protocol uses to lower the number of round trips is
 * client-controlled identifiers.  The basic idea is this:  whenever a
 * client wants to set up and use a piece of server state, it picks an
 * integer *which it knows is not in use* to identify it.  The server then
 * maintains per-client, per-resource id->resource maps.  This has a number
 * of advantages:
 *
 * 1.	Since the client allocates the identifiers, we don't need to do
 *	a round-trip just to allocate a number.
 *
 * 2.	Since it is the client's job to make sure identifiers don't collide,
 *	idempotency for setup (destroy) are simple:  If the identifier
 *	already exists (does not exist), we just return success.
 *
 * 3.	Since the identifiers are per-client, the design automatically
 *	precludes clients being able to manipulate other client's state.
 *
 * 3.1.2 Sequence numbers
 *
 * A standard way of gaining idempotency is introducing sequence numbers.
 * These are simply integers which get incremented at points in the protocol,
 * and make sure the client and server are in sync.
 *
 * In this protocol, we use sequence numbers for requests (like ITER_READ)
 * which are repeated, returning different data each time.  Since requests
 * can also be repeated due to unreliable dispatch, the client increments
 * the sequence number after every successful request.  This allows the server
 * to differentiate the two cases. (note that this means that failing
 * requests have no side effects and are repeatable)
 *
 * 3.2. Client abstractions
 * ------------------------
 * 3.2.1 Entities
 *
 * An "entity" is a typed register which the client can manipulate.
 * Entities are named in the protocol by client-controlled identifiers.
 * They have a fixed type for their entire lifetime, and may be in one
 * of two states:
 *
 * valid
 *	The entity has a valid value, and may be read from.  This state
 *	is reached by a successful write to the entity by some protocol
 *	step.
 *
 * invalid
 *	The entity does not contain a valid value.  There are a number
 *	of ways to reach this state:
 *
 *	1.  The entity was just created.
 *	2.  The underlying object that this entity refers to was destroyed.
 *	3.  A protocol request which would have modified this entity
 *	    failed.
 *
 * An entity is an element in the tree of repository data.  Every entity
 * (except for the most distant SCOPE) has exactly one parent.  Entities
 * can have multiple children of different types, restricted by its base
 * type.
 *
 * The ENTITY_GET call is used to get the root of the tree (the most local
 * scope)
 *
 * 3.2.2. The entity tree
 * ----------------------
 * The structure of a scope is as follows:
 *
 *	 _______
 *	| SCOPE |
 *	|_______|
 *	    \ .
 *	     \ .
 *	      \_________
 *	      | SERVICE |
 *	      |_________|
 *		/.    \ .
 *	       /.      \ .
 *	  ____/		\__________
 *	 | PG |		| INSTANCE |
 *	 |____|		|__________|
 *			  /.	 \ .
 *			 /.	  \ .
 *		    ____/	   \__________
 *		   | PG |	   | SNAPSHOT |
 *		   |____|	   |__________|
 *					\ .
 *					 \ .
 *					  \___________
 *					  | SNAPLEVEL |
 *					  |___________|
 *					     /.
 *					    /.
 *				       ____/
 *				      | PG |
 *				      |____|
 *
 * Where the dots indicate an arbitrary number (including 0) of children.
 *
 * For a given scope, the next scope (in the sense of distance) is its
 * TYPE_SCOPE parent.  The furthest out scope has no parent.
 *
 * 3.2.2 Iterators
 *
 * GLXXX
 *
 * 3.3. Client requests
 * --------------------
 *
 * CLOSE() -> result
 *	Closes the connection, revoking the door.  After this call completes,
 *	no further calls will succeed.
 *
 * ENTITY_SETUP(entity_id, type) -> result
 *	Sets up an entity, identified by entity_id, to identify a single
 *	<type>.  <type> may not be TYPE_NONE.
 *
 * ENTITY_NAME(entity_id, name_type) -> result, name
 *	Returns the name of entity_id.  name_type determines which type of
 *	name to get.
 *
 * ENTITY_PARENT_TYPE(entity_id) -> result, parent_type
 *	Retrieves the type of entity_id's parent
 *
 * ENTITY_GET_CHILD(entity_id, child_id, name) -> result
 *	Puts entity_id's child (of child_id's type) named 'name' into child_id.
 *
 * ENTITY_GET_PARENT(entity_id, out_id) -> result
 *	Puts entity_id's parent into out_id.
 *
 * ENTITY_GET(entity_id, number) -> result
 *	Makes entity_id point to a particular object.  If any error
 *	occurs, dest_id will be invalid.
 *
 * ENTITY_UPDATE(entity_id, changeid) -> result
 *	Updates the entity to pick up any new changes.
 *
 * ENTITY_CREATE_CHILD(entity_id, type, name, child_id, changeid) -> result
 *	Attaches the object of type /type/ in child_id as the child of
 *	entity_id named 'name'.
 *
 * ENTITY_CREATE_PG(entity_id, name, type, flags, child_id, changeid) -> result
 *	Creates a property group child of entity_id named 'name', type 'type'
 *	and flags 'flags', and puts the resulting object in child_id.
 *
 * ENTITY_DELETE(entity_id, changeid) -> result
 *	Deletes the entity represented by entity_id.
 *
 * ENTITY_RESET(entity_id) -> result
 *	Resets the entity.
 *
 * ENTITY_TEARDOWN(entity_id) -> result
 *	Destroys the entity entity_id.
 *
 * ITER_SETUP(iter_id) -> result
 *	Sets up an iterator id.
 *
 * ITER_START(iter_id, entity_id, itertype, flags, pattern) -> result
 *	Sets up an iterator, identified by iter_id, which will iterate the
 *	<itertype> children of entity_id whose names match 'pattern',
 *	with the matching controlled by flags.  Initializing an iterator
 *	counts as the first sequence number (1).
 *
 * ITER_READ(iter_id, sequence, entity_id) -> result
 *	Retrieves the next element of iterator iter_id.  Sequence starts at 2,
 *	and is incremented by the client after each successful iteration.
 *	The result is written to entity_id, which must be of the same type
 *	as the iterator result.  The iterator must not be iterating values.
 *
 * ITER_READ_VALUE(iter_id, sequence) -> result, type, value
 *	Retrieves the next value for iterator iter_id.  Sequence starts at 2,
 *	and is incremented by the client after each successful iteration.
 *	The iterator must be iterating a property's values.
 *
 * ITER_RESET(iter_id) -> result
 *	Throws away any accumulated state.
 *
 * ITER_TEARDOWN(iter_id) -> result
 *	Destroys the iterator iter_id.
 *
 * NEXT_SNAPLEVEL(entity_src, entity_dst) -> result
 *	If entity_src is a snapshot, set entity_dst to the first snaplevel
 *	in it.  If entity_src is a snaplevel, set entity_dst to the next
 *	snaplevel, or fail if there isn't one.
 *
 * SNAPSHOT_TAKE(entity_id, name, dest_id, flags) -> result
 *	Takes a snapshot of entity_id, creating snaplevels for the instance and
 *	its parent service.  If flags is REP_SNAPSHOT_NEW, a new snapshot named
 *	'name' is created as a child of entity_id, dest_id is pointed to it,
 *	and the new snaplevels are attached to it.  If flags is
 *	REP_SNAPSHOT_ATTACH, name must be empty, and the new snaplevels are
 *	attached to the snapshot dest_id points to.
 *
 * SNAPSHOT_TAKE_NAMED(entity_id, instname, svcname, name, dest_id) -> result
 *	Like SNAPSHOT_TAKE, but always acts as if REP_SNAPSHOT_NEW is
 *	specified, and instname and svcname override the actual service and
 *	instance names, respectively, written into the snaplevels.
 *
 *	Note that this is only useful for writing snapshots which will later
 *	be transferred to another instance (svc:/svcname:instname/)
 *
 * SNAPSHOT_ATTACH(source_id, dest_id) -> result
 *	The snaplevels attached to the snapshot referenced by source_id are
 *	attached to the snapshot dest_id is pointed at.
 *
 * PROPERTY_GET_TYPE(entity_id) -> result, value type
 *	Finds the value type of entity_id, which must be a property.
 *
 * PROPERTY_GET_VALUE(entity_id) -> result, type, value
 *	If the property contains a single value, returns it and its type.
 *
 * PROPERTYGRP_SETUP_WAIT(entity_id) -> result, [pipe fd]
 *	Sets up a notification for changes to the object entity_id currently
 *	references.  On success, returns one side of a pipe -- when there
 *	has been a change (or the daemon dies), the other end of the pipe will
 *	be closed.
 *
 *	Only one of these can be set up per client -- attempts to set up more
 *	than one will cause the previous one to get closed.
 *
 * PROPERTYGRP_TX_START(entity_id_tx, entity_id) -> result
 *	Makes entity_id_tx point to the same property group as entity_id,
 *	then attempts to set up entity_id_tx as a transaction on that group.
 *	entity_id and entity_id_tx must be distinct.  On failure, entity_id_tx
 *	is reset.
 *
 * PROPERTYGRP_TX_COMMIT(entity_id, data) -> result
 *	Gives the actual steps to follow, and attempts to commit them.
 *
 * CLIENT_ADD_NOTIFY(type, pattern) -> result
 *	Adds a new property group name or type pattern to the notify list
 *	(see CLIENT_WAIT).  If successful, takes effect immediately.
 *
 * CLIENT_WAIT(entity_id) -> result, fmri
 *	Waits for a change to a propertygroup that matches the patterns
 *	set up using CLIENT_ADD_NOTIFY, and puts the resultant propertygroup
 *	in entity_id.  Note that if an error occurs, you can loose
 *	notifications.  Either entity_id is set to a changed propertygroup,
 *	or fmri is a non-zero-length string identifying a deleted thing.
 *
 * BACKUP(name) -> result
 *	Backs up the persistant repository with a particular name.
 *
 * SET_ANNOTATION(operation, file)
 *	Set up a security audit annotation event.  operation is the name of
 *	the operation that is being annotated, and file is the file being
 *	processed.  This will be used to mark operations which comprise
 *	multiple primitive operations such as svccfg import.
 *
 * SWITCH(flag) -> result
 *	The flag is used to indicate the direction of the switch operation.
 *	When the flag is set to 'fast', move the main repository from the
 *	default location (/etc/svc) to the tmpfs locationa (/etc/svc/volatile).
 *	When it is set to 'perm', the switch is reversed.
 */

#include <door.h>
#include <stddef.h>
#include <sys/sysmacros.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * svc.configd initial protocol details
 */
#define	REPOSITORY_DOOR_BASEVER	(('R' << 24) | ('e' << 16) | ('p' << 8))
#define	REPOSITORY_DOOR_NAME	"/etc/svc/volatile/repository_door"
#define	REPOSITORY_DOOR_COOKIE	((void *)REPOSITORY_DOOR_BASEVER)

#define	REPOSITORY_BOOT_BACKUP	((const char *)"boot")

/*
 * This value should be incremented any time the protocol changes.  When in
 * doubt, bump it.
 */
#define	REPOSITORY_DOOR_VERSION			(21 + REPOSITORY_DOOR_BASEVER)

/*
 * flags for rdr_flags
 */
#define	REPOSITORY_DOOR_FLAG_DEBUG		0x00000001	/* rdr_debug */

#define	REPOSITORY_DOOR_FLAG_ALL		0x00000001	/* all flags */

/*
 * Request IDs
 */
enum repository_door_requestid {
	REPOSITORY_DOOR_REQUEST_CONNECT = (('M' << 8) | 1)
};

enum repository_door_statusid {
	REPOSITORY_DOOR_SUCCESS			= 0,
	REPOSITORY_DOOR_FAIL_BAD_REQUEST	= 1,
	REPOSITORY_DOOR_FAIL_VERSION_MISMATCH	= 2,
	REPOSITORY_DOOR_FAIL_BAD_FLAG		= 3,
	REPOSITORY_DOOR_FAIL_NO_RESOURCES	= 4,
	REPOSITORY_DOOR_FAIL_PERMISSION_DENIED	= 5
};

/*
 * You may only add elements to the end of this structure.
 */
typedef struct repository_door_request {
	uint32_t rdr_version;			/* must be first element */
	enum repository_door_requestid rdr_request;
	uint32_t rdr_flags;
	uint32_t rdr_debug;
} repository_door_request_t;

typedef struct repository_door_response {
	enum repository_door_statusid rdr_status;
} repository_door_response_t;

/*
 * Client interface.  Used on doors returned by REQUEST_CONNECT
 */

#define	REP_PROTOCOL_NAME_LEN		120	/* maximum name length */
#define	REP_PROTOCOL_VALUE_LEN		4096	/* maximum value length */

#define	REP_PROTOCOL_FMRI_LEN		(6 * REP_PROTOCOL_NAME_LEN)

#define	REP_PROTOCOL_BASE		('C' << 8)

/*
 * Request codes
 */
enum rep_protocol_requestid {
	REP_PROTOCOL_CLOSE		= REP_PROTOCOL_BASE,

	REP_PROTOCOL_ENTITY_SETUP,
	REP_PROTOCOL_ENTITY_NAME,
	REP_PROTOCOL_ENTITY_PARENT_TYPE,
	REP_PROTOCOL_ENTITY_GET_CHILD,
	REP_PROTOCOL_ENTITY_GET_PARENT,
	REP_PROTOCOL_ENTITY_GET,
	REP_PROTOCOL_ENTITY_UPDATE,
	REP_PROTOCOL_ENTITY_CREATE_CHILD,
	REP_PROTOCOL_ENTITY_CREATE_PG,
	REP_PROTOCOL_ENTITY_DELETE,
	REP_PROTOCOL_ENTITY_RESET,
	REP_PROTOCOL_ENTITY_TEARDOWN,

	REP_PROTOCOL_ITER_SETUP,
	REP_PROTOCOL_ITER_START,
	REP_PROTOCOL_ITER_READ,
	REP_PROTOCOL_ITER_READ_VALUE,
	REP_PROTOCOL_ITER_RESET,
	REP_PROTOCOL_ITER_TEARDOWN,

	REP_PROTOCOL_NEXT_SNAPLEVEL,

	REP_PROTOCOL_SNAPSHOT_TAKE,
	REP_PROTOCOL_SNAPSHOT_TAKE_NAMED,
	REP_PROTOCOL_SNAPSHOT_ATTACH,

	REP_PROTOCOL_PROPERTY_GET_TYPE,
	REP_PROTOCOL_PROPERTY_GET_VALUE,

	REP_PROTOCOL_PROPERTYGRP_SETUP_WAIT,
	REP_PROTOCOL_PROPERTYGRP_TX_START,
	REP_PROTOCOL_PROPERTYGRP_TX_COMMIT,

	REP_PROTOCOL_CLIENT_ADD_NOTIFY,
	REP_PROTOCOL_CLIENT_WAIT,

	REP_PROTOCOL_BACKUP,

	REP_PROTOCOL_SET_AUDIT_ANNOTATION,

	REP_PROTOCOL_SWITCH,

	REP_PROTOCOL_MAX_REQUEST
};

/*
 * Response codes.  These are returned to the client, and the errors are
 * translated into scf_error_t's by libscf (see proto_error()).
 */
typedef int32_t rep_protocol_responseid_t;
enum rep_protocol_responseid {
	REP_PROTOCOL_SUCCESS =			0,
	/* iterators: No more values. */
	REP_PROTOCOL_DONE =			1,

	/* Request from client was malformed. */
	REP_PROTOCOL_FAIL_BAD_REQUEST =		-1,
	/* Prerequisite call has not been made. */
	REP_PROTOCOL_FAIL_MISORDERED =		-2,
	/* Register for ID has not been created. */
	REP_PROTOCOL_FAIL_UNKNOWN_ID =		-3,
	/* Out of memory or other resource. */
	REP_PROTOCOL_FAIL_NO_RESOURCES =	-4,
	/* Type argument is invalid. */
	REP_PROTOCOL_FAIL_INVALID_TYPE =	-5,
	/* Requested object does not exist. */
	REP_PROTOCOL_FAIL_NOT_FOUND =		-6,
	/* Register for given ID does not point to an object. */
	REP_PROTOCOL_FAIL_NOT_SET =		-7,

	/* Requested name is longer than supplied buffer. */
	REP_PROTOCOL_FAIL_TRUNCATED =		-8,
	/* Operation requires different type. */
	REP_PROTOCOL_FAIL_TYPE_MISMATCH =	-9,

	/* Changeable object has been changed since last update. */
	REP_PROTOCOL_FAIL_NOT_LATEST =		-10,
	/* Creation failed because object with given name exists. */
	REP_PROTOCOL_FAIL_EXISTS =		-11,
	/* Transaction is invalid. */
	REP_PROTOCOL_FAIL_BAD_TX =		-12,
	/* Operation is not applicable to indicated object. */
	REP_PROTOCOL_FAIL_NOT_APPLICABLE =	-13,
	/* Two IDs for operation were unexpectedly equal. */
	REP_PROTOCOL_FAIL_DUPLICATE_ID =	-14,

	/* Permission denied. */
	REP_PROTOCOL_FAIL_PERMISSION_DENIED =	-15,
	/* Backend does not exist or otherwise refused access. */
	REP_PROTOCOL_FAIL_BACKEND_ACCESS =	-16,
	/* Backend is read-only. */
	REP_PROTOCOL_FAIL_BACKEND_READONLY =	-17,

	/* Object has been deleted. */
	REP_PROTOCOL_FAIL_DELETED =		-18,

	REP_PROTOCOL_FAIL_UNKNOWN =		-0xfd
};

/*
 * Types
 */
typedef enum rep_protocol_entity {
	REP_PROTOCOL_ENTITY_NONE,
	REP_PROTOCOL_ENTITY_SCOPE,
	REP_PROTOCOL_ENTITY_SERVICE,
	REP_PROTOCOL_ENTITY_INSTANCE,
	REP_PROTOCOL_ENTITY_SNAPSHOT,
	REP_PROTOCOL_ENTITY_SNAPLEVEL,
	REP_PROTOCOL_ENTITY_PROPERTYGRP,
	REP_PROTOCOL_ENTITY_CPROPERTYGRP,	/* "composed" property group */
	REP_PROTOCOL_ENTITY_PROPERTY,
	REP_PROTOCOL_ENTITY_VALUE,

	REP_PROTOCOL_ENTITY_MAX
} rep_protocol_entity_t;

typedef enum rep_protocol_value_type {
	REP_PROTOCOL_TYPE_INVALID	= '\0',
	REP_PROTOCOL_TYPE_BOOLEAN	= 'b',
	REP_PROTOCOL_TYPE_COUNT		= 'c',
	REP_PROTOCOL_TYPE_INTEGER	= 'i',
	REP_PROTOCOL_TYPE_TIME		= 't',
	REP_PROTOCOL_TYPE_STRING	= 's',
	REP_PROTOCOL_TYPE_OPAQUE	= 'o',

	REP_PROTOCOL_SUBTYPE_USTRING	= REP_PROTOCOL_TYPE_STRING|('u' << 8),
	REP_PROTOCOL_SUBTYPE_URI	= REP_PROTOCOL_TYPE_STRING|('U' << 8),
	REP_PROTOCOL_SUBTYPE_FMRI	= REP_PROTOCOL_TYPE_STRING|('f' << 8),

	REP_PROTOCOL_SUBTYPE_HOST	= REP_PROTOCOL_TYPE_STRING|('h' << 8),
	REP_PROTOCOL_SUBTYPE_HOSTNAME	= REP_PROTOCOL_TYPE_STRING|('N' << 8),
	REP_PROTOCOL_SUBTYPE_NETADDR	= REP_PROTOCOL_TYPE_STRING|('n' << 8),
	REP_PROTOCOL_SUBTYPE_NETADDR_V4	= REP_PROTOCOL_TYPE_STRING|('4' << 8),
	REP_PROTOCOL_SUBTYPE_NETADDR_V6	= REP_PROTOCOL_TYPE_STRING|('6' << 8)
} rep_protocol_value_type_t;


#define	REP_PROTOCOL_BASE_TYPE(t)	((t) & 0x00ff)
#define	REP_PROTOCOL_SUBTYPE(t)		(((t) & 0xff00) >> 8)

/*
 * Request structures
 */
typedef struct rep_protocol_request {
	enum rep_protocol_requestid rpr_request;
} rep_protocol_request_t;

struct rep_protocol_iter_request {
	enum rep_protocol_requestid rpr_request;
	uint32_t rpr_iterid;
};

struct rep_protocol_iter_start {
	enum rep_protocol_requestid rpr_request;	/* ITER_START */
	uint32_t rpr_iterid;

	uint32_t rpr_entity;
	uint32_t rpr_itertype;
	uint32_t rpr_flags;
	char	rpr_pattern[REP_PROTOCOL_NAME_LEN];
};
#define	RP_ITER_START_ALL	0x00000001	/* ignore pattern, match all */
#define	RP_ITER_START_EXACT	0x00000002	/* exact match with pattern */
#define	RP_ITER_START_PGTYPE	0x00000003	/* exact match pg type */
#define	RP_ITER_START_FILT_MASK	0x00000003
#define	RP_ITER_START_COMPOSED	0x00000004	/* composed */

struct rep_protocol_iter_read {
	enum rep_protocol_requestid rpr_request;	/* ITER_READ */
	uint32_t rpr_iterid;
	uint32_t rpr_sequence;		/* client increments upon success */
	uint32_t rpr_entityid;		/* entity to write result to */
};

struct rep_protocol_iter_read_value {
	enum rep_protocol_requestid rpr_request;	/* ITER_READ_VALUE */
	uint32_t rpr_iterid;
	uint32_t rpr_sequence;		/* client increments upon success */
};

struct rep_protocol_entity_setup {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_SETUP */
	uint32_t rpr_entityid;
	uint32_t rpr_entitytype;
};

struct rep_protocol_entity_name {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_NAME */
	uint32_t rpr_entityid;
	uint32_t rpr_answertype;
};
#define	RP_ENTITY_NAME_NAME			0
#define	RP_ENTITY_NAME_PGTYPE			1
#define	RP_ENTITY_NAME_PGFLAGS			2
#define	RP_ENTITY_NAME_SNAPLEVEL_SCOPE		3
#define	RP_ENTITY_NAME_SNAPLEVEL_SERVICE	4
#define	RP_ENTITY_NAME_SNAPLEVEL_INSTANCE	5
#define	RP_ENTITY_NAME_PGREADPROT		6

struct rep_protocol_entity_update {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_UPDATE */
	uint32_t rpr_entityid;
	uint32_t rpr_changeid;
};

struct rep_protocol_entity_parent_type {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_PARENT_TYPE */
	uint32_t rpr_entityid;
};

struct rep_protocol_entity_parent {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_GET_PARENT */
	uint32_t rpr_entityid;
	uint32_t rpr_outid;
};

struct rep_protocol_entity_get {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_SET */
	uint32_t rpr_entityid;
	uint32_t rpr_object;
};
#define	RP_ENTITY_GET_INVALIDATE	1
#define	RP_ENTITY_GET_MOST_LOCAL_SCOPE	2

struct rep_protocol_entity_create_child {
	enum rep_protocol_requestid rpr_request; /* ENTITY_CREATE_CHILD */
	uint32_t rpr_entityid;
	uint32_t rpr_childtype;
	uint32_t rpr_childid;
	uint32_t rpr_changeid;
	char	rpr_name[REP_PROTOCOL_NAME_LEN];
};

struct rep_protocol_entity_create_pg {
	enum rep_protocol_requestid rpr_request; /* ENTITY_CREATE_PG */
	uint32_t rpr_entityid;
	uint32_t rpr_childtype;
	uint32_t rpr_childid;
	uint32_t rpr_changeid;
	char	rpr_name[REP_PROTOCOL_NAME_LEN];
	char	rpr_type[REP_PROTOCOL_NAME_LEN];
	uint32_t rpr_flags;
};

struct rep_protocol_entity_get_child {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_GET_CHILD */
	uint32_t rpr_entityid;
	uint32_t rpr_childid;
	char	rpr_name[REP_PROTOCOL_NAME_LEN];
};

struct rep_protocol_entity_delete {
	enum rep_protocol_requestid rpr_request; /* ENTITY_DELETE_CHILD */
	uint32_t rpr_entityid;
	uint32_t rpr_changeid;
};

struct rep_protocol_entity_reset {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_NAME */
	uint32_t rpr_entityid;
};

struct rep_protocol_entity_request {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_NAME */
	uint32_t rpr_entityid;
};

struct rep_protocol_entity_teardown {
	enum rep_protocol_requestid rpr_request;	/* ENTITY_TEARDOWN */
	uint32_t rpr_entityid;
};

struct rep_protocol_entity_pair {
	enum rep_protocol_requestid rpr_request;	/* NEXT_SNAPLEVEL */
	uint32_t rpr_entity_src;
	uint32_t rpr_entity_dst;
};

struct rep_protocol_transaction_start {
	enum rep_protocol_requestid rpr_request;	/* TX_SETUP */
	uint32_t rpr_entityid_tx;		/* property group tx entity */
	uint32_t rpr_entityid;			/* property group entity */
};

struct rep_protocol_transaction_commit {
	enum rep_protocol_requestid rpr_request; /* TX_COMMIT */
	uint32_t rpr_entityid;
	uint32_t rpr_size;			/* size of entire structure */
	uint8_t rpr_cmd[1];
};

#define	REP_PROTOCOL_TRANSACTION_COMMIT_SIZE(sz) \
	    (offsetof(struct rep_protocol_transaction_commit, rpr_cmd[sz]))

#define	REP_PROTOCOL_TRANSACTION_COMMIT_MIN_SIZE \
	    REP_PROTOCOL_TRANSACTION_COMMIT_SIZE(0)

enum rep_protocol_transaction_action {
	REP_PROTOCOL_TX_ENTRY_INVALID,	/* N/A */
	REP_PROTOCOL_TX_ENTRY_NEW,	/* new property */
	REP_PROTOCOL_TX_ENTRY_CLEAR,	/* clear old property */
	REP_PROTOCOL_TX_ENTRY_REPLACE,	/* change type of old property */
	REP_PROTOCOL_TX_ENTRY_DELETE	/* delete property (no values) */
};

struct rep_protocol_transaction_cmd {
	enum	rep_protocol_transaction_action rptc_action;
	uint32_t rptc_type;
	uint32_t rptc_size;		/* size of entire structure */
	uint32_t rptc_name_len;
	uint8_t	rptc_data[1];
};

#define	REP_PROTOCOL_TRANSACTION_CMD_SIZE(sz) \
	    (offsetof(struct rep_protocol_transaction_cmd, rptc_data[sz]))

#define	REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE \
	    REP_PROTOCOL_TRANSACTION_CMD_SIZE(0)

#define	TX_SIZE(x)	P2ROUNDUP((x), sizeof (uint32_t))

struct rep_protocol_transaction_request {
	enum rep_protocol_requestid rpr_request; /* SETUP, ABORT or TEARDOWN */
	uint32_t rpr_txid;
};

struct rep_protocol_property_request {
	enum rep_protocol_requestid rpr_request;
	uint32_t rpr_entityid;
};

struct rep_protocol_propertygrp_request {
	enum rep_protocol_requestid rpr_request;
	uint32_t rpr_entityid;
};

struct rep_protocol_notify_request {
	enum rep_protocol_requestid rpr_request;
	uint32_t rpr_type;
	char	rpr_pattern[REP_PROTOCOL_NAME_LEN];
};
#define	REP_PROTOCOL_NOTIFY_PGNAME 1
#define	REP_PROTOCOL_NOTIFY_PGTYPE 2

struct rep_protocol_wait_request {
	enum rep_protocol_requestid rpr_request;
	uint32_t rpr_entityid;
};

struct rep_protocol_snapshot_take {
	enum rep_protocol_requestid rpr_request;	/* SNAPSHOT_TAKE */
	uint32_t rpr_entityid_src;
	uint32_t rpr_entityid_dest;
	int	rpr_flags;
	char	rpr_name[REP_PROTOCOL_NAME_LEN];
};
#define	REP_SNAPSHOT_NEW	0x00000001
#define	REP_SNAPSHOT_ATTACH	0x00000002

struct rep_protocol_snapshot_take_named {
	enum rep_protocol_requestid rpr_request; /* SNAPSHOT_TAKE_NAMED */
	uint32_t rpr_entityid_src;
	uint32_t rpr_entityid_dest;
	char	rpr_svcname[REP_PROTOCOL_NAME_LEN];
	char	rpr_instname[REP_PROTOCOL_NAME_LEN];
	char	rpr_name[REP_PROTOCOL_NAME_LEN];
};

struct rep_protocol_snapshot_attach {
	enum rep_protocol_requestid rpr_request;	/* SNAPSHOT_ATTACH */
	uint32_t rpr_entityid_src;
	uint32_t rpr_entityid_dest;
};

struct rep_protocol_backup_request {
	enum rep_protocol_requestid rpr_request;	/* BACKUP */
	uint32_t rpr_changeid;
	char rpr_name[REP_PROTOCOL_NAME_LEN];
};

struct rep_protocol_annotation {
	enum rep_protocol_requestid rpr_request;	/* SET_ANNOTATION */
	char rpr_operation[REP_PROTOCOL_NAME_LEN];
	char rpr_file[MAXPATHLEN];
};

struct rep_protocol_switch_request {
	enum rep_protocol_requestid rpr_request;	/* SWITCH */
	uint32_t rpr_changeid;
	int rpr_flag;
};

/*
 * Response structures
 */
typedef struct rep_protocol_response {
	rep_protocol_responseid_t rpr_response;
} rep_protocol_response_t;

struct rep_protocol_integer_response {
	rep_protocol_responseid_t rpr_response;
	uint32_t rpr_value;
};

struct rep_protocol_name_response {	/* response to ENTITY_NAME */
	rep_protocol_responseid_t rpr_response;
	char rpr_name[REP_PROTOCOL_NAME_LEN];
};

struct rep_protocol_fmri_response {
	rep_protocol_responseid_t rpr_response;
	char rpr_fmri[REP_PROTOCOL_FMRI_LEN];
};

struct rep_protocol_value_response {
	rep_protocol_responseid_t rpr_response;
	rep_protocol_value_type_t rpr_type;
	char			rpr_value[2 * REP_PROTOCOL_VALUE_LEN + 1];
};

#ifdef	__cplusplus
}
#endif

#endif	/* _REPCACHE_PROTOCOL_H */
