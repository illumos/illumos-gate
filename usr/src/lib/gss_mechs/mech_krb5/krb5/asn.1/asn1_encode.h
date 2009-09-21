/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * src/lib/krb5/asn.1/asn1_encode.h
 *
 * Copyright 1994, 2008 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef __ASN1_ENCODE_H__
#define __ASN1_ENCODE_H__

#include "k5-int.h"
#include "krbasn1.h"
#include "asn1buf.h"
#include <time.h>

/*
   Overview

     Each of these procedures inserts the encoding of an ASN.1
     primitive in a coding buffer.

   Operations

     asn1_encode_boolean
     asn1_encode_integer
     asn1_encode_unsigned_integer
     asn1_encode_octetstring
     asn1_encode_generaltime
     asn1_encode_generalstring
     asn1_encode_bitstring
     asn1_encode_oid
*/

asn1_error_code asn1_encode_boolean
        (asn1buf *buf, asn1_intmax val, unsigned int *retlen);
asn1_error_code asn1_encode_integer
        (asn1buf *buf, asn1_intmax val, unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_enumerated
(asn1buf *buf, long val, unsigned int *retlen);

asn1_error_code asn1_encode_unsigned_integer
        (asn1buf *buf, asn1_uintmax val,
                   unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_octetstring
        (asn1buf *buf,
                   unsigned int len, const void *val,
                   unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */
#define asn1_encode_charstring asn1_encode_octetstring

asn1_error_code asn1_encode_oid
        (asn1buf *buf,
                   unsigned int len, const asn1_octet *val,
                   unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_null
        (asn1buf *buf, int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of NULL into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_printablestring
        (asn1buf *buf,
                   unsigned int len, const char *val,
                   int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_ia5string
        (asn1buf *buf,
                   unsigned int len, const char *val,
                   int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_generaltime
        (asn1buf *buf, time_t val, unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer.
   Note: The encoding of GeneralizedTime is YYYYMMDDhhmmZ */

asn1_error_code asn1_encode_generalstring
        (asn1buf *buf,
                   unsigned int len, const void *val,
                   unsigned int *retlen);
/* requires  *buf is allocated,  val has a length of len characters
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_bitstring(asn1buf *buf, unsigned int len,
                                      const void *val,
                                      unsigned int *retlen);
/* requires  *buf is allocated,  val has a length of len characters
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_opaque(asn1buf *buf, unsigned int len,
                                   const void *val,
                                   unsigned int *retlen);
/* requires  *buf is allocated,  val has a length of len characters
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

/* Type descriptor info.

   In this context, a "type" is a combination of a C data type
   and an ASN.1 encoding scheme for it.  So we would have to define
   different "types" for:

   * unsigned char* encoded as octet string
   * char* encoded as octet string
   * char* encoded as generalstring
   * krb5_data encoded as octet string
   * krb5_data encoded as generalstring
   * int32_t encoded as integer
   * unsigned char encoded as integer

   Perhaps someday some kind of flags could be defined so that minor
   variations on the C types could be handled via common routines.

   The handling of strings is pretty messy.  Currently, we have a
   separate kind of encoder function that takes an extra length
   parameter.  Perhaps we should just give up on that, always deal
   with just a single location, and handle strings by via encoder
   functions for krb5_data, keyblock, etc.

   We wind up with a lot of load-time relocations being done, which is
   a bit annoying.  Be careful about "fixing" that at the cost of too
   much run-time performance.  It might work to have a master "module"
   descriptor with pointers to various arrays (type descriptors,
   strings, field descriptors, functions) most of which don't need
   relocation themselves, and replace most of the pointers with table
   indices.

   It's a work in progress.  */

enum atype_type {
    /* For bounds checking only.  By starting with values above 1, we
       guarantee that zero-initialized storage will be recognized as
       invalid.  */
    atype_min = 1,
    /* Encoder function to be called with address of <thing>.  */
    atype_fn,
    /* Encoder function to be called with address of <thing> and a
       length (unsigned int).  */
    atype_fn_len,
    /* Pointer to actual thing to be encoded.

       Most of the fields are related only to the C type -- size, how
       to fetch a pointer in a type-safe fashion -- but since the base
       type descriptor encapsulates the encoding as well, different
       encodings for the same C type may require different pointer-to
       types as well.

       Must not refer to atype_fn_len.  */
    atype_ptr,
    /* Sequence, with pointer to sequence descriptor header.  */
    atype_sequence,
    /* Sequence-of, with pointer to base type descriptor, represented
       as a null-terminated array of pointers (and thus the "base"
       type descriptor is actually an atype_ptr node).  */
    atype_nullterm_sequence_of,
    atype_nonempty_nullterm_sequence_of,
    /* Encode this object using a single field descriptor.  This may
       mean the atype/field breakdown needs revision....

       Main expected uses: Encode realm component of principal as a
       GENERALSTRING.  Pluck data and length fields out of a structure
       and encode a counted SEQUENCE OF.  */
    atype_field,
    /* Tagged version of another type.  */
    atype_tagged_thing,
    /* Integer types.  */
    atype_int,
    atype_uint,
    /* Unused except for bounds checking.  */
    atype_max
};

/* Initialized structures could be a lot smaller if we could use C99
   designated initializers, and a union for all the type-specific
   stuff.  Maybe use the hack we use for krb5int_access, where we use
   a run-time initialize if the compiler doesn't support designated
   initializers?  That's a lot of work here, though, with so many
   little structures.  Maybe if/when these get auto-generated.  */
struct atype_info {
    enum atype_type type;
    /* used for sequence-of processing */
    unsigned int size;
    /* atype_fn */
    asn1_error_code (*enc)(asn1buf *, const void *, unsigned int *);
    /* atype_fn_len */
    asn1_error_code (*enclen)(asn1buf *, unsigned int, const void *,
                              unsigned int *);
    /* atype_ptr, atype_fn_len */
    const void *(*loadptr)(const void *);
    /* atype_ptr, atype_nullterm_sequence_of */
    const struct atype_info *basetype;
    /* atype_sequence */
    const struct seq_info *seq;
    /* atype_field */
    const struct field_info *field;
    /* atype_tagged_thing */
    unsigned int tagval : 8, tagtype : 8;
    /* atype_[u]int */
    asn1_intmax (*loadint)(const void *);
    asn1_uintmax (*loaduint)(const void *);
};

/* The various DEF*TYPE macros must:

   + Define a type named aux_typedefname_##DESCNAME, for use in any
     types derived from the type being defined.

   + Define an atype_info struct named krb5int_asn1type_##DESCNAME.

   + Define any extra stuff needed in the type descriptor, like
     pointer-load functions.

   + Accept a following semicolon syntactically, to keep Emacs parsing
     (and indentation calculating) code happy.

   Nothing else should directly define the atype_info structures.  */

/* Define a type for which we must use an explicit encoder function.
   The DEFFNTYPE variant uses a function taking a void*, the
   DEFFNXTYPE form wants a function taking a pointer to the actual C
   type to be encoded; you should use the latter unless you've already
   got the void* function supplied elsewhere.

   Of course, we need a single, consistent type for the descriptor
   structure field, so we use the function pointer type that uses
   void*, and create a wrapper function in DEFFNXTYPE.  However, in
   all our cases so far, the supplied function is static and not used
   otherwise, so the compiler can merge it with the wrapper function
   if the optimizer is good enough.  */
#define DEFFNTYPE(DESCNAME, CTYPENAME, ENCFN)                   \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_fn, sizeof(CTYPENAME), ENCFN,                     \
    }
#define DEFFNXTYPE(DESCNAME, CTYPENAME, ENCFN)                  \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    static asn1_error_code                                      \
    aux_encfn_##DESCNAME(asn1buf *buf, const void *val,         \
                         unsigned int *retlen)                  \
    {                                                           \
        return ENCFN(buf,                                       \
                     (const aux_typedefname_##DESCNAME *)val,   \
                     retlen);                                   \
    }                                                           \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_fn, sizeof(CTYPENAME), aux_encfn_##DESCNAME,      \
    }
/* XXX The handling of data+length fields really needs reworking.
   A type descriptor probably isn't the right way.

   Also, the C type is likely to be one of char*, unsigned char*,
   or (maybe) void*.  An enumerator or reference to an external
   function would be more compact.

   The supplied encoder function takes as an argument the data pointer
   loaded from the indicated location, not the address of the field.
   This isn't consistent with DEFFN[X]TYPE above, but all of the uses
   of DEFFNLENTYPE are for string encodings, and that's how our
   string-encoding primitives work.  So be it.  */
#ifdef POINTERS_ARE_ALL_THE_SAME
#define DEFFNLENTYPE(DESCNAME, CTYPENAME, ENCFN)                \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_fn_len, 0, 0, ENCFN,                              \
    }
#else
#define DEFFNLENTYPE(DESCNAME, CTYPENAME, ENCFN)                \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    static const void *loadptr_for_##DESCNAME(const void *pv)   \
    {                                                           \
        const aux_typedefname_##DESCNAME *p = pv;               \
        return *p;                                              \
    }                                                           \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_fn_len, 0, 0, ENCFN,                              \
        loadptr_for_##DESCNAME                                  \
    }
#endif
/* A sequence, defined by the indicated series of fields, and an
   optional function indicating which fields are present.  */
#define DEFSEQTYPE(DESCNAME, CTYPENAME, FIELDS, OPT)            \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    static const struct seq_info aux_seqinfo_##DESCNAME = {     \
        OPT, FIELDS, sizeof(FIELDS)/sizeof(FIELDS[0])           \
    };                                                          \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_sequence, sizeof(CTYPENAME), 0,0,0,0,             \
        &aux_seqinfo_##DESCNAME,                                \
    }
/* Integer types.  */
#define DEFINTTYPE(DESCNAME, CTYPENAME)                         \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    static asn1_intmax loadint_##DESCNAME(const void *p)        \
    {                                                           \
        assert(sizeof(CTYPENAME) <= sizeof(asn1_intmax));       \
        return *(const aux_typedefname_##DESCNAME *)p;          \
    }                                                           \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_int, sizeof(CTYPENAME), 0, 0, 0, 0, 0, 0, 0, 0,   \
        loadint_##DESCNAME, 0,                                  \
    }
#define DEFUINTTYPE(DESCNAME, CTYPENAME)                        \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    static asn1_uintmax loaduint_##DESCNAME(const void *p)      \
    {                                                           \
        assert(sizeof(CTYPENAME) <= sizeof(asn1_uintmax));      \
        return *(const aux_typedefname_##DESCNAME *)p;          \
    }                                                           \
    const struct atype_info krb5int_asn1type_##DESCNAME = {     \
        atype_uint, sizeof(CTYPENAME), 0, 0, 0, 0, 0, 0, 0, 0,  \
        0, loaduint_##DESCNAME,                                 \
    }
/* Pointers to other types, to be encoded as those other types.  */
#ifdef POINTERS_ARE_ALL_THE_SAME
#define DEFPTRTYPE(DESCNAME,BASEDESCNAME)                               \
    typedef aux_typedefname_##BASEDESCNAME * aux_typedefname_##DESCNAME; \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_ptr, sizeof(aux_typedefname_##DESCNAME), 0, 0, 0,         \
        &krb5int_asn1type_##BASEDESCNAME, 0                             \
    }
#else
#define DEFPTRTYPE(DESCNAME,BASEDESCNAME)                               \
    typedef aux_typedefname_##BASEDESCNAME * aux_typedefname_##DESCNAME; \
    static const void *                                                 \
    loadptr_for_##BASEDESCNAME##_from_##DESCNAME(const void *p)         \
    {                                                                   \
        const aux_typedefname_##DESCNAME *inptr = p;                    \
        const aux_typedefname_##BASEDESCNAME *retptr;                   \
        retptr = *inptr;                                                \
        return retptr;                                                  \
    }                                                                   \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_ptr, sizeof(aux_typedefname_##DESCNAME), 0, 0,            \
        loadptr_for_##BASEDESCNAME##_from_##DESCNAME,                   \
        &krb5int_asn1type_##BASEDESCNAME, 0                             \
    }
#endif
/* This encodes a pointer-to-pointer-to-thing where the passed-in
   value points to a null-terminated list of pointers to objects to be
   encoded, and encodes a (possibly empty) SEQUENCE OF these objects.

   BASEDESCNAME is a descriptor name for the pointer-to-thing
   type.

   When dealing with a structure containing a
   pointer-to-pointer-to-thing field, make a DEFPTRTYPE of this type,
   and use that type for the structure field.  */
#define DEFNULLTERMSEQOFTYPE(DESCNAME,BASEDESCNAME)                     \
    typedef aux_typedefname_##BASEDESCNAME aux_typedefname_##DESCNAME;  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_nullterm_sequence_of, sizeof(aux_typedefname_##DESCNAME), \
        0, 0,                                                           \
        0 /* loadptr */,                                                \
        &krb5int_asn1type_##BASEDESCNAME, 0                             \
    }
#define DEFNONEMPTYNULLTERMSEQOFTYPE(DESCNAME,BASEDESCNAME)             \
    typedef aux_typedefname_##BASEDESCNAME aux_typedefname_##DESCNAME;  \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_nonempty_nullterm_sequence_of,                            \
        sizeof(aux_typedefname_##DESCNAME),                             \
        0, 0,                                                           \
        0 /* loadptr */,                                                \
        &krb5int_asn1type_##BASEDESCNAME, 0                             \
    }
/* Encode a thing (probably sub-fields within the structure) as a
   single object.  */
#define DEFFIELDTYPE(DESCNAME, CTYPENAME, FIELDINFO)                    \
    typedef CTYPENAME aux_typedefname_##DESCNAME;                       \
    static const struct field_info aux_fieldinfo_##DESCNAME = FIELDINFO; \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_field, sizeof(CTYPENAME), 0, 0, 0, 0, 0,                  \
        &aux_fieldinfo_##DESCNAME                                       \
    }
/* Objects with an APPLICATION tag added.  */
#define DEFAPPTAGGEDTYPE(DESCNAME, TAG, BASEDESC)                       \
    typedef aux_typedefname_##BASEDESC aux_typedefname_##DESCNAME;      \
    const struct atype_info krb5int_asn1type_##DESCNAME = {             \
        atype_tagged_thing, sizeof(aux_typedefname_##DESCNAME),         \
        0, 0, 0, &krb5int_asn1type_##BASEDESC, 0, 0, TAG, APPLICATION   \
    }

/* Declare an externally-defined type.  This is a hack we should do
   away with once we move to generating code from a script.  For now,
   this macro is unfortunately not compatible with the defining macros
   above, since you can't do the typedefs twice and we need the
   declarations to produce typedefs.  (We could eliminate the typedefs
   from the DEF* macros, but then every DEF* macro use, even the ones
   for internal type nodes we only use to build other types, would
   need an accompanying declaration which explicitly lists the
   type.)  */
#define IMPORT_TYPE(DESCNAME, CTYPENAME)                        \
    typedef CTYPENAME aux_typedefname_##DESCNAME;               \
    extern const struct atype_info krb5int_asn1type_##DESCNAME

/* Create a partial-encoding function by the indicated name, for the
   indicated type.  Should only be needed until we've converted all of
   the encoders, then everything should use descriptor tables.  */
extern asn1_error_code
krb5int_asn1_encode_a_thing(asn1buf *buf, const void *val,
                            const struct atype_info *a, unsigned int *retlen);
#define MAKE_ENCFN(FNAME,DESC)                                          \
   static asn1_error_code FNAME (asn1buf *buf,                          \
                           const aux_typedefname_##DESC *val,           \
                           unsigned int *retlen)                        \
    {                                                                   \
        return krb5int_asn1_encode_a_thing(buf, val,                    \
                                           &krb5int_asn1type_##DESC,    \
                                           retlen);                     \
    }                                                                   \
    extern int dummy /* gobble semicolon */

/* Sequence field descriptor.

   Currently we assume everything is a single object with a type
   descriptor, and then we bolt on some ugliness on the side for
   handling strings with length fields.

   Anything with "interesting" encoding handling, like a sequence-of
   or a pointer to the actual value to encode, is handled via opaque
   types with their own encoder functions.  Most of that should
   eventually change.  */

enum field_type {
    /* Unused except for range checking.  */
    field_min = 1,
    /* Field ATYPE describes processing of field at DATAOFF.  */
    field_normal,
    /* Encode an "immediate" integer value stored in DATAOFF, with no
       reference to the data structure.  */
    field_immediate,
    /* Encode some kind of string field encoded with pointer and
       length.  (A GENERALSTRING represented as a null-terminated C
       string would be handled as field_normal.)  */
    field_string,
    /* LENOFF indicates a value describing the length of the array at
       DATAOFF, encoded as a sequence-of with the element type
       described by ATYPE.  */
    field_sequenceof_len,
    /* Unused except for range checking.  */
    field_max
};
/* To do: Consider using bitfields.  */
struct field_info {
    /* Type of the field.  */
    unsigned int /* enum field_type */ ftype : 3;

    /* Use of DATAOFF and LENOFF are described by the value in FTYPE.
       Generally DATAOFF will be the offset from the supplied pointer
       at which we find the object to be encoded.  */
    unsigned int dataoff : 9, lenoff : 9;

    /* If TAG is non-negative, a context tag with that value is added
       to the encoding of the thing.  (XXX This would encode more
       compactly as an unsigned bitfield value tagnum+1, with 0=no
       tag.)  The tag is omitted for optional fields that are not
       present.

       It's a bit illogical to combine the tag and other field info,
       since really a sequence field could have zero or several
       context tags, and of course a tag could be used elsewhere.  But
       the normal mode in the Kerberos ASN.1 description is to use one
       context tag on each sequence field, so for now let's address
       that case primarily and work around the other cases (thus tag<0
       means skip tagging).  */
    signed int tag : 5;

    /* If OPT is non-negative and the sequence header structure has a
       function pointer describing which fields are present, OPT is
       the bit position indicating whether the currently-described
       element is present.  (XXX Similar encoding issue.)

       Note: Most of the time, I'm using the same number here as for
       the context tag.  This is just because it's easier for me to
       keep track while working on the code by hand.  The *only*
       meaningful correlation is of this value and the bits set by the
       "optional" function when examining the data structure.  */
    signed int opt : 5;

    /* For some values of FTYPE, this describes the type of the
       object(s) to be encoded.  */
    const struct atype_info *atype;

    /* We use different types for "length" fields in different places.
       So we need a good way to retrieve the various kinds of lengths
       in a compatible way.  This may be a string length, or the
       length of an array of objects to encode in a SEQUENCE OF.

       In case the field is signed and negative, or larger than
       size_t, return SIZE_MAX as an error indication.  We'll assume
       for now that we'll never have 4G-1 (or 2**64-1, or on tiny
       systems, 65535) sized values.  On most if not all systems we
       care about, SIZE_MAX is equivalent to "all of addressable
       memory" minus one byte.  That wouldn't leave enough extra room
       for the structure we're encoding, so it's pretty safe to assume
       SIZE_MAX won't legitimately come up on those systems.

       If this code gets ported to a segmented architecture or other
       system where it might be possible... figure it out then.  */
    const struct atype_info *lentype;
};

/* Normal or optional sequence fields at a particular offset, encoded
   as indicated by the listed DESCRiptor.  */
#define FIELDOF_OPT(TYPE,DESCR,FIELDNAME,TAG,OPT)                       \
    {                                                                   \
        field_normal, OFFOF(TYPE, FIELDNAME, aux_typedefname_##DESCR),  \
        0, TAG, OPT, &krb5int_asn1type_##DESCR                          \
    }
#define FIELDOF_NORM(TYPE,DESCR,FIELDNAME,TAG)  \
    FIELDOF_OPT(TYPE,DESCR,FIELDNAME,TAG,-1)
/* If encoding a subset of the fields of the current structure (for
   example, a flat structure describing data that gets encoded as a
   sequence containing one or more sequences), use ENCODEAS, no struct
   field name(s), and the indicated type descriptor must support the
   current struct type.  */
#define FIELDOF_ENCODEAS(TYPE,DESCR,TAG) \
    FIELDOF_ENCODEAS_OPT(TYPE,DESCR,TAG,-1)
#define FIELDOF_ENCODEAS_OPT(TYPE,DESCR,TAG,OPT)                        \
    {                                                                   \
        field_normal,                                                   \
        0 * sizeof(0 ? (TYPE *)0 : (aux_typedefname_##DESCR *) 0),      \
        0, TAG, OPT, &krb5int_asn1type_##DESCR                          \
    }

/* Reinterpret some subset of the structure itself as something
   else.  */
#define FIELD_SELF(DESCR, TAG) \
    { field_normal, 0, 0, TAG, -1, &krb5int_asn1type_##DESCR }

#define FIELDOF_OPTSTRINGL(STYPE,DESC,PTRFIELD,LENDESC,LENFIELD,TAG,OPT) \
   {                                                                    \
       field_string,                                                    \
       OFFOF(STYPE, PTRFIELD, aux_typedefname_##DESC),                  \
       OFFOF(STYPE, LENFIELD, aux_typedefname_##LENDESC),               \
       TAG, OPT, &krb5int_asn1type_##DESC, &krb5int_asn1type_##LENDESC  \
   }
#define FIELDOF_OPTSTRING(STYPE,DESC,PTRFIELD,LENFIELD,TAG,OPT)         \
    FIELDOF_OPTSTRINGL(STYPE,DESC,PTRFIELD,uint,LENFIELD,TAG,OPT)
#define FIELDOF_STRINGL(STYPE,DESC,PTRFIELD,LENDESC,LENFIELD,TAG)       \
    FIELDOF_OPTSTRINGL(STYPE,DESC,PTRFIELD,LENDESC,LENFIELD,TAG,-1)
#define FIELDOF_STRING(STYPE,DESC,PTRFIELD,LENFIELD,TAG) \
    FIELDOF_OPTSTRING(STYPE,DESC,PTRFIELD,LENFIELD,TAG,-1)
#define FIELD_INT_IMM(VALUE,TAG)   \
    { field_immediate, VALUE, 0, TAG, -1, 0, }

#define FIELDOF_SEQOF_LEN(STYPE,DESC,PTRFIELD,LENFIELD,LENTYPE,TAG)     \
    {                                                                   \
        field_sequenceof_len,                                           \
        OFFOF(STYPE, PTRFIELD, aux_typedefname_##DESC),                 \
        OFFOF(STYPE, LENFIELD, aux_typedefname_##LENTYPE),              \
        TAG, -1, &krb5int_asn1type_##DESC, &krb5int_asn1type_##LENTYPE  \
    }
#define FIELDOF_SEQOF_INT32(STYPE,DESC,PTRFIELD,LENFIELD,TAG)   \
    FIELDOF_SEQOF_LEN(STYPE,DESC,PTRFIELD,LENFIELD,int32,TAG)

struct seq_info {
    /* If present, returns a bitmask indicating which fields are
       present.  See the "opt" field in struct field_info.  */
    unsigned int (*optional)(const void *);
    /* Indicates an array of sequence field descriptors.  */
    const struct field_info *fields;
    size_t n_fields;
    /* Missing: Extensibility handling.  (New field type?)  */
};

extern krb5_error_code
krb5int_asn1_do_full_encode(const void *rep, krb5_data **code,
                            const struct atype_info *a);

#define MAKE_FULL_ENCODER(FNAME, DESC)                                  \
    krb5_error_code FNAME(const aux_typedefname_##DESC *rep,            \
                          krb5_data **code)                             \
    {                                                                   \
        return krb5int_asn1_do_full_encode(rep, code,                   \
                                           &krb5int_asn1type_##DESC);   \
    }                                                                   \
    extern int dummy /* gobble semicolon */

#include <stddef.h>
/* Ugly hack!
   Like "offsetof", but with type checking.  */
#define WARN_IF_TYPE_MISMATCH(LVALUE, TYPE)  \
    (sizeof(0 ? (TYPE *) 0 : &(LVALUE)))
#define OFFOF(TYPE,FIELD,FTYPE)                                 \
    (offsetof(TYPE, FIELD)                                      \
     + 0 * WARN_IF_TYPE_MISMATCH(((TYPE*)0)->FIELD, FTYPE))

#endif
