/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * src/lib/krb5/asn.1/asn1_encode.c
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

/* ASN.1 primitive encoders */

#include "asn1_encode.h"
#include "asn1_make.h"

asn1_error_code asn1_encode_boolean(asn1buf *buf, asn1_intmax val,
                                    unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int length = 0;
    unsigned int partlen = 1;
    asn1_octet bval;

    bval = val ? 0xFF : 0x00;

    retval = asn1buf_insert_octet(buf, bval);
    if (retval) return retval;

    length = partlen;
    retval = asn1_make_tag(buf, UNIVERSAL, PRIMITIVE, ASN1_BOOLEAN, length, &partlen);
    if (retval) return retval;
    length += partlen;

    *retlen = length;
    return 0;
}

static asn1_error_code asn1_encode_integer_internal(asn1buf *buf,
                                                    asn1_intmax val,
                                                    unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int length = 0;
    long valcopy;
    int digit;

    valcopy = val;
    do {
        digit = (int) (valcopy&0xFF);
        retval = asn1buf_insert_octet(buf,(asn1_octet) digit);
        if (retval) return retval;
        length++;
        valcopy = valcopy >> 8;
    } while (valcopy != 0 && valcopy != ~0);

    if ((val > 0) && ((digit&0x80) == 0x80)) { /* make sure the high bit is */
        retval = asn1buf_insert_octet(buf,0); /* of the proper signed-ness */
        if (retval) return retval;
        length++;
    } else if ((val < 0) && ((digit&0x80) != 0x80)) {
        retval = asn1buf_insert_octet(buf,0xFF);
        if (retval) return retval;
        length++;
    }


    *retlen = length;
    return 0;
}

asn1_error_code asn1_encode_integer(asn1buf * buf, asn1_intmax val,
                                    unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int length = 0;
    unsigned  int partlen;
    retval = asn1_encode_integer_internal(buf, val, &partlen);
    if (retval) return retval;

    length = partlen;
    retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_INTEGER,length, &partlen);
    if (retval) return retval;
    length += partlen;

    *retlen = length;
    return 0;
}

#if 0
asn1_error_code
asn1_encode_enumerated(asn1buf * buf, long val,
                       unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int length = 0;
    unsigned  int partlen;
    retval = asn1_encode_integer_internal(buf, val, &partlen);
    if (retval) return retval;

    length = partlen;
    retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_ENUMERATED,length, &partlen);
    if (retval) return retval;
    length += partlen;

    *retlen = length;
    return 0;
}
#endif

asn1_error_code asn1_encode_unsigned_integer(asn1buf *buf, asn1_uintmax val,
                                             unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int length = 0;
    unsigned int partlen;
    unsigned long valcopy;
    int digit;

    valcopy = val;
    do {
        digit = (int) (valcopy&0xFF);
        retval = asn1buf_insert_octet(buf,(asn1_octet) digit);
        if (retval) return retval;
        length++;
        valcopy = valcopy >> 8;
    } while (valcopy != 0);

    if (digit&0x80) {                     /* make sure the high bit is */
        retval = asn1buf_insert_octet(buf,0); /* of the proper signed-ness */
        if (retval) return retval;
        length++;
    }

    retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_INTEGER,length, &partlen);
    if (retval) return retval;
    length += partlen;

    *retlen = length;
    return 0;
}

static asn1_error_code
encode_bytestring_with_tag(asn1buf *buf, unsigned int len,
                           const void *val, int tag,
                           unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int length;

    if (len > 0 && val == 0) return ASN1_MISSING_FIELD;
    retval = asn1buf_insert_octetstring(buf, len, val);
    if (retval) return retval;
    retval = asn1_make_tag(buf, UNIVERSAL, PRIMITIVE, tag,
                           len, &length);
    if (retval) return retval;

    *retlen = len + length;
    return 0;
}

asn1_error_code asn1_encode_oid(asn1buf *buf, unsigned int len,
                                const asn1_octet *val,
                                unsigned int *retlen)
{
    return encode_bytestring_with_tag(buf, len, val, ASN1_OBJECTIDENTIFIER,
                                      retlen);
}

asn1_error_code asn1_encode_octetstring(asn1buf *buf, unsigned int len,
                                        const void *val,
                                        unsigned int *retlen)
{
    return encode_bytestring_with_tag(buf, len, val, ASN1_OCTETSTRING,
                                      retlen);
}

#if 0
asn1_error_code asn1_encode_null(asn1buf *buf, int *retlen)
{
    asn1_error_code retval;

    retval = asn1buf_insert_octet(buf,0x00);
    if (retval) return retval;
    retval = asn1buf_insert_octet(buf,0x05);
    if (retval) return retval;

    *retlen = 2;
    return 0;
}

asn1_error_code asn1_encode_printablestring(asn1buf *buf, unsigned int len,
                                            const char *val, int *retlen)
{
    return encode_bytestring_with_tag(buf, len, val, ASN1_PRINTABLESTRING,
                                      retlen);
}

asn1_error_code asn1_encode_ia5string(asn1buf *buf, unsigned int len,
                                      const char *val, int *retlen)
{
    return encode_bytestring_with_tag(buf, len, val, ASN1_IA5STRING,
                                      retlen);
}
#endif

asn1_error_code asn1_encode_generaltime(asn1buf *buf, time_t val,
                                        unsigned int *retlen)
{
    struct tm *gtime, gtimebuf;
    char s[16], *sp;
    time_t gmt_time = val;

    /*
     * Time encoding: YYYYMMDDhhmmssZ
     */
    if (gmt_time == 0) {
        sp = "19700101000000Z";
    } else {
        int len;

        /*
         * Sanity check this just to be paranoid, as gmtime can return NULL,
         * and some bogus implementations might overrun on the sprintf.
         */
#ifdef HAVE_GMTIME_R
# ifdef GMTIME_R_RETURNS_INT
        if (gmtime_r(&gmt_time, &gtimebuf) != 0)
            return ASN1_BAD_GMTIME;
# else
        if (gmtime_r(&gmt_time, &gtimebuf) == NULL)
            return ASN1_BAD_GMTIME;
# endif
#else
        gtime = gmtime(&gmt_time);
        if (gtime == NULL)
            return ASN1_BAD_GMTIME;
        memcpy(&gtimebuf, gtime, sizeof(gtimebuf));
#endif
        gtime = &gtimebuf;

        if (gtime->tm_year > 8099 || gtime->tm_mon > 11 ||
            gtime->tm_mday > 31 || gtime->tm_hour > 23 ||
            gtime->tm_min > 59 || gtime->tm_sec > 59)
            return ASN1_BAD_GMTIME;
        len = snprintf(s, sizeof(s), "%04d%02d%02d%02d%02d%02dZ",
                       1900+gtime->tm_year, gtime->tm_mon+1,
                       gtime->tm_mday, gtime->tm_hour,
                       gtime->tm_min, gtime->tm_sec);
        if (SNPRINTF_OVERFLOW(len, sizeof(s)))
            /* Shouldn't be possible given above tests.  */
            return ASN1_BAD_GMTIME;
        sp = s;
    }

    return encode_bytestring_with_tag(buf, 15, sp, ASN1_GENERALTIME,
                                      retlen);
}

asn1_error_code asn1_encode_generalstring(asn1buf *buf, unsigned int len,
                                          const void *val,
                                          unsigned int *retlen)
{
    return encode_bytestring_with_tag(buf, len, val, ASN1_GENERALSTRING,
                                      retlen);
}

asn1_error_code asn1_encode_bitstring(asn1buf *buf, unsigned int len,
                                      const void *val,
                                      unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int length;

    retval = asn1buf_insert_octetstring(buf, len, val);
    if (retval) return retval;
    retval = asn1buf_insert_octet(buf, 0);
    if (retval) return retval;
    retval = asn1_make_tag(buf, UNIVERSAL, PRIMITIVE, ASN1_BITSTRING,
                           len+1, &length);
    if (retval) return retval;
    *retlen = len + 1 + length;
    return 0;
}

asn1_error_code asn1_encode_opaque(asn1buf *buf, unsigned int len,
                                   const void *val, unsigned int *retlen)
{
    asn1_error_code retval;

    retval = asn1buf_insert_octetstring(buf, len, val);
    if (retval) return retval;
    *retlen = len;
    return 0;
}

/* ASN.1 constructed type encoder engine

   Two entry points here:

   krb5int_asn1_encode_a_thing: Incrementally adds the partial
   encoding of an object to an already-initialized asn1buf.

   krb5int_asn1_do_full_encode: Returns a completed encoding, in the
   correct byte order, in an allocated krb5_data.  */

#ifdef POINTERS_ARE_ALL_THE_SAME
#define LOADPTR(PTR,TYPE)       \
    (assert((TYPE)->loadptr != NULL), (TYPE)->loadptr(PTR))
#else
#define LOADPTR(PTR,TYPE)       \
    (*(const void *const *)(PTR))
#endif

static int
get_nullterm_sequence_len(const void *valp, const struct atype_info *seq)
{
    int i;
    const struct atype_info *a;
    const void *elt, *eltptr;

    a = seq;
    i = 0;
    assert(a->type == atype_ptr);
    assert(seq->size != 0);

    while (1) {
        eltptr = (const char *) valp + i * seq->size;
        elt = LOADPTR(eltptr, a);
        if (elt == NULL)
            break;
        i++;
    }
    return i;
}
static asn1_error_code
encode_sequence_of(asn1buf *buf, int seqlen, const void *val,
                   const struct atype_info *eltinfo,
                   unsigned int *retlen);

static asn1_error_code
encode_nullterm_sequence_of(asn1buf *buf, const void *val,
                            const struct atype_info *type,
                            int can_be_empty,
                            unsigned int *retlen)
{
    int length = get_nullterm_sequence_len(val, type);
    if (!can_be_empty && length == 0) return ASN1_MISSING_FIELD;
    return encode_sequence_of(buf, length, val, type, retlen);
}

static asn1_error_code
just_encode_sequence(asn1buf *buf, const void *val,
                     const struct seq_info *seq,
                     unsigned int *retlen);
static asn1_error_code
encode_a_field(asn1buf *buf, const void *val,
               const struct field_info *field,
               unsigned int *retlen);

asn1_error_code
krb5int_asn1_encode_a_thing(asn1buf *buf, const void *val,
                            const struct atype_info *a, unsigned int *retlen)
{
    switch (a->type) {
    case atype_fn:
        assert(a->enc != NULL);
        return a->enc(buf, val, retlen);
    case atype_sequence:
        assert(a->seq != NULL);
        return just_encode_sequence(buf, val, a->seq, retlen);
    case atype_ptr:
        assert(a->basetype != NULL);
        return krb5int_asn1_encode_a_thing(buf, LOADPTR(val, a),
                                           a->basetype, retlen);
    case atype_field:
        assert(a->field != NULL);
        return encode_a_field(buf, val, a->field, retlen);
    case atype_nullterm_sequence_of:
    case atype_nonempty_nullterm_sequence_of:
        assert(a->basetype != NULL);
        return encode_nullterm_sequence_of(buf, val, a->basetype,
                                           a->type == atype_nullterm_sequence_of,
                                           retlen);
    case atype_tagged_thing:
    {
        asn1_error_code retval;
        unsigned int length, sum = 0;
        retval = krb5int_asn1_encode_a_thing(buf, val, a->basetype, &length);
        if (retval) return retval;
        sum = length;
        retval = asn1_make_etag(buf, a->tagtype, a->tagval, sum, &length);
        if (retval) return retval;
        sum += length;
        *retlen = sum;
        return 0;
    }
    case atype_int:
        assert(a->loadint != NULL);
        return asn1_encode_integer(buf, a->loadint(val), retlen);
    case atype_uint:
        assert(a->loaduint != NULL);
        return asn1_encode_unsigned_integer(buf, a->loaduint(val), retlen);
    case atype_min:
    case atype_max:
    case atype_fn_len:
    default:
        assert(a->type > atype_min);
        assert(a->type < atype_max);
        assert(a->type != atype_fn_len);
        abort();
    }
}

static asn1_error_code
encode_a_field(asn1buf *buf, const void *val,
               const struct field_info *field,
               unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int sum = 0;

    if (val == NULL) return ASN1_MISSING_FIELD;

    switch (field->ftype) {
    case field_immediate:
    {
        unsigned int length;

        retval = asn1_encode_integer(buf, (asn1_intmax) field->dataoff,
                                     &length);
        if (retval) return retval;
        sum += length;
        break;
    }
    case field_sequenceof_len:
    {
        const void *dataptr, *lenptr;
        int slen;
        unsigned int length;
        const struct atype_info *a;

        /* The field holds a pointer to the array of objects.  So the
           address we compute is a pointer-to-pointer, and that's what
           field->atype must help us dereference.  */
        dataptr = (const char *)val + field->dataoff;
        lenptr = (const char *)val + field->lenoff;
        assert(field->atype->type == atype_ptr);
        dataptr = LOADPTR(dataptr, field->atype);
        a = field->atype->basetype;
        assert(field->lentype != 0);
        assert(field->lentype->type == atype_int || field->lentype->type == atype_uint);
        assert(sizeof(int) <= sizeof(asn1_intmax));
        assert(sizeof(unsigned int) <= sizeof(asn1_uintmax));
        if (field->lentype->type == atype_int) {
            asn1_intmax xlen = field->lentype->loadint(lenptr);
            if (xlen < 0)
                return EINVAL;
            if ((unsigned int) xlen != (asn1_uintmax) xlen)
                return EINVAL;
            if ((unsigned int) xlen > INT_MAX)
                return EINVAL;
            slen = (int) xlen;
        } else {
            asn1_uintmax xlen = field->lentype->loaduint(lenptr);
            if ((unsigned int) xlen != xlen)
                return EINVAL;
            if (xlen > INT_MAX)
                return EINVAL;
            slen = (int) xlen;
        }
        if (slen != 0 && dataptr == NULL)
            return ASN1_MISSING_FIELD;
        retval = encode_sequence_of(buf, slen, dataptr, a, &length);
        if (retval) return retval;
        sum += length;
        break;
    }
    case field_normal:
    {
        const void *dataptr;
        const struct atype_info *a;
        unsigned int length;

        dataptr = (const char *)val + field->dataoff;

        a = field->atype;
        assert(a->type != atype_fn_len);
        retval = krb5int_asn1_encode_a_thing(buf, dataptr, a, &length);
        if (retval) {
            return retval;
        }
        sum += length;
        break;
    }
    case field_string:
    {
        const void *dataptr, *lenptr;
        const struct atype_info *a;
        size_t slen;
        unsigned int length;

        dataptr = (const char *)val + field->dataoff;
        lenptr = (const char *)val + field->lenoff;

        a = field->atype;
        assert(a->type == atype_fn_len);
        assert(field->lentype != 0);
        assert(field->lentype->type == atype_int || field->lentype->type == atype_uint);
        assert(sizeof(int) <= sizeof(asn1_intmax));
        assert(sizeof(unsigned int) <= sizeof(asn1_uintmax));
        if (field->lentype->type == atype_int) {
            asn1_intmax xlen = field->lentype->loadint(lenptr);
            if (xlen < 0)
                return EINVAL;
            if ((size_t) xlen != (asn1_uintmax) xlen)
                return EINVAL;
            slen = (size_t) xlen;
        } else {
            asn1_uintmax xlen = field->lentype->loaduint(lenptr);
            if ((size_t) xlen != xlen)
                return EINVAL;
            slen = (size_t) xlen;
        }

        dataptr = LOADPTR(dataptr, a);
        if (slen == SIZE_MAX)
            /* Error - negative or out of size_t range.  */
            return EINVAL;
        if (dataptr == NULL && slen != 0)
            return ASN1_MISSING_FIELD;
        /* Currently our string encoders want "unsigned int" for
           lengths.  */
        if (slen != (unsigned int) slen)
            return EINVAL;
        assert(a->enclen != NULL);
        retval = a->enclen(buf, (unsigned int) slen, dataptr, &length);
        if (retval) {
            return retval;
        }
        sum += length;
        break;
    }
    default:
        assert(field->ftype > field_min);
        assert(field->ftype < field_max);
        assert(__LINE__ == 0);
        abort();
    }
    if (field->tag >= 0) {
        unsigned int length;
        retval = asn1_make_etag(buf, CONTEXT_SPECIFIC, field->tag, sum,
                                &length);
        if (retval) {
            return retval;
        }
        sum += length;
    }
    *retlen = sum;
    return 0;
}

static asn1_error_code
encode_fields(asn1buf *buf, const void *val,
              const struct field_info *fields, size_t nfields,
              unsigned int optional,
              unsigned int *retlen)
{
    size_t i;
    unsigned int sum = 0;
    for (i = nfields; i > 0; i--) {
        const struct field_info *f = fields+i-1;
        unsigned int length;
        asn1_error_code retval;
        int present;

        if (f->opt == -1)
            present = 1;
        else if ((1u << f->opt) & optional)
            present = 1;
        else
            present = 0;
        if (present) {
            retval = encode_a_field(buf, val, f, &length);
            if (retval) return retval;
            sum += length;
        }
    }
    *retlen = sum;
    return 0;
}

static asn1_error_code
just_encode_sequence(asn1buf *buf, const void *val,
                     const struct seq_info *seq,
                     unsigned int *retlen)
{
    const struct field_info *fields = seq->fields;
    size_t nfields = seq->n_fields;
    unsigned int optional;
    asn1_error_code retval;
    unsigned int sum = 0;

    if (seq->optional)
        optional = seq->optional(val);
    else
        /* In this case, none of the field descriptors should indicate
           that we examine any bits of this value.  */
        optional = 0;
    {
        unsigned int length;
        retval = encode_fields(buf, val, fields, nfields, optional, &length);
        if (retval) return retval;
        sum += length;
    }
    {
        unsigned int length;
        retval = asn1_make_sequence(buf, sum, &length);
        if (retval) return retval;
        sum += length;
    }
    *retlen = sum;
    return 0;
}

static asn1_error_code
encode_sequence_of(asn1buf *buf, int seqlen, const void *val,
                   const struct atype_info *eltinfo,
                   unsigned int *retlen)
{
    asn1_error_code retval;
    unsigned int sum = 0;
    int i;

    for (i = seqlen-1; i >= 0; i--) {
        const void *eltptr;
        unsigned int length;
        const struct atype_info *a = eltinfo;

        assert(eltinfo->size != 0);
        eltptr = (const char *)val + i * eltinfo->size;
        retval = krb5int_asn1_encode_a_thing(buf, eltptr, a, &length);
        if (retval) return retval;
        sum += length;
    }
    {
        unsigned int length;
        retval = asn1_make_sequence(buf, sum, &length);
        if (retval) return retval;
        sum += length;
    }
    *retlen = sum;
    return 0;
}

krb5_error_code
krb5int_asn1_do_full_encode(const void *rep, krb5_data **code,
                            const struct atype_info *a)
{
    unsigned int length;
    asn1_error_code retval;
    asn1buf *buf = NULL;
    krb5_data *d;

    *code = NULL;

    if (rep == NULL)
        return ASN1_MISSING_FIELD;

    retval = asn1buf_create(&buf);
    if (retval)
        return retval;

    retval = krb5int_asn1_encode_a_thing(buf, rep, a, &length);
    if (retval)
        goto cleanup;
    retval = asn12krb5_buf(buf, &d);
    if (retval)
        goto cleanup;
    *code = d;
cleanup:
    asn1buf_destroy(&buf);
    return retval;
}
