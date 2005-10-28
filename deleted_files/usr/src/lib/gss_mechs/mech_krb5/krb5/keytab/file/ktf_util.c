/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include "krb5.h"
#include "k5-int.h"
#include <stdio.h>
#include "ktfile.h"
#include <sys/byteorder.h>


static void
cleanup_ktdata(krb5_ktfile_data *kdata)
{
	if (kdata->datap)
		free(kdata->datap);

	kdata->datap = NULL;
	kdata->filesize = 0;
	kdata->bufsize = 0;
	kdata->offset = 0;
	kdata->writable = 0;
}

/*
 * Write the data to disk.
 */
static krb5_error_code
ktf_update_file_on_disk(krb5_ktfile_data *kdata)
{
	krb5_error_code ret = 0;
	int fd;

	/*
	 * If the file was not previously opened for writing,
	 * return an error.
	 */
	if (!kdata->writable)
		return (EBADF);

	fd = open(kdata->name, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd == -1)
		return (KRB5_KT_IOERR);

	/* If no data, just write the version bytes */
	if (kdata->filesize == 0) {
		if (write(fd, &kdata->version, sizeof (kdata->version)) !=
			sizeof (kdata->version))
			ret = KRB5_KT_IOERR;
		else
			kdata->filesize = sizeof (kdata->version);
	} else {
		if (write(fd, kdata->datap, kdata->filesize) !=
			kdata->filesize)
			ret = KRB5_KT_IOERR;
	}

	close(fd);

	return (ret);
}

static int
ktf_open_file(krb5_ktfile_data *kdata, int writable)
{
	int fd;
	int oflags = O_RDONLY;
	struct stat statrec;

	if (writable) {
		oflags = (O_RDWR | O_CREAT);
	}

	fd = open(kdata->name, oflags, 0600);
	if (fd == -1)
		return (errno);

	if (fstat(fd, &statrec) == -1)
		return (errno);

	kdata->filesize = statrec.st_size;

	/* If opening a writable buffer, make it large enough to grow */
	if (writable) {
		kdata->bufsize = kdata->filesize + (8 * BUFSIZ);
		kdata->writable = 1;
	} else {
		kdata->bufsize = kdata->filesize;
		kdata->writable = 0;
	}

	/*
	 * The file was empty, just malloc
	 * a new buffer.  It will get dumped to disk later.
	 */
	kdata->datap = (char *)malloc(kdata->bufsize);
	if (kdata->datap != NULL) {
		bzero(kdata->datap, kdata->bufsize);
		if (read(fd, kdata->datap, kdata->filesize) != kdata->filesize) {
			cleanup_ktdata(kdata);
			(void) close(fd);
			return (errno);
		}
		(void) close(fd);
	} else {
		cleanup_ktdata(kdata);
		return(errno);
	}

	return (0);
}

static int
mread(void *data, size_t length, krb5_ktfile_data *kdata)
{
	if (kdata->offset + length > kdata->filesize) {
		errno = EINVAL;
		return (0);
	}

	(void) memcpy(data, &kdata->datap[kdata->offset], length);
	kdata->offset += length;

	return (length);
}

static int
mwrite(void *data, size_t length, krb5_ktfile_data *kdata)
{
	int err = 0;

	if ((kdata->offset + length) > kdata->bufsize) {
		krb5_error_code ret;
		int fd;
		struct stat statrec;
		/*
		 * Because we never know exactly how large
		 * the intial buffer will need to be there is a
		 * small chance that the data written will exceed
		 * our initial estimate.  In this case,
		 * reallocate a larger buffer before continuing.
		 */
		kdata->datap = realloc(kdata->datap,
				kdata->bufsize + (8 * BUFSIZ));
		if (kdata->datap == NULL) {
			int err = errno;
			cleanup_ktdata(kdata);
			return(err);
		}
		/* indicate the larger buffer size. */
		kdata->bufsize += (8 * BUFSIZ);

		/*
		 * In this situation, we want to continue adding
		 * to the end of the file, so set the 'offset'.
		 */
		kdata->offset = kdata->filesize;
	}

	(void) memcpy(&kdata->datap[kdata->offset], data, length);
	kdata->offset += length;

	/* grow the filesize if we appended */
	if (kdata->offset > kdata->filesize)
		kdata->filesize = kdata->offset;

	return (length);
}

static int
mclear(size_t length, krb5_ktfile_data *kdata)
{
	if (kdata->offset + length > kdata->bufsize)
		return (KRB5_KT_IOERR);
	
	bzero(&kdata->datap[kdata->offset], length);
		
	if (kdata->filesize > kdata->offset)
		kdata->filesize = kdata->offset;

	return (0);
}

krb5_error_code
krb5_ktfileint_openr(context, id)
	krb5_context context;
	krb5_keytab id;
{
	krb5_ktfile_data *kdata = (krb5_ktfile_data *) id->data;
	krb5_error_code retval = 0;
	char *open_flag;
	krb5_int16 kvno;
	int fd, err;
	struct stat statrec;

	/* Don't know what state it's in; shut down and start anew. */
	if (kdata->datap) {
		cleanup_ktdata(kdata);
	}

	if (ktf_open_file(kdata, 0))
		return (KRB5_KT_IOERR);

	kdata->offset = 0;

	if (!mread(&kvno, sizeof (kvno), kdata)) {
		cleanup_ktdata(kdata);
		return(KRB5_KT_IOERR);
	}

	kdata->version = ntohs(kvno);

	if ((kdata->version != KRB5_KT_VNO_1) &&
	    (kdata->version != KRB5_KT_VNO)) {
		cleanup_ktdata(kdata);
		return (KRB5_KEYTAB_BADVNO);
	}

	return (0);
}

krb5_error_code
krb5_ktfileint_openw(context, id)
	krb5_context context;
	krb5_keytab id;
{
	krb5_ktfile_data *kdata = (krb5_ktfile_data *) id->data;
	krb5_error_code retval = 0;
	krb5_int16 kvno;
	struct stat statrec;
	int fd;

	/*
	 * If the file was already opened for writing,
	 * just reset the offset to skip past the kvno.
	 */
	if (kdata->datap && kdata->writable)  {
		kdata->offset = sizeof (kvno);
		return (0);
	}

	cleanup_ktdata(kdata);
	if (ktf_open_file(kdata, 1))
		return (KRB5_KT_IOERR);

	kdata->offset = 0;

	/* overwrite the version number */
	kdata->version = kvno = htons(KRB5_KT_DEFAULT_VNO);

	if (mwrite(&kvno, sizeof (kvno), kdata) != sizeof (kvno)) {
		cleanup_ktdata(kdata);
		return (KRB5_KT_IOERR);
	}

	return (0);
}

krb5_error_code
krb5_ktfileint_close(context, id)
	krb5_context context;
	krb5_keytab id;
{
	krb5_ktfile_data *kdata = (krb5_ktfile_data *) id->data;
	krb5_error_code retval = 0;

	if (kdata->datap == NULL)
		return (KRB5_FCC_INTERNAL);

	cleanup_ktdata(kdata);

	return (retval);
}


krb5_error_code
krb5_ktfileint_delete_entry(context, id, delete_point)
	krb5_context context;
	krb5_keytab id;
	krb5_int32 delete_point;
{
	krb5_ktfile_data *kdata = (krb5_ktfile_data *) id->data;
	krb5_int32 size, nsize;
	krb5_error_code ret;

	kdata->offset = delete_point;
	if (!mread(&size, sizeof(size), kdata)) {
		return (KRB5_KT_END);
	}

	if (kdata->version != KRB5_KT_VNO_1)
		size = ntohl(size);

	if (size >= 0) {
		kdata->offset = delete_point;
		/*
		 * Shift the remainder of the keytab to the delete point.  This
		 * avoids writing holes to the keytab file, as we used to, and
		 * so is more space efficient.  Older versions of this code, as
		 * well as non-Solaris writers of keytabs may still write holes,
		 * so we still support reading holes.
		 */
		(void) memmove(&kdata->datap[delete_point], 
			&kdata->datap[delete_point + sizeof (size) + size],
			kdata->filesize - (size + sizeof (size)));

		kdata->filesize -= (size + sizeof (size));
		kdata->offset = delete_point;
		
		return (ktf_update_file_on_disk(kdata));
	}
	return (0);
}

/*ARGSUSED*/
krb5_error_code
krb5_ktfileint_internal_read_entry(context, id, ret_entry, delete_point)
	krb5_context context;
	krb5_keytab id;
	krb5_keytab_entry *ret_entry;
	krb5_int32 *delete_point;
{
	krb5_ktfile_data *kdata = (krb5_ktfile_data *) id->data;
	krb5_int32 size, fpos, type;
	krb5_int16 length, realm_len, compsize;
	krb5_data  *data;
	char *realmdata;
	krb5_timestamp timestamp;
	krb5_int16 enctype;
	krb5_octet vno;
	int i;
	krb5_int16 datasize;
	krb5_error_code error = 0;

	do {
		*delete_point = kdata->offset;
		if (!mread((void *)&size, sizeof (size), kdata)) {
			return (KRB5_KT_END);
		}

		if (kdata->version != KRB5_KT_VNO_1)
			size = ntohl(size);

		if (size < 0) {
			kdata->offset += -size;
		}
	} while (size < 0);

	if (size == 0) /* EOF reached */
		return (KRB5_KT_END);
		
	fpos = kdata->offset;
	memset(ret_entry, 0, sizeof (krb5_keytab_entry));
	ret_entry->magic = KV5M_KEYTAB_ENTRY;

	ret_entry->principal = (krb5_principal)
			malloc(sizeof (krb5_principal_data));
	if (ret_entry->principal == NULL) {
		return (KRB5_CC_NOMEM);
	}

	/*
	 * Read the number of components
	 * DCE includes the principal's realm in the count;
	 * the new format does not
	 */

	if (!mread((char *)&length, sizeof (length), kdata)) {
		return (KRB5_KT_END);
	}
	if (kdata->version != KRB5_KT_VNO_1)
		length = ntohs(length);
	else
		length--;

	if (length) {
		ret_entry->principal->data = (krb5_data *)
			malloc(length*sizeof (krb5_data));
		if (ret_entry->principal->data == NULL) {
			free((char *)ret_entry->principal);
			return (KRB5_CC_NOMEM);
		}
	} else
		return (KRB5_KT_END);

	ret_entry->principal->magic = KV5M_PRINCIPAL;
	ret_entry->principal->length = length;

	/* Read the realm length */
	if (!mread((char *)&realm_len, sizeof (realm_len), kdata)) {
		free((char *)ret_entry->principal);
		free((char *)ret_entry->principal->data);
		return (KRB5_KT_END);
	}

	if (kdata->version != KRB5_KT_VNO_1)
		realm_len = ntohs(realm_len);

	/* Read the realm data */
	if (realm_len) {
		realmdata = (char *) malloc((realm_len+1) * sizeof (char));
		if (realmdata == NULL) {
			free((char *)ret_entry->principal);
			free((char *)ret_entry->principal->data);
			return (KRB5_CC_NOMEM);
		}
	} else {
		free((char *)ret_entry->principal);
		free((char *)ret_entry->principal->data);
		return (KRB5_KT_END);
	}

	if (!mread((char *)realmdata, realm_len, kdata)) { 
		free((char *)ret_entry->principal);
		free((char *)ret_entry->principal->data);
		free((char *)realmdata);
		return (KRB5_KT_END);
	}
	realmdata[realm_len] = 0; /* Null termination */

	krb5_princ_set_realm_length(context, ret_entry->principal, realm_len);
	krb5_princ_set_realm_data(context, ret_entry->principal, realmdata);

	/* Read principal components */
	for (i = 0; i < length; i++) {
		data = krb5_princ_component(context, ret_entry->principal, i);

		if (!mread((char *)&compsize, sizeof (compsize), kdata)) {
			error = KRB5_KT_END;
			goto errout;
		}
		if (kdata->version != KRB5_KT_VNO_1)
			compsize = ntohs(compsize);
		else
			compsize--;
		data->length = compsize;

		if (data->length) {
			data->data = (char *)
				malloc((data->length+1) * sizeof (char));
		if (data->data == NULL) {
			error = KRB5_CC_NOMEM;
			goto errout;
		}
		} else {
			data->data = 0;
			error = KRB5_KT_END;
			goto errout;
		}

		datasize = mread((char *)data->data, data->length, kdata);
		if (datasize != compsize) {
			error = KRB5_KT_END;
			goto errout;
		}

		/* Null terminate, just in case..... */
		data->data[data->length] = 0;
	}
	/* Read the principal type */
	if (!mread((char *)&type, sizeof (type), kdata)) {
		error = KRB5_KT_END;
		goto errout;
	}

	if (kdata->version != KRB5_KT_VNO_1)
		type = ntohl(type);
	ret_entry->principal->type = type;

	/* Read the timestamp */
	if (!mread((char *)&timestamp, sizeof (timestamp), kdata)) {
		error = KRB5_KT_END;
		goto errout;
	}

	if (kdata->version != KRB5_KT_VNO_1)
		timestamp = ntohl(timestamp);
	ret_entry->timestamp = timestamp;

	/* Read the Version number */
	if (!mread((char *)&vno, sizeof (vno), kdata)) {
		error = KRB5_KT_END;
		goto errout;
	}

	ret_entry->vno = (krb5_kvno)vno;

	/* Read the key type */
	if (!mread((char *)&enctype, sizeof (enctype), kdata)) {
		error = KRB5_KT_END;
		goto errout;
	}

	if (kdata->version != KRB5_KT_VNO_1)
		enctype = ntohs(enctype);
	ret_entry->key.enctype = (krb5_enctype)enctype;

	ret_entry->key.magic = KV5M_KEYBLOCK;

	/* Read the key length */
	if (!mread((char *)&length, sizeof (length), kdata)) {
		error = KRB5_KT_END;
		goto errout;
	}

	if (kdata->version != KRB5_KT_VNO_1)
		length = ntohs(length);
	ret_entry->key.length = length;

	if (length) {
		ret_entry->key.contents = (krb5_octet *)
			malloc(length * sizeof (krb5_octet));
		if (ret_entry->key.contents == NULL) {
			error = KRB5_CC_NOMEM;
			goto errout;
		} else {
			if (!mread((char *)ret_entry->key.contents,
				length, kdata)) {
				free((char *)ret_entry->key.contents);
				error = KRB5_KT_END;
				goto errout;
			}
		}
	} else {
		ret_entry->key.contents = 0;
		free((char *)ret_entry->key.contents);
		error = KRB5_KT_END;
		goto errout;
	}

	/* the file position should left at delete_point+N */
	kdata->offset = fpos + size;

	return (0);

errout:
	i = ret_entry->principal->length;
	while (--i >= 0)
		free(krb5_princ_component(context,
			ret_entry->principal, i)->data);
	free((char *)ret_entry->principal->data);
	free((char *)ret_entry->principal);
	free((char *)realmdata);
	return (error);
}

krb5_error_code
krb5_ktfileint_read_entry(context, id, entryp)
	krb5_context context;
	krb5_keytab id;
	krb5_keytab_entry *entryp;
{
	krb5_int32 delete_point;

	return (krb5_ktfileint_internal_read_entry(context, id,
						entryp, &delete_point));
}


krb5_error_code
krb5_ktfileint_write_entry(context, id, entry)
	krb5_context context;
	krb5_keytab id;
	krb5_keytab_entry *entry;
{
	krb5_ktfile_data *kdata = (krb5_ktfile_data *) id->data;
	krb5_error_code retval = 0;
	krb5_int32 size_needed, commit_point, type;
	krb5_int16 length, realm_len, compsize;
	krb5_timestamp timestamp;
	krb5_int16 enctype;
	krb5_data *data;
	char *realmdata;
	int i;
	krb5_octet kvno;
	krb5_int16 count;


	retval = krb5_ktfileint_size_entry(context, entry, &size_needed);
	if (retval)
		return (retval);

	retval = krb5_ktfileint_find_slot(context, id,
				&size_needed, &commit_point);
	if (retval)
		return (retval);

	/* principal size */
	length = (krb5_int16) krb5_princ_size(context, entry->principal);
	if (kdata->version != KRB5_KT_VNO_1)
		length = htons(length);
	else
		length++;

	if (!mwrite((char *)&length, sizeof(length), kdata))
		return (KRB5_KT_IOERR);

	/* Realm length */
	realm_len = krb5_princ_realm(context, entry->principal)->length;
	if (kdata->version != KRB5_KT_VNO_1)
		realm_len = htons(realm_len);

	if (!mwrite((char *)&realm_len, sizeof (realm_len), kdata))
		return (KRB5_KT_IOERR);

	/* Realm data */
	if (realm_len) {
		realmdata = (char *) krb5_princ_realm(context,
					entry->principal)->data;
		if (!mwrite((char *)realmdata, 
			krb5_princ_realm(context, entry->principal)->length,
			kdata))
			return (KRB5_KT_IOERR);
	}

	/* Princ components */
	count = (krb5_int16) entry->principal->length;
	for (i = 0; i < count; i++) {
		data = krb5_princ_component(context, entry->principal, i);
		compsize = data->length;
		if (kdata->version != KRB5_KT_VNO_1)
			compsize = htons(compsize);
		else
			compsize++;

		if (!mwrite((char *)&compsize, sizeof (compsize), kdata)) {
			return (KRB5_KT_IOERR);
		}

		if (data->length) {
			if (!mwrite((char *)data->data, data->length, kdata))
				return (KRB5_KT_IOERR);
		}
	}
	/* principal type */
	type = krb5_princ_type(context, entry->principal);
	if (kdata->version != KRB5_KT_VNO_1)
		type = htonl(type);
	
	if (!mwrite((char *)&type, sizeof (type), kdata))
		return (KRB5_KT_IOERR);

	/* timestamp */
	if (krb5_timeofday(context, &entry->timestamp))
		entry->timestamp = 0;
	if (kdata->version != KRB5_KT_VNO_1)
		timestamp = htonl(entry->timestamp);
	else
		timestamp = entry->timestamp;

	if (!mwrite((char *)&timestamp, sizeof (timestamp), kdata))
		return (KRB5_KT_IOERR);

	/* key version */
	kvno = (krb5_octet)entry->vno;
	if (!mwrite((char *)&kvno, sizeof (kvno), kdata))
		return (KRB5_KT_IOERR);

	/* key type */
	enctype = entry->key.enctype;
	if (kdata->version != KRB5_KT_VNO_1)
		enctype = htons(enctype);

	if (!mwrite((char *)&enctype, sizeof (enctype), kdata))
		return (KRB5_KT_IOERR);

	/* key length and contents */
	length = entry->key.length;
	if (kdata->version != KRB5_KT_VNO_1)
		length = htons(length);

	if (!mwrite((char *)&length, sizeof (length), kdata))
		return (KRB5_KT_IOERR);

	if (length) {
		if (!mwrite((char *)entry->key.contents,
			entry->key.length, kdata))
			return (KRB5_KT_IOERR);
	}

	/* seek to the start of the entry and write size_needed */
	kdata->offset = commit_point;

	if (kdata->version != KRB5_KT_VNO_1)
		size_needed = htonl(size_needed);

	if (!mwrite((char *)&size_needed, sizeof (size_needed), kdata))
		return (KRB5_KT_IOERR);

	return (ktf_update_file_on_disk(kdata));
}

/*ARGSUSED*/
krb5_error_code
krb5_ktfileint_size_entry(context, entry, size_needed)
	krb5_context context;
	krb5_keytab_entry *entry;
	krb5_int32 *size_needed;
{
	int i;
	krb5_int32 size = 0;

	/* principal size */
	size = sizeof ((krb5_int16) (krb5_princ_size(context, entry->principal)));

	/* realm length */
	size += krb5_princ_realm(context, entry->principal)->length +
				(sizeof (krb5_int16));

	/* length of princ components */
	for (i = 0; i < entry->principal->length; i++) {
		size += krb5_princ_component(context,
			entry->principal, i)->length + sizeof (krb5_int16);
	}

	/* principal type */
	size += sizeof (krb5_princ_type(context, entry->principal));

	/* timestamp */
	size += sizeof (entry->timestamp);
	/* key version */
	size += sizeof ((krb5_octet)(entry->vno));
	/* secret key length */
	size += sizeof (krb5_int16) + (entry->key.length);
	/* key enc type */
	size += sizeof ((krb5_int16)(entry->key.enctype));

	*size_needed = size;
	return (0);
}

/*ARGSUSED*/
krb5_error_code
krb5_ktfileint_find_slot(context, id, size_needed, commit_point)
	krb5_context context;
	krb5_keytab id;
	krb5_int32 *size_needed;
	krb5_int32 *commit_point;
{
	krb5_ktfile_data *kdata = (krb5_ktfile_data *) id->data;
	krb5_int32 size, nsize, fpos;
	char zeros[BUFSIZ];
	krb5_boolean foundslot = FALSE;
	krb5_error_code ret;
	krb5_int16 kvno;
	krb5_int32 temp_pos;

	/* check for size_needed for entry */
	if (size_needed == 0)
		return (errno);

	kdata->offset = 0;

	/* read the key version */
	if (!mread(&kvno, sizeof (kvno), kdata))
		return (KRB5_KT_IOERR);

	while (!foundslot) {
		/* offset of slot */
		*commit_point = kdata->offset;

		if (!mread((char *)&size, sizeof (size), kdata)) {
			/* EOF reached */
			/*
			 * reset to the commit_point, just in case if
			 * bytes read were less than 4
			 */
			kdata->offset = *commit_point;

			/* append sizeof(krb5_int32) bytes of zeros */
			size = 0;
			if (!mwrite((char *)&size, sizeof (size), kdata))
                        	return (KRB5_KT_IOERR);

			foundslot = TRUE;
		}

		if (kdata->version != KRB5_KT_VNO_1)
			size = ntohl(size);

		if (size > 0) {
			kdata->offset += size;
		} else if (!foundslot) {
			/* empty slot has an entry of -N */
			nsize = -size;
			if (nsize >= *size_needed) {
				*size_needed = nsize;
				foundslot = TRUE;
			} else if (nsize > 0) {
				/* current slot is small */
				kdata->offset += nsize;
			} else {
				/*
				 * Slot with size = 0
				 *
				 * If krb5_ktfileint_write_entry fails and the entry
				 * was being added at the EOF, we have have a slot
				 * with size = 0. Hence we need to clear every byte
				 * from here to EOF. A slot with size = 0 will always
				 * be at the EOF.
				 * If krb5_ktfileint_write_entry fails and the entry
				 * was being added to a slot from where previous entry
				 * was deleted, this slot will have a size of -N.
				 * This slot will not be at EOF, hence we do not clear
				 * this slot. This slot will be overwritten by the
				 * entry that can fit in the slot.
				 */
				fpos = kdata->offset;

				/*
				 * While loop will zero fill 4 bytes at a time from
				 * the current file position through EOF
				 * We must clear the bytes at 4 byte boundary, since
				 * the previous entry may have failed at an odd
				 * boundary.
				 */
				while (!foundslot) {
					temp_pos = kdata->offset;
					if (!mread(&size, sizeof (size),kdata)) {
						foundslot = TRUE;
					}
		
					if (!foundslot) {
						kdata->offset = temp_pos;
						ret = mclear(sizeof(nsize), kdata);
						if (ret)
							return (ret);
						kdata->offset += sizeof(nsize);
					}
				} /* while */

				/* reset to start of available slot */
				kdata->offset = fpos;
			} /* else */
		}
	} /* while */

	return (0);
}
