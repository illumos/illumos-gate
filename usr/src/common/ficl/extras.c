#include "ficl.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Ficl interface to system (ANSI)
 * Gets a newline (or NULL) delimited string from the input
 * and feeds it to the ANSI system function...
 * Example:
 *    system del *.*
 *    \ ouch!
 */
static void
ficlPrimitiveSystem(ficlVm *vm)
{
	ficlCountedString *counted = (ficlCountedString *)vm->pad;

	ficlVmGetString(vm, counted, '\n');
	if (FICL_COUNTED_STRING_GET_LENGTH(*counted) > 0) {
		int returnValue = \
		    system(FICL_COUNTED_STRING_GET_POINTER(*counted));
		if (returnValue) {
			sprintf(vm->pad, "System call returned %d\n",
			    returnValue);
			ficlVmTextOut(vm, vm->pad);
			ficlVmThrow(vm, FICL_VM_STATUS_QUIT);
		}
	} else {
		ficlVmTextOut(vm, "Warning (system): nothing happened\n");
	}
}

/*
 * Ficl add-in to load a text file and execute it...
 * Cheesy, but illustrative.
 * Line oriented... filename is newline (or NULL) delimited.
 * Example:
 *    load test.f
 */
#define	BUFFER_SIZE	256
static void
ficlPrimitiveLoad(ficlVm *vm)
{
	char buffer[BUFFER_SIZE];
	char filename[BUFFER_SIZE];
	ficlCountedString *counted = (ficlCountedString *)filename;
	int line = 0;
	FILE *f;
	int result = 0;
	ficlCell oldSourceId;
	ficlString s;

	ficlVmGetString(vm, counted, '\n');

	if (FICL_COUNTED_STRING_GET_LENGTH(*counted) <= 0) {
		ficlVmTextOut(vm, "Warning (load): nothing happened\n");
		return;
	}

	/*
	 * get the file's size and make sure it exists
	 */

	f = fopen(FICL_COUNTED_STRING_GET_POINTER(*counted), "r");
	if (!f) {
		ficlVmTextOut(vm, "Unable to open file ");
		ficlVmTextOut(vm, FICL_COUNTED_STRING_GET_POINTER(*counted));
		ficlVmTextOut(vm, "\n");
		ficlVmThrow(vm, FICL_VM_STATUS_QUIT);
	}

	oldSourceId = vm->sourceId;
	vm->sourceId.p = (void *)f;

	/* feed each line to ficlExec */
	while (fgets(buffer, BUFFER_SIZE, f)) {
		int length = strlen(buffer) - 1;

		line++;
		if (length <= 0)
			continue;

		if (buffer[length] == '\n')
			buffer[length--] = '\0';

		FICL_STRING_SET_POINTER(s, buffer);
		FICL_STRING_SET_LENGTH(s, length + 1);
		result = ficlVmExecuteString(vm, s);
		/* handle "bye" in loaded files. --lch */
		switch (result) {
		case FICL_VM_STATUS_OUT_OF_TEXT:
		case FICL_VM_STATUS_USER_EXIT:
		break;

		default:
			vm->sourceId = oldSourceId;
			fclose(f);
			ficlVmThrowError(vm, "Error loading file <%s> line %d",
			    FICL_COUNTED_STRING_GET_POINTER(*counted), line);
		break;
		}
	}
	/*
	 * Pass an empty line with SOURCE-ID == -1 to flush
	 * any pending REFILLs (as required by FILE wordset)
	 */
	vm->sourceId.i = -1;
	FICL_STRING_SET_FROM_CSTRING(s, "");
	ficlVmExecuteString(vm, s);

	vm->sourceId = oldSourceId;
	fclose(f);

	/* handle "bye" in loaded files. --lch */
	if (result == FICL_VM_STATUS_USER_EXIT)
		ficlVmThrow(vm, FICL_VM_STATUS_USER_EXIT);
}

/*
 * Dump a tab delimited file that summarizes the contents of the
 * dictionary hash table by hashcode...
 */
static void
ficlPrimitiveSpewHash(ficlVm *vm)
{
	ficlHash *hash = ficlVmGetDictionary(vm)->forthWordlist;
	ficlWord *word;
	FILE *f;
	unsigned i;
	unsigned hashSize = hash->size;

	if (!ficlVmGetWordToPad(vm))
		ficlVmThrow(vm, FICL_VM_STATUS_OUT_OF_TEXT);

	f = fopen(vm->pad, "w");
	if (!f) {
		ficlVmTextOut(vm, "unable to open file\n");
		return;
	}

	for (i = 0; i < hashSize; i++) {
		int n = 0;

		word = hash->table[i];
		while (word) {
			n++;
			word = word->link;
		}

		fprintf(f, "%d\t%d", i, n);

		word = hash->table[i];
		while (word) {
			fprintf(f, "\t%s", word->name);
			word = word->link;
		}

		fprintf(f, "\n");
	}

	fclose(f);
}

static void
ficlPrimitiveBreak(ficlVm *vm)
{
	vm->state = vm->state;
}

void
ficlSystemCompileExtras(ficlSystem *system)
{
	ficlDictionary *dictionary = ficlSystemGetDictionary(system);

	ficlDictionarySetPrimitive(dictionary, "break", ficlPrimitiveBreak,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "load", ficlPrimitiveLoad,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "spewhash",
	    ficlPrimitiveSpewHash, FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "system", ficlPrimitiveSystem,
	    FICL_WORD_DEFAULT);
}
