#include "ficl.h"

extern ficlSystem *ficlSystemGlobal;

/*
 * f i c l C a l l b a c k T e x t O u t
 * Feeds text to the vm's output callback
 */
void
ficlCallbackTextOut(ficlCallback *callback, char *text)
{
	ficlOutputFunction textOut = NULL;

	if (callback != NULL) {
		if (callback->textOut != NULL)
			textOut = callback->textOut;
		else if ((callback->system != NULL) &&
		    (callback != &(callback->system->callback))) {
			ficlCallbackTextOut(&(callback->system->callback),
			    text);
			return;
		}
	}

	if ((textOut == NULL) && (ficlSystemGlobal != NULL)) {
		callback = &(ficlSystemGlobal->callback);
		textOut = callback->textOut;
	}

	if (textOut == NULL)
		textOut = ficlCallbackDefaultTextOut;

	(textOut)(callback, text);
}

/*
 * f i c l C a l l b a c k E r r o r O u t
 * Feeds text to the vm's error output callback
 */
void
ficlCallbackErrorOut(ficlCallback *callback, char *text)
{
	ficlOutputFunction errorOut = NULL;

	if (callback != NULL) {
		if (callback->errorOut != NULL)
			errorOut = callback->errorOut;
		else if ((callback->system != NULL) &&
		    (callback != &(callback->system->callback))) {
			ficlCallbackErrorOut(&(callback->system->callback),
			    text);
			return;
		}
	}

	if ((errorOut == NULL) && (ficlSystemGlobal != NULL)) {
		callback = &(ficlSystemGlobal->callback);
		errorOut = callback->errorOut;
	}

	if (errorOut == NULL) {
		ficlCallbackTextOut(callback, text);
		return;
	}

	(errorOut)(callback, text);
}
