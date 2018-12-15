void * CreateFile();
void * socket();

int func (void)
{
	int *x;

	if (x = CreateFile()) {
		
	}

	x = socket();
	if (x != 0) {
	      
	}
	return;
}
/*
 * check-name: use INVALID_HANDLE_VALUE not zero
 * check-command: smatch -p=wine sm_wine_filehandles.c
 *
 * check-output-start
sm_wine_filehandles.c:8 func() error: comparing a filehandle against zero 'x'
sm_wine_filehandles.c:13 func() error: comparing a filehandle against zero 'x'
 * check-output-end
 */
