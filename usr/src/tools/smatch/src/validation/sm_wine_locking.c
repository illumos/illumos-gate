int create_window_handle(int x);
void WIN_ReleasePtr(int x);
void EnterCriticalSection(int x);
void LeaveCriticalSection(int x);
void USER_Lock(void);
void USER_Unlock(void);
int GDI_GetObjPtr(int x);
void GDI_ReleaseObj(int x);

int a, b, c, d, e, z;

void test1(void)
{
	b = create_window_handle(a);
	z = frob();

	if (d = GDI_GetObjPtr(e))
		GDI_ReleaseObj(e);
	if (GDI_GetObjPtr(e))
		GDI_ReleaseObj(e);
	EnterCriticalSection(c);
	USER_Lock();
	if (b) {
		LeaveCriticalSection(c);
		WIN_ReleasePtr(b);
	}
	WIN_ReleasePtr(b);
	if (z)
		return;
	USER_Unlock();
	if (!b)
		LeaveCriticalSection(c);
}
/*
 * check-name: WINE locking
 * check-command: smatch -p=wine --spammy sm_wine_locking.c
 *
 * check-output-start
sm_wine_locking.c:27 test1() error: double unlock 'create_window_handle:b'
sm_wine_locking.c:29 test1() warn: 'CriticalSection:c' is sometimes locked here and sometimes unlocked.
sm_wine_locking.c:32 test1() warn: inconsistent returns 'USER_Lock:'.
  Locked on:   line 29
  Unlocked on: line 32
 * check-output-end
 */
