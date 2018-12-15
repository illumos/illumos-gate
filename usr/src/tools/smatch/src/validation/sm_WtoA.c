void wwww();
void wwwA();

void xxxW (void)
{
	wwwA();
	www();
}

void DRAW (void)
{
	wwwA();
}

void xxxA (void)
{
	wwwA();
	www();
}


/*
 * check-name: Cross calls WtoA
 * check-command: smatch -p=wine sm_WtoA.c
 *
 * check-output-start
sm_WtoA.c:6 xxxW() warn: WtoA call 'wwwA()'
 * check-output-end
 */
