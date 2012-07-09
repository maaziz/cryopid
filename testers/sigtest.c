/* Do signal handlers get restored? */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

void sig_handler(int sig) {
	printf("Got signal %d!\n", sig);
}

int main() {
	signal(SIGUSR1, sig_handler);
	signal(SIGUSR2, sig_handler);
	for(;;) {
		raise(SIGUSR1);
		sleep(2);
		raise(SIGUSR2);
		sleep(2);
	}
	return 0;
}
