#include <unistd.h>
#include <stdio.h>

int main(int argc, char** argv) {
	while(1) {
		printf("My pid is %d\n", getpid());
		sleep(5);
	}
}
