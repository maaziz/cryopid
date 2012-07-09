#include <unistd.h>

int main() {
	unsigned long a;
	for(a=0; a < 0x1fffffff; a++);
	write(2, "Moo\n", 4);
	return 0;
}
