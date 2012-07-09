#include <stdio.h>
int i;
void d() {
    int k = 0;
foo:
    k = k + 1;
    if(k < 0x20000000)
        goto foo;
    printf("meep\n");
    fflush(stdout);
}
void c(int z) { if(z)d(); }
void b(int z) { if(z)c(z); }
void a(int z) { if(z)b(z); }
int main() {
    int j = 0;
    a(0);
    b(0);
    c(0);
    d();
    printf("moo\n");
    fflush(stdout);
    exit(42);
	return 0;
}
