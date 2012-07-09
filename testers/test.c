#include <malloc.h>
#include <unistd.h>
#include <stdio.h>

#define MEM_SIZE (1024*1024)

void* gimme_some_memory() {
	return malloc(MEM_SIZE);
}

void fill_in(char* mem) {
	int i;
	for (i=0; i < MEM_SIZE; i++)
		mem[i] = i%256;
}

void play_with(unsigned char* mem1, unsigned char* mem2, int offset) {
	int i;
	for (i=0; i < MEM_SIZE; i++) {
		if (mem1[i] != mem2[i]) {
			printf("mem1[%d] == 0x%x != mem[%d] == 0x%x\n", i, mem1[i], i, mem2[i]);
		}
		mem1[i] = (i+offset)%256;
		mem2[i] = (i+offset)%256;
	}
}

int main() {
	unsigned char *mem1, *mem2;
	int offset;
	mem1 = (unsigned char*)gimme_some_memory();
	mem2 = (unsigned char*)gimme_some_memory();
	fill_in(mem1);
	fill_in(mem2);

	offset = 0;
	do {
        int j;
		play_with(mem1, mem2, offset);
        printf("Loop done, offset = %d\n", offset);
		sleep(1);
        /* for (j=0;j<0x4000000;j++); */
		offset++;
		if (offset > 256) offset = 0;
	} while(1);
	return 0;
}
