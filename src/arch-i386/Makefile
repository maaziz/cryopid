COMMON_OBJS = 
R_CHUNK_OBJS = cp_r_regs.o cp_r_tls.o cp_r_i387.o start.o plt-resolve.o
W_CHUNK_OBJS = cp_w_regs.o cp_w_tls.o cp_w_i387.o
override CFLAGS += -g -Wall -Os -fpic -I. -I..

all: arch_r_objs.o arch_w_objs.o

arch_r_objs.o: $(COMMON_OBJS) stub.o $(R_CHUNK_OBJS)
	$(LD) -m elf_i386  -r -o $@ $^

arch_w_objs.o: $(COMMON_OBJS) process.o elfwriter.o $(W_CHUNK_OBJS)
	$(LD) -m elf_i386  -r -o $@ $^

