# Disabling tcpcp support saves a few KB in the binary.
USE_TCPCP=y
USE_GTK=n

ARCH=$(shell uname -m)
LIBCOMPAT=../../cryopid-0.6.9/dietlibc-x86_64/bin-x86_64/libcompat.a

# Test if this gcc supports stack protection (and if so, turn it off).
ifeq ($(shell $(CC) -E -fno-stack-protector - < /dev/null > /dev/null 2>&1 && echo 1),1)
CFLAGS_GCC_SP = -fno-stack-protector
endif

CFLAGS = -g -Wall -Os $(CFLAGS_GCC_SP) -I. -Iarch -D__$(ARCH)__

# Set arch-specific settings
ifneq ($(filter i%86,$(ARCH)), )
ARCH=i386
ARCH_OFORMAT=elf32-i386
LD_FORMAT=elf_i386
endif
ifeq ($(ARCH), x86_64)
ARCH_OFORMAT=elf64-x86-64
LD_FORMAT=elf_x86_64
USE_TCPCP=n
USE_GTK=n
endif
ifeq ($(ARCH), sparc)
ARCH_OFORMAT=elf32-sparc
LD_FORMAT=elf32_sparc
USE_TCPCP=n
USE_GTK=n
CFLAGS += -DARCH_HAS_ALIGNED_INSTRUCTIONS
endif
ifeq ($(ARCH), alpha)
ARCH_OFORMAT=elf64-alpha
LD_FORMAT=elf64alpha
USE_TCPCP=n
USE_GTK=n
endif

R_CHUNK_OBJS = cpimage_r.o cp_r_fd.o cp_r_fd_console.o cp_r_fd_file.o cp_r_fd_fifo.o cp_r_fd_socket.o cp_r_misc.o cp_r_sighand.o cp_r_vma.o cp_r_header.o arch/arch_r_objs.o fork2.o
W_CHUNK_OBJS = cpimage_w.o cp_w_fd.o cp_w_fd_console.o cp_w_fd_file.o cp_w_fd_fifo.o cp_w_fd_socket.o cp_w_misc.o cp_w_sighand.o cp_w_vma.o cp_w_header.o arch/arch_w_objs.o list.o 
COMMON_OBJS = common.c
STUB_TYPES = gzip # raw buffered lzo
STUBS = $(patsubst %,stub-%,$(STUB_TYPES))
TARGETS = freeze fork2_helper

# How do we get our libc linked into the stub?
LIBC = -DPROVIDE_MALLOC -nostdlib -nostartfiles ../dietlibc-x86_64/dietlibc.a $(LIBCOMPAT) -lgcc
#LIBC = -nostdlib -nostartfiles -lc

# Compile in tcpcp if wanted/needed
ifeq ($(USE_TCPCP),y)
R_CHUNK_OBJS += tcpcp_r.o 
W_CHUNK_OBJS += tcpcp_w.o 
DEFINES += -DUSE_TCPCP
endif

# Compile in Gtk+ support if wanted
ifeq ($(USE_GTK),y)
R_CHUNK_OBJS += gtk_support.o
DEFINES += -DUSE_GTK
endif

DEFINES += -DFORK2HELPER=\"$(PREFIX)/lib/cryopid/fork2_helper\"
CFLAGS += $(DEFINES)

# Utilities
CHPAX = /sbin/chpax
DEPAX = test ! -x $(CHPAX) || $(CHPAX) -xperms

# Targets
all: arch $(TARGETS) $(COMMON_OBJS) $(R_CHUNK_OBJS) $(W_CHUNK_OBJS)

arch:
	! test -h arch && rm -f arch && ln -s arch-$(ARCH) arch || true
	make -C arch 'CFLAGS+=$(DEFINES) $(CFLAGS_GCC_SP)'

distclean clean:
	rm -f *.o arch/*.o $(TARGETS) 
	rm -f arch

stub-image-%.o: stub-%
	@echo Generating binary object of $^
	@$(LD) -m $(LD_FORMAT) --format binary --oformat $(ARCH_OFORMAT) -r $< -o $@

stub-%: stub_common.o $(COMMON_OBJS) $(R_CHUNK_OBJS) writer_%.c
	@echo Linking $@
	$(CC) -static $(CFLAGS) -DCOMPILING_STUB -Tarch/stub-linking.x -Os -o $@ $^ -lz $(LIBC)
	@strip $@
	@$(DEPAX) $@

freeze: $(COMMON_OBJS) $(W_CHUNK_OBJS) freeze.o $(patsubst %,stub-image-%.o,$(STUB_TYPES)) $(patsubst %,writer_%.c,$(STUB_TYPES))
	@echo Linking $@
	$(CC) $(CFLAGS) -Os -o $@ $^ -lz

gtk_support.o: gtk_support.c
	$(CC) $(CFLAGS) -I/usr/include/gtk-2.0 -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include/pango-1.0 -I/usr/lib/gtk-2.0/include -I/usr/include/atk-1.0 -c $<

DESTDIR=/ws
PREFIX=harspras-bgl

fork2_helper: fork2_helper.c
	$(CC) $(CFLAGS) $< -o $@

install: freeze fork2_helper
	[ -d $(DESTDIR)/$(PREFIX)/bin/ ] || mkdir -p $(DESTDIR)/$(PREFIX)/bin/
	cp freeze $(DESTDIR)/$(PREFIX)/bin/
	[ -d $(DESTDIR)/$(PREFIX)/lib/cryopid/ ] || mkdir -p $(DESTDIR)/$(PREFIX)/lib/cryopid/
	cp fork2_helper $(DESTDIR)/$(PREFIX)/lib/cryopid/

.PHONY: arch clean distclean
