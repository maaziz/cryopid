CFLAGS=-g -Wall

OBJECTS = test easytest mypidis sigtest

CHPAX = /sbin/chpax
DEPAX = test -x $(CHPAX) && $(CHPAX) -xperms 

all: $(OBJECTS)
	$(DEPAX) $^

clean:
	rm -f *.o $(OBJECTS)
