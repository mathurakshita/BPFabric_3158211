CFLAGS := -g -I../ubpf/inc -I../protocol/src/c -I../bpfmap -I../includes

all: agent.a

agent.a: agent.o signature_verifier.o
	ar cr agent.a agent.o signature_verifier.o

agent.o: agent.c signature_verifier.h
	gcc $(CFLAGS) -c agent.c

signature_verifier.o: signature_verifier.c signature_verifier.h
	gcc $(CFLAGS) -c signature_verifier.c

clean:
	$(RM) -f *.o *.a
