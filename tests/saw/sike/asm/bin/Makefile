S2N_ROOT=../../../../..

test: test.c
	$(CC) -D _MULX_ -D _ADX_ $< $(S2N_ROOT)/pq-crypto/sike_r2/fp_x64_asm.S $(S2N_ROOT)/lib/libs2n.a -lcrypto -lpthread -o $@
