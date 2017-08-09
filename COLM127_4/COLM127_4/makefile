TARGET	= test85
# LIBSRCS	= colm0_working.c
LIBOBJS	= main.o encrypt.o decrypt.o auxfuncs.o
HEADERS = api.h
CC	= gcc
CFLAGS= -march=native -std=c99 -O3 # -Wall

# SOFLAGS = # -shared 
# XLIBS	= 

$(TARGET): $(LIBOBJS)
	$(CC) $(LIBOBJS) -o $(TARGET) 
	
main.o: main.c auxfuncs.h crypto_aead.h api.h
	 $(CC) -c main.c $(CFLAGS) -o $@ 

encrypt.o: encrypt.c crypto_aead.h auxfuncs.h api.h
	 $(CC) -c encrypt.c $(CFLAGS) -o $@ 
	 
decrypt.o: decrypt.c crypto_aead.h auxfuncs.h api.h
	 $(CC) -c decrypt.c $(CFLAGS) -o $@ 
	 
auxfuncs.o: auxfuncs.c auxfuncs.h api.h
	 $(CC) -c auxfuncs.c $(CFLAGS) -o $@ 

cleaner: clean
	rm -f outfile*
	rm -f test85
	
clean:
	@/bin/rm -f core core.* $(LIBOBJS) 
	
