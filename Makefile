CC := gcc
CFLAGS := -I./include -I./sdns/include -Wall
CLIBS := -ljansson -lpthread
SHELL = /bin/bash


OUTDIR = bin
DEPS = $(wildcard ./src/*.c)
DEPS_sdns = $(wildcard ./sdns/src/*.c)
HDEPS = $(wildcard ./include/*.h)
HDEPS_sdns = $(wildcard ./sdns/include/*.h)
OBJS = sdns.o sdns_print.o sdns_json.o sdns_dynamic_buffer.o sdns_utils.o
LIBOBJS = sdns.o sdns_print.o sdns_json.o sdns_dynamic_buffer.o sdns_utils.o
OBJSTEST = sdns.o sdns_print.o sdns_json.o sdns_dynamic_buffer.o sdns_utils.o test1.o
LIBNAME = libsdns.so


bulkdns: dummy bulkdns.o $(OBJS) $(HDEPS) $(HDEPS_sdns) cqueue.o cmdparser.o cstrlib.o
	@$(CC) $(CFLAGS) -o bin/bulkdns $(addprefix bin/, $(LIBOBJS)) $(CLIBS) bin/bulkdns.o bin/cstrlib.o bin/cqueue.o bin/cmdparser.o
	@rm -f bin/*.o

sdns.o: ./sdns/src/sdns.c ./sdns/include/sdns.h
	@$(CC) $(CFLAGS) -c $< -o bin/$@

sdns_print.o: ./sdns/src/sdns_print.c ./sdns/include/sdns_print.h
	@$(CC) $(CFLAGS) -c $< -o bin/$@

sdns_json.o: ./sdns/src/sdns_json.c ./sdns/include/sdns_json.h
	@$(CC) $(CFLAGS) -c $< -o bin/$@

sdns_dynamic_buffer.o: ./sdns/src/sdns_dynamic_buffer.c ./sdns/include/sdns_dynamic_buffer.h
	@$(CC) $(CFLAGS) -c $< -o bin/$@

sdns_utils.o: ./sdns/src/sdns_utils.c ./sdns/include/sdns_utils.h
	@$(CC) $(CFLAGS) -c $< -o bin/$@

bulkdns.o: src/scanner.c
	@$(CC) $(CFLAGS) -c $< -o bin/$@

cqueue.o: src/cqueue.c
	@$(CC) $(CFLAGS) -c $< -o bin/$@

cmdparser.o: src/cmdparser.c
	@$(CC) $(CFLAGS) -c $< -o bin/$@

cstrlib.o: src/cstrlib.c
	@$(CC) $(CFLAGS) -c $< -o bin/$@

dummy:
	@mkdir -p bin
	@rm -f bin/*.o

.PHONY: clean
clean:
	@rm -f bin/*.o

