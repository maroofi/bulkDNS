CC := gcc
CFLAGS := -I./include -I./sdns/include -Wall -Werror
CLIBS := -ljansson -lpthread
SHELL = /bin/bash
LUA_INC_DIR=/usr/include/lua5.4
LUA_LIB=lua5.4


OUTDIR=bin
DEPS=./src/scanner.c ./src/cmdparser.c ./src/cqueue.c ./src/cstrlib.c
DEPS_sdns =./sdns/src/sdns.c ./sdns/src/sdns_dynamic_buffer.c ./sdns/src/sdns_json.c ./sdns/src/sdns_print.c ./sdns/src/sdns_utils.c 
HDEPS = $(wildcard ./include/*.h)
HDEPS_sdns = $(wildcard ./sdns/include/*.h)

DEPS_sdns_lua=$(wildcard ./sdns/src/*.c)
DEPS_lua=$(wildcard ./src/*.c)

bulkdns: dummy
	$(CC) $(CFLAGS) -o $(OUTDIR)/bulkdns $(DEPS) $(DEPS_sdns) $(CLIBS)
	@rm -f bin/*.o

with-lua: dummy
	$(CC) $(CFLAGS) -I$(LUA_INC_DIR) -o $(OUTDIR)/bulkdns $(DEPS) $(DEPS_sdns) $(CLIBS) -l$(LUA_LIB) -DCOMPILE_WITH_LUA
	@rm -f bin/*.o

dummy:
	@mkdir -p bin
	@rm -f bin/*.o

.PHONY: clean
clean:
	@rm -f bin/*.o

