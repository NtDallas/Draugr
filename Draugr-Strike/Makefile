#Makefile

CCX64	=	x86_64-w64-mingw32-gcc
LDX64	= 	x86_64-w64-mingw32-ld

INCLUDE		= 	include/

CFLAGS	= -I./$(INCLUDE) -w -Os -s -m64 -masm=intel

all: prebuild core bof postbuild

prebuild:
	@ rm bin/*.o

core:
	@ nasm -f win64 src/asm/Utils.s -o bin/utils.o 
	@ $(CCX64) -c src/core/Spoof.c $(CFLAGS) -o bin/spoof.o

bof:
	@ $(CCX64) -c src/Main.c $(CFLAGS) -o bin/main.o
	@ $(LDX64) -r bin/*.o -o bin/draugr-strike.o
	@ echo "[*] BOF Ready in bin/draugr-strike.o !"

postbuild:
	@ rm bin/utils.o
	@ rm bin/main.o
	@ rm bin/spoof.o


