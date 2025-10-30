#Makefile

CCX64	=	x86_64-w64-mingw32-gcc
LDX64	= 	x86_64-w64-mingw32-ld

CFLAGS	=  -w -Os -s -m64 -masm=intel

TEMP_PATH	= Bin/temp

draugr:
	@ rm Bin/temp/*
	@ nasm -f win64 Src/Stub.s -o $(TEMP_PATH)/Stub.o
	@ $(CCX64) -c Src/Bof.c $(CFLAGS) -o $(TEMP_PATH)/Bof.o
	@ $(CCX64) -c Src/Draugr.c $(CFLAGS) -o $(TEMP_PATH)/Draugr.o
	@ $(LDX64) -r $(TEMP_PATH)/*.o -o Bin/bof.o 
	@ echo "[*] BOF Ready "	