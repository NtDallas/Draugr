#Makefile

CCX64	=	x86_64-w64-mingw32-gcc
LDX64	= 	x86_64-w64-mingw32-ld

INCLUDE		= 	include/

CFLAGS	= -I./$(INCLUDE) -w -Os -s -m64 -masm=intel

.DEFAULT: helper 

helper:
	@ echo "Injection method : earlybird threadspoof threadpool"
	@ echo "For threadpool method, threadpooling is for explicit injection. The inplicit injection use early bird !"
	@ echo "NB : Threadpooling is not stable, for stability use earlybird or threadspoof"

prebuild:
	@ echo "[*] Init prebuild ..."
	@ rm bin/*.o

core:
	@ echo "[*] Building core..."
	@ nasm -f win64 src/asm/Utils.s -o bin/utils.o 
	@ $(CCX64) -c src/core/Spoof.c $(CFLAGS) -o bin/spoof.o
	@ $(CCX64) -c src/core/Syscalls.c $(CFLAGS) -o bin/syscalls.o

core_inject:
	@ echo "[*] Building core inject..."
	@ $(CCX64) -c src/Injection/EarlyBird_Injection.c $(CFLAGS) -o bin/earlybird_injection.o
	@ $(CCX64) -c src/Injection/ThreadSpoof_Injection.c $(CFLAGS) -o bin/threadspoof_injection.o

threadspoof: prebuild core core_inject
	@ $(MAKE) --no-print-directory inject_explicit THREADSPOOF=1
	@ echo "[*] BOF Ready in bin/inject_explicit.o with thread spoof injection !"

	@ $(MAKE) --no-print-directory inject_spawn THREADSPOOF=1
	@ echo "[*] BOF Ready in bin/inject_spawn.o with thread spoof injection !"

	@ $(MAKE) --no-print-directory postbuild  

earlybird: prebuild core core_inject
	@ $(MAKE) --no-print-directory inject_explicit EARLYBIRD=1
	@ echo "[*] BOF Ready in bin/inject_explicit.o with thread spoof injection !"

	@ $(MAKE) --no-print-directory inject_spawn EARLYBIRD=1
	@ echo "[*] BOF Ready in bin/inject_spawn.o with thread spoof injection !"

	@ $(MAKE) --no-print-directory postbuild  

inject_explicit:
	@ $(CCX64) -c src/Main.c $(CFLAGS) -DINJECT_EXPLICIT $(if $(THREADSPOOF),-DTHREADSPOOF) $(if $(EARLYBIRD),-DEARLYBIRD) -o bin/inject_explicit_temp.o
	@ $(LDX64) -r bin/*.o -o bin/temp/inject_explicit.o
	@ rm bin/inject_explicit_temp.o

inject_spawn:
	@ $(CCX64) -c src/Main.c $(CFLAGS) -DINJECT_SPAWN $(if $(THREADSPOOF),-DTHREADSPOOF) $(if $(EARLYBIRD),-DEARLYBIRD) -o bin/inject_spawn_temp.o
	@ $(LDX64) -r bin/*.o -o bin/temp/inject_spawn.o
	@ rm bin/inject_spawn_temp.o

postbuild:
	@ echo "[*] Cleanup ..."
	@ rm bin/*.o
	@ mv bin/temp/inject_explicit.o bin/inject_explicit.o
	@ mv bin/temp/inject_spawn.o bin/inject_spawn.o



