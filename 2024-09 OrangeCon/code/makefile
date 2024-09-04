# Mozilla Public License (MPL) Version 2.0.
#
# Copyright (c) 2024 Tijme Gommers (@tijme).
#
# This source code file is licensed under Mozilla Public 
# License (MPL) Version 2.0, and you are free to use, modify, 
# and distribute this file under its terms. However, any 
# modified versions of this file must include this same 
# license and copyright notice.

CC64 := x86_64-w64-mingw32-gcc

.PHONY: require_mingw dst/DisplayCurrentIntegrityLevel.x64.exe dst/EnableAllPrivilegesOfParentProcess.x64.exe dst/SpawnHighIntegrityShellWithFilteredToken.x64.exe dst/CopyFile.x64.exe dst/CopyFileElevated.x64.exe dst/UACBypassCMSTPLUA.x64.exe

all: require_mingw dst/DisplayCurrentIntegrityLevel.x64.exe dst/EnableAllPrivilegesOfParentProcess.x64.exe dst/SpawnHighIntegrityShellWithFilteredToken.x64.exe dst/CopyFile.x64.exe dst/CopyFileElevated.x64.exe dst/UACBypassCMSTPLUA.x64.exe

require_mingw:
ifeq (, $(shell which $(CC64)))
		@echo "[!] MinGW $(CC64) is not installed! Please install via one of the commands below."
		@echo "    - Linux: apt install mingw-w64"
		@echo "    - MacOS: brew install mingw-w64"
		@echo "    - Other: https://www.mingw-w64.org/downloads/"
		@exit 0
else
	@echo "[+] Using MinGW $(CC64)!"
endif

dst/DisplayCurrentIntegrityLevel.x64.exe:
	$(CC64) ./src/1_uac/DisplayCurrentIntegrityLevel.c -o ./dst/DisplayCurrentIntegrityLevel.x64.exe -masm=intel -lntdll

dst/EnableAllPrivilegesOfParentProcess.x64.exe:
	$(CC64) ./src/1_uac/EnableAllPrivilegesOfParentProcess.c -o ./dst/EnableAllPrivilegesOfParentProcess.x64.exe -masm=intel -lntdll

dst/SpawnHighIntegrityShellWithFilteredToken.x64.exe:
	$(CC64) ./src/1_uac/SpawnHighIntegrityShellWithFilteredToken.c -o ./dst/SpawnHighIntegrityShellWithFilteredToken.x64.exe -masm=intel -lntdll

dst/CopyFile.x64.exe:
	$(CC64) ./src/2_com/CopyFile.c -o ./dst/CopyFile.x64.exe -masm=intel -lntdll -lole32 -lshell32 -lshlwapi -luuid

dst/CopyFileElevated.x64.exe:
	$(CC64) ./src/2_com/CopyFileElevated.c -o ./dst/CopyFileElevated.x64.exe -masm=intel -lntdll -lole32 -lshell32 -lshlwapi -luuid

dst/UACBypassCMSTPLUA.x64.exe:
	$(CC64) ./src/3_bypass/UACBypassCMSTPLUA.c -o ./dst/UACBypassCMSTPLUA.x64.exe -masm=intel -lntdll -lole32 -lshell32 -lshlwapi -luuid

clean:
	rm -f ./dst/*.exe