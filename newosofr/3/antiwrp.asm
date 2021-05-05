format pe gui 4.0
include 'include\win32ax.inc'

.data
loaderexe db 'drm.exe',0
wrpexe db 'drm_.exe',0
injlib db 'antiwrp.inj.dll',0
sr WIN32_FIND_DATA
pinfo PROCESS_INFORMATION
sinfo STARTUPINFO

.code
start:
        stdcall ExtractOrigWrapper,loaderexe,wrpexe
        .if eax=1
            invoke CreateProcessA,0,wrpexe,0,0,0,CREATE_SUSPENDED,0,0,sinfo,pinfo
            stdcall InjectLibA,injlib,[pinfo.dwProcessId],0
            .if eax=0
                invoke MessageBoxTimeoutA,0,'ERR',0,0,MB_OK,5000
            .endif
            invoke ResumeThread,[pinfo.hThread]
            invoke CloseHandle,[pinfo.hProcess]
            invoke CloseHandle,[pinfo.hThread]
        .endif
        invoke ExitProcess,0


proc ExtractOrigWrapper loaderPath,wrapperPath
        stdcall _FileIsExists,[loaderPath]
        .if eax<>0
            stdcall _FileIsExists,[wrapperPath]
            .if eax=0
                stdcall SaveResourceToFile,[loaderPath],[wrapperPath],1,8
                ret
            .else
                xor eax,eax
                inc eax
                ret
            .endif
        .endif
        xor eax,eax
        ret
endp

proc _FileIsExists path
        invoke GetFileAttributesA,[path]
        .if eax=-1
            xor eax,eax
        .else
            xor eax,eax
            inc eax
        .endif
        ret
endp

proc SaveResourceToFile srcFilePath,dstFilePath,name,type
        local hDstFile:DWORD
        local hResource:DWORD
        local hGlobal:DWORD
        local hMem:DWORD
        local hModule:DWORD
        local pResource:DWORD
        local sizeOfResource:DWORD
        local sizeOfFile:DWORD
        local numberOfBytes:DWORD

        invoke LoadLibraryA,[srcFilePath]
        .if eax<>0
            mov [hModule],eax
            invoke FindResourceA,[hModule],[name],[type]
             .if eax<>0
                 mov [hResource],eax
                 invoke LoadResource,[hModule],eax
                 .if eax<>0
                     mov [hGlobal],eax
                     invoke LockResource,[hGlobal]
                     .if eax<>0
                         mov [pResource],eax
                         invoke SizeofResource,[hModule],[hResource]
                         .if eax<>0
                             mov [sizeOfResource],eax
                             invoke CreateFile,[dstFilePath],GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
                             .if eax<>INVALID_HANDLE_VALUE
                                 mov [hDstFile],eax
                                 lea ecx,[numberOfBytes]
                                 invoke WriteFile,[hDstFile],[pResource],[sizeOfResource],ecx,0
                                 mov esi,eax
                                 invoke CloseHandle,[hDstFile]
                                 .if esi<>0
                                     xor eax,eax
                                     inc eax
                                     ret
                                 .endif
                             .endif
                         .endif
                     .endif
                 .endif
                 invoke FreeResource,[hGlobal]
             .endif
             invoke FreeLibrary,[hModule]
        .endif
        xor eax,eax
        ret
endp

proc InjectLibA libname,pid,curdir
        local hProcess:DWORD
        local mem:DWORD
        local size:DWORD
        local buff rb 512

        .if [curdir]=1
                lea eax,[buff]
                invoke GetCurrentDirectoryA,512,eax
                lea ecx,[buff]
                mov byte [eax+ecx],'\'
                invoke lstrcatA,ecx,[libname]
        .endif
        invoke OpenProcess,PROCESS_QUERY_INFORMATION + PROCESS_CREATE_THREAD+\
                           PROCESS_VM_OPERATION + PROCESS_VM_WRITE,0,[pid]
        test eax,eax
        je .err1
        mov [hProcess],eax
        .if [curdir]=1
                lea eax,[buff]
        .else
                mov eax,[libname]
        .endif
        invoke lstrlenA,eax
        inc eax
        mov [size],eax
        invoke VirtualAllocEx,[hProcess],0,eax,MEM_COMMIT,PAGE_READWRITE
        test eax,eax
        je .err2
        mov [mem],eax
        .if [curdir]=1
                lea ecx,[buff]
        .else
                mov ecx,[libname]
        .endif
        invoke WriteProcessMemory,[hProcess],eax,ecx,[size],0
        test eax,eax
        je .err3
        invoke GetModuleHandle,'kernel32.dll'
        invoke GetProcAddress,eax,'LoadLibraryA'
        test eax,eax
        je .err3
        invoke CreateRemoteThread,[hProcess],0,0,eax,[mem],0,0
        test eax,eax
        je .err3
        push eax
        invoke WaitForSingleObject,eax,-1
        pop eax
        invoke CloseHandle,eax
        invoke VirtualFreeEx,[hProcess],[mem],0,MEM_RELEASE
        invoke CloseHandle,[hProcess]
        xor eax,eax
        inc eax
        ret
       .err3:
        invoke VirtualFreeEx,[hProcess],[mem],0,MEM_RELEASE
       .err2:
        invoke CloseHandle,[hProcess]
       .err1:
        xor eax,eax
        ret
endp
.end start