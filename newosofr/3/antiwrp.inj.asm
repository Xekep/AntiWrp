format pe gui 4.0 dll
include 'include\win32ax.inc'

IMAGE_DIRECTORY_ENTRY_IMPORT = 1

struct  IMAGE_IMPORT_DESCRIPTOR
    OriginalFirstThunk  dd  ?
    TimeDateStamp       dd  ?
    ForwarderChain      dd  ?
    Name                dd  ?
    FirstThunk          dd  ?
ends

.data
WaitForSingleObject_ dd ?
hmodCaller dd ?
ImageDirectoryEntryToData dd ?
hProcess dd 0
CreateProcessW_ dd ?
CreateWindowExW_ dd ?
QueryPerformanceCounter_ dd ?
Process32FirstW_ dd ?
pkernel32 dd ?
.code

proc start hinstDLL,fdwReason,lpvReserved
        cmp [fdwReason],DLL_PROCESS_ATTACH
        jne .exit
        invoke GetModuleHandleA,0;drm
        mov [hmodCaller],eax
        ;invoke MessageBoxA,0,"Снят лимит на время","Cracked",MB_OK+MB_ICONINFORMATION
        invoke LoadLibrary,'imagehlp.dll'
        invoke GetProcAddress,eax,'ImageDirectoryEntryToData'
        mov [ImageDirectoryEntryToData],eax
        invoke GetModuleHandleA,'KERNEL32.DLL'
        mov [pkernel32],eax
        invoke GetProcAddress,eax,'WaitForSingleObject'
        test eax,eax
        je @f
        mov [WaitForSingleObject_],eax
        stdcall ReplaceIATEntryInOneMod,'KERNEL32.DLL',eax,_WaitForSingleObject,[hmodCaller]
        @@:
        ;
        invoke GetProcAddress,[pkernel32],'CreateProcessW'
        test eax,eax
        je @f
        mov [CreateProcessW_],eax
        stdcall ReplaceIATEntryInOneMod,'KERNEL32.DLL',eax,_CreateProcessW,[hmodCaller]
        @@:
        ;
        invoke GetModuleHandleA,'USER32.DLL'
        invoke GetProcAddress,eax,'CreateWindowExW'
        test eax,eax
        je @f
        mov [CreateWindowExW_],eax
        stdcall ReplaceIATEntryInOneMod,'USER32.DLL',eax,_CreateWindowExW,[hmodCaller]
        @@:
        ;
        invoke GetProcAddress,[pkernel32],'QueryPerformanceCounter'
        test eax,eax
        je @f
        mov [QueryPerformanceCounter_],eax
        stdcall ReplaceIATEntryInOneMod,'KERNEL32.DLL',[QueryPerformanceCounter_],_QueryPerformanceCounter,[hmodCaller]
        @@:
        ; Чтобы не DRM не мог убить родительский процесс
        invoke GetModuleHandleA,'KERNEL32.DLL'
        invoke GetProcAddress,eax,'Process32FirstW'
        test eax,eax
        je @f
        mov [Process32FirstW_],eax
        stdcall ReplaceIATEntryInOneMod,'KERNEL32.DLL',[Process32FirstW_],_Process32FirstW,[hmodCaller]
        @@:
        stdcall Patch,[hmodCaller]
        .exit:
        ret
endp

proc Patch hMod
        local offsetOfSection:DWORD
        local sizeOfSection:DWORD
        local oldProtect:DWORD
        local numOfSections:DWORD
        ;0x0CB1AE5 | 81F1 BE77C14A         | xor ecx,0x4AC177BE   | xor ecx,ebx
        ;0x0CB1AEB | 83F2 0C               | xor edx,C            | xor edx,edx
        ; 81 ?? BE 77 C1 4A 83 ?? 0C
        ; Поиск первой секции text
        ; https://habr.com/ru/post/266831/
        mov eax,[hMod]
        mov edi,eax
        add eax,[eax+3Ch] ; PE Header
        movsx ecx,word [eax+6] ; IMAGE_FILE_HEADER.NumberOfSections
        mov [numOfSections],ecx
        ; offset PE Header + sizeof.FileHeader + sizeof.OptionalHeader + = IMAGE_SECTION_HEADER
        lea eax,[eax+0F8h]
       .fnd:
        cmp dword [eax+1],'text' ; IMAGE_SECTION_HEADER.Name
        je .begin_patch
        add eax,28h
        loop .fnd
        jmp .end_patch
       .begin_patch:
        mov ecx,[eax+0Ch] ; IMAGE_SECTION_HEADER.VirtualAddress
        add ecx,edi
        mov [offsetOfSection],ecx
        mov ecx,[eax+8] ; IMAGE_SECTION_HEADER.VirtualSize
        mov [sizeOfSection],ecx
        lea eax,[oldProtect]
        invoke VirtualProtect,[offsetOfSection],[sizeOfSection],PAGE_EXECUTE_READWRITE,eax
        ; Поиск сигнатуры
        mov ecx,[sizeOfSection]
        mov eax,[offsetOfSection]
       .loop:
        cmp dword [eax],77BEF181h
        jne .end_loop
        cmp dword [eax+4],0F2834AC1h
        jne .end_loop
        ; Патчинг
        push esi
        call @f
       .code_begin:
        xor ecx,ebx
        xor edx,edx
        nop
        nop
        nop
        nop
        nop
       .code_end:
        @@:
        pop esi
        mov esi,.code_begin
        lea edi,[eax]
        mov ecx,.code_end-.code_begin
        rep movsb
        pop esi
        jmp .end_patch
       .end_loop:
        inc eax
        loop .loop
       .end_patch:
        ret
endp

proc _QueryPerformanceCounter lpPerformanceCount
        xor eax,eax
        ret
endp

proc _CreateWindowExW ExStyle,Class,WindowName,Style,x,y,Width,Height,hParent,\
                      hMenu,hInst,lParam

        .if [Width]=800 & [Height]=600
                xor eax,eax
                jmp @f
        .endif
        stdcall [CreateWindowExW_],[ExStyle],[Class],[WindowName],[Style],[x],[y],[Width],\
                                   [Height],[hParent],[hMenu],[hInst],[lParam]
        @@:
        ret
endp

proc _CreateProcessW lpApplicationName,lpCommandLine,lpProcessAttributes,\
                     lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,\
                     lpCurrentDirectory,lpStartupInfo,lpProcessInformation

        stdcall [CreateProcessW_],[lpApplicationName],[lpCommandLine],[lpProcessAttributes],\
                     [lpThreadAttributes],[bInheritHandles],[dwCreationFlags],[lpEnvironment],\
                     [lpCurrentDirectory],[lpStartupInfo],[lpProcessInformation]
        invoke lstrlenW,[lpApplicationName]
        lea eax,[eax*2]
        sub eax,8
        add eax,[lpApplicationName]
        call @f
        du '.exe',0
        @@:
        invoke lstrcmpiW,eax
        .if eax=0
                mov eax,[lpProcessInformation]
                mov eax,[eax+PROCESS_INFORMATION.hProcess]
                mov [hProcess],eax
        .else
                mov eax,[lpProcessInformation]
                mov eax,[eax+PROCESS_INFORMATION.hProcess]
        .endif
        ret
endp

proc _WaitForSingleObject hObject,dwTimeout
        mov eax,[hProcess]
        .if [hObject]=eax
                stdcall [WaitForSingleObject_],[hObject],-1
        .else
                stdcall [WaitForSingleObject_],[hObject],[dwTimeout]
        .endif
        ret
endp

proc _Process32FirstW hSnapshot,lppe
        xor eax,eax
        ret
endp

proc ReplaceIATEntryInOneMod pszCalleeModName,pfnCurrent,pfnNew,hmodCaller
        local pImportDesc:DWORD
        local ulSize:DWORD

        ; Получение указателя на секцию импорта
        lea eax,[ulSize]
        invoke ImageDirectoryEntryToData,[hmodCaller],TRUE,IMAGE_DIRECTORY_ENTRY_IMPORT,eax
        test eax,eax
        je .err1
        mov [pImportDesc],eax
        ; Получение указателя на секцию импорта у нужной библиотеки
        @@:
        mov eax,[pImportDesc]
        mov eax,[eax+IMAGE_IMPORT_DESCRIPTOR.Name]
        add eax,[hmodCaller]
        test eax,eax
        je .err1
        invoke lstrcmpiA,eax,[pszCalleeModName]
        test eax,eax
        je .end1
        add [pImportDesc],sizeof.IMAGE_IMPORT_DESCRIPTOR
        jmp @b
      .end1:
        ; Получение указателя на нужную функцию и его подмена
        mov eax,[pImportDesc]
        mov eax,[eax+IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
        add eax,[hmodCaller]
        mov ecx,[pfnCurrent]
        @@:
        cmp dword [eax],0
        je .err1
        cmp ecx,[eax]
        jne .end2
        pushad
        lea ecx,[ulSize]
        invoke VirtualProtect,eax,4,PAGE_EXECUTE_READWRITE,ecx
        popad
        mov ecx,[pfnNew]
        mov [eax],ecx
        jmp @f
      .end2:
        add eax,4
        jmp @b
        @@:
        xor eax,eax
        inc eax
        ret
     .err1:
        xor eax,eax
        ret
endp
.end start
section '.reloc' fixups data discardable readable