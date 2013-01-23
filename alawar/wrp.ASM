format pe gui 4.0
include '%fasm_inc%\win32ax.inc'
.data
title_err db 'Something wrong',0
mess_err1 db 'Не удаётся найти игру!',0
mess_err2 db 'Программа выполнила недопустимую ошибку и будет закрыта!',0
file_wrp db '*.wrp.exe',0

sr WIN32_FIND_DATA
pinfo PROCESS_INFORMATION
sinfo STARTUPINFO
bytes dd 606Ah
lpflOldProtec dd ?
buffer rb 200h
OEP dd ?

.code
start:
	invoke MessageBoxTimeoutA,0,'Coded by Xekep [ICQ: 667-416]','Crack for Alawar games',MB_ICONINFORMATION+MB_OK,0,2000
	invoke FindFirstFileA,file_wrp,sr
	.if eax=-1
		push mess_err1
		jmp err!
	.endif
	invoke CreateFileA,sr.cFileName,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if eax=-1
		push mess_err2
		jmp err!
	.endif
	push eax
	invoke GetFileSize,eax,0
	.if eax=0
		push mess_err2
		jmp err!
	.endif
	invoke ReadFile,dword [esp+16],buffer,200h,0,lpflOldProtec
	.if eax=0
		invoke CloseHandle,dword [esp]
		push mess_err2
		jmp err!
	.endif
	invoke CloseHandle,dword [esp]
	mov eax,buffer
	xor esi,esi
       metka1:
	cmp word [eax+esi],'PE'
	jne metka2
	jmp metka3
       metka2:
	inc esi
	cmp esi,200h
	jc metka1
	push mess_err2
	jmp err!
       metka3:
	mov ecx,dword [eax+esi+40]
	mov [OEP],ecx
	mov ecx,dword [eax+esi+52]
	add [OEP],ecx
	invoke GetCurrentDirectoryA,MAX_PATH,buffer
	invoke CreateProcessA,0,sr.cFileName,0,0,0,CREATE_SUSPENDED,0,buffer,sinfo,pinfo
	.if eax=0
		push mess_err2
		jmp err!
	.endif
	invoke VirtualProtectEx,[pinfo.hProcess],[OEP],2,PAGE_EXECUTE_READWRITE,lpflOldProtec
	.if eax=0
		invoke TerminateProcess,[pinfo.hProcess],0
		push mess_err2
		jmp err!
	.endif
	invoke WriteProcessMemory,[pinfo.hProcess],[OEP],bytes,2,lpflOldProtec
	.if eax=0
		invoke TerminateProcess,[pinfo.hProcess],0
		push mess_err2
		jmp err!
	.endif
	invoke FlushInstructionCache,[pinfo.hProcess],[OEP],2
	.if eax=0
		invoke TerminateProcess,[pinfo.hProcess],0
		push mess_err2
		jmp err!
	.endif
	invoke ResumeThread,[pinfo.hThread]
	.if eax=-1
		invoke TerminateProcess,[pinfo.hProcess],0
		push mess_err2
		jmp err!
	.endif
	invoke CloseHandle,[pinfo.hThread]
	invoke CloseHandle,[pinfo.hProcess]
      exit:
	invoke ExitProcess,0
   err!:
	invoke MessageBoxA,0,dword [esp+8],title_err,MB_ICONWARNING+MB_OK
	jmp exit
.end start