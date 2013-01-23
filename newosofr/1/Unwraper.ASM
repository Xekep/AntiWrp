format PE GUI 4.0

include '%fasm_inc%\win32ax.inc'

MAXSIZE = 512

.data

_message3 db 'Success!',0
_caption3 db 'Cool!',0
_message  db 'ERROR',0
_access db 'File access error!',0
_size db 'File size error!',0
_read db 'File read error!',0
_mem db 'Memory allocation error!',0
_executable db 'Invalid executable file!',0
un db 'Unsupported version.',0
FilterString db 'Game EXE file',0,'*.exe',0,'all files',0,'*.*',0
title db 'Static Nevosoft UnWrapper. Coded by Xekep. ICQ: 667-416 [10.06.2010]',0
ofn OPENFILENAME
buffer rb MAXSIZE
modulehandle dd ?
handle dd ?
size dd ?
mem_alloc dd ?
offset_ dd ?

.code

start:
	invoke GetCommandLineA
  cycle_one:
	.if byte [eax]=0
		jmp start_two
	.elseif word [eax]=2022h
		.if byte [eax+2]=22h
			add eax,3
			push 3
			jmp start_two2
		.elseif byte [eax+2]>0
			add eax,2
			push 2
		    start_two2:
			mov esi,eax
			invoke lstrlen,eax
			.if dword [esp]=3
				mov byte [eax+esi-1],0
			.endif
			add esp,4
			mov [ofn.lpstrFile],esi
			jmp file_
		.endif
	.else
		inc eax
		jmp cycle_one

	.endif
     start_two:
	mov [ofn.lStructSize],sizeof.OPENFILENAME
	mov [ofn.lpstrTitle],title
	mov [ofn.lpstrFilter],FilterString
	mov [ofn.lpstrFile],buffer
	mov [ofn.nMaxFile],MAXSIZE
	mov [ofn.Flags],OFN_FILEMUSTEXIST + OFN_PATHMUSTEXIST + OFN_LONGNAMES \
			+ OFN_EXPLORER + OFN_HIDEREADONLY
	invoke GetOpenFileName,ofn
	or eax,eax
	je exit
      file_:
	invoke CreateFileA,[ofn.lpstrFile],GENERIC_READ+GENERIC_WRITE,FILE_SHARE_READ+FILE_SHARE_WRITE,\
			   0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	cmp eax,-1
	je access
	mov [handle],eax
	invoke GetFileSize,[handle],0
	or eax,eax
	je file_size
	MOV [size],EAX
	mov esi,eax
	invoke	GlobalAlloc,GPTR,eax
	or eax,eax
	je error_mem
	mov [mem_alloc],eax
	add esi,eax
	invoke ReadFile,[handle],[mem_alloc],[size],ofn,0
	test eax,eax
	je error_read
	mov eax,[mem_alloc]
	cmp word [eax],'MZ'
	jne ver
	add eax,1000h
	mov [offset_],eax
	xor eax,eax
	mov ebx,[mem_alloc]
	add ebx,3Ch
	mov eax,[ebx]
	sub ebx,3Ch
	;add eax,6 - кол во секций
	add eax,14h
	add ebx,eax
	mov ax,word [ebx]
	sub ebx,14h
	add eax,18h
	add ebx,eax
	;;mov ebx, .text
	xor eax,eax
	mov edi,dword [ebx+10h];99000h   ;Размер Raw секции text
      xor!:
	mov edx,dword [ebx+14h];1000h    ;Raw offset
	mov ecx,[mem_alloc]
	;add ecx,99C00h
	add ecx,edi
	add ecx,9CCh;0C00h
	;
	add edx,eax
	and edx,3FFh
	mov dl,byte [edx+ecx]
	mov ecx,[mem_alloc]
	add ecx,dword [ebx+14h]
	xor byte [eax+ecx],dl
	inc eax
	cmp eax,edi
	jl xor!
	jmp crack
  exit:
	invoke	ExitProcess,0

crack:
	invoke CloseHandle,[handle]
	xor bl,bl
	mov eax,[ofn.lpstrFile]
     wrp_:
	inc eax
	cmp byte [eax],bl
	jne wrp_
	sub eax,3
	mov byte [eax],65h   ;e
	mov byte [eax+1],78h ;x
	mov byte [eax+2],65h ;e
	invoke DeleteFileA,[ofn.lpstrFile]
	invoke CreateFileA,[ofn.lpstrFile],GENERIC_READ+GENERIC_WRITE,FILE_SHARE_READ+FILE_SHARE_WRITE,\
			   0,OPEN_EXISTING+CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
	cmp eax,-1
	je access
	mov [handle],eax
	invoke WriteFile,[handle],[mem_alloc],[size],ofn,0
	invoke CloseHandle,[handle]
	invoke GlobalFree,[mem_alloc]
	jmp  finish!
finish!:
	invoke	      MessageBoxA,0,_message3,_caption3,MB_ICONINFORMATION,MB_OK
	jmp  exit
access:
	invoke CloseHandle,[handle]
	invoke	      MessageBoxA,0,_access,_message,MB_ICONERROR,MB_OK       ;Сообщение File access error!
	jmp  exit
file_size:
	invoke CloseHandle,[handle]
	invoke	      MessageBoxA,0,_size,_message,MB_ICONERROR,MB_OK	      ;Сообщение File size error!
	jmp  exit
error_read:
	invoke CloseHandle,[handle]
	invoke GlobalFree,[mem_alloc]
	invoke	      MessageBoxA,0,_read,_message,MB_ICONERROR,MB_OK	      ;Сообщение File read error!
	jmp  exit
error_mem:
	invoke CloseHandle,[handle]
	invoke	      MessageBoxA,0,_mem,_message,MB_ICONERROR,MB_OK	      ;Сообщение Memory allocation error!
	jmp  exit
ver:
	invoke CloseHandle,[handle]
	invoke GlobalFree,[mem_alloc]
	invoke	      MessageBoxA,0,un,_message,MB_ICONERROR,MB_OK	      ;Сообщение Unsupported version!
	jmp  exit
retn
.end start
section '.rsrc' resource data readable
;data resource

  directory   RT_VERSION,versions;,\
;              RT_ICON,icons,\
;              RT_GROUP_ICON,group_icons


;  resource icons,\
;           1,LANG_NEUTRAL,icon_data

;  resource group_icons,\
;           17,LANG_NEUTRAL,main_icon

  resource versions,\
	   1,LANG_NEUTRAL,version

;   icon main_icon,icon_data,'Crack.ico'

  versioninfo version,VOS__WINDOWS32,VFT_APP,VFT2_UNKNOWN,LANG_ENGLISH+SUBLANG_DEFAULT,0,\
	      'FileDescription','Crack For Nevosoft v1.0',\
	      'LegalCopyright','All rights reserved.',\
	      'FileVersion','1.0',\
	      'ProductVersion','Privat Release',\
	      'OriginalFilename','Unwraper.EXE'
;end data