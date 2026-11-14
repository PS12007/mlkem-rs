
mlkem::hazmat::keccak_f1600:
	jmp mlkem::hash::keccak::f1600

======================= Additional context =========================

mlkem::hash::keccak::f1600:
	push r15
	push r14
	push r13
	push r12
	push rsi
	push rdi
	push rbp
	push rbx
	sub rsp, 456
	mov rdi, rcx
	lea rcx, [rsp + 264]
	lea rdx, [rip + anon.bcdc364150e6b6d4e7eb0dd3f005f22e.59]
	mov r8d, 192
	call memcpy
	mov rax, qword ptr [rdi]
	mov qword ptr [rsp + 72], rax
	mov rax, qword ptr [rdi + 8]
	mov qword ptr [rsp + 120], rax
	mov rax, qword ptr [rdi + 40]
	mov qword ptr [rsp + 96], rax
	mov rdx, qword ptr [rdi + 80]
	mov rax, qword ptr [rdi + 120]
	mov rcx, qword ptr [rdi + 160]
	mov qword ptr [rsp + 160], rcx
	mov rcx, rdx
	mov rdx, qword ptr [rdi + 48]
	mov qword ptr [rsp + 144], rdx
	mov r10, qword ptr [rdi + 88]
	mov r9, qword ptr [rdi + 128]
	mov rdx, qword ptr [rdi + 168]
	mov qword ptr [rsp + 112], rdx
	mov rdx, qword ptr [rdi + 16]
	mov qword ptr [rsp + 128], rdx
	mov rdx, qword ptr [rdi + 56]
	mov qword ptr [rsp + 88], rdx
	mov r15, qword ptr [rdi + 96]
	mov rdx, qword ptr [rdi + 136]
	mov qword ptr [rsp + 80], rdx
	mov rdx, qword ptr [rdi + 176]
	mov qword ptr [rsp + 104], rdx
	mov r11, qword ptr [rdi + 24]
	mov rsi, qword ptr [rdi + 64]
	mov rbx, qword ptr [rdi + 104]
	mov r12, qword ptr [rdi + 144]
	mov rdx, qword ptr [rdi + 184]
	mov qword ptr [rsp + 152], rdx
	mov rdx, qword ptr [rdi + 32]
	mov qword ptr [rsp + 40], rdx
	mov r8, qword ptr [rdi + 72]
	mov qword ptr [rsp + 64], r8
	mov rbp, qword ptr [rdi + 112]
	mov rdx, qword ptr [rdi + 152]
	mov qword ptr [rsp + 208], rdi
	mov r8, qword ptr [rdi + 192]
	mov qword ptr [rsp + 56], r8
	mov rdi, r10
	mov r8d, 2
.LBB63_1:
	mov qword ptr [rsp + 136], rbp
	mov qword ptr [rsp + 192], rdi
	mov qword ptr [rsp + 200], rdx
	mov qword ptr [rsp + 240], r8
	mov r8, rdx
	xor r8, rbp
	mov r14, qword ptr [rsp + 64]
	xor r14, qword ptr [rsp + 40]
	xor r14, r8
	mov r10, qword ptr [rsp + 56]
	xor r10, r14
	mov r8, r12
	mov rbp, r12
	xor r8, rbx
	mov r14, rsi
	mov qword ptr [rsp + 48], r11
	xor r14, r11
	xor r14, r8
	mov r12, qword ptr [rsp + 144]
	mov r8, r12
	xor r8, qword ptr [rsp + 120]
	mov r13, rdi
	xor r13, r9
	xor r13, r8
	mov rdi, qword ptr [rsp + 104]
	xor rdi, qword ptr [rsp + 80]
	mov r8, r15
	xor r8, qword ptr [rsp + 88]
	xor r13, qword ptr [rsp + 112]
	mov rdx, r13
	rol rdx
	xor r8, rdi
	xor rdx, r10
	rol r10
	xor r8, qword ptr [rsp + 128]
	xor r10, r8
	xor qword ptr [rsp + 48], r10
	xor rsi, r10
	mov qword ptr [rsp + 216], rsi
	xor rbx, r10
	mov qword ptr [rsp + 232], rbx
	xor rbp, r10
	mov rbx, rbp
	mov rsi, qword ptr [rsp + 152]
	xor r10, rsi
	mov qword ptr [rsp + 184], r10
	xor rsi, r14
	mov rbp, qword ptr [rsp + 96]
	mov rdi, rbp
	mov r11, qword ptr [rsp + 40]
	mov r10, qword ptr [rsp + 72]
	xor rdi, r10
	mov r14, rcx
	xor r14, rax
	xor r14, rdi
	mov rdi, qword ptr [rsp + 160]
	xor r14, rdi
	xor r10, rdx
	mov qword ptr [rsp + 176], r10
	xor rbp, rdx
	mov qword ptr [rsp + 96], rbp
	xor rcx, rdx
	xor rax, rdx
	xor rdx, rdi
	mov qword ptr [rsp + 224], rdx
	rol r8
	xor r8, r14
	mov rdi, qword ptr [rsp + 120]
	xor rdi, r8
	xor r12, r8
	xor qword ptr [rsp + 192], r8
	xor r9, r8
	xor r8, qword ptr [rsp + 112]
	mov qword ptr [rsp + 168], r8
	rol r14
	xor r14, rsi
	mov r8, rsi
	rol r8
	xor r8, r13
	mov rsi, qword ptr [rsp + 128]
	xor rsi, r8
	xor qword ptr [rsp + 88], r8
	xor r15, r8
	xor qword ptr [rsp + 80], r8
	xor r8, qword ptr [rsp + 104]
	mov r13, r11
	xor r13, r14
	mov rdx, qword ptr [rsp + 64]
	xor rdx, r14
	mov r11, qword ptr [rsp + 136]
	xor r11, r14
	xor qword ptr [rsp + 200], r14
	rol r12, 44
	rol r15, 43
	rol rbx, 21
	xor r14, qword ptr [rsp + 56]
	rol r14, 14
	mov rbp, qword ptr [rsp + 48]
	rol rbp, 28
	rol rdx, 20
	mov qword ptr [rsp + 64], rdx
	rol r8, 61
	mov qword ptr [rsp + 136], rdi
	mov qword ptr [rsp + 48], r13
	mov rdi, rsi
	rol rdi, 62
	mov rdx, r12
	not rdx
	and rdx, r15
	mov qword ptr [rsp + 72], rdx
	mov qword ptr [rsp + 40], rbx
	mov r10, rbx
	not r10
	and r10, r14
	xor r10, r15
	mov qword ptr [rsp + 128], r10
	not r15
	and r15, rbx
	xor r15, r12
	mov qword ptr [rsp + 120], r15
	mov r13, qword ptr [rsp + 176]
	not r13
	and r13, r12
	mov rdx, qword ptr [rsp + 216]
	rol rdx, 55
	rol r11, 39
	mov rbx, rax
	rol rbx, 41
	mov rax, qword ptr [rsp + 168]
	rol rax, 2
	mov rsi, rdx
	not rsi
	and rsi, r11
	xor rsi, rdi
	mov qword ptr [rsp + 160], rsi
	mov rsi, rbx
	not rsi
	mov qword ptr [rsp + 168], rax
	and rsi, rax
	xor rsi, r11
	mov qword ptr [rsp + 104], rsi
	not r11
	and r11, rbx
	xor r11, rdx
	mov qword ptr [rsp + 112], r11
	not rax
	and rax, rdi
	not rdi
	and rdi, rdx
	mov qword ptr [rsp + 56], rdi
	mov r10, qword ptr [rsp + 96]
	rol r9, 45
	rol rcx, 3
	mov rdi, qword ptr [rsp + 64]
	mov rdx, rdi
	not rdx
	and rdx, rcx
	xor rdx, rbp
	mov qword ptr [rsp + 96], rdx
	mov rdx, rcx
	not rdx
	and rdx, r9
	xor rdx, rdi
	mov qword ptr [rsp + 144], rdx
	mov rsi, r8
	not rsi
	and rsi, rbp
	not rbp
	and rdi, rbp
	mov r15, rdi
	mov r11, r14
	not r11
	and r11, qword ptr [rsp + 176]
	xor r11, qword ptr [rsp + 40]
	xor r13, r14
	mov qword ptr [rsp + 40], r13
	mov rdx, qword ptr [rsp + 88]
	mov rdi, r9
	not rdi
	and rdi, r8
	xor rdi, rcx
	mov qword ptr [rsp + 88], rdi
	xor rsi, r9
	xor r15, r8
	mov qword ptr [rsp + 64], r15
	xor rax, rbx
	mov qword ptr [rsp + 152], rax
	mov rbx, qword ptr [rsp + 48]
	rol rbx, 27
	mov qword ptr [rsp + 48], rbx
	rol r10, 36
	mov r8, qword ptr [rsp + 192]
	rol r8, 10
	mov rdi, qword ptr [rsp + 80]
	rol rdi, 15
	mov rcx, qword ptr [rsp + 184]
	rol rcx, 56
	mov qword ptr [rsp + 184], rcx
	mov r13, r10
	not r13
	and r13, r8
	mov r9, r8
	not r9
	and r9, rdi
	mov rax, rcx
	not rax
	and rax, rbx
	xor rax, rdi
	not rdi
	and rdi, rcx
	xor rdi, r8
	mov r8, qword ptr [rsp + 240]
	mov qword ptr [rsp + 80], rdi
	mov rbp, qword ptr [rsp + 136]
	rol rbp
	rol rdx, 6
	mov rbx, qword ptr [rsp + 232]
	rol rbx, 25
	mov rcx, qword ptr [rsp + 200]
	rol rcx, 8
	mov r12, qword ptr [rsp + 224]
	rol r12, 18
	mov r14, rdx
	not r14
	and r14, rbx
	mov r15, rcx
	not r15
	and r15, r12
	xor r15, rbx
	mov rdi, rbx
	not rdi
	and rdi, rcx
	mov rbx, r12
	not rbx
	and rbx, rbp
	xor rbx, rcx
	mov rcx, r14
	xor rcx, rbp
	xor rdi, rdx
	not rbp
	and rbp, rdx
	xor rbp, r12
	mov r12, rax
	mov rax, r13
	mov rdx, qword ptr [rsp + 48]
	xor rax, rdx
	xor r9, r10
	not rdx
	and rdx, r10
	xor rdx, qword ptr [rsp + 184]
	mov r10, qword ptr [rsp + 72]
	xor r10, qword ptr [rsp + 8*r8 + 248]
	mov r13, qword ptr [rsp + 56]
	xor r13, qword ptr [rsp + 168]
	mov qword ptr [rsp + 56], r13
	xor r10, qword ptr [rsp + 176]
	mov qword ptr [rsp + 72], r10
	inc r8
	cmp r8, 26
	jne .LBB63_1
	mov r8, qword ptr [rsp + 208]
	mov qword ptr [r8 + 120], rax
	mov rax, qword ptr [rsp + 88]
	mov qword ptr [r8 + 56], rax
	mov qword ptr [r8 + 96], r15
	mov rax, qword ptr [rsp + 80]
	mov qword ptr [r8 + 136], rax
	mov rax, qword ptr [rsp + 104]
	mov qword ptr [r8 + 176], rax
	mov qword ptr [r8 + 24], r11
	mov qword ptr [r8 + 64], rsi
	mov qword ptr [r8 + 104], rbx
	mov qword ptr [r8 + 144], r12
	mov rax, qword ptr [rsp + 152]
	mov qword ptr [r8 + 184], rax
	mov rax, qword ptr [rsp + 40]
	mov qword ptr [r8 + 32], rax
	mov rax, qword ptr [rsp + 64]
	mov qword ptr [r8 + 72], rax
	mov qword ptr [r8 + 112], rbp
	mov qword ptr [r8 + 152], rdx
	mov rax, qword ptr [rsp + 56]
	mov qword ptr [r8 + 192], rax
	mov rax, qword ptr [rsp + 120]
	mov qword ptr [r8 + 8], rax
	mov rax, qword ptr [rsp + 128]
	mov qword ptr [r8 + 16], rax
	mov rax, qword ptr [rsp + 96]
	mov qword ptr [r8 + 40], rax
	mov rax, qword ptr [rsp + 144]
	mov qword ptr [r8 + 48], rax
	mov qword ptr [r8 + 80], rcx
	mov qword ptr [r8 + 88], rdi
	mov qword ptr [r8 + 128], r9
	mov rax, qword ptr [rsp + 160]
	mov qword ptr [r8 + 160], rax
	mov rax, qword ptr [rsp + 112]
	mov qword ptr [r8 + 168], rax
	mov rax, qword ptr [rsp + 72]
	mov qword ptr [r8], rax
	add rsp, 456
	pop rbx
	pop rbp
	pop rdi
	pop rsi
	pop r12
	pop r13
	pop r14
	pop r15
	ret
