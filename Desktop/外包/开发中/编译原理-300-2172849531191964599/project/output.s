sub esp, 4
mov dword ptr [ebp-4], 0
add eax, 0
mov [c], 0
mov eax, 0
.global add10
add10:
push ebp
mov ebp, esp
pop ebp
ret
