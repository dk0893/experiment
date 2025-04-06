pwndbg> disassemble 
Dump of assembler code for function check:
   0x0000000000401156 <+0>:	push   rbp
   0x0000000000401157 <+1>:	mov    rbp,rsp
   0x000000000040115a <+4>:	push   rbx
   0x000000000040115b <+5>:	sub    rsp,0x58
   0x000000000040115f <+9>:	mov    QWORD PTR [rbp-0x58],rdi
   0x0000000000401163 <+13>:	mov    rax,QWORD PTR [rbp-0x58]
   0x0000000000401167 <+17>:	mov    rdi,rax
   0x000000000040116a <+20>:	call   0x401040 <strlen@plt>
   0x000000000040116f <+25>:	cmp    rax,0x1b
   0x0000000000401173 <+29>:	je     0x40117f <check+41>
   0x0000000000401175 <+31>:	mov    eax,0x1
   0x000000000040117a <+36>:	jmp    0x40129f <check+329>
   0x000000000040117f <+41>:	movabs rax,0x617b2375f81ea7e1
   0x0000000000401189 <+51>:	movabs rdx,0xd269df5b5afc9db9
   0x0000000000401193 <+61>:	mov    QWORD PTR [rbp-0x50],rax
   0x0000000000401197 <+65>:	mov    QWORD PTR [rbp-0x48],rdx
   0x000000000040119b <+69>:	movabs rax,0xf467edf4ed1bfed2
   0x00000000004011a5 <+79>:	mov    QWORD PTR [rbp-0x41],rax
   0x00000000004011a9 <+83>:	mov    DWORD PTR [rbp-0x14],0x0
   0x00000000004011b0 <+90>:	mov    DWORD PTR [rbp-0x18],0x0
   0x00000000004011b7 <+97>:	mov    DWORD PTR [rbp-0x24],0x0
   0x00000000004011be <+104>:	mov    DWORD PTR [rbp-0x1c],0x0
   0x00000000004011c5 <+111>:	jmp    0x40128e <check+312>
   0x00000000004011ca <+116>:	mov    DWORD PTR [rbp-0x20],0x0
   0x00000000004011d1 <+123>:	jmp    0x401280 <check+298>
   0x00000000004011d6 <+128>:	cmp    DWORD PTR [rbp-0x18],0x0
   0x00000000004011da <+132>:	jne    0x4011e0 <check+138>
   0x00000000004011dc <+134>:	add    DWORD PTR [rbp-0x18],0x1
   0x00000000004011e0 <+138>:	mov    eax,0x7
   0x00000000004011e5 <+143>:	sub    eax,DWORD PTR [rbp-0x20]
   0x00000000004011e8 <+146>:	mov    edx,0x1
   0x00000000004011ed <+151>:	mov    ecx,eax
   0x00000000004011ef <+153>:	shl    edx,cl
   0x00000000004011f1 <+155>:	mov    eax,edx
   0x00000000004011f3 <+157>:	mov    DWORD PTR [rbp-0x28],eax
   0x00000000004011f6 <+160>:	mov    eax,0x7
   0x00000000004011fb <+165>:	sub    eax,DWORD PTR [rbp-0x18]
   0x00000000004011fe <+168>:	mov    edx,0x1
   0x0000000000401203 <+173>:	mov    ecx,eax
   0x0000000000401205 <+175>:	shl    edx,cl
   0x0000000000401207 <+177>:	mov    eax,edx
   0x0000000000401209 <+179>:	mov    DWORD PTR [rbp-0x2c],eax
   0x000000000040120c <+182>:	mov    eax,DWORD PTR [rbp-0x1c]
   0x000000000040120f <+185>:	cdqe
   0x0000000000401211 <+187>:	movzx  eax,BYTE PTR [rbp+rax*1-0x50]
   0x0000000000401216 <+192>:	movsx  eax,al
   0x0000000000401219 <+195>:	and    eax,DWORD PTR [rbp-0x28]
   0x000000000040121c <+198>:	test   eax,eax
   0x000000000040121e <+200>:	setg   cl
   0x0000000000401221 <+203>:	mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000401224 <+206>:	movsxd rdx,eax
   0x0000000000401227 <+209>:	mov    rax,QWORD PTR [rbp-0x58]
   0x000000000040122b <+213>:	add    rax,rdx
   0x000000000040122e <+216>:	movzx  eax,BYTE PTR [rax]
   0x0000000000401231 <+219>:	movsx  eax,al
   0x0000000000401234 <+222>:	and    eax,DWORD PTR [rbp-0x2c]
   0x0000000000401237 <+225>:	test   eax,eax
   0x0000000000401239 <+227>:	setg   al
   0x000000000040123c <+230>:	xor    eax,ecx
   0x000000000040123e <+232>:	test   al,al
=> 0x0000000000401240 <+234>:	je     0x401249 <check+243>
   0x0000000000401242 <+236>:	mov    eax,0x1
   0x0000000000401247 <+241>:	jmp    0x40129f <check+329>
   0x0000000000401249 <+243>:	add    DWORD PTR [rbp-0x18],0x1
   0x000000000040124d <+247>:	cmp    DWORD PTR [rbp-0x18],0x8
   0x0000000000401251 <+251>:	jne    0x40125e <check+264>
   0x0000000000401253 <+253>:	mov    DWORD PTR [rbp-0x18],0x0
   0x000000000040125a <+260>:	add    DWORD PTR [rbp-0x14],0x1
   0x000000000040125e <+264>:	mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000401261 <+267>:	movsxd rbx,eax
   0x0000000000401264 <+270>:	mov    rax,QWORD PTR [rbp-0x58]
   0x0000000000401268 <+274>:	mov    rdi,rax
   0x000000000040126b <+277>:	call   0x401040 <strlen@plt>
   0x0000000000401270 <+282>:	cmp    rbx,rax
   0x0000000000401273 <+285>:	jne    0x40127c <check+294>
   0x0000000000401275 <+287>:	mov    eax,0x0
   0x000000000040127a <+292>:	jmp    0x40129f <check+329>
   0x000000000040127c <+294>:	add    DWORD PTR [rbp-0x20],0x1
   0x0000000000401280 <+298>:	cmp    DWORD PTR [rbp-0x20],0x7
   0x0000000000401284 <+302>:	jle    0x4011d6 <check+128>
   0x000000000040128a <+308>:	add    DWORD PTR [rbp-0x1c],0x1
   0x000000000040128e <+312>:	mov    eax,DWORD PTR [rbp-0x1c]
   0x0000000000401291 <+315>:	cmp    eax,0x16
   0x0000000000401294 <+318>:	jbe    0x4011ca <check+116>
   0x000000000040129a <+324>:	mov    eax,0x0
   0x000000000040129f <+329>:	mov    rbx,QWORD PTR [rbp-0x8]
   0x00000000004012a3 <+333>:	leave
   0x00000000004012a4 <+334>:	ret
End of assembler dump.
