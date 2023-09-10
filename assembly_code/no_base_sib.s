[BITS 32]

xor dword [  edi*1 +  0x33333333 ], edi
xor dword [  edi*2 +  0x33333333 ], edi
xor dword [  edi*4 +  0x33333333 ], edi
xor dword [  edi*8 +  0x33333333 ], edi
xor dword [  edi*1 +  0x33 ], edi
xor dword [  edi*2 +  0x33 ], edi
xor dword [  edi*4 +  0x33 ], edi
xor dword [  edi*8 +  0x33 ], edi
xor dword [  edi*1 ], edi
xor dword [  edi*2 ], edi
xor dword [  edi*4 ], edi
xor dword [  edi*8 ], edi