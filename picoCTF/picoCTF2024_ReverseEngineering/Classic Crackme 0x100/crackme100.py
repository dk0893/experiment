import os, sys

output = "kgxmwpbpuqtorzapjhfmebmccvwycyvewpxiheifvnuqsrgexl"

ret = []
for i_1, out in enumerate(output):
    
    tmps = [ aa for aa in range(0x21, 0x7f) ]
    #print( tmps )
    
    flag = False
    for tmp in tmps:
        input = tmp
        for ii in range(3):
            
            uVar1 = ((((i_1 % 0xff) >> 1)) & 0x55) + ((i_1 % 0xff) & 0x55)
            uVar1 = ((uVar1 >> 2) & 0x33) + (uVar1 & 0x33)
            iVar2 = (uVar1 >> 4) + input - 0x61 + (uVar1 & 0xf)
            input = (iVar2 & 0xff) - ((iVar2 // 0x1a) & 0xff) * (0x1a) + 0x61
        
        #print( f"out={out}, ord(out)={ord(out)}" )
        
        if input == ord( out ):
            ret.append( chr(tmp) )
            flag = True
            break
    
    assert flag, f"fail, ret={ret}"

print( f"ret={''.join(ret)}" )
