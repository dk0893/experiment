def main():
    
    password = "abcdefghijklmnopqrstuvwxyz"
    
    lst = [ 0xe1, 0xa7, 0x1e, 0xf8, 0x75, 0x23, 0x7b, 0x61, 0xb9, 0x9d, 0xfc, 0x5a, 0x5b, 0xdf, 0x69, 0xd2, 0xfe, 0x1b, 0xed, 0xf4, 0xed, 0x67, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00 ]
    ret = [ 0 ] * 27
    
    l_1c = 0
    l_20 = 0
    for l_24 in range( 23 ):
        for l_28 in range( 8 ):
            
            if l_20 == 0:
                l_20 = 1
            
            l_30 = 1 << ( (7 - l_28) & 0x1F )
            l_34 = 1 << ( (7 - l_20) & 0x1F )
            
            #if (0 < ord(password[l_1c]) & l_34) != (0 < (lst[l_24] & l_30)):
            #    print( "failure" )
            
            if (lst[l_24] & l_30) != 0:
                ret[l_1c] |= l_34
            
            print( f"ii={l_24:2d}, jj={l_28}: l_30=0x{l_30:02X}, l_34=0x{l_34:02X}, l_20={l_20}, l_1c={l_1c}" )
            
            l_20 += 1
            if l_20 == 8:
                l_20 = 0
                l_1c += 1
            
            if l_1c == 27:
                print( "success" )
    
    ret = [ chr(ii) for ii in ret ]
    ret = "".join( ret )
    print( ret )

if __name__ == "__main__":
    main()
