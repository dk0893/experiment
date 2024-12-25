import gdb

gdb.execute( 'break *0x4006f7' )
gdb.execute( 'run' )

password = ''

for ii in range( 10 ):
    
    al = gdb.parse_and_eval( '$al' )
    password += chr( al )
    
    gdb.execute( f'set $bl = {al}' )
    gdb.execute( 'continue' )

print( "=" * 10 )
print( password )
print( "=" * 10 )
