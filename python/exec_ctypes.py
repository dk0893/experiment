import ctypes

libc = ctypes.cdll.LoadLibrary( '/lib/x86_64-linux-gnu/libc.so.6' )

libc.srand( libc.time(0) )

print( libc.rand() )

