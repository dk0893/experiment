import os, sys
import argparse
import shutil

def parse_args():
    
    parser = argparse.ArgumentParser( description='baby_stack' )
    
    parser.add_argument( '--ope',   default=None,        help='select operation, [None or ...]' )
    parser.add_argument( '--fpath', default=None,        help='input program path' )
    parser.add_argument( '--debug', action='store_true', help='debug' )
    
    return parser.parse_args()

def unzip( fpath ):
    
    shutil.unpack_archive( fpath )
    os.remove( fpath )

if __name__ == '__main__':
    
    args = parse_args()
    print( f"args={args}" )
    
    if args.ope is None:
        
        # unzip
        if args.fpath is None:
            shutil.unpack_archive( "../setodaNoteCTF/Programming/flag1000.zip" )
        
        else:
            
            fpath = args.fpath
            dname = os.path.dirname( fpath )
            
            while True:
                
                # unzip and remove
                unzip( fpath )
                
                files = os.listdir( dname )
                
                if len(files) > 1: raise
                
                fpath = files[0]
                
                if os.path.splitext( fpath )[1] != ".zip": break
                
                print( fpath )
