import os, sys
import argparse

# r = S(q - Z)
# q = r / S + Z
# S = (max - min) / (2^n - 1)：量子化空間の1あたりのリアル空間のサイズ

def quantize( r, min, max, bit=8 ):
    
    S = (max - min) / (2**bit - 1)
    
    q = round( (r - min) / S )
    
    print( f"r={r}, max={max}, min={min}, S={S}, q={q}" )

def main( args ):
    
    print( f"{args.bit}bit quantize: r1={args.r1}" )
    
    quantize( args.r1, -2, 7, bit=args.bit )

def parse_args():
    
    parser = argparse.ArgumentParser( description='quantize.py' )
    
    parser.add_argument( '--ope',   default=None,           help='select operation, [None or ...]' )
    parser.add_argument( '--r1',    default=0,    type=int, help='input real number' )
    parser.add_argument( '--bit',   default=8,    type=int, help='input bit' )
    
    return parser.parse_args()

if __name__ == '__main__':
    
    args = parse_args()
    print( f"args={args}" )
    
    if args.ope is None:
        
        main( args )
