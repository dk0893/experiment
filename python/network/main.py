import os, sys
import argparse
import logging

def memo():
    
    print( "--- summary ---" )
    
    pkt.summary()

def main( args ):
    
    print( f"{args.bit}bit quantize: r1={args.r1}" )
    
    quantize( args.r1, -2, 7, bit=args.bit )

def parse_args():
    
    parser = argparse.ArgumentParser( description='Scapy program' )
    
    parser.add_argument( '--ope',   default=None,           help='select operation, [None or ...]' )
    parser.add_argument( '--',    default=0,    type=int, help='input real number' )
    parser.add_argument( '--',   default=8,    type=int, help='input bit' )
    
    return parser.parse_args()

if __name__ == '__main__':
    
    args = parse_args()
    print( f"args={args}" )
    
    if args.debug:
        logging.basicConfig( level=logging.DEBUG, filename=f"{argv[0]}.log" )
    else:
        logging.basicConfig( level=logging.INFO )
    
    main( args )
