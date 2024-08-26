#include <unistd.h>

typedef long Align;           /* ユニットアライメント(1ユニットは 8 or 16byte) */

union header                  /* ブロックヘッダ */
{
  struct
  {
    union header *ptr;        /* フリーリストにある場合は次のブロックの先頭アドレス */
    unsigned size;            /* このブロックのサイズ */
  } s;
  
  Align x;                    /* ユニットアライメント強制 */

};
typedef union header Header;

static Header base;           /* empty list to get started */
static Header* freep = NULL;  /* フリーリスト開始アドレス */

static Header *morecore(unsigned nu);
void myfree(void *ap);

/* malloc: general-purpose storage allocator */
void* mymalloc (unsigned nbytes)
{
  Header*   p;
  Header*   prevp;
  unsigned  nunits;
  
  nunits = (nbytes + sizeof(Header) - 1) / sizeof(Header) + 1; /* 1byte要求でもヘッダとデータで2ユニット必要 */
  
  if ((prevp = freep) == NULL)           /* まだフリーリストが存在しない場合 */
  {
    base.s.ptr = freep = prevp = &base;
    base.s.size = 0;
  }
  
  for (p = prevp->s.ptr; ; prevp = p, p = p->s.ptr)
  {
    if (p->s.size >= nunits)             /* big enough */
    {
      if (p->s.size == nunits)           /* ちょうど同じサイズ */
        prevp->s.ptr = p->s.ptr;         /* 使用済みとして次の空きを指すようにする */
      else                               /* allocate tail end */
      {
        p->s.size -= nunits;             /* 後ろから切り分ける */
        p += p->s.size;
        p->s.size = nunits;
      }
      
      freep = prevp;
      return (void *)(p + 1);            /* ヘッダ＋１を返す */
    }
    
    if (p == freep)                      /* wrapped around free list */
      if ((p = morecore(nunits)) == NULL)
        return NULL;                     /* メモリ取得失敗 */
  }
}

#define NALLOC 1024 /* 要求する最小単位：1024ユニット */

/* morecore: システムにメモリの追加を要求する */
static Header *morecore(unsigned nu)
{
  char *cp;
  Header *up;
  
  if (nu < NALLOC)
    nu = NALLOC;
  
  cp = sbrk(nu * sizeof(Header));
  
  if (cp == (char *) -1) /* メモリ取得失敗 */
    return NULL;
  
  up = (Header *) cp;
  up->s.size = nu;
  myfree((void *)(up + 1)); /* free()はデータのアドレスを指定する */
  
  return freep;
}

/* free: put block ap in free list */
void myfree(void *ap) {
  Header *bp, *p;
  
  bp = (Header *)ap - 1; /* ヘッダのアドレスを取得 */
  
  for (p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
    if (p >= p->s.ptr && (bp > p || bp < p->s.ptr))
      break; /* freed block at start or end of arena */
  
  if (bp + bp->s.size == p->s.ptr) { /* 右隣と連結可能なら連結する */
    bp->s.size += p->s.ptr->s.size;
    bp->s.ptr = p->s.ptr->s.ptr;
  } else
      bp->s.ptr = p->s.ptr;
  
  if (p + p->s.size == bp) { /* 左隣と連結可能なら連結する */
    p->s.size += bp->s.size;
    p->s.ptr = bp->s.ptr;
  } else
    p->s.ptr = bp;
  
  freep = p;
}

#ifdef DEBUG
#include <stdio.h>
int main( int argc, char *argv[] )
{
  char *p0, *p1, *p2;
  
  p0 = (char *)mymalloc( 2 );
  printf( "%d, %d\n", p0[0], p0[1] );
  
  p1 = (char *)mymalloc( 4 );
  printf( "%d, %d, %d, %d\n", p1[0], p1[1], p1[2], p1[3] );
  
  p2 = (char *)mymalloc( 6 );
  printf( "%d, %d, %d, %d, %d, %d\n", p1[0], p1[1], p1[2], p1[3], p1[4], p1[5] );
  
  myfree( p1 );
  myfree( p0 );
  myfree( p2 );
}
#endif /* DEBUG */
