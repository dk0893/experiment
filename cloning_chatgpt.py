import time
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# 再帰的にページをクロールしてURLとタイトルを取得する関数
def crawl_page(url, visited_pages=set()):
    
    if url[-1] == "/":
        url = url[:-1]
    
    # すでに訪れたページであればスキップ
    if url in visited_pages:
        return
    
    try:
        # ページを取得
        time.sleep(1)
        response = requests.get(url)
        response.raise_for_status()  # エラーチェック
        
        # BeautifulSoupでHTMLをパース
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # タイトルを取得
        title = soup.title.text.strip()
        
        # URLとタイトルを出力
        print(f"URL: {url} - タイトル: {title}")
        
        # 今訪れたページを追加
        visited_pages.add(url)
        
        # ページ内のリンクを見つける
        for link in soup.find_all('a', href=True):
            # 絶対URLに変換
            absolute_link = urljoin(url, link['href'])
            
            # 同じドメインのページに絞る（適宜変更）
            if absolute_link.startswith("https://daisuke20240310.hatenablog.com") and "archive" not in absolute_link and "#" not in absolute_link and "?page=" not in absolute_link:
                # 再帰的にそのページをクロール
                crawl_page(absolute_link, visited_pages)
    
    except Exception as e:
        print(f"エラーが発生しました: {e}")

# トップページのURL
start_url = "https://daisuke20240310.hatenablog.com"

# 関数を呼び出してクロールを開始
crawl_page(start_url)
