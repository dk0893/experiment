import TkEasyGUI as eg
import pyperclip
import requests
from bs4 import BeautifulSoup

DEBUG = True #True
TITLE = "url2title.py"
MYURL = "https://daisuke20240310.hatenablog.com"

def get_title( url ):
    
    try:
        # ページを取得
        response = requests.get( url )
        response.raise_for_status()  # エラーチェック
        
        # BeautifulSoupでHTMLをパース
        soup = BeautifulSoup( response.text, 'html.parser' )
        
        # タイトルを取得
        title = soup.title.text.strip()
        
        if DEBUG: print( f"URL: {url} - タイトル: {title}" )
        
        return title
    
    except Exception as e:
        print(f"エラーが発生しました: {e}")

def main():
    
    layout = [ [eg.Text("", key='text')] ]
    
    window = eg.Window( TITLE, layout, size=(700, 60) )
    
    getdata = pyperclip.paste()
    getdata_old = ""
    
    while True:
        
        # ウィンドウ表示
        event, values = window.read( timeout=1000 )
        if event != "__TIMEOUT__" and event != "-TIMEOUT-":
            if event == eg.WIN_CLOSED:
                break
        
        getdata = pyperclip.paste()
        
        if getdata == getdata_old:
            continue # 取得したクリップボードのデータが前回と同じなら何もしない
        
        else:
            
            txt = getdata
            
            if MYURL in getdata:
                
                # 自分のURL以外は対象としない
                
                title = get_title( getdata )
                
                if DEBUG: print( f"getdata={getdata}, title={title}" )
                
                if title is not None:
                    txt = "URL：" + getdata + "\n" + "タイトル：" + title
            
            window['text'].update( txt )
            
            getdata_old = getdata
    
    window.close()

if __name__ == '__main__':
    main()
