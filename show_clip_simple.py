import TkEasyGUI as eg
import pyperclip

TITLE = "show clip_simple.py"

layout = [ [eg.Text("", key='text')] ]

window = eg.Window( TITLE, layout, size=(250, 40) )

getdata = pyperclip.paste()
getdata_old = ""

# GUI表示実行
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
        
        window['text'].update( getdata )
        
        getdata_old = getdata

window.close()
