import os
from PIL import Image
from PIL.ExifTags import TAGS
import piexif
from datetime import datetime

def get_exif(image_path):
    image = Image.open(image_path)
    exif_data = {}
    info = image._getexif()
    if info:
        for tag_id, value in info.items():
            tag = TAGS.get(tag_id, tag_id)
            exif_data[tag] = value
    return exif_data

def set_exif( fpath, exif_dict ):
    
    exif_bytes = piexif.dump( exif_dict )
    piexif.insert( exif_bytes, fpath )

def update_timestamp( fpath, epoch_time, epoch_subsec ):
    
    exif_dict = piexif.load( fpath )
    
    # Update DateTimeOriginal and SubSecTimeOriginal
    if piexif.ExifIFD.DateTimeOriginal in exif_dict['Exif']:
        exif_dict['Exif'][piexif.ExifIFD.DateTimeOriginal]   = epoch_time.encode()
        exif_dict['Exif'][piexif.ExifIFD.SubSecTimeOriginal] = epoch_subsec.encode()

    # Update DateTimeDigitized and SubSecTimeDigitized
    if piexif.ExifIFD.DateTimeDigitized in exif_dict['Exif']:
        exif_dict['Exif'][piexif.ExifIFD.DateTimeDigitized]   = epoch_time.encode()
        exif_dict['Exif'][piexif.ExifIFD.SubSecTimeDigitized] = epoch_subsec.encode()

    # Update DateTime and SubSecTime in 0th IFD
    if piexif.ImageIFD.DateTime in exif_dict['0th']:
        exif_dict['0th'][piexif.ImageIFD.DateTime]   = epoch_time.encode()
        exif_dict['Exif'][piexif.ExifIFD.SubSecTime] = epoch_subsec.encode()

    
    makernotes = exif_dict['Exif'].get( piexif.ExifIFD.MakerNote )
    print( f"{makernotes}" )
    
    set_exif( fpath, exif_dict )
    
    # 以下は意味なかった
    new_datetime = datetime.strptime(epoch_time, "%Y:%m:%d %H:%M:%S")
    os.utime(fpath, (new_datetime.timestamp(), new_datetime.timestamp()))
    
    print( f"Updated timestamps: {fpath} to {epoch_time}.{epoch_subsec}" )

# 設定
fpath        = "../picoCTF/picoCTF2024_Forensics/original.jpg"
epoch_time   = "1970:01:01 00:00:00"
epoch_subsec = "001"

# あとは、TimeStamp のところだけ
update_timestamp( fpath, epoch_time, epoch_subsec )
