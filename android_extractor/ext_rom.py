import os
import sys

ext_config={
        "rom_path":"",
        "ext_path":"",
        "ext2rd_path":"./addons/extfstools/ext2rd"
        }

#使用extractor.sh解压固件
def rom_ext():

    order1="./extractor.sh {} {}".format(
        ext_config["rom_path"],ext_config["ext_path"]
    )

    try:
        os.system(order1)
    except:
        return False

    if len(os.listdir(ext_config["ext_path"]))==0:
        return False
    else:
        return True

#使用其他工具解压img
def img_ext():

    for f in os.listdir(ext_config["ext_path"]):
        order2="{} {} ./:{}".format(
                ext_config["ext2rd_path"],
                os.path.abspath(ext_config["ext_path"]+"/"+f),
                os.path.abspath(ext_config["ext_path"]+"/"+f+".extracted"),
               )
        os.system(order2)


if __name__=="__main__":
    print("Ready")
   
    if len(sys.argv)!=3:
        print("python|python3 ext_rom.py <rom_path> <ext_path>")
        exit()
    else:
        print("Try to ext a Rom")
    
    try:
        ext_config["rom_path"]=os.path.abspath(sys.argv[1])
        ext_config["ext_path"]=os.path.abspath(sys.argv[2])
    except:
        print("input path error")

    if rom_ext()==False:
        print("ext failed")
        exit()
    else:
        print("ext succeed")

    try:
        print("Try to ext img")
        img_ext()
    except:
        print("ext img error")
