import csv
import json
import os
import time
import hashlib
import logging
from analysis.TestEngine import TestEngine


def runBasicTest(uuid,targetFirmware):
    #uuid = "0027C159EF6B441B"
    engine = TestEngine(targetFirmware)
    # engine.loadAllBasicTests(allBasicTests)
    result = engine.executeBasicTestByUUID(uuid)
    print(uuid, result)
        
def runVulnLogic(firmware):
    engine = TestEngine(firmware)
    reports = engine.runAllVulnLogicTest()
    print(reports)
    
def testSingleVuln(cve,firmware):
    engine = TestEngine(firmware)
    # engine.loadAllBasicTests(allBasicTests)
    vulnObject = engine.getVulnLogicByCVE(cve)
    print(vulnObject)
    
    isVulnerable = engine.runVulnLogicTest(vulnObject["testVulnerable"])
    isFixed = engine.runVulnLogicTest(vulnObject["testFixed"])
    isNotAffected = engine.runVulnLogicTest(vulnObject["testNotAffected"])
    print(isFixed)
    print(isVulnerable)
    print(isNotAffected)
    
    print(engine.testWorker([cve,vulnObject]))
    print(engine._basicTestResultCache)


def loadBuildProperties(filePath):
    buildProperties = dict()
    if not filePath:
        return buildProperties

    with open(filePath) as fp:
        data = fp.readlines()

    for line in data:
        line = line.strip()
        if not line or line[0] == "#" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        buildProperties[key] = value
    return buildProperties


def md5_check(filename,hash_factory=hashlib.md5,chunk_num_blocks=128):
    h=hash_factory()
    with open(filename,'rb') as f:
        for chunk in iter(lambda:f.read(chunk_num_blocks*h.block_size),b''):
            h.update(chunk)
    return h.hexdigest()    


def brand_cve_check(rom_path):
    rom_path=os.path.abspath(rom_path)
    model_name=rom_path[rom_path.rfind('/')+1:]
    
    if model_name.endswith(".zip.extracted"):
        model_name=model_name.replace('.zip.extracted','')
    elif model_name.endswith(".ozip.extracted"):
        model_name=model_name.replace('.ozip.extracted','')
    else:
        return 0
    
    root_path=rom_path[:rom_path.rfind('/')]
    
    
    logger=logging.getLogger(model_name)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')
    hd = logging.FileHandler('./logs/'+model_name+'.log', 'a+', encoding='utf-8')
    hd.setFormatter(formatter)
    logger.addHandler(hd)
    logger.setLevel(logging.DEBUG)
    logger.debug("Model Name:"+model_name)
    logger.debug("Model Path:"+rom_path)
    logger.debug("Root Path:"+root_path)
    

    prop_path=rom_path+'/system.img.extracted/system/build.prop'
    prop_path=os.path.abspath(prop_path)
    check_path=rom_path+'/system.img.extracted/'
    if os.path.isfile(prop_path)==False:
        prop_path=rom_path+'/payload.bin.extracted/system.img.extracted/system/build.prop'
        check_path=rom_path+'/payload.bin.extracted/system.img.extracted/'
        prop_path=os.path.abspath(prop_path)
    if os.path.isfile(prop_path)==False:
        prop_path=rom_path+'/system.img.extracted/system/system/build.prop'
        check_path=rom_path+'/system.img.extracted/system'
        prop_path=os.path.abspath(prop_path)
    if os.path.isfile(prop_path)==False:
        print("Can not find build.prop")
        logger.debug("Can not find build.prop")
        return 0
    logger.debug("Check Path:"+check_path)
    logger.debug("Prop Path:"+prop_path)


    prop_dict=loadBuildProperties(prop_path)

    prop_fingerprint=prop_dict.get('ro.system.build.fingerprint')
    prop_version=prop_dict.get('ro.system.build.version.incremental')

    build_date_utc=int(prop_dict.get('ro.build.date.utc'))
    timeArray = time.localtime(build_date_utc)
    build_date = time.strftime("%Y%m%d%H%M%S", timeArray)

    if 'ro.huawei.build.version.security_patch' in prop_dict.keys():
        patch_date=prop_dict.get('ro.huawei.build.version.security_patch')
    else:
        patch_date=prop_dict.get('ro.build.version.security_patch')

    patch_date=patch_date[0:4]+patch_date[5:7]+patch_date[8:10]+'000000'
    timeArray = time.strptime(patch_date, "%Y%m%d%H%M%S")
    patch_date_utc = int(time.mktime(timeArray))

    delay=(build_date_utc-patch_date_utc)
    if delay<0:
        delay=0
    else:
        delay=delay//(60*60*24*30)

    api_level=prop_dict.get('ro.system.build.version.sdk')

    if 'ro.fota.oem' not in prop_dict.keys():
        vendor=prop_dict.get('ro.product.system.brand')
    else:
        vendor=prop_dict.get('ro.fota.oem')

    print()
    print(model_name)
    print(root_path)
    print(rom_path)
    print(check_path)

    print(api_level)
    print(vendor)
    print(prop_fingerprint)
    print(prop_version)

    print(build_date_utc)
    print(build_date)
    print(patch_date_utc)
    print(patch_date)
    print(delay)
    print()
    
    logger.debug("api_level:"+api_level)
    logger.debug("vendor:"+vendor)
    logger.debug("prop_fingerprint:"+prop_fingerprint)
    logger.debug("prop_version:"+prop_version)
    
    logger.debug("build_date_utc:"+build_date_utc)
    logger.debug("build_date:"+build_date)
    logger.debug("patch_date_utc:"+patch_date_utc)
    logger.debug("patch_date:"+patch_date)
    logger.debug("delay:"+delay)
    logger.debug("================")
    
    
    #Merge system_ext
    if os.path.isdir(check_path+'/system/system_ext/')==False \
       or os.path.islink(check_path+'/system/system_ext/') \
       or len(os.listdir(check_path+'/system/system_ext/'))==0:
        print('system_ext_need_merge')
        logger.debug('system_ext_need_merge')
        
        ordera='rm -r '+check_path+'/system/system_ext'
        orderb='rm '+check_path+'/system/system_ext'
        order1='mkdir '+check_path+'/system/system_ext'
        
        if prop_path.endswith('/payload.bin.extracted/system.img.extracted/system/build.prop'):
            order2='cp -r '+rom_path+'/payload.bin.extracted/system_ext.img.extracted/* '+check_path+'/system/system_ext/'
        elif prop_path.endswith('/system.img.extracted/system/system/build.prop'):
            order2='cp -r '+rom_path+'/system_ext.img.extracted/system/* '+check_path+'/system/system_ext/'
        else: 
            order2='cp -r '+rom_path+'/system_ext.img.extracted/* '+check_path+'/system/system_ext/'
        
        logger.debug('Merge order:'+order2)
        try:
            os.system(ordera)
            os.system(orderb)
            os.system(order1) 
            os.system(order2)
            if len(os.listdir(check_path+'/system/system_ext/'))!=0:
                logger.debug(model_name+' merge success')
            else:
                logger.debug(model_name+' still has problem')
        except:
            print('merge failed')
            logger.debug('Merge failed')
    else:
        logger.debug("system_ext don't need merge")
        logger.debug("================")
    
        
    #Repair apk
    all_files=open('assets/new_official_check_files.json','r')
    all_files_dic=json.load(all_files)
    all_files.close()
    
    all_files_real=all_files_dic[api_level]
    need_repaire=False
    for apk_0 in all_files_real:
        apk_real_path=check_path+apk_0
        if os.path.isfile(apk_real_path) and apk_0.endswith('.apk'):
            r=os.popen('zip '+apk_real_path).read()
            if r.find('Zip file structure invalid')!=-1:
                need_repaire=True
                print(r)
                logger.debug('Find apk needs repair:'+apk_0)
                
                try:
                    os.system('cp '+apk_real_path+' '+apk_real_path+'.backup')
                    os.system('7za x '+apk_real_path+' -o'+apk_real_path+'.temp')
                    os.system('7za a -r -tzip '+apk_real_path+'.temp.apk '+apk_real_path+'.temp')
                    os.system('rm -rf '+apk_real_path+'.temp')
                    os.system('mv '+apk_real_path+' '+apk_real_path+'.origin')
                    os.system('mv '+apk_real_path+'.temp.apk '+apk_real_path)
                except:
                    logger.debug('Repair failed'+apk_0)      

    r=os.popen('find '+check_path+' -name "*.backup"').read()
    logger.debug('Repaired Apks:'+str(need_repaire))
    logger.debug('Repaired Apks'+r)
    

    if api_level=='30' or api_level=='31':
        print('OK')
        
        print('========CVE check=======')
        engine = TestEngine(check_path)
        reports = engine.runAllVulnLogicTest()
        print(reports)
        json_file=open('./result/'+model_name+'.cve.json',"a+",encoding='utf-8')
        json_file.write(json.dumps(reports,indent = 4,ensure_ascii= False))
        json_file.close()
        #reports=json.load(open('./'+model_name+'.cve.json',"a+",encoding='utf-8'))
        
        sev_json=open('assets/vuln_level.json','r',encoding='utf-8')
        sev_dict=json.load(sev_json)
        sev_json.close()
        temp_dic={'low':0,'moderate':0,'high':0,'critical':0}
        for r in reports:
            if r=='Summary':
                continue
            if reports[r]=='F':
                temp_dic[sev_dict[r]]+=1
        print(reports['Summary']['Patched'],reports['Summary']['Missing'],reports['Summary']['Claimed'],
              reports['Summary']['Inconclusive'],reports['Summary']['NotAffected'],
              temp_dic['low'],temp_dic['moderate'],temp_dic['high'],temp_dic['critical'])

        csv_file=open('result.csv','a+',encoding='utf-8',newline='')
        csv_writer=csv.writer(csv_file)
        csv_writer.writerow([model_name,root_path,rom_path,check_path,api_level,vendor,prop_fingerprint,
                      prop_version,build_date_utc,build_date,patch_date_utc,patch_date,delay,
                      reports['Summary']['Patched'],reports['Summary']['Missing'],reports['Summary']['Claimed'],
                      reports['Summary']['Inconclusive'],reports['Summary']['NotAffected'],
                      temp_dic['low'],temp_dic['moderate'],temp_dic['high'],temp_dic['critical']])
        csv_file.close()
        
       
        """
        #Collect apks if necessary
        print('========APK deal=======')
        apk_dic={model_name:[]}
        try:
            os.system('rm -r /android_data/result_rom/'+model_name+'/apks')
            os.mkdir('/android_data/result_rom/'+model_name+'/apks')
        except:
            print('mkdir error')
            return 0

        for root,dirs,files in os.walk(rom_path):
            for f in files:
                if(str(f).endswith('.apk')):
                    apk_abs_path=os.path.join(root,f)
                    apk_relative=apk_abs_path[len(rom_path):]
                    apk_name=str(f)
                    apk_md5=md5_check(apk_abs_path)
                    print(apk_name)
                    print(apk_relative)
                    print(apk_md5)
                    apk_dic[model_name].append({'APKName':apk_name,'APKPath':apk_relative,'APKMd5':apk_md5,
                                                'belongsRom':model_name,'belongsRomfingerprint':prop_fingerprint})
                    os.system('cp '+apk_abs_path+' /android_data/result_rom/'+model_name+'/apks/'+apk_md5+'.apk')
                    print()

        json_apk=open('/android_data/result_rom/'+model_name+'/'+model_name+'.apk.json','a+',encoding='utf-8')
        json_apk.write(json.dumps(apk_dic,indent=4,ensure_ascii=False))
        json_apk.close()
        print(len(apk_dic[model_name])) 

        """
        print('=======Done======')
        return 1
    else:
        print("API not match")
        return 0



if __name__ == '__main__':
    rom_path='/your_unpacked_rom_path/'
    brand_cve_check(rom_path)
    
