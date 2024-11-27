import csv
import json
import os
import time
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


def readProp(root_path,rom_path,model_name):
    prop_path=rom_path+'/system/build.prop'
    prop_path=os.path.abspath(prop_path)
    prop_dict=loadBuildProperties(prop_path)

    prop_fingerprint=prop_dict.get('ro.system.build.fingerprint')
    prop_version=prop_dict.get('ro.system.build.version.incremental')

    build_date_utc=int(prop_dict.get('ro.build.date.utc'))
    timeArray = time.localtime(build_date_utc)
    build_date = time.strftime("%Y%m%d%H%M%S", timeArray)

    patch_date=prop_dict.get('ro.build.version.security_patch')
    patch_date=patch_date[0:4]+patch_date[5:7]+patch_date[8:10]+'000000'
    timeArray = time.strptime(patch_date, "%Y%m%d%H%M%S")
    patch_date_utc = int(time.mktime(timeArray))

    delay=abs(build_date_utc-patch_date_utc)
    delay=delay//(60*60*24*30)

    api_level=prop_dict.get('ro.system.build.version.sdk')
    vendor=prop_dict.get('ro.fota.oem')

    print(root_path)
    print(model_name)
    print(rom_path)
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


if __name__=='__main__':
    root_path="/android_data/rom_ext/"
    rom_path = "/android_data/sam/230119/SM-T307U_2_20221228011020_6fd7h3ipmj_fac_USC.zip.extracted/system.img.extracted/"
    model_name='test_rom'
 
    engine = TestEngine(rom_path)
    reports = engine.runAllVulnLogicTest()
    print(reports)
    #json_file=open("test.json",'a+',encoding='utf-8')
    #json_file.write(json.dumps(reports,indent = 4,ensure_ascii= False))
    
    #testSingleVuln('CVE-2021-0473',rom_path)
