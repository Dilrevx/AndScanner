import os
import json
import click
from datetime import datetime
from loguru import logger
from pathlib import Path
from analysis.TestEngine import TestEngine
from threading import Thread
from queue import Queue
from hashlib import md5, sha1, sha256
from zlib import crc32


# from analysis.database.mongo import MongoManager

logger.add("logs/{time}.log", format="{name} {message}", level="DEBUG")

allBasicTests = "/home/dell/tmp_ls/PatchSher/assets/allBasicTests.json"

FIELD_UTC = ('ro.build.date.utc', 'ro.system.build.date.utc', 'ro.vendor.build.date.utc', 'ro.odm.build.date.utc', 'ro.product.build.date.utc', 'ro.bootimage.build.date.utc')
FIELD_PATCH = (
    'ro.build.version.security_patch',
    'ro.vendor.build.security_patch'
)

FIELD_VERSION = (
    'ro.build.version.release',
    'ro.system.build.version.release',
    'ro.vendor.build.version.release',
    'ro.odm.build.version.release',
    'ro.product.build.version.release',
    'ro.mediatek.version.release'
)

FIELD_SDK = ('ro.build.version.sdk')

def runVulnLogic(firmware):
    engine = TestEngine(firmware)
    engine.loadAllBasicTests(allBasicTests)
    reports = engine.runAllVulnLogicTest()
    return reports

def generateRomMeta():
    pass

class PatchAnalysisThread(Thread):
    def __init__(self, task_queue, name="PatchAnalysisThread"):
        super().__init__()
        self._task_queue = task_queue
        self._name = name

    def run(self):
        while True:
            repoData = self._task_queue.get()
            localRepo = repoData["path"]
            branches = repoData["branches"]
            repoGroup = localRepo.relative_to(Path("/data/android_rom/dumps"))

            logger.info(
                "{} - {} tasks - {}".format(
                    self._name, self._task_queue.qsize(), localRepo
                )
            )

            cwd = Path("/home/dell/tmp_ls/PatchSher")
            try:
                for branch in branches:
                    os.chdir(str(localRepo))
                    os.system("git checkout -f {}".format(branch))
                    os.chdir(str(cwd))
                    branchName = branch[len("remotes/origin/") :]

                    '''
                    romMeta = {
                        "branchName": branchName,
                        "group": str(repoGroup),
                        "build_date": set(),
                        "build_date_utc": set(),
                        "security_patch_date": set(),
                        "security_patch_date_utc": set(),
                        "android_version": set(),
                        "android_sdk_level": set(),
                    }
                    for f in localRepo.rglob("*.prop"):
                        if not f.exists(): continue

                        with open(f) as fp:
                            data = fp.readlines()
                        for line in data:
                            if '=' not in line: continue
                            fieldName, fieldValue = line.split('=', 1)
                            fieldName = fieldName.strip()
                            fieldValue = fieldValue.strip()
                            if not fieldValue: continue

                            if fieldName in FIELD_PATCH:
                                dt = datetime.strptime(fieldValue.strip(), "%Y-%m-%d")
                                buildtime = dt.strftime("%Y%m%d%H%M%S")
                                utctime = int(dt.timestamp())
                                romMeta["security_patch_date"].add(buildtime)
                                romMeta["security_patch_date_utc"].add(utctime)

                            elif fieldName in FIELD_UTC:
                                utctime = int(fieldValue)
                                buildtime = datetime.utcfromtimestamp(utctime)
                                buildtime = buildtime.strftime("%Y%m%d%H%M%S")
                                romMeta["build_date"].add(buildtime)
                                romMeta["build_date_utc"].add(utctime)

                            elif fieldName == 'ro.build.date.YmdHM':
                                buildtime = fieldValue.strip()
                                dt = datetime.strptime(buildtime, "%Y%m%d%H%M%S")
                                utctime = int(dt.timestamp())

                                romMeta["build_date"].add(buildtime)
                                romMeta["build_date_utc"].add(utctime)
                            elif fieldName in FIELD_VERSION:
                                # TODO:
                                # print("Android Version:", filemd5, fieldValue)
                                romMeta["android_version"].add(fieldValue)
                            elif fieldName in FIELD_SDK:
                                romMeta["android_sdk_level"].add(fieldValue)


                    fields = ["build_date", "build_date_utc", "security_patch_date", "security_patch_date_utc", 'android_version', 'android_sdk_level']
                    for field in fields:
                        romMeta[field] = list(romMeta[field])
                        if len(romMeta[field]) == 1:
                            romMeta[field] = romMeta[field][0]

                    with open("/home/dell/tmp_ls/PatchSher/results/{}-rom.json".format(self._name), 'a') as fp:
                        fp.write(json.dumps(romMeta)+"\n")
                    
                    # FIXME: temporarily disable apk extract.
                    # for apk in localRepo.rglob("*.apk"):
                    #     if not apk.exists(): continue
                    #     apk_raw = apk.read_bytes()
                    #     apkMeta = {
                    #         "name": str(apk.name),
                    #         "belongsBranch": branchName,
                    #         "rompath": str(apk.relative_to(localRepo)),
                    #         "md5" :  md5(apk_raw).hexdigest(),
                    #         "sha1" : sha1(apk_raw).hexdigest(),
                    #         "sha256" : sha256(apk_raw).hexdigest(),
                    #         "crc32" : str(crc32(apk_raw)),
                    #     }
                    #     with open("/home/dell/tmp_ls/PatchSher/results/{}-apk.json".format(self._name), 'a') as fp:
                    #         fp.write(json.dumps(apkMeta)+"\n")
                    '''

                    reports = runVulnLogic(localRepo)
                    if not reports:
                        logger.warning("No reports generated")
                        continue
                    reportPath = (
                        cwd / "reports/git.rip" / repoGroup / (branchName + ".json")
                    )
                    reportPath.parent.mkdir(parents=True, exist_ok=True)
                    with reportPath.open("w") as fp:
                        json.dump(reports, fp, indent=2, sort_keys=True)
            except Exception as e:
                logger.exception(e)


def main():
    patchThreads = []
    analysis_queue = Queue()
    for i in range(4):
        patchthread = PatchAnalysisThread(
            task_queue=analysis_queue, name="PatchAnalysisThread{:02d}".format(i + 1)
        )
        patchThreads.append(patchthread)
        patchthread.start()

    with open("/home/dell/tmp_ls/PatchSher/scripts/repobranches.json") as fp:
        repoBranches = json.load(fp)

    for localRepo, branches in repoBranches.items():
        analysis_queue.put({"path": Path(localRepo), "branches": branches})

    analysis_queue.join()


def run_single_firmware():
    firmware_path = Path("/data/android_rom/dumps/oneplus/oneplus3.git/remotes_origin_OnePlus3-user-6.0.1-MMB29M-23-dev-keys")
            
    reports = runVulnLogic(firmware_path)
    if not reports:
        logger.warning("No reports generated")
        return
                                        
    reportPath = Path.cwd() / "output.json"
    with reportPath.open("w") as fp:
        json.dump(reports, fp, indent=2, sort_keys=True)

if __name__ == "__main__":
    run_single_firmware()
#    main()

