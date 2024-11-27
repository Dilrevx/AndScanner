import requests
from rich.progress import track
from loguru import logger
from pathlib import Path
import json
import os
from bs4 import BeautifulSoup

chunksPath = Path("assets/chunks/")
chunksUrl = "https://snoopsnitch-api.srlabs.de/chunks"

testSuiteUrl = "https://snoopsnitch-api.srlabs.de/v1/test/suite"
testSuitePath = Path("assets/allTestSuites.json")


def ScratchSnoopsnitchChunks():
    response = requests.get(chunksUrl)
    logger.debug("Success request chunks.")
    soup = BeautifulSoup(response.content, "html.parser")
    for links in track(soup.findChildren("td"), description="scratch chunks..."):
        if links.a and links.a.text.endswith(".json"):
            filename = links.a.text
            remote = chunksUrl + "/" + filename
            local = chunksPath / filename
            if local.exists():
                continue
            r = requests.get(remote, proxies={"http": "http://proxy.lfk.360es.cn:3128"})
            with local.open("wb") as fp:
                fp.write(r.content)
            # os.system(f"aria2c -s16 -x16 {remote}")


def AssembleAllBasicTests():
    basicTests = dict()
    for file in chunksPath.glob("*.json"):
        with file.open() as fp:
            data = json.load(fp)
        if "basicTests" not in data:
            continue
        data = data["basicTests"]
        basicTests.update(data)
    with open("assets/allBasicTests.json", "w") as fp:
        json.dump(basicTests, fp, indent=2, sort_keys=True)


def AssembleAllVulnLogics():
    vulnLogics = dict()
    for file in chunksPath.glob("*.json"):
        with file.open() as fp:
            data = json.load(fp)
        if "vulnerabilities" not in data:
            continue
        data = data["vulnerabilities"]
        vulnLogics.update(data)
    with open("assets/allVulnLogics.json", "w") as fp:
        json.dump(vulnLogics, fp, indent=2, sort_keys=True)


def RequestSnoopsnitchBundles():
    allApiVersion = dict()
    for apiVersion in track(range(21, 31)):
        remoteUrl = (
            testSuiteUrl
            + "?appId=7dd984da"
            + f"&androidApiVersion={apiVersion}"
            + "&testVersion=0"
            + "&appVersion=11"
            + "&64bit=true"
        )
        try:
            response = requests.get(remoteUrl)
            data = json.loads(response.content)
            allApiVersion[apiVersion] = data
        except Exception as e:
            logger.exception(e)

    with testSuitePath.open("w") as fp:
        json.dump(allApiVersion, fp, indent=2, sort_keys=True)


if __name__ == "__main__":
    # ScratchSnoopsnitchChunks()
    # AssembleAllBasicTests()
    AssembleAllVulnLogics()
    # RequestSnoopsnitchBundles()
