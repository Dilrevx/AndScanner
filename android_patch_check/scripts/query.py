import json
import requests
from pathlib import Path
from rich.progress import track
from rich.progress import Progress

from loguru import logger
from subprocess import check_output

logger.add(
    "logs/download_{time}.log",
    format="{name} {message}",
    level="DEBUG",
    rotation="5 MB",
)

ACCESS_TOKEN = "Ctgx7cWVCarsxoQtz6Qr"
header = {"PRIVATE-TOKEN": ACCESS_TOKEN}

proxies = {
    "http": "http://proxy.lfk.360es.cn:3128",
    "https": "http://proxy.lfk.360es.cn:3128",
}


def queryAndroDumpsProjects():
    result = []
    startLink = "https://git.rip/api/v4/groups/dumps/projects?include_subgroups=true&simple=true&pagination=keyset&per_page=100&order_by=id"

    nextPage = startLink
    idx = 1
    while nextPage:
        resp = requests.get(nextPage, headers=header)
        projectsMetainfo = json.loads(resp.content)
        result.append(projectsMetainfo)

        print(idx, len(projectsMetainfo))
        idx += 1
        nextPage = None

        links = resp.headers["Link"].split(",")
        for link in links:
            if 'rel="next"' in link:
                nextPage = link.split(";", 1)[0]
                nextPage = nextPage.strip()
                nextPage = nextPage.strip("<")
                nextPage = nextPage.strip(">")
                print("nextPage", nextPage)

    print(len(result))
    with open("projects.json", "w") as fp:
        json.dump(result, fp, indent=2)


def assembleProjects():
    with open("projects.json") as fp:
        data = json.load(fp)
    result = list()
    for pageList in data:
        for linkInfo in pageList:
            result.append(linkInfo)
    with open("projects.json", "w") as fp:
        json.dump(result, fp, indent=2)


def queryProjectBranches():
    with open("projects.json") as fp:
        data = json.load(fp)

    for idx in track(range(len(data))):
        try:
            projectInfo = data[idx]
            projectID = projectInfo["id"]
            branchUrl = (
                f"https://git.rip/api/v4/projects/{projectID}/repository/branches"
            )
            resp = requests.get(branchUrl, headers=header)
            branchInfo = json.loads(resp.content)
            branches = []
            for branch in branchInfo:
                branches.append(branch["name"])
            projectInfo["branches"] = branches
            data[idx] = projectInfo
        except:
            print("error happened", idx)
    with open("projectsWithBranches.json", "w") as fp:
        json.dump(data, fp, indent=2)


internalErrorIdx = [
    267,
    289,
    380,
    523,
    528,
    529,
    530,
    531,
    554,
    603,
    631,
    679,
    691,
    705,
    744,
    880,
    924,
    960,
    992,
    1053,
]


def queryErrorRepo():
    with open("projects.json") as fp:
        data = json.load(fp)
    for idx in internalErrorIdx:
        projectInfo = data[idx]
        print(projectInfo["web_url"])


def downloadDumpFiles():

    firmwareRoot = Path("firmwares")
    firmwareRoot.mkdir(parents=True, exist_ok=True)
    with open("assets/android_dumps.json") as fp:
        androdumps = json.load(fp)

    with open("assets/checklist.txt") as fp:
        filelist = fp.readlines()

    with Progress() as progress:

        task1 = progress.add_task("[red]Downloading Projects...", total=len(androdumps))
        for projectMetainfo in androdumps:
            subgroup = projectMetainfo["namespace"]["name"]
            projectName = projectMetainfo["name"]

            web_url = projectMetainfo["web_url"]
            branches = projectMetainfo["branches"]
            task2 = progress.add_task(
                "[green]Downloading branch...", total=len(branches)
            )
            for branch in branches:
                task3 = progress.add_task(
                    "[cyan]Downloading target...", total=len(filelist)
                )
                for target in filelist:
                    projectRoot = firmwareRoot / subgroup / projectName / branch
                    localfile = projectRoot / target.lstrip("/")
                    localdir = localfile.parent
                    localdir.mkdir(parents=True, exist_ok=True)
                    command = 'curl --silent --request GET --header "PRIVATE-TOKEN: {token}" "{weburl}/-/raw/{branch}{target}" --output {local}'.format(
                        token=ACCESS_TOKEN,
                        weburl=web_url,
                        branch=branch,
                        target=target.strip(),
                        local=localfile,
                    )
                    # logger.info(command)
                    try:
                        _ = check_output(command, shell=True)
                    except:
                        logger.exception(
                            f"Exception: {subgroup} {projectName} {branch} {target}"
                        )
                    finally:
                        progress.update(task3, advance=1)
                progress.update(task2, advance=1)
            progress.update(task1, advance=1)


if __name__ == "__main__":
    # queryAndroDumpsProjects()
    # assembleProjects()
    # queryProjectBranches()
    # queryErrorRepo()
    downloadDumpFiles()