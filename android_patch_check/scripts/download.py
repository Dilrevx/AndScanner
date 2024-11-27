from analysis.database.mongo import MongoManager
from analysis.database.aws import AWSManager
from rich.progress import track
from pathlib import Path
from threading import Thread
from queue import Queue

collection = "androimg"
mg = MongoManager("10.252.144.74", 27017, "newrom", collection)
aws = AWSManager()


class DownloadThread(Thread):
    def __init__(self, task_queue, name="DownloadThread"):
        super().__init__()
        self._task_queue = task_queue
        self._name = name
        self._aws = AWSManager()

    def run(self):
        while True:
            meta = self._task_queue.get()
            md5 = meta["md5"]
            local = meta["path"]
            print(f"{self._name} - {self._task_queue.qsize()} tasks - {md5}")
            try:
                aws.download(md5, local)
            except:
                pass


download_queue = Queue()


def main():
    downThreads = []
    for i in range(10):
        downthread = DownloadThread(
            task_queue=download_queue, name="DownloadThread{:02d}".format(i + 1)
        )
        downThreads.append(downthread)
        downthread.start()
    task()
    download_queue.join()


def task():
    firmwareRoot = Path("/data/patch") / collection
    firmwareRoot.mkdir(parents=True, exist_ok=True)

    with open("assets/checklist.txt") as fp:
        filelists = fp.readlines()
        filelists = [line.strip().strip("/system/") for line in filelists]

    for fileRelPath in filelists:
        filename = fileRelPath.split("/")[-1]
        for record in mg.find(
            {"name": filename}, {"rompath": 1, "md5": 1, "belongsMd5": 1}
        ):
            rompath = record["rompath"]
            # folder = "/".join(rompath.split("/")[:3])
            if "system" not in rompath:
                continue
            if fileRelPath not in rompath:
                continue
            local = firmwareRoot / record["belongsMd5"] / "system" / fileRelPath
            local.parent.mkdir(parents=True, exist_ok=True)
            download_queue.put({"md5": record["md5"], "path": local})

    for record in mg.find(
        {"name": "build.prop"}, {"rompath": 1, "md5": 1, "belongsMd5": 1}
    ):
        rompath = record["rompath"]
        local = firmwareRoot / record["belongsMd5"] / "system/build.prop"
        local.parent.mkdir(parents=True, exist_ok=True)
        download_queue.put({"md5": record["md5"], "path": local})


if __name__ == "__main__":
    main()
