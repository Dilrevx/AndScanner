import os
import logging
from loguru import logger
from rich.progress import Progress
from pathlib import Path

import boto3
from boto3.session import Session
from botocore.config import Config

from configparser import ConfigParser

# disable boto3 log
logging.getLogger("boto").setLevel(logging.WARNING)
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("s3transfer").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def readcfg(filepath, section="", field=""):
    conf = ConfigParser()
    conf.read(filepath)
    if not section:
        return conf
    elif section and not field:
        return conf[section]
    else:
        return conf[section][field]


class AWSManager:
    def __init__(self, config="configs/aws.cfg", storage=""):

        conf = readcfg(config, "AWS")
        self.bucket = conf["Bucket"]

        session = Session(conf["AccessKey"], conf["SecretKey"])
        self.client = session.client(
            service_name="s3",
            endpoint_url=conf["Endpoint"],
            config=Config(
                connect_timeout=int(conf["ConnectTimeout"]),
                read_timeout=int(conf["ReadTimeout"]),
            ),
        )

    def exists(self, key):
        try:
            resp = self.client.head_object(Bucket=self.bucket, Key=key)
            return resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        except:
            return False

    def download(self, key, local_path=""):
        if not self.exists(key):
            logger.warning("Not exists: {}".format(key))
            return None
        maxsize = self.client.head_object(Bucket=self.bucket, Key=key)["ContentLength"]

        # with Progress() as progress:
        #     task = progress.add_task(f"[red]Downloading {key}...", total=maxsize)

        #     def download_progress(chunk):
        #         progress.update(task, advance=chunk)

        try:
            self.client.download_file(
                Bucket=self.bucket,
                Key=key,
                Filename=local_path.as_posix(),
                # Callback=download_progress,
            )

            return local_path
        except Exception as e:
            logger.exception(e)
            return None
