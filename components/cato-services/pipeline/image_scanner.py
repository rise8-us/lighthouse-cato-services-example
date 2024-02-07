"""Provides Aqua API functions for the ``tornado_shared_resources`` package."""

import urllib.parse
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from typing import TypedDict, List

from catoservices.util import utils

class Image(TypedDict):
    name: str
    digest: str
    tag: str

class Vulnerability(TypedDict):
    cve: str
    resource_path: str

class Suppression(TypedDict):
    cve: str
    resource_path: str

class ImageScanner(ABC):
    @abstractmethod
    def get_all_suppressions(self) -> List[Suppression]:
        pass

    @abstractmethod
    def get_vulnerabilities(self, image: Image) -> List[Vulnerability]:
        pass

    @abstractmethod
    def get_assurance_results(self, image: Image):
        pass