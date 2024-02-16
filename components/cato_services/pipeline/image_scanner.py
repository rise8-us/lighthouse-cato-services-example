"""Provides Image Scanner Abstraction"""

from abc import ABC, abstractmethod
from typing import Optional, TypedDict, List
from cato_services.crm_db.models import Repository, System, Team

class Image(TypedDict):
    name: str
    digest: str
    tag: str

class Suppression(TypedDict):
    cve: str
    resource_path: str

class Vulnerability(TypedDict):
    cve: str
    resource_path: str
    suppression: Optional[Suppression]

class ImageScannerConfig(TypedDict):
    repository: Repository
    system: System
    team: Team

class AssuranceResult(TypedDict):
    passes: bool

class ImageScanner(ABC):
    """
    The Image Scanner Abstraction represents a service that scans Docker Images for vulnerabilities, tracks suppressions, and determines
    if an image has passed or failed based on whatever policies have been set.
    """
    @abstractmethod
    def get_vulnerabilities_for_image(self, image: Image) -> List[Vulnerability]:
        """Given an image that has been scanned, the image scanner should provide a list of its vulnerabilities and suppression data"""
        pass

    @abstractmethod
    def get_assurance_results(self, image: Image) -> AssuranceResult:
        """Given an image that has been scanned, the image scanner should give back a result of whether or not it has passed the policies"""
        pass
    
    @abstractmethod
    def onboard_new_customer(self, configuration: ImageScannerConfig):
        """Given a repository, system, and team, the image scanner should figure out how to change its settings accordingly"""
        pass