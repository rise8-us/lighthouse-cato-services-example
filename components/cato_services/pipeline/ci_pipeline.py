from abc import ABC, abstractmethod
from typing import List, TypedDict

from cato_services.pipeline.image_scanner import AssuranceResult, Image

class ImageScanResult(TypedDict):
    assurance_result: AssuranceResult
    images: List[Image]

class CIPipeline(ABC):
    @abstractmethod
    def output_step(self, output, params=None):
        pass
    @abstractmethod
    def output_summary(self, output, params=None):
        pass

class ImageScanPipelineStep(ABC):
    @abstractmethod
    def output_image_scan_summary(self, scan_result: ImageScanResult):
        pass

class CodeScanPipelineStep(ABC):
    @abstractmethod
    def output_image_scan_summary(self, scan_result: ImageScanResult):
        pass

class DependencyScanPipelineStep(ABC):
    @abstractmethod
    def output_image_scan_summary(self, scan_result: ImageScanResult):
        pass

class CompliancePipelineStep(ABC):
    @abstractmethod
    def output_image_scan_summary(self, scan_result: ImageScanResult):
        pass