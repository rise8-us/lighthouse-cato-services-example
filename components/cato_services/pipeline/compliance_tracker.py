from abc import ABC, abstractmethod
from typing import List, TypedDict

class ComplianceCountermeasure(TypedDict):
    id: str

class ComplianceProject(TypedDict):
    name: str

class CompliancePolicy(TypedDict):
    name: str

class ComplianceTracker(ABC):
    @abstractmethod
    def get_countermeasures(self, project_id: str) -> List[ComplianceCountermeasure]:
        pass
    @abstractmethod
    def get_projects(self) -> List[ComplianceProject]:
        pass
    @abstractmethod
    def get_policies(self) -> List[CompliancePolicy]:
        pass