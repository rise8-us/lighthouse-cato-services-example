import json

from sqlalchemy import ARRAY, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship


Base = declarative_base()


class Team(Base):
    __tablename__ = "Team"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    slack_channel_id = Column(String(20), nullable=False)
    snyk_org_id = Column(String(50), nullable=False)

    def __str__(self):
        return json.dumps(
            {
                "id": self.id,
                "name": self.name,
                "slack_channel_id": self.slack_channel_id,
                "snyk_org_id": self.snyk_org_id,
            }
        )


class System(Base):
    __tablename__ = "System"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(String(1000), nullable=False)
    sde_application_id = Column(Integer, nullable=False)
    status = Column(String(100), nullable=False, server_default="Active")
    first_image_signed_date = Column(DateTime(timezone=True), nullable=True)
    sde_policy_round_2_start_date = Column(DateTime(timezone=True), nullable=True)
    sde_policy_round_2_expiration_date = Column(DateTime(timezone=True), nullable=True)
    sde_policy_round_3_start_date = Column(DateTime(timezone=True), nullable=True)
    sde_policy_round_3_expiration_date = Column(DateTime(timezone=True), nullable=True)
    repositories = relationship("Repository", back_populates="system")

    def __str__(self):
        return json.dumps(
            {
                "id": self.id,
                "name": self.name,
                "description": self.description,
                "sde_application_id": self.sde_application_id,
                "status": self.status,
                "first_image_signed_date": self.first_image_signed_date,
                "sde_policy_round_2_start_date": self.sde_policy_round_2_start_date,
                "sde_policy_round_2_expiration_date": self.sde_policy_round_2_expiration_date,
                "sde_policy_round_3_start_date": self.sde_policy_round_3_start_date,
                "sde_policy_round_3_expiration_date": self.sde_policy_round_3_expiration_date,
            }
        )


class Repository(Base):
    __tablename__ = "Repository"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    system_id = Column(Integer, ForeignKey(System.id), nullable=False)
    team_id = Column(Integer, ForeignKey(Team.id), nullable=False)
    default_branch = Column(String(100), nullable=False)
    onboard_request_start_date = Column(DateTime(timezone=True), nullable=True)
    onboard_request_complete_date = Column(DateTime(timezone=True), nullable=True)
    onboard_issue_number = Column(Integer, nullable=False)
    system = relationship(
        "System", foreign_keys=system_id, back_populates="repositories"
    )
    team = relationship("Team", foreign_keys=team_id)

    def __str__(self):
        return json.dumps(
            {
                "id": self.id,
                "name": self.name,
                "system_id": self.system_id,
                "team_id": self.team_id,
                "default_branch": self.default_branch,
                "onboard_request_start_date": str(self.onboard_request_start_date),
                "onboard_request_complete_date": str(
                    self.onboard_request_complete_date
                ),
                "onboard_issue_number": self.onboard_issue_number,
            }
        )


class Client(Base):
    __tablename__ = "Client"
    id = Column(String(100), primary_key=True, autoincrement=False)
    hashed_secret = Column(String(100), nullable=False)
    scopes = Column(ARRAY(String(50)), nullable=True)


class Alembic(Base):
    __tablename__ = "alembic_version"
    version = Column("version_num", String(100), primary_key=True)
