from sqlalchemy.orm import Mapped, mapped_column
from backend.models.base import Base, int_pk, str_uniq, int_null_true

from sqlalchemy import ForeignKey, text
from sqlalchemy.orm import relationship
import json


class VacancyModel(Base):
    id: Mapped[int_pk]
    employer: Mapped[str]
    name: Mapped[str]
    salary: Mapped[bool]
    salary_min: Mapped[int_null_true]
    salary_max: Mapped[int_null_true]
    experience: Mapped[str]
    schedule: Mapped[str]
    keywords: Mapped[str]
    description: Mapped[str]
    source: Mapped[str] = mapped_column(server_default=text("HH.ru"))
    request_id: Mapped[int] = mapped_column(ForeignKey("monitoringrequestmodels.id", ondelete="CASCADE"))

    request: Mapped["MonitoringRequestModel"] = relationship("MonitoringRequestModel", back_populates="vacancies")

    def get_keywords(self) -> list[str]:
        try:
            return json.loads(self.keywords)
        except Exception:
            return self.keywords.split(",") if self.keywords else []

    def set_keywords(self, items: list[str]):
        self.keywords = json.dumps(items)

    def __str__(self):
        return f"<VacancyModel {self.name}>"

    def __repr__(self):
        return str(self)


class MonitoringRequestModel(Base):
    id: Mapped[int_pk]
    position: Mapped[str]
    salary: Mapped[int]
    region: Mapped[str]
    experience: Mapped[str]

    vacancies = relationship("VacancyModel", back_populates="request", cascade="all, delete")

    def __str__(self):
        return f"<MonitoringRequestModel {self.position} in {self.region}>"

    def __repr__(self):
        return str(self)


class UserModel(Base):
    id: Mapped[int_pk]
    email: Mapped[str_uniq] = mapped_column(unique=True, nullable=False)
    hashed_password: Mapped[str]
    role: Mapped[str] = mapped_column(default="hr")  # можно admin потом добавить