from enum import Enum
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class VacancyBase(BaseModel):
    employer: str
    name: str
    salary: bool
    salary_min: int
    salary_max: int
    experience: str
    schedule: str
    keywords: List[str]
    description: str
    source: str = "HH.ru"

    model_config = ConfigDict(from_attributes=True)


class VacancyCreate(VacancyBase):
    request_id: int


class VacancyRead(VacancyBase):
    id: int
    request_id: int
    created_at: datetime
    updated_at: datetime


class MonitoringRequestBase(BaseModel):
    position: str
    salary: int
    region: str
    experience: str

    model_config = ConfigDict(from_attributes=True)


class MonitoringRequestCreate(MonitoringRequestBase):
    pass


class MonitoringRequestRead(MonitoringRequestBase):
    id: int
    created_at: datetime
    updated_at: datetime
    vacancies: Optional[List[VacancyRead]] = []


class AnalyticsResult(BaseModel):
    distribution_salary: float
    vacancies_found: int
    median_salary: int
    min_salary: int
    max_salary: int
    benefits: List[str]
    suggested_indexation: str


class UserCreate(BaseModel):
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: int
    email: str
    role: str

    model_config = ConfigDict(from_attributes=True)
