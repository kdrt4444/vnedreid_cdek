import httpx
import csv
import json
import ast
from backend.models.models import VacancyModel


async def parse_dicts_to_models(rows: list[dict], request_id: int) -> list[VacancyModel]:
    vacancies = []
    for row in rows:
        try:
            raw_keywords = row.get("Keys", "[]")
            keywords_list = ast.literal_eval(raw_keywords) if raw_keywords else []
        except Exception:
            keywords_list = []

        vacancy = VacancyModel(
            employer=row.get("Employer", "не указано"),
            name=row.get("Name", "Без названия"),
            salary=bool(row.get("Salary")),
            salary_min=int(float(row.get("From") or 0)) if row.get("From") else None,
            salary_max=int(float(row.get("To") or 0)) if row.get("To") else None,
            experience=str(row.get("Experience") or "Без опыта"),
            schedule=row.get("Schedule", "не указано"),
            keywords=json.dumps(keywords_list),
            description=row.get("Description", ""),
            request_id=request_id,
            source=row.get("Source", "") or "hh.ru",
        )

        vacancies.append(vacancy)

    return vacancies
