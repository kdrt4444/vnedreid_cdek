import httpx
from fastapi import FastAPI, Response, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from authx import AuthX
from authx.exceptions import JWTDecodeError
from fastapi.middleware.cors import CORSMiddleware

from backend.core.config import config
from backend.core.database import SessionDep

from backend.models.models import UserModel, MonitoringRequestModel
from backend.schemas import UserLogin, MonitoringRequestCreate

from passlib.context import CryptContext

from backend.service.hh_runner import parse_dicts_to_models

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
)

security = AuthX(config=config)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.exception_handler(JWTDecodeError)
async def jwt_expired_handler(request: Request, exc: JWTDecodeError):
    return JSONResponse(
        status_code=401,
        content={"detail": "Срок действия токена истёк. Пожалуйста, выполните вход заново."},
    )

@app.post("/login")
async def login(credentials: UserLogin, response: Response, session: SessionDep):
    stmt = select(UserModel).where(UserModel.email == credentials.email)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not pwd_context.verify(credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    token = security.create_access_token(uid=str(user.id))
    response.set_cookie(config.JWT_ACCESS_COOKIE_NAME, token, httponly=True)
    return {"access_token": token, "message": "Login successful"}

async def run_hh_parser(text: str) -> str:
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post("http://hh_parser:8000/parse/", json={"text": text})
        response.raise_for_status()
        data = response.json()
        return data["vacancies"]

@app.post("/monitoring")
async def monitor(payload: MonitoringRequestCreate, session: SessionDep, user=Depends(security.access_token_required)):
    # 1. Сохраняем запрос
    request = MonitoringRequestModel(
        salary= payload.salary,
        position=payload.position,
        region=payload.region,
        experience=payload.experience,
    )
    session.add(request)
    await session.flush()  # чтобы получить ID
    await session.commit()

    # 2. Запускаем парсер
    csv_path = await run_hh_parser(text=f"{payload.position}")
    print(f"csv_path: {csv_path}")
    # 3. Считываем CSV и сохраняем вакансии
    all_vacancies = await parse_dicts_to_models(csv_path, request_id=request.id)
    filtered_vacancies = [v for v in all_vacancies if v.employer != ""]
    # filtered_vacancies = all_vacancies
    session.add_all(filtered_vacancies)
    await session.commit()

    # 4. Вернуть количество или вызвать аналитик
    return {"vacancies_found": len(filtered_vacancies),
            "vacancies": filtered_vacancies
            }


