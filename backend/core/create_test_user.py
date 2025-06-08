import asyncio

from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import async_session_maker
from backend.models.models import UserModel

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def create_user():
    async with async_session_maker() as session:  # type: AsyncSession
        user = UserModel(
            email="hr@example.com",
            hashed_password=pwd_context.hash("hrpassword123"),
            role="hr"
        )
        session.add(user)
        await session.commit()
        print("✅ Пользователь создан: hr@example.com / hrpassword123")

if __name__ == "__main__":
    asyncio.run(create_user())
