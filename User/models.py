from pydantic import BaseModel, Field, EmailStr, model_validator
from typing import Optional
from mongo_file import mongo_get_username
from utils.validate_password import validate_password
from utils.generate_password import generate_password
from utils.cyrillic_latin import cyrillic_to_latin
import re
import hashlib
from datetime import datetime
from enum import Enum
from logger import logger


class Gender(str, Enum):
    MALE = "male"
    FEMALE = "female"


class EmployeeRole(str, Enum):
    EMPLOYEE = "employee"
    GUEST = "guest"
    ADMINISTRATOR = "administrator"


class User(BaseModel):
    name: Optional[str] = Field(
        default=None,
        description="Имя пользователя на кириллице"
    )
    surname: Optional[str] = Field(
        default=None,
        description="Фамилия пользователя на кириллице"
    )
    father_name: Optional[str] = Field(
        default=None,
        description="Отчество пользователя на кириллице"
    )
    email: Optional[EmailStr] = Field(
        default=None,
        description="Валидный емайл"
    )
    iin: Optional[str] = Field(
        default=None,
        description="ИИН должен содержать 12 цифр",
        pattern=r"^\d{12}$"
    )
    birth_date: Optional[str] = Field(
        default=None,
        description="Дата рождения в формате YYYY-MM-DD",

    )
    role: EmployeeRole = Field(
        default=None,
        description="Сотрудник, посетитель или админ"
    )
    phone_number: Optional[str] = Field(
        default=None,
        pattern=r"^(?:\+7|8)\d{10}$"
    )
    rank: Optional[str] = Field(
        default=None,
        examples=["майор", "капитан", "полковник"],
        description="Военное звание пользователя если есть"
    )
    military_unit: Optional[str] = Field(
        default=None, 
        description="Наименование части где работает пользователь если есть"
    )
    department: Optional[str] = Field(
        default=None,
        description="Департамент где работает пользователь"
    )
    gender: Gender = Field(
        default=None,
        description="Пол пользователя"
    )
    marital_status: Optional[str] = Field(
        default=None,
        description="Семейное положение"
    )
    address: Optional[str] = Field(
        default=None
    )
    education_level: Optional[str] = Field(
        default=None
    )
    languages_spoken: Optional[str] = Field(
        default=None
    )
    comments: Optional[str] = Field(
        default=None,
        description="Комментарий"
    )

    @model_validator(mode="before")
    def validate_birth_date(cls, values):
        birth_date = values.get("birth_date")
        if birth_date is None:
            return values 

        try:
            dob = datetime.strptime(birth_date, "%Y-%m-%d")
        except ValueError:
            raise ValueError("Дата рождения должна быть в формате YYYY-MM-DD.")

        if dob > datetime.now():
            raise ValueError("Дата рождения не может быть в будущем.")

        if (datetime.now() - dob).days / 365 > 150:
            raise ValueError("Возраст не может превышать 150 лет.")

        return values

class UserCreate(User):
    user_id: Optional[str] = Field(
        default=None,
        description="Генерирует автоматический"
    )
    img_path: Optional[str] = Field(
        default=None,
        description="Вставляется автоматический, это ссылка на фото пользователя"
    )
    username: Optional[str] = Field(
        default=None,
        description="Генерируется автоматический"
    )
    password: Optional[str] = Field(
        default="123456",
        # default_factory=generate_password,
        description="Генерируется автоматический первый раз"
    )
    created_at: Optional[datetime] = Field(
        default_factory=datetime.now
    )
    
    @model_validator(mode="before")
    def generate_username(cls, values):
        name = values.get("name").lower()
        surname = values.get("surname").lower()
        username = cyrillic_to_latin(f"{name[:1]}.{surname}")
        if mongo_get_username(username):
            values["username"] = username
        else:
            values["username"] = cyrillic_to_latin(f"{name}.{surname}")
        return values
    
    @model_validator(mode="after")
    def validate_password(self):
        password = self.password
        logger.info(password)
        if not isinstance(password, str):
            raise ValueError("Пароль должен быть строкой.")
        
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        self.password = str(hashed_password)
        return self


class UserRead(User):
    user_id: Optional[str] = Field(
        default=None,
        description="Генерирует автоматический"
    )
    img_path: Optional[str] = Field(
        default=None,
        description="Вставляется автоматический, это ссылка на фото пользователя"
    )
    username: Optional[str] = Field(
        default=None,
        description="Генерируется автоматический"
    )
    password: Optional[str] = Field(
        default=None,
        description="По умолчанию 123456"
    )
    created_at: Optional[datetime] = Field(
        default=None,
    )

    # @model_validator(mode="before")
    # def validate_password(cls, values):
    #     password = values.get("password")
    #     if not password:
    #         return values
    #     print(password)
    #     if not isinstance(password, str):
    #         raise ValueError("Пароль должен быть строкой.")
    #     pattern = (
    #         r"^(?=.*[a-z])"        # хотя бы одна строчная буква
    #         r"(?=.*[A-Z])"         # хотя бы одна заглавная буква
    #         r"(?=.*\d)"            # хотя бы одна цифра
    #         r"(?=.*[!@#$%^&*])"    # хотя бы один специальный символ
    #         r".{8,20}$"            # длина от 8 до 20 символов
    #     )
    #     if not re.match(pattern, password):
    #         raise ValueError(
    #             "Пароль должен содержать от 8 до 20 символов, включая строчные и заглавные буквы, цифры и специальные символы."
    #         )
    #     hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    #     values["password"] = str(hashed_password)
    #     return values
    

class UserUpdate(UserRead):

    @model_validator(mode="before")
    def validate_password(cls, values):
        password = values.get("password")
        if not password:
            return values
        print(password)
        if not isinstance(password, str):
            raise ValueError("Пароль должен быть строкой.")
        pattern = (
            r"^(?=.*[a-z])"        # хотя бы одна строчная буква
            r"(?=.*[A-Z])"         # хотя бы одна заглавная буква
            r"(?=.*\d)"            # хотя бы одна цифра
            r"(?=.*[!@#$%^&*])"    # хотя бы один специальный символ
            r".{8,20}$"            # длина от 8 до 20 символов
        )
        if not re.match(pattern, password):
            raise ValueError(
                "Пароль должен содержать от 8 до 20 символов, включая строчные и заглавные буквы, цифры и специальные символы."
            )
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        values["password"] = str(hashed_password)
        return values

    
    
