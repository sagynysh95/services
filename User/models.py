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
        description="User name"
    )
    surname: Optional[str] = Field(
        default=None,
        description="User surname"
    )
    father_name: Optional[str] = Field(
        default=None,
        description="User middle name"
    )
    email: Optional[EmailStr] = Field(
        default=None,
        description="Valid email"
    )
    iin: Optional[str] = Field(
        default=None,
        description="IIN must contain 12 digits",
        pattern=r"^\d{12}$"
    )
    birth_date: Optional[str] = Field(
        default=None,
        description="Birth date format YYYY-MM-DD",

    )
    role: EmployeeRole = Field(
        default=None,
        description="employee, guest or administrator"
    )
    phone_number: Optional[str] = Field(
        default=None,
        pattern=r"^(?:\+7|8)\d{10}$"
    )
    rank: Optional[str] = Field(
        default=None,
        examples=["Major", "Captain", "Colonel"],
        description="User's military rank"
    )
    military_unit: Optional[str] = Field(
        default=None, 
        description="The name of military unit where user works"
    )
    department: Optional[str] = Field(
        default=None,
        description="Department where user works"
    )
    gender: Gender = Field(
        default=None,
        description="User's gender"
    )
    marital_status: Optional[str] = Field(
        default=None,
        description="Marital status of user"
    )
    address: Optional[str] = Field(
        default=None,
        description="Address where user lives"
    )
    education_level: Optional[str] = Field(
        default=None,
        description="User's educational level",
        examples=["bachelor's degree", "master's degree"]
    )
    languages_spoken: Optional[str] = Field(
        default=None,
        description="languages spoken by the user"
    )
    comments: Optional[str] = Field(
        default=None,
        description="Any comments"
    )

    @model_validator(mode="before")
    def validate_birth_date(cls, values):
        birth_date = values.get("birth_date")
        if birth_date is None:
            return values 

        try:
            dob = datetime.strptime(birth_date, "%Y-%m-%d")
        except ValueError:
            raise ValueError("The date of birth must be in the YYYY-MM-DD format.")

        if dob > datetime.now():
            raise ValueError("The date of birth cannot be in the future.")

        if (datetime.now() - dob).days / 365 > 150:
            raise ValueError("The age may not exceed 150 years.")

        return values

class UserCreate(User):
    user_id: Optional[str] = Field(
        default=None,
        description="Generates an automatic"
    )
    img_path: Optional[str] = Field(
        default=None,
        description="It is inserted automatically, this is a link to the user's photo"
    )
    username: Optional[str] = Field(
        default=None,
        description="Generates automatically by user name and surname"
    )
    password: Optional[str] = Field(
        default="123456",
        # default_factory=generate_password,
        description="It is '123456' by default. Need to be updated by user"
    )
    created_at: Optional[datetime] = Field(
        default_factory=datetime.now,
        description="Time when user's account was created"
    )
    updated_at: Optional[datetime] = Field(
        default_factory=datetime.now,
        description="Time when user updated information"
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
            raise ValueError("Password must be a string")
        
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        self.password = str(hashed_password)
        return self


class UserRead(User):
    user_id: Optional[str] = Field(
        default=None
    )
    img_path: Optional[str] = Field(
        default=None
    )
    username: Optional[str] = Field(
        default=None
    )
    password: Optional[str] = Field(
        default=None
    )
    created_at: Optional[datetime] = Field(
        default=None
    )
    updated_at: Optional[datetime] = Field(
        default=None
    )
    

class UserUpdate(UserRead):
    updated_at: Optional[datetime] = Field(
        default_factory=datetime.now
    )

    @model_validator(mode="before")
    def validate_password(cls, values):
        password = values.get("password")
        if not password:
            return values
        print(password)
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        pattern = (
            r"^(?=.*[a-z])"        # хотя бы одна строчная буква
            r"(?=.*[A-Z])"         # хотя бы одна заглавная буква
            r"(?=.*\d)"            # хотя бы одна цифра
            r"(?=.*[!@#$%^&*])"    # хотя бы один специальный символ
            r".{8,20}$"            # длина от 8 до 20 символов
        )
        if not re.match(pattern, password):
            raise ValueError(
                "The password must contain from 8 to 20 characters, including lowercase and uppercase letters, numbers, and special characters."
            )
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        values["password"] = str(hashed_password)
        return values

    
    
