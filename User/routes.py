from fastapi import APIRouter, HTTPException, Query
from models import User, UserCreate, UserRead, UserUpdate
from minio_file import upload_photo_minio
from mongo_file import (mongo_insert_and_return, mongo_update_one, 
                        mongo_delete_one, mongo_get, mongo_get_query, count_documents)
from typing import List, Optional

router = APIRouter(tags=["users"])


@router.post("/", status_code=201, response_model=UserRead)
def create_user(employee: User):
    try:
        file_path = upload_photo_minio(employee.name, employee.surname, employee.iin)
        result = UserCreate(**employee.dict(), img_path=file_path)
        result = mongo_insert_and_return(result)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Error: {e}")
    return UserRead.model_validate(result)


@router.get("/", status_code=200, response_model=List[UserRead])
def get_users():
    try:
        result = mongo_get()
        return [UserRead(**data) for data in result]
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Error: {e}")


@router.get("/find", response_model=dict)
def find_users(
    skip: int = Query(0),
    limit: int = Query(100),
    username: Optional[str] = None,
    name: Optional[str] = None,
    surname: Optional[str] = None,
    father_name: Optional[str] = None,
    email: Optional[str] = None,
    iin: Optional[str] = None,
    role: Optional[str] = None,
    phone_number: Optional[str] = None,
    rank: Optional[str] = None,
    military_unit: Optional[str] = None,
    user_id: Optional[str] = None,
):
    try:
        query = {}

        if username:
            query["username"] = username
        if name:
            query["name"] = name
        if surname:
            query["surname"] = surname
        if father_name:
            query["father_name"] = father_name
        if email:
            query["email"] = email
        if iin:
            query["iin"] = iin
        if role:
            query["role"] = role
        if phone_number:
            query["phone_number"] = phone_number
        if rank:
            query["rank"] = rank
        if military_unit:
            query["military_unit"] = military_unit
        if user_id:
            query["user_id"] = user_id
        
        total_count = count_documents(query)
        result = mongo_get_query(query, skip, limit)
        return {"totalCount": total_count, "users": result}
    
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Error: {e}")
    


@router.put("/", status_code=200, response_model=dict)
def update_user(user_id: str, employee: UserUpdate):
    try:
        update_data = employee.model_dump(exclude_none=True)
        if not update_data:
            raise HTTPException(status_code=400, detail="no data for")
        result = mongo_update_one(user_id, update_data)

        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        return {"updated": "Data was successfully updated"}
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Error: {e}")
    

@router.delete("/{user_id}", status_code=200, response_model=dict)
def delete_user(user_id: str):
    try:
        result = mongo_delete_one(user_id)
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        return {"deleted": "User wa deleted"}
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Error: {e}")
