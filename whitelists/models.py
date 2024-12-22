from pydantic import BaseModel, Field, model_validator, root_validator
from typing import Optional
from datetime import datetime, timedelta, time
from enum import Enum
from fastapi import HTTPException
from dateutil.relativedelta import relativedelta
from mongo_file import mongo_find_by_user_id
from logger import logger


class WeekdayEnum(str, Enum):
    monday = "Monday"
    tuesday = "Tuesday"
    wednesday = "Wednesday"
    thursday = "Thursday"
    friday = "Friday"
    saturday = "Saturday"
    sunday = "Sunday"


class MonthEnum(str, Enum):
    january = "January"
    february = "February"
    march = "March"
    april = "April"
    may = "May"
    June = "June"
    july = "July"
    august = "August"
    september = "September"
    october = "October"
    november = "November"
    december = "December"


class WhitelistBase(BaseModel):
    user_id: Optional[str] = Field(
        default=None
    )
    start_time: Optional[str] = Field(
        default=None,
        description="start time for permission",
        examples=["2024-12-12 18:12:00"]
    )
    end_time: Optional[str] = Field(
        default=None, 
        description="permission expiration time",
        examples=["2024-12-24 00:00:00"]
    )
    weekday: Optional[WeekdayEnum] = Field(
        default=None,
        description="exact weekday for permission"
    )
    month: Optional[MonthEnum] = Field(
        default=None,
        description="exact month for permission"
    )
    hours_start: Optional[str] = Field(
        default=None,
        description="start hour for permission, format '23:48'"
    )
    hours_end: Optional[str] = Field(
        default=None,
        description="end hour for permission, format '09:15'"
    )


class WhitelistCreate(WhitelistBase):
    user_id: str
    minutes: Optional[int] = Field(
        default=None,
        description="minutes for permission, end_time calculates automatically"
    )
    hours: Optional[int] = Field(
        default=None,
        description="hours for permission, end_time calculates automatically"
    )
    days: Optional[int] = Field(
        default=None,
        description="days for permission, end_time calculates automatically"
    )
    weeks: Optional[int] = Field(
        default=None,
        description="weeks for adding to calculate permission end_time"
    )
    months: Optional[int] = Field(
        default=None,
        description="months for adding to calculate permission end_time"
    ) 
    years: Optional[int] = Field(
        default=None,
        description="years for adding to calculate permission end_time"
    ) 
    

    @model_validator(mode="before")
    def validate_times(cls, values):
        start_time = values.get("start_time")
        end_time = values.get("end_time")

        if values.get("end_time") and any([values.get("hours"), values.get("minutes"), values.get("days"), values.get("weeks"), values.get("months"), values.get("years")]):
            raise HTTPException(status_code=422, detail="end_time is defined, no need for days, months, etc")

        if start_time is None:
            values["start_time"] = datetime.now().replace(microsecond=0)
            start_time = values["start_time"]
        else:
            try:
                # logger.info(f"СТАРТ ТАЙМ {start_time}")
                if len(start_time) == 10:
                    start_time += " 00:00:00"
                if len(end_time) == 10:
                    end_time += " 00:00:00"
                start_time = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                end_time = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                raise HTTPException(status_code=422, detail="start_time format must be 'YYYY-MM-DD HH:MM:SS'")
        
        if start_time and end_time:
            values["start_time"] = str(start_time)
            values["end_time"] = str(end_time)
            return values
        
        values["start_time"] = str(start_time)
        end_time = start_time

        if values.get("minutes"):
            end_time += timedelta(minutes=values["minutes"])
        if values.get("hours"):
            end_time += timedelta(hours=values["hours"])
        if values.get("days"):
            end_time += timedelta(days=values["days"])
        if values.get("weeks"):
            end_time += timedelta(weeks=values["weeks"])
        if values.get("months"):
            end_time += relativedelta(months=+values["months"])
        if values.get("years"):
            values["end_time"] = str(end_time.replace(year=end_time.year + values["years"]))
        else:
            values["end_time"] = str(end_time)
        return values

    @model_validator(mode="after")
    def check_duration_consistency(self):
        if self.start_time and self.end_time:
            start_dt = datetime.strptime(self.start_time, "%Y-%m-%d %H:%M:%S")
            end_dt = datetime.strptime(self.end_time, "%Y-%m-%d %H:%M:%S")
            if end_dt <= start_dt:
                raise HTTPException(detail="end_time must be after start_time")
        return self
    
    @model_validator(mode="after")
    def check_duration_hours(self):
        if (not self.hours_start and self.hours_end) or (not self.hours_end and self.hours_start):
            raise HTTPException(status_code=400, detail=f"Error: Both hours_start and hours_end must be defined or none of them")
        if self.hours_end and self.hours_start:
            if len(self.hours_start) == 5:
                self.hours_start += ":00"
            if len(self.hours_end) == 5:
                self.hours_end += ":00"
            hours_start = datetime.strptime(self.hours_start, "%H:%M:%S").time()
            hours_end = datetime.strptime(self.hours_end, "%H:%M:%S").time()
            if hours_end <= hours_start:
                raise HTTPException(detail="hours_end must be after hours_start")
        return self


class WhitelistUpdate(WhitelistBase):


    @model_validator(mode="before")
    def check_dates_hours(cls, values):
        start_time = values.get("start_time")
        end_time = values.get("end_time")
        hours_start = values.get("hours_start")
        hours_end = values.get("hours_end")

        if start_time and len(start_time) == 10:
            start_time += " 00:00:00"
        if end_time and len(end_time) == 10:
            end_time += " 00:00:00"
        if hours_start and len(hours_start) == 5:
            hours_start += ":00"
        if hours_end and len(hours_end) == 5:
            hours_end += ":00"

        values["start_time"] = start_time
        values["end_time"] = end_time
        values["hours_start"] = hours_start
        values["hours_end"] = hours_end

        user_id = values.get("user_id")
        if not user_id:
            raise HTTPException(status_code=400, detail="Error: user_id not given")

        # date
        if start_time and end_time:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            if end_dt <= start_dt:
                raise HTTPException(status_code=400, detail="end_time must be after start_time")
        
        if start_time:
            result = mongo_find_by_user_id(user_id)
            end_time = result["end_time"]

            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            if end_dt <= start_dt:
                raise HTTPException(status_code=400, detail="end_time must be after start_time")
        
        if end_time:
            result = mongo_find_by_user_id(user_id)
            start_time = result["start_time"]

            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            if end_dt <= start_dt:
                raise HTTPException(status_code=400, detail="end_time must be after start_time")
        
        # hours
        if hours_start and hours_end:
            start_dt_hour = datetime.strptime(hours_start, "%H:%M:%S").time()
            end_dt_hour = datetime.strptime(hours_end, "%H:%M:%S").time()
            if end_dt_hour <= start_dt_hour:
                raise HTTPException(status_code=400, detail="hours_end must be after hours_start")
        
        if hours_start:
            result = mongo_find_by_user_id(user_id)
            hours_end = result["hours_end"]

            start_dt_hour = datetime.strptime(hours_start, "%H:%M:%S").time()
            end_dt_hour = datetime.strptime(hours_end, "%H:%M:%S").time()
            if end_dt_hour <= start_dt_hour:
                raise HTTPException(status_code=400, detail="hours_end must be after hours_start")
        
        if hours_end:
            result = mongo_find_by_user_id(user_id)
            hours_start = result["hours_start"]

            start_dt_hour = datetime.strptime(hours_start, "%H:%M:%S").time()
            end_dt_hour = datetime.strptime(hours_end, "%H:%M:%S").time()
            if end_dt_hour <= start_dt_hour:
                raise HTTPException(status_code=400, detail="hours_end must be after hours_start")
        
        return values
    


    


