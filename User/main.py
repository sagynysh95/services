from fastapi import FastAPI
from routes import router
from mongo_file import setup_mongo
from dotenv import load_dotenv

app = FastAPI()

load_dotenv()
setup_mongo()

app.include_router(router=router)