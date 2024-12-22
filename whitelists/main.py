from fastapi import FastAPI
from routes import router
from dotenv import load_dotenv


app = FastAPI()

load_dotenv()
app.include_router(router=router)