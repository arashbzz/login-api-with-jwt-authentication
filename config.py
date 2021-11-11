from os import getenv

class Config:
    server = getenv("server")
    database = getenv("database")
    SECRET_KEY = getenv('SECRET_KEY')
