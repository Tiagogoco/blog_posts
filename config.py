# SQLITE = "sqlite:///project.db"
POSTGRESQL = 'postgresql+psycopg2://postgres:123@localhost:5432/blogposts_db'
class Config:
    DEBUG = True
    SECRET_KEY = 'dev'
    SQLALCHEMY_DATABASE_URI = POSTGRESQL
