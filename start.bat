@echo off
REM 
call .\env\Scripts\activate.bat

REM 
pip install -r requirements.txt

REM 
start python manage.py runserver

REM 
start http://127.0.0.1:8000

pause
