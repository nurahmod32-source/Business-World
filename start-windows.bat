@echo off
npm install
if not exist .env copy .env.example .env
echo Edit .env and set ADMIN_PASSWORD and SESSION_SECRET before running publicly.
npm start
pause
