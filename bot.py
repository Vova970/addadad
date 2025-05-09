from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import WebAppInfo
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web
import logging

# Настройка логгирования
logging.basicConfig(level=logging.INFO)

# Инициализация бота
bot = Bot(token="8167920353:AAELgjCtw3zYadW1Mc6sWH-7an0JQ3sg3Ns")
dp = Dispatcher()

# Команда /start
@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    builder = InlineKeyboardBuilder()
    builder.button(
        text="Авторизоваться на сайте", 
        web_app=WebAppInfo(url="https://ваш-сайт/auth/telegram")
    )
    
    await message.answer(
        "Добро пожаловать! Для авторизации на сайте нажмите кнопку ниже:",
        reply_markup=builder.as_markup()
    )

# Обработка данных из WebApp
@dp.message()
async def handle_web_app_data(message: types.Message):
    if message.web_app_data:
        user_id = message.from_user.id
        first_name = message.from_user.first_name
        
        await message.answer(
            "✅ Вы успешно авторизовались. Можете вернуться на сайт.",
            reply_markup=types.ReplyKeyboardRemove()
        )

# Запуск бота
async def on_startup(bot: Bot):
    await bot.delete_webhook()
    await bot.set_webhook("https://ваш-домен.ру/bot_path")

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())