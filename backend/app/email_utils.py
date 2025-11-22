import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import random
import string

def generate_otp(length=6):
    """Gera um código numérico de 6 dígitos"""
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(to_email: str, code: str):
    smtp_server = "smtp.gmail.com"
    smtp_port = 465
    sender_email = os.getenv("MAIL_USERNAME")
    password = os.getenv("MAIL_PASSWORD")

    if not sender_email or not password:
        print("❌ Erro: Credenciais de e-mail não configuradas no .env")
        return False

    subject = "Seu Código de Verificação - Secure Chat"
    body = f"""
    <html>
      <body>
        <h2>Olá!</h2>
        <p>Seu código de verificação para entrar no Secure Chat é:</p>
        <h1 style="color: #4CAF50; letter-spacing: 5px;">{code}</h1>
        <p>Este código expira em 5 minutos.</p>
        <p>Se você não solicitou este código, ignore este e-mail.</p>
      </body>
    </html>
    """

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, to_email, message.as_string())
        print(f"✅ E-mail de OTP enviado para {to_email}")
        return True
    except Exception as e:
        print(f"❌ Falha ao enviar e-mail: {e}")
        return False