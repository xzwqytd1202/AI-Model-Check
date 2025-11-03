import imaplib
import poplib
import email
from email.header import decode_header
from email.parser import BytesParser
from email.policy import default
import traceback
import requests
from datetime import datetime, timedelta

# ------------------- 工具函数 -------------------
def decode_with_fallback(bytes_data, charset=None):
    encodings = [charset] if charset else []
    encodings += ['utf-8', 'gbk', 'gb18030', 'iso-8859-1', 'windows-1252']
    for enc in encodings:
        if enc:
            try:
                return bytes_data.decode(enc)
            except UnicodeDecodeError:
                continue
    return str(bytes_data)

# ------------------- IMAP 相关 -------------------
def connect_imap(email_addr, password, imap_server, imap_port):
    mail = imaplib.IMAP4_SSL(imap_server, imap_port)
    mail.login(email_addr, password)
    mail.select("inbox")
    return mail

def fetch_email_list(mail, minutes_ago=None):
    search_criteria = "ALL"
    if minutes_ago:
        start_time = datetime.now() - timedelta(minutes=minutes_ago)
        since_date = start_time.strftime("%d-%b-%Y")
        search_criteria = f'(SINCE "{since_date}")'
    status, messages = mail.search(None, search_criteria)
    if status != "OK":
        raise Exception("Failed to search emails")
    return messages[0].split()

def get_email_date(mail, msg_id):
    status, msg = mail.fetch(msg_id, "(RFC822)")
    if status != "OK":
        return None
    email_msg = email.message_from_bytes(msg[0][1])
    date_str = email_msg["Date"]
    if date_str:
        try:
            email_date = email.utils.parsedate_to_datetime(date_str)
            if email_date.tzinfo is None:
                email_date = email_date.replace(tzinfo=datetime.now().astimezone().tzinfo)
            return email_date.replace(tzinfo=None)
        except:
            return None
    return None

def fetch_email_content_imap(mail, msg_id):
    status, msg = mail.fetch(msg_id, "(RFC822)")
    if status != "OK":
        raise Exception("Failed to fetch email")
    email_msg = email.message_from_bytes(msg[0][1])

    subject_parts = decode_header(email_msg["Subject"] or "")
    subject = ""
    for part, charset in subject_parts:
        if isinstance(part, bytes):
            subject += decode_with_fallback(part, charset)
        else:
            subject += part
    from_email = email.utils.parseaddr(email_msg["From"])[1]

    content = ""
    if email_msg.is_multipart():
        for part in email_msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset()
                content = decode_with_fallback(payload, charset)
                break
            elif part.get_content_type() == "text/html" and not content:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset()
                content = decode_with_fallback(payload, charset)
    else:
        payload = email_msg.get_payload(decode=True)
        charset = email_msg.get_content_charset()
        content = decode_with_fallback(payload, charset)

    return f"From: {from_email}\nSubject: {subject}\nContent: {content}"

# ------------------- POP3 相关 -------------------
def fetch_latest_email_pop3(email_addr, password, pop_server, pop_port):
    """仅获取最近一封邮件内容"""
    server = poplib.POP3_SSL(pop_server, pop_port)
    server.user(email_addr)
    server.pass_(password)

    num_messages = len(server.list()[1])
    if num_messages == 0:
        server.quit()
        return None, None

    resp, lines, octets = server.retr(num_messages)
    msg = BytesParser(policy=default).parsebytes(b"\r\n".join(lines))
    subject_parts = decode_header(msg["Subject"] or "")
    subject = ""
    for part, charset in subject_parts:
        if isinstance(part, bytes):
            subject += decode_with_fallback(part, charset)
        else:
            subject += part
    from_email = email.utils.parseaddr(msg["From"])[1]

    content = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset()
                content = decode_with_fallback(payload, charset)
                break
    else:
        payload = msg.get_payload(decode=True)
        charset = msg.get_content_charset()
        content = decode_with_fallback(payload, charset)

    server.quit()
    return subject, f"From: {from_email}\nSubject: {subject}\nContent: {content}"

# ------------------- 钓鱼检测与推送 -------------------
def predict_phishing(phishing_url, email_content):
    body = {"email_content": email_content}
    response = requests.post(phishing_url, json=body)
    data = response.json()
    return data.get("result")

def send_to_webhook(webhook_url, message):
    try:
        body = {
            "msgtype": "text",
            "text": {"content": message}
        }
        response = requests.post(webhook_url, json=body)
        if response.json().get("errcode") != 0:
            print("Failed to send to webhook")
        else:
            print("Message sent")
    except Exception as e:
        print("Webhook send error:", e)

# ------------------- 主逻辑 -------------------
def main(minutes, email_addr, password, imap_server, imap_port, webhook_url, phishing_api_url="http://localhost:8891/api/phishing/predict"):
    """
    检查邮箱钓鱼邮件（支持 IMAP/POP3 自动切换）
    """
    try:
        print(f"[*] 尝试通过 IMAP 连接 {imap_server}:{imap_port}")
        mail = connect_imap(email_addr, password, imap_server, imap_port)
        current_time = datetime.now()
        start_time = current_time - timedelta(minutes=minutes)
        email_ids = fetch_email_list(mail, minutes)

        filtered_emails = []
        phishing_count = 0

        for email_id in email_ids:
            email_date = get_email_date(mail, email_id)
            if email_date and start_time <= email_date <= current_time:
                filtered_emails.append(email_id)

        print(f"找到 {len(filtered_emails)} 封邮件在过去 {minutes} 分钟内 for {email_addr}")

        for email_id in filtered_emails:
            content = fetch_email_content_imap(mail, email_id)
            is_phishing = predict_phishing(phishing_api_url, content)
            result = "phishing" if is_phishing == "Phishing" else "Safe"
            if is_phishing == "Phishing":
                phishing_count += 1
                message = f"⚠️ 钓鱼邮件警报!\nEmail ID: {email_id.decode()}\nResult: {result}\nDetails: {content[:200]}..."
                send_to_webhook(webhook_url, message)

        mail.logout()
        return {'email_ids': [eid.decode() for eid in filtered_emails], 'phishing_count': phishing_count}

    except Exception as e_imap:
        print(f"[!] IMAP 模式失败: {repr(e_imap)}")
        print(traceback.format_exc())
        print("[*] 尝试使用 POP3 模式重新连接...")

        try:
            subject, content = fetch_latest_email_pop3(email_addr, password, imap_server, 995)
            if not content:
                print("POP3 邮箱为空，无需检测。")
                return {'email_ids': [], 'phishing_count': 0}

            is_phishing = predict_phishing(phishing_api_url, content)
            result = "phishing" if is_phishing == "Phishing" else "Safe"
            phishing_count = 1 if is_phishing == "Phishing" else 0

            if is_phishing == "Phishing":
                message = f"⚠️ 钓鱼邮件警报!\nEmail: {email_addr}\nResult: {result}\nSubject: {subject[:100]}"
                send_to_webhook(webhook_url, message)

            return {'email_ids': [subject or "last_mail"], 'phishing_count': phishing_count}

        except Exception as e_pop:
            print(f"[X] POP3 模式也失败: {repr(e_pop)}")
            print(traceback.format_exc())
            error_message = f"❌ 邮件检测出错!\n邮箱: {email_addr}\nIMAP错误: {str(e_imap)}\nPOP3错误: {str(e_pop)}"
            send_to_webhook(webhook_url, error_message)
            return {'email_ids': [], 'phishing_count': 0}
