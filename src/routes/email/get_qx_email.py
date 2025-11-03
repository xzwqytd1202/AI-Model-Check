# get_qx_email.py
# 整合版：优先 IMAP，失败回退 POP3；支持查找过去 N 分钟内的所有邮件并逐封检测
import imaplib
import poplib
import email
from email.header import decode_header
from email.parser import BytesParser
from email.policy import default
import requests
import json
import time
import traceback
from datetime import datetime, timedelta

# ---------- 配置说明 ----------
# main(minutes, email_addr, password, imap_server, imap_port, webhook_url, phishing_api_url)
# 示例:
# main(60, "a@x.com", "passwd", "mail.example.com", 993, "https://qywx.webhook.url")
# --------------------------------

# 常用编码回退表
DEFAULT_ENCODINGS = ['utf-8', 'gbk', 'gb18030', 'iso-8859-1', 'windows-1252']


def decode_with_fallback(bytes_data, charset=None):
    """尝试用 charset 解码，若失败使用预定义编码回退；异常时返回原始字符串表示"""
    if bytes_data is None:
        return ""
    if isinstance(bytes_data, str):
        return bytes_data
    encs = [charset] if charset else []
    encs += [e for e in DEFAULT_ENCODINGS if e and e not in encs]
    for enc in encs:
        if not enc:
            continue
        try:
            return bytes_data.decode(enc, errors='ignore')
        except Exception:
            continue
    try:
        return bytes_data.decode('utf-8', errors='ignore')
    except Exception:
        return str(bytes_data)


def connect_imap(email_addr, password, imap_server, imap_port, timeout=10):
    """创建 IMAP SSL 连接并登录，抛出异常由调用方处理"""
    mail = imaplib.IMAP4_SSL(imap_server, imap_port, timeout=timeout)
    mail.login(email_addr, password)
    mail.select("INBOX")
    return mail


def fetch_emails_imap(mail, minutes):
    """
    使用 IMAP 检索过去 minutes 分钟内的所有邮件，返回列表，元素结构与 POP3 方法一致：
    [{ "subject":..., "from":..., "date": datetime, "content": ... }, ...]
    """
    results = []
    current_time = datetime.now()
    start_time = current_time - timedelta(minutes=minutes)

    # 使用 ALL + 按邮件逐个判断时间（因为 IMAP SINCE 只按天）
    status, data = mail.search(None, "ALL")
    if status != "OK":
        return results

    msg_ids = data[0].split()
    # 遍历从最新到最旧（可缩短数量以防超时）
    for msg_id in reversed(msg_ids):
        try:
            status, msg_data = mail.fetch(msg_id, "(RFC822)")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)

            # 解析 Date
            date_str = msg.get("Date")
            if not date_str:
                continue
            try:
                email_date = email.utils.parsedate_to_datetime(date_str)
                if email_date.tzinfo is None:
                    email_date = email_date.replace(tzinfo=datetime.now().astimezone().tzinfo)
                # remove tzinfo for comparison
                email_date = email_date.replace(tzinfo=None)
            except Exception:
                continue

            if not (start_time <= email_date <= current_time):
                # 如果邮件早于时间窗口，continue（因为我们是从新到旧，遇到早于窗口后可以继续检查，但不跳出，防止间断）
                continue

            # 解析主题
            subject_parts = decode_header(msg.get("Subject", ""))
            subject = ""
            for part, charset in subject_parts:
                if isinstance(part, bytes):
                    subject += decode_with_fallback(part, charset)
                else:
                    subject += str(part)

            from_email = email.utils.parseaddr(msg.get("From", ""))[1]

            # 解析正文（优先 text/plain）
            content = ""
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    disp = str(part.get("Content-Disposition"))
                    if ctype == "text/plain" and 'attachment' not in disp:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset()
                        content = decode_with_fallback(payload, charset)
                        break
                if not content:
                    # fallback to first text/html
                    for part in msg.walk():
                        if part.get_content_type() == "text/html":
                            payload = part.get_payload(decode=True)
                            charset = part.get_content_charset()
                            content = decode_with_fallback(payload, charset)
                            break
            else:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset()
                content = decode_with_fallback(payload, charset)

            results.append({
                "subject": subject,
                "from": from_email,
                "date": email_date,
                "content": f"From: {from_email}\nSubject: {subject}\nContent: {content}"
            })
        except Exception:
            # 解析单封邮件异常，不影响其他邮件
            continue

    return results


def fetch_recent_emails_pop3(email_addr, password, pop_server, pop_port, minutes, max_check=200):
    """
    使用 POP3_SSL 检索过去 minutes 分钟内的所有邮件。
    max_check: 最多遍历的最近邮件数（倒序），防止邮件数太多导致超时。
    返回格式同 IMAP。
    """
    results = []
    try:
        server = poplib.POP3_SSL(pop_server, pop_port, timeout=10)
        server.user(email_addr)
        server.pass_(password)
    except Exception as e:
        raise

    try:
        resp, listings, octets = server.list()
        # listings 中每行 "num size"
        total = len(listings)
        if total == 0:
            server.quit()
            return []

        current_time = datetime.now()
        start_time = current_time - timedelta(minutes=minutes)

        # 遍历最近 total -> 1，最多检查 max_check 封
        checked = 0
        for i in range(total, 0, -1):
            if checked >= max_check:
                break
            try:
                resp, lines, octets = server.retr(i)
                raw = b"\r\n".join(lines)
                msg = BytesParser(policy=default).parsebytes(raw)

                # 解析 Date
                date_str = msg.get("Date")
                if not date_str:
                    continue
                try:
                    email_date = email.utils.parsedate_to_datetime(date_str)
                    if email_date.tzinfo is None:
                        email_date = email_date.replace(tzinfo=datetime.now().astimezone().tzinfo)
                    email_date = email_date.replace(tzinfo=None)
                except Exception:
                    continue

                # 若邮件早于时间窗口则跳过
                if not (start_time <= email_date <= current_time):
                    checked += 1
                    continue

                # 解析主题
                subject_parts = decode_header(msg.get("Subject", ""))
                subject = ""
                for part, charset in subject_parts:
                    if isinstance(part, bytes):
                        subject += decode_with_fallback(part, charset)
                    else:
                        subject += str(part)

                from_email = email.utils.parseaddr(msg.get("From", ""))[1]

                # 解析正文
                content = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        disp = str(part.get("Content-Disposition"))
                        if ctype == "text/plain" and 'attachment' not in disp:
                            payload = part.get_payload(decode=True)
                            charset = part.get_content_charset()
                            content = decode_with_fallback(payload, charset)
                            break
                    if not content:
                        for part in msg.walk():
                            if part.get_content_type() == "text/html":
                                payload = part.get_payload(decode=True)
                                charset = part.get_content_charset()
                                content = decode_with_fallback(payload, charset)
                                break
                else:
                    payload = msg.get_payload(decode=True)
                    charset = msg.get_content_charset()
                    content = decode_with_fallback(payload, charset)

                results.append({
                    "subject": subject,
                    "from": from_email,
                    "date": email_date,
                    "content": f"From: {from_email}\nSubject: {subject}\nContent: {content}"
                })
                checked += 1
            except Exception:
                # 单条邮件解析异常，继续下一封
                checked += 1
                continue
    finally:
        try:
            server.quit()
        except Exception:
            pass

    return results


def predict_phishing(phishing_url, email_content):
    """调用钓鱼检测接口，返回接口返回的判断值（例如 'Phishing' 或 'Safe'）"""
    try:
        body = {"email_content": email_content}
        resp = requests.post(phishing_url, json=body, timeout=10)
        data = resp.json()
        # 兼容性：尝试几种可能的字段
        if isinstance(data, dict):
            return data.get("result") or data.get("label") or data.get("prediction") or data.get("status")
        return None
    except Exception:
        return None


def send_to_webhook(webhook_url, message):
    """发送文本消息到企业微信 webhook（默认 text 类型）"""
    try:
        body = {
            "msgtype": "text",
            "text": {"content": message}
        }
        resp = requests.post(webhook_url, json=body, timeout=5)
        # 部分企业微信 webhook 返回 {"errcode":0}
        if resp is None:
            return False
        try:
            rjson = resp.json()
            if isinstance(rjson, dict) and rjson.get("errcode") == 0:
                return True
        except Exception:
            # 非 JSON 返回也视为成功或失败不用严格判断
            return resp.status_code in (200, 204)
        return False
    except Exception:
        return False


def main(minutes, email_addr, password, imap_server, imap_port, webhook_url, phishing_api_url="http://localhost:8891/api/phishing/predict"):
    """
    主函数：检查邮箱在过去 minutes 分钟内的邮件并调用钓鱼检测
    返回：
        {'email_ids': [...], 'phishing_count': N}
    """
    try:
        # 尝试 IMAP 方式
        try:
            mail = connect_imap(email_addr, password, imap_server, imap_port)
            emails = fetch_emails_imap(mail, minutes)
            try:
                mail.logout()
            except Exception:
                pass
        except Exception as imap_err:
            # IMAP 失败时记录并尝试 POP3
            # print("IMAP 连接或读取失败，尝试 POP3。错误:", imap_err)
            emails = []
            try:
                # POP3 常用端口 995（SSL）
                emails = fetch_recent_emails_pop3(email_addr, password, imap_server, 995, minutes)
            except Exception as pop_err:
                # 两种方式都失败，发送错误通知并返回
                try:
                    err_msg = f"❌ 邮件检测出错!\n邮箱: {email_addr}\nIMAP错误: {str(imap_err)}\nPOP3错误: {str(pop_err)}"
                    send_to_webhook(webhook_url, err_msg)
                except Exception:
                    pass
                return {'email_ids': [], 'phishing_count': 0}

        if not emails:
            # 没有邮件在该时间范围内
            return {'email_ids': [], 'phishing_count': 0}

        phishing_count = 0
        processed_subjects = []
        for em in emails:
            processed_subjects.append(em.get("subject", "")[:200])
            is_phishing = predict_phishing(phishing_api_url, em["content"])
            result = "phishing" if is_phishing == "Phishing" else "Safe"
            if is_phishing == "Phishing":
                phishing_count += 1
                # 仅在检测到钓鱼时发送 webhook，避免刷屏
                try:
                    message = f"⚠️ 钓鱼邮件警报!\n邮箱: {email_addr}\nResult: {result}\nSubject: {em.get('subject','')[:200]}\nFrom: {em.get('from','')}\nDate: {em.get('date')}"
                    send_to_webhook(webhook_url, message)
                except Exception:
                    pass

        return {'email_ids': processed_subjects, 'phishing_count': phishing_count}
    except Exception as e:
        # 全局捕获，避免抛出到外部
        try:
            send_to_webhook(webhook_url, f"❌ 邮件检测异常: {str(e)}")
        except Exception:
            pass
        return {'email_ids': [], 'phishing_count': 0}


# 如果作为脚本直接运行做本地测试，可以使用下面的示例（可注释/删除）：
if __name__ == "__main__":
    # 示例测试（替换为真实值）
    minutes = 60
    email_addr = "test@example.com"
    password = "password"
    imap_server = "mail.example.com"
    imap_port = 993
    webhook_url = "https://qywx.webhook.url"
    phishing_api_url = "http://localhost:8891/api/phishing/predict"
    res = main(minutes, email_addr, password, imap_server, imap_port, webhook_url, phishing_api_url)
    print("检测结果:", res)
