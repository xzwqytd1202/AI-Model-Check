# test_mail_login.py
import poplib, imaplib, socket, traceback, logging
from email.parser import BytesParser
from email.policy import default

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("mail_check")

HOST = "mail.ultrapower.com.cn"
USER = "xxaq_daiyongtao@ultrapower.com.cn"
PASSWORD = "nblwr#54492025"   # ← 替换为真实密码或临时密码

def try_pop3s():
    try:
        logger.info("尝试 POP3S %s:995 登录", HOST)
        srv = poplib.POP3_SSL(HOST, 995, timeout=10)
        srv.user(USER)
        srv.pass_(PASSWORD)
        resp = srv.stat()
        logger.info("POP3 登录成功，邮件数: %s", resp)
        # 取最新一封的主题示例（可选）
        if resp[0] > 0:
            resp, lines, size = srv.retr(resp[0])
            msg = BytesParser(policy=default).parsebytes(b"\r\n".join(lines))
            logger.info("最新邮件主题: %s", msg.get("subject"))
        srv.quit()
        return True
    except Exception as e:
        logger.error("POP3S 登录异常: %s", repr(e))
        logger.debug("POP3S 异常堆栈:\n%s", traceback.format_exc())
        return False

def try_imap_ssl():
    try:
        logger.info("尝试 IMAP SSL %s:993 登录", HOST)
        m = imaplib.IMAP4_SSL(HOST, 993, timeout=10)
        m.login(USER, PASSWORD)
        typ, data = m.select("INBOX")
        logger.info("IMAP 登录成功，INBOX 状态: %s, %s", typ, data)
        m.logout()
        return True
    except Exception as e:
        logger.error("IMAP SSL 登录异常: %s", repr(e))
        logger.debug("IMAP 异常堆栈:\n%s", traceback.format_exc())
        return False

if __name__ == "__main__":
    # 先试 POP3S（你之前测试显示 995 开着）
    ok_pop = try_pop3s()
    # 再试 IMAP（预期会失败，但做记录）
    ok_imap = try_imap_ssl()
    logger.info("结果汇总: POP3S=%s, IMAP=%s", ok_pop, ok_imap)
