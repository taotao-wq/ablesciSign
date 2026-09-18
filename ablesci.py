"""AbleSci sign-in for GitHub Actions. Uses only Python's standard library.

Endpoint workflow follows https://github.com/daitcl/ablesciSign.
Never logs account values, passwords, cookies, or response bodies.
"""

import json
import os
import sys
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, Request, build_opener

LOGIN = "https://www.ablesci.com/site/login"
SIGN = "https://www.ablesci.com/user/sign"


class SafeError(Exception):
    """Fixed, credential-free message suitable for public workflow logs."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SafeError("网站发生重定向，已停止；请检查官网登录方式是否变化。")


class TokenParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.input_token = ""
        self.meta_token = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == "_csrf":
            self.input_token = attrs.get("value") or ""
        if tag == "meta" and attrs.get("name") == "csrf-token":
            self.meta_token = attrs.get("content") or ""


def csrf_token(html):
    parser = TokenParser()
    parser.feed(html)
    token = parser.input_token or parser.meta_token
    if not token:
        raise SafeError("未找到登录令牌；网站页面可能变化或要求人工验证。")
    return token


def accounts_from_secret(value):
    accounts = []
    for number, line in enumerate(value.splitlines(), 1):
        if not line.strip():
            continue
        email, separator, password = line.partition(":")
        if not separator or "@" not in email or not password:
            raise SafeError(f"账号配置第 {number} 行无效；每行应为邮箱:密码。")
        accounts.append((email.strip(), password))
    if not accounts:
        raise SafeError("请在 GitHub Actions Secrets 中设置 ABLESCI_ACCOUNTS。")
    return accounts


def decode_result(body):
    try:
        result = json.loads(body)
    except (ValueError, TypeError):
        raise SafeError("网站未返回预期结果，可能需要在官网完成人工验证。") from None
    if not isinstance(result, dict) or "code" not in result:
        raise SafeError("网站返回格式变化，无法确认操作成功。")
    return result


def successful(result):
    code = result.get("code")
    return type(code) in (str, int) and str(code) == "0"


def sign_account(email, password):
    opener = build_opener(HTTPCookieProcessor(CookieJar()), NoRedirect())

    def request(url, data=None):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": LOGIN if url == LOGIN else "https://www.ablesci.com/",
        }
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
            data = urlencode(data).encode("utf-8")
        with opener.open(Request(url, data=data, headers=headers), timeout=30) as response:
            return response.read().decode("utf-8")

    token = csrf_token(request(LOGIN))
    login = decode_result(request(LOGIN, {
        "_csrf": token, "email": email, "password": password, "remember": "off"
    }))
    if not successful(login):
        raise SafeError("登录失败，请在官网核对账号或完成验证后再运行。")
    result = decode_result(request(SIGN))
    if successful(result):
        return "签到成功。"
    message = result.get("msg", "")
    if isinstance(message, str) and ("您今天已于" in message or "今日已签到" in message or "今天已签到" in message):
        return "今日已签到。"
    raise SafeError("签到未完成，请在科研通官网检查。")


def main():
    try:
        accounts = accounts_from_secret(os.environ.get("ABLESCI_ACCOUNTS", ""))
    except SafeError as error:
        print(str(error))
        return 1
    failed = False
    for index, (email, password) in enumerate(accounts, 1):
        try:
            status = sign_account(email, password)
        except SafeError as error:
            status, failed = str(error), True
        except HTTPError as error:
            status, failed = f"网站返回 HTTP {error.code}，签到未确认。", True
        except (URLError, TimeoutError):
            status, failed = "网络连接失败或超时，签到未确认。", True
        except Exception:
            status, failed = "运行异常，签到未确认。", True
        print(f"账号 {index}：{status}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
