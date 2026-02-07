# meta developer: @DegradationModules
#
# LICENSE NOTICE (DegradationModules):
# This module is owned by https://t.me/DegradationModules.
# You are allowed to use, modify, and redistribute this module (including with changes),
# but you must not claim authorship/ownership or rebrand it as your own work.
# You must keep this license notice and the original attribution intact in all copies
# and substantial portions of the code.

from .. import loader, utils

import aiohttp
import asyncio
import io
import json
import logging
import re
import time
from telethon import events, types

logger = logging.getLogger(__name__)

# SYSTEM PROMPTS (unchanged)
GEN_SYSTEM_PROMPT = """
You are an expert Python developer specializing in writing high-quality modules for the Telegram Userbot Hikka (formerly known as Heroku/Hikka).
Your task is to generate a complete, valid, working, and error-free Python module for Hikka Userbot based on the user's description.

### STRICT ARCHITECTURE RULES (MUST FOLLOW EXACTLY):
1.  **First line**: Always start the code with `# meta developer: {developer}`
2.  **Imports**: Use relative imports: `from .. import loader, utils`. Add any other necessary imports (e.g., `asyncio`, `logging`, third-party libraries if needed).
3.  **Class**:
    - Inherit from `loader.Module`
    - Decorate the class with `@loader.tds`
    - Define `strings = {{"name": "ModuleName"}}` (Choose a unique, CamelCase English name).
    - Add a docstring (3 quotation marks) "Brief description of what the module does" (3 quotation marks) right after the class name.
4.  **Commands**:
    - Use `@loader.command()` decorator (optionally with parameters like `alias="alias"`, `ru_doc="..."` if needed).
    - Methods: `async def <command>cmd(self, message):`
    - Use `await utils.answer(message, "text")` for responses (supports HTML/markup).
    - For file responses: `await utils.answer_file(message, file, caption="...")`
5.  **Other handlers**:
    - Watchers: `@loader.watcher()` (e.g., for incoming messages).
    - Inline handlers if needed.
6.  **Config**:
    - If the module needs configuration, add in `__init__`: `self.config = loader.ModuleConfig(...)` with proper `ConfigValue`s.
7.  **Best practices**:
    - Handle errors gracefully (try/except where needed).
    - Use logging if useful: `logging.getLogger(__name__)`
    - Make code clean, commented if complex.
    - Avoid dangerous operations unless explicitly requested.

The module must be installable via .dlmod in Hikka.
RETURN ONLY THE FULL PYTHON CODE wrapped in ```python ... ``` markdown blocks.
NO explanations, NO additional text, NO partial code.
"""

REFINE_SYSTEM_PROMPT = """
You are an expert Python developer for Hikka Userbot.
Your task is to EDIT, IMPROVE, and FIX the provided Python module code based on the user's instructions or error reports.

### RULES (MUST FOLLOW):
1.  **First line**: Always ensure the first line is `# meta developer: {developer}`.
2.  Preserve the original module logic and functionality unless the user explicitly asks to change or remove it.
3.  Ensure full compatibility with current Hikka architecture:
    - Relative imports: `from .. import loader, utils`
    - Class inherits `loader.Module`, decorated with `@loader.tds`
    - `strings = {{"name": "..."}}`
    - Commands with `@loader.command()`
    - Responses via `await utils.answer(message, ...)`
4.  **Description**: Ensure the class docstring describes **WHAT the module does** (e.g., "Downloads music from YouTube"). Do **NOT** write changelogs like "Fixed import error" or "Updated logic" in the docstring.
5.  Fix any syntax errors, logical bugs, deprecated patterns, or potential crashes based on the user's prompt (which may contain error logs).
6.  Implement the user's requested changes precisely.

RETURN ONLY THE FULL UPDATED PYTHON CODE wrapped in ```python ... ``` markdown blocks.
NO explanations, NO additional text.
"""

CHAT_SYSTEM_PROMPT = """
You are a helpful expert assistant for Hikka Userbot developers.
The user will send you questions, error tracebacks, or code snippets.
Your task is to explain the error, suggest fixes, or answer the question clearly and concisely.
If you provide code, wrap it in ```python ... ``` blocks.
Do not generate a full module unless asked; focus on the specific question or error.
"""

GEN_SYSTEM_PROMPT_V2 = """
You are a senior Python engineer who writes production-ready modules for the Telegram Userbot Hikka.
Generate a COMPLETE working module in ONE FILE.

Hard requirements:
1) The very first line of the file MUST be exactly: # meta developer: {developer}
2) Use Hikka module style:
   - from .. import loader, utils
   - @loader.tds
   - class <Name>Mod(loader.Module):
   - strings = {{"name": "<Name>"}}
3) All user-visible messages must support HTML formatting and must escape user input using utils.escape_html().
4) Provide full error handling for IO/Telegram/API operations. No silent failures.
5) If configuration is needed, add loader.ModuleConfig with validators.
6) Do NOT output any additional explanations. Output ONLY Python code wrapped in ```python ... ```.

Module quality checklist:
- Clean architecture with helper methods.
- No unused imports.
- Avoid blocking calls inside async code (use aiohttp/asyncio).
- Rate limiting/backoff when interacting with external services if applicable.
- If the task requests long-running operations, show progress updates.

Now generate a module based on the user's request.
"""

REFINE_SYSTEM_PROMPT_V2 = """
You are a senior Python engineer for Hikka Userbot.
You will RECEIVE an existing module and a user request.
Return a FULL updated module file.

Rules:
1) Ensure the very first line stays: # meta developer: {developer}
2) Keep the module functional. Implement requested changes fully.
3) Fix bugs, edge cases, and improve robustness.
4) Preserve compatibility with Hikka (loader/utils).
5) Output ONLY Python code wrapped in ```python ... ```.
"""


@loader.tds
class HerokuGenMod(loader.Module):
    """Advanced AI Module Generator with Custom API, Proxy, Model support, and Error Debugging."""

    strings = {
        "name": "DemoGen",
        "no_args": "<b>❌ Enter a prompt, question, or error log!</b>",
        "no_reply": "<b>❌ Reply to a python file (.py).</b>",
        "bad_file": "<b>❌ Failed to read file. Ensure it is text/python.</b>",
        "generating": "<blockquote><b>🎲 Generating module...</b>\n<b>Model:</b> <code>{}</code>\n<b>Prompt:</b> <code>{}</code></blockquote>",
        "refining": "<blockquote><b>🔧 Refining module...</b>\n<b>Model:</b> <code>{}</code>\n<b>Task/Error:</b> <code>{}</code></blockquote>",
        "asking": "<blockquote><b>🤔 Asking AI...</b>\n<b>Model:</b> <code>{}</code>\n<b>Question/Log:</b> <code>{}</code></blockquote>",
        "error": "<b>❌ API Error:</b>\n<blockquote><code>{}</code></blockquote>",
        "no_code": "<b>❌ The AI did not return code.</b>\n<blockquote>Response snippet:\n{}</blockquote>",
        "set_key": "<b>🔑 API Key set!</b>",
        "set_url": "<b>🔗 API URL set to:</b>\n<blockquote><code>{}</code></blockquote>",
        "set_model": "<b>🧠 Model set to:</b>\n<blockquote><code>{}</code></blockquote>",
        "set_proxy": "<b>🛡️ Proxy set to:</b>\n<blockquote><code>{}</code></blockquote>",
        "proxy_cleared": "<b>🛡️ Proxy disabled.</b>",
        "invalid_url": "<b>❌ Invalid URL. Must start with http:// or https://</b>",
        "invalid_proxy": "<b>❌ Invalid proxy. Must start with http://, https://, socks4:// or socks5://</b>",
        "auth_required": (
            "<b>🔑 Authentication failed.</b>\n"
            "<blockquote>"
            "The API returned <code>401</code>. Check that you set the correct key and that the provider expects it in the <code>Authorization: Bearer</code> header.\n"
            "Current key (masked): <code>{}</code>\n"
            "Tip: if your provider uses a query parameter (<code>?key=</code>), enable it in config or switch auth mode.\n"
            "</blockquote>"
        ),
        "config_info": (
            "<b>⚙️ HerokuGen Configuration:</b>\n\n"
            "<b>🔗 URL:</b> <code>{url}</code>\n"
            "<b>🧠 Model:</b> <code>{model}</code>\n"
            "<b>🔑 Key:</b> <code>{key}</code>\n"
            "<b>🛡️ Proxy:</b> <code>{proxy}</code>"
        ),
        "cfg_api_key": "API Key for OpenAI-compatible API",
        "cfg_api_url": "Endpoint URL for Chat Completions",
        "cfg_model": "Model name to use for generation",
        "cfg_proxy": "Proxy URL (http/socks) or 'None' to disable",
        "fix_prompt": "✍️ <b>OK. Now send me the instructions on what to fix. You have 2 minutes.</b>",
        "timeout": "<b>⌛️ Timeout.</b>",
        "regen_no_prompt": "<b>❌ Original prompt not found.</b>",
        "regenerating": "<b>🔄 Re-generating...</b>",
        "btn_regen": "Перегенерировать",
        "btn_fix": "Пофиксить",
        "btn_analyze": "Анализ",
        "btn_trace": "Трейс",
        "busy": "<b>⏳ I'm busy with another request. Try again later.</b>",
        "too_long": "<b>⚠️ The model produced too much text. I will send it as a file instead.</b>",
        "rate_limited": "<b>⏳ Rate limited. Waiting <code>{}</code> seconds…</b>",
        "analysis_title": "<b>🧪 Module analysis</b>\n<blockquote><b>Module:</b> <code>{}</code>\n<b>Model:</b> <code>{}</code></blockquote>",
        "analysis_empty": "<b>ℹ️ No issues found.</b>",
        "analysis_error": "<b>❌ Analyzer error:</b>\n<blockquote><code>{}</code></blockquote>",
        "trace_title": "<b>🧾 Error trace</b>\n<blockquote><b>Context:</b> <code>{}</code></blockquote>\n",
        "trace_empty": "<b>ℹ️ No recent errors recorded.</b>",
    }

    def __init__(self):
        self.config = loader.ModuleConfig(
            loader.ConfigValue(
                "api_key",
                "free",
                lambda: self.strings("cfg_api_key"),
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "api_url",
                "https://api.algion.dev/v1/chat/completions",
                lambda: self.strings("cfg_api_url"),
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "model",
                "claude-sonnet-4",
                lambda: self.strings("cfg_model"),
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "proxy",
                None,
                lambda: self.strings("cfg_proxy"),
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "timeout",
                180,
                lambda: "HTTP timeout (seconds)",
                validator=loader.validators.Integer(minimum=15, maximum=600),
            ),
            loader.ConfigValue(
                "max_output_chars",
                180000,
                lambda: "Max chars kept from AI response (safety)",
                validator=loader.validators.Integer(minimum=10000, maximum=2000000),
            ),
            loader.ConfigValue(
                "max_prompt_chars",
                40000,
                lambda: "Max prompt chars sent to API (safety)",
                validator=loader.validators.Integer(minimum=2000, maximum=400000),
            ),
            loader.ConfigValue(
                "retries",
                4,
                lambda: "API retries",
                validator=loader.validators.Integer(minimum=0, maximum=10),
            ),
            loader.ConfigValue(
                "temperature",
                0.4,
                lambda: "Model temperature",
                validator=loader.validators.Float(minimum=0.0, maximum=2.0),
            ),
            loader.ConfigValue(
                "auth_mode",
                "bearer",
                lambda: "Auth mode: bearer (Authorization: Bearer), header (X-API-Key), query (?key=), none",
                validator=loader.validators.Choice(["bearer", "header", "query", "none"]),
            ),
            loader.ConfigValue(
                "auth_header",
                "X-API-Key",
                lambda: "Header name for auth_mode=header",
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "auth_query_param",
                "key",
                lambda: "Query param name for auth_mode=query",
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "analysis_max_lines",
                40,
                lambda: "Max analyzer issues shown in message",
                validator=loader.validators.Integer(minimum=10, maximum=200),
            ),
            loader.ConfigValue(
                "error_trace_max",
                50,
                lambda: "How many last internal errors to keep",
                validator=loader.validators.Integer(minimum=10, maximum=500),
            ),
        )
        self.prompts = {}
        self._locks = {}
        self._artifacts = {}
        self._error_trace = []

    async def client_ready(self, client, db):
        self.client = client
        self.db = db
        prompts = self.get("prompts", {})
        self.prompts = prompts if isinstance(prompts, dict) else {}
        artifacts = self.get("artifacts", {})
        self._artifacts = artifacts if isinstance(artifacts, dict) else {}
        trace = self.get("error_trace", [])
        self._error_trace = trace if isinstance(trace, list) else []

    async def on_unload(self):
        self.prompts.clear()
        self._locks.clear()
        self._artifacts.clear()
        self._error_trace.clear()

    async def _get_developer_tag(self, message):
        me = await self.client.get_me()
        return f"@{me.username}" if me.username else f"tg://user?id={me.id}"

    def _mask_api_key(self, key: str) -> str:
        if not key or key == "free":
            return "free"
        if len(key) <= 8:
            return "*" * len(key)
        return key[:4] + "*" * (len(key) - 8) + key[-4:]

    @staticmethod
    def _is_valid_proxy(value: str) -> bool:
        if not value:
            return True
        val = value.strip().lower()
        return (
            val.startswith("http://")
            or val.startswith("https://")
            or val.startswith("socks4://")
            or val.startswith("socks5://")
        )

    @staticmethod
    def _truncate_middle(text: str, limit: int) -> str:
        if not isinstance(text, str):
            return ""
        if limit <= 0:
            return ""
        if len(text) <= limit:
            return text
        head = max(1, int(limit * 0.7))
        tail = max(1, limit - head - 20)
        return text[:head] + "\n...<truncated>...\n" + text[-tail:]

    @staticmethod
    def _extract_api_error_payload(text: str) -> str:
        if not text:
            return ""
        raw = text.strip()
        if not raw:
            return ""
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                err = data.get("error")
                if isinstance(err, dict):
                    msg = err.get("message") or err.get("detail") or err.get("type") or ""
                    if msg:
                        return str(msg)
                if data.get("message"):
                    return str(data["message"])
        except Exception:
            return raw[:2000]
        return raw[:2000]

    def _get_lock(self, key: int) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    def _trace(self, context: str, exc: Exception = None, extra: str = "") -> None:
        try:
            max_items = int(self.config.get("error_trace_max") or 50)
        except Exception:
            max_items = 50
        max_items = max(10, min(500, max_items))

        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        exc_name = exc.__class__.__name__ if exc else ""
        try:
            exc_text = str(exc) if exc else ""
        except Exception:
            exc_text = "<unprintable>"

        item = {
            "t": now,
            "ctx": str(context or "unknown")[:200],
            "exc": exc_name[:80],
            "msg": (exc_text or "")[:700],
            "extra": (extra or "")[:1200],
        }
        self._error_trace.append(item)
        if len(self._error_trace) > max_items:
            self._error_trace = self._error_trace[-max_items:]

        try:
            self.set("error_trace", self._error_trace)
        except Exception:
            logger.info("Failed to persist error_trace")

        if exc:
            logger.exception(f"[HerokuGen] {context}: {exc_name}: {exc_text}")
        else:
            logger.error(f"[HerokuGen] {context}: {extra}")

    def _render_trace(self, limit: int = 15) -> str:
        if not self._error_trace:
            return self.strings("trace_empty")
        try:
            limit = int(limit)
        except Exception:
            limit = 15
        limit = max(1, min(50, limit))

        items = self._error_trace[-limit:]
        lines = []
        for it in items:
            t = utils.escape_html(str(it.get("t", "")))
            ctx = utils.escape_html(str(it.get("ctx", "")))
            exc = utils.escape_html(str(it.get("exc", "")))
            msg = utils.escape_html(str(it.get("msg", "")))
            extra = utils.escape_html(str(it.get("extra", "")))
            block = f"<b>{t}</b> <code>{ctx}</code>"
            if exc or msg:
                block += f"\n<code>{exc}</code>: {msg}".rstrip()
            if extra:
                block += f"\n<i>{extra}</i>"
            lines.append(block)
        return "<blockquote expandable>\n" + "\n\n".join(lines) + "\n</blockquote>"

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not isinstance(url, str):
            url = str(url)
        return url.strip()

    def _build_auth(self):
        key = (self.config.get("api_key") or "").strip()
        mode = (self.config.get("auth_mode") or "bearer").strip().lower()
        headers = {}
        params = {}

        if not key or key.lower() == "none":
            key = ""

        if mode not in ("bearer", "header", "query", "none"):
            mode = "bearer"

        if mode == "none" or not key:
            return headers, params, mode

        if mode == "bearer":
            headers["Authorization"] = f"Bearer {key}"
            return headers, params, mode

        if mode == "header":
            hname = (self.config.get("auth_header") or "X-API-Key").strip() or "X-API-Key"
            headers[hname] = key
            return headers, params, mode

        if mode == "query":
            qname = (self.config.get("auth_query_param") or "key").strip() or "key"
            params[qname] = key
            return headers, params, mode

        return headers, params, mode

    async def _call_api(self, message, system_prompt, user_prompt):
        base_headers = {"Content-Type": "application/json"}
        timeout_s = int(self.config["timeout"] or 180)
        max_prompt = int(self.config["max_prompt_chars"] or 40000)
        retries = int(self.config["retries"] or 0)
        temperature = float(self.config["temperature"] if self.config["temperature"] is not None else 0.4)
        api_url = self._normalize_url(self.config.get("api_url") or "")

        if not api_url or not (api_url.startswith("http://") or api_url.startswith("https://")):
            last_error_text = "Invalid api_url. It must start with http:// or https://"
            logger.error(f"API request failed: {last_error_text}")
            try:
                await utils.answer(message, self.strings("error").format(utils.escape_html(last_error_text)))
            except Exception:
                logger.exception("Failed to send error message")
            return None

        auth_headers, auth_params, _ = self._build_auth()
        headers = dict(base_headers)
        headers.update(auth_headers)

        if not isinstance(system_prompt, str):
            system_prompt = str(system_prompt)
        if not isinstance(user_prompt, str):
            user_prompt = str(user_prompt)

        system_prompt = system_prompt[:max_prompt]
        user_prompt = user_prompt[:max_prompt]

        payload = {
            "model": self.config["model"],
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
        }

        proxy = self.config["proxy"]
        if proxy is not None:
            proxy = str(proxy).strip()
        if proxy and not self._is_valid_proxy(proxy):
            logger.warning("Invalid proxy in config, ignoring it")
            proxy = None

        last_error_text = None
        started = time.time()
        attempt = 0

        while True:
            attempt += 1
            try:
                timeout = aiohttp.ClientTimeout(total=timeout_s)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        api_url,
                        headers=headers,
                        json=payload,
                        proxy=proxy,
                        params=auth_params or None,
                    ) as resp:
                        if resp.status == 429:
                            retry_after = resp.headers.get("Retry-After")
                            wait_s = 10
                            if retry_after:
                                try:
                                    wait_s = int(float(retry_after))
                                except Exception:
                                    wait_s = 10
                            if attempt <= retries + 1:
                                try:
                                    await utils.answer(message, self.strings("rate_limited").format(wait_s))
                                except Exception:
                                    logger.info("Failed to edit rate limit message")
                                await asyncio.sleep(max(1, min(wait_s, 120)))
                                continue
                            body = await resp.text()
                            last_error_text = f"HTTP 429: {self._extract_api_error_payload(body)}"
                            break

                        if resp.status in (401, 403):
                            body = await resp.text()
                            extracted = self._extract_api_error_payload(body)
                            last_error_text = (
                                f"HTTP {resp.status}: {extracted}"
                                if extracted
                                else f"HTTP {resp.status}: Authentication/Authorization failed"
                            )
                            break

                        if resp.status >= 500:
                            body = await resp.text()
                            last_error_text = f"HTTP {resp.status}: {self._extract_api_error_payload(body)}"
                            if attempt <= retries + 1:
                                await asyncio.sleep(min(2 ** (attempt - 1), 20))
                                continue
                            break

                        if resp.status != 200:
                            body = await resp.text()
                            last_error_text = f"HTTP {resp.status}: {self._extract_api_error_payload(body)}"
                            break

                        # Try json, fallback to text
                        try:
                            data = await resp.json()
                        except Exception:
                            body = await resp.text()
                            last_error_text = f"Bad JSON response: {self._extract_api_error_payload(body)}"
                            break

                        content = None
                        try:
                            content = data["choices"][0]["message"]["content"]
                        except Exception:
                            pass

                        if not content:
                            last_error_text = "Empty response content"
                            break

                        max_out = int(self.config["max_output_chars"] or 180000)
                        if len(content) > max_out:
                            content = content[:max_out]
                        return content

            except asyncio.TimeoutError:
                last_error_text = f"Timeout after {timeout_s}s"
                if attempt <= retries + 1:
                    await asyncio.sleep(min(2 ** (attempt - 1), 20))
                    continue
                break
            except aiohttp.ClientConnectorError as e:
                try:
                    name = e.os_error.__class__.__name__
                except Exception:
                    name = e.__class__.__name__
                last_error_text = f"Connection Error: {name}"
                if attempt <= retries + 1:
                    await asyncio.sleep(min(2 ** (attempt - 1), 20))
                    continue
                break
            except aiohttp.ClientError as e:
                last_error_text = f"HTTP Client Error: {e.__class__.__name__}: {str(e)[:300]}"
                if attempt <= retries + 1:
                    await asyncio.sleep(min(2 ** (attempt - 1), 20))
                    continue
                break
            except Exception as e:
                logger.exception("An unexpected error occurred in _call_api")
                last_error_text = f"Unexpected error: {e.__class__.__name__}: {str(e)[:300]}"
                self._trace("_call_api.unexpected", e)
                break

            if time.time() - started > max(30, timeout_s + 30):
                last_error_text = "Timeout budget exceeded"
                break

        if last_error_text is None:
            last_error_text = "Unknown API error"
        logger.error(f"API request failed: {last_error_text}")
        try:
            if "HTTP 401" in last_error_text or "HTTP 403" in last_error_text:
                masked = self._mask_api_key((self.config.get("api_key") or "").strip())
                await utils.answer(message, self.strings("auth_required").format(utils.escape_html(masked)))
            await utils.answer(message, self.strings("error").format(utils.escape_html(last_error_text)))
        except Exception as e:
            logger.exception("Failed to send error message")
            self._trace("_call_api.send_error", e, extra=last_error_text)
        return None

    def _generate_module_summary(self, code: str) -> str:
        summary_parts = []

        module_doc_match = re.search(
            r"class\s+\w+\(loader\.Module\):\s*\"\"\"(.*?)\"\"\"",
            code,
            re.DOTALL | re.MULTILINE,
        )
        if module_doc_match:
            summary_parts.append(utils.escape_html(module_doc_match.group(1).strip()))

        command_matches = re.findall(
            r"@loader\.command\([^)]*\)\s+async\s+def\s+(\w+cmd)\(self,.*?\):\s*\"\"\"(.*?)\"\"\"",
            code,
            re.DOTALL,
        )

        if command_matches:
            summary_parts.append("\n<b>Commands:</b>" if summary_parts else "<b>Commands:</b>")
            for command_name, docstring in command_matches:
                clean_name = command_name[:-3]
                doc = docstring.strip().split("\n")[0]
                summary_parts.append(f"• <code>.{clean_name}</code> - {utils.escape_html(doc)}")

        return "\n".join(summary_parts)

    @staticmethod
    def _safe_strip_code_fences(text: str) -> str:
        if not isinstance(text, str):
            try:
                text = str(text)
            except Exception:
                return ""
        raw = text.strip()
        if not raw:
            return ""

        # Prefer ```python ... ```
        m = re.search(r"```python\s*(.*?)```", raw, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()

        # Any fenced block
        m = re.search(r"```\s*(.*?)```", raw, re.DOTALL)
        if m:
            return m.group(1).strip()

        return raw

    async def _process_code(self, peer_id, content, prompt, status_msg, reply_to_id):
        try:
            code = self._safe_strip_code_fences(content)
        except Exception as e:
            self._trace("_process_code.strip", e)
            code = content if isinstance(content, str) else ""

        if not code or ("class " not in code or "loader.Module" not in code):
            if status_msg:
                snippet = self._truncate_middle(content if isinstance(content, str) else str(content), 900)
                await utils.answer(status_msg, self.strings("no_code").format(utils.escape_html(snippet)))
            return

        class_match = re.search(r"class\s+([a-zA-Z0-9_]+)\s*\(\s*loader\.Module\s*\)\s*:", code)
        module_name = class_match.group(1) if class_match else "GeneratedMod"

        summary = self._generate_module_summary(code)
        prompt_display = (
            f"<blockquote>{summary}</blockquote>"
            if summary
            else f"<blockquote><code>{utils.escape_html(prompt)}</code></blockquote>"
        )

        filename = f"{module_name}.py"
        file = io.BytesIO(code.encode("utf-8"))
        file.name = filename

        safe_model = utils.escape_html(str(self.config["model"]))
        caption = (
            f"<b>✅ Done</b>\n"
            f"<blockquote>"
            f"🧠 <b>Model:</b> <code>{safe_model}</code>\n"
            f"📦 <b>Module:</b> <code>{utils.escape_html(module_name)}</code>"
            f"</blockquote>\n\n"
            f"📝 <b>Summary:</b>\n{prompt_display}"
        )

        # Persist prompt for regen/fix
        try:
            self.prompts[str(reply_to_id)] = str(prompt)
            self.set("prompts", self.prompts)
        except Exception as e:
            self._trace("_process_code.persist_prompt", e)

        buttons = [
            [types.KeyboardButtonCallback(self.strings("btn_regen"), data=f"hgg_regen_{reply_to_id}")],
            [types.KeyboardButtonCallback(self.strings("btn_fix"), data=f"hgg_fix_{reply_to_id}")],
            [types.KeyboardButtonCallback(self.strings("btn_trace"), data=f"hgg_trace_{reply_to_id}")],
        ]

        try:
            await self.client.send_file(
                peer_id,
                file=file,
                caption=caption,
                reply_to=reply_to_id,
                buttons=buttons,
            )
        except Exception as e:
            self._trace("_process_code.send_file", e)
            if status_msg:
                await utils.answer(status_msg, self.strings("error").format(utils.escape_html(str(e)[:500])))
            return

        if status_msg:
            try:
                await status_msg.delete()
            except Exception:
                logger.info("Failed to delete status message")

    @loader.command()
    async def setgenkey(self, message):
        """<key> - Set API Key"""
        args = utils.get_args_raw(message)
        self.config["api_key"] = args or "free"
        await self.config.save()
        await utils.answer(message, self.strings("set_key"))
        try:
            await message.delete()
        except Exception:
            logger.info("Failed to delete command message (setgenkey)")

    @loader.command()
    async def setgenurl(self, message):
        """<url> - Set API URL"""
        args = utils.get_args_raw(message)
        if not args or not (args.startswith("http://") or args.startswith("https://")):
            await utils.answer(message, self.strings("invalid_url"))
            return
        self.config["api_url"] = args
        await self.config.save()
        await utils.answer(message, self.strings("set_url").format(utils.escape_html(args)))

    @loader.command()
    async def setgenmodel(self, message):
        """<model> - Set Model"""
        args = utils.get_args_raw(message)
        if not args:
            await utils.answer(message, self.strings("no_args"))
            return
        self.config["model"] = args
        await self.config.save()
        await utils.answer(message, self.strings("set_model").format(utils.escape_html(args)))

    @loader.command()
    async def setgenproxy(self, message):
        """<proxy_url> - Set Proxy or 'None'"""
        args = utils.get_args_raw(message)
        raw = (args or "").strip()
        if not raw or raw.lower() in ["none", "null", "off", "clean", "clear", "disable", "disabled"]:
            self.config["proxy"] = None
        else:
            if not self._is_valid_proxy(raw):
                await utils.answer(message, self.strings("invalid_proxy"))
                return
            self.config["proxy"] = raw
        await self.config.save()
        await utils.answer(
            message,
            self.strings("proxy_cleared")
            if not self.config["proxy"]
            else self.strings("set_proxy").format(utils.escape_html(raw)),
        )

    @loader.command()
    async def geninfo(self, message):
        """- Check config"""
        proxy_display = utils.escape_html(self.config["proxy"] or "Disabled")
        key_display = utils.escape_html(self._mask_api_key(self.config["api_key"]))
        await utils.answer(
            message,
            self.strings("config_info").format(
                url=utils.escape_html(str(self.config["api_url"])),
                model=utils.escape_html(str(self.config["model"])),
                key=key_display,
                proxy=proxy_display,
            ),
        )

    async def _generate(self, message, args):
        lock = self._get_lock(int(message.chat_id or 0))
        if lock.locked():
            await utils.answer(message, self.strings("busy"))
            return

        async with lock:
            status_msg = await utils.answer(
                message,
                self.strings("generating").format(
                    utils.escape_html(str(self.config["model"])),
                    utils.escape_html(args),
                ),
            )

            dev_tag = await self._get_developer_tag(message)
            formatted_prompt = GEN_SYSTEM_PROMPT_V2.format(developer=dev_tag)
            user_prompt = (
                "User request:\n"
                f"{args}\n\n"
                "Output requirements:\n"
                "- Return ONLY the final module file code.\n"
                "- Wrap it in ```python ... ```.\n"
                "- The module should be robust, with validations and error handling.\n"
            )
            content = await self._call_api(status_msg, formatted_prompt, user_prompt)
            if content:
                await self._process_code(message.peer_id, content, args, status_msg, reply_to_id=message.id)

    async def _refine(self, message, reply, args):
        lock = self._get_lock(int(message.chat_id or 0))
        if lock.locked():
            await utils.answer(message, self.strings("busy"))
            return

        async with lock:
            status_msg = await utils.answer(
                message,
                self.strings("refining").format(
                    utils.escape_html(str(self.config["model"])),
                    utils.escape_html(args),
                ),
            )

            try:
                raw = await reply.download_media(bytes)
                if not raw:
                    raise ValueError("empty file")
                source_code = raw.decode("utf-8", errors="replace")
            except Exception as e:
                logger.exception("Failed to download or decode file for refinement")
                self._trace("_refine.download_decode", e)
                await utils.answer(status_msg, self.strings("bad_file"))
                return

            dev_tag = await self._get_developer_tag(message)
            formatted_prompt = REFINE_SYSTEM_PROMPT_V2.format(developer=dev_tag)
            source_code = source_code.replace("\r\n", "\n").replace("\r", "\n")
            max_prompt = int(self.config["max_prompt_chars"] or 40000)
            if len(source_code) > max_prompt:
                source_code = source_code[:max_prompt]

            user_request = (
                "Existing module code:\n\n"
                f"```python\n{source_code}\n```\n\n"
                "User request / error report:\n"
                f"{args}\n\n"
                "Important:\n"
                "- Fix reported bugs.\n"
                "- Improve stability and formatting.\n"
                "- Avoid timeouts and handle API errors gracefully.\n"
                "- Return ONLY the full updated module code wrapped in ```python ... ```.\n"
            )

            content = await self._call_api(status_msg, formatted_prompt, user_request)
            if content:
                reply_to_id = getattr(reply, "reply_to_msg_id", None) or message.id
                await self._process_code(message.peer_id, content, args, status_msg, reply_to_id=reply_to_id)

    @loader.command()
    async def genmod(self, message):
        """<prompt> - Generate a new module"""
        args = utils.get_args_raw(message)
        if not args:
            await utils.answer(message, self.strings("no_args"))
            return
        await self._generate(message, args)

    @loader.command(alias="fixmod")
    async def refinemod(self, message):
        """<prompt/error> (reply to file) - Fix existing module"""
        reply = await message.get_reply_message()
        args = utils.get_args_raw(message)
        if not reply or not getattr(reply, "file", None):
            await utils.answer(message, self.strings("no_reply"))
            return
        if not args:
            await utils.answer(message, self.strings("no_args"))
            return
        await self._refine(message, reply, args)

    @loader.command()
    async def genask(self, message):
        """<question/log> - Ask AI about code or errors (Text response)"""
        args = utils.get_args_raw(message)
        if not args:
            await utils.answer(message, self.strings("no_args"))
            return

        lock = self._get_lock(int(message.chat_id or 0))
        if lock.locked():
            await utils.answer(message, self.strings("busy"))
            return

        async with lock:
            status_msg = await utils.answer(
                message,
                self.strings("asking").format(
                    utils.escape_html(str(self.config["model"])),
                    utils.escape_html(args),
                ),
            )
            content = await self._call_api(
                status_msg,
                CHAT_SYSTEM_PROMPT,
                args[: int(self.config["max_prompt_chars"] or 40000)],
            )

            if not content:
                return

            safe = utils.escape_html(content)
            if len(safe) > 3500:
                buf = io.BytesIO(content.encode("utf-8"))
                buf.name = "answer.txt"
                await utils.answer(status_msg, self.strings("too_long"))
                try:
                    await self.client.send_file(
                        message.peer_id,
                        file=buf,
                        caption="<b>🤖 Answer (file)</b>\n<blockquote>Output was too large for a message.</blockquote>",
                        reply_to=message.id,
                    )
                except Exception as e:
                    self._trace("genask.send_file", e)
                    await utils.answer(status_msg, self.strings("error").format(utils.escape_html(str(e)[:500])))
                    return
                try:
                    await status_msg.delete()
                except Exception:
                    logger.info("Failed to delete status message after sending answer file")
                return

            await utils.answer(status_msg, f"<b>🤖 Answer:</b>\n\n<blockquote>{safe}</blockquote>")

    @loader.command()
    async def gentrace(self, message):
        """[n] - Show last internal errors trace"""
        args = utils.get_args_raw(message)
        try:
            n = int(args.strip()) if args else 15
        except Exception:
            n = 15
        text = self._render_trace(limit=n)
        await utils.answer(message, self.strings("trace_title").format(utils.escape_html("manual")) + text)

    @loader.callback_handler(
        filter=lambda call: (
            (call.data.startswith(b"hgg_") if isinstance(call.data, (bytes, bytearray)) else str(call.data).startswith("hgg_"))
        )
    )
    async def _buttons_callback(self, call: events.CallbackQuery.Event):
        try:
            data = call.data.decode("utf-8") if isinstance(call.data, (bytes, bytearray)) else str(call.data)
            parts = data.split("_", 2)
            if len(parts) != 3:
                return await call.answer("Invalid callback data!", alert=True)

            action = parts[1]
            msg_id = int(parts[2])
        except Exception as e:
            self._trace("callback.parse", e, extra=str(getattr(call, "data", ""))[:200])
            return await call.answer("Invalid callback!", alert=True)

        try:
            chat_id = int(getattr(call, "chat_id", None) or getattr(call.message, "chat_id", 0) or 0)
        except Exception:
            chat_id = 0

        if action == "trace":
            try:
                await call.answer("Trace", alert=False)
            except Exception:
                pass
            text = self._render_trace(limit=15)
            try:
                await self.client.send_message(
                    call.message.peer_id,
                    self.strings("trace_title").format(utils.escape_html(f"callback:{msg_id}")) + text,
                    reply_to=call.message.id,
                )
            except Exception as e:
                self._trace("callback.trace.send", e)
            return

        if action not in ("regen", "fix"):
            return await call.answer("Unknown action!", alert=True)

        prompt = self.prompts.get(str(msg_id))
        if not prompt:
            return await call.answer("Prompt not found", alert=True)

        # For regen: just generate again with stored prompt
        if action == "regen":
            try:
                await call.answer("Re-generating…", alert=False)
            except Exception:
                pass
            fake_message = call.message
            await self._generate(fake_message, prompt)
            return

        # For fix: ask user to send instructions; store artifact for 2 minutes
        if action == "fix":
            try:
                await call.answer("Send fix instructions", alert=False)
            except Exception:
                pass
            try:
                self._artifacts[str(call.message.id)] = {
                    "base_msg_id": msg_id,
                    "t": time.time(),
                }
                self.set("artifacts", self._artifacts)
            except Exception as e:
                self._trace("callback.fix.persist", e)

            await self.client.send_message(call.message.peer_id, self.strings("fix_prompt"), reply_to=call.message.id)
            return

    @loader.watcher()
    async def _fix_watcher(self, message):
        # If user replied with fix instructions within 2 minutes after pressing "fix"
        try:
            if not message.is_private and not message.is_group and not message.is_channel:
                return
        except Exception:
            pass

        if not getattr(message, "reply_to_msg_id", None):
            return

        key = str(message.reply_to_msg_id)
        art = self._artifacts.get(key)
        if not art:
            return

        # Expire after 2 minutes
        if time.time() - float(art.get("t", 0)) > 120:
            try:
                del self._artifacts[key]
                self.set("artifacts", self._artifacts)
            except Exception:
                pass
            return

        base_msg_id = art.get("base_msg_id")
        if not base_msg_id:
            return

        instructions = (getattr(message, "raw_text", None) or "").strip()
        if not instructions:
            return

        # Try to find the .py file in the replied-to message thread:
        try:
            base_msg = await self.client.get_messages(message.peer_id, ids=int(base_msg_id))
        except Exception as e:
            self._trace("fix_watcher.get_base", e)
            return

        if not base_msg or not getattr(base_msg, "file", None):
            return

        # Consume artifact
        try:
            del self._artifacts[key]
            self.set("artifacts", self._artifacts)
        except Exception:
            pass

        await self._refine(message, base_msg, instructions)