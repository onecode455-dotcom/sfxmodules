# meta developer: https://t.me/DegradationModules/

from .. import loader, utils
import aiohttp
import logging
import re
import io
import asyncio
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


@loader.tds
class TikTokDownloaderMod(loader.Module):
    """Download TikTok videos by link (always no-watermark, best quality when possible)"""

    strings = {
        "name": "TikTokDownloader",
        "downloading": "<b>⏳ Downloading TikTok video...</b>",
        "error": "<b>❌ Error: {}</b>",
        "invalid_link": "<b>❌ Invalid TikTok link!</b>",
        "no_link": "<b>❌ Please provide a TikTok link!\nUsage: .tiktok &lt;link&gt;</b>",
        "api_error": "<b>❌ Failed to get download link. Try again later.</b>",
        "too_big": "<b>❌ Video is too large to download ({size} MB).</b>",
    }

    strings_ru = {
        "downloading": "<b>⏳ Скачиваю видео из TikTok...</b>",
        "error": "<b>❌ Ошибка: {}</b>",
        "invalid_link": "<b>❌ Неверная ссылка на TikTok!</b>",
        "no_link": "<b>❌ Укажите ссылку на TikTok!\nИспользование: .tiktok &lt;ссылка&gt;</b>",
        "api_error": "<b>❌ Не удалось получить ссылку на скачивание. Попробуйте позже.</b>",
        "too_big": "<b>❌ Видео слишком большое для скачивания ({size} МБ).</b>",
    }

    def __init__(self):
        self.config = loader.ModuleConfig(
            loader.ConfigValue(
                "max_size_mb",
                120,
                lambda: "Max size (MB) to download into memory before sending",
                validator=loader.validators.Integer(minimum=5, maximum=2048),
            ),
            loader.ConfigValue(
                "timeout",
                30,
                lambda: "HTTP timeout (seconds)",
                validator=loader.validators.Integer(minimum=10, maximum=120),
            ),
        )

    # --- Utils ---

    def _is_tiktok_link(self, url: str) -> bool:
        patterns = [
            r"^https?://(?:www\.)?tiktok\.com/@[\w.-]+/video/\d+",
            r"^https?://vm\.tiktok\.com/[\w/]+",
            r"^https?://vt\.tiktok\.com/[\w/]+",
            r"^https?://(?:www\.)?tiktok\.com/t/[\w/]+",
            r"^https?://(?:www\.)?tiktok\.com/.*",  # keep broad as TikTok has many formats
        ]
        return any(re.match(p, url) for p in patterns)

    def _timeout(self) -> aiohttp.ClientTimeout:
        return aiohttp.ClientTimeout(total=int(self.config["timeout"]))

    def _ua_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }

    async def _request_json(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        try:
            async with session.request(method, url, **kwargs) as resp:
                if resp.status != 200:
                    return None
                # Some APIs return wrong content-type
                return await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.info("HTTP JSON request failed: %s", e)
            return None
        except Exception:
            logger.exception("Unexpected error in _request_json")
            return None

    # --- Providers (always try no-watermark / best quality) ---

    async def _provider_tikwm(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """
        TikWM: returns hdplay/play/wmplay.
        We prefer hdplay (no watermark usually), then play, never wmplay.
        """
        api_url = "https://www.tikwm.com/api/"
        data = await self._request_json(
            session,
            "POST",
            api_url,
            data={"url": url, "hd": "1"},
            headers=self._ua_headers(),
        )
        if not data or data.get("code") != 0:
            return None

        v = (data.get("data") or {}) if isinstance(data.get("data"), dict) else {}
        video_url = v.get("hdplay") or v.get("play")
        if not video_url:
            return None

        author = "Unknown"
        a = v.get("author")
        if isinstance(a, dict):
            author = a.get("unique_id") or a.get("nickname") or author

        return {
            "video_url": video_url,
            "title": v.get("title") or "TikTok Video",
            "author": author,
        }

    async def _provider_tikmate(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """
        TikMate public endpoint (may change). We keep it as best-effort fallback.
        """
        api_url = "https://tikmate.app/api/lookup"
        data = await self._request_json(
            session,
            "POST",
            api_url,
            data={"url": url},
            headers={**self._ua_headers(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        if not data or not isinstance(data, dict):
            return None

        # Known formats: {"success":true,"data":{"token":"...","id":"..."}}
        d = data.get("data") if isinstance(data.get("data"), dict) else None
        if not d:
            return None

        token = d.get("token")
        vid = d.get("id") or d.get("video_id") or d.get("id_video")
        if not token or not vid:
            return None

        # Download URL pattern used by tikmate
        video_url = f"https://tikmate.app/download/{token}/{vid}.mp4"
        return {"video_url": video_url, "title": "TikTok Video", "author": "Unknown"}

    async def _get_video_info(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Tries multiple providers; returns dict with video_url/title/author.
        """
        async with aiohttp.ClientSession(timeout=self._timeout()) as session:
            # Order: tikwm (most stable) -> tikmate (best-effort)
            for provider in (self._provider_tikwm, self._provider_tikmate):
                try:
                    res = await provider(session, url)
                    if res and res.get("video_url"):
                        return res
                except Exception:
                    logger.exception("Provider failed: %s", provider.__name__)
                    continue
        return None

    async def _download_video_content(self, video_url: str) -> Optional[bytes]:
        """
        Downloads video into memory with size guard.
        """
        max_size = int(self.config["max_size_mb"]) * 1024 * 1024

        async with aiohttp.ClientSession(timeout=self._timeout()) as session:
            try:
                # Try HEAD to get size
                try:
                    async with session.head(video_url, headers=self._ua_headers(), allow_redirects=True) as rhead:
                        clen = rhead.headers.get("Content-Length")
                        if clen and clen.isdigit() and int(clen) > max_size:
                            return b"__TOO_BIG__:" + str(int(clen)).encode()
                except Exception:
                    # HEAD may be blocked; ignore
                    pass

                async with session.get(
                    video_url,
                    headers=self._ua_headers(),
                    allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        return None

                    buf = bytearray()
                    async for chunk in resp.content.iter_chunked(256 * 1024):
                        if not chunk:
                            continue
                        buf.extend(chunk)
                        if len(buf) > max_size:
                            return b"__TOO_BIG__:" + str(len(buf)).encode()
                    return bytes(buf)

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.info("Video download failed: %s", e)
                return None
            except Exception:
                logger.exception("Unexpected error in _download_video_content")
                return None

    @loader.command(
        ru_doc="<ссылка> - Скачать видео из TikTok (без водяного знака, хорошее качество)",
        alias="tt",
    )
    async def tiktok(self, message):
        """<link> - Download TikTok video (no watermark, best quality when possible)"""
        args = (utils.get_args_raw(message) or "").strip()

        if not args:
            await utils.answer(message, self.strings("no_link"))
            return

        url = args
        if not self._is_tiktok_link(url):
            await utils.answer(message, self.strings("invalid_link"))
            return

        status = await utils.answer(message, self.strings("downloading"))

        try:
            info = await self._get_video_info(url)
            if not info:
                await utils.answer(status, self.strings("api_error"))
                return

            content = await self._download_video_content(info["video_url"])
            if not content:
                await utils.answer(status, self.strings("error").format("Failed to download video"))
                return

            if content.startswith(b"__TOO_BIG__:"):
                raw = content.split(b":", 1)[1]
                try:
                    size_mb = round(int(raw) / 1024 / 1024, 2)
                except Exception:
                    size_mb = "?"
                await utils.answer(status, self.strings("too_big").format(size=size_mb))
                return

            try:
                await status.delete()
            except Exception:
                pass

            video_file = io.BytesIO(content)
            video_file.name = "tiktok.mp4"

            # As requested: no captions/inscriptions
            await message.client.send_file(
                message.peer_id,
                file=video_file,
                caption=None,
                supports_streaming=True,
                reply_to=message.reply_to_msg_id,
                force_document=False,
            )

        except Exception as e:
            logger.exception("Error downloading TikTok video")
            try:
                await utils.answer(status, self.strings("error").format(utils.escape_html(str(e))))
            except Exception:
                await message.respond(self.strings("error").format(utils.escape_html(str(e))))