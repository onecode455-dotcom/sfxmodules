# meta developer: @Akira_Lucky_Star

import logging
import base64
import aiohttp
from .. import loader, utils

logger = logging.getLogger(__name__)


@loader.tds
class GitHubUploaderMod(loader.Module):
    """Upload .py files to GitHub repository and get raw link"""

    strings = {
        "name": "GitHubUploader",
        "no_token": "❌ <b>GitHub token not configured!</b>\n<blockquote><code>.config GitHubUploader</code></blockquote>",
        "no_repo": "❌ <b>Repository not configured!</b>\n<blockquote><code>.config GitHubUploader</code></blockquote>",
        "no_file": "❌ <b>Reply to a .py file!</b>",
        "not_py": "❌ <b>Only .py files are supported!</b>",
        "uploading": "⏳ <b>Uploading to GitHub...</b>",
        "success": (
            "✅ <b>File uploaded!</b>\n\n"
            "<blockquote>"
            "📁 <b>File:</b> <code>{}</code>\n"
            "🔗 <b>Raw URL:</b>\n<code>{}</code>"
            "</blockquote>"
        ),
        "error": "❌ <b>Error:</b>\n<blockquote><code>{}</code></blockquote>",
        "file_exists": "⚠️ <b>File exists. Updating...</b>",
        "loading_repos": "⏳ <b>Loading repositories...</b>",
        "no_repos": "📭 <b>No repositories found</b>",
        "repos_list": "📚 <b>GitHub Repos</b> <code>[{}/{}]</code>\n\n{}",
        "repo_item": (
            "<blockquote>"
            "<b>{}.</b> <code>{}</code> {}\n"
            "⭐ <code>{}</code> │ 🍴 <code>{}</code>\n"
            "<i>{}</i>"
            "</blockquote>\n"
        ),
        "config_info": (
            "⚙️ <b>GitHub Uploader Config</b>\n\n"
            "<blockquote>"
            "🔑 <b>Token:</b> {}\n"
            "📁 <b>Repo:</b> <code>{}</code>\n"
            "🌿 <b>Branch:</b> <code>{}</code>\n"
            "📂 <b>Path:</b> <code>{}</code>"
            "</blockquote>"
        ),
    }

    strings_ru = {
        "no_token": "❌ <b>GitHub токен не настроен!</b>\n<blockquote><code>.config GitHubUploader</code></blockquote>",
        "no_repo": "❌ <b>Репозиторий не настроен!</b>\n<blockquote><code>.config GitHubUploader</code></blockquote>",
        "no_file": "❌ <b>Ответьте на .py файл!</b>",
        "not_py": "❌ <b>Только .py файлы!</b>",
        "uploading": "⏳ <b>Загрузка на GitHub...</b>",
        "success": (
            "✅ <b>Файл загружен!</b>\n\n"
            "<blockquote>"
            "📁 <b>Файл:</b> <code>{}</code>\n"
            "🔗 <b>Raw URL:</b>\n<code>{}</code>"
            "</blockquote>"
        ),
        "error": "❌ <b>Ошибка:</b>\n<blockquote><code>{}</code></blockquote>",
        "file_exists": "⚠️ <b>Файл существует. Обновление...</b>",
        "loading_repos": "⏳ <b>Загрузка репозиториев...</b>",
        "no_repos": "📭 <b>Репозитории не найдены</b>",
        "repos_list": "📚 <b>GitHub Репозитории</b> <code>[{}/{}]</code>\n\n{}",
        "repo_item": (
            "<blockquote>"
            "<b>{}.</b> <code>{}</code> {}\n"
            "⭐ <code>{}</code> │ 🍴 <code>{}</code>\n"
            "<i>{}</i>"
            "</blockquote>\n"
        ),
        "config_info": (
            "⚙️ <b>Настройки GitHub Uploader</b>\n\n"
            "<blockquote>"
            "🔑 <b>Токен:</b> {}\n"
            "📁 <b>Репо:</b> <code>{}</code>\n"
            "🌿 <b>Ветка:</b> <code>{}</code>\n"
            "📂 <b>Путь:</b> <code>{}</code>"
            "</blockquote>"
        ),
    }

    def __init__(self):
        self.config = loader.ModuleConfig(
            loader.ConfigValue(
                "github_token",
                "",
                lambda: "GitHub Personal Access Token",
                validator=loader.validators.Hidden(),
            ),
            loader.ConfigValue(
                "repository",
                "",
                lambda: "Repository in format: username/repo",
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "branch",
                "main",
                lambda: "Branch name (default: main)",
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "path",
                "",
                lambda: "Path in repository (e.g., modules/ or leave empty for root)",
                validator=loader.validators.String(),
            ),
        )

    async def _get_file_sha(self, session, headers, file_path):
        """Get SHA of existing file for update"""
        repo = self.config["repository"]
        branch = self.config["branch"]
        
        url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={branch}"
        
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("sha")
        return None

    async def _upload_to_github(self, file_content: bytes, filename: str):
        """Upload file to GitHub repository"""
        token = self.config["github_token"]
        repo = self.config["repository"]
        branch = self.config["branch"]
        path = self.config["path"]

        if path and not path.endswith("/"):
            path += "/"
        
        file_path = f"{path}{filename}"
        
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }

        content_b64 = base64.b64encode(file_content).decode("utf-8")

        async with aiohttp.ClientSession() as session:
            sha = await self._get_file_sha(session, headers, file_path)
            
            url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
            
            payload = {
                "message": f"Upload {filename} via Hikka GitHubUploader",
                "content": content_b64,
                "branch": branch,
            }
            
            if sha:
                payload["sha"] = sha

            async with session.put(url, headers=headers, json=payload) as resp:
                if resp.status in (200, 201):
                    raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{file_path}"
                    return True, raw_url, sha is not None
                else:
                    error_data = await resp.json()
                    error_msg = error_data.get("message", "Unknown error")
                    return False, error_msg, False

    async def _get_user_repos(self):
        """Get list of user's repositories"""
        token = self.config["github_token"]
        
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        
        repos = []
        page = 1
        
        async with aiohttp.ClientSession() as session:
            while True:
                url = f"https://api.github.com/user/repos?per_page=100&page={page}&sort=updated"
                
                async with session.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        error_data = await resp.json()
                        return None, error_data.get("message", "Unknown error")
                    
                    data = await resp.json()
                    
                    if not data:
                        break
                    
                    repos.extend(data)
                    page += 1
                    
                    if len(data) < 100:
                        break
        
        return repos, None

    @loader.command(ru_doc="<ответ на .py файл> - Загрузить файл на GitHub")
    async def ghupload(self, message):
        """<reply to .py file> - Upload file to GitHub"""
        
        if not self.config["github_token"]:
            await utils.answer(message, self.strings["no_token"])
            return

        if not self.config["repository"]:
            await utils.answer(message, self.strings["no_repo"])
            return

        reply = await message.get_reply_message()
        
        if not reply or not reply.file:
            await utils.answer(message, self.strings["no_file"])
            return

        filename = reply.file.name
        
        if not filename or not filename.endswith(".py"):
            await utils.answer(message, self.strings["not_py"])
            return

        await utils.answer(message, self.strings["uploading"])

        try:
            file_content = await reply.download_media(bytes)
            success, result, was_update = await self._upload_to_github(file_content, filename)
            
            if success:
                await utils.answer(message, self.strings["success"].format(filename, result))
            else:
                await utils.answer(message, self.strings["error"].format(result))
                
        except Exception as e:
            logger.exception("GitHub upload error")
            await utils.answer(message, self.strings["error"].format(str(e)))

    @loader.command(ru_doc="Показать настройки GitHub")
    async def ghinfo(self, message):
        """Show GitHub configuration"""
        
        token = "✅" if self.config["github_token"] else "❌"
        repo = self.config["repository"] or "—"
        branch = self.config["branch"]
        path = self.config["path"] or "/"
        
        await utils.answer(message, self.strings["config_info"].format(token, repo, branch, path))

    @loader.command(ru_doc="Список ваших GitHub репозиториев")
    async def ghrepos(self, message):
        """List your GitHub repositories"""
        
        if not self.config["github_token"]:
            await utils.answer(message, self.strings["no_token"])
            return
        
        await utils.answer(message, self.strings["loading_repos"])
        
        try:
            repos, error = await self._get_user_repos()
            
            if error:
                await utils.answer(message, self.strings["error"].format(error))
                return
            
            if not repos:
                await utils.answer(message, self.strings["no_repos"])
                return
            
            repos_text = ""
            for i, repo in enumerate(repos[:30], 1):
                name = repo["full_name"]
                private = "🔒" if repo["private"] else "🌐"
                stars = repo["stargazers_count"]
                forks = repo["forks_count"]
                description = repo["description"] or "—"
                
                if len(description) > 40:
                    description = description[:37] + "..."
                
                repos_text += self.strings["repo_item"].format(
                    i, name, private, stars, forks, description
                )
            
            total = len(repos)
            shown = min(total, 30)
            
            if total > 30:
                repos_text += f"<blockquote><i>+{total - 30} more...</i></blockquote>"
            
            await utils.answer(message, self.strings["repos_list"].format(shown, total, repos_text))
            
        except Exception as e:
            logger.exception("GitHub repos fetch error")
            await utils.answer(message, self.strings["error"].format(str(e)))