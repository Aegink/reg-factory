"""reauth-web features hosted by the existing K12 service."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from dataclasses import replace
from pathlib import Path
from typing import Callable, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from vendor.reauth_web.config import Settings, load_settings
from vendor.reauth_web.convert import ConvertError
from vendor.reauth_web.engine import STEPS_CONVERT, STEPS_LOGIN, STEPS_REDEEM
from vendor.reauth_web.formats import OUTPUT_KINDS, output_bundle
from vendor.reauth_web.jobs import JobManager, MODE_REDEEM
from vendor.reauth_web.parsing import AccountLineError, parse_account_lines
from vendor.reauth_web.security import RateLimiter, SessionTokens
from vendor.reauth_web.upstream import UpstreamError
from vendor.reauth_web.visits import VisitTracker


class SubmitRequest(BaseModel):
    text: str = Field(default="", max_length=200000)
    mode: Literal["reauth", "redeem"] = "reauth"


class ConvertRequest(BaseModel):
    text: str = Field(default="", max_length=2000000)


class VisitRequest(BaseModel):
    visitor_id: str = Field(min_length=1, max_length=128)


class ReauthService:
    def __init__(self, data_root: Path, config: Callable[[], dict], environment: Callable[[], dict]):
        self.data_root = data_root
        self.config = config
        self.environment = environment
        self.managers: dict[tuple, JobManager] = {}
        self.busy: dict[JobManager, int] = {}
        # Results and credentials live in memory; only anonymous visits persist.
        self.tokens = SessionTokens(data_root, secret=secrets.token_urlsafe(32))
        self.visits = VisitTracker(data_root)
        self.limiter = RateLimiter(load_settings().submit_limit_per_minute)
        self.sweeper: asyncio.Task | None = None

    def settings(self) -> Settings:
        from common.proxy_switch import effective_proxy_url

        config = self.config()
        defaults = load_settings()
        return replace(
            defaults,
            data_dir=self.data_root,
            proxy=str(config.get("reauth_proxy") or effective_proxy_url(self.environment())),
            concurrency=max(1, min(5, int(config.get("concurrency") or 1))),
            max_accounts_per_submit=min(200, defaults.max_accounts_per_submit),
            account_timeout_seconds=int(config.get("timeout") or defaults.account_timeout_seconds),
            upstream_base=str(config.get("reauth_upstream_base") or "").rstrip("/"),
            upstream_key=str(config.get("reauth_upstream_key") or ""),
        )

    def manager(self) -> JobManager:
        settings = self.settings()
        # A config change applies to new jobs. Existing jobs keep their egress
        # and upstream credentials until their results expire.
        key = (settings.proxy, settings.concurrency, settings.account_timeout_seconds,
               settings.upstream_base, settings.upstream_key)
        if key not in self.managers:
            self.managers[key] = JobManager(settings)
        return self.managers[key]

    def active_jobs(self, owner: str) -> int:
        return sum(manager.active_jobs_for_ip(owner) for manager in self.managers.values())

    def job(self, job_id: str):
        for manager in self.managers.values():
            job = manager.get(job_id)
            if job:
                return manager, job
        raise HTTPException(404, "任务不存在或已过期")

    def cleanup(self) -> None:
        for key, manager in list(self.managers.items()):
            manager.cleanup()
            if not manager.jobs and manager not in self.busy:
                manager.close()
                self.managers.pop(key, None)

    async def start(self) -> None:
        async def sweep():
            while True:
                await asyncio.sleep(60)
                self.cleanup()

        self.sweeper = asyncio.create_task(sweep())

    async def close(self) -> None:
        if self.sweeper:
            self.sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.sweeper
            self.sweeper = None
        for manager in self.managers.values():
            manager.close()
        self.managers.clear()


def create_router(service_provider: Callable[[], ReauthService]) -> APIRouter:
    async def no_store(response: Response):
        response.headers["Cache-Control"] = "no-store"

    router = APIRouter(prefix="/api/reauth", tags=["K12 reauth"], dependencies=[Depends(no_store)])

    async def service() -> ReauthService:
        return service_provider()

    def client_ip(request: Request) -> str:
        return str(getattr(request.client, "host", "") or "local")

    async def submission(request: Request, runtime: ReauthService = Depends(service)) -> ReauthService:
        if not runtime.tokens.verify(request.headers.get("X-REAUTH-TOKEN", ""),
                                     ip=client_ip(request), user_agent=request.headers.get("User-Agent", "")):
            raise HTTPException(403, "会话校验失败，请刷新重登面板后重试")
        allowed, retry = runtime.limiter.allow(client_ip(request))
        if not allowed:
            raise HTTPException(429, "提交太频繁，请稍后重试", headers={"Retry-After": str(retry)})
        runtime.cleanup()
        if runtime.active_jobs(client_ip(request)) >= runtime.settings().max_jobs_per_ip:
            raise HTTPException(429, "还有任务在运行，请等待完成")
        return runtime

    @router.get("/session")
    async def session(request: Request, runtime: ReauthService = Depends(service)):
        token, ttl = runtime.tokens.issue(ip=client_ip(request), user_agent=request.headers.get("User-Agent", ""))
        return {"token": token, "expires_in": ttl}

    @router.get("/meta")
    async def meta(runtime: ReauthService = Depends(service)):
        settings = runtime.settings()
        return {"max_accounts": settings.max_accounts_per_submit, "concurrency": settings.concurrency,
                "outputs": list(OUTPUT_KINDS), "proxy_configured": bool(settings.proxy),
                "redeem_configured": bool(settings.upstream_base and settings.upstream_key),
                "result_ttl_seconds": max(settings.job_ttl_seconds, settings.result_ttl_seconds),
                "steps": {mode: [label for _, label in steps] for mode, steps in
                          (("reauth", STEPS_LOGIN), ("redeem", STEPS_REDEEM), ("convert", STEPS_CONVERT))}}

    @router.post("/submit")
    async def submit(payload: SubmitRequest, request: Request, runtime: ReauthService = Depends(submission)):
        settings = runtime.settings()
        if payload.mode == "redeem" and not (settings.upstream_base and settings.upstream_key):
            raise HTTPException(400, "请先配置上游兑换地址和密钥")
        try:
            accounts, errors = parse_account_lines(payload.text, max_accounts=settings.max_accounts_per_submit)
        except AccountLineError as exc:
            raise HTTPException(422, str(exc)) from exc
        manager = runtime.manager()
        job = manager.create_job(accounts, mode=payload.mode, owner_ip=client_ip(request), errors=errors)
        with job.lock:
            return job.snapshot()

    @router.post("/convert")
    async def convert(payload: ConvertRequest, request: Request, runtime: ReauthService = Depends(submission)):
        manager = runtime.manager()
        runtime.busy[manager] = runtime.busy.get(manager, 0) + 1
        try:
            # Conversions are local but may be large; keep them off the API loop.
            job = await asyncio.to_thread(manager.create_convert_job, payload.text, owner_ip=client_ip(request))
        except (ConvertError, ValueError, TypeError, OverflowError, OSError) as exc:
            detail = str(exc) if isinstance(exc, ConvertError) else "账号字段格式不正确，请检查数值和过期时间"
            raise HTTPException(422, detail) from exc
        finally:
            runtime.busy[manager] -= 1
            if not runtime.busy[manager]:
                runtime.busy.pop(manager)
        return job.snapshot()

    @router.get("/job/{job_id}")
    async def status(job_id: str, request: Request, runtime: ReauthService = Depends(service)):
        runtime.cleanup()
        _, job = runtime.job(job_id)
        if job.owner_ip != client_ip(request):
            raise HTTPException(404, "任务不存在或已过期")
        with job.lock:
            return job.snapshot()

    @router.get("/job/{job_id}/download/{kind}")
    async def download(job_id: str, kind: str, request: Request, runtime: ReauthService = Depends(service)):
        runtime.cleanup()
        manager, job = runtime.job(job_id)
        if job.owner_ip != client_ip(request):
            raise HTTPException(404, "任务不存在或已过期")
        if kind not in OUTPUT_KINDS:
            raise HTTPException(404, "不支持的下载格式")
        if not job.finished_at:
            raise HTTPException(409, "任务还没完成")
        if not (job.outputs or {}).get("count"):
            raise HTTPException(404, "没有可下载的成功账号")
        try:
            if job.mode == MODE_REDEEM:
                name, body, media_type = await asyncio.to_thread(manager.fetch_redeem_output, job, kind)
            else:
                name, body, media_type = await asyncio.to_thread(output_bundle, job.outputs, kind)
        except UpstreamError as exc:
            raise HTTPException(502, str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(404, "没有可下载的成功账号") from exc
        return Response(body, media_type=media_type, headers={"Cache-Control": "no-store",
                        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name, safe='')}"})

    @router.post("/visit")
    async def visit(payload: VisitRequest, runtime: ReauthService = Depends(service)):
        return await asyncio.to_thread(runtime.visits.record, payload.visitor_id)

    @router.get("/visit")
    async def visits(runtime: ReauthService = Depends(service)):
        return await asyncio.to_thread(runtime.visits.snapshot)

    return router
