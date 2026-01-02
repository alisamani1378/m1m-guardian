import time
import asyncio
import redis.asyncio as redis
import logging

log = logging.getLogger("guardian.store")

class Store:
    def __init__(self, url:str):
        # استفاده از connection pool با تنظیمات بهینه
        self.r = redis.from_url(
            url,
            decode_responses=True,
            socket_timeout=5.0,           # timeout برای هر operation
            socket_connect_timeout=5.0,   # timeout برای اتصال
            retry_on_timeout=True,        # تلاش مجدد در timeout
            health_check_interval=30,     # health check هر 30 ثانیه
            max_connections=20,           # حداکثر اتصالات همزمان
        )
        self._last_error_log = 0.0

    async def _safe_execute(self, coro, default=None):
        """Execute Redis operation with timeout and error handling."""
        try:
            return await asyncio.wait_for(coro, timeout=10.0)
        except asyncio.TimeoutError:
            now = time.time()
            if now - self._last_error_log > 60:  # log هر 60 ثانیه
                log.error("Redis operation timeout")
                self._last_error_log = now
            return default
        except redis.ConnectionError as e:
            now = time.time()
            if now - self._last_error_log > 60:
                log.error("Redis connection error: %s", e)
                self._last_error_log = now
            return default
        except Exception as e:
            now = time.time()
            if now - self._last_error_log > 60:
                log.error("Redis error: %s", e)
                self._last_error_log = now
            return default

    async def ping(self) -> bool:
        """Test Redis connection. Raises exception if fails."""
        return await asyncio.wait_for(self.r.ping(), timeout=5.0)

    async def add_ip(self, inbound:str, email:str, ip:str, limit:int):
        """
        برمی‌گرداند: (evicted_ips:list[str], already_present:bool)
        """
        try:
            key=f"a:{inbound}:{email}"
            now_ts=time.time()
            pipe=self.r.pipeline()
            # امتیاز=زمان برای ZSET
            pipe.zadd(key, {ip: now_ts})
            pipe.zcard(key)
            pipe.expire(key, 3600*6)  # نگهداری ۶ ساعت (قابل تغییر)
            res=await asyncio.wait_for(pipe.execute(), timeout=5.0)
            count=int(res[1])
            evicted=[]
            if count>limit:
                # قدیمی‌ها را حذف کن تا به limit برسیم
                k = count - limit
                old=await asyncio.wait_for(self.r.zrange(key, 0, k-1), timeout=3.0)
                if old:
                    await asyncio.wait_for(self.r.zrem(key, *old), timeout=3.0)
                    evicted=old
            return evicted, (count>0 and not evicted and await asyncio.wait_for(self.r.zscore(key, ip), timeout=3.0) is not None)
        except asyncio.TimeoutError:
            log.warning("add_ip timeout for %s:%s", inbound, email)
            return [], False
        except Exception as e:
            log.warning("add_ip error: %s", e)
            return [], False

    async def mark_banned(self, ip:str, seconds:int):
        try:
            await asyncio.wait_for(self.r.setex(f"banned:{ip}", seconds, "1"), timeout=3.0)
        except Exception as e:
            log.warning("mark_banned error ip=%s: %s", ip, e)

    async def is_banned_recently(self, ip:str)->bool:
        try:
            return await asyncio.wait_for(self.r.exists(f"banned:{ip}"), timeout=3.0) == 1
        except Exception:
            return False

    async def list_active(self, limit:int=200):
        """Return up to limit entries of (inbound,email,ips:list)."""
        out=[]
        cursor=0
        pattern='a:*'
        while True:
            cursor, keys = await self.r.scan(cursor=cursor, match=pattern, count=200)
            for k in keys:
                try:
                    _, inbound, email = k.split(':',2)
                except ValueError:
                    continue
                ips = await self.r.zrange(k,0,-1)
                out.append((inbound,email,ips))
                if len(out)>=limit:
                    return out
            if cursor==0:
                break
        return out

    async def list_banned(self, limit:int=200):
        out=[]
        cursor=0
        while True:
            cursor, keys = await self.r.scan(cursor=cursor, match='banned:*', count=200)
            for k in keys:
                ip=k.split(':',1)[1]
                ttl=await self.r.ttl(k)
                out.append((ip, ttl))
                if len(out)>=limit:
                    return out
            if cursor==0:
                break
        return out

    async def unmark_banned(self, ip:str):
        await self.r.delete(f"banned:{ip}")

    async def unmark_all_banned(self) -> int:
        """Delete all banned:* keys. Returns count of deleted keys (best-effort)."""
        total_deleted=0
        cursor=0
        while True:
            cursor, keys = await self.r.scan(cursor=cursor, match='banned:*', count=500)
            if keys:
                pipe=self.r.pipeline()
                for k in keys:
                    pipe.delete(k)
                try:
                    res=await pipe.execute()
                    total_deleted += sum(1 for r in res if (isinstance(r,int) and r>0) or r==True)
                except Exception:
                    pass
            if cursor==0:
                break
        return total_deleted

    async def get_all_nodes(self)->list[str]:
        # اختیاری: می‌تواند برای cross-node ban استفاده شود
        return []
