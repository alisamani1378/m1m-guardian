import time
import redis.asyncio as redis

class Store:
    def __init__(self, url:str):
        self.r = redis.from_url(url, decode_responses=True)

    async def ping(self) -> bool:
        """Test Redis connection. Raises exception if fails."""
        return await self.r.ping()

    async def add_ip(self, inbound:str, email:str, ip:str, limit:int):
        """
        برمی‌گرداند: (evicted_ips:list[str], already_present:bool)
        """
        key=f"a:{inbound}:{email}"
        now=time.time()
        pipe=self.r.pipeline()
        # امتیاز=زمان برای ZSET
        pipe.zadd(key, {ip: now})
        pipe.zcard(key)
        pipe.expire(key, 3600*6)  # نگهداری ۶ ساعت (قابل تغییر)
        res=await pipe.execute()
        count=int(res[1])
        evicted=[]
        if count>limit:
            # قدیمی‌ها را حذف کن تا به limit برسیم
            k = count - limit
            old=await self.r.zrange(key, 0, k-1)
            if old:
                await self.r.zrem(key, *old)
                evicted=old
        return evicted, (count>0 and not evicted and await self.r.zscore(key, ip) is not None)

    async def mark_banned(self, ip:str, seconds:int):
        await self.r.setex(f"banned:{ip}", seconds, "1")

    async def is_banned_recently(self, ip:str)->bool:
        return await self.r.exists(f"banned:{ip}") == 1

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
