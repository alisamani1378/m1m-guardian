import time, asyncio
import redis.asyncio as redis

class Store:
    def __init__(self, url:str):
        self.r = redis.from_url(url, decode_responses=True)

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

    async def get_all_nodes(self)->list[str]:
        # اختیاری: می‌تواند برای cross-node ban استفاده شود
        return []
