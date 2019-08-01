from flask import current_app


from .exceptions import RequestProcessError


class RLimit():
    def __init__(self, redis, remote_addr):
        self.redis = redis
        self.ban_time = current_app.config["RLIMIT_BAN_TIME"]
        self.window_time = current_app.config["RLIMIT_WINDOW_TIME"]
        self.max_hits = current_app.config["RLIMIT_MAX_HITS"]
        self.key = "rate-limit:{}".format(remote_addr)

        self.hits = self._get_hits()

    def count(self):
        pipe = self.redis.pipeline(transaction=True)
        pipe.setnx(self.key, 0)  # Set to 0 (default) when the key does Not eXist
        pipe.incr(self.key)
        pipe.expire(self.key, self.window_time)
        pipe_result = pipe.execute()

        self.hits = pipe_result[1]

    def _get_hits(self):
        hits_redis = self.redis.get(self.key)
        hits = 0 if not hits_redis else int(hits_redis)
        return hits

    def reached_enough_hits(self):
        return self.hits > self.max_hits

    def set_ban_window(self):
        self.redis.expire(self.key, self.ban_time)

    def deny_access(self):
        raise RequestProcessError("You hit the rate limit")


def check_rate_limit(redis, remote_addr):
    rl = RLimit(redis, remote_addr)

    if rl.reached_enough_hits():
        rl.deny_access()

    else:
        rl.count()
        if rl.reached_enough_hits():
            rl.set_ban_window()
            rl.deny_access()


def rlimit_enabled():
    return int(current_app.config["RLIMIT_MAX_HITS"]) > 0
