from threading import Thread, Condition
import key_cache_handler as key_cache

class ResponseChecker(Thread):
    def __init__(self, sleepTime):
        Thread.__init__(self)
        self.sleepTime = sleepTime
        self.bRunning = True
        self.condition = Condition()

    def run(self):
        while self.bRunning:
            self.condition.acquire()
            self.condition.wait(self.sleepTime)
            self.condition.release()
            if self.bRunning == False:
                break

            print(f"--- woke-up after {self.sleepTime}s : {self.getName()}")
            response = key_cache.read_response()
            if response:
                if key_cache.read_mem_response(bLock=False) != response:
                    if key_cache.write_mem_response(response):
                        print(f"write key response to mem cache :\n {response}")
                    else:
                        print("mem cache write error on key response")
            else:
                key_cache.write_mem_response(None)
            
            last_updated = key_cache.read_last_updated()
            if last_updated:
                if key_cache.read_mem_last_updated(bLock=False) != last_updated:
                    if key_cache.write_mem_last_updated(last_updated):
                        print(f"write last updated to mem cache : {last_updated}")
                    else:
                        print("mem cache write error on last_updated")
            else:
                key_cache.write_mem_last_updated(None)

            tv_token = key_cache.read_tv_token()
            if tv_token:
                if key_cache.read_mem_tv_token(bLock=False) != tv_token:
                    if key_cache.write_mem_tv_token(tv_token):
                        print(f"write tv token to mem cache : {tv_token}")
                    else:
                        print("mem cache write error on tv token")
            else:
                key_cache.write_mem_tv_token(None)

        print(f"{self.getName()} thread exits !!!")

    def terminate(self):
        self.bRunning = False
        self.condition.acquire()
        self.condition.notify()
        self.condition.release()


