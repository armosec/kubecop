# locustfile.py
from locust import HttpUser, task, constant_throughput
import os

class QuickstartUser(HttpUser):
    wait_time = constant_throughput(0.1)
    host = os.getenv("TARGET_URL")
    @task
    def request(self):
        self.client.get("/")
