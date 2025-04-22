# WebsiteTest
https://pixeldrain.com/u/4fJy3vMP
```python
import requests
import threading

def send_requests():
    for _ in range(1000):
        try:
            requests.get("http://192.168.1.100:5000")
        except:
            pass

threads = []
for _ in range(50):  # Simulate 50 "clients"
    t = threading.Thread(target=send_requests)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```
