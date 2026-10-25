import time
import requests
import statistics
from typing import List

def run_benchmark(iterations: int = 20):
    url = "http://localhost:8888/api/policies/simulate"
    payload = {
        "policy_expr": "action == 'file_write' IMPLIES resource.startswith('/tmp/')",
        "context": {
            "action": "file_write",
            "resource": "/workspace/README.md",
            "autonomy": 1
        }
    }
    
    latencies = []
    print(f"Starting benchmark: {iterations} iterations...")
    
    for i in range(iterations):
        start = time.perf_counter()
        try:
            res = requests.post(url, json=payload)
            res.raise_for_status()
            end = time.perf_counter()
            latencies.append((end - start) * 1000) # ms
        except Exception as e:
            print(f"Error at iteration {i}: {e}")
            
    if latencies:
        avg = statistics.mean(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18] # approx p95
        print("\nBenchmark Results:")
        print(f"- Average Latency: {avg:.2f} ms")
        print(f"- P95 Latency: {p95:.2f} ms")
        print(f"- Max Latency: {max(latencies):.2f} ms")
        print(f"- Min Latency: {min(latencies):.2f} ms")
    else:
        print("No successful iterations.")

if __name__ == "__main__":
    # Wait a bit for server to be fully ready if needed
    time.sleep(2)
    run_benchmark()
