import json
import threading
import time
import uuid
import queue
from typing import List, Any, Dict, Callable, Optional
import logging

class DistributedCluster:
    """
    Enterprise Distributed Scanning Cluster.
    Optimized for high-concurrency and reliable task tracking.
    """
    def __init__(self, broker_url: str = None):
        self.logger = logging.getLogger("vortex.cluster")
        self.task_queue = queue.Queue()
        self.results_lock = threading.Lock()
        self.results: Dict[str, Any] = {}
        self.workers: List[threading.Thread] = []
        self.running = False
        self.cluster_id = str(uuid.uuid4())

    def submit_task(self, task_type: str, data: Dict[str, Any]) -> str:
        """Submit a scan task and return a unique tracking ID."""
        task_id = str(uuid.uuid4())
        task = {
            "id": task_id,
            "type": task_type,
            "data": data,
            "timestamp": time.time()
        }
        self.task_queue.put(task)
        self.logger.debug(f"[Cluster] Task {task_id} submitted: {task_type}")
        return task_id

    def start_workers(self, count: int = 20, worker_func: Callable = None):
        """Starts a high-performance worker pool."""
        if self.running: return
        self.running = True
        for i in range(count):
            t = threading.Thread(target=self._worker_loop, args=(worker_func,), name=f"Worker-{i}")
            t.daemon = True
            t.start()
            self.workers.append(t)
        self.logger.info(f"[Cluster] Cluster {self.cluster_id} active with {count} workers.")

    def _worker_loop(self, worker_func: Callable):
        while self.running:
            try:
                # Use a shorter timeout to allow for clean shutdown
                task = self.task_queue.get(timeout=1)
                task_id = task['id']
                
                try:
                    self.logger.debug(f"[Worker] Processing task {task_id}")
                    if worker_func:
                        result = worker_func(task)
                        with self.results_lock:
                            self.results[task_id] = {
                                "status": "completed",
                                "data": result,
                                "timestamp": time.time()
                            }
                except Exception as e:
                    self.logger.error(f"[Worker] Task {task_id} failed: {e}", exc_info=True)
                    with self.results_lock:
                        self.results[task_id] = {"status": "failed", "error": str(e)}
                finally:
                    self.task_queue.task_done()
                    
            except queue.Empty:
                continue

    def wait_for_completion(self, timeout: Optional[float] = None):
        """Blocks until all submitted tasks are processed."""
        self.logger.info("[Cluster] Waiting for all tasks to complete...")
        self.task_queue.join()

    def get_results(self) -> Dict[str, Any]:
        """Atomically retrieves and clears the results cache."""
        with self.results_lock:
            snapshot = self.results.copy()
            self.results.clear()
            return snapshot

    def shutdown(self):
        """Gracefully shuts down all workers."""
        self.logger.info("[Cluster] Initiating graceful shutdown...")
        self.running = False
        self.wait_for_completion()
        for t in self.workers:
            t.join(timeout=2)
        self.logger.info("[Cluster] All workers terminated.")
