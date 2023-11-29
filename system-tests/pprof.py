import subprocess
import requests
import time


class pprof_recorder:
    def __init__(self, namespace, pod_name, port):
        self.namespace = namespace
        self.pod_name = pod_name
        self.port = port
        self.proc = None
        # Start kubectl port-forward as a subprocess
        port_forward_command = "kubectl -n %s port-forward pod/%s %d:%d" % (self.namespace,self.pod_name, self.port, self.port)
        self.proc = subprocess.Popen(port_forward_command, shell=True)

        # Give it a moment to establish the port forwarding
        time.sleep(2)

    def __del__(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()

    def record(self, duration=60, type="cpu", filename=None):
        if type == "cpu":
            url = 'http://localhost:%d/debug/pprof/profile?seconds=%d' % (self.port, duration)
        elif type == "mem":
            url = 'http://localhost:%d/debug/pprof/heap?seconds=%d' % (self.port, duration)
        response = requests.get(url)
        response.raise_for_status()
        if filename:
            with open(filename, 'wb') as f:
                f.write(response.content)
            return True
        else:
            return response.content

    def record_detached(self, duration=60, type="cpu", filename='pprof.pprof'):
        # Call the record function in a different thread
        import threading
        thread = threading.Thread(target=self.record, args=(duration, type, filename))
        thread.start()
        return True

