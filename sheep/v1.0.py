import os
import argparse
import ctypes
import signal
from ctypes.util import find_library
import sys
import functools

# Clone 系统调用的标志
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNS = 0x00020000
# CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000

MS_REC = 0x0004000
MS_PRIVATE = 0x00020000
MS_BIND = 0x0001000


def _write_file(path, content):
    with open(path, "w") as f:
        f.write(content)


def _parse_limit(string):
    """
    将用户输入的限制（如 100m 或 2g）解析为字节数
    支持单位：k（KB）、m（MB）、g（GB）
    """

    try:
        num_str, unit = string[:-1], string[-1].lower()
        num = int(num_str)
    except Exception:
        sys.exit(f"[X] Failed to parse limit: {string}")

    trans_map = {
        "k": num * 1024,
        "m": num * 1024 * 1024,
        "g": num * 1024 * 1024 * 1024,
    }
    if unit not in trans_map:
        sys.exit(f"[X] Failed to parse limit: {string}")

    return trans_map[unit]


def libc_error_handler(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        args = [(i.encode() if type(i) is str else i) for i in args]
        result = func(*args, **kwargs)
        if result != 0:
            err_msg = f"[X] {func.__name__} failed: {os.strerror(ctypes.get_errno())}"
            sys.exit(err_msg)

        return result

    return wrapper


class Container:
    def __init__(self, root_path, memory_limit=None, cpu_limit=None):
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.cgroup_base_path = "/sys/fs/cgroup"  # cgroup 的挂载点
        self.root_path = os.path.abspath(root_path)
        if not os.path.exists(self.root_path):
            sys.exit(f"[X] The new root directory '{self.root_path}' does not exist!")

    def _set_cgroup_limit(self, pid):
        """
        为容器设置 memory 和 cpu 的 cgroup 限制
        """

        container_name = f"container_{pid}"
        memory_cgroup_path = os.path.join(
            self.cgroup_base_path, "memory", container_name
        )
        cpu_cgroup_path = os.path.join(self.cgroup_base_path, "cpu", container_name)

        try:  # 创建 cgroup 控制组目录
            os.makedirs(memory_cgroup_path, exist_ok=True)
            os.makedirs(cpu_cgroup_path, exist_ok=True)
        except Exception as e:
            sys.exit(f"[X] Failed to create cgroup directories: {e}")

        if self.memory_limit:
            # 设置 Memory 限制
            _write_file(
                os.path.join(memory_cgroup_path, "memory.limit_in_bytes"),
                str(self.memory_limit),
            )

        if self.cpu_limit:
            # 设置 CPU 限制
            cpu_quota_us = str(self.cpu_limit * 100000)  # 转换为微秒(100% = 100000)
            _write_file(os.path.join(cpu_cgroup_path, "cpu.cfs_quota_us"), cpu_quota_us)
            _write_file(
                os.path.join(cpu_cgroup_path, "cpu.cfs_period_us"), "100000"
            )  # 周期为 100ms

        # 将容器进程加入 cgroup
        _write_file(os.path.join(memory_cgroup_path, "tasks"), str(pid))
        _write_file(os.path.join(cpu_cgroup_path, "tasks"), str(pid))

    def _cleanup_cgroup(self, pid):
        """
        清理创建的 cgroup 目录
        """

        container_name = f"container_{pid}"
        memory_cgroup_path = os.path.join(
            self.cgroup_base_path, "memory", container_name
        )
        cpu_cgroup_path = os.path.join(self.cgroup_base_path, "cpu", container_name)

        try:
            os.rmdir(memory_cgroup_path)
            os.rmdir(cpu_cgroup_path)
        except Exception as e:
            print(f"[X] Failed to cleanup cgroup for PID {pid}: {e}")

    def _set_root(self):
        """
        将容器的根文件系统切换到 new_root
        """

        # new_root 首先需要是一个文件系统挂载点
        LIBC.mount(self.root_path, self.root_path, None, MS_BIND | MS_REC, None)

        old = os.path.join(self.root_path, ".old_rootfs")
        if not os.path.exists(old):
            os.mkdir(old)

        LIBC.mount(None, "/", None, MS_REC | MS_PRIVATE, None)
        LIBC.pivot_root(self.root_path, old)

        os.chdir("/")

        old_full_path = os.path.join("/", ".old_rootfs")
        LIBC.umount2(old_full_path, 2)
        os.rmdir(old_full_path)

    def _create_child(self, cmd):
        """
        在新的命名空间中运行子进程
        """

        new_hostname = "sheep"
        LIBC.sethostname(new_hostname, len(new_hostname))
        self._set_root()
        LIBC.mount("proc", "/proc", "proc", 0, None)
        os.execlp(cmd[0], *cmd)

    def create(self, cmd):
        """
        创建容器
        """

        stack_size = 1024 * 1024  # 子栈大小
        stack = ctypes.create_string_buffer(stack_size)

        # 调用 clone 创建容器
        child_stack = ctypes.c_void_p(ctypes.addressof(stack) + stack_size)
        pid = LIBC.clone(
            ctypes.CFUNCTYPE(ctypes.c_int)(lambda: self._create_child(cmd)),
            child_stack,
            CLONE_NEWUTS
            | CLONE_NEWIPC
            | CLONE_NEWPID
            | CLONE_NEWNS
            | CLONE_NEWNET
            | signal.SIGCHLD,
        )

        if pid == -1:
            sys.exit("[X] Failed to create new namespace")

        self._set_cgroup_limit(pid)
        os.waitpid(pid, 0)  # 等待子进程完成
        self._cleanup_cgroup(pid)

        LIBC.umount2(self.root_path, 2)


# 需要用到的系统调用
LIBC = ctypes.CDLL(find_library("c"), use_errno=True)  # 查找 libc 的位置
for func in ["sethostname", "umount2", "mount", "pivot_root"]:
    setattr(LIBC, func, libc_error_handler(getattr(LIBC, func)))

# 命令行解析器
parser = argparse.ArgumentParser(description="Wandering Sheep CLI")
subparsers = parser.add_subparsers(dest="command", help="子命令")
run_parser = subparsers.add_parser("run", help="运行命令")
run_parser.add_argument(
    "-m", "--memory", type=str, help="内存限制，如 100m 或 2g", default=None
)
run_parser.add_argument("-c", "--cpu", type=int, help="CPU 限制（核）", default=None)
run_parser.add_argument("cmd", nargs=argparse.REMAINDER, help="要运行的命令及参数")
args = parser.parse_args()
print(args)

# 主程序入口
if args.command == "run":
    Container(
        "./busybox",
        memory_limit=_parse_limit(args.memory) if args.memory else None,
        cpu_limit=args.cpu,
    ).create(args.cmd)
else:
    parser.print_help()

