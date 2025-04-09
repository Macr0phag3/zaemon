import os
import argparse
import ctypes
import shutil
import signal
from ctypes.util import find_library
import sys
import functools
import hashlib
import time

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
    """
    文件写入
    """

    with open(path, "w") as f:
        f.write(content)


def _safe_join_path(base_dir, *user_path):
    real_user_path = os.path.realpath(
        os.path.join(base_dir, *[i.lstrip("/") for i in user_path])
    )

    if not real_user_path.startswith(base_dir):
        raise ValueError(
            f"Invalid path: {user_path} in {base_dir}, directory traversal detected."
        )

    return real_user_path


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
    def __init__(
        self,
        root_path,
        memory_limit=None,
        cpu_limit=None,
        name=None,
        volumes=None,
        sheep_mnt_path="/mnt/sheep/",
    ):
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.root_path = os.path.abspath(root_path)
        self.container_id = hashlib.sha1(str(time.time()).encode()).hexdigest()

        self._dir_maker(sheep_mnt_path, volumes)

    def _dir_maker(self, sheep_mnt_path, volumes):
        self.cgroup_base_path = "/sys/fs/cgroup"  # cgroup 的挂载点
        self.overlay_base_path = _safe_join_path(
            sheep_mnt_path, self.container_id
        )  # OverlayFS 基目录
        self.lowerdir = self.root_path  # 镜像所在目录
        self.upperdir = _safe_join_path(self.overlay_base_path, "upperdir")  # 可写目录
        self.workdir = _safe_join_path(self.overlay_base_path, "workdir")  # 工作目录
        self.mergeddir = _safe_join_path(self.overlay_base_path, "merged")  # 挂载点

        self.volumes = []
        for volume in volumes:
            host_dir, container_dir = volume.split(":")
            container_dir = _safe_join_path(self.mergeddir, container_dir)
            self.volumes.append([host_dir, container_dir])

    def _set_cgroup_limit(self, pid):
        """
        为容器设置 memory 和 cpu 的 cgroup 限制
        """

        container_name = f"container_{pid}"
        memory_cgroup_path = _safe_join_path(
            self.cgroup_base_path, "memory", container_name
        )
        cpu_cgroup_path = _safe_join_path(self.cgroup_base_path, "cpu", container_name)

        try:  # 创建 cgroup 控制组目录
            os.makedirs(memory_cgroup_path, exist_ok=True)
            os.makedirs(cpu_cgroup_path, exist_ok=True)
        except Exception as e:
            sys.exit(f"[X] Failed to create cgroup directories: {e}")

        if self.memory_limit:
            # 设置 Memory 限制
            _write_file(
                _safe_join_path(memory_cgroup_path, "memory.limit_in_bytes"),
                str(self.memory_limit),
            )

        if self.cpu_limit:
            # 设置 CPU 限制
            cpu_quota_us = str(self.cpu_limit * 100000)  # 转换为微秒(100% = 100000)
            _write_file(
                _safe_join_path(cpu_cgroup_path, "cpu.cfs_quota_us"), cpu_quota_us
            )
            _write_file(
                _safe_join_path(cpu_cgroup_path, "cpu.cfs_period_us"), "100000"
            )  # 周期为 100ms

        # 将容器进程加入 cgroup
        _write_file(_safe_join_path(memory_cgroup_path, "tasks"), str(pid))
        _write_file(_safe_join_path(cpu_cgroup_path, "tasks"), str(pid))

    def _cleanup_cgroup(self, pid):
        """
        清理创建的 cgroup 目录
        """

        container_name = f"container_{pid}"
        memory_cgroup_path = _safe_join_path(
            self.cgroup_base_path, "memory", container_name
        )
        cpu_cgroup_path = _safe_join_path(self.cgroup_base_path, "cpu", container_name)

        try:
            os.rmdir(memory_cgroup_path)
            os.rmdir(cpu_cgroup_path)
        except Exception as e:
            print(f"[X] Failed to cleanup cgroup for PID {pid}: {e}")

    def _set_root(self):
        """
        将容器的根文件系统切换到 new_root
        """
        # 设置 OverlayFS 根文件系统
        self._create_overlay2()

        old = _safe_join_path(self.mergeddir, ".old_rootfs")
        if not os.path.exists(old):
            os.mkdir(old)

        LIBC.mount(None, "/", None, MS_REC | MS_PRIVATE, None)  # 将当前的根目录设为私有

        LIBC.pivot_root(self.mergeddir, old)  # 切换根为 OverlayFS

        # 切换工作目录到新根下
        os.chdir("/")

        # 卸载旧的根目录
        old_full_path = _safe_join_path("/", ".old_rootfs")
        LIBC.umount2(old_full_path, 2)
        os.rmdir(old_full_path)

    def _create_child(self, cmd):
        """
        在新的命名空间中运行子进程
        """

        new_hostname = "sheep"
        LIBC.sethostname(new_hostname, len(new_hostname))
        try:
            self._set_root()
        except Exception as e:
            sys.exit(f"[X] Failed to set root filesystem: {e}")

        LIBC.mount("proc", "/proc", "proc", 0, None)
        os.execlp(cmd[0], *cmd)

    def _create_overlay2(self):
        """
        创建 OverlayFS 文件系统并将其挂载到 path 下
        """

        try:
            # 创建 OverlayFS 所需的目录
            os.makedirs(self.upperdir, exist_ok=True)
            os.makedirs(self.workdir, exist_ok=True)
            os.makedirs(self.mergeddir, exist_ok=True)

            # 格式化 mount 选项
            mount_data = f"lowerdir={self.lowerdir},upperdir={self.upperdir},workdir={self.workdir}"

            # 挂载 OverlayFS 到 mergeddir
            print(f"[+] Mounting OverlayFS: {mount_data} -> {self.mergeddir}")
            LIBC.mount("overlay", self.mergeddir, "overlay", 0, mount_data)
        except Exception as e:
            sys.exit(f"[X] Failed to create or mount OverlayFS: {e}")

        if not self.volumes:
            return self.mergeddir

        # 处理挂载宿主机提供的 volumes
        for volume in self.volumes:
            # 创建容器内目标目录
            host_dir, container_dir = volume
            os.makedirs(container_dir, exist_ok=True)
            # 使用 bind mount 绑定宿主机目录
            print(f"[+] Mounting volume: {host_dir} -> {container_dir}")
            LIBC.mount(
                host_dir.encode(),
                container_dir.encode(),
                None,
                MS_BIND | MS_REC,
                None,
            )

    def _cleanup_overlay2(self):
        """
        移除 OverlayFS 的挂载和辅助目录
        """
        # 卸载宿主机提供的 volumes
        for volume in self.volumes:
            host_dir, container_dir = volume
            print(f"[+] Umounting volume: {host_dir} -> {container_dir}")
            LIBC.umount2(container_dir.encode(), 1)

        # 卸载 OverlayFS
        print(f"[+] Unmounting OverlayFS from {self.mergeddir}")
        LIBC.umount2(self.mergeddir, 1)  # 强制卸载 merged 挂载点
        shutil.rmtree(self.overlay_base_path)

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

        try:
            if pid == -1:
                sys.exit("[X] Failed to create new namespace")

            self._set_cgroup_limit(pid)
            os.waitpid(pid, 0)  # 等待子进程完成
            self._cleanup_cgroup(pid)
        except Exception as e:
            print(f"[X] Container run error: {e}")
        finally:
            # 清理 OverlayFS，卸载根路径
            self._cleanup_overlay2()


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
run_parser.add_argument(
    "-v",
    "--volume",
    action="append",
    default=[],
    help="数据卷挂载，格式为: host_dir:container_dir",
)
run_parser.add_argument("cmd", nargs=argparse.REMAINDER, help="要运行的命令及参数")
args = parser.parse_args()
print(args)

# 主程序入口
if args.command == "run":
    Container(
        os.path.abspath("./busybox"),
        memory_limit=_parse_limit(args.memory) if args.memory else None,
        cpu_limit=args.cpu,
        volumes=args.volume,
    ).create(args.cmd)
else:
    parser.print_help()

