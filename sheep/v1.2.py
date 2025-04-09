import datetime
import json
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
import stat
import psutil  # type: ignore
from prettytable import PrettyTable  # type: ignore

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


def output(message, level="info", debug=False, show=True):
    """
    基于消息等级统一输出打印信息
    """

    color_map = {
        "error": "red",
        "warning": "yellow",
        "info": "white",
        "debug": "gray",
        "success": "green",
    }

    if level == "debug" and not debug:
        return  # 如果是调试信息且 debug 未开启，忽略输出

    message = _put_color(level.upper(), color_map[level]) + " " + message
    if show:
        print(message)

    return message


def _put_color(string, color):
    colors = {
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "pink": "35",
        "cyan": "36",
        "gray": "2",
        "white": "37",
    }
    return f"\033[40;1;{colors[color]}m{str(string)}\033[0m"


def _safe_join_path(base_dir, *user_path):
    real_user_path = os.path.realpath(
        os.path.join(base_dir, *[i.lstrip("/") for i in user_path])
    )

    if not real_user_path.startswith(base_dir):
        raise ValueError(
            output(
                f"Invalid path: {user_path} in {base_dir}, directory traversal detected.",
                level="error",
                show=False,
            )
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
    except Exception as e:
        sys.exit(output(f"Failed to parse limit, {e}: {string}", "error", show=False))

    trans_map = {
        "k": num * 1024,
        "m": num * 1024 * 1024,
        "g": num * 1024 * 1024 * 1024,
    }
    if unit not in trans_map:
        sys.exit(output(f"No such unit: {string}", "error", show=False))

    return trans_map[unit]


def libc_error_handler(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        args = [(i.encode() if type(i) is str else i) for i in args]
        result = func(*args, **kwargs)
        if result != 0:
            sys.exit(
                output(
                    f"{func.__name__} failed: {os.strerror(ctypes.get_errno())}",
                    "error",
                    show=False,
                )
            )

        return result

    return wrapper


def get_container_info():
    """
    根据容器 id 查找对应的容器信息
    （这里 id 需要是完整的）
    """

    containers = []
    # 遍历 /var/sheep 目录下的所有 .json 文件
    for json_filename in os.listdir(METADATA_DIR):
        if not json_filename.endswith(".json"):
            continue  # 过滤非 JSON 文件

        metadata_file = os.path.join(METADATA_DIR, json_filename)
        try:
            with open(metadata_file, "r") as f:
                info = json.load(f)
        except Exception as e:
            output(f"Failed to process {metadata_file}: {e}", "warning")
            return None

        proc_info = get_container_proc_info(info)
        if proc_info["status"] != info["status"]:
            output(
                f"Updated status for container {info['pid']} to {proc_info['status']}",
                "debug",
            )
            info["status"] = proc_info["status"]
            with open(metadata_file, "w") as f:
                json.dump(info, f, indent=4)

        containers.append(info)

    return containers


def get_container_proc_info(info):
    """
    根据容器信息查找对应的宿主机进程信息
    （这里 id 需要是完整的）
    """

    pid = info["pid"]
    command = info["command"]
    proc_info = {
        "pid": pid,
        "status": "stopped",
    }

    try:
        process = psutil.Process(pid)
        running_command = process.cmdline()
        if running_command == command:
            proc_info["status"] = "running"
    except psutil.NoSuchProcess:
        proc_info["status"] = "stopped"
    except Exception as e:
        sys.exit(output(f"Error accessing process {pid}: {e}", "error", show=False))

    return proc_info


def find_container_by_prefix(containers, prefix):
    """
    根据容器 ID 的前缀查找完整的容器 ID

    :param containers: 包含所有容器的列表
    :param prefix: 输入的容器 ID 前缀
    :return: 匹配到的唯一完整容器 ID
    """

    matched_containers = [
        container for container in containers if container["id"].startswith(prefix)
    ]

    if len(matched_containers) > 1:
        output(f"Multiple containers match prefix '{prefix}'", "warning")
        for container in matched_containers:
            print(f"  - {container['id'][:12]} ({container['status']})")

        sys.exit(output(f"找到多个容器，请明确指定", "error", show=False))
    elif not matched_containers:
        sys.exit(
            output(f"No container found with prefix '{prefix}'", "error", show=False)
        )
        return None  # 未找到匹配的容器
    else:
        output(f"转换 container id: {prefix} => {matched_containers[0]['id']}", "debug")
        return matched_containers[0]  # 唯一匹配时返回容器对象


class Container:
    def __init__(
        self,
        root_path,
        memory_limit=None,
        cpu_limit=None,
        name=None,
        volumes=None,
        sheep_mnt_path="/mnt/sheep/",
        detach=False,
        metadata_dir="/var/sheep/",
    ):
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.detach = detach
        self.root_path = os.path.abspath(root_path)
        self.container_id = hashlib.sha1(str(time.time()).encode()).hexdigest()
        self.metadata_dir = os.path.abspath(metadata_dir)

        self._dir_maker(sheep_mnt_path, volumes)

    def _dir_maker(self, sheep_mnt_path, volumes):
        self.metadata_file = _safe_join_path(
            self.metadata_dir, f"{self.container_id}.json"
        )
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
            sys.exit(
                output(
                    f"Failed to create cgroup directories: {e}", "errror", show=False
                )
            )

        if self.memory_limit:
            output(f"设置 Memory 限制", "debug")
            with open(
                _safe_join_path(memory_cgroup_path, "memory.limit_in_bytes"), "w"
            ) as f:
                f.write(str(self.memory_limit))

        if self.cpu_limit:
            output(f"设置 CPU 限制", "debug")
            cpu_quota_us = str(self.cpu_limit * 100000)  # 转换为微秒(100% = 100000)
            with open(_safe_join_path(cpu_cgroup_path, "cpu.cfs_quota_us"), "w") as f:
                f.write(cpu_quota_us)

            with open(_safe_join_path(cpu_cgroup_path, "cpu.cfs_period_us"), "w") as f:
                f.write("100000")  # 周期为 100ms

        # 将容器进程加入 cgroup
        with open(_safe_join_path(memory_cgroup_path, "tasks"), "w") as f:
            f.write(str(pid))

        with open(_safe_join_path(cpu_cgroup_path, "tasks"), "w") as f:
            f.write(str(pid))

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
            output(f"Failed to cleanup cgroup for PID {pid}: {e}", "warning")
        else:
            output("清理完成", "debug")

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

    def _save_metadata(self, pid, cmd):
        """
        保存容器元数据到 /var/sheep/<container_id>.json 文件
        """

        # 确保 /var/sheep/ 目录存在
        os.makedirs(self.metadata_dir, exist_ok=True)

        container_metadata = {
            "id": self.container_id,
            "pid": pid,
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command": cmd,
            "memory_limit": self.memory_limit,
            "cpu_limit": self.cpu_limit,
            "volumes": self.volumes,
            "status": "created" if not self.detach else "running",
        }

        # 写入 JSON 文件
        with open(self.metadata_file, "w") as f:
            json.dump(container_metadata, f, indent=4)

        output(f"Container metadata saved to {self.metadata_file}", "debug")

    def _create_child(self, cmd):
        """
        在新的命名空间中运行子进程
        """

        new_hostname = "sheep"
        LIBC.sethostname(new_hostname, len(new_hostname))
        try:
            self._set_root()
        except Exception as e:
            sys.exit(output(f"Failed to set root filesystem: {e}", "error", show=False))

        LIBC.mount("proc", "/proc", "proc", 0, None)
        os.makedirs("/dev", exist_ok=True)
        os.mknod("/dev/null", 0o666 | stat.S_IFCHR, os.makedev(1, 3))
        os.mknod("/dev/zero", 0o666 | stat.S_IFCHR, os.makedev(1, 5))
        os.mknod("/dev/tty", 0o666 | stat.S_IFCHR, os.makedev(5, 0))
        os.mknod("/dev/ptmx", 0o666 | stat.S_IFCHR, os.makedev(5, 2))
        LIBC.mount("devpts", "/dev/pts", "devpts", 0, "ptmxmode=666,newinstance")

        output(f"新容器开始执行命令: {cmd}", "debug")
        if self.detach:
            os.setsid()
            master_fd, slave_fd = os.openpty()
            os.dup2(master_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            os.close(slave_fd)
            os.close(master_fd)

        os.execvp(cmd[0], cmd)

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
            output(f"Mounting OverlayFS: {mount_data} -> {self.mergeddir}", "debug")
            LIBC.mount("overlay", self.mergeddir, "overlay", 0, mount_data)
        except Exception as e:
            sys.exit(
                output(
                    f"[X] Failed to create or mount OverlayFS: {e}", "error", show=False
                )
            )

        if not self.volumes:
            return self.mergeddir

        # 处理挂载宿主机提供的 volumes
        for volume in self.volumes:
            # 创建容器内目标目录
            host_dir, container_dir = volume
            os.makedirs(container_dir, exist_ok=True)
            # 使用 bind mount 绑定宿主机目录
            output(f"Mounting volume: {host_dir} -> {container_dir}", "debug")
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
            output(f"[+] Umounting volume: {host_dir} -> {container_dir}", "debug")
            LIBC.umount2(container_dir.encode(), 1)

        # 卸载 OverlayFS
        output(f"Unmounting OverlayFS from {self.mergeddir}", "debug")
        LIBC.umount2(self.mergeddir, 1)  # 强制卸载 merged 挂载点
        shutil.rmtree(self.overlay_base_path)

    def create(self, cmd):
        """
        创建容器
        """
        stack_size = 1024 * 1024  # 子栈大小
        stack = ctypes.create_string_buffer(stack_size)
        print(cmd)
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
            sys.exit(output("Failed to create new namespace", "error", show=False))

        # 记录容器数据信息到 JSON
        self._save_metadata(pid, cmd)

        self._set_cgroup_limit(pid)
        if not self.detach:
            output("detach 的容器，后面统一清理资源", "debug")
            os.waitpid(pid, 0)  # 等待子进程完成
            self._cleanup_cgroup(pid)
            self._cleanup_overlay2()


class CLI_Parser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Wandering Sheep CLI")
        self.parser.add_argument("--debug", action="store_true", help="debug 模式")
        self.subparsers = self.parser.add_subparsers(dest="command", help="子命令")
        [getattr(self, i)() for i in dir(self) if i.startswith("_parse_")]
        self.args = self.parser.parse_args()

    def _parse_run(self):
        # 命令行解析器
        run_parser = self.subparsers.add_parser("run", help="运行命令")
        run_parser.add_argument(
            "-m", "--memory", type=str, help="内存限制，如 100m 或 2g", default=None
        )
        run_parser.add_argument(
            "-c", "--cpu", type=int, help="CPU 限制（核）", default=None
        )
        run_parser.add_argument("-d", "--detach", action="store_true", help="后台运行")
        run_parser.add_argument(
            "-v",
            "--volume",
            action="append",
            default=[],
            help="数据卷挂载，格式为: host_dir:container_dir",
        )
        run_parser.add_argument(
            "cmd", nargs=argparse.REMAINDER, help="要运行的命令及参数"
        )

    def _parse_commit(self):
        # 命令行解析器
        run_parser = self.subparsers.add_parser("commit", help="运行命令")
        run_parser.add_argument("id", help="容器 id")
        run_parser.add_argument("path", help="打包后镜像存储的位置")
        run_parser.add_argument(
            "--sheep-path",
            default="/mnt/sheep/",
            help="宿主机上容器 overlay2 存储的位置",
        )

    def _parse_inspect(self):
        inspect_parser = self.subparsers.add_parser("inspect", help="查看容器信息")
        inspect_parser.add_argument("id", help="容器 ID")

    def _parse_ps(self):
        ps_parser = self.subparsers.add_parser("ps", help="查看当前容器")
        ps_parser.add_argument("-a", "--all", action="store_true", help="查看所有")

    def _inspect(self):
        container = find_container_by_prefix(get_container_info(), self.args.id)
        container_id = container["id"]
        metadata_file = f"/var/sheep/{container_id}.json"

        if not os.path.exists(metadata_file):
            output(f"No such container with ID: {container_id}", "warning")
            return

        with open(metadata_file, "r") as f:
            metadata = json.load(f)
            print(json.dumps(metadata, indent=4))

    def _run(self):
        Container(
            os.path.abspath("./busybox"),
            memory_limit=_parse_limit(self.args.memory) if self.args.memory else None,
            cpu_limit=self.args.cpu,
            volumes=self.args.volume,
            detach=self.args.detach,
        ).create(self.args.cmd)

    def _ps(self):
        table = PrettyTable(border=False)
        table.field_names = ["CONTAINER ID", "PID", "STATUS", "CREATED", "COMMAND"]
        table.align["PID"] = "l"
        table.align["COMMAND"] = "l"
        for container in get_container_info():
            if not self.args.all and container["status"] != "running":
                continue  # 如果不是 `--all`，过滤掉非运行状态的容器

            table.add_row(
                [
                    container["id"][:12],
                    container["pid"],
                    container["status"].upper(),
                    container["created_at"],
                    " ".join(container["command"]),
                ]
            )

        print(table)

    def _run(self):
        Container(
            os.path.abspath("./busybox"),
            memory_limit=_parse_limit(self.args.memory) if self.args.memory else None,
            cpu_limit=self.args.cpu,
            volumes=self.args.volume,
            detach=self.args.detach,
        ).create(self.args.cmd)

    def run(self):
        {
            i: getattr(self, "_" + i)
            for i in [
                "run",
                "inspect",
                "ps",
            ]
        }.get(args.command, cli.help)()

    def help(self):
        self.parser.print_help()


# ---------- 配置区 ------------
METADATA_DIR = "/var/sheep"


if not os.path.exists(METADATA_DIR):
    sys.exit(
        f"Metadata directory '{METADATA_DIR}' does not exist",
        "error",
        show=False,
    )

# 需要用到的系统调用
LIBC = ctypes.CDLL(find_library("c"), use_errno=True)  # 查找 libc 的位置
for func in ["sethostname", "umount2", "mount", "pivot_root"]:
    setattr(LIBC, func, libc_error_handler(getattr(LIBC, func)))

cli = CLI_Parser()

args = cli.args
output = functools.partial(output, debug=args.debug)
output(str(args), "debug")
cli.run()

