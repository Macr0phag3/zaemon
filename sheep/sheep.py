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
import copy
import ipaddress

# pip install -i https://pypi.tuna.tsinghua.edu.cn/simple python-iptables pyroute2 prettytable psutil
from pyroute2 import IPRoute, NetNS, IPDB  # type: ignore
import iptc  # type: ignore
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
        exit(f"Failed to parse limit, {e}: {string}")

    trans_map = {
        "k": num * 1024,
        "m": num * 1024**2,
        "g": num * 1024**3,
    }
    if unit not in trans_map:
        exit(f"No such unit: {string}")

    return trans_map[unit]


def time_ago(input_time):
    now = datetime.datetime.now()
    input_time = datetime.datetime.strptime(input_time, "%Y-%m-%d %H:%M:%S")
    delta = now - input_time
    seconds = abs(delta.total_seconds())
    past = delta.days >= 0

    units = {
        "years": 31536000,
        "months": 2592000,
        "weeks": 604800,
        "days": 86400,
        "hours": 3600,
        "minutes": 60,
        "seconds": 1,
    }

    for unit, value in units.items():
        if seconds >= value:
            count = seconds // value
            return f"{int(count)} {unit} ago" if past else f"in {int(count)} {unit}"

    return "just now"


def output(message, level="info", debug=False, show=True):
    color_map = {
        "error": "red",
        "warning": "yellow",
        "info": "white",
        "debug": "gray",
        "success": "green",
    }

    if level == "debug" and not debug:
        return

    message = str(message)
    message = _put_color(level.upper(), color_map[level]) + " " + message
    if show:
        print(message)

    return message


def exit(msg):
    sys.exit(output(msg, "error", show=False))


def libc_error_handler(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        args = [(i.encode() if type(i) is str else i) for i in args]
        result = func(*args, **kwargs)
        if result != 0:
            raise RuntimeError(
                output(
                    f"{func.__name__} failed: {os.strerror(ctypes.get_errno())}",
                    "error",
                    show=False,
                )
            )

        return result

    return wrapper


def get_containers(short_id=None):
    """
    根据短的容器 id 查找对应的容器信息
    - 如果没有指定 short_id: 返回所有的容器
    - 如果指定 short_id: 返回匹配的容器

    均返回容器对象
    """

    if short_id is None:
        containers = []
        # 遍历 /var/sheep 目录下的所有 .json 文件
        for json_filename in os.listdir(CONTAINER_INFO_DIR):
            if not json_filename.endswith(".json"):
                continue

            container_id = json_filename.split(".")[0]
            container = Container()
            container.reload(container_id)
            containers.append(container)

        return containers
    else:
        matched_containers = [
            json_filename.split(".")[0]
            for json_filename in os.listdir(CONTAINER_INFO_DIR)
            if json_filename.endswith(".json") and json_filename.startswith(short_id)
        ]

        if len(matched_containers) > 1:
            output(f"Multiple containers match prefix '{short_id}'", "warning")
            for _id in matched_containers:
                container = Container()
                container.reload(_id)
                print(f"  - {container.container_id} ({container.status})")

            exit(f"{short_id} 找到多个容器，请明确指定")
        elif not matched_containers:
            exit(f"No container found with prefix '{short_id}'")
        else:
            container = Container()
            container.reload(matched_containers[0])
            if short_id != container.container_id:
                output(
                    f"转换 container id: {short_id} => {container.container_id}",
                    "debug",
                )
            return container


def get_networks():
    networks = []
    for d in os.listdir(NETWORK_INFO_DIR):
        net = IPAM(d.strip(".json"))
        net._load_info()
        networks.append(net)

    return networks


class IPAM:
    """
    IP Address Management
    用来给容器分配 IP
    """

    def __init__(self, network_name="default"):
        self.network_name = network_name
        self.db = _safe_join_path(NETWORK_INFO_DIR, self.network_name + ".json")
        self.bridge_name = f"sheep-{self.network_name}"

    def _load_info(self):
        """
        读取网络配置信息

        TODO: 其实最好加个锁?
        """

        if not os.path.exists(self.db):
            exit(f"网络配置 {self.network_name} 不存在")

        with open(self.db, "r") as f:
            self.metadata = json.load(f)

        self.gateway = self.metadata["gateway"]
        self.subnet = ipaddress.ip_network(self.metadata["subnet"])
        self.subnet_str = self.metadata["subnet"]
        self.containers = self.metadata["containers"]
        self.bridge_name = self.metadata["bridge_name"]
        self.driver = self.metadata["driver"]
        self.created_at = self.metadata["created_at"]
        self.used_ip = [
            self.metadata["containers"][container_id]["ip"]
            for container_id in self.metadata.get("containers", [])
        ] + [self.gateway]

    def _manage_bridge_snat(self, action):
        """
        配置 iptables 的 MASQUERADE 规则，将容器流量的源地址转换为宿主机的出口地址
        iptables -t nat -A POSTROUTING -o <非桥接网卡> -s <桥接网络子网> -d <非桥接网络子网> -j MASQUERADE
        """

        tip = f"iptables -t nat -A POSTROUTING -o {self.bridge_name} -s {self.subnet_str} -j MASQUERADE"
        table = iptc.Table(iptc.Table.NAT)
        chain = iptc.Chain(table, "POSTROUTING")

        rule = iptc.Rule()
        rule.create_match("comment").comment = "sheep:nat:" + self.bridge_name
        rule.out_interface = f"!{self.bridge_name}"
        rule.src = self.subnet_str
        rule.dst = f"!{self.subnet_str}"
        rule.target = iptc.Target(rule, "MASQUERADE")

        old_rules = [old_rule for old_rule in chain.rules if old_rule == rule]
        if action == "add":
            if old_rules:
                output(f"MASQUERADE 规则已存在: {tip}", "debug")
                return
            else:
                chain.insert_rule(rule)
                table.commit()
                output(f"MASQUERADE 规则已添加", "debug")
        else:
            if old_rules:
                for rule in old_rules:
                    chain.delete_rule(rule)
                table.commit()
                output(f"MASQUERADE 规则已删除: {tip}", "debug")
            else:
                output(f"MASQUERADE 规则不存在，不需要删除: {tip}", "debug")

    def _manage_brigde_forward(self, action):
        """
        配置 iptables 的 FORWARD 规则，FORWARD 很多默认策略是 DROP，会导致容器的流量无法通过宿主机转发
        iptables -A FORWARD -o <桥接网卡> -d <桥接网络子网> -j ACCEPT
        iptables -A FORWARD -i <桥接网卡> -s <桥接网络子网> -j ACCEPT
        """

        for conf in [
            {
                "direction": "in",
                "iface": "in_interface",
                "target": "src",
            },
            {
                "direction": "out",
                "iface": "out_interface",
                "target": "dst",
            },
        ]:
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, "FORWARD")

            rule = iptc.Rule()
            rule.create_match("comment").comment = "sheep:forward:" + self.bridge_name
            setattr(rule, conf["iface"], self.bridge_name)
            setattr(rule, conf["target"], self.subnet_str)
            rule.target = iptc.Target(rule, "ACCEPT")

            tip = f"{conf['direction']} FORWARD 规则"
            old_rules = [old_rule for old_rule in chain.rules if old_rule == rule]
            if action == "add":
                if old_rules:
                    output(f"{tip}已存在", "debug")
                    continue
                else:
                    chain.insert_rule(rule)
                    table.commit()
                    output(f"{tip}已添加", "debug")
            else:
                if old_rules:
                    for rule in old_rules:
                        chain.delete_rule(rule)
                    table.commit()
                    output(f"{tip}已删除", "debug")
                else:
                    output(f"{tip}不存在，不需要删除", "debug")

    def _manage_port_map(self, container_id, container_ip, port_map, action):
        """
        # 处理外部数据包（即流量来自网络的客户端，目的地址是宿主机）并将其转发到容器
        iptables -t nat -A PREROUTING -p tcp --dport <宿主机端口> -j DNAT --to-destination <容器 IP>:<容器端口>
        # 处理宿主机自己发出的数据包，将其转发到容器
        iptables -t nat -A OUTPUT     -p tcp --dport <宿主机端口> -j DNAT --to-destination <容器 IP>:<容器端口>
        # 保障响应包能够正常返回给宿主机
        iptables -t nat -A POSTROUTING -d <容器 IP> -p tcp --dport <容器端口> -j SNAT --to-source <桥接网络网关地址>
        """

        table = iptc.Table(iptc.Table.NAT)
        for protocol in ["tcp", "udp"]:
            for ch in ["PREROUTING", "OUTPUT"]:
                chain = iptc.Chain(table, ch)
                for pm in port_map:
                    host_port, container_port = pm

                    rule = iptc.Rule()
                    rule.create_match("comment").comment = (
                        "sheep:port-map:" + container_id
                    )
                    rule.protocol = protocol
                    # rule.in_interface = f"!{self.bridge_name}"
                    match = rule.create_match(protocol)
                    match.dport = host_port

                    target = rule.create_target("DNAT")
                    target.to_destination = f"{container_ip}:{container_port}"

                    old_rules = [
                        old_rule for old_rule in chain.rules if old_rule == rule
                    ]
                    tip = f"{ch} {host_port}:{container_port} {protocol} 端口映射规则"
                    if action == "add":
                        if old_rules:
                            output(f"{tip}已存在", "debug")
                            continue
                        else:
                            chain.insert_rule(rule)
                            table.commit()
                            output(f"{tip}已添加", "debug")
                    else:
                        if old_rules:
                            for rule in old_rules:
                                chain.delete_rule(rule)
                            table.commit()
                            output(f"{tip}已删除", "debug")
                        else:
                            output(
                                f"{tip}不存在，不需要删除",
                                "debug",
                            )

        table = iptc.Table(iptc.Table.NAT)
        for protocol in ["tcp", "udp"]:
            chain = iptc.Chain(table, "POSTROUTING")
            for pm in port_map:
                host_port, container_port = pm

                rule = iptc.Rule()
                rule.protocol = protocol
                rule.dst = container_ip

                match = rule.create_match(protocol)
                match.dport = container_port

                target = rule.create_target("SNAT")
                target.to_source = self.gateway

                rule.create_match("comment").comment = "sheep:port-map:" + container_id

                old_rules = [old_rule for old_rule in chain.rules if old_rule == rule]
                tip = (
                    f"POSTROUTING {host_port}:{container_port} {protocol} 端口映射规则"
                )
                if action == "add":
                    if old_rules:
                        output(f"{tip}已存在", "debug")
                        continue
                    else:
                        chain.insert_rule(rule)
                        table.commit()
                        output(f"{tip}已添加", "info")
                else:
                    if old_rules:
                        for rule in old_rules:
                            chain.delete_rule(rule)
                        table.commit()
                        output(f"{tip}已删除", "debug")
                    else:
                        output(
                            f"{tip}不存在，不需要删除",
                            "debug",
                        )

    def _remove_bridge(self):
        """
        删除 Linux 网桥 (Bridge)
        """
        self._load_info()
        ipr = IPRoute()
        links = ipr.link_lookup(ifname=self.bridge_name)
        if not links:
            return output(f"桥接 {self.bridge_name} 不存在，无需删除", "info")

        ipr.link("del", index=links[0])
        output(f"桥接设备 {self.bridge_name} 已删除", "info")
        ipr.close()
        self._manage_bridge_snat("rm")
        self._manage_brigde_forward("rm")

    def _create_bridge(self):
        """
        创建 Linux 网桥 (Bridge)
        """
        ipr = IPRoute()

        links = ipr.link_lookup(ifname=self.bridge_name)
        if links:
            return output(f"桥接 {self.bridge_name} 已存在", "debug")

        output(f"创建桥接: {self.bridge_name}", "debug")
        ipr.link("add", ifname=self.bridge_name, kind="bridge")
        bridge_index = ipr.link_lookup(ifname=self.bridge_name)[0]
        ipr.addr(
            "add",
            index=bridge_index,
            address=self.gateway,
            prefixlen=self.subnet.prefixlen,
        )
        output(
            f"为桥接 {self.bridge_name} 分配网关: {self.gateway}/{self.subnet.prefixlen}",
            "debug",
        )

        ipr.link("set", index=bridge_index, state="up")
        output(f"桥接 {self.bridge_name} 已启动")

        ipr.close()
        self._manage_bridge_snat("add")
        self._manage_brigde_forward("add")

    def _create_veth(
        self, ip, container_id, container_namespace, container_ifname="eth0"
    ):
        """
        创建 veth 对，并将其中一端挂载到网桥
        """
        self._load_info()

        ipr = IPRoute()
        veth_left = f"sheep-{container_id}"[:15]
        veth_right = f"right-{container_id}"[:15]

        if ipr.link_lookup(ifname=veth_left):
            return output(f"{veth_left} 已存在", "debug")

        output(f"创建 veth 对: {veth_left} 和 {veth_right}", "debug")
        ipr.link("add", ifname=veth_left, kind="veth", peer={"ifname": veth_right})
        bridge_index = ipr.link_lookup(ifname=self.bridge_name)[0]

        host_index = ipr.link_lookup(ifname=veth_left)[0]
        ipr.link("set", index=host_index, master=bridge_index)
        output(f"veth {veth_left} 已挂载到桥接设备 {self.bridge_name}", "debug")
        ipr.link("set", index=host_index, state="up")
        output(f"{veth_left} 已启动", "debug")

        # 容器端的 veth 移动到网络命名空间
        with NetNS(container_namespace) as ns:
            output(f"veth {veth_right} 移动到容器网络命名空间 {container_id}", "debug")
            ipr.link(
                "set",
                index=ipr.link_lookup(ifname=veth_right)[0],
                net_ns_fd=container_namespace,
            )
            container_index = ns.link_lookup(ifname=veth_right)[0]

            # 分配 IP 地址和子网掩码
            ns.addr(
                "add",
                index=container_index,
                address=ip,
                prefixlen=self.subnet.prefixlen,
            )
            output(f"为 {veth_left} 分配 IP 地址 {ip}/{self.subnet.prefixlen}", "debug")

            # 设置接口为 UP
            ns.link("set", index=ns.link_lookup(ifname="lo")[0], state="up")
            ns.link("set", index=container_index, state="up", ifname=container_ifname)
            output(f"启用容器网络接口 {veth_left}", "debug")

            # 添加默认路由
            ns.route("add", gateway=self.gateway, dst="0.0.0.0/0")
            output(f"容器设置默认路由: 通过网关 {self.gateway}", "debug")

        ipr.close()
        return veth_left, container_ifname

    def _remove_veth(self, container_id):
        """
        删除 veth 对，包括主机端和容器端
        """
        self._load_info()

        ipr = IPRoute()
        veth_left = f"sheep-{container_id}"[:15]

        # 删除主机端的 veth
        host_index = ipr.link_lookup(ifname=veth_left)
        if host_index:
            ipr.link("del", index=host_index)

        output(f"主机端的 veth {veth_left} 已删除", "debug")

        ipr.close()

    def create(self, driver, subnet, gateway):
        if os.path.exists(self.db):
            return output(f"网络配置: {self.network_name} 已存在", "warning")

        self.metadata = {
            "containers": {},
            "driver": driver,
            "bridge_name": self.bridge_name,
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "subnet": subnet,
            "gateway": gateway,
        }
        with open(self.db, "w") as f:
            json.dump(self.metadata, f, indent=4)

        self._load_info()
        self._create_bridge()

    def remove(self):
        if os.path.exists(self.db):
            with open(self.db, "r") as f:
                self.metadata = json.load(f)
                # return output(f"无法删除默认的网络配置: {self.network_name}", "error")
        else:
            return output(f"网络配置: {self.network_name} 不存在，无法删除", "warning")

        self._load_info()
        if self.containers:
            return output(
                f"网络配置: {self.network_name} 有 {len(self.containers)} 个容器占用，需要先删除容器: {list(self.containers)}",
                "warning",
            )

        self._remove_bridge()
        os.remove(self.db)

    def allocate(self, container_id, container_namespace, port_map):
        self._load_info()
        invalid_ip = [
            str(ip) for ip in self.subnet.hosts() if str(ip) not in self.used_ip
        ]
        if not invalid_ip:
            exit(f"{self.network_name}({self.subnet}) 的 IP 已全部被占用")

        ip = invalid_ip.pop(0)
        host_veth, container_veth = self._create_veth(
            ip, container_id, container_namespace
        )
        self._manage_port_map(container_id, ip, port_map, "add")
        self.metadata["containers"][container_id] = {
            "ip": ip,
            "host_veth": host_veth,
            "container_veth": container_veth,
        }
        with open(self.db, "w") as f:
            json.dump(self.metadata, f, indent=4)

        self._load_info()
        return ip, self.bridge_name, host_veth, container_veth

    def release(self, container_id, ip, port_map):
        self._load_info()
        self._remove_veth(container_id)
        if ip:
            self._manage_port_map(container_id, ip, port_map, "rm")
        if container_id in self.metadata["containers"]:
            del self.metadata["containers"][container_id]
        with open(self.db, "w") as f:
            json.dump(self.metadata, f, indent=4)
        self._load_info()


class Container:
    def __init__(self):
        pass

    def __str__(self):
        return self.inspect(show=False)

    def _build_info(
        self,
        command,
        image,
        ip,
        bridge_name,
        host_veth,
        container_veth,
        network_name,
        container_id,
        name=None,
        memory_limit=None,
        cpu_limit=None,
        detach=False,
        volumes=[],
        created_at=None,
        port_map=None,
    ):
        """
        构建容器信息
        """
        self.ip = ip
        self.bridge_name = bridge_name
        self.host_veth = host_veth
        self.container_veth = container_veth
        self.network_name = network_name
        self.image = image
        self.image_path = _safe_join_path(IMAGE_BASE_DIR, image)
        if not os.path.exists(self.image_path):
            exit(
                output(
                    f"{image} 镜像不存在，搜索路径为: {self.image_path}",
                    "error",
                    show=False,
                )
            )

        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.detach = detach
        self.container_id = container_id
        self.metadata_file = _safe_join_path(
            CONTAINER_INFO_DIR, f"{self.container_id}.json"
        )
        self.cgroup_base_path = "/sys/fs/cgroup"  # cgroup 的挂载点
        self.overlay_base_path = _safe_join_path(
            SHEEP_MNT_DIR, self.container_id
        )  # OverlayFS 基目录
        self.lowerdir = self.image_path  # 镜像所在目录
        self.upperdir = _safe_join_path(self.overlay_base_path, "upperdir")  # 可写目录
        self.workdir = _safe_join_path(self.overlay_base_path, "workdir")  # 工作目录
        self.mergeddir = _safe_join_path(self.overlay_base_path, "merged")  # 挂载点
        self.port_map = port_map
        self.cmd = command
        self.created_at = created_at
        self.volumes = self._dir_maker(volumes)

    def _build_proc_info(self, pid):
        self.pid = pid
        self.status = "running"
        if not os.path.exists(f"/proc/{pid}"):
            self.status = "stopped"

    def _dir_maker(self, _volumes):
        volumes = []
        for volume in _volumes:
            host_dir, container_dir = volume.split(":")
            if not container_dir.startswith(self.mergeddir):
                container_dir = _safe_join_path(self.mergeddir, container_dir)
            volumes.append([host_dir, container_dir])

        return volumes

    def _set_cgroup_limit(self):
        """
        为容器设置 memory 和 cpu 的 cgroup 限制
        """

        container_name = f"container_{self.pid}"
        memory_cgroup_path = _safe_join_path(
            self.cgroup_base_path, "memory", container_name
        )
        cpu_cgroup_path = _safe_join_path(self.cgroup_base_path, "cpu", container_name)

        try:  # 创建 cgroup 控制组目录
            os.makedirs(memory_cgroup_path, exist_ok=True)
            os.makedirs(cpu_cgroup_path, exist_ok=True)
        except Exception as e:
            exit(
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
            f.write(str(self.pid))

        with open(_safe_join_path(cpu_cgroup_path, "tasks"), "w") as f:
            f.write(str(self.pid))

    def _clean(self):
        IPAM(self.network_name).release(self.container_id, self.ip, self.port_map)
        self._cleanup_cgroup()
        self._cleanup_overlay2()

    def _cleanup_cgroup(self):
        """
        清理创建的 cgroup 目录
        """

        container_name = f"container_{self.pid}"
        memory_cgroup_path = _safe_join_path(
            self.cgroup_base_path, "memory", container_name
        )
        cpu_cgroup_path = _safe_join_path(self.cgroup_base_path, "cpu", container_name)
        for i in [memory_cgroup_path, cpu_cgroup_path]:
            if os.path.exists(i):
                try:
                    os.rmdir(i)
                except Exception as e:
                    output(
                        f"Failed to cleanup {i} cgroup for PID {self.pid}: {e}",
                        "warning",
                    )

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

    def _save_metadata(self):
        """
        保存容器元数据到 /var/sheep/container_info/<container_id>.json 文件
        """

        os.makedirs(CONTAINER_INFO_DIR, exist_ok=True)
        container_metadata = {
            "container_id": self.container_id,
            "ip": self.ip,
            "network_name": self.network_name,
            "bridge_name": self.bridge_name,
            "host_veth": self.host_veth,
            "container_veth": self.container_veth,
            "image": self.image,
            "pid": self.pid,
            "detach": self.detach,
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command": self.cmd,
            "memory_limit": self.memory_limit,
            "cpu_limit": self.cpu_limit,
            "volumes": [":".join(i) for i in self.volumes],
            "status": self.status,
            "image_path": self.image_path,
            "port_map": self.port_map,
        }

        with open(self.metadata_file, "w") as f:
            json.dump(container_metadata, f, indent=4)

        output(f"Container metadata saved to {self.metadata_file}", "debug")

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
            exit(
                output(f"Failed to create or mount OverlayFS: {e}", "error", show=False)
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
        if os.path.exists(self.mergeddir):
            try:
                LIBC.umount2(self.mergeddir, 1)  # 强制卸载 merged 挂载点
            except Exception:
                output(f"卸载 {self.mergeddir} 失败，尝试直接删除", "warning")

        try:
            shutil.rmtree(self.overlay_base_path)
        except FileNotFoundError:
            output(f"{self.overlay_base_path} 不存在，跳过", "debug")

    def _create_child(self, cmd, env={}):
        """
        在新的命名空间中运行子进程
        """

        log_file = _safe_join_path(CONTAINER_LOG_DIR, f"{self.container_id}.log")
        out_fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        new_hostname = "sheep"
        LIBC.sethostname(new_hostname, len(new_hostname))
        self._set_root()
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
            os.dup2(out_fd, 1)  # stdout -> 日志文件
            os.dup2(out_fd, 2)  # stderr -> 日志文件
            os.dup2(slave_fd, 3)
            os.close(slave_fd)
            os.close(master_fd)
            print("-" * 20)

        try:
            exit_id = os.execvpe(cmd[0], cmd, env)
            if exit_id not in [0, 1]:
                output(f"exited in {exit_id}", "warning")
            else:
                output(f"exited in {exit_id}")
        except Exception as e:
            print(f"{cmd} run failed: {e}")

        return os.getpid()

    def _create_container(
        self,
        image,
        cmd,
        memory_limit=None,
        cpu_limit=None,
        name=None,
        volumes=[],
        detach=False,
        env={},
        network_name="default",
        port_map=None,
    ):
        """
        创建容器
        """

        container_id = hashlib.sha1(str(time.time()).encode()).hexdigest()
        port_map = [list(m.split(":")) for m in port_map]
        self._build_info(
            ip=None,
            bridge_name=None,
            host_veth=None,
            container_veth=None,
            network_name=network_name,
            image=image,
            memory_limit=memory_limit,
            cpu_limit=cpu_limit,
            name=name,
            command=cmd,
            volumes=volumes,
            detach=detach,
            container_id=container_id,
            port_map=port_map,
        )

        stack_size = 1024 * 1024  # 子栈大小
        stack = ctypes.create_string_buffer(stack_size)

        # 调用 clone 创建容器
        child_stack = ctypes.c_void_p(ctypes.addressof(stack) + stack_size)
        pid = LIBC.clone(
            ctypes.CFUNCTYPE(ctypes.c_int)(lambda: self._create_child(cmd, env)),
            child_stack,
            CLONE_NEWUTS
            | CLONE_NEWIPC
            | CLONE_NEWPID
            | CLONE_NEWNS
            | CLONE_NEWNET
            | signal.SIGCHLD,
        )
        if pid == -1:
            exit("容器启动失败")

        self._build_proc_info(pid)
        try:
            self.ip, self.bridge_name, self.host_veth, self.container_veth = IPAM(
                self.network_name
            ).allocate(self.container_id, f"/proc/{pid}/ns/net", port_map)
        except FileNotFoundError as e:
            if f"/proc/{pid}/ns/net" in str(e):
                exit("容器已停止运行")
            raise
        finally:
            self._save_metadata()

        self._set_cgroup_limit()

        if not self.detach:
            try:
                os.waitpid(pid, 0)  # 等待子进程完成
            except KeyboardInterrupt:
                exit("Ctrl+C 停止了进程")

    def reload(self, container_id):
        """
        通过容器的信息文件来重建容器的各个属性
        """

        metadata_file = _safe_join_path(CONTAINER_INFO_DIR, container_id + ".json")
        try:
            with open(metadata_file, "r") as f:
                info = json.load(f)
        except Exception as e:
            output(f"Failed to process {metadata_file}: {e}", "warning")
            return None

        self._build_info(
            **{
                key: info[key]
                for key in info
                # 这些字段由另外的方法载入
                if key not in ["pid", "status", "image_path"]
            }
        )
        self._build_proc_info(info["pid"])
        self._save_metadata()

    def run(self, *args, **xargs):
        self._create_container(*args, **xargs)

    def inspect(self, show=True):
        self.reload(self.container_id)

        with open(self.metadata_file, "r") as f:
            metadata = json.dumps(json.load(f), indent=4)

        if show:
            print(metadata)
        return metadata

    def exec(self, cmd, env={}):
        self.reload(self.container_id)

        if self.status != "running":
            output(f"container {self.pid} is not running", "warning")
            return

        for nstype in ["ipc", "net", "pid", "uts", "mnt"]:
            ns_path = f"/proc/{self.pid}/ns/{nstype}"
            if not os.path.exists(ns_path):
                output(f"Namespace file does not exist: {ns_path}", "warning")
                continue

            try:
                with open(ns_path, "r") as ns_file:
                    fd = ns_file.fileno()  # 获取文件描述符
                    LIBC.setns(fd, 0)  # 调用 setns 切换命名空间
                    output(f"Switched to {nstype} namespace of PID {self.pid}", "debug")
            except PermissionError:
                output(
                    "Permission denied. Are you running the script as root?",
                    "warning",
                )
            except Exception as e:
                output(f"Failed to switch namespace: {e}", "warning")

        pid = os.fork()
        if pid == 0:
            output(f"执行命令 {cmd}", "debug")
            exit_id = os.execvpe(cmd[0], cmd, env)
            if exit_id not in [0, 1]:
                output(f"exited in {exit_id}", "warning")
            else:
                output(f"exited in {exit_id}", "debug")
        else:
            _, status = os.waitpid(pid, 0)
            exit_code = os.WEXITSTATUS(status)
            if exit_code != 0:
                output(f"exited in {exit_code}", "warning")
            else:
                output(f"exited in {exit_code}", "debug")

    def stop(self):
        output(f"Try to stop: {self.pid}", "debug")
        if self.status != "running":
            output(f"container {self.container_id} is already stopped", "warning")
            return

        os.kill(self.pid, 15)
        time.sleep(1)  # 暂停一下，给进程一点时间
        self.reload(self.container_id)
        if self.status != "stopped":
            output(f"容器未能停止运行: {self.container_id}", "warning")
        else:
            output(f"容器已停止运行: {self.container_id}")

    def kill(self):
        output(f"Try to force kill: {self.pid}", "debug")
        if self.status != "running":
            output(f"container {self.container_id} is already stopped", "warning")
            return

        os.kill(self.pid, 9)
        time.sleep(0.1)
        self.reload(self.container_id)
        if self.status != "stopped":
            output(f"容器未能强制停止运行: {self.container_id}", "warning")
        else:
            output(f"容器已强制停止运行: {self.container_id}")

    def remove(self):
        output(f"rm container {self.container_id}", "debug")
        if self.status == "running":
            output(
                f"container {self.container_id} is running, stop it before remove",
                "warning",
            )
            return

        if os.path.exists(self.metadata_file):
            os.remove(self.metadata_file)

        self._clean()
        output(f"容器已删除: {self.container_id}")


class CLI_Parser:
    def __init__(self):
        self.core_parser = argparse.ArgumentParser(description="Wandering Sheep CLI")
        self.core_parser.add_argument("--debug", action="store_true", help="debug 模式")
        self.specs = {
            "container": {
                "run": {
                    "help": "运行命令",
                    "args": [
                        {
                            "name": "-m",
                            "dest": "memory",
                            "help": "内存限制",
                            "default": None,
                        },
                        {
                            "name": "-c",
                            "dest": "cpu",
                            "help": "CPU 限制核",
                            "default": None,
                        },
                        {
                            "name": "-e",
                            "dest": "env",
                            "action": "append",
                            "help": "环境变量",
                            "default": [],
                        },
                        {
                            "name": "-d",
                            "dest": "detach",
                            "action": "store_true",
                            "help": "后台运行",
                        },
                        {
                            "name": "-v",
                            "dest": "volume",
                            "action": "append",
                            "help": "数据卷挂载",
                            "default": [],
                        },
                        {
                            "name": "-p",
                            "dest": "publish",
                            "action": "append",
                            "help": "port 映射",
                            "default": [],
                        },
                        {
                            "name": "-n",
                            "dest": "net",
                            "help": "指定网络配置",
                            "default": "default",
                        },
                        {"name": "image", "help": "镜像名称"},
                        {"name": "cmd", "nargs": "...", "help": "运行的命令和参数"},
                    ],
                },
                "inspect": {
                    "help": "查看容器信息",
                    "args": [{"name": "id", "help": "容器 ID"}],
                },
                "ps": {
                    "help": "查看当前容器",
                    "args": [
                        {
                            "name": "-a",
                            "dest": "all",
                            "action": "store_true",
                            "help": "查看所有",
                        }
                    ],
                },
                "exec": {
                    "help": "在容器中执行命令",
                    "args": [
                        {"name": "id", "help": "容器 ID"},
                        {
                            "name": "-e",
                            "dest": "env",
                            "action": "append",
                            "help": "环境变量",
                            "default": [],
                        },
                        {"name": "cmd", "nargs": "...", "help": "运行的命令和参数"},
                    ],
                },
                "stop": {
                    "help": "停止一个容器",
                    "args": [
                        {"name": "id", "nargs": "?", "help": "容器 ID"},
                        {
                            "name": "-a",
                            "dest": "all",
                            "action": "store_true",
                            "help": "停止所有运行中的容器",
                        },
                    ],
                },
                "kill": {
                    "help": "杀死一个容器",
                    "args": [
                        {"name": "id", "nargs": "?", "help": "容器 ID"},
                        {
                            "name": "-a",
                            "dest": "all",
                            "action": "store_true",
                            "help": "强制停止所有运行中的容器",
                        },
                    ],
                },
                "rm": {
                    "help": "删除一个已经停止的容器",
                    "args": [
                        {"name": "id", "nargs": "?", "help": "容器 ID"},
                        {
                            "name": "-a",
                            "dest": "all",
                            "action": "store_true",
                            "help": "删除所有已停止的容器",
                        },
                    ],
                },
            },
            "network": {
                "rm": {
                    "help": "删除网络配置",
                    "args": [
                        {"name": "name", "nargs": "?", "help": "网络配置名称"},
                        {
                            "name": "-a",
                            "dest": "all",
                            "action": "store_true",
                            "help": "删除所有已停止的容器",
                        },
                    ],
                },
                "create": {
                    "help": "创建一个网络配置",
                    "args": [
                        {"name": "name", "help": "新建的网络名称"},
                        {
                            "name": "subnet",
                            "help": "子网网段",
                        },
                        {"name": "gateway", "help": "网关地址"},
                        {
                            "name": "driver",
                            "default": "bridge",
                            "help": "新建的网络名称",
                        },
                    ],
                },
            },
        }

        self.main_parse = self.core_parser.add_subparsers(
            dest="main_command", help="主命令组"
        )
        self.main_parse.add_parser("clear", help="清理残余垃圾")
        self.main_parse.add_parser("reset", help="重置所有配置")
        self._main_parse()

    def _main_parse(self):
        """
        配置所有命令的元数据
        """

        for _cmd in self.specs:
            _parser = self.main_parse.add_parser(_cmd, help=f"{_cmd} 相关命令")
            sub_parser = _parser.add_subparsers(
                dest=_cmd + "_subcommand", help=f"{_cmd} 子命令"
            )
            spec = self.specs[_cmd]
            for cmd_name, _spec in spec.items():
                setattr(
                    self,
                    _cmd + "_sub_cmd",
                    sub_parser.add_parser(cmd_name, help=_spec["help"]),
                )
                parse_subcmd = getattr(self, _cmd + "_sub_cmd")
                for arg in _spec["args"]:
                    if arg["name"].startswith("-"):
                        parse_subcmd.add_argument(
                            *[arg["name"], "--" + arg["dest"]],
                            dest=arg["dest"],
                            action=arg.get("action"),
                            help=arg["help"],
                            default=arg.get("default"),
                        )
                    else:
                        parse_subcmd.add_argument(
                            arg["name"],
                            nargs=arg.get("nargs", None),
                            help=arg.get("help"),
                        )

            setattr(self, _cmd + "_parser", _parser)

        self.args = self.core_parser.parse_args()

    def _check_env(self):
        try:
            return dict([e.split("=") for e in self.args.env])
        except Exception:
            exit("env 格式错误，示例: -e a=1")

    def network_create(self):
        IPAM(self.args.name).create(
            self.args.driver, self.args.subnet, self.args.gateway
        )

    def network_rm(self):
        IPAM(self.args.name).remove()

    def container_run(self):
        Container().run(
            self.args.image,
            self.args.cmd,
            memory_limit=_parse_limit(self.args.memory) if self.args.memory else None,
            cpu_limit=self.args.cpu,
            volumes=self.args.volume,
            detach=self.args.detach,
            env=self._check_env(),
            network_name=self.args.net,
            port_map=self.args.publish,
        )

    def container_inspect(self):
        get_containers(self.args.id).inspect()

    def container_ps(self):
        table = PrettyTable(header=True, border=False)
        table.field_names = [
            "CONTAINER ID",
            "IMAGE",
            "COMMAND",
            "CREATED",
            "STATUS",
        ]
        table.align["PID"] = "l"
        table.align["COMMAND"] = "l"
        containers = get_containers()
        for container in containers:
            if not self.args.all and container.status != "running":
                continue

            table.add_row(
                [
                    container.container_id[:12],
                    container.image,
                    " ".join(container.cmd),
                    time_ago(container.created_at),
                    container.status.upper(),
                ]
            )

        if table.rows:
            print(table)
        else:
            table.add_row(table.field_names)
            print(table.get_string(header=False, border=False))

    def container_exec(self):
        get_containers(self.args.id).exec(self.args.cmd, self._check_env())

    def container_stop(self):
        if not (bool(self.args.id) ^ bool(self.args.all)):
            output("参数 'id' 和 '-a' 必须指定一个，且不可同时使用", "error")
            return False

        if self.args.id:
            get_containers(self.args.id).stop()
        else:
            output("停止全部运行中的容器", "debug")
            containers = get_containers()
            need_force_stop = [c for c in containers if c.status == "running"]
            if not need_force_stop:
                output("没有需要停止的容器")
                return

            for container in need_force_stop:
                get_containers(container.container_id).stop()

            output(f"批量停止了 {len(need_force_stop)} 个容器")

    def container_kill(self):
        if not (bool(self.args.id) ^ bool(self.args.all)):
            output("参数 'id' 和 '-a' 必须指定一个，且不可同时使用", "error")
            return False

        if self.args.id:
            get_containers(self.args.id).kill()
        else:
            output("强制停止全部运行中的容器", "debug")
            containers = get_containers()
            need_force_stop = [c for c in containers if c.status == "running"]
            if not need_force_stop:
                output("没有需要强制停止的容器")
                return

            for container in need_force_stop:
                get_containers(container.container_id).kill()

            output(f"批量强制停止了 {len(need_force_stop)} 个容器")

    def container_rm(self):
        if not (bool(self.args.id) ^ bool(self.args.all)):
            output("参数 'id' 和 '-a' 必须指定一个，且不可同时使用", "error")
            return False

        if self.args.id:
            get_containers(self.args.id).remove()
        else:
            output("移除全部停止的容器", "debug")
            containers = get_containers()
            need_rm = [c for c in containers if c.status == "stopped"]
            if not need_rm:
                output("没有需要删除的容器")
                return

            for container in need_rm:
                get_containers(container.container_id).remove()

            output(f"批量删除了 {len(need_rm)} 个容器")

    def clear(self):
        containers = {i.container_id: i for i in get_containers()}
        networks = {i.bridge_name: i for i in get_networks()}

        _clear_mount(containers)
        _clear_network(containers)
        _clear_iptables(containers, networks)

    def reset(self):
        self.args.id = None
        self.args.all = True
        self.container_kill()
        self.container_rm()
        # 先移除网络配置，确保 iptables 都被移除
        if os.path.exists(NETWORK_INFO_DIR):
            for i in os.listdir(NETWORK_INFO_DIR):
                os.remove(_safe_join_path(NETWORK_INFO_DIR, i))

        self.clear()
        for i in [
            SHEEP_MNT_DIR,
            # IMAGE_BASE_DIR
            CONTAINER_INFO_DIR,
            CONTAINER_LOG_DIR,
            NETWORK_INFO_DIR,
        ]:
            if os.path.exists(i):
                shutil.rmtree(i)

        ipr = IPRoute()
        index = ipr.link_lookup(ifname="sheep-default")
        if index:
            output(f"删除默认 bridge: sheep-default")
            ipr.link("del", index=index[0])

    def parse(self):
        if self.args.main_command == "clear":
            return self.clear()

        if self.args.main_command == "reset":
            return self.reset()

        for _cmd in self.specs:
            if self.args.main_command == _cmd:
                subcmd = getattr(self.args, _cmd + "_subcommand")
                if subcmd not in self.specs[_cmd]:
                    return getattr(self, _cmd + "_parser").print_help()

                handler = getattr(self, f"{_cmd}_{subcmd}", None)
                if handler and handler() is not False:
                    return

                return getattr(self, _cmd + "_sub_cmd").print_help()

        self.core_parser.print_help()


def _clear_iptables(containers, networks):
    # 获取链对象
    iptables = {
        iptc.Table.NAT: ["POSTROUTING", "PREROUTING", "OUTPUT"],
        iptc.Table.FILTER: ["FORWARD"],
    }
    for tab_type in iptables:
        table = iptc.Table(tab_type)
        for chain_name in iptables[tab_type]:
            chain = iptc.Chain(table, chain_name)
            matched_rules = []
            for rule in chain.rules:
                for match in rule.matches:
                    if match.name != "comment":
                        continue

                    comment = match.parameters.get("comment", "")
                    if match.name == "comment" and comment.startswith("sheep:"):
                        matched_rules.append([comment, rule])

            for comment, rule in matched_rules:
                _, _type, v = comment.split(":")
                if _type == "port-map" and v not in containers:
                    output(f"删除无用 port-map: {comment}")
                    chain.delete_rule(rule)

                if _type in ["nat", "forward"] and v not in networks:
                    output(f"删除无用 nat/forward: {comment}")
                    chain.delete_rule(rule)

        table.commit()


def _clear_network(containers):
    for d in os.listdir(NETWORK_INFO_DIR):
        db = _safe_join_path(NETWORK_INFO_DIR, d)
        with open(db, "r") as f:
            metadata = json.load(f)

        for cid in copy.deepcopy(metadata)["containers"]:
            if cid not in containers:
                output(f"删除不存在的容器 ip 分配: {cid}")
                del metadata["containers"][cid]

        with open(db, "w") as f:
            json.dump(metadata, f, indent=4)

    alive_hiface = [containers[i].host_veth for i in containers]
    interfaces = list(IPDB().interfaces.items())
    ipr = IPRoute()
    for iface_name, _ in interfaces:
        iface_name = str(iface_name)
        if iface_name.startswith("right-"):
            output(f"删除临时 veth: {iface_name}")
            index = ipr.link_lookup(ifname=iface_name)
            if index:
                ipr.link("del", index=index[0])

        if (
            iface_name != "sheep-default"
            and iface_name.startswith("sheep-")
            and iface_name not in alive_hiface
        ):
            index = ipr.link_lookup(ifname=iface_name)
            if index:
                output(f"删除无用的宿主机 veth: {iface_name}")
                ipr.link("del", index=index[0])


def _clear_mount(containers):
    mounts = []
    with open("/proc/mounts", "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue

            device = parts[0]
            mount_point = parts[1]
            if not mount_point.startswith(SHEEP_MNT_DIR):
                continue

            mounts.append((device, mount_point))

    for m in mounts[::-1]:
        _type, path = m
        container_id = path.replace(SHEEP_MNT_DIR + "/", "").split("/")[0]
        if container_id not in containers:
            LIBC.umount2(path, 1)
            output(f"umount 无用挂载目录: {path}")

    for d in os.listdir(SHEEP_MNT_DIR):
        if d in containers:
            continue

        path = _safe_join_path(SHEEP_MNT_DIR, d)
        shutil.rmtree(path)
        output(f"删除无用的挂载目录: {path}")


# ---------- 配置区 ------------
METADATA_DIR = os.path.abspath("/var/sheep")
SHEEP_MNT_DIR = os.path.abspath("/mnt/sheep/")
# -----------------------------

if not os.path.exists(METADATA_DIR):
    exit(f"Metadata directory '{METADATA_DIR}' does not exist")

# 需要用到的系统调用
LIBC = ctypes.CDLL(find_library("c"), use_errno=True)  # 查找 libc 的位置
for func in ["sethostname", "umount2", "mount", "pivot_root", "setns"]:
    setattr(LIBC, func, libc_error_handler(getattr(LIBC, func)))


original_stdout_fd = sys.stdout.fileno()

cli = CLI_Parser()
args = cli.args
output = functools.partial(output, debug=args.debug)
output(str(args), "debug")

if not os.path.exists(SHEEP_MNT_DIR):
    os.makedirs(SHEEP_MNT_DIR, exist_ok=True)
    output(f"创建容器 overlay2 挂载目录: {SHEEP_MNT_DIR}", "debug")

IMAGE_BASE_DIR = _safe_join_path(METADATA_DIR, "/images")
if not os.path.exists(IMAGE_BASE_DIR):
    os.makedirs(IMAGE_BASE_DIR, exist_ok=True)
    output(f"创建容器信息目录: {IMAGE_BASE_DIR}", "debug")

CONTAINER_INFO_DIR = _safe_join_path(METADATA_DIR, "/container_info")
if not os.path.exists(CONTAINER_INFO_DIR):
    os.makedirs(CONTAINER_INFO_DIR, exist_ok=True)
    output(f"创建容器信息目录: {CONTAINER_INFO_DIR}", "debug")

CONTAINER_LOG_DIR = _safe_join_path(METADATA_DIR, "/container_log")
if not os.path.exists(CONTAINER_LOG_DIR):
    os.makedirs(CONTAINER_LOG_DIR, exist_ok=True)
    output(f"创建容器日志目录: {CONTAINER_LOG_DIR}", "debug")

NETWORK_INFO_DIR = _safe_join_path(METADATA_DIR, "/network")
if not os.path.exists(NETWORK_INFO_DIR):
    os.makedirs(NETWORK_INFO_DIR, exist_ok=True)
    output(f"创建容器网络信息目录: {NETWORK_INFO_DIR}", "debug")

# 默认网络配置
if not os.path.exists(_safe_join_path(NETWORK_INFO_DIR, "default.json")):
    IPAM("default").create("bridge", "10.10.0.0/16", "10.10.0.1")
    output(f"创建容器默认网络配置: default.json")
    # 解决 localhost 默认不 route 的问题
    open("/proc/sys/net/ipv4/conf/all/route_localnet", "w").write("1")

cli.parse()

