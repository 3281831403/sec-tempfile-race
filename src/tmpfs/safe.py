"""临时文件安全导出桩：独占创建、原子发布与权限边界。

威胁模型
--------
导出目录可能被其他本地用户写入，攻击者可以事先放好与候选名同名的文件或符号
链接。可预测的候选名、非独占的打开方式、普通打开回退、非原子改名，都会让
导出内容写进攻击者指定的位置，或者留下半截文件。

契约与容差 0
------------
- 候选名的不可预测部分由调用方通过 suffix 显式传入，必须原样保留，不得改用
  递增序号。
- 已存在的路径绝不能被覆盖、截断或跟随；独占创建失败必须原样抛出
  FileExistsError，不得回退到普通打开。
- 最终文件只能通过一次原子改名出现；任何失败都不得留下半截目标或临时文件。
- 权限容差为 0：模式位不得宽于 0o600，创建、设置与导出流程都必须保证这一点。
- 清理与所有者校验只接受精确边界，不做前缀、用户名或路径猜测。
"""

import os
import stat
import tempfile

#: 允许的最高权限位：仅所有者可读写。
_MAX_MODE = 0o600


def _check_mode(mode: int) -> None:
    """mode 含 0o600 之外的位时抛 ValueError，容差 0。"""
    if mode & ~_MAX_MODE:
        raise ValueError(f"mode 不得宽于 0o600: {mode!r}")


def candidate_name(directory: str, prefix: str, suffix: str) -> str:
    """返回 directory 下的候选文件路径。

    返回值必须是 str；目录部分等于 directory，文件名以 prefix 开头、以调用方
    传入的 suffix 结尾，suffix 必须原样保留。禁止使用固定递增序号或进程内
    计数器制造唯一性，因为序号可以被预测并抢先占位；真正的唯一性由
    create_exclusive 的独占创建保证。
    容差 0：prefix 与 suffix 逐字符保留，不追加、不截断、不改写。
    """
    return os.path.join(directory, f"{prefix}{suffix}")


def create_exclusive(path: str, mode: int) -> int:
    """独占创建 path，返回可写的文件描述符。

    必须使用 os.open 并带上 os.O_CREAT 与 os.O_EXCL；path 已存在时抛
    FileExistsError，原有内容与权限保持不变，绝不覆盖或截断。
    创建模式必须使用调用方传入的 mode，禁止写死为 0o755 等更宽的模式；mode 中
    0o600 之外的位必须抛 ValueError。独占创建失败后禁止回退到普通打开，竞态
    必须原样暴露。权限容差为 0。
    """
    _check_mode(mode)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, mode)


def write_atomic(path: str, data: bytes, mode: int) -> str:
    """把 data 原子发布到 path，返回最终路径 str。

    先在 path 所在目录用独占方式创建唯一临时文件，权限收紧到 mode；写入全部
    data 并 flush、fsync，再用 os.replace 一次原子改名到 path。目标已存在时抛
    FileExistsError 并保持原内容，不得回退普通打开；任何失败都要删除临时文件，
    path 上不得出现半截内容。
    mode 只允许 0o600 以内的位；最终权限必须精确等于 mode，容差 0。
    """
    _check_mode(mode)
    if os.path.lexists(path):
        raise FileExistsError(f"目标已存在，拒绝覆盖: {path}")
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".export-")
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return path


def set_permissions(path: str, mode: int) -> None:
    """把 path 的权限设置为 mode。

    先校验 mode：只允许 0o600 以内的位；只要含 0o600 之外的位，包括 0o077 的
    组与其他用户位，就抛 ValueError，并且不得调用 os.chmod，原权限保持不变。
    校验通过后调用 os.chmod(path, mode)。权限容差为 0：不做掩码截断、不做
    静默降级，也不接受 0o755、0o777 等过宽模式。
    """
    _check_mode(mode)
    os.chmod(path, mode)


def cleanup(path: str) -> bool:
    """删除临时文件，成功返回 True，否则返回 False。

    先用 realpath 解析 path，确认它位于 tempfile.gettempdir() 之内；越界路径
    直接返回 False 且不删除，也不抛异常。只删除普通文件，不删除目录，不跟随
    符号链接。路径不存在时返回 False。
    容差 0：边界按完整路径判断，不用字符串前缀或包含关系放宽。
    """
    root = os.path.realpath(tempfile.gettempdir())
    target = os.path.realpath(path)
    if target != root and not target.startswith(root + os.sep):
        return False
    try:
        status = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(status.st_mode):
        return False
    try:
        os.unlink(path)
    except OSError:
        return False
    return True


def verify_owner(path: str, expected_uid: int) -> bool:
    """校验 path 的所有者是否为 expected_uid。

    必须按数值比较 os.stat(path).st_uid 与 expected_uid，禁止比较用户名或用户
    名字符串，否则同名用户会被误判。文件不存在或无法 stat 时返回 False，不抛
    异常。容差 0：uid 不相等即返回 False。
    """
    try:
        return os.stat(path).st_uid == expected_uid
    except OSError:
        return False


def validate_policy(policy: dict) -> list[str]:
    """返回导出策略的问题代码列表，安全策略返回 []。

    固定检查顺序与代码：
    1. policy["overwrite"] 为真：overwrite_allowed；
    2. policy["mode"] 含 0o600 之外的位：mode_too_wide；
    3. policy["directory"] 的 st_mode 含 S_IWGRP 或 S_IWOTH：
       directory_writable_by_others。
    overwrite 缺省为 False，mode 缺省为 0o600；directory 必须存在且是目录。
    只返回上述三个稳定代码。容差 0：按完整模式位判断，不做前缀、白名单或
    静默放行。
    """
    problems = []
    if policy.get("overwrite", False):
        problems.append("overwrite_allowed")
    if policy.get("mode", _MAX_MODE) & ~_MAX_MODE:
        problems.append("mode_too_wide")
    try:
        status = os.stat(policy["directory"])
    except (OSError, KeyError, TypeError):
        status = None
    if (
        status is not None
        and stat.S_ISDIR(status.st_mode)
        and status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        problems.append("directory_writable_by_others")
    return problems


def export_batch(items: list, policy: dict) -> dict:
    """批量导出，条目之间完全独立，返回 {"exported": [...], "problems": [...]}。

    items 是映射序列，每项含 name、data、suffix。每个条目必须把自身的 suffix
    原样传给 candidate_name，独立走候选名、独占创建、原子写入与权限收紧流程，
    禁止复用同一候选名，也禁止让前一条目的数据或状态影响后一条目。
    policy 提供 directory、prefix、mode 与 overwrite；overwrite 为真属于不安全
    配置，不得真的覆盖已有文件。
    单条失败只把原因写入 problems，不中断其余条目；exported 按输入顺序记录成功
    条目的最终路径。容差 0：每个成功文件的内容与权限必须与单独导出完全一致。
    """
    directory = policy["directory"]
    prefix = policy.get("prefix", "")
    mode = policy.get("mode", _MAX_MODE)
    exported = []
    problems = []
    for item in items:
        try:
            path = candidate_name(directory, prefix, item["suffix"])
            write_atomic(path, item["data"], mode)
        except Exception as exc:
            problems.append(f"{item.get('name', '?')}: {exc}")
        else:
            exported.append(path)
    return {"exported": exported, "problems": problems}
