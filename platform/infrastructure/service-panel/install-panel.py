#!/usr/bin/python3
"""Install only panel files, retaining a reversible snapshot. Ubuntu 24.04."""
import argparse
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
APP = Path("/opt/athenasec/service-panel")
LAUNCHER = Path("/usr/local/bin/athenasec-service-panel")
DESKTOP = Path("/usr/share/applications/athenasec-service-panel.desktop")
PROFILE = Path("/etc/apparmor.d/athenasec-service-panel")
PARSER = "/usr/sbin/apparmor_parser"
APPARMOR_ENABLED = Path("/sys/module/apparmor/parameters/enabled")
FILES = (
    "app.py", "auth.py", "metrics.py", "services.py", "browser.py",
    "site_policy.py", "bootstrap.py", "README.md", "ui/style.css",
    "assets/athenasec-service-panel.svg",
)
TARGETS = {"app": APP, "launcher": LAUNCHER, "desktop": DESKTOP, "profile": PROFILE}


def run_parser(*args):
    subprocess.run([PARSER, "-I", "/etc/apparmor.d", *map(str, args)], check=True)


def validate_target(path):
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise RuntimeError(f"Refusing symlink: {ancestor}")
    if path.exists() and ((path == APP and not path.is_dir()) or (path != APP and not path.is_file())):
        raise RuntimeError(f"Unexpected target type: {path}")


def write_file(source, target, mode=0o644):
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    fd, name = tempfile.mkstemp(prefix=".panel-v3-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(source.read_bytes())
        os.chmod(name, mode)
        os.chown(name, 0, 0)
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def restore(backup):
    """Accept only installer-created root-owned private snapshots at fixed paths."""
    if backup.is_symlink():
        raise RuntimeError("Refusing symlink backup")
    backup = backup.resolve(strict=True)
    if backup.parent != APP.parent or not backup.name.startswith("service-panel-v3-backup."):
        raise RuntimeError("Not a panel v3 backup directory")
    if backup.stat().st_uid != 0 or backup.stat().st_mode & 0o077:
        raise RuntimeError("Backup must be root-owned and private (0700)")
    manifest = json.loads((backup / "manifest.json").read_text())
    if set(manifest) != set(TARGETS) or any(type(v) is not bool for v in manifest.values()):
        raise RuntimeError("Invalid backup manifest")
    for key, target in TARGETS.items():
        validate_target(target)
        if manifest[key] and not (backup / key).exists():
            raise RuntimeError(f"Incomplete backup: {key}")
    # Load the former policy before touching application files. A first-install
    # rollback removes the newly installed policy from the kernel instead.
    policy_error = None
    try:
        if manifest["profile"]:
            run_parser("-Q", "-T", backup / "profile")
            run_parser("-r", backup / "profile")
        elif PROFILE.exists():
            run_parser("-R", PROFILE)
    except subprocess.SubprocessError as error:
        # Still restore the files if the kernel policy operation failed.
        # Report incomplete policy rollback instead of claiming success.
        policy_error = error
    if APP.exists():
        shutil.rmtree(APP)
    if manifest["app"]:
        shutil.copytree(backup / "app", APP, symlinks=True)
    for key, target in TARGETS.items():
        if key == "app":
            continue
        if manifest[key]:
            write_file(backup / key, target, (backup / key).stat().st_mode & 0o777)
        elif target.exists():
            target.unlink()
    if policy_error is not None:
        raise RuntimeError(f"Panel files restored, but AppArmor rollback failed. Keep backup: {backup}") from policy_error
    print(f"Previous panel restored. Snapshot retained: {backup}")


def install():
    if not Path(PARSER).is_file():
        raise RuntimeError("Install apparmor before running this installer")
    if not APPARMOR_ENABLED.read_text().strip() == "Y":
        raise RuntimeError("AppArmor must be enabled for this launcher")
    disabled = PROFILE.parent / "disable" / PROFILE.name
    if disabled.exists() or disabled.is_symlink():
        raise RuntimeError("The panel profile is explicitly disabled; resolve that before installing")
    for target in TARGETS.values():
        validate_target(target)
    desired_profile = SOURCE / "apparmor" / PROFILE.name
    if PROFILE.exists() and PROFILE.read_bytes() != desired_profile.read_bytes():
        raise RuntimeError("Existing panel AppArmor profile differs; refusing to overwrite custom policy")
    for relative in FILES:
        source = SOURCE / "service-panel" / relative
        if not source.is_file() or source.is_symlink():
            raise RuntimeError(f"Missing or symlink source: {source}")
        if source.suffix == ".py":
            ast.parse(source.read_text(), filename=relative)
    run_parser("-Q", "-T", desired_profile)
    APP.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    backup = Path(tempfile.mkdtemp(prefix="service-panel-v3-backup.", dir=APP.parent))
    manifest = {key: target.exists() for key, target in TARGETS.items()}
    for key, target in TARGETS.items():
        if manifest[key]:
            if target.is_dir():
                shutil.copytree(target, backup / key, symlinks=True)
            else:
                shutil.copy2(target, backup / key)
    (backup / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Backup: {backup}", flush=True)
    try:
        # Prepare the whole replacement beside the target before a short swap.
        staged = backup / "new-app"
        staged.mkdir(mode=0o755)
        for relative in FILES:
            write_file(SOURCE / "service-panel" / relative, staged / relative)
        write_file(desired_profile, PROFILE)
        run_parser("-r", PROFILE)
        if APP.exists():
            APP.rename(backup / "displaced-app")
        staged.rename(APP)
        write_file(SOURCE / "launchers" / LAUNCHER.name, LAUNCHER, 0o755)
        write_file(SOURCE / "launchers" / DESKTOP.name, DESKTOP)
    except Exception:
        print("Installation failed; attempting to restore the previous panel.", flush=True)
        restore(backup)
        raise
    print("Installed v3. Run athenasec-service-panel as your normal desktop user.")
    print(f"Rollback: sudo python3 {SOURCE / 'install-panel.py'} --rollback {backup}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rollback", type=Path, help="Exact backup directory printed during installation")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Installation/rollback needs sudo; the panel itself must run as your normal user")
    os.umask(0o022)
    try:
        restore(args.rollback) if args.rollback else install()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Panel installation/rollback stopped: {error}\n")


if __name__ == "__main__":
    main()
