from pathlib import Path


def create_dir(dir_path):
    try:
        dir_path.mkdir(parents=True, exist_ok=False)
        print(f"\tDirectory '{dir_path}' created successfully.")
    except PermissionError:
        raise ValueError(f"Permission denied: Unable to create '{dir_path}'.")
    except Exception as e:
        raise ValueError(f"An error occurred: {e}")


def docker_dir(base_path, cve_id, tool):
    return Path(base_path) / "dockers" / cve_id / tool


def logs_dir(base_path, cve_id, tool):
    """Logs subdirectory for a given CVE/tool run."""
    return docker_dir(base_path, cve_id, tool) / "logs"