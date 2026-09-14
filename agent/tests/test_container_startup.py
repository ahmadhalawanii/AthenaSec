from pathlib import Path


def test_dockerfile_uses_uvicorn_application_factory():
    dockerfile_path = (
        Path(__file__).resolve().parents[1]
        / "Dockerfile"
    )

    dockerfile = dockerfile_path.read_text(
        encoding="utf-8"
    )

    assert '"app.main:create_app"' in dockerfile
    assert '"--factory"' in dockerfile