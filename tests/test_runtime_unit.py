from docker.errors import ImageNotFound

from poi.runtime import PROXY_IMAGE, ensure_proxy_image


class _Images:
    def __init__(self, present):
        self.present, self.built = present, []

    def get(self, tag):
        if not self.present:
            raise ImageNotFound(tag)

    def build(self, **kw):
        self.built.append(kw["tag"])


class _Client:
    def __init__(self, present):
        self.images = _Images(present)


def test_builds_proxy_image_only_when_missing():
    missing, present = _Client(False), _Client(True)
    ensure_proxy_image(missing)
    ensure_proxy_image(present)
    assert missing.images.built == [PROXY_IMAGE]
    assert present.images.built == []
