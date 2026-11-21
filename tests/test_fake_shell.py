from honeypot.fake_shell import respond


def test_known_command():
    assert respond("whoami") == ("root", False)


def test_exit_ends_session():
    out, done = respond("exit")
    assert done is True


def test_unknown_command():
    out, done = respond("foobar --x")
    assert "command not found" in out and done is False


def test_download_tools_time_out():
    out, _ = respond("wget http://example.com/x.sh")
    assert "timed out" in out


def test_empty_input():
    assert respond("   ") == ("", False)
