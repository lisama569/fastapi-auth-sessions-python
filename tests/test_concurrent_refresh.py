"""并发刷新：同一刷新凭证被多个请求同时使用时，有且仅有一个成功；
其余必须失败且不得产生新的有效会话/令牌；重放要触发整族吊销。"""

from __future__ import annotations

import threading

import pytest

from app.errors import AuthError, ErrorCode
from app.services import AuthService


def test_concurrent_refresh_exactly_one_winner(svc: AuthService):
    login = svc.login("viewer", "viewer-pw", "10.0.0.1")
    n = 16
    barrier = threading.Barrier(n)
    results: list[object] = []
    results_lock = threading.Lock()

    def worker() -> None:
        barrier.wait()  # 最大化竞争：所有线程同时进入旋转临界区
        try:
            access, refresh = svc.refresh(login.refresh_token)
            with results_lock:
                results.append(("ok", access, refresh))
        except AuthError as exc:
            with results_lock:
                results.append(("err", exc.code))

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "err"]

    print(f"\n[input] {n} concurrent refresh requests with same credential")
    print(f"[decision] winners={len(winners)} losers={len(losers)} "
          f"loser_codes={sorted({r[1].value for r in losers})}")

    assert len(winners) == 1, f"expected exactly 1 winner, got {len(winners)}"
    assert len(losers) == n - 1

    # 只有第一个并发完成者可能命中"正常"路径；由于检测到重放，整族已被吊销，
    # 胜出者刚签发的访问令牌也必须立即失效（盗用处置）
    codes = {r[1] for r in losers}
    assert codes <= {ErrorCode.REFRESH_TOKEN_REPLAY,
                     ErrorCode.REFRESH_TOKEN_REVOKED}
    assert ErrorCode.REFRESH_TOKEN_REPLAY in codes

    winner_access = winners[0][1]
    with pytest.raises(AuthError) as after:
        svc.authenticate(winner_access)
    assert after.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    print("[decision] winner's new access revoked after replay detection; "
          "no surviving valid session")


def test_serial_refresh_chain_then_replay_revokes_family(svc: AuthService):
    """正常串行旋转链可连续成功；任意旧凭证重放都终结整条链。"""
    login = svc.login("editor", "editor-pw", "10.0.0.2")
    credential = login.refresh_token
    history = [credential]
    for _ in range(3):
        _access, credential = svc.refresh(credential)
        history.append(credential)
    # 链上最新凭证有效
    access_last, _ = svc.refresh(credential)
    svc.authenticate(access_last)
    print(f"\n[input] serial rotation chain length={len(history) + 1} "
          f"-> [decision] all rotations ok")

    # 重放链中第一代旧凭证
    with pytest.raises(AuthError) as replay:
        svc.refresh(history[0])
    assert replay.value.code is ErrorCode.REFRESH_TOKEN_REPLAY

    # 链上所有其它凭证（含最新）全部失效，没有任何有效会话残留
    for old in history[1:]:
        with pytest.raises(AuthError) as e:
            svc.refresh(old)
        assert e.value.code in (ErrorCode.REFRESH_TOKEN_REPLAY,
                                ErrorCode.REFRESH_TOKEN_REVOKED)
    print("[input] replay first-generation credential "
          "-> [decision] entire family revoked, no surviving credentials")
