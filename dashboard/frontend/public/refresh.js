// 라이브 뷰 '화면 새로고침' 버튼 (2026-11-26). React 번들과 따로 도는 작은 스크립트:
// 대시보드 서버에 POST /api/runtimes/refresh 를 보내면 켜져 있는 Host들이 화면을 한 장씩 새로 찍는다.
// 새 그림은 페이지가 원래 하던 주기 갱신으로 2~5초 안에 바뀐다. 입력(클릭·키)은 보내지 않는다.
(function () {
  var token = new URLSearchParams(window.location.search).get('token');
  if (!token) return;
  var button = document.createElement('button');
  button.type = 'button';
  button.textContent = '화면 새로고침';
  button.title = '켜져 있는 실행 환경의 화면을 지금 한 장씩 새로 찍습니다';
  button.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:9999;padding:10px 16px;' +
    'border:0;border-radius:10px;background:#2563eb;color:#fff;font:600 14px/1 "Malgun Gothic",sans-serif;' +
    'box-shadow:0 4px 14px rgba(0,0,0,.25);cursor:pointer';
  function reset() { button.disabled = false; button.style.opacity = '1'; button.textContent = '화면 새로고침'; }
  button.addEventListener('click', function () {
    button.disabled = true; button.style.opacity = '.7'; button.textContent = '찍는 중…';
    fetch('/api/runtimes/refresh', { method: 'POST', headers: { Authorization: 'Bearer ' + token } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        button.textContent = d.requested.length ? d.requested.length + '개 요청함' : '켜진 환경 없음';
        setTimeout(reset, 4000);
      })
      .catch(function () { button.textContent = '요청 실패'; setTimeout(reset, 3000); });
  });
  document.body.appendChild(button);
})();
