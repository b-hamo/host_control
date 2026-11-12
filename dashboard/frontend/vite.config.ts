import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 개발 중에는 /api 요청을 백엔드(host_control 집계 API)로 프록시.
// 백엔드 주소가 정해지면 target만 바꾸면 됩니다.
export default defineConfig({
  plugins: [react()],
  // 빌드 결과는 dashboard/static/ 에 바로 쓴다. python -m dashboard 가 그 폴더를 / 로 내보낸다.
  build: {
    outDir: '../static',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        // 대시보드 백엔드(host_control dashboard 서버). 실제 연동은 보통
        // 빌드 결과를 dashboard/static/ 에 두고 127.0.0.1:17480 에서 바로 열지만,
        // dev에서 실 API로 붙여볼 때를 위한 프록시.
        target: 'http://127.0.0.1:17480',
        changeOrigin: true,
      },
    },
  },
})
